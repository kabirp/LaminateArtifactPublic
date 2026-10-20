#include "test_helpers.hpp"

#include "laminate/field/serialization.hpp"
#include "laminate/spartan/sumcheck.hpp"
#include "laminate/transcript/hash.hpp"
#include "laminate/transcript/transcript.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <span>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace {

using laminate::Fq;
using laminate::Fq2;
using laminate::Transcript;
using laminate::spartan::ConstraintSumcheckArtifactArrays;
using laminate::spartan::ConstraintSumcheckArtifactOptions;
using laminate::spartan::ConstraintSumcheckArtifactReport;
using laminate::spartan::ConstraintSumcheckOutput;
using laminate::spartan::WiringSumcheckOutput;

class TemporaryDirectory {
  public:
    explicit TemporaryDirectory(std::string label) {
        const auto stamp = std::chrono::steady_clock::now()
                               .time_since_epoch()
                               .count();
        for (std::size_t attempt = 0; attempt < 100; ++attempt) {
            path_ = std::filesystem::temp_directory_path() /
                    ("laminate-constraint-sumcheck-" + label + "-" +
                     std::to_string(stamp) + "-" +
                     std::to_string(attempt));
            if (std::filesystem::create_directory(path_)) {
                return;
            }
        }
        throw std::runtime_error(
            "failed to create constraint sumcheck test directory");
    }

    ~TemporaryDirectory() {
        std::error_code ignored;
        std::filesystem::remove_all(path_, ignored);
    }

    const std::filesystem::path &path() const { return path_; }

  private:
    std::filesystem::path path_;
};

bool throws_exception(const auto &body) {
    try {
        body();
    } catch (const std::exception &) {
        return true;
    }
    return false;
}

std::uint64_t recursive_file_bytes(
    const std::filesystem::path &directory) {
    std::uint64_t bytes = 0;
    for (const auto &entry :
         std::filesystem::recursive_directory_iterator(directory)) {
        if (entry.is_regular_file()) {
            bytes += entry.file_size();
        }
    }
    return bytes;
}

laminate::Digest constraint_source_identity() {
    constexpr std::string_view label =
        "laminate/test/constraint-sumcheck-source/v1";
    return laminate::sha256(std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t *>(label.data()),
        label.size()));
}

laminate::storage::NativeFieldArtifact write_constraint_source(
    const std::filesystem::path &directory, std::span<const Fq> az,
    std::span<const Fq> bz, std::span<const Fq> cz) {
    laminate::storage::NativeFieldArtifactWriter writer(
        directory,
        {.max_total_bytes = 1ULL << 24U, .min_free_bytes = 1},
        constraint_source_identity());
    const std::array<std::pair<std::string_view, std::span<const Fq>>, 3>
        arrays{{{"az-values", az}, {"bz-values", bz}, {"cz-values", cz}}};
    for (const auto &[name, values] : arrays) {
        writer.begin_array(std::string(name),
                           laminate::storage::NativeFieldElementKind::Fq,
                           values.size());
        writer.append(values);
        writer.finish_array();
    }
    (void)writer.finish();
    return laminate::storage::NativeFieldArtifact::open(
        directory, constraint_source_identity());
}

ConstraintSumcheckArtifactArrays constraint_source_names() {
    return {.az = "az-values", .bz = "bz-values", .cz = "cz-values"};
}

ConstraintSumcheckArtifactOptions artifact_options(
    const std::filesystem::path &scratch, std::size_t source_rounds,
    std::size_t block_elements,
    std::uint64_t max_working_field_bytes = 1ULL << 20U,
    std::uint64_t max_scratch_bytes = 1ULL << 24U,
    std::size_t logical_domain_size = 0) {
    return {
        .expected_source_identity = constraint_source_identity(),
        .scratch_directory = scratch,
        .max_live_storage_bytes = 1ULL << 25U,
        .max_total_scratch_bytes = max_scratch_bytes,
        .min_free_bytes = 1,
        .max_working_field_bytes = max_working_field_bytes,
        .block_elements = block_elements,
        .source_rounds = source_rounds,
        .logical_domain_size = logical_domain_size,
    };
}

std::vector<std::uint8_t> constraint_proof_bytes(
    const laminate::spartan::ConstraintSumcheckProof &proof) {
    std::vector<std::uint8_t> result;
    result.reserve(proof.rounds.size() * 2U *
                   laminate::kSerializedFq2Bytes);
    for (const auto &round : proof.rounds) {
        for (const Fq2 &value :
             std::array<Fq2, 2>{round.endpoint, round.at_two}) {
            const laminate::SerializedFq2 encoded = laminate::serialize(value);
            result.insert(result.end(), encoded.begin(), encoded.end());
        }
    }
    return result;
}

std::vector<Fq2> lift(std::span<const Fq> values) {
    std::vector<Fq2> result;
    result.reserve(values.size());
    for (const Fq &value : values) {
        result.push_back(Fq2::from_base(value));
    }
    return result;
}

void bind_first_variable(std::vector<Fq2> &table,
                         const Fq2 &challenge) {
    const std::size_t half = table.size() / 2;
    for (std::size_t suffix = 0; suffix < half; ++suffix) {
        table[suffix] +=
            challenge * (table[half + suffix] - table[suffix]);
    }
    table.resize(half);
}

Fq2 evaluate_mle(std::span<const Fq> evaluations,
                 std::span<const Fq2> point) {
    std::vector<Fq2> table = lift(evaluations);
    for (const Fq2 &challenge : point) {
        bind_first_variable(table, challenge);
    }
    return table.front();
}

Fq2 evaluate_mle(std::span<const Fq2> evaluations,
                 std::span<const Fq2> point) {
    std::vector<Fq2> table(evaluations.begin(), evaluations.end());
    for (const Fq2 &challenge : point) {
        bind_first_variable(table, challenge);
    }
    return table.front();
}

std::vector<Fq2> equality_table(std::span<const Fq2> point) {
    std::vector<Fq2> result{Fq2::one()};
    for (const Fq2 &coordinate : point) {
        const std::size_t previous_size = result.size();
        result.resize(2 * previous_size);
        for (std::size_t index = previous_size; index-- > 0;) {
            const Fq2 previous = result[index];
            const Fq2 high = previous * coordinate;
            result[2 * index] = previous - high;
            result[2 * index + 1] = high;
        }
    }
    return result;
}

Fq2 equality_evaluation(std::span<const Fq2> left,
                        std::span<const Fq2> right) {
    Fq2 result = Fq2::one();
    for (std::size_t variable = 0; variable < left.size(); ++variable) {
        result *= (Fq2::one() - left[variable]) *
                      (Fq2::one() - right[variable]) +
                  left[variable] * right[variable];
    }
    return result;
}

struct ConstraintFixture {
    std::vector<Fq> az;
    std::vector<Fq> bz;
    std::vector<Fq> cz;
};

Fq equality_weight(std::size_t index, std::span<const Fq> point) {
    Fq result = Fq::one();
    for (std::size_t variable = 0; variable < point.size(); ++variable) {
        const bool bit =
            ((index >> (point.size() - 1U - variable)) & 1U) != 0;
        result *= bit ? point[variable] : Fq::one() - point[variable];
    }
    return result;
}

ConstraintFixture make_zero_sum_fixture(std::span<const Fq> tau) {
    ConstraintFixture result;
    const std::size_t domain_size = std::size_t{1} << tau.size();
    for (std::size_t index = 0; index < domain_size; ++index) {
        result.az.push_back(Fq(3 * index + 2));
        result.bz.push_back(Fq(5 * index + 7));
        result.cz.push_back(result.az.back() * result.bz.back());
    }

    // Give two rows nonzero residuals e(x)=Az(x)Bz(x)-Cz(x), while keeping
    // the initial claim sum_x eq(tau,x)e(x)=0. If their equality weights are
    // w_0,w_1, choose e(x_0)=w_1 and e(x_1)=-w_0.
    std::vector<std::pair<std::size_t, Fq>> nonzero_weights;
    for (std::size_t index = 0; index < result.az.size(); ++index) {
        const Fq weight = equality_weight(index, tau);
        if (!weight.is_zero()) {
            nonzero_weights.emplace_back(index, weight);
        }
    }
    CHECK(nonzero_weights.size() >= 2);
    const auto &[first_index, first_weight] = nonzero_weights[0];
    const auto &[second_index, second_weight] = nonzero_weights[1];
    result.cz[first_index] -= second_weight;
    result.cz[second_index] += first_weight;
    return result;
}

std::size_t test_floor_power_of_two(std::size_t value) {
    return std::size_t{1} << (std::bit_width(value) - 1U);
}

std::uint64_t test_scratch_artifact_bytes(std::size_t element_count) {
    const std::array<laminate::storage::NativeFieldArrayLayout, 3> layout{{
        {"az", laminate::storage::NativeFieldElementKind::Fq2,
         element_count},
        {"bz", laminate::storage::NativeFieldElementKind::Fq2,
         element_count},
        {"cz", laminate::storage::NativeFieldElementKind::Fq2,
         element_count},
    }};
    return laminate::storage::native_field_artifact_physical_bytes(layout);
}

std::uint64_t test_expected_field_peak(std::size_t domain_size,
                                       std::size_t source_rounds,
                                       std::size_t block_elements) {
    const std::size_t prefix_count = std::size_t{1} << source_rounds;
    const std::size_t checkpoint_size = domain_size / prefix_count;
    const std::uint64_t prefix_bytes = prefix_count * sizeof(Fq2);
    std::uint64_t peak =
        prefix_bytes +
        std::min(block_elements, checkpoint_size) *
            (sizeof(Fq2) + sizeof(Fq));
    for (std::size_t round = 0; round < source_rounds; ++round) {
        const std::size_t suffix = domain_size >> (round + 1U);
        peak = std::max<std::uint64_t>(
            peak, prefix_bytes +
                      std::min(block_elements, suffix) *
                          (7U * sizeof(Fq2) + sizeof(Fq)));
    }
    for (std::size_t size = checkpoint_size; size > 1; size >>= 1U) {
        const std::size_t half = size / 2U;
        peak = std::max<std::uint64_t>(
            peak, std::min(block_elements, half) *
                      7U * sizeof(Fq2));
        peak = std::max<std::uint64_t>(
            peak, std::min(block_elements, half) *
                      2U * sizeof(Fq2));
    }
    return std::max<std::uint64_t>(peak, sizeof(Fq2));
}

ConstraintSumcheckArtifactReport expected_artifact_report(
    const laminate::storage::NativeFieldArtifact &source,
    std::size_t active_size, std::size_t domain_size,
    std::size_t requested_source_rounds,
    std::size_t requested_block,
    std::uint64_t max_working_field_bytes = 1ULL << 20U) {
    ConstraintSumcheckArtifactReport result;
    const std::size_t variables = std::bit_width(domain_size) - 1U;
    const std::size_t source_rounds =
        std::min(requested_source_rounds, variables);
    std::size_t block = test_floor_power_of_two(
        std::min(requested_block, domain_size));
    while (test_expected_field_peak(domain_size, source_rounds, block) >
           max_working_field_bytes) {
        CHECK(block > 1);
        block >>= 1U;
    }
    const std::size_t prefix_count = std::size_t{1} << source_rounds;
    const std::size_t checkpoint_size = domain_size / prefix_count;
    result.source_artifact_physical_bytes = source.physical_bytes();
    result.source_validation_bytes = source.physical_bytes();
    result.selected_source_payload_bytes = 3U * active_size * sizeof(Fq);
    result.effective_block_elements = block;
    result.source_rescan_rounds = source_rounds;
    result.peak_working_field_bytes =
        test_expected_field_peak(domain_size, source_rounds, block);

    for (std::size_t round = 0; round < source_rounds; ++round) {
        const std::size_t suffix = domain_size >> (round + 1U);
        const std::size_t pass_block = std::min(block, suffix);
        result.indexed_read_payload_bytes +=
            3U * active_size * sizeof(Fq);
        const std::size_t prefix_count = std::size_t{1} << round;
        for (std::size_t prefix = 0; prefix < prefix_count; ++prefix) {
            for (std::size_t branch = 0; branch < 2; ++branch) {
                const std::size_t begin =
                    (2U * prefix + branch) * suffix;
                const std::size_t available =
                    begin >= active_size
                        ? 0
                        : std::min(suffix, active_size - begin);
                result.indexed_read_operations +=
                    3U * ((available + pass_block - 1U) / pass_block);
            }
        }
    }

    const std::size_t checkpoint_block =
        std::min(block, checkpoint_size);
    const std::size_t checkpoint_blocks =
        checkpoint_size / checkpoint_block;
    result.indexed_read_payload_bytes +=
        3U * active_size * sizeof(Fq);
    for (std::size_t prefix = 0; prefix < prefix_count; ++prefix) {
        const std::size_t begin = prefix * checkpoint_size;
        const std::size_t available =
            begin >= active_size
                ? 0
                : std::min(checkpoint_size, active_size - begin);
        result.indexed_read_operations +=
            3U * ((available + checkpoint_block - 1U) /
                  checkpoint_block);
    }
    result.sequential_write_payload_bytes +=
        3U * checkpoint_size * sizeof(Fq2);
    result.sequential_write_operations += 3U * checkpoint_blocks;

    std::uint64_t previous = 0;
    for (std::size_t size = checkpoint_size;; size >>= 1U) {
        const std::uint64_t physical = test_scratch_artifact_bytes(size);
        result.scratch_written_physical_bytes += physical;
        result.scratch_deleted_physical_bytes += physical;
        result.scratch_artifact_validation_bytes += physical;
        result.scratch_peak_physical_bytes = std::max(
            result.scratch_peak_physical_bytes, previous + physical);
        previous = physical;
        if (size == 1) {
            break;
        }
        const std::size_t half = size / 2U;
        const std::size_t fold_block = std::min(block, half);
        const std::size_t blocks = half / fold_block;
        result.indexed_read_payload_bytes +=
            2U * 3U * size * sizeof(Fq2);
        result.indexed_read_operations += 12U * blocks;
        result.sequential_write_payload_bytes +=
            3U * half * sizeof(Fq2);
        result.sequential_write_operations += 3U * blocks;
        ++result.fold_passes;
    }
    result.sequential_read_payload_bytes = 3U * sizeof(Fq2);
    result.sequential_read_operations = 3;
    result.peak_live_storage_bytes =
        source.physical_bytes() + result.scratch_peak_physical_bytes;
    return result;
}

void test_gruen_rounds_match_naive_reference() {
    const std::vector<Fq> tau_base{Fq::one(), Fq(3), Fq(5)};
    const std::vector<Fq2> tau = lift(tau_base);
    const ConstraintFixture fixture = make_zero_sum_fixture(tau_base);
    Transcript prover("laminate/test/spartan-gruen/v1");
    const ConstraintSumcheckOutput output =
        laminate::spartan::prove_constraint_sumcheck(
            tau, fixture.az, fixture.bz, fixture.cz, prover);
    CHECK(output.proof.rounds.size() == tau.size());

    // Independent fold-per-round reference for
    //   S_i(X)=sum_u eq(tau_suffix,u)(A_i(X,u)B_i(X,u)-C_i(X,u)).
    std::vector<Fq2> az = lift(fixture.az);
    std::vector<Fq2> bz = lift(fixture.bz);
    std::vector<Fq2> cz = lift(fixture.cz);
    bool saw_nonzero_round = false;
    for (std::size_t round = 0; round < tau.size(); ++round) {
        const std::size_t half = az.size() / 2;
        const std::vector<Fq2> suffix = equality_table(
            std::span<const Fq2>(tau).subspan(round + 1));
        Fq2 at_one = Fq2::zero();
        Fq2 at_two = Fq2::zero();
        for (std::size_t index = 0; index < half; ++index) {
            const Fq2 a2 = az[half + index] + az[half + index] - az[index];
            const Fq2 b2 = bz[half + index] + bz[half + index] - bz[index];
            const Fq2 c2 = cz[half + index] + cz[half + index] - cz[index];
            at_one += suffix[index] *
                      (az[half + index] * bz[half + index] -
                       cz[half + index]);
            at_two += suffix[index] * (a2 * b2 - c2);
        }
        CHECK(output.proof.rounds[round].endpoint == at_one);
        CHECK(output.proof.rounds[round].at_two == at_two);
        saw_nonzero_round =
            saw_nonzero_round || !at_one.is_zero() || !at_two.is_zero();
        bind_first_variable(az, output.point[round]);
        bind_first_variable(bz, output.point[round]);
        bind_first_variable(cz, output.point[round]);
    }
    CHECK(saw_nonzero_round);

    Transcript verifier("laminate/test/spartan-gruen/v1");
    const auto checked = laminate::spartan::verify_constraint_sumcheck(
        output.proof, Fq2::zero(), tau, verifier);
    CHECK(checked.accepts);
    CHECK(checked.point == output.point);
    CHECK(checked.final_claim ==
          equality_evaluation(tau, checked.point) *
              (evaluate_mle(fixture.az, checked.point) *
                   evaluate_mle(fixture.bz, checked.point) -
               evaluate_mle(fixture.cz, checked.point)));
}

void test_gruen_tau_one_uses_other_endpoint() {
    const std::vector<Fq> tau_base{Fq(2), Fq::one(), Fq(5)};
    const std::vector<Fq2> tau = lift(tau_base);
    ConstraintFixture fixture = make_zero_sum_fixture(tau_base);
    // tau_1=1 gives every row with middle bit zero equality weight zero. Add
    // a residual there so the otherwise recoverable S_1(0) is visibly nonzero.
    fixture.cz[0] -= Fq(7);
    Transcript prover("laminate/test/spartan-gruen-singular/v1");
    const ConstraintSumcheckOutput output =
        laminate::spartan::prove_constraint_sumcheck(
            tau, fixture.az, fixture.bz, fixture.cz, prover);
    Transcript verifier("laminate/test/spartan-gruen-singular/v1");
    const auto checked = laminate::spartan::verify_constraint_sumcheck(
        output.proof, Fq2::zero(), tau, verifier);
    CHECK(checked.accepts);
    CHECK(checked.point == output.point);
    CHECK(checked.final_claim == output.final_claim);

    // At round one tau_1=1, so S_1(1) is the running claim. The proof must
    // carry S_1(0) in `endpoint` to retain three points for interpolation.
    std::vector<Fq2> az = lift(fixture.az);
    std::vector<Fq2> bz = lift(fixture.bz);
    std::vector<Fq2> cz = lift(fixture.cz);
    bind_first_variable(az, output.point[0]);
    bind_first_variable(bz, output.point[0]);
    bind_first_variable(cz, output.point[0]);
    const std::vector<Fq2> suffix = equality_table(
        std::span<const Fq2>(tau).subspan(2));
    Fq2 expected_at_zero = Fq2::zero();
    for (std::size_t index = 0; index < az.size() / 2; ++index) {
        expected_at_zero +=
            suffix[index] * (az[index] * bz[index] - cz[index]);
    }
    CHECK(!expected_at_zero.is_zero());
    CHECK(output.proof.rounds[1].endpoint == expected_at_zero);
}

void test_source_rounds_preserve_constraint_transcript() {
    const std::vector<Fq> tau_base{Fq(2), Fq(3), Fq(5)};
    const std::vector<Fq2> tau = lift(tau_base);
    const ConstraintFixture fixture = make_zero_sum_fixture(tau_base);
    Transcript immediate("laminate/test/spartan-source-constraint/v1");
    const ConstraintSumcheckOutput baseline =
        laminate::spartan::prove_constraint_sumcheck(
            tau, fixture.az, fixture.bz, fixture.cz, immediate, 0);
    Transcript deferred("laminate/test/spartan-source-constraint/v1");
    const ConstraintSumcheckOutput optimized =
        laminate::spartan::prove_constraint_sumcheck(
            tau, fixture.az, fixture.bz, fixture.cz, deferred, 2);

    CHECK(optimized.proof.rounds == baseline.proof.rounds);
    CHECK(optimized.point == baseline.point);
    CHECK(optimized.final_claim == baseline.final_claim);
    CHECK(optimized.az_evaluation == baseline.az_evaluation);
    CHECK(optimized.bz_evaluation == baseline.bz_evaluation);
    CHECK(optimized.cz_evaluation == baseline.cz_evaluation);
}

void test_source_round_boundaries() {
    for (std::size_t variables = 0; variables <= 2; ++variables) {
        const std::size_t table_size = std::size_t{1} << variables;
        std::vector<Fq2> tau;
        std::vector<Fq> az;
        std::vector<Fq> bz;
        std::vector<Fq> cz;
        std::vector<Fq2> matrix;
        std::vector<Fq> assignment;
        Fq2 wiring_claim = Fq2::zero();
        for (std::size_t variable = 0; variable < variables; ++variable) {
            tau.push_back(Fq2::from_base(Fq(variable + 2)));
        }
        for (std::size_t index = 0; index < table_size; ++index) {
            az.push_back(Fq(3 * index + 2));
            bz.push_back(Fq(5 * index + 7));
            cz.push_back(az.back() * bz.back());
            matrix.push_back(
                Fq2({Fq(2 * index + 1), Fq(3 * index + 4)}));
            assignment.push_back(Fq(7 * index + 3));
            wiring_claim += matrix.back() * assignment.back();
        }

        Transcript constraint_baseline(
            "laminate/test/spartan-source-boundary-constraint/v1");
        const ConstraintSumcheckOutput expected_constraint =
            laminate::spartan::prove_constraint_sumcheck(
                tau, az, bz, cz, constraint_baseline, 0);
        Transcript wiring_baseline(
            "laminate/test/spartan-source-boundary-wiring/v1");
        const WiringSumcheckOutput expected_wiring =
            laminate::spartan::prove_wiring_sumcheck(
                matrix, assignment, wiring_claim, wiring_baseline, 0);

        for (std::size_t source_rounds = 1; source_rounds <= 2;
             ++source_rounds) {
            Transcript constraint_candidate(
                "laminate/test/spartan-source-boundary-constraint/v1");
            const ConstraintSumcheckOutput actual_constraint =
                laminate::spartan::prove_constraint_sumcheck(
                    tau, az, bz, cz, constraint_candidate, source_rounds);
            CHECK(actual_constraint.proof.rounds ==
                  expected_constraint.proof.rounds);
            CHECK(actual_constraint.point == expected_constraint.point);
            CHECK(actual_constraint.final_claim ==
                  expected_constraint.final_claim);
            CHECK(actual_constraint.az_evaluation ==
                  expected_constraint.az_evaluation);
            CHECK(actual_constraint.bz_evaluation ==
                  expected_constraint.bz_evaluation);
            CHECK(actual_constraint.cz_evaluation ==
                  expected_constraint.cz_evaluation);

            Transcript wiring_candidate(
                "laminate/test/spartan-source-boundary-wiring/v1");
            const WiringSumcheckOutput actual_wiring =
                laminate::spartan::prove_wiring_sumcheck(
                    matrix, assignment, wiring_claim, wiring_candidate,
                    source_rounds);
            CHECK(actual_wiring.proof.rounds ==
                  expected_wiring.proof.rounds);
            CHECK(actual_wiring.point == expected_wiring.point);
            CHECK(actual_wiring.final_claim == expected_wiring.final_claim);
            CHECK(actual_wiring.matrix_evaluation ==
                  expected_wiring.matrix_evaluation);
            CHECK(actual_wiring.assignment_evaluation ==
                  expected_wiring.assignment_evaluation);
        }
    }
}

void test_tau_one_across_source_transition() {
    for (std::size_t singular_variable = 0; singular_variable < 3;
         ++singular_variable) {
        std::vector<Fq> tau_base{Fq(2), Fq(3), Fq(5)};
        tau_base[singular_variable] = Fq::one();
        const std::vector<Fq2> tau = lift(tau_base);
        const ConstraintFixture fixture = make_zero_sum_fixture(tau_base);
        Transcript baseline(
            "laminate/test/spartan-source-tau-one/v1");
        const ConstraintSumcheckOutput expected =
            laminate::spartan::prove_constraint_sumcheck(
                tau, fixture.az, fixture.bz, fixture.cz, baseline, 0);
        Transcript candidate(
            "laminate/test/spartan-source-tau-one/v1");
        const ConstraintSumcheckOutput actual =
            laminate::spartan::prove_constraint_sumcheck(
                tau, fixture.az, fixture.bz, fixture.cz, candidate, 2);
        CHECK(actual.proof.rounds == expected.proof.rounds);
        CHECK(actual.point == expected.point);
        CHECK(actual.final_claim == expected.final_claim);
        CHECK(actual.az_evaluation == expected.az_evaluation);
        CHECK(actual.bz_evaluation == expected.bz_evaluation);
        CHECK(actual.cz_evaluation == expected.cz_evaluation);
    }
}

void test_source_round_limit() {
    const std::vector<Fq> tau_base{Fq(2), Fq(3), Fq(5)};
    const std::vector<Fq2> tau = lift(tau_base);
    const ConstraintFixture fixture = make_zero_sum_fixture(tau_base);
    bool constraint_rejected = false;
    try {
        Transcript transcript("laminate/test/spartan-source-limit/v1");
        (void)laminate::spartan::prove_constraint_sumcheck(
            tau, fixture.az, fixture.bz, fixture.cz, transcript, 3);
    } catch (const std::invalid_argument &) {
        constraint_rejected = true;
    }
    CHECK(constraint_rejected);

    std::vector<Fq2> matrix(8, Fq2::one());
    std::vector<Fq> assignment(8, Fq::one());
    bool wiring_rejected = false;
    try {
        Transcript transcript("laminate/test/spartan-source-limit/v1");
        (void)laminate::spartan::prove_wiring_sumcheck(
            matrix, assignment, Fq2::from_base(Fq(8)), transcript, 3);
    } catch (const std::invalid_argument &) {
        wiring_rejected = true;
    }
    CHECK(wiring_rejected);
}

void test_wiring_omits_zero_and_rejects_tampering_at_terminal() {
    std::vector<Fq2> matrix;
    std::vector<Fq> assignment;
    Fq2 claimed = Fq2::zero();
    for (std::size_t index = 0; index < 8; ++index) {
        matrix.push_back(Fq2({Fq(2 * index + 1), Fq(3 * index + 4)}));
        assignment.push_back(Fq(7 * index + 3));
        claimed += matrix.back() * assignment.back();
    }
    Transcript prover("laminate/test/spartan-wiring/v1");
    const WiringSumcheckOutput output =
        laminate::spartan::prove_wiring_sumcheck(
            matrix, assignment, claimed, prover);
    Transcript verifier("laminate/test/spartan-wiring/v1");
    const auto checked = laminate::spartan::verify_wiring_sumcheck(
        output.proof, claimed, verifier);
    CHECK(checked.accepts);
    CHECK(checked.point == output.point);
    CHECK(checked.final_claim ==
          output.matrix_evaluation * output.assignment_evaluation);

    auto tampered = output.proof;
    tampered.rounds.front().at_two += Fq2::one();
    Transcript bad("laminate/test/spartan-wiring/v1");
    const auto rejected = laminate::spartan::verify_wiring_sumcheck(
        tampered, claimed, bad);
    CHECK(rejected.accepts);
    CHECK(rejected.final_claim !=
          evaluate_mle(assignment, rejected.point) *
              evaluate_mle(matrix, rejected.point));
}

void test_source_rounds_preserve_wiring_transcript() {
    std::vector<Fq2> matrix;
    std::vector<Fq> assignment;
    Fq2 claimed = Fq2::zero();
    for (std::size_t index = 0; index < 16; ++index) {
        matrix.push_back(Fq2({Fq(2 * index + 1), Fq(3 * index + 4)}));
        assignment.push_back(Fq(7 * index + 3));
        claimed += matrix.back() * assignment.back();
    }
    Transcript immediate("laminate/test/spartan-source-wiring/v1");
    const WiringSumcheckOutput baseline =
        laminate::spartan::prove_wiring_sumcheck(
            matrix, assignment, claimed, immediate, 0);
    Transcript deferred("laminate/test/spartan-source-wiring/v1");
    const WiringSumcheckOutput optimized =
        laminate::spartan::prove_wiring_sumcheck(
            matrix, assignment, claimed, deferred, 2);

    CHECK(optimized.proof.rounds == baseline.proof.rounds);
    CHECK(optimized.point == baseline.point);
    CHECK(optimized.final_claim == baseline.final_claim);
    CHECK(optimized.matrix_evaluation == baseline.matrix_evaluation);
    CHECK(optimized.assignment_evaluation == baseline.assignment_evaluation);
}

void test_artifact_constraint_sumcheck_matches_resident() {
    const std::vector<Fq> tau_base{
        Fq(2), Fq::one(), Fq(5), Fq(7), Fq(11)};
    const std::vector<Fq2> tau = lift(tau_base);
    const ConstraintFixture fixture = make_zero_sum_fixture(tau_base);
    TemporaryDirectory source_directory("parity-source");
    const auto source = write_constraint_source(
        source_directory.path(), fixture.az, fixture.bz, fixture.cz);
    const std::uint64_t source_bytes = source.physical_bytes();
    const auto source_arrays = source.arrays();

    for (std::size_t source_rounds = 0; source_rounds <= 4;
         ++source_rounds) {
        for (const std::size_t requested_block :
             std::array<std::size_t, 3>{1, 3, 8}) {
            Transcript resident(
                "laminate/test/artifact-constraint-parity/v1");
            const ConstraintSumcheckOutput expected =
                laminate::spartan::prove_constraint_sumcheck(
                    tau, fixture.az, fixture.bz, fixture.cz, resident, 0);
            const Fq2 expected_next = resident.challenge_fq2();

            TemporaryDirectory scratch(
                "parity-s" + std::to_string(source_rounds) + "-b" +
                std::to_string(requested_block));
            Transcript external(
                "laminate/test/artifact-constraint-parity/v1");
            const auto actual =
                laminate::spartan::prove_constraint_sumcheck_artifact(
                    source, constraint_source_names(), tau, external,
                    artifact_options(scratch.path(), source_rounds,
                                     requested_block));
            const Fq2 actual_next = external.challenge_fq2();

            CHECK(constraint_proof_bytes(actual.sumcheck.proof) ==
                  constraint_proof_bytes(expected.proof));
            CHECK(actual.sumcheck.proof.rounds == expected.proof.rounds);
            CHECK(actual.sumcheck.point == expected.point);
            CHECK(actual.sumcheck.final_claim == expected.final_claim);
            CHECK(actual.sumcheck.az_evaluation == expected.az_evaluation);
            CHECK(actual.sumcheck.bz_evaluation == expected.bz_evaluation);
            CHECK(actual.sumcheck.cz_evaluation == expected.cz_evaluation);
            CHECK(actual_next == expected_next);
            CHECK(actual.report == expected_artifact_report(
                                       source, fixture.az.size(),
                                       fixture.az.size(),
                                       source_rounds, requested_block));
            CHECK(std::filesystem::is_empty(scratch.path()));
            CHECK(source.physical_bytes() == source_bytes);
            CHECK(source.arrays() == source_arrays);
            CHECK(recursive_file_bytes(source_directory.path()) ==
                  source_bytes);

            Transcript verifier(
                "laminate/test/artifact-constraint-parity/v1");
            const auto checked =
                laminate::spartan::verify_constraint_sumcheck(
                    actual.sumcheck.proof, Fq2::zero(), tau, verifier);
            CHECK(checked.accepts);
            CHECK(checked.point == actual.sumcheck.point);
            CHECK(checked.final_claim == actual.sumcheck.final_claim);
        }
    }
}

void test_artifact_constraint_zero_extends_active_prefix() {
    constexpr std::size_t kLogicalDomain = 32;
    constexpr std::size_t kActiveRows = 19;
    const std::vector<Fq> tau_base{
        Fq(2), Fq::one(), Fq(5), Fq(7), Fq(11)};
    const std::vector<Fq2> tau = lift(tau_base);
    const ConstraintFixture complete = make_zero_sum_fixture(tau_base);
    ConstraintFixture active{
        .az = {complete.az.begin(), complete.az.begin() + kActiveRows},
        .bz = {complete.bz.begin(), complete.bz.begin() + kActiveRows},
        .cz = {complete.cz.begin(), complete.cz.begin() + kActiveRows},
    };
    ConstraintFixture padded = active;
    padded.az.resize(kLogicalDomain, Fq::zero());
    padded.bz.resize(kLogicalDomain, Fq::zero());
    padded.cz.resize(kLogicalDomain, Fq::zero());

    TemporaryDirectory source_directory("active-prefix-source");
    const auto source = write_constraint_source(
        source_directory.path(), active.az, active.bz, active.cz);
    const std::uint64_t source_bytes = source.physical_bytes();
    const auto source_arrays = source.arrays();

    for (std::size_t source_rounds = 0; source_rounds <= 4;
         ++source_rounds) {
        Transcript resident(
            "laminate/test/artifact-constraint-active-prefix/v1");
        const ConstraintSumcheckOutput expected =
            laminate::spartan::prove_constraint_sumcheck(
                tau, padded.az, padded.bz, padded.cz, resident, 0);
        const Fq2 expected_next = resident.challenge_fq2();

        TemporaryDirectory scratch(
            "active-prefix-s" + std::to_string(source_rounds));
        auto options = artifact_options(
            scratch.path(), source_rounds, 8);
        options.logical_domain_size = kLogicalDomain;
        Transcript external(
            "laminate/test/artifact-constraint-active-prefix/v1");
        const auto actual =
            laminate::spartan::prove_constraint_sumcheck_artifact(
                source, constraint_source_names(), tau, external,
                options);
        const Fq2 actual_next = external.challenge_fq2();

        CHECK(constraint_proof_bytes(actual.sumcheck.proof) ==
              constraint_proof_bytes(expected.proof));
        CHECK(actual.sumcheck.proof.rounds == expected.proof.rounds);
        CHECK(actual.sumcheck.point == expected.point);
        CHECK(actual.sumcheck.final_claim == expected.final_claim);
        CHECK(actual.sumcheck.az_evaluation == expected.az_evaluation);
        CHECK(actual.sumcheck.bz_evaluation == expected.bz_evaluation);
        CHECK(actual.sumcheck.cz_evaluation == expected.cz_evaluation);
        CHECK(actual_next == expected_next);
        CHECK(actual.report == expected_artifact_report(
                                   source, kActiveRows, kLogicalDomain,
                                   source_rounds, 8));
        CHECK(actual.report.selected_source_payload_bytes ==
              3U * kActiveRows * sizeof(Fq));
        CHECK(actual.report.indexed_read_payload_bytes >=
              (source_rounds + 1U) * 3U * kActiveRows * sizeof(Fq));
        CHECK(std::filesystem::is_empty(scratch.path()));
        CHECK(source.physical_bytes() == source_bytes);
        CHECK(source.arrays() == source_arrays);
        CHECK(recursive_file_bytes(source_directory.path()) ==
              source_bytes);
    }
}

void test_artifact_constraint_accepts_one_active_row() {
    constexpr std::size_t kLogicalDomain = 32;
    const std::vector<Fq> tau_base{
        Fq(2), Fq(3), Fq::one(), Fq(7), Fq(11)};
    const std::vector<Fq2> tau = lift(tau_base);
    const ConstraintFixture active{
        .az = {Fq(3)},
        .bz = {Fq(5)},
        .cz = {Fq(15)},
    };
    ConstraintFixture padded = active;
    padded.az.resize(kLogicalDomain, Fq::zero());
    padded.bz.resize(kLogicalDomain, Fq::zero());
    padded.cz.resize(kLogicalDomain, Fq::zero());
    TemporaryDirectory source_directory("one-active-source");
    const auto source = write_constraint_source(
        source_directory.path(), active.az, active.bz, active.cz);
    TemporaryDirectory scratch("one-active-scratch");
    auto options = artifact_options(scratch.path(), 4, 8);
    options.logical_domain_size = kLogicalDomain;

    Transcript resident("laminate/test/artifact-one-active/v1");
    const auto expected = laminate::spartan::prove_constraint_sumcheck(
        tau, padded.az, padded.bz, padded.cz, resident, 0);
    Transcript external("laminate/test/artifact-one-active/v1");
    const auto actual =
        laminate::spartan::prove_constraint_sumcheck_artifact(
            source, constraint_source_names(), tau, external, options);
    CHECK(actual.sumcheck.proof.rounds == expected.proof.rounds);
    CHECK(actual.sumcheck.point == expected.point);
    CHECK(actual.sumcheck.az_evaluation == expected.az_evaluation);
    CHECK(actual.sumcheck.bz_evaluation == expected.bz_evaluation);
    CHECK(actual.sumcheck.cz_evaluation == expected.cz_evaluation);
    CHECK(actual.report == expected_artifact_report(
                               source, 1, kLogicalDomain, 4, 8));
    CHECK(std::filesystem::is_empty(scratch.path()));
}

void test_artifact_constraint_memory_selects_smaller_block() {
    const std::vector<Fq> tau_base{Fq(2), Fq(3), Fq(5), Fq(7), Fq(11)};
    const std::vector<Fq2> tau = lift(tau_base);
    const ConstraintFixture fixture = make_zero_sum_fixture(tau_base);
    TemporaryDirectory source_directory("memory-source");
    const auto source = write_constraint_source(
        source_directory.path(), fixture.az, fixture.bz, fixture.cz);
    TemporaryDirectory scratch("memory-scratch");
    constexpr std::uint64_t kMemoryLimit = 400;
    Transcript resident("laminate/test/artifact-constraint-memory/v1");
    const auto expected = laminate::spartan::prove_constraint_sumcheck(
        tau, fixture.az, fixture.bz, fixture.cz, resident, 0);
    Transcript external("laminate/test/artifact-constraint-memory/v1");
    const auto actual =
        laminate::spartan::prove_constraint_sumcheck_artifact(
            source, constraint_source_names(), tau, external,
            artifact_options(scratch.path(), 2, 8, kMemoryLimit));
    CHECK(actual.sumcheck.proof.rounds == expected.proof.rounds);
    CHECK(actual.sumcheck.point == expected.point);
    CHECK(actual.report.effective_block_elements == 2);
    CHECK(actual.report == expected_artifact_report(
                               source, fixture.az.size(), fixture.az.size(),
                               2, 8,
                               kMemoryLimit));
    CHECK(std::filesystem::is_empty(scratch.path()));
}

void test_artifact_constraint_small_domains() {
    for (std::size_t variables = 0; variables <= 3; ++variables) {
        const std::size_t domain_size = std::size_t{1} << variables;
        std::vector<Fq> tau_base;
        std::vector<Fq2> tau;
        for (std::size_t variable = 0; variable < variables; ++variable) {
            tau_base.push_back(Fq(variable + 2));
            tau.push_back(Fq2::from_base(tau_base.back()));
        }
        ConstraintFixture fixture;
        for (std::size_t index = 0; index < domain_size; ++index) {
            fixture.az.push_back(Fq(3 * index + 2));
            fixture.bz.push_back(Fq(5 * index + 7));
            fixture.cz.push_back(fixture.az.back() * fixture.bz.back());
        }
        TemporaryDirectory source_directory(
            "small-source-" + std::to_string(variables));
        const auto source = write_constraint_source(
            source_directory.path(), fixture.az, fixture.bz, fixture.cz);
        for (std::size_t source_rounds = 0; source_rounds <= variables;
             ++source_rounds) {
            Transcript resident(
                "laminate/test/artifact-constraint-small/v1");
            const auto expected =
                laminate::spartan::prove_constraint_sumcheck(
                    tau, fixture.az, fixture.bz, fixture.cz, resident, 0);
            TemporaryDirectory scratch(
                "small-scratch-" + std::to_string(variables) + "-" +
                std::to_string(source_rounds));
            Transcript external(
                "laminate/test/artifact-constraint-small/v1");
            const auto actual =
                laminate::spartan::prove_constraint_sumcheck_artifact(
                    source, constraint_source_names(), tau, external,
                    artifact_options(scratch.path(), source_rounds, 3));
            CHECK(actual.sumcheck.proof.rounds == expected.proof.rounds);
            CHECK(actual.sumcheck.point == expected.point);
            CHECK(actual.sumcheck.final_claim == expected.final_claim);
            CHECK(actual.sumcheck.az_evaluation == expected.az_evaluation);
            CHECK(actual.sumcheck.bz_evaluation == expected.bz_evaluation);
            CHECK(actual.sumcheck.cz_evaluation == expected.cz_evaluation);
            CHECK(actual.report == expected_artifact_report(
                                       source, domain_size, domain_size,
                                       source_rounds, 3));
            CHECK(std::filesystem::is_empty(scratch.path()));
        }
    }
}

void test_artifact_constraint_rejects_invalid_resources_and_sources() {
    const std::vector<Fq> tau_base{Fq(2), Fq(3), Fq(5), Fq(7)};
    const std::vector<Fq2> tau = lift(tau_base);
    const ConstraintFixture fixture = make_zero_sum_fixture(tau_base);
    TemporaryDirectory source_directory("reject-source");
    const auto source = write_constraint_source(
        source_directory.path(), fixture.az, fixture.bz, fixture.cz);
    const std::uint64_t source_bytes = source.physical_bytes();
    const auto source_arrays = source.arrays();

    std::uint64_t exact_scratch_peak = 0;
    {
        TemporaryDirectory scratch("reject-baseline");
        Transcript transcript(
            "laminate/test/artifact-constraint-reject/v1");
        const auto baseline =
            laminate::spartan::prove_constraint_sumcheck_artifact(
                source, constraint_source_names(), tau, transcript,
                artifact_options(scratch.path(), 2, 3));
        exact_scratch_peak = baseline.report.scratch_peak_physical_bytes;
    }

    const auto fails_cleanly =
        [&](ConstraintSumcheckArtifactArrays names,
            std::span<const Fq2> selected_tau, const auto &configure) {
            TemporaryDirectory scratch("reject-case");
            auto options = artifact_options(scratch.path(), 2, 3);
            configure(options, scratch);
            Transcript transcript(
                "laminate/test/artifact-constraint-reject/v1");
            CHECK(throws_exception([&] {
                (void)laminate::spartan::
                    prove_constraint_sumcheck_artifact(
                        source, names, selected_tau, transcript, options);
            }));
            CHECK(std::filesystem::is_empty(scratch.path()));
            CHECK(source.physical_bytes() == source_bytes);
            CHECK(source.arrays() == source_arrays);
            CHECK(recursive_file_bytes(source_directory.path()) ==
                  source_bytes);
        };

    fails_cleanly(constraint_source_names(), tau,
                  [](auto &options, const auto &) {
                      options.expected_source_identity[0] ^= 1U;
                  });
    fails_cleanly(constraint_source_names(), tau,
                  [exact_scratch_peak](auto &options, const auto &) {
                      options.max_total_scratch_bytes =
                          exact_scratch_peak - 1U;
                  });
    fails_cleanly(constraint_source_names(), tau,
                  [](auto &options, const auto &) {
                      options.max_live_storage_bytes = 1;
                  });
    fails_cleanly(constraint_source_names(), tau,
                  [](auto &options, const auto &) {
                      options.max_working_field_bytes = 1;
                  });
    fails_cleanly(constraint_source_names(), tau,
                  [](auto &options, const auto &) {
                      options.source_rounds = 5;
                  });
    fails_cleanly({.az = "az-values",
                   .bz = "az-values",
                   .cz = "cz-values"},
                  tau, [](auto &, const auto &) {});
    fails_cleanly({.az = "missing",
                   .bz = "bz-values",
                   .cz = "cz-values"},
                  tau, [](auto &, const auto &) {});
    fails_cleanly(constraint_source_names(),
                  std::span<const Fq2>(tau).first(tau.size() - 1U),
                  [](auto &, const auto &) {});
    fails_cleanly(constraint_source_names(), tau,
                  [](auto &options, const auto &) {
                      options.logical_domain_size = 8;
                  });
    fails_cleanly(constraint_source_names(), tau,
                  [](auto &options, const auto &) {
                      options.logical_domain_size = 12;
                  });
    fails_cleanly(constraint_source_names(), tau,
                  [](auto &options, const auto &) {
                      options.logical_domain_size = 32;
                  });
    fails_cleanly(
        constraint_source_names(), tau,
        [exact_scratch_peak](auto &options, const auto &scratch) {
            const std::uint64_t available =
                std::filesystem::space(scratch.path()).available;
            CHECK(available > exact_scratch_peak);
            options.min_free_bytes =
                available - exact_scratch_peak + 1U;
        });

    {
        TemporaryDirectory scratch("reject-nonempty");
        const std::filesystem::path marker = scratch.path() / "occupied";
        std::ofstream output(marker);
        output << "occupied";
        output.close();
        Transcript transcript(
            "laminate/test/artifact-constraint-reject/v1");
        CHECK(throws_exception([&] {
            (void)laminate::spartan::prove_constraint_sumcheck_artifact(
                source, constraint_source_names(), tau, transcript,
                artifact_options(scratch.path(), 2, 3));
        }));
        CHECK(std::filesystem::exists(marker));
    }

    {
        TemporaryDirectory unequal_directory("unequal-source");
        const auto unequal = write_constraint_source(
            unequal_directory.path(), fixture.az,
            std::span<const Fq>(fixture.bz).first(fixture.bz.size() / 2U),
            fixture.cz);
        TemporaryDirectory scratch("unequal-scratch");
        Transcript transcript(
            "laminate/test/artifact-constraint-reject/v1");
        CHECK(throws_exception([&] {
            (void)laminate::spartan::prove_constraint_sumcheck_artifact(
                unequal, constraint_source_names(), tau, transcript,
                artifact_options(scratch.path(), 2, 3));
        }));
        CHECK(std::filesystem::is_empty(scratch.path()));
    }
    {
        TemporaryDirectory nonpower_directory("nonpower-source");
        std::vector<Fq> values(6, Fq::one());
        const auto nonpower = write_constraint_source(
            nonpower_directory.path(), values, values, values);
        TemporaryDirectory scratch("nonpower-scratch");
        Transcript transcript(
            "laminate/test/artifact-constraint-reject/v1");
        CHECK(throws_exception([&] {
            (void)laminate::spartan::prove_constraint_sumcheck_artifact(
                nonpower, constraint_source_names(), tau, transcript,
                artifact_options(scratch.path(), 2, 3));
        }));
        CHECK(std::filesystem::is_empty(scratch.path()));
    }
    {
        TemporaryDirectory type_directory("type-source");
        laminate::storage::NativeFieldArtifactWriter writer(
            type_directory.path(),
            {.max_total_bytes = 1ULL << 24U, .min_free_bytes = 1},
            constraint_source_identity());
        writer.begin_array("az-values",
                           laminate::storage::NativeFieldElementKind::Fq,
                           fixture.az.size());
        writer.append(fixture.az);
        writer.finish_array();
        std::vector<Fq2> wrong_kind(fixture.bz.size(), Fq2::one());
        writer.begin_array("bz-values",
                           laminate::storage::NativeFieldElementKind::Fq2,
                           wrong_kind.size());
        writer.append(wrong_kind);
        writer.finish_array();
        writer.begin_array("cz-values",
                           laminate::storage::NativeFieldElementKind::Fq,
                           fixture.cz.size());
        writer.append(fixture.cz);
        writer.finish_array();
        (void)writer.finish();
        const auto wrong_type =
            laminate::storage::NativeFieldArtifact::open(
                type_directory.path(), constraint_source_identity());
        TemporaryDirectory scratch("type-scratch");
        Transcript transcript(
            "laminate/test/artifact-constraint-reject/v1");
        CHECK(throws_exception([&] {
            (void)laminate::spartan::prove_constraint_sumcheck_artifact(
                wrong_type, constraint_source_names(), tau, transcript,
                artifact_options(scratch.path(), 2, 3));
        }));
        CHECK(std::filesystem::is_empty(scratch.path()));
    }

    {
        TemporaryDirectory corrupt_directory("corrupt-source");
        auto corrupt = write_constraint_source(
            corrupt_directory.path(), fixture.az, fixture.bz, fixture.cz);
        std::fstream bytes(
            corrupt_directory.path() / "array-0000000000000000.bin",
            std::ios::binary | std::ios::in | std::ios::out);
        CHECK(static_cast<bool>(bytes));
        bytes.seekg(-1, std::ios::end);
        char value = 0;
        bytes.read(&value, 1);
        bytes.seekp(-1, std::ios::end);
        value ^= 1;
        bytes.write(&value, 1);
        bytes.close();
        TemporaryDirectory scratch("corrupt-scratch");
        Transcript transcript(
            "laminate/test/artifact-constraint-reject/v1");
        CHECK(throws_exception([&] {
            (void)laminate::spartan::prove_constraint_sumcheck_artifact(
                corrupt, constraint_source_names(), tau, transcript,
                artifact_options(scratch.path(), 2, 3));
        }));
        CHECK(std::filesystem::is_empty(scratch.path()));
    }
}

void test_artifact_constraint_late_failure_cleans_but_advances_coin() {
#ifndef _WIN32
    const std::vector<Fq> tau_base{Fq(2), Fq(3), Fq(5), Fq(7)};
    const std::vector<Fq2> tau = lift(tau_base);
    const ConstraintFixture fixture = make_zero_sum_fixture(tau_base);
    TemporaryDirectory source_directory("late-source");
    const auto source = write_constraint_source(
        source_directory.path(), fixture.az, fixture.bz, fixture.cz);
    const std::uint64_t source_bytes = source.physical_bytes();
    const auto source_arrays = source.arrays();
    TemporaryDirectory scratch("late-scratch");
    std::filesystem::permissions(
        scratch.path(),
        std::filesystem::perms::owner_read |
            std::filesystem::perms::owner_exec,
        std::filesystem::perm_options::replace);
    Transcript failed("laminate/test/artifact-constraint-late/v1");
    const bool rejected = throws_exception([&] {
        (void)laminate::spartan::prove_constraint_sumcheck_artifact(
            source, constraint_source_names(), tau, failed,
            artifact_options(scratch.path(), 1, 3));
    });
    std::filesystem::permissions(
        scratch.path(), std::filesystem::perms::owner_all,
        std::filesystem::perm_options::replace);
    CHECK(rejected);
    CHECK(std::filesystem::is_empty(scratch.path()));
    CHECK(source.physical_bytes() == source_bytes);
    CHECK(source.arrays() == source_arrays);
    CHECK(recursive_file_bytes(source_directory.path()) == source_bytes);

    Transcript fresh("laminate/test/artifact-constraint-late/v1");
    CHECK(failed.challenge_fq2() != fresh.challenge_fq2());
#endif
}

void test_artifact_constraint_target_geometry() {
    // ConstraintCheck uses the padded row domain C_x=2^32. The separate
    // WiringCheck/assignment domain C_y=2^33 must not leak into these bounds.
    const std::size_t domain_size = std::size_t{1} << 32U;
    const std::size_t wiring_domain_size = std::size_t{1} << 33U;
    const std::size_t active_size = 3'278'045'184ULL;
    const std::size_t source_rounds = 4;
    const std::size_t block_elements = std::size_t{1} << 17U;
    const std::size_t checkpoint_size = domain_size >> source_rounds;
    const std::uint64_t selected_source_bytes =
        3U * active_size * sizeof(Fq);
    const std::uint64_t canonical_source_reads =
        (source_rounds + 1U) * selected_source_bytes;
    CHECK(2U * domain_size == wiring_domain_size);
    CHECK(selected_source_bytes == 78'673'084'416ULL);
    CHECK(canonical_source_reads == 393'365'422'080ULL);

    const std::uint64_t checkpoint_bytes =
        test_scratch_artifact_bytes(checkpoint_size);
    const std::uint64_t successor_bytes =
        test_scratch_artifact_bytes(checkpoint_size / 2U);
    CHECK(checkpoint_bytes == 12ULL * (1ULL << 30U) + 612U);
    CHECK(checkpoint_bytes + successor_bytes ==
          18ULL * (1ULL << 30U) + 1224U);

    std::uint64_t cumulative = 0;
    for (std::size_t size = checkpoint_size;; size >>= 1U) {
        cumulative += test_scratch_artifact_bytes(size);
        if (size == 1) {
            break;
        }
    }
    CHECK(cumulative == 24ULL * (1ULL << 30U) + 17'700U);
    CHECK(test_expected_field_peak(domain_size, source_rounds,
                                   block_elements) ==
          15ULL * (1ULL << 20U) + 256U);

    std::uint64_t source_operations = 0;
    for (std::size_t round = 0; round < source_rounds; ++round) {
        const std::size_t suffix = domain_size >> (round + 1U);
        for (std::size_t prefix = 0;
             prefix < (std::size_t{1} << round); ++prefix) {
            for (std::size_t branch = 0; branch < 2; ++branch) {
                const std::size_t begin =
                    (2U * prefix + branch) * suffix;
                const std::size_t available =
                    begin >= active_size
                        ? 0
                        : std::min(suffix, active_size - begin);
                source_operations +=
                    3U * ((available + block_elements - 1U) /
                          block_elements);
            }
        }
    }
    for (std::size_t prefix = 0;
         prefix < (std::size_t{1} << source_rounds); ++prefix) {
        const std::size_t begin = prefix * checkpoint_size;
        const std::size_t available =
            begin >= active_size
                ? 0
                : std::min(checkpoint_size, active_size - begin);
        source_operations +=
            3U * ((available + block_elements - 1U) /
                  block_elements);
    }
    CHECK(source_operations == 375'150U);
}

} // namespace

int main() {
    laminate::test::Runner runner("test_spartan_sumcheck");
    runner.run("Gruen rounds match naive fold-per-round reference",
               test_gruen_rounds_match_naive_reference);
    runner.run("Gruen handles tau equal to one without extra bytes",
               test_gruen_tau_one_uses_other_endpoint);
    runner.run("source rounds preserve the constraint transcript",
               test_source_rounds_preserve_constraint_transcript);
    runner.run("source rounds cover zero-, one-, and two-variable domains",
               test_source_round_boundaries);
    runner.run("tau one works before and after the source transition",
               test_tau_one_across_source_transition);
    runner.run("source rounds are capped at the modeled schedule",
               test_source_round_limit);
    runner.run("wiring sumcheck omits zero and detects terminal tampering",
               test_wiring_omits_zero_and_rejects_tampering_at_terminal);
    runner.run("source rounds preserve the wiring transcript",
               test_source_rounds_preserve_wiring_transcript);
    runner.run("artifact constraint sumcheck matches resident bytes",
               test_artifact_constraint_sumcheck_matches_resident);
    runner.run("artifact constraint zero-extends an active prefix",
               test_artifact_constraint_zero_extends_active_prefix);
    runner.run("artifact constraint accepts one active row",
               test_artifact_constraint_accepts_one_active_row);
    runner.run("artifact constraint sumcheck selects a bounded block",
               test_artifact_constraint_memory_selects_smaller_block);
    runner.run("artifact constraint sumcheck covers small domains",
               test_artifact_constraint_small_domains);
    runner.run("artifact constraint sumcheck rejects invalid resources",
               test_artifact_constraint_rejects_invalid_resources_and_sources);
    runner.run("artifact constraint late failure cleans scratch",
               test_artifact_constraint_late_failure_cleans_but_advances_coin);
    runner.run("artifact constraint target geometry",
               test_artifact_constraint_target_geometry);
    return runner.summary();
}
