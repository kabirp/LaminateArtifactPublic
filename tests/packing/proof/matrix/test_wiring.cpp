/// @file test_wiring.cpp
/// @brief Compact row-bound packing matrix parity and resource tests.

#include "test_helpers.hpp"

#include "laminate/packing/alignment/layout.hpp"
#include "laminate/packing/proof/matrix/wiring.hpp"
#include "laminate/spartan/basefold_pcs.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <limits>
#include <memory>
#include <numeric>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

using namespace laminate;
using namespace laminate::packing;

namespace {

class TemporaryDirectory {
  public:
    explicit TemporaryDirectory(std::string_view label) {
        const auto stamp = std::chrono::steady_clock::now()
                               .time_since_epoch()
                               .count();
        for (std::size_t attempt = 0; attempt < 100; ++attempt) {
            path_ = std::filesystem::temp_directory_path() /
                    ("laminate-wiring-" + std::string(label) + "-" +
                     std::to_string(stamp) + "-" +
                     std::to_string(attempt));
            if (std::filesystem::create_directory(path_)) {
                return;
            }
        }
        throw std::runtime_error("failed to create temporary directory");
    }

    ~TemporaryDirectory() {
        std::error_code ignored;
        std::filesystem::remove_all(path_, ignored);
    }

    const std::filesystem::path &path() const { return path_; }

  private:
    std::filesystem::path path_;
};

template <typename Exception = std::exception, typename Action>
bool rejects_as(Action action) {
    try {
        action();
    } catch (const Exception &) {
        return true;
    }
    return false;
}

SignedCoefficientMask identity_coefficients(const fhe::SlotVector &slots) {
    SignedCoefficientMask result;
    result.reserve(slots.size());
    for (const Fp value : slots) {
        result.push_back(static_cast<std::int64_t>(value.value()));
    }
    return result;
}

std::vector<std::uint64_t> identity_native_ntt(
    std::span<const std::int64_t> coefficients) {
    std::vector<std::uint64_t> result;
    result.reserve(coefficients.size());
    for (const std::int64_t coefficient : coefficients) {
        const std::uint64_t magnitude =
            coefficient >= 0
                ? static_cast<std::uint64_t>(coefficient)
                : std::uint64_t{0} -
                      static_cast<std::uint64_t>(coefficient);
        result.push_back(
            coefficient >= 0 || magnitude == 0
                ? magnitude % kOuterFieldOrder
                : (kOuterFieldOrder - magnitude % kOuterFieldOrder) %
                      kOuterFieldOrder);
    }
    return result;
}

OuterRelationPlan make_test_plan(
    const NativePackingOperator &native,
    gkr::CiphertextCommitmentPolicy policy) {
    OuterRelationPlan result = make_outer_relation_plan(native, 2, 2, 5);
    result.shape.ciphertext_commitment_policy = policy;
    return result;
}

struct Fixture {
    BalancedRadix radix =
        make_minimal_balanced_radix(kBaseFieldOrder, 17);
    PackingLinearOperator logical = make_packing_linear_operator(
        make_prefix_packing_layout(
            16, std::vector<std::size_t>{4, 4, 4}));
    NativePackingOperator native =
        make_native_signed_digit_packing_operator(
            logical, identity_coefficients, identity_native_ntt,
            kOuterFieldOrder, radix);
    OuterRelationPlan plan;
    CompiledProofOfPackingR1cs compiled;

    explicit Fixture(
        gkr::CiphertextCommitmentPolicy commitment_policy =
            gkr::CiphertextCommitmentPolicy::poseidon_v2())
        : plan(make_test_plan(native, commitment_policy)),
          compiled(compile_proof_of_packing_r1cs(
              plan, logical,
              {.centered_coefficients = identity_coefficients,
               .native_ntt = identity_native_ntt},
              radix)) {}
};

spartan::FactoredMatrixArtifactOptions factored_options(
    const std::filesystem::path &directory) {
    return {
        .directory = directory,
        .limits = {
            .max_total_bytes = 1ULL << 24U,
            .min_free_bytes = 1,
        },
    };
}

ProofOfPackingWiringArtifactOptions wiring_options(
    const std::filesystem::path &directory,
    std::uint64_t max_total_bytes = 1ULL << 28U,
    std::uint64_t max_working_field_bytes = 1ULL << 20U,
    std::size_t block_elements = 7,
    std::uint64_t max_live_storage_bytes = 1ULL << 29U) {
    return {
        .directory = directory,
        .storage_limits = {
            .max_total_bytes = max_total_bytes,
            .min_free_bytes = 1,
        },
        .max_live_storage_bytes = max_live_storage_bytes,
        .max_working_field_bytes = max_working_field_bytes,
        .block_elements = block_elements,
    };
}

spartan::FactoredMatrixSetup write_factored_source(
    const Fixture &fixture, const std::filesystem::path &directory) {
    std::vector<PackingTensor> tensors = compile_packing_tensors(
        fixture.plan, fixture.native);
    const auto structure = make_proof_of_packing_factored_structure(
        fixture.plan, fixture.compiled.layout, tensors,
        fixture.compiled.circuit.metadata());
    std::vector<std::vector<std::vector<Fq>>> columns;
    columns.reserve(tensors.size());
    for (PackingTensor &tensor : tensors) {
        columns.push_back(std::move(tensor.digit_columns));
    }
    const spartan::BaseFoldPcs pcs(
        {.log_rate = 1, .query_count = 1});
    return spartan::preprocess_factored_matrix_to_artifact(
        structure, std::move(columns), pcs,
        factored_options(directory));
}

std::vector<Fq2> row_point(const spartan::R1csMetadata &metadata) {
    std::vector<Fq2> result;
    result.reserve(metadata.row_variables());
    for (std::size_t index = 0; index < metadata.row_variables(); ++index) {
        result.emplace_back(Fq2::Coefficients{
            Fq(7 + 13 * index), Fq(19 + 17 * index)});
    }
    return result;
}

std::vector<Fq2> read_array(
    const storage::NativeFieldArtifact &artifact,
    std::string_view name) {
    auto reader = artifact.open_array(name);
    std::vector<Fq2> result(static_cast<std::size_t>(reader.size()));
    CHECK(reader.read(result) == result.size());
    return result;
}

void flip_last_byte(const std::filesystem::path &path) {
    std::fstream file(path, std::ios::in | std::ios::out | std::ios::binary);
    if (!file) {
        throw std::runtime_error("failed to open artifact for corruption");
    }
    file.seekg(-1, std::ios::end);
    char value = 0;
    file.read(&value, 1);
    value ^= 1;
    file.seekp(-1, std::ios::end);
    file.write(&value, 1);
}

} // namespace

int main() {
    test::Runner runner("test_proof_of_packing_wiring");

    runner.run("compact prefixes reconstruct the resident Wiring table", [] {
        const Fixture fixture;
        const auto metadata = fixture.compiled.circuit.metadata();
        CHECK(fixture.plan.shape.aligned_ciphertexts == 3);
        CHECK(fixture.compiled.layout.ciphertext_segments.size() > 1);
        CHECK(fixture.native.nonzero_constant_matrix_terms(2) > 0);

        TemporaryDirectory factored_directory("factored");
        TemporaryDirectory wiring_directory("matrix");
        const auto factored = write_factored_source(
            fixture, factored_directory.path());
        const std::vector<Fq2> rx = row_point(metadata);
        const Fq2 gamma(
            Fq2::Coefficients{Fq(313), Fq(911)});
        const ProofOfPackingWiringArtifact compact =
            write_proof_of_packing_wiring_matrix_artifact(
                fixture.plan, fixture.compiled.layout, metadata,
                factored.prover_key, rx, gamma,
                wiring_options(wiring_directory.path()));

        const std::vector<Fq2> expected =
            fixture.compiled.circuit.batched_wiring_table(rx, gamma);
        std::vector<Fq2> reconstructed(expected.size(), Fq2::zero());
        read_proof_of_packing_wiring_matrix_range(
            *compact.artifact, metadata, 0, reconstructed);
        CHECK(reconstructed == expected);

        const std::vector<Fq2> public_columns = read_array(
            *compact.artifact, kProofOfPackingWiringPublicColumns);
        const std::vector<Fq2> witness_columns = read_array(
            *compact.artifact, kProofOfPackingWiringWitnessColumns);
        const std::size_t half = metadata.assignment_half_size();
        CHECK(std::equal(public_columns.begin(), public_columns.end(),
                         expected.begin()));
        CHECK(std::all_of(
            expected.begin() +
                static_cast<std::ptrdiff_t>(public_columns.size()),
            expected.begin() + static_cast<std::ptrdiff_t>(half),
            [](const Fq2 &value) { return value.is_zero(); }));
        CHECK(std::equal(witness_columns.begin(), witness_columns.end(),
                         expected.begin() +
                             static_cast<std::ptrdiff_t>(half)));
        CHECK(std::all_of(
            expected.begin() + static_cast<std::ptrdiff_t>(
                                   half + witness_columns.size()),
            expected.end(),
            [](const Fq2 &value) { return value.is_zero(); }));

        const auto &report = compact.report;
        CHECK(report.public_column_elements == public_columns.size());
        CHECK(report.witness_column_elements == witness_columns.size());
        CHECK(report.logical_padded_column_elements == expected.size());
        CHECK(report.virtual_zero_column_elements ==
              expected.size() - public_columns.size() -
                  witness_columns.size());
        CHECK(report.matrix_payload_bytes ==
              (public_columns.size() + witness_columns.size()) *
                  sizeof(Fq2));
        CHECK(report.sequential_output_payload_bytes ==
              report.matrix_payload_bytes);
        // Pin the cache traversal as part of the runtime/storage contract.
        // A loop-order change may improve these counts, but may not silently
        // turn the compact tensor source into unbounded random I/O.
        CHECK(report.factored_tensor_io.payload_bytes == 19'488);
        CHECK(report.factored_tensor_io.read_operations == 348);
        CHECK(report.factored_tensor_io.seek_operations == 256);
        const auto tensor_mappings =
            proof_of_packing_factored_tensor_mappings(
                *factored.prover_key.structure);
        CHECK(estimate_proof_of_packing_wiring_tensor_io(
                  fixture.plan, fixture.compiled.layout, tensor_mappings,
                  report.effective_block_elements) ==
              report.factored_tensor_io);
        CHECK(report.source_artifact_validation_bytes ==
              report.source_artifact_physical_bytes);
        CHECK(report.output_artifact_validation_bytes ==
              report.physical_bytes);
        CHECK(report.peak_live_storage_bytes ==
              report.source_artifact_physical_bytes +
                  report.physical_bytes);
        CHECK(report.peak_working_field_bytes <=
              wiring_options(wiring_directory.path())
                  .max_working_field_bytes);

        const auto reopened =
            open_proof_of_packing_wiring_matrix_artifact(
                wiring_directory.path(), fixture.plan,
                fixture.compiled.layout, metadata,
                factored.prover_key, rx, gamma);
        CHECK(reopened->identity() == compact.artifact->identity());
        CHECK(reopened->arrays() == compact.artifact->arrays());

        std::vector<Fq2> crossing(11);
        const std::uint64_t crossing_begin =
            report.public_column_elements - 3;
        read_proof_of_packing_wiring_matrix_range(
            *compact.artifact, metadata, crossing_begin, crossing);
        CHECK(std::equal(crossing.begin(), crossing.begin() + 3,
                         public_columns.end() - 3));
        CHECK(std::all_of(crossing.begin() + 3, crossing.end(),
                          [](const Fq2 &value) {
                              return value.is_zero();
                          }));
    });

    runner.run("diagnostic simpleCTHash compact wiring matches the resident "
               "table",
               [] {
                   const Fixture fixture(
                       gkr::CiphertextCommitmentPolicy::
                           diagnostic_simple_ct_hash_v2());
                   const auto metadata =
                       fixture.compiled.circuit.metadata();
                   TemporaryDirectory factored_directory(
                       "simple-factored");
                   TemporaryDirectory wiring_directory("simple-matrix");
                   const auto factored = write_factored_source(
                       fixture, factored_directory.path());
                   const std::vector<Fq2> rx = row_point(metadata);
                   const Fq2 gamma(
                       Fq2::Coefficients{Fq(317), Fq(919)});
                   const auto compact =
                       write_proof_of_packing_wiring_matrix_artifact(
                           fixture.plan, fixture.compiled.layout, metadata,
                           factored.prover_key, rx, gamma,
                           wiring_options(wiring_directory.path()));
                   const std::vector<Fq2> expected =
                       fixture.compiled.circuit.batched_wiring_table(
                           rx, gamma);
                   std::vector<Fq2> reconstructed(expected.size(),
                                                  Fq2::zero());
                   read_proof_of_packing_wiring_matrix_range(
                       *compact.artifact, metadata, 0, reconstructed);
                   CHECK(reconstructed == expected);
               });

    runner.run("identity output and report are deterministic", [] {
        const Fixture fixture;
        const auto metadata = fixture.compiled.circuit.metadata();
        TemporaryDirectory factored_directory("det-factored");
        TemporaryDirectory first_directory("det-first");
        TemporaryDirectory second_directory("det-second");
        const auto factored = write_factored_source(
            fixture, factored_directory.path());
        const std::vector<Fq2> rx = row_point(metadata);
        const Fq2 gamma(Fq2::Coefficients{Fq(41), Fq(73)});
        const auto first = write_proof_of_packing_wiring_matrix_artifact(
            fixture.plan, fixture.compiled.layout, metadata,
            factored.prover_key, rx, gamma,
            wiring_options(first_directory.path()));
        const auto second = write_proof_of_packing_wiring_matrix_artifact(
            fixture.plan, fixture.compiled.layout, metadata,
            factored.prover_key, rx, gamma,
            wiring_options(second_directory.path()));
        CHECK(first.report == second.report);
        CHECK(first.artifact->identity() == second.artifact->identity());
        CHECK(first.artifact->arrays() == second.artifact->arrays());
    });

    runner.run("limits source types aliases and challenges fail closed", [] {
        const Fixture fixture;
        const auto metadata = fixture.compiled.circuit.metadata();
        TemporaryDirectory factored_directory("fail-factored");
        TemporaryDirectory baseline_directory("fail-baseline");
        const auto factored = write_factored_source(
            fixture, factored_directory.path());
        const std::vector<Fq2> rx = row_point(metadata);
        const Fq2 gamma(Fq2::Coefficients{Fq(101), Fq(103)});
        const auto baseline =
            write_proof_of_packing_wiring_matrix_artifact(
                fixture.plan, fixture.compiled.layout, metadata,
                factored.prover_key, rx, gamma,
                wiring_options(baseline_directory.path()));

        TemporaryDirectory quota_directory("fail-quota");
        CHECK(rejects_as<std::invalid_argument>([&] {
            (void)write_proof_of_packing_wiring_matrix_artifact(
                fixture.plan, fixture.compiled.layout, metadata,
                factored.prover_key, rx, gamma,
                wiring_options(quota_directory.path(),
                               baseline.report.physical_bytes - 1));
        }));
        CHECK(std::filesystem::is_empty(quota_directory.path()));

        TemporaryDirectory live_directory("fail-live");
        CHECK(rejects_as<std::invalid_argument>([&] {
            (void)write_proof_of_packing_wiring_matrix_artifact(
                fixture.plan, fixture.compiled.layout, metadata,
                factored.prover_key, rx, gamma,
                wiring_options(
                    live_directory.path(), 1ULL << 28U, 1ULL << 20U, 7,
                    baseline.report.peak_live_storage_bytes - 1));
        }));
        CHECK(std::filesystem::is_empty(live_directory.path()));

        TemporaryDirectory memory_directory("fail-memory");
        CHECK(rejects_as<std::invalid_argument>([&] {
            (void)write_proof_of_packing_wiring_matrix_artifact(
                fixture.plan, fixture.compiled.layout, metadata,
                factored.prover_key, rx, gamma,
                wiring_options(memory_directory.path(), 1ULL << 28U, 1));
        }));
        CHECK(std::filesystem::is_empty(memory_directory.path()));

        spartan::FactoredMatrixProverKey resident = factored.prover_key;
        resident.tensor_column_source =
            spartan::FactoredTensorColumnSource::Resident;
        resident.tensor_columns_artifact.reset();
        TemporaryDirectory resident_directory("fail-resident");
        CHECK(rejects_as<std::invalid_argument>([&] {
            (void)write_proof_of_packing_wiring_matrix_artifact(
                fixture.plan, fixture.compiled.layout, metadata, resident,
                rx, gamma, wiring_options(resident_directory.path()));
        }));
        CHECK(std::filesystem::is_empty(resident_directory.path()));

        std::vector<Fq2> short_rx = rx;
        short_rx.pop_back();
        TemporaryDirectory point_directory("fail-point");
        CHECK(rejects_as<std::invalid_argument>([&] {
            (void)write_proof_of_packing_wiring_matrix_artifact(
                fixture.plan, fixture.compiled.layout, metadata,
                factored.prover_key, short_rx, gamma,
                wiring_options(point_directory.path()));
        }));
        CHECK(std::filesystem::is_empty(point_directory.path()));

        const Fq2 wrong_gamma(
            Fq2::Coefficients{Fq(107), Fq(109)});
        CHECK(rejects_as([&] {
            (void)open_proof_of_packing_wiring_matrix_artifact(
                baseline_directory.path(), fixture.plan,
                fixture.compiled.layout, metadata, factored.prover_key,
                rx, wrong_gamma);
        }));

        const std::filesystem::path nested =
            factored_directory.path() / "nested-output";
        std::filesystem::create_directory(nested);
        CHECK(rejects_as<std::invalid_argument>([&] {
            (void)write_proof_of_packing_wiring_matrix_artifact(
                fixture.plan, fixture.compiled.layout, metadata,
                factored.prover_key, rx, gamma, wiring_options(nested));
        }));
        CHECK(std::filesystem::is_empty(nested));
    });

    runner.run("changed tensor source is revalidated before output", [] {
        const Fixture fixture;
        const auto metadata = fixture.compiled.circuit.metadata();
        TemporaryDirectory factored_directory("late-factored");
        TemporaryDirectory wiring_directory("late-wiring");
        const auto factored = write_factored_source(
            fixture, factored_directory.path());
        flip_last_byte(factored_directory.path() /
                       "array-0000000000000000.bin");
        const std::vector<Fq2> rx = row_point(metadata);
        const Fq2 gamma(Fq2::Coefficients{Fq(127), Fq(131)});
        CHECK(rejects_as([&] {
            (void)write_proof_of_packing_wiring_matrix_artifact(
                fixture.plan, fixture.compiled.layout, metadata,
                factored.prover_key, rx, gamma,
                wiring_options(wiring_directory.path()));
        }));
        CHECK(std::filesystem::is_empty(wiring_directory.path()));
        CHECK(std::filesystem::exists(
            factored_directory.path() / "manifest.bin"));
    });

    runner.run("current Folded compact Wiring payload is exact", [] {
        const OuterRelationPlan target = make_outer_relation_plan(
            OuterRelationShape{
                .native_modulus = kOuterFieldOrder,
                .ring_degree = 1U << 14U,
                .aligned_ciphertexts = 517,
                .repetitions = kPackingWellFormednessRepetitions,
                .logical_packed_outputs = 1,
                .packing_digit_count = 4,
                .ciphertext_components = 2,
                .public_input_capacity_bits = 59,
            });
        const ProofOfPackingR1csLayout layout =
            make_proof_of_packing_r1cs_layout(target);
        const spartan::R1csMetadata metadata(
            spartan::R1csShape{
                .constraints = layout.rows.total,
                .public_inputs = layout.logical_inputs,
                .witness_variables = layout.witness.total,
            },
            std::bit_ceil(static_cast<std::size_t>(layout.rows.total)),
            std::bit_ceil(static_cast<std::size_t>(std::max(
                layout.logical_inputs + 1U, layout.witness.total))),
            Digest{});
        CHECK(metadata.shape().public_inputs == 4'068'438ULL);
        CHECK(metadata.shape().witness_variables == 3'181'396'898ULL);
        CHECK(metadata.assignment_half_size() == 4'294'967'296ULL);
        CHECK(proof_of_packing_wiring_matrix_payload_bytes(metadata) ==
              50'967'445'392ULL);
        const long double gib = static_cast<long double>(
                                    proof_of_packing_wiring_matrix_payload_bytes(
                                        metadata)) /
                                static_cast<long double>(1ULL << 30U);
        CHECK(static_cast<std::uint64_t>(gib * 1000.0L + 0.5L) ==
              47'467ULL);

        const std::array<std::size_t, 1> owner_counts{{517}};
        const PackingTensorGeometry tensors = packing_tensor_geometry(
            owner_counts, target.shape.ring_degree,
            target.shape.packing_digit_count, sizeof(Fq));
        PackingTensorMapping mapping{
            .descriptor = tensors.outputs.front(),
        };
        mapping.global_owners.resize(target.shape.aligned_ciphertexts);
        std::iota(mapping.global_owners.begin(),
                  mapping.global_owners.end(), std::size_t{0});
        const std::array<PackingTensorMapping, 1>
            mappings{{std::move(mapping)}};
        const ProofOfPackingWiringIoReport tensor_io =
            estimate_proof_of_packing_wiring_tensor_io(
                target, layout, mappings, 1U << 17U);
        CHECK(tensor_io.payload_bytes == 2'877'292'544ULL);
        CHECK(tensor_io.read_operations == 2'744ULL);
        CHECK(tensor_io.seek_operations == 180ULL);
        const std::uint64_t useful_tensor_bytes =
            static_cast<std::uint64_t>(
                target.shape.aligned_ciphertexts) *
            target.shape.ciphertext_components *
            target.shape.ring_degree *
            target.shape.packing_digit_count * sizeof(Fq);
        CHECK(useful_tensor_bytes == 542'113'792ULL);
    });

    return runner.summary();
}
