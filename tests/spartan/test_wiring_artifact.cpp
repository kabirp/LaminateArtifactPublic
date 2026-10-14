#include "test_helpers.hpp"

#include "laminate/field/serialization.hpp"
#include "laminate/spartan/wiring_artifact.hpp"
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
#include <functional>
#include <iterator>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#if !defined(_WIN32)
#include <sys/resource.h>
#endif

namespace {

using laminate::Digest;
using laminate::Fq;
using laminate::Fq2;
using laminate::Transcript;
using laminate::spartan::WiringSumcheckArtifactArrays;
using laminate::spartan::WiringSumcheckArtifactOptions;
using laminate::spartan::WiringAssignmentStorageLayout;

class TemporaryDirectory {
  public:
    explicit TemporaryDirectory(std::string label) {
        const auto stamp = std::chrono::steady_clock::now()
                               .time_since_epoch()
                               .count();
        for (std::size_t attempt = 0; attempt < 100; ++attempt) {
            path_ = std::filesystem::temp_directory_path() /
                    ("laminate-wiring-artifact-" + label + "-" +
                     std::to_string(stamp) + "-" +
                     std::to_string(attempt));
            if (std::filesystem::create_directory(path_)) {
                return;
            }
        }
        throw std::runtime_error(
            "failed to create WiringCheck test directory");
    }

    ~TemporaryDirectory() {
        std::error_code ignored;
        std::filesystem::remove_all(path_, ignored);
    }

    const std::filesystem::path &path() const { return path_; }

  private:
    std::filesystem::path path_;
};

#if !defined(_WIN32)
class ScopedFileDescriptorLimit {
  public:
    explicit ScopedFileDescriptorLimit(rlim_t maximum) {
        if (::getrlimit(RLIMIT_NOFILE, &original_) != 0) {
            throw std::runtime_error("failed to read descriptor limit");
        }
        struct rlimit selected = original_;
        selected.rlim_cur = std::min(selected.rlim_cur, maximum);
        changed_ = selected.rlim_cur != original_.rlim_cur;
        if (changed_ && ::setrlimit(RLIMIT_NOFILE, &selected) != 0) {
            throw std::runtime_error("failed to lower descriptor limit");
        }
    }

    ~ScopedFileDescriptorLimit() {
        if (changed_) {
            (void)::setrlimit(RLIMIT_NOFILE, &original_);
        }
    }

  private:
    struct rlimit original_ {};
    bool changed_ = false;
};
#endif

Digest identity(std::string_view label) {
    return laminate::sha256(std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t *>(label.data()),
        label.size()));
}

Digest matrix_identity() {
    return identity("laminate/test/wiring-matrix-source/v1");
}

Digest assignment_identity() {
    return identity("laminate/test/wiring-assignment-source/v1");
}

class HookedPublicCoin final : public laminate::PublicCoin {
  public:
    using Hook = std::function<void(std::size_t)>;

    HookedPublicCoin(std::string_view domain, Hook hook)
        : transcript_(domain), hook_(std::move(hook)) {}

    void observe(std::string_view label,
                 std::span<const std::uint8_t> bytes) override {
        transcript_.observe(label, bytes);
    }

    void observe(std::string_view label, std::uint64_t value) override {
        transcript_.observe(label, value);
    }

    laminate::Fpk challenge_fpk() override {
        return transcript_.challenge_fpk();
    }

    Fq challenge_fq() override { return transcript_.challenge_fq(); }

    Fq2 challenge_fq2() override {
        const Fq2 result = transcript_.challenge_fq2();
        ++fq2_challenges_;
        if (hook_) {
            hook_(fq2_challenges_);
        }
        return result;
    }

    std::vector<Fq2> challenge_fq2_vector(std::size_t count) override {
        return transcript_.challenge_fq2_vector(count);
    }

    std::vector<laminate::Fpk>
    challenge_vector(std::size_t count) override {
        return transcript_.challenge_vector(count);
    }

    std::vector<bool> challenge_bits(std::size_t count) override {
        return transcript_.challenge_bits(count);
    }

  private:
    Transcript transcript_;
    Hook hook_;
    std::size_t fq2_challenges_ = 0;
};

void write_marker(const std::filesystem::path &path) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output.put('x');
    output.close();
    if (!output) {
        throw std::runtime_error("failed to write WiringCheck test marker");
    }
}

WiringSumcheckArtifactArrays source_names() {
    return {
        .matrix_public = "public-columns",
        .matrix_witness = "witness-columns",
        .assignment_public = "public-inputs",
        .assignment_witness = "witness-half",
    };
}

laminate::storage::NativeFieldArtifact write_matrix_source(
    const std::filesystem::path &directory,
    std::span<const Fq2> public_columns,
    std::span<const Fq2> witness_columns) {
    laminate::storage::NativeFieldArtifactWriter writer(
        directory,
        {.max_total_bytes = 1ULL << 24U, .min_free_bytes = 1},
        matrix_identity());
    writer.begin_array("public-columns",
                       laminate::storage::NativeFieldElementKind::Fq2,
                       public_columns.size());
    writer.append(public_columns);
    writer.finish_array();
    writer.begin_array("witness-columns",
                       laminate::storage::NativeFieldElementKind::Fq2,
                       witness_columns.size());
    writer.append(witness_columns);
    writer.finish_array();
    (void)writer.finish();
    return laminate::storage::NativeFieldArtifact::open(
        directory, matrix_identity());
}

laminate::storage::NativeFieldArtifact write_assignment_source(
    const std::filesystem::path &directory,
    std::span<const Fq> public_inputs,
    std::span<const Fq> witness_half) {
    laminate::storage::NativeFieldArtifactWriter writer(
        directory,
        {.max_total_bytes = 1ULL << 24U, .min_free_bytes = 1},
        assignment_identity());
    writer.begin_array("public-inputs",
                       laminate::storage::NativeFieldElementKind::Fq,
                       public_inputs.size());
    writer.append(public_inputs);
    writer.finish_array();
    writer.begin_array("witness-half",
                       laminate::storage::NativeFieldElementKind::Fq,
                       witness_half.size());
    writer.append(witness_half);
    writer.finish_array();
    (void)writer.finish();
    return laminate::storage::NativeFieldArtifact::open(
        directory, assignment_identity());
}

laminate::storage::NativeFieldArtifact write_compact_assignment_source(
    const std::filesystem::path &directory,
    std::span<const Fq> public_inputs, std::span<const Fq> stored_witness) {
    laminate::storage::NativeFieldArtifactWriter writer(
        directory,
        {.max_total_bytes = 1ULL << 24U, .min_free_bytes = 1},
        assignment_identity());
    writer.begin_array("public-inputs",
                       laminate::storage::NativeFieldElementKind::Fq,
                       public_inputs.size());
    writer.append(public_inputs);
    writer.finish_array();
    writer.begin_array("witness-half",
                       laminate::storage::NativeFieldElementKind::Fq,
                       stored_witness.size());
    writer.append(stored_witness);
    writer.finish_array();
    (void)writer.finish();
    return laminate::storage::NativeFieldArtifact::open(
        directory, assignment_identity());
}

WiringSumcheckArtifactOptions options(
    const std::filesystem::path &scratch, std::size_t source_rounds,
    std::size_t block_elements,
    std::uint64_t working_bytes = 1ULL << 20U,
    std::uint64_t scratch_bytes = 1ULL << 24U) {
    return {
        .expected_matrix_identity = matrix_identity(),
        .expected_assignment_identity = assignment_identity(),
        .scratch_directory = scratch,
        .max_live_storage_bytes = 1ULL << 25U,
        .max_total_scratch_bytes = scratch_bytes,
        .min_free_bytes = 1,
        .max_working_field_bytes = working_bytes,
        .block_elements = block_elements,
        .source_rounds = source_rounds,
    };
}

struct Fixture {
    std::vector<Fq2> public_matrix;
    std::vector<Fq2> witness_matrix;
    std::vector<Fq> public_inputs;
    std::vector<Fq> witness_half;
    std::vector<Fq2> matrix;
    std::vector<Fq> assignment;
    Fq2 claim{};
};

Fixture make_fixture() {
    constexpr std::size_t kHalf = 16;
    constexpr std::size_t kPublicInputs = 5;
    constexpr std::size_t kWitnessMatrix = 11;
    Fixture result;
    for (std::size_t index = 0; index < kPublicInputs + 1U; ++index) {
        result.public_matrix.push_back(
            Fq2({Fq(index + 2), Fq(3 * index + 1)}));
    }
    for (std::size_t index = 0; index < kWitnessMatrix; ++index) {
        result.witness_matrix.push_back(
            Fq2({Fq(5 * index + 7), Fq(2 * index + 9)}));
    }
    for (std::size_t index = 0; index < kPublicInputs; ++index) {
        result.public_inputs.emplace_back(7 * index + 3);
    }
    for (std::size_t index = 0; index < kHalf; ++index) {
        // Nonzero padding after the active matrix prefix checks that the
        // terminal z(r) evaluation uses the complete witness half.
        result.witness_half.emplace_back(11 * index + 4);
    }

    result.matrix.assign(2U * kHalf, Fq2::zero());
    std::copy(result.public_matrix.begin(), result.public_matrix.end(),
              result.matrix.begin());
    std::copy(result.witness_matrix.begin(), result.witness_matrix.end(),
              result.matrix.begin() + kHalf);
    result.assignment.assign(2U * kHalf, Fq::zero());
    result.assignment.front() = Fq::one();
    std::copy(result.public_inputs.begin(), result.public_inputs.end(),
              result.assignment.begin() + 1U);
    std::copy(result.witness_half.begin(), result.witness_half.end(),
              result.assignment.begin() + kHalf);
    for (std::size_t index = 0; index < result.matrix.size(); ++index) {
        result.claim += result.matrix[index] *
                        Fq2::from_base(result.assignment[index]);
    }
    return result;
}

std::uint64_t scratch_artifact_bytes(std::size_t elements) {
    const std::array<laminate::storage::NativeFieldArrayLayout, 2> arrays{{
        {"matrix", laminate::storage::NativeFieldElementKind::Fq2,
         elements},
        {"assignment", laminate::storage::NativeFieldElementKind::Fq2,
         elements},
    }};
    return laminate::storage::native_field_artifact_physical_bytes(arrays);
}

std::uint64_t expected_field_peak(std::size_t domain_size,
                                  std::size_t source_rounds,
                                  std::size_t requested_block) {
    const std::size_t block = std::size_t{1}
                              << (std::bit_width(
                                      std::min(domain_size, requested_block)) -
                                  1U);
    const std::size_t prefix_count = std::size_t{1} << source_rounds;
    const std::size_t variables = std::bit_width(domain_size) - 1U;
    const std::uint64_t retained_output_bytes =
        variables * 3U * sizeof(Fq2);
    const std::uint64_t prefix_bytes = prefix_count * sizeof(Fq2);
    std::uint64_t peak = retained_output_bytes;
    for (std::size_t round = 0; round < source_rounds; ++round) {
        const std::size_t suffix = domain_size >> (round + 1U);
        peak = std::max<std::uint64_t>(
            peak, retained_output_bytes + prefix_bytes +
                      std::min(block, suffix) *
                          (5U * sizeof(Fq2) + sizeof(Fq)));
    }
    const std::size_t checkpoint = domain_size / prefix_count;
    peak = std::max<std::uint64_t>(
        peak, retained_output_bytes + prefix_bytes +
                  std::min(block, checkpoint) *
                      (2U * sizeof(Fq2) + sizeof(Fq)));
    for (std::size_t size = checkpoint; size > 1; size >>= 1U) {
        const std::size_t half = size / 2U;
        peak = std::max<std::uint64_t>(
            peak, retained_output_bytes +
                      std::min(block, half) * 4U * sizeof(Fq2));
    }
    return peak;
}

bool throws_exception(const auto &body) {
    try {
        body();
    } catch (const std::exception &) {
        return true;
    }
    return false;
}

std::size_t directory_child_count(const std::filesystem::path &directory) {
    return static_cast<std::size_t>(std::distance(
        std::filesystem::directory_iterator(directory),
        std::filesystem::directory_iterator()));
}

void test_matches_resident_wiring_bytes() {
    const Fixture fixture = make_fixture();
    TemporaryDirectory matrix_directory("matrix");
    TemporaryDirectory assignment_directory("assignment");
    const auto matrix = write_matrix_source(
        matrix_directory.path(), fixture.public_matrix,
        fixture.witness_matrix);
    const auto assignment = write_assignment_source(
        assignment_directory.path(), fixture.public_inputs,
        fixture.witness_half);
    const std::uint64_t selected_payload =
        (fixture.public_matrix.size() + fixture.witness_matrix.size()) *
            laminate::kSerializedFq2Bytes +
        (fixture.public_inputs.size() + fixture.witness_half.size()) *
            laminate::kSerializedFqBytes;

    for (std::size_t source_rounds = 0; source_rounds <= 4;
         ++source_rounds) {
        for (const std::size_t requested_block :
             std::array<std::size_t, 3>{1, 3, 8}) {
            Transcript resident("laminate/test/wiring-artifact-parity/v1");
            const auto expected = laminate::spartan::prove_wiring_sumcheck(
                fixture.matrix, fixture.assignment, fixture.claim, resident,
                0);
            const Fq2 expected_next = resident.challenge_fq2();

            TemporaryDirectory scratch(
                "scratch-" + std::to_string(source_rounds) + "-" +
                std::to_string(requested_block));
            Transcript external("laminate/test/wiring-artifact-parity/v1");
            const auto actual =
                laminate::spartan::prove_wiring_sumcheck_artifact(
                    matrix, assignment, source_names(), fixture.claim,
                    external,
                    options(scratch.path(), source_rounds,
                            requested_block));
            const Fq2 actual_next = external.challenge_fq2();

            CHECK(actual.sumcheck.proof.rounds == expected.proof.rounds);
            CHECK(actual.sumcheck.point == expected.point);
            CHECK(actual.sumcheck.final_claim == expected.final_claim);
            CHECK(actual.sumcheck.matrix_evaluation ==
                  expected.matrix_evaluation);
            CHECK(actual.sumcheck.assignment_evaluation ==
                  expected.assignment_evaluation);
            CHECK(actual_next == expected_next);
            CHECK(actual.report.selected_source_payload_bytes ==
                  selected_payload);
            CHECK(actual.report.source_read_payload_bytes ==
                  (source_rounds + 1U) * selected_payload);
            CHECK(actual.report.source_rescan_rounds == source_rounds);
            CHECK(actual.report.fold_passes == 5U - source_rounds);
            CHECK(actual.report.peak_working_field_bytes ==
                  expected_field_peak(32, source_rounds,
                                      requested_block));
            CHECK(actual.report.scratch_retained_physical_bytes == 0);
            CHECK(actual.report.peak_live_storage_bytes ==
                  matrix.physical_bytes() + assignment.physical_bytes() +
                      actual.report.scratch_peak_physical_bytes);
            CHECK(actual.report.scratch_written_physical_bytes ==
                  actual.report.scratch_deleted_physical_bytes);
            CHECK(std::filesystem::is_empty(scratch.path()));

            Transcript verifier("laminate/test/wiring-artifact-parity/v1");
            const auto checked =
                laminate::spartan::verify_wiring_sumcheck(
                    actual.sumcheck.proof, fixture.claim, verifier);
            CHECK(checked.accepts);
            CHECK(checked.point == actual.sumcheck.point);
            CHECK(checked.final_claim == actual.sumcheck.final_claim);
        }
    }
}

void test_segmented_witness_matches_resident_wiring_bytes() {
    Fixture fixture = make_fixture();
    // Preserve three nonzero runs and make every omitted position a public,
    // setup-known zero in the logical H-value witness polynomial.
    const std::array<std::pair<std::size_t, std::size_t>, 3> runs{{
        {1, 3}, {7, 2}, {12, 4},
    }};
    std::vector<Fq> stored;
    WiringAssignmentStorageLayout layout{.half_size =
                                              fixture.witness_half.size()};
    std::vector<Fq> logical(fixture.witness_half.size(), Fq::zero());
    for (const auto &[begin, count] : runs) {
        layout.segments.push_back({
            .logical_begin = begin,
            .stored_begin = stored.size(),
            .element_count = count,
        });
        for (std::size_t index = 0; index < count; ++index) {
            logical[begin + index] = fixture.witness_half[begin + index];
            stored.push_back(fixture.witness_half[begin + index]);
        }
    }
    fixture.witness_half = logical;
    std::copy(logical.begin(), logical.end(),
              fixture.assignment.begin() + 16);
    fixture.claim = Fq2::zero();
    for (std::size_t index = 0; index < fixture.matrix.size(); ++index) {
        fixture.claim += fixture.matrix[index] *
                         Fq2::from_base(fixture.assignment[index]);
    }

    TemporaryDirectory matrix_directory("segmented-matrix");
    TemporaryDirectory assignment_directory("segmented-assignment");
    TemporaryDirectory scratch("segmented-scratch");
    const auto matrix = write_matrix_source(
        matrix_directory.path(), fixture.public_matrix,
        fixture.witness_matrix);
    const auto assignment = write_compact_assignment_source(
        assignment_directory.path(), fixture.public_inputs, stored);

    Transcript resident("laminate/test/wiring-artifact-segmented/v1");
    const auto expected = laminate::spartan::prove_wiring_sumcheck(
        fixture.matrix, fixture.assignment, fixture.claim, resident, 0);
    const Fq2 expected_next = resident.challenge_fq2();
    Transcript external("laminate/test/wiring-artifact-segmented/v1");
    const auto actual = laminate::spartan::prove_wiring_sumcheck_artifact(
        matrix, assignment, source_names(), layout, fixture.claim, external,
        options(scratch.path(), 4, 3));
    CHECK(actual.sumcheck.proof.rounds == expected.proof.rounds);
    CHECK(actual.sumcheck.point == expected.point);
    CHECK(actual.sumcheck.final_claim == expected.final_claim);
    CHECK(actual.sumcheck.matrix_evaluation ==
          expected.matrix_evaluation);
    CHECK(actual.sumcheck.assignment_evaluation ==
          expected.assignment_evaluation);
    CHECK(external.challenge_fq2() == expected_next);
    CHECK(actual.report.selected_assignment_payload_bytes ==
          (fixture.public_inputs.size() + stored.size()) * sizeof(Fq));
    CHECK(std::filesystem::is_empty(scratch.path()));
}

void test_highly_fragmented_witness_uses_bounded_readers() {
    constexpr std::size_t kHalf = 1024;
    const std::vector<Fq> public_inputs{Fq(9)};
    const std::vector<Fq2> public_matrix{
        Fq2({Fq(2), Fq(3)}), Fq2({Fq(5), Fq(7)})};
    std::vector<Fq2> witness_matrix(kHalf);
    std::vector<Fq> logical_witness(kHalf, Fq::zero());
    std::vector<Fq> stored_witness;
    WiringAssignmentStorageLayout layout{.half_size = kHalf};
    for (std::size_t index = 0; index < kHalf; ++index) {
        witness_matrix[index] =
            Fq2({Fq(3U * index + 1U), Fq(5U * index + 2U)});
        if ((index & 1U) == 0) {
            logical_witness[index] = Fq(7U * index + 4U);
            layout.segments.push_back({
                .logical_begin = index,
                .stored_begin = stored_witness.size(),
                .element_count = 1,
            });
            stored_witness.push_back(logical_witness[index]);
        }
    }
    std::vector<Fq2> matrix(2U * kHalf, Fq2::zero());
    matrix[0] = public_matrix[0];
    matrix[1] = public_matrix[1];
    std::copy(witness_matrix.begin(), witness_matrix.end(),
              matrix.begin() + kHalf);
    std::vector<Fq> assignment(2U * kHalf, Fq::zero());
    assignment[0] = Fq::one();
    assignment[1] = public_inputs[0];
    std::copy(logical_witness.begin(), logical_witness.end(),
              assignment.begin() + kHalf);
    Fq2 claim = Fq2::zero();
    for (std::size_t index = 0; index < matrix.size(); ++index) {
        claim += matrix[index] * Fq2::from_base(assignment[index]);
    }

    TemporaryDirectory matrix_directory("fragmented-matrix");
    TemporaryDirectory assignment_directory("fragmented-assignment");
    TemporaryDirectory scratch("fragmented-scratch");
    const auto matrix_source = write_matrix_source(
        matrix_directory.path(), public_matrix, witness_matrix);
    const auto assignment_source = write_compact_assignment_source(
        assignment_directory.path(), public_inputs, stored_witness);
    Transcript resident("laminate/test/wiring-artifact-fragmented/v1");
    const auto expected = laminate::spartan::prove_wiring_sumcheck(
        matrix, assignment, claim, resident, 0);
#if !defined(_WIN32)
    ScopedFileDescriptorLimit descriptor_limit(64);
#endif
    Transcript external("laminate/test/wiring-artifact-fragmented/v1");
    const auto actual = laminate::spartan::prove_wiring_sumcheck_artifact(
        matrix_source, assignment_source, source_names(), layout, claim,
        external, options(scratch.path(), 4, 7));
    CHECK(actual.sumcheck.proof.rounds == expected.proof.rounds);
    CHECK(actual.sumcheck.point == expected.point);
    CHECK(actual.sumcheck.matrix_evaluation ==
          expected.matrix_evaluation);
    CHECK(actual.sumcheck.assignment_evaluation ==
          expected.assignment_evaluation);
    CHECK(std::filesystem::is_empty(scratch.path()));
}

void test_exact_scratch_and_memory_ledger() {
    const Fixture fixture = make_fixture();
    TemporaryDirectory matrix_directory("ledger-matrix");
    TemporaryDirectory assignment_directory("ledger-assignment");
    const auto matrix = write_matrix_source(
        matrix_directory.path(), fixture.public_matrix,
        fixture.witness_matrix);
    const auto assignment = write_assignment_source(
        assignment_directory.path(), fixture.public_inputs,
        fixture.witness_half);
    TemporaryDirectory scratch("ledger-scratch");
    Transcript transcript("laminate/test/wiring-artifact-ledger/v1");
    const auto result = laminate::spartan::prove_wiring_sumcheck_artifact(
        matrix, assignment, source_names(), fixture.claim, transcript,
        options(scratch.path(), 2, 3, 480));

    CHECK(result.report.effective_block_elements == 2);
    CHECK(result.report.peak_working_field_bytes == 480);
    CHECK(result.report.source_validation_bytes ==
          matrix.physical_bytes() + assignment.physical_bytes());
    CHECK(result.report.source_read_operations == 60);
    std::uint64_t cumulative = 0;
    std::uint64_t peak = 0;
    std::uint64_t previous = 0;
    for (std::size_t size = 8;; size >>= 1U) {
        const std::uint64_t current = scratch_artifact_bytes(size);
        cumulative += current;
        peak = std::max(peak, previous + current);
        previous = current;
        if (size == 1) {
            break;
        }
    }
    CHECK(result.report.scratch_written_physical_bytes == cumulative);
    CHECK(result.report.scratch_artifact_validation_bytes == 2U * cumulative);
    CHECK(result.report.scratch_peak_physical_bytes == peak);
    CHECK(result.report.scratch_write_payload_bytes ==
          2U * (8U + 4U + 2U + 1U) * laminate::kSerializedFq2Bytes);
    CHECK(result.report.scratch_read_payload_bytes ==
          4U * (8U + 4U + 2U) * laminate::kSerializedFq2Bytes +
              2U * laminate::kSerializedFq2Bytes);
    CHECK(result.report.scratch_read_operations == 34);
    CHECK(result.report.scratch_write_operations == 16);
    CHECK(std::filesystem::is_empty(scratch.path()));
}

void test_rejects_bad_resources_before_transcript_use() {
    const Fixture fixture = make_fixture();
    TemporaryDirectory matrix_directory("reject-matrix");
    TemporaryDirectory assignment_directory("reject-assignment");
    const auto matrix = write_matrix_source(
        matrix_directory.path(), fixture.public_matrix,
        fixture.witness_matrix);
    const auto assignment = write_assignment_source(
        assignment_directory.path(), fixture.public_inputs,
        fixture.witness_half);

    const auto fails = [&](const auto &configure) {
        TemporaryDirectory scratch("reject-scratch");
        auto selected = options(scratch.path(), 2, 3);
        configure(selected);
        Transcript failed("laminate/test/wiring-artifact-reject/v1");
        Transcript fresh("laminate/test/wiring-artifact-reject/v1");
        CHECK(throws_exception([&] {
            (void)laminate::spartan::prove_wiring_sumcheck_artifact(
                matrix, assignment, source_names(), fixture.claim, failed,
                selected);
        }));
        CHECK(failed.challenge_fq2() == fresh.challenge_fq2());
        CHECK(std::filesystem::is_empty(scratch.path()));
    };
    fails([](auto &selected) { selected.expected_matrix_identity[0] ^= 1U; });
    fails([](auto &selected) { selected.max_total_scratch_bytes = 1; });
    fails([](auto &selected) { selected.max_live_storage_bytes = 1; });
    fails([](auto &selected) { selected.max_working_field_bytes = 1; });
    fails([](auto &selected) { selected.source_rounds = 5; });
    fails([](auto &selected) { selected.block_elements = 0; });
}

void test_rejects_scratch_symlink_before_transcript_use() {
#ifndef _WIN32
    const Fixture fixture = make_fixture();
    TemporaryDirectory matrix_directory("symlink-matrix");
    TemporaryDirectory assignment_directory("symlink-assignment");
    const auto matrix = write_matrix_source(
        matrix_directory.path(), fixture.public_matrix,
        fixture.witness_matrix);
    const auto assignment = write_assignment_source(
        assignment_directory.path(), fixture.public_inputs,
        fixture.witness_half);
    TemporaryDirectory scratch("symlink-target");
    TemporaryDirectory aliases("symlink-alias");
    const std::filesystem::path alias = aliases.path() / "scratch";
    std::filesystem::create_directory_symlink(scratch.path(), alias);

    Transcript failed("laminate/test/wiring-artifact-symlink/v1");
    Transcript fresh("laminate/test/wiring-artifact-symlink/v1");
    CHECK(throws_exception([&] {
        (void)laminate::spartan::prove_wiring_sumcheck_artifact(
            matrix, assignment, source_names(), fixture.claim, failed,
            options(alias, 2, 3));
    }));
    CHECK(failed.challenge_fq2() == fresh.challenge_fq2());
    CHECK(std::filesystem::is_empty(scratch.path()));
#endif
}

void test_checked_cleanup_owns_only_registered_scratch() {
    const Fixture fixture = make_fixture();
    TemporaryDirectory matrix_directory("cleanup-matrix");
    TemporaryDirectory assignment_directory("cleanup-assignment");
    const auto matrix = write_matrix_source(
        matrix_directory.path(), fixture.public_matrix,
        fixture.witness_matrix);
    const auto assignment = write_assignment_source(
        assignment_directory.path(), fixture.public_inputs,
        fixture.witness_half);

    {
        TemporaryDirectory scratch("cleanup-late");
        HookedPublicCoin coin(
            "laminate/test/wiring-artifact-cleanup-late/v1",
            [](std::size_t challenge) {
                if (challenge == 2) {
                    throw std::runtime_error("injected late WiringCheck failure");
                }
            });
        CHECK(throws_exception([&] {
            (void)laminate::spartan::prove_wiring_sumcheck_artifact(
                matrix, assignment, source_names(), fixture.claim, coin,
                options(scratch.path(), 1, 3));
        }));
        CHECK(std::filesystem::is_empty(scratch.path()));
    }

    {
        TemporaryDirectory scratch("cleanup-foreign");
        const std::filesystem::path foreign = scratch.path() / "foreign.bin";
        HookedPublicCoin coin(
            "laminate/test/wiring-artifact-cleanup-foreign/v1",
            [&](std::size_t challenge) {
                if (challenge == 2) {
                    write_marker(foreign);
                    throw std::runtime_error(
                        "injected failure after foreign scratch appeared");
                }
            });
        CHECK(throws_exception([&] {
            (void)laminate::spartan::prove_wiring_sumcheck_artifact(
                matrix, assignment, source_names(), fixture.claim, coin,
                options(scratch.path(), 1, 3));
        }));
        CHECK(std::filesystem::is_regular_file(foreign));
        CHECK(directory_child_count(scratch.path()) == 1);
    }

    {
        TemporaryDirectory scratch("cleanup-changed");
        const std::filesystem::path checkpoint =
            scratch.path() / "checkpoint-1";
        const std::filesystem::path foreign = checkpoint / "foreign.bin";
        HookedPublicCoin coin(
            "laminate/test/wiring-artifact-cleanup-changed/v1",
            [&](std::size_t challenge) {
                if (challenge == 2) {
                    write_marker(foreign);
                }
            });
        std::string failure;
        try {
            (void)laminate::spartan::prove_wiring_sumcheck_artifact(
                matrix, assignment, source_names(), fixture.claim, coin,
                options(scratch.path(), 1, 3));
        } catch (const std::exception &error) {
            failure = error.what();
        }
        CHECK(failure.find("refusing to remove changed wiring scratch data") !=
              std::string::npos);
        CHECK(std::filesystem::is_regular_file(foreign));
        CHECK(!std::filesystem::exists(scratch.path() / "fold-1"));
        CHECK(directory_child_count(scratch.path()) == 1);
    }

    {
        TemporaryDirectory scratch("cleanup-extra-directory");
        const std::filesystem::path checkpoint =
            scratch.path() / "checkpoint-1";
        const std::filesystem::path foreign =
            checkpoint / "foreign-directory";
        HookedPublicCoin coin(
            "laminate/test/wiring-artifact-cleanup-extra-directory/v1",
            [&](std::size_t challenge) {
                if (challenge == 2 &&
                    !std::filesystem::create_directory(foreign)) {
                    throw std::runtime_error(
                        "failed to add foreign scratch directory");
                }
            });
        std::string failure;
        try {
            (void)laminate::spartan::prove_wiring_sumcheck_artifact(
                matrix, assignment, source_names(), fixture.claim, coin,
                options(scratch.path(), 1, 3));
        } catch (const std::exception &error) {
            failure = error.what();
        }
        CHECK(failure.find("refusing to remove changed wiring scratch data") !=
              std::string::npos);
        CHECK(std::filesystem::is_directory(foreign));
        CHECK(!std::filesystem::exists(scratch.path() / "fold-1"));
        CHECK(directory_child_count(scratch.path()) == 1);
    }
}

void test_target_geometry_stays_below_storage_budget() {
    constexpr std::uint64_t kHalf = 1ULL << 32U;
    constexpr std::uint64_t kPublicInputs = 3'413'091ULL;
    constexpr std::uint64_t kWitnessMatrix = 3'296'776'360ULL;
    constexpr std::uint64_t kSourceRounds = 4;
    constexpr std::uint64_t kBlock = 1ULL << 17U;
    const std::uint64_t matrix_bytes =
        (kPublicInputs + 1U + kWitnessMatrix) *
        laminate::kSerializedFq2Bytes;
    const std::uint64_t assignment_bytes =
        (kPublicInputs + kHalf) * laminate::kSerializedFqBytes;
    CHECK(matrix_bytes == 52'803'031'232ULL);
    CHECK(assignment_bytes == 34'387'043'096ULL);
    CHECK(matrix_bytes + assignment_bytes == 87'190'074'328ULL);
    CHECK((kSourceRounds + 1U) * (matrix_bytes + assignment_bytes) ==
          435'950'371'640ULL);

    const std::size_t checkpoint =
        static_cast<std::size_t>((2U * kHalf) >> kSourceRounds);
    CHECK(checkpoint == (std::size_t{1} << 29U));
    const std::uint64_t first = scratch_artifact_bytes(checkpoint);
    const std::uint64_t successor = scratch_artifact_bytes(checkpoint / 2U);
    CHECK(first > 16ULL * (1ULL << 30U));
    CHECK(first + successor > 24ULL * (1ULL << 30U));
    CHECK(first + successor < 25ULL * (1ULL << 30U));
    CHECK(expected_field_peak(static_cast<std::size_t>(2U * kHalf),
                              kSourceRounds, kBlock) ==
          11ULL * (1ULL << 20U) + 1'840U);
}

} // namespace

int main() {
    laminate::test::Runner runner("test_wiring_artifact");
    runner.run("compact WiringCheck matches resident proof bytes",
               test_matches_resident_wiring_bytes);
    runner.run("segmented witness WiringCheck matches resident proof bytes",
               test_segmented_witness_matches_resident_wiring_bytes);
    runner.run("fragmented witness WiringCheck bounds source readers",
               test_highly_fragmented_witness_uses_bounded_readers);
    runner.run("compact WiringCheck reports exact scratch lifetime",
               test_exact_scratch_and_memory_ledger);
    runner.run("compact WiringCheck rejects resources before transcript use",
               test_rejects_bad_resources_before_transcript_use);
    runner.run("compact WiringCheck rejects a scratch symlink",
               test_rejects_scratch_symlink_before_transcript_use);
    runner.run("compact WiringCheck cleanup owns registered scratch only",
               test_checked_cleanup_owns_only_registered_scratch);
    runner.run("compact WiringCheck target geometry is bounded",
               test_target_geometry_stays_below_storage_budget);
    return runner.summary();
}
