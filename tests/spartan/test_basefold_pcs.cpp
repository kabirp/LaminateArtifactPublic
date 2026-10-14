#include "test_helpers.hpp"

#include "laminate/spartan/basefold_pcs.hpp"
#include "laminate/transcript/hash.hpp"
#include "laminate/transcript/transcript.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <functional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#if !defined(_WIN32)
#include <sys/resource.h>
#endif

namespace {

using laminate::Fq;
using laminate::Fq2;
using laminate::Transcript;
using laminate::spartan::BaseFoldPcs;
using laminate::spartan::BaseFoldExternalOpeningOptions;
using laminate::spartan::BaseFoldExternalCommitOptions;
using laminate::spartan::BaseFoldExternalCommitProgress;
using laminate::spartan::BaseFoldExternalCommitProgressKind;
using laminate::spartan::BaseFoldExternalCommitPhase;
using laminate::spartan::BaseFoldExternalCommitSubpass;
using laminate::spartan::BaseFoldExternalCommitWorkUnit;
using laminate::spartan::BaseFoldExternalStateOptions;
using laminate::spartan::basefold_opening_max_merkle_hashes;
using laminate::spartan::basefold_opening_proof_max_size_bytes;
using laminate::spartan::IPCS;
using laminate::spartan::PcsCommitment;
using laminate::spartan::PcsOpeningProof;

class QueryBlockRecordingCoin final : public laminate::PublicCoin {
  public:
    explicit QueryBlockRecordingCoin(Transcript &transcript)
        : transcript_(transcript) {}

    void observe(std::string_view label,
                 std::span<const std::uint8_t> bytes) override {
        last_observation = label;
        transcript_.observe(label, bytes);
    }
    void observe(std::string_view label, std::uint64_t value) override {
        last_observation = label;
        transcript_.observe(label, value);
    }
    laminate::Fpk challenge_fpk() override {
        return transcript_.challenge_fpk();
    }
    Fq challenge_fq() override { return transcript_.challenge_fq(); }
    Fq2 challenge_fq2() override {
        ++fold_challenges;
        return transcript_.challenge_fq2();
    }
    std::vector<Fq2> challenge_fq2_vector(std::size_t count) override {
        return transcript_.challenge_fq2_vector(count);
    }
    std::vector<laminate::Fpk> challenge_vector(std::size_t count) override {
        return transcript_.challenge_vector(count);
    }
    std::vector<bool> challenge_bits(std::size_t count) override {
        query_blocks.push_back(count);
        observations_before_queries.push_back(last_observation);
        return transcript_.challenge_bits(count);
    }

    std::size_t fold_challenges = 0;
    std::vector<std::size_t> query_blocks;
    std::vector<std::string> observations_before_queries;
    std::string last_observation;

  private:
    Transcript &transcript_;
};

class TemporaryDirectory {
  public:
    explicit TemporaryDirectory(std::string label) {
        const auto stamp = std::chrono::steady_clock::now()
                               .time_since_epoch()
                               .count();
        for (std::size_t attempt = 0; attempt < 100; ++attempt) {
            path_ = std::filesystem::temp_directory_path() /
                    ("laminate-basefold-" + label + "-" +
                     std::to_string(stamp) + "-" +
                     std::to_string(attempt));
            if (std::filesystem::create_directory(path_)) {
                return;
            }
        }
        throw std::runtime_error("failed to create BaseFold test directory");
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

std::uint64_t test_fold_chunk_physical_bytes(std::size_t count) {
    const std::array<laminate::storage::NativeFieldArrayLayout, 1> layout{{
        {"fold-values", laminate::storage::NativeFieldElementKind::Fq2,
         count},
    }};
    return laminate::storage::native_field_artifact_physical_bytes(layout);
}

BaseFoldExternalOpeningOptions external_opening_options(
    const std::filesystem::path &scratch,
    std::uint64_t max_working_field_bytes = 3328,
    std::uint64_t max_scratch_bytes = 1ULL << 24U,
    std::size_t fold_chunk_elements = 128) {
    return BaseFoldExternalOpeningOptions{
        .scratch_directory = scratch,
        .max_live_storage_bytes = 1ULL << 25U,
        .max_total_scratch_bytes = max_scratch_bytes,
        .min_free_bytes = 1,
        .max_working_field_bytes = max_working_field_bytes,
        .fold_chunk_elements = fold_chunk_elements,
    };
}

laminate::Digest external_commit_source_identity() {
    constexpr std::string_view label =
        "laminate/test/basefold-external-commit-source/v1";
    return laminate::sha256(std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t *>(label.data()), label.size()));
}

std::shared_ptr<const laminate::storage::NativeFieldArtifact>
write_external_commit_source(
    const std::filesystem::path &directory,
    const std::vector<std::string> &names,
    const std::vector<std::vector<Fq>> &columns,
    bool include_bad_extension = false) {
    laminate::storage::NativeFieldArtifactWriter writer(
        directory,
        {.max_total_bytes = 1ULL << 24U, .min_free_bytes = 1},
        external_commit_source_identity());
    for (std::size_t column = 0; column < columns.size(); ++column) {
        writer.begin_array(names[column],
                           laminate::storage::NativeFieldElementKind::Fq,
                           columns[column].size());
        writer.append(columns[column]);
        writer.finish_array();
    }
    if (include_bad_extension) {
        const std::array<Fq2, 2> extension{
            Fq2({Fq(3), Fq(5)}), Fq2({Fq(7), Fq(11)})};
        writer.begin_array("extension",
                           laminate::storage::NativeFieldElementKind::Fq2,
                           extension.size());
        writer.append(extension);
        writer.finish_array();
    }
    (void)writer.finish();
    return std::make_shared<laminate::storage::NativeFieldArtifact>(
        laminate::storage::NativeFieldArtifact::open(
            directory, external_commit_source_identity()));
}

BaseFoldExternalCommitOptions external_commit_options(
    const std::filesystem::path &destination,
    const std::filesystem::path &scratch,
    std::size_t block_elements = 2,
    std::uint64_t max_working_field_bytes = 1ULL << 16U,
    std::uint64_t max_final_bytes = 1ULL << 24U,
    std::uint64_t max_scratch_bytes = 1ULL << 24U) {
    return {
        .destination_directory = destination,
        .scratch_directory = scratch,
        .max_final_bytes = max_final_bytes,
        .max_scratch_bytes = max_scratch_bytes,
        .min_free_bytes = 1,
        .max_working_field_bytes = max_working_field_bytes,
        .block_elements = block_elements,
    };
}

std::size_t test_ceil_div(std::size_t numerator, std::size_t denominator) {
    return numerator / denominator + (numerator % denominator != 0 ? 1U : 0U);
}

std::size_t test_floor_power_of_two(std::size_t value) {
    return std::size_t{1} << (std::bit_width(value) - 1U);
}

std::size_t test_balanced_factor_radix(std::size_t size,
                                       std::size_t radix_cap) {
    if (size <= radix_cap) {
        return size;
    }
    const std::size_t log_size = std::bit_width(size) - 1U;
    return std::min(radix_cap,
                    std::size_t{1} << ((log_size + 1U) / 2U));
}

std::pair<std::size_t, std::size_t> test_transpose_tile_shape(
    std::size_t rows, std::size_t columns, std::size_t block_elements) {
    const std::size_t available_bits =
        std::bit_width(test_floor_power_of_two(block_elements)) - 1U;
    const std::size_t row_bits = std::bit_width(rows) - 1U;
    const std::size_t column_bits = std::bit_width(columns) - 1U;
    std::size_t tile_row_bits = std::min(row_bits, available_bits / 2U);
    std::size_t tile_column_bits =
        std::min(column_bits, available_bits - tile_row_bits);
    std::size_t used = tile_row_bits + tile_column_bits;
    while (used < available_bits &&
           (tile_row_bits < row_bits ||
            tile_column_bits < column_bits)) {
        if (tile_row_bits < row_bits &&
            (tile_column_bits == column_bits ||
             tile_row_bits <= tile_column_bits)) {
            ++tile_row_bits;
        } else {
            ++tile_column_bits;
        }
        ++used;
    }
    return {std::size_t{1} << tile_row_bits,
            std::size_t{1} << tile_column_bits};
}

struct FactorizedTransformAccounting {
    std::uint64_t pass_count = 0;
    std::uint64_t local_pass_count = 0;
    std::uint64_t transpose_pass_count = 0;
    std::uint64_t local_operations = 0;
    std::uint64_t indexed_read_operations = 0;
    std::uint64_t indexed_write_operations = 0;
    std::uint64_t read_seeks = 0;
    std::uint64_t write_seeks = 0;
    std::uint64_t peak_coverage_intervals = 0;
    std::uint64_t cache_resident_layers = 0;
};

std::uint64_t expected_local_ntt_operations(
    std::size_t total_size, std::size_t row_count, std::size_t row_size,
    std::size_t block_elements) {
    constexpr std::size_t minimum_transfer_elements =
        std::size_t{1} << 16U;
    const std::size_t transfer_elements = std::min(
        total_size,
        std::max(row_size,
                 std::min(block_elements, minimum_transfer_elements)));
    return test_ceil_div(row_count, transfer_elements / row_size);
}

void account_expected_transpose(FactorizedTransformAccounting &result,
                                std::size_t batch_count,
                                std::size_t rows, std::size_t columns,
                                std::size_t block_elements) {
    const auto [tile_rows, tile_columns] =
        test_transpose_tile_shape(rows, columns, block_elements);
    const std::uint64_t elements = batch_count * rows * columns;
    result.indexed_read_operations += elements / tile_columns;
    result.indexed_write_operations += elements / tile_rows;
    result.read_seeks += elements / tile_columns;
    result.write_seeks += elements / tile_rows;
    result.peak_coverage_intervals = std::max<std::uint64_t>(
        result.peak_coverage_intervals,
        tile_rows == rows ? 1U : columns);
    ++result.pass_count;
    ++result.transpose_pass_count;
}

FactorizedTransformAccounting expected_factorized_mobius(
    std::size_t size, std::size_t block_elements,
    std::size_t cache_radix_elements) {
    FactorizedTransformAccounting result;
    const std::size_t radix_cap = test_floor_power_of_two(
        std::min(block_elements, cache_radix_elements));
    std::function<void(std::size_t, std::size_t)> transform;
    transform = [&](std::size_t batch_count, std::size_t transform_size) {
        const std::size_t radix =
            test_balanced_factor_radix(transform_size, radix_cap);
        const std::size_t outer = transform_size / radix;
        ++result.pass_count;
        ++result.local_pass_count;
        result.local_operations += batch_count * transform_size / radix;
        result.cache_resident_layers +=
            batch_count * transform_size / radix *
            (std::bit_width(radix) - 1U);
        if (outer == 1) {
            return;
        }
        account_expected_transpose(result, batch_count, outer, radix,
                                   block_elements);
        transform(batch_count * radix, outer);
        account_expected_transpose(result, batch_count, radix, outer,
                                   block_elements);
    };
    transform(1, size);
    return result;
}

FactorizedTransformAccounting expected_factorized_ntt(
    std::size_t size, std::size_t block_elements,
    std::size_t cache_radix_elements) {
    FactorizedTransformAccounting result;
    const std::size_t radix_cap = test_floor_power_of_two(
        std::min(block_elements, cache_radix_elements));
    std::function<void(std::size_t, std::size_t)> transform;
    transform = [&](std::size_t batch_count, std::size_t transform_size) {
        const std::size_t radix =
            test_balanced_factor_radix(transform_size, radix_cap);
        const std::size_t outer = transform_size / radix;
        if (outer == 1) {
            ++result.pass_count;
            ++result.local_pass_count;
            result.local_operations += expected_local_ntt_operations(
                size, batch_count, radix, block_elements);
            result.cache_resident_layers +=
                batch_count * (std::bit_width(radix) - 1U);
            return;
        }
        account_expected_transpose(result, batch_count, outer, radix,
                                   block_elements);
        transform(batch_count * radix, outer);
        account_expected_transpose(result, batch_count, radix, outer,
                                   block_elements);
        ++result.pass_count;
        ++result.local_pass_count;
        result.local_operations += expected_local_ntt_operations(
            size, batch_count * outer, radix, block_elements);
        result.cache_resident_layers +=
            batch_count * outer * (std::bit_width(radix) - 1U);
        account_expected_transpose(result, batch_count, outer, radix,
                                   block_elements);
    };
    transform(1, size);
    return result;
}

Fq2 evaluate_msb(const std::vector<Fq> &evaluations,
                 const std::vector<Fq2> &point) {
    Fq2 result = Fq2::zero();
    for (std::size_t index = 0; index < evaluations.size(); ++index) {
        Fq2 weight = Fq2::one();
        for (std::size_t variable = 0; variable < point.size(); ++variable) {
            const bool bit =
                ((index >> (point.size() - 1 - variable)) & 1U) != 0;
            weight *= bit ? point[variable]
                          : Fq2::one() - point[variable];
        }
        result += weight * evaluations[index];
    }
    return result;
}

Fq2 evaluate_linear_combination_msb(
    const std::vector<std::vector<Fq>> &columns,
    const std::vector<Fq2> &weights, const std::vector<Fq2> &point) {
    Fq2 result = Fq2::zero();
    for (std::size_t column = 0; column < columns.size(); ++column) {
        result += weights[column] * evaluate_msb(columns[column], point);
    }
    return result;
}

void bind(const PcsCommitment &commitment, Transcript &transcript) {
    transcript.observe("test/basefold/commitment",
                       laminate::spartan::encode_pcs_commitment(commitment));
}

void test_open_and_verify() {
    // Pin the single-instance encoding independently of selected defaults.
    BaseFoldPcs pcs({.log_rate = 1, .query_count = 128});
    std::vector<Fq> evaluations(64);
    for (std::size_t index = 0; index < evaluations.size(); ++index) {
        evaluations[index] = Fq(17 * index * index + 9 * index + 4);
    }
    const std::vector<Fq2> point{
        Fq2({Fq(2), Fq(3)}),   Fq2({Fq(5), Fq(7)}),
        Fq2({Fq(11), Fq(13)}), Fq2({Fq(17), Fq(19)}),
        Fq2({Fq(23), Fq(29)}), Fq2({Fq(31), Fq(37)}),
    };
    const Fq2 value = evaluate_msb(evaluations, point);
    const IPCS::CommitOutput committed = pcs.commit(evaluations);

    Transcript prover("laminate/test/basefold-pcs/v1");
    bind(committed.commitment, prover);
    const PcsOpeningProof proof = pcs.open(
        committed.prover_state, point, value, prover);
    const laminate::Digest expected_digest{
        0xc3, 0xe7, 0x66, 0xf0, 0x98, 0xb9, 0x53, 0xcb,
        0x7b, 0x9b, 0x7c, 0x6a, 0xf6, 0xfc, 0x1c, 0x4d,
        0x69, 0x0d, 0x84, 0xb4, 0x19, 0xe6, 0xfe, 0x93,
        0x8e, 0xd5, 0xd9, 0x37, 0x82, 0x03, 0x92, 0x4e,
    };
    CHECK(laminate::sha256(proof.bytes) == expected_digest);
    CHECK(!proof.bytes.empty());
    CHECK(proof.bytes.size() <=
          basefold_opening_proof_max_size_bytes(point.size(), 1,
                                               pcs.parameters()));

    Transcript verifier("laminate/test/basefold-pcs/v1");
    bind(committed.commitment, verifier);
    CHECK(pcs.verify(committed.commitment, point, value, proof, verifier));
}

void test_default_rate_eight_resident_and_external_openings() {
    const BaseFoldPcs pcs;
    CHECK(pcs.parameters().log_rate == 3U);
    CHECK(pcs.parameters().query_count ==
          laminate::kTranscriptPackingBaseFoldQueries);
    CHECK(pcs.parameters().query_count == 150U);
    // Fq supports codewords through 2^37, leaving 2^34 message entries
    // at rate 1/8. Check capacity using formulas, without allocating tables.
    CHECK(basefold_opening_proof_max_size_bytes(
              34U, 1U, pcs.parameters()) > 0U);
    CHECK(basefold_opening_max_merkle_hashes(34U, pcs.parameters()) > 0U);
    CHECK(throws_exception([&] {
        (void)basefold_opening_proof_max_size_bytes(
            35U, 1U, pcs.parameters());
    }));
    CHECK(throws_exception([&] {
        (void)basefold_opening_max_merkle_hashes(35U, pcs.parameters());
    }));
    const std::vector<Fq2> point{
        Fq2({Fq(3), Fq(5)}), Fq2({Fq(7), Fq(11)}),
        Fq2({Fq(13), Fq(17)}), Fq2({Fq(19), Fq(23)}),
    };
    const std::vector<Fq2> weights{
        Fq2({Fq(29), Fq(31)}), Fq2({Fq(37), Fq(41)}),
    };
    std::vector<std::vector<Fq>> columns(2, std::vector<Fq>(16));
    for (std::size_t column = 0; column < columns.size(); ++column) {
        for (std::size_t index = 0; index < columns[column].size(); ++index) {
            columns[column][index] =
                Fq(index * index + 13 * column * index + 17 * column + 3);
        }
    }
    const Fq2 value =
        evaluate_linear_combination_msb(columns, weights, point);
    const IPCS::CommitOutput committed = pcs.commit_columns(columns);
    CHECK(committed.commitment.log_rate == 3U);
    CHECK(committed.commitment.query_count == 150U);
    CHECK(laminate::spartan::encode_pcs_commitment(committed.commitment).size() ==
          80U);
    Transcript resident_coin("laminate/test/basefold-selected-policy/v1");
    bind(committed.commitment, resident_coin);
    QueryBlockRecordingCoin resident_recording(resident_coin);
    const PcsOpeningProof resident = pcs.open_linear_combination(
        committed.prover_state, weights, point, value, resident_recording);
    CHECK(resident.bytes.size() <= basefold_opening_proof_max_size_bytes(
                                       point.size(), columns.size(),
                                       pcs.parameters()));

    TemporaryDirectory state_directory("selected-state");
    const auto externalized = pcs.externalize_prover_state(
        committed.prover_state,
        BaseFoldExternalStateOptions{
            .directory = state_directory.path(),
            .limits = {.max_total_bytes = 1ULL << 20U,
                       .min_free_bytes = 1},
        });
    CHECK(externalized.report.codeword_payload_bytes ==
          2U * 16U * 8U * sizeof(Fq));
    const auto reopened = pcs.open_external_prover_state(
        state_directory.path(), committed.commitment);
    TemporaryDirectory scratch_directory("selected-scratch");
    Transcript external_coin("laminate/test/basefold-selected-policy/v1");
    bind(committed.commitment, external_coin);
    QueryBlockRecordingCoin external_recording(external_coin);
    const auto opening_options =
        external_opening_options(scratch_directory.path());
    const auto preflight = pcs.preflight_external_opening(
        reopened, committed.commitment, opening_options);
    const auto external = pcs.open_linear_combination_external(
        reopened, weights, point, value,
        opening_options, external_recording);
    CHECK(external.proof == resident);
    CHECK(external.report.proof_bytes == resident.bytes.size());
    CHECK(external.report.artifact_validation_passes == 1U);
    CHECK(external.report.state_artifact_validation_bytes ==
          externalized.report.physical_bytes);
    CHECK(external.report.scratch_peak_physical_bytes ==
          preflight.required_scratch_physical_bytes);
    CHECK(external.report.scratch_written_physical_bytes ==
          preflight.required_scratch_written_physical_bytes);
    CHECK(external.report.scratch_chunk_artifacts_written ==
          preflight.required_chunk_artifacts_written);
    CHECK(external_coin.challenge_fq2() == resident_coin.challenge_fq2());
    CHECK(std::filesystem::is_empty(scratch_directory.path()));

    const auto check_challenge_blocks = [&](const QueryBlockRecordingCoin &coin) {
        CHECK(coin.fold_challenges == point.size());
        // The 16-row, rate-1/8 codeword has 64 possible first query pairs.
        CHECK(coin.query_blocks == std::vector<std::size_t>{150U * 6U});
        CHECK(coin.observations_before_queries ==
              std::vector<std::string>{"laminate/basefold/final/v1"});
    };
    check_challenge_blocks(resident_recording);
    check_challenge_blocks(external_recording);

    const auto verifies = [&](const BaseFoldPcs &verifier_pcs,
                              const PcsOpeningProof &proof,
                              const Fq2 &claim) {
        Transcript verifier("laminate/test/basefold-selected-policy/v1");
        bind(committed.commitment, verifier);
        QueryBlockRecordingCoin recording(verifier);
        const bool accepted = verifier_pcs.verify_linear_combination(
            committed.commitment, weights, point, claim, proof, recording);
        if (accepted) {
            check_challenge_blocks(recording);
        }
        return accepted;
    };
    CHECK(verifies(pcs, external.proof, value));
    CHECK(!verifies(pcs, external.proof, value + Fq2::one()));
    PcsOpeningProof corrupted = external.proof;
    corrupted.bytes[corrupted.bytes.size() / 2U] ^= 1U;
    CHECK(!verifies(pcs, corrupted, value));

    const auto read_u64 = [&](std::size_t position) {
        CHECK(position + 8U <= resident.bytes.size());
        std::uint64_t result = 0;
        for (std::size_t byte = 0; byte < 8U; ++byte) {
            result |= std::uint64_t(resident.bytes[position + byte]) <<
                      (8U * byte);
        }
        return result;
    };
    // One version-four proof directly contains its sumcheck rounds. There is
    // no outer envelope or repeated-proof count.
    CHECK(read_u64(0) == 4U);
    CHECK(read_u64(8) == point.size());
    PcsOpeningProof truncated = resident;
    truncated.bytes.pop_back();
    CHECK(!verifies(pcs, truncated, value));
    corrupted = resident;
    corrupted.bytes[0] = 5U;
    CHECK(!verifies(pcs, corrupted, value));
    corrupted = resident;
    corrupted.bytes.push_back(0U);
    CHECK(!verifies(pcs, corrupted, value));

    auto changed_parameters = pcs.parameters();
    --changed_parameters.log_rate;
    const BaseFoldPcs changed_rate(changed_parameters);
    CHECK(!verifies(changed_rate, resident, value));
    CHECK(throws_exception([&] {
        (void)changed_rate.open_external_prover_state(
            state_directory.path(), committed.commitment);
    }));
    changed_parameters = pcs.parameters();
    --changed_parameters.query_count;
    const BaseFoldPcs changed_queries(changed_parameters);
    CHECK(!verifies(changed_queries, resident, value));
    PcsCommitment changed_commitment = committed.commitment;
    --changed_commitment.query_count;
    CHECK(laminate::spartan::encode_pcs_commitment(changed_commitment) !=
          laminate::spartan::encode_pcs_commitment(committed.commitment));
    CHECK(laminate::spartan::basefold_external_state_identity(changed_commitment) !=
          laminate::spartan::basefold_external_state_identity(committed.commitment));
    CHECK(throws_exception([&] {
        (void)changed_queries.open_external_prover_state(
            state_directory.path(), committed.commitment);
    }));
}

void test_mutations_reject() {
    BaseFoldPcs pcs({.log_rate = 2, .query_count = 16});
    std::vector<Fq> evaluations(16);
    for (std::size_t index = 0; index < evaluations.size(); ++index) {
        evaluations[index] = Fq(index + 1);
    }
    const std::vector<Fq2> point{
        Fq2({Fq(3), Fq(1)}), Fq2({Fq(5), Fq(2)}),
        Fq2({Fq(7), Fq(4)}), Fq2({Fq(11), Fq(8)}),
    };
    const Fq2 value = evaluate_msb(evaluations, point);
    const IPCS::CommitOutput committed = pcs.commit(evaluations);
    Transcript prover("laminate/test/basefold-mutation/v1");
    bind(committed.commitment, prover);
    const PcsOpeningProof proof = pcs.open(
        committed.prover_state, point, value, prover);

    PcsOpeningProof corrupted = proof;
    corrupted.bytes[corrupted.bytes.size() / 2] ^= 1U;
    Transcript bad_proof("laminate/test/basefold-mutation/v1");
    bind(committed.commitment, bad_proof);
    CHECK(!pcs.verify(committed.commitment, point, value, corrupted,
                      bad_proof));

    Transcript bad_value("laminate/test/basefold-mutation/v1");
    bind(committed.commitment, bad_value);
    CHECK(!pcs.verify(committed.commitment, point, value + Fq2::one(),
                      proof, bad_value));

    PcsCommitment bad_commitment = committed.commitment;
    bad_commitment.root[0] ^= 1U;
    Transcript bad_root("laminate/test/basefold-mutation/v1");
    bind(bad_commitment, bad_root);
    CHECK(!pcs.verify(bad_commitment, point, value, proof, bad_root));
}

void test_batched_linear_combination() {
    BaseFoldPcs pcs({.log_rate = 2, .query_count = 16});
    std::vector<std::vector<Fq>> columns(4, std::vector<Fq>(32));
    for (std::size_t column = 0; column < columns.size(); ++column) {
        for (std::size_t index = 0; index < columns[column].size(); ++index) {
            columns[column][index] =
                Fq((column + 3) * index * index + 11 * column + index + 7);
        }
    }
    const std::vector<Fq2> weights{
        Fq2({Fq(2), Fq(3)}), Fq2({Fq(5), Fq(7)}),
        Fq2({Fq(11), Fq(13)}), Fq2({Fq(17), Fq(19)}),
    };
    const std::vector<Fq2> point{
        Fq2({Fq(23), Fq(29)}), Fq2({Fq(31), Fq(37)}),
        Fq2({Fq(41), Fq(43)}), Fq2({Fq(47), Fq(53)}),
        Fq2({Fq(59), Fq(61)}),
    };
    const Fq2 value =
        evaluate_linear_combination_msb(columns, weights, point);
    const IPCS::CommitOutput committed = pcs.commit_columns(columns);
    CHECK(committed.commitment.width == columns.size());

    Transcript prover("laminate/test/basefold-batched/v1");
    bind(committed.commitment, prover);
    const PcsOpeningProof proof = pcs.open_linear_combination(
        committed.prover_state, weights, point, value, prover);
    const laminate::Digest expected_digest{
        0x6a, 0x26, 0xc8, 0x73, 0x51, 0x89, 0x75, 0x70,
        0xfb, 0xb6, 0x8e, 0x3b, 0x2d, 0xd4, 0x86, 0x55,
        0xf6, 0x97, 0xc8, 0xa5, 0x4a, 0xac, 0xf0, 0x73,
        0x0a, 0xc1, 0x58, 0x40, 0x19, 0x1a, 0x28, 0xe5,
    };
    CHECK(laminate::sha256(proof.bytes) == expected_digest);
    CHECK(proof.bytes.size() <= basefold_opening_proof_max_size_bytes(
                                     point.size(), columns.size(),
                                     {.log_rate = 2,
                                      .query_count = 16}));

    Transcript verifier("laminate/test/basefold-batched/v1");
    bind(committed.commitment, verifier);
    CHECK(pcs.verify_linear_combination(committed.commitment, weights,
                                        point, value, proof, verifier));

    std::vector<Fq2> bad_weights = weights;
    bad_weights[2] += Fq2::one();
    Transcript bad("laminate/test/basefold-batched/v1");
    bind(committed.commitment, bad);
    CHECK(!pcs.verify_linear_combination(committed.commitment, bad_weights,
                                         point, value, proof, bad));
}

void test_singleton_and_shape_checks() {
    BaseFoldPcs pcs({.log_rate = 2, .query_count = 8});
    const std::vector<Fq> evaluations{Fq(42)};
    const std::vector<Fq2> point;
    const IPCS::CommitOutput committed = pcs.commit(evaluations);
    Transcript prover("laminate/test/basefold-singleton/v1");
    bind(committed.commitment, prover);
    const PcsOpeningProof proof = pcs.open(
        committed.prover_state, point, Fq2::from_base(Fq(42)), prover);
    Transcript verifier("laminate/test/basefold-singleton/v1");
    bind(committed.commitment, verifier);
    CHECK(pcs.verify(committed.commitment, point,
                     Fq2::from_base(Fq(42)), proof, verifier));

    bool threw = false;
    try {
        const std::vector<Fq2> wrong_point{Fq2::one()};
        Transcript wrong("laminate/test/basefold-singleton/v1");
        (void)pcs.open(committed.prover_state, wrong_point,
                       Fq2::from_base(Fq(42)), wrong);
    } catch (const std::invalid_argument &) {
        threw = true;
    }
    CHECK(threw);

    TemporaryDirectory state_directory("singleton-state");
    const auto externalized = pcs.externalize_prover_state(
        committed.prover_state,
        BaseFoldExternalStateOptions{
            .directory = state_directory.path(),
            .limits = {
                .max_total_bytes = 1ULL << 20U,
                .min_free_bytes = 1,
            },
        });
    TemporaryDirectory scratch_directory("singleton-scratch");
    Transcript external_coin("laminate/test/basefold-singleton/v1");
    bind(committed.commitment, external_coin);
    const auto external = pcs.open_external(
        externalized.prover_state, point, Fq2::from_base(Fq(42)),
        external_opening_options(scratch_directory.path(), 256),
        external_coin);
    CHECK(external.proof == proof);
    CHECK(external.report.from_scratch_sumcheck_rounds == 0);
    CHECK(external.report.scratch_physical_bytes == 0);
    CHECK(std::filesystem::is_empty(scratch_directory.path()));
}

void test_multiproof_work_bounds() {
    // message_log=7 and log_rate=2 give oracle leaf counts
    // 8,4,2,1,1,1,1 from the base layer through the committed folds.
    CHECK(basefold_opening_max_merkle_hashes(
              7, {.log_rate = 2, .query_count = 1}) == 19U);
    CHECK(basefold_opening_max_merkle_hashes(
              7, {.log_rate = 2, .query_count = 2}) == 25U);

    const BaseFoldPcs pcs({.log_rate = 2, .query_count = 2});
    std::vector<Fq> evaluations(128);
    for (std::size_t index = 0; index < evaluations.size(); ++index) {
        evaluations[index] = Fq(13 * index + 9);
    }
    const std::vector<Fq2> point{
        Fq2({Fq(2), Fq(3)}),   Fq2({Fq(5), Fq(7)}),
        Fq2({Fq(11), Fq(13)}), Fq2({Fq(17), Fq(19)}),
        Fq2({Fq(23), Fq(29)}), Fq2({Fq(31), Fq(37)}),
        Fq2({Fq(41), Fq(43)}),
    };
    const Fq2 value = evaluate_msb(evaluations, point);
    const IPCS::CommitOutput committed = pcs.commit(evaluations);
    Transcript prover("laminate/test/basefold-multiproof-bound/v1");
    bind(committed.commitment, prover);
    const PcsOpeningProof proof = pcs.open(
        committed.prover_state, point, value, prover);
    CHECK(!proof.bytes.empty());
    CHECK(proof.bytes.size() <= basefold_opening_proof_max_size_bytes(
                                     point.size(), 1U,
                                     {.log_rate = 2,
                                      .query_count = 2}));
}

void test_small_domains_at_supported_rates() {
    for (const std::size_t message_size : {std::size_t{2},
                                           std::size_t{8}}) {
        for (std::size_t log_rate = 0; log_rate <= 3; ++log_rate) {
            const BaseFoldPcs pcs({.log_rate = log_rate,
                                   .query_count = 1});
            std::vector<Fq> evaluations(message_size);
            for (std::size_t index = 0; index < message_size; ++index) {
                evaluations[index] = Fq(5 * index + log_rate + 1);
            }
            std::vector<Fq2> point;
            for (std::size_t size = message_size; size > 1; size /= 2) {
                point.push_back(Fq2({Fq(size + log_rate), Fq(size + 3)}));
            }
            const Fq2 value = evaluate_msb(evaluations, point);
            const IPCS::CommitOutput committed = pcs.commit(evaluations);
            Transcript prover("laminate/test/basefold-small-domain/v1");
            bind(committed.commitment, prover);
            const PcsOpeningProof proof = pcs.open(
                committed.prover_state, point, value, prover);
            CHECK(proof.bytes.size() <=
                  basefold_opening_proof_max_size_bytes(
                      point.size(), 1, pcs.parameters()));
            Transcript verifier("laminate/test/basefold-small-domain/v1");
            bind(committed.commitment, verifier);
            CHECK(pcs.verify(committed.commitment, point, value, proof,
                             verifier));
        }
    }
}

void test_external_opening_matches_resident() {
    const BaseFoldPcs pcs({.log_rate = 2, .query_count = 16});
    std::vector<std::vector<Fq>> columns(3, std::vector<Fq>(256));
    for (std::size_t column = 0; column < columns.size(); ++column) {
        for (std::size_t index = 0; index < columns[column].size(); ++index) {
            columns[column][index] =
                Fq(19 * index * index + 7 * column * index + 31 * column + 5);
        }
    }
    const std::vector<Fq2> weights{
        Fq2({Fq(2), Fq(3)}), Fq2({Fq(5), Fq(7)}),
        Fq2({Fq(11), Fq(13)}),
    };
    const std::vector<Fq2> point{
        Fq2({Fq(17), Fq(19)}), Fq2({Fq(23), Fq(29)}),
        Fq2({Fq(31), Fq(37)}), Fq2({Fq(41), Fq(43)}),
        Fq2({Fq(47), Fq(53)}), Fq2({Fq(59), Fq(61)}),
        Fq2({Fq(67), Fq(71)}), Fq2({Fq(73), Fq(79)}),
    };
    const Fq2 value =
        evaluate_linear_combination_msb(columns, weights, point);
    const IPCS::CommitOutput committed = pcs.commit_columns(columns);

    Transcript resident_coin("laminate/test/basefold-external/v1");
    bind(committed.commitment, resident_coin);
    const PcsOpeningProof resident = pcs.open_linear_combination(
        committed.prover_state, weights, point, value, resident_coin);

    TemporaryDirectory state_directory("state");
    const auto externalized = pcs.externalize_prover_state(
        committed.prover_state,
        BaseFoldExternalStateOptions{
            .directory = state_directory.path(),
            .limits = {
                .max_total_bytes = 1ULL << 24U,
                .min_free_bytes = 1,
            },
        });
    CHECK(externalized.commitment == committed.commitment);
    CHECK(externalized.report.physical_bytes ==
          recursive_file_bytes(state_directory.path()));
    CHECK(externalized.report.message_payload_bytes == 3U * 256U * 8U);
    CHECK(externalized.report.codeword_payload_bytes == 3U * 1024U * 8U);
    CHECK(externalized.report.merkle_tree_payload_bytes == 31U * 40U);

    const auto reopened = pcs.open_external_prover_state(
        state_directory.path(), committed.commitment);
    TemporaryDirectory scratch_directory("scratch");
    Transcript external_coin("laminate/test/basefold-external/v1");
    bind(committed.commitment, external_coin);
    const BaseFoldExternalOpeningOptions opening_options =
        external_opening_options(scratch_directory.path());
    const auto admission = pcs.preflight_external_opening(
        reopened, committed.commitment, opening_options);
    const auto external = pcs.open_linear_combination_external(
        reopened, weights, point, value, opening_options, external_coin);
    CHECK(external.proof == resident);
    CHECK(external_coin.challenge_fq2() == resident_coin.challenge_fq2());
    CHECK(external.report.proof_bytes == resident.bytes.size());
    CHECK(external.report.from_scratch_sumcheck_rounds == 2);
    CHECK(external.report.materialized_sumcheck_entries == 64);
    CHECK(external.report.peak_working_field_bytes == 3328);
    CHECK(external.report.scratch_physical_bytes == 0);
    CHECK(std::filesystem::is_empty(scratch_directory.path()));
    CHECK(external.report.scratch_peak_physical_bytes ==
          admission.required_scratch_physical_bytes);
    CHECK(external.report.scratch_written_physical_bytes ==
          admission.required_scratch_written_physical_bytes);
    CHECK(external.report.scratch_deleted_physical_bytes ==
          external.report.scratch_written_physical_bytes);
    CHECK(external.report.pass_one_scratch_written_physical_bytes ==
          external.report.pass_two_scratch_written_physical_bytes);
    CHECK(2U * external.report.pass_one_scratch_written_physical_bytes ==
          external.report.scratch_written_physical_bytes);
    CHECK(external.report.peak_live_storage_bytes ==
          externalized.report.physical_bytes +
              external.report.scratch_peak_physical_bytes);
    CHECK(external.report.artifact_validation_bytes ==
          externalized.report.physical_bytes +
              2U * external.report.scratch_written_physical_bytes);
    CHECK(external.report.scratch_deletion_validation_bytes ==
          external.report.scratch_written_physical_bytes);
    std::uint64_t expected_one_pass_physical = 0;
    std::uint64_t expected_one_pass_payload = 0;
    for (const std::size_t layer_size :
         {std::size_t{512}, std::size_t{256}, std::size_t{128},
          std::size_t{64}, std::size_t{32}, std::size_t{16},
          std::size_t{8}}) {
        const std::size_t chunk_size =
            std::min(layer_size, std::size_t{128});
        for (std::size_t first = 0; first < layer_size;
             first += chunk_size) {
            expected_one_pass_physical +=
                test_fold_chunk_physical_bytes(
                    std::min(chunk_size, layer_size - first));
        }
        expected_one_pass_payload += 16U * layer_size;
    }
    CHECK(external.report.pass_one_scratch_written_physical_bytes ==
          expected_one_pass_physical);
    CHECK(external.report.scratch_peak_physical_bytes ==
          5U * test_fold_chunk_physical_bytes(128));
    CHECK(external.report.sequential_write_payload_bytes ==
          2U * expected_one_pass_payload);
    CHECK(external.report.pass_one_sequential_write_payload_bytes ==
          expected_one_pass_payload);
    CHECK(external.report.pass_two_sequential_write_payload_bytes ==
          expected_one_pass_payload);
    CHECK(external.report.pass_one_chunk_artifacts_written == 11);
    CHECK(external.report.pass_two_chunk_artifacts_written == 11);
    CHECK(external.report.scratch_chunk_artifacts_written == 22);
    CHECK(external.report.scratch_chunk_artifacts_deleted == 22);
    CHECK(external.report.scratch_files_written == 44);
    CHECK(external.report.scratch_files_deleted == 44);
    CHECK(external.report.sequential_read_payload_bytes ==
          external.report.sumcheck_sequential_read_payload_bytes +
              external.report.pass_one_fold_sequential_read_payload_bytes +
              external.report.pass_two_fold_sequential_read_payload_bytes);
    CHECK(external.report.base_query_indexed_read_payload_bytes <
          external.report.indexed_read_payload_bytes);
    CHECK(external.report.sequential_read_payload_bytes >
          external.report.sequential_write_payload_bytes);
    CHECK(external.report.indexed_read_payload_bytes != 0);

    TemporaryDirectory repeat_scratch("repeat-scratch");
    Transcript repeat_coin("laminate/test/basefold-external/v1");
    bind(committed.commitment, repeat_coin);
    const auto repeated = pcs.open_linear_combination_external(
        reopened, weights, point, value,
        external_opening_options(repeat_scratch.path()), repeat_coin);
    CHECK(repeated.proof == external.proof);
    CHECK(repeated.report == external.report);

    Transcript verifier("laminate/test/basefold-external/v1");
    bind(committed.commitment, verifier);
    CHECK(pcs.verify_linear_combination(committed.commitment, weights,
                                        point, value, external.proof,
                                        verifier));
}

void test_external_opening_limits_and_identity() {
    const BaseFoldPcs pcs({.log_rate = 1, .query_count = 4});
    std::vector<Fq> evaluations(64);
    for (std::size_t index = 0; index < evaluations.size(); ++index) {
        evaluations[index] = Fq(3 * index + 1);
    }
    const std::vector<Fq2> point{
        Fq2({Fq(2), Fq(3)}), Fq2({Fq(5), Fq(7)}),
        Fq2({Fq(11), Fq(13)}), Fq2({Fq(17), Fq(19)}),
        Fq2({Fq(23), Fq(29)}), Fq2({Fq(31), Fq(37)}),
    };
    const Fq2 value = evaluate_msb(evaluations, point);
    const IPCS::CommitOutput committed = pcs.commit(evaluations);
    TemporaryDirectory state_quota("state-quota");
    CHECK(throws_exception([&] {
        (void)pcs.externalize_prover_state(
            committed.prover_state,
            BaseFoldExternalStateOptions{
                .directory = state_quota.path(),
                .limits = {
                    .max_total_bytes = 128,
                    .min_free_bytes = 1,
                },
            });
    }));
    TemporaryDirectory state_directory("limits-state");
    const auto externalized = pcs.externalize_prover_state(
        committed.prover_state,
        BaseFoldExternalStateOptions{
            .directory = state_directory.path(),
            .limits = {
                .max_total_bytes = 1ULL << 20U,
                .min_free_bytes = 1,
            },
        });

    TemporaryDirectory admitted_scratch("admitted-scratch");
    BaseFoldExternalOpeningOptions admitted_options =
        external_opening_options(admitted_scratch.path(), 4096);
    const auto admission = pcs.preflight_external_opening(
        externalized.prover_state, committed.commitment,
        admitted_options);
    CHECK(admission.state_artifact_directory ==
          std::filesystem::canonical(state_directory.path()));
    CHECK(admission.required_live_storage_bytes ==
          admission.state_artifact_physical_bytes +
              admission.required_scratch_physical_bytes);
    CHECK(admission.state_artifact_physical_bytes ==
          externalized.report.physical_bytes);
    CHECK(admission.required_scratch_written_physical_bytes >
          admission.required_scratch_physical_bytes);
    CHECK(admission.required_sequential_write_payload_bytes != 0);

    TemporaryDirectory small_live("small-live");
    BaseFoldExternalOpeningOptions small_live_options =
        external_opening_options(small_live.path(), 4096);
    small_live_options.max_live_storage_bytes =
        admission.required_live_storage_bytes - 1U;
    Transcript live_coin("laminate/test/basefold-external-limits/v1");
    bind(committed.commitment, live_coin);
    CHECK(throws_exception([&] {
        (void)pcs.open_external(
            externalized.prover_state, point, value,
            small_live_options, live_coin);
    }));
    CHECK(std::filesystem::is_empty(small_live.path()));
    Transcript untouched_live_coin(
        "laminate/test/basefold-external-limits/v1");
    bind(committed.commitment, untouched_live_coin);
    CHECK(live_coin.challenge_fq2() ==
          untouched_live_coin.challenge_fq2());

    PcsCommitment wrong = committed.commitment;
    wrong.root.front() ^= 1U;
    CHECK(throws_exception([&] {
        (void)pcs.open_external_prover_state(state_directory.path(), wrong);
    }));

    TemporaryDirectory small_ram("small-ram");
    Transcript ram_coin("laminate/test/basefold-external-limits/v1");
    bind(committed.commitment, ram_coin);
    CHECK(throws_exception([&] {
        (void)pcs.open_external(
            externalized.prover_state, point, value,
            external_opening_options(small_ram.path(), 1), ram_coin);
    }));
    CHECK(std::filesystem::is_empty(small_ram.path()));
    Transcript untouched_ram_coin(
        "laminate/test/basefold-external-limits/v1");
    bind(committed.commitment, untouched_ram_coin);
    CHECK(ram_coin.challenge_fq2() == untouched_ram_coin.challenge_fq2());

    TemporaryDirectory bad_chunk("bad-chunk");
    BaseFoldExternalOpeningOptions bad_chunk_options =
        external_opening_options(bad_chunk.path(), 4096);
    bad_chunk_options.fold_chunk_elements = 3;
    Transcript bad_chunk_coin(
        "laminate/test/basefold-external-limits/v1");
    bind(committed.commitment, bad_chunk_coin);
    CHECK(throws_exception([&] {
        (void)pcs.open_external(externalized.prover_state, point, value,
                                bad_chunk_options, bad_chunk_coin);
    }));
    CHECK(std::filesystem::is_empty(bad_chunk.path()));
    Transcript untouched_bad_chunk_coin(
        "laminate/test/basefold-external-limits/v1");
    bind(committed.commitment, untouched_bad_chunk_coin);
    CHECK(bad_chunk_coin.challenge_fq2() ==
          untouched_bad_chunk_coin.challenge_fq2());

    TemporaryDirectory unaligned_chunk("unaligned-chunk");
    BaseFoldExternalOpeningOptions unaligned_chunk_options =
        external_opening_options(unaligned_chunk.path(), 4096);
    unaligned_chunk_options.fold_chunk_elements = 1;
    Transcript unaligned_chunk_coin(
        "laminate/test/basefold-external-limits/v1");
    bind(committed.commitment, unaligned_chunk_coin);
    CHECK(throws_exception([&] {
        (void)pcs.open_external(
            externalized.prover_state, point, value,
            unaligned_chunk_options, unaligned_chunk_coin);
    }));
    CHECK(std::filesystem::is_empty(unaligned_chunk.path()));
    Transcript untouched_unaligned_chunk_coin(
        "laminate/test/basefold-external-limits/v1");
    bind(committed.commitment, untouched_unaligned_chunk_coin);
    CHECK(unaligned_chunk_coin.challenge_fq2() ==
          untouched_unaligned_chunk_coin.challenge_fq2());

    TemporaryDirectory small_disk("small-disk");
    Transcript disk_coin("laminate/test/basefold-external-limits/v1");
    bind(committed.commitment, disk_coin);
    CHECK(throws_exception([&] {
        (void)pcs.open_external(
            externalized.prover_state, point, value,
            external_opening_options(small_disk.path(), 4096, 128),
            disk_coin);
    }));

    // A failure after Fiat--Shamir has advanced still owns and cleans every
    // chunk it published. The caller must discard this advanced transcript.
    TemporaryDirectory late_failure("late-failure");
    Transcript late_coin("laminate/test/basefold-external-limits/v1");
    bind(committed.commitment, late_coin);
    CHECK(throws_exception([&] {
        (void)pcs.open_external(
            externalized.prover_state, point, value + Fq2::one(),
            external_opening_options(late_failure.path(), 4096),
            late_coin);
    }));
    CHECK(std::filesystem::is_empty(late_failure.path()));

    const std::filesystem::path array =
        state_directory.path() / "array-0000000000000000.bin";
    std::fstream bytes(array, std::ios::binary | std::ios::in |
                                  std::ios::out);
    CHECK(static_cast<bool>(bytes));
    bytes.seekg(-1, std::ios::end);
    char last = 0;
    bytes.read(&last, 1);
    bytes.seekp(-1, std::ios::end);
    last ^= 1;
    bytes.write(&last, 1);
    bytes.close();
    CHECK(throws_exception([&] {
        (void)pcs.open_external_prover_state(
            state_directory.path(), committed.commitment);
    }));
}

void test_external_commitment_matches_resident() {
    struct TestCase {
        std::size_t message_size;
        std::size_t log_rate;
        std::size_t width;
        std::size_t block_elements;
    };
    const std::array<TestCase, 6> cases{{
        {2, 0, 1, 2},
        // Requested block 3 floors to radix 2, so codeword 16 exercises
        // several recursive factors as well as a non-power-of-two request.
        {8, 1, 2, 3},
        {16, 2, 3, 8},
        {32, 0, 2, 8},
        {64, 2, 3, 16},
        {64, 3, 3, 16},
    }};

    for (std::size_t case_index = 0; case_index < cases.size();
         ++case_index) {
        const TestCase selected = cases[case_index];
        const BaseFoldPcs pcs({
            .log_rate = selected.log_rate,
            .query_count = selected.log_rate == 3U
                ? laminate::kTranscriptPackingBaseFoldQueries : 4U,
        });
        std::vector<std::string> names;
        std::vector<std::vector<Fq>> columns(
            selected.width, std::vector<Fq>(selected.message_size));
        for (std::size_t column = 0; column < selected.width; ++column) {
            names.push_back("source-column-" + std::to_string(column));
            for (std::size_t index = 0; index < selected.message_size;
                 ++index) {
                columns[column][index] = Fq(
                    23 * index * index + 17 * column * index +
                    31 * column + 7 * case_index + 5);
            }
        }
        TemporaryDirectory source_directory(
            "commit-source-" + std::to_string(case_index));
        TemporaryDirectory destination_directory(
            "commit-final-" + std::to_string(case_index));
        TemporaryDirectory scratch_directory(
            "commit-scratch-" + std::to_string(case_index));
        const auto source = write_external_commit_source(
            source_directory.path(), names, columns);
        const auto source_arrays = source->arrays();
        const std::uint64_t source_bytes = source->physical_bytes();

        const IPCS::CommitOutput resident = pcs.commit_columns(columns);
        std::vector<BaseFoldExternalCommitProgress> progress_events;
        BaseFoldExternalCommitOptions commit_options =
            external_commit_options(destination_directory.path(),
                                    scratch_directory.path(),
                                    selected.block_elements);
        commit_options.progress =
            [&](const BaseFoldExternalCommitProgress &progress) {
                progress_events.push_back(progress);
            };
        const auto external = pcs.commit_artifact_columns(
            source, names, std::move(commit_options));
        CHECK(external.externalization.commitment == resident.commitment);
        CHECK(external.externalization.report.physical_bytes ==
              external.report.final_physical_bytes);
        CHECK(external.externalization.report.physical_bytes ==
              recursive_file_bytes(destination_directory.path()));
        CHECK(std::filesystem::is_empty(scratch_directory.path()));
        CHECK(source->physical_bytes() == source_bytes);
        CHECK(source->arrays() == source_arrays);
        CHECK(recursive_file_bytes(source_directory.path()) == source_bytes);
        CHECK(!progress_events.empty());
        std::uint64_t previous_passes = 0;
        std::uint64_t previous_pass_work = 0;
        std::size_t work_updates_in_pass = 0;
        for (const BaseFoldExternalCommitProgress &progress :
             progress_events) {
            CHECK(progress.column_count == selected.width);
            CHECK(progress.completed_passes >= previous_passes);
            CHECK(progress.completed_passes <= progress.total_passes);
            CHECK(progress.pass_total_work_units != 0);
            CHECK(progress.pass_completed_work_units <=
                  progress.pass_total_work_units);
            CHECK(progress.phase_completed_passes <=
                  progress.phase_total_passes);
            CHECK(progress.pass_completed_read_bytes <=
                  progress.pass_total_read_bytes);
            CHECK(progress.pass_completed_write_bytes <=
                  progress.pass_total_write_bytes);
            CHECK(progress.phase_completed_read_bytes <=
                  progress.phase_total_read_bytes);
            CHECK(progress.phase_completed_write_bytes <=
                  progress.phase_total_write_bytes);
            CHECK(progress.pass_completed_butterflies <=
                  progress.pass_total_butterflies);
            CHECK(progress.phase_completed_butterflies <=
                  progress.phase_total_butterflies);
            if (progress.kind ==
                BaseFoldExternalCommitProgressKind::PassStarted) {
                work_updates_in_pass = 0;
                previous_pass_work = 0;
                CHECK(progress.pass_completed_work_units == 0);
            } else if (progress.kind ==
                BaseFoldExternalCommitProgressKind::WorkAdvanced) {
                ++work_updates_in_pass;
                CHECK(work_updates_in_pass <= 64);
                CHECK(progress.pass_completed_work_units >=
                      previous_pass_work);
            } else if (progress.kind ==
                       BaseFoldExternalCommitProgressKind::PassCompleted) {
                CHECK(progress.pass_completed_work_units ==
                      progress.pass_total_work_units);
            }
            if (progress.subpass ==
                BaseFoldExternalCommitSubpass::LocalNtt &&
                progress.pass_total_butterflies != 0) {
                CHECK(progress.work_unit ==
                      BaseFoldExternalCommitWorkUnit::NttButterflies);
                CHECK(progress.pass_completed_work_units ==
                      progress.pass_completed_butterflies);
                CHECK(progress.pass_total_work_units ==
                      progress.pass_total_butterflies);
            }
            previous_passes = progress.completed_passes;
            previous_pass_work = progress.pass_completed_work_units;
        }
        const BaseFoldExternalCommitProgress &final_progress =
            progress_events.back();
        CHECK(final_progress.kind ==
              BaseFoldExternalCommitProgressKind::PhaseCompleted);
        CHECK(final_progress.phase ==
              BaseFoldExternalCommitPhase::FinalPublication);
        CHECK(final_progress.completed_passes ==
              final_progress.total_passes);
        CHECK(final_progress.pass_completed_work_units ==
              final_progress.pass_total_work_units);
        CHECK(final_progress.phase_completed_read_bytes ==
              final_progress.phase_total_read_bytes);
        CHECK(final_progress.phase_completed_write_bytes ==
              final_progress.phase_total_write_bytes);

        const std::size_t codeword_size =
            selected.message_size << selected.log_rate;
        const std::size_t leaf_size =
            std::min(codeword_size, std::size_t{64});
        const std::size_t leaf_count = codeword_size / leaf_size;
        const std::size_t tree_nodes = 2 * leaf_count - 1;
        const std::size_t effective_block =
            test_floor_power_of_two(selected.block_elements);
        const std::size_t cache_radix =
            std::min(effective_block, std::size_t{1} << 17U);
        const FactorizedTransformAccounting mobius =
            expected_factorized_mobius(selected.message_size,
                                        effective_block, cache_radix);
        const FactorizedTransformAccounting ntt =
            expected_factorized_ntt(codeword_size, effective_block,
                                    cache_radix);
        const std::uint64_t message_scratch_bytes =
            selected.message_size * 8U + 276U;
        const std::uint64_t codeword_scratch_bytes =
            codeword_size * 8U + 276U;
        const std::uint64_t message_array_file_bytes =
            selected.message_size * 8U + 94U;
        const std::uint64_t codeword_array_file_bytes =
            codeword_size * 8U + 94U;
        const std::uint64_t tree_payload_bytes = tree_nodes * 40U;
        const std::uint64_t tree_scratch_bytes =
            tree_payload_bytes + 292U;
        CHECK(external.report.source_artifact_physical_bytes == source_bytes);
        CHECK(external.report.selected_source_payload_bytes ==
              selected.width * selected.message_size * 8U);
        CHECK(external.report.final_payload_bytes ==
              selected.width * selected.message_size * 8U +
                  selected.width * codeword_size * 8U +
                  tree_payload_bytes);
        const std::uint64_t expected_scratch_written =
            selected.width *
                (mobius.pass_count * message_scratch_bytes +
                 ((selected.log_rate == 0 ? 0U : 1U) +
                  ntt.pass_count) * codeword_scratch_bytes) +
            tree_scratch_bytes;
        CHECK(external.report.scratch_written_physical_bytes ==
              expected_scratch_written);
        CHECK(external.report.scratch_written_physical_bytes ==
              external.report.scratch_deleted_physical_bytes);
        CHECK(external.report.scratch_peak_physical_bytes ==
              std::max((selected.width + 1U) *
                           codeword_scratch_bytes,
                       selected.width * codeword_scratch_bytes +
                           tree_scratch_bytes));
        CHECK(external.report.artifact_validation_bytes == 0);
        CHECK(external.report.positional_publication_read_bytes ==
              selected.width *
                  (mobius.transpose_pass_count * message_array_file_bytes +
                   ntt.transpose_pass_count * codeword_array_file_bytes));
        CHECK(external.report.positional_publication_read_operations ==
              selected.width *
                  (mobius.transpose_pass_count *
                       test_ceil_div(message_array_file_bytes, 64U << 10U) +
                   ntt.transpose_pass_count *
                       test_ceil_div(codeword_array_file_bytes, 64U << 10U)));
        const std::uint64_t expected_indexed_reads =
            selected.width *
                (mobius.transpose_pass_count * selected.message_size * 8U +
                 ntt.transpose_pass_count * codeword_size * 8U) +
            40U;
        CHECK(external.report.indexed_read_payload_bytes ==
              expected_indexed_reads);
        const std::uint64_t expected_sequential_reads =
            selected.width *
                (mobius.local_pass_count * selected.message_size * 8U +
                 (selected.log_rate == 0
                      ? 0U
                      : selected.message_size * 8U) +
                 ntt.local_pass_count * codeword_size * 8U +
                 codeword_size * 8U) +
            external.report.final_payload_bytes;
        CHECK(external.report.sequential_read_payload_bytes ==
              expected_sequential_reads);
        const std::uint64_t expected_sequential_writes =
            selected.width *
                (mobius.local_pass_count * selected.message_size * 8U +
                 (selected.log_rate == 0 ? 0U
                                         : codeword_size * 8U) +
                 ntt.local_pass_count * codeword_size * 8U) +
            tree_payload_bytes + external.report.final_payload_bytes;
        CHECK(external.report.sequential_write_payload_bytes ==
              expected_sequential_writes);
        CHECK(external.report.indexed_write_payload_bytes ==
              selected.width *
                  (mobius.transpose_pass_count * selected.message_size * 8U +
                   ntt.transpose_pass_count * codeword_size * 8U));

        std::uint64_t per_column_sequential_reads =
            mobius.local_operations + ntt.local_operations;
        std::uint64_t per_column_sequential_writes =
            mobius.local_operations + ntt.local_operations;
        if (selected.log_rate != 0) {
            per_column_sequential_reads += test_ceil_div(
                selected.message_size, effective_block);
            per_column_sequential_writes +=
                test_ceil_div(selected.message_size,
                              effective_block) +
                test_ceil_div(codeword_size - selected.message_size,
                              effective_block);
        }
        const std::uint64_t digest_operations =
            test_ceil_div(tree_nodes, 1024U);
        const std::uint64_t final_fq_operations =
            selected.width *
            (test_ceil_div(selected.message_size,
                           effective_block) +
             test_ceil_div(codeword_size, effective_block));
        CHECK(external.report.indexed_read_operations ==
              selected.width *
                      (mobius.indexed_read_operations +
                       ntt.indexed_read_operations) +
                  1U);
        CHECK(external.report.indexed_write_operations ==
              selected.width *
                  (mobius.indexed_write_operations +
                   ntt.indexed_write_operations));
        CHECK(external.report.sequential_read_operations ==
              selected.width * per_column_sequential_reads +
                  selected.width * leaf_count + final_fq_operations +
                  digest_operations);
        CHECK(external.report.sequential_write_operations ==
              selected.width * per_column_sequential_writes +
                  digest_operations + final_fq_operations +
                  digest_operations);
        CHECK(external.report.read_seek_operations ==
              selected.width *
                      (mobius.read_seeks + ntt.read_seeks) +
                  1U);
        CHECK(external.report.write_seek_operations ==
              selected.width *
                  (mobius.write_seeks + ntt.write_seeks));
        CHECK(external.report.peak_positional_coverage_intervals ==
              std::max(mobius.peak_coverage_intervals,
                       ntt.peak_coverage_intervals));
        CHECK(external.report.peak_working_field_bytes ==
              std::max<std::uint64_t>(
                  2U * effective_block * sizeof(Fq),
                  (selected.width + 1U) * leaf_size * sizeof(Fq)));
        CHECK(external.report.transform_pass_count ==
              selected.width *
                  (mobius.pass_count +
                   (selected.log_rate == 0 ? 0U : 1U) +
                   ntt.pass_count));
        CHECK(external.report.transpose_pass_count ==
              selected.width *
                  (mobius.transpose_pass_count +
                   ntt.transpose_pass_count));
        CHECK(external.report.cache_resident_butterfly_layers ==
              selected.width *
                  (mobius.cache_resident_layers +
                   ntt.cache_resident_layers));

        std::vector<Fq2> weights;
        for (std::size_t column = 0; column < selected.width; ++column) {
            weights.push_back(Fq2({Fq(2 * column + 3),
                                   Fq(3 * column + 5)}));
        }
        std::vector<Fq2> point;
        for (std::size_t variable = 0;
             variable < std::bit_width(selected.message_size) - 1U;
             ++variable) {
            point.push_back(Fq2({Fq(5 * variable + 7),
                                 Fq(7 * variable + 11)}));
        }
        const Fq2 value =
            evaluate_linear_combination_msb(columns, weights, point);
        Transcript resident_coin(
            "laminate/test/basefold-external-commit/v1");
        bind(resident.commitment, resident_coin);
        const PcsOpeningProof resident_proof =
            pcs.open_linear_combination(resident.prover_state, weights,
                                        point, value, resident_coin);
        TemporaryDirectory opening_scratch(
            "commit-opening-" + std::to_string(case_index));
        Transcript external_coin(
            "laminate/test/basefold-external-commit/v1");
        bind(external.externalization.commitment, external_coin);
        const auto external_opening =
            pcs.open_linear_combination_external(
                external.externalization.prover_state, weights, point,
                value,
                external_opening_options(opening_scratch.path(),
                                         1ULL << 16U),
                external_coin);
        CHECK(external_opening.proof == resident_proof);
        CHECK(external_coin.challenge_fq2() ==
              resident_coin.challenge_fq2());
        Transcript verifier(
            "laminate/test/basefold-external-commit/v1");
        bind(external.externalization.commitment, verifier);
        CHECK(pcs.verify_linear_combination(
            external.externalization.commitment, weights, point, value,
            external_opening.proof, verifier));

        if (case_index == 4) {
            TemporaryDirectory repeat_destination("commit-repeat-final");
            TemporaryDirectory repeat_scratch("commit-repeat-scratch");
            BaseFoldExternalCommitOptions repeat_options =
                external_commit_options(repeat_destination.path(),
                                        repeat_scratch.path(),
                                        selected.block_elements);
            repeat_options.progress =
                [](const BaseFoldExternalCommitProgress &) {
                    throw std::runtime_error("ignored progress failure");
                };
            const auto repeated = pcs.commit_artifact_columns(
                source, names, std::move(repeat_options));
            CHECK(repeated.externalization.commitment ==
                  external.externalization.commitment);
            CHECK(repeated.report == external.report);
            CHECK(std::filesystem::is_empty(repeat_scratch.path()));
        }
    }
}

void test_segmented_external_commitment_matches_resident() {
    const BaseFoldPcs pcs({.log_rate = 1, .query_count = 4});
    std::vector<Fq> logical(16, Fq::zero());
    const std::array<std::pair<std::size_t, std::size_t>, 3> runs{{
        {1, 3}, {7, 2}, {12, 4},
    }};
    std::vector<Fq> stored;
    laminate::spartan::BaseFoldArtifactColumn column{
        .array_name = "compact-witness",
        .logical_evaluation_count = logical.size(),
    };
    for (const auto &[begin, count] : runs) {
        column.segments.push_back({
            .logical_begin = begin,
            .stored_begin = stored.size(),
            .element_count = count,
        });
        for (std::size_t index = 0; index < count; ++index) {
            const Fq value(17 * (begin + index) + 5);
            logical[begin + index] = value;
            stored.push_back(value);
        }
    }

    TemporaryDirectory source_directory("commit-segmented-source");
    const std::vector<std::string> names{column.array_name};
    const auto source = write_external_commit_source(
        source_directory.path(), names, {stored});
    const IPCS::CommitOutput resident = pcs.commit(logical);
    TemporaryDirectory destination("commit-segmented-final");
    TemporaryDirectory scratch("commit-segmented-scratch");
    const auto external = pcs.commit_artifact_columns(
        source, std::span<const laminate::spartan::BaseFoldArtifactColumn>(
                    &column, 1),
        external_commit_options(destination.path(), scratch.path(), 4));
    CHECK(external.externalization.commitment == resident.commitment);
    CHECK(external.report.selected_source_payload_bytes ==
          stored.size() * sizeof(Fq));
    CHECK(external.externalization.report.message_payload_bytes ==
          logical.size() * sizeof(Fq));
    const FactorizedTransformAccounting mobius =
        expected_factorized_mobius(logical.size(), 4, 4);
    const FactorizedTransformAccounting ntt =
        expected_factorized_ntt(2U * logical.size(), 4, 4);
    CHECK(external.report.transform_pass_count ==
          mobius.pass_count + 1U + ntt.pass_count);
    CHECK(external.report.transpose_pass_count ==
          mobius.transpose_pass_count + ntt.transpose_pass_count);
    CHECK(std::filesystem::is_empty(scratch.path()));

    const std::vector<Fq2> point{
        Fq2({Fq(3), Fq(5)}), Fq2({Fq(7), Fq(11)}),
        Fq2({Fq(13), Fq(17)}), Fq2({Fq(19), Fq(23)}),
    };
    const Fq2 value = evaluate_msb(logical, point);
    Transcript resident_coin(
        "laminate/test/basefold-segmented-commit/v1");
    bind(resident.commitment, resident_coin);
    const PcsOpeningProof resident_proof = pcs.open(
        resident.prover_state, point, value, resident_coin);
    TemporaryDirectory opening_scratch("commit-segmented-opening");
    Transcript external_coin(
        "laminate/test/basefold-segmented-commit/v1");
    bind(external.externalization.commitment, external_coin);
    const auto external_opening = pcs.open_external(
        external.externalization.prover_state, point, value,
        external_opening_options(opening_scratch.path(), 1ULL << 16U),
        external_coin);
    CHECK(external_opening.proof == resident_proof);
    CHECK(external_coin.challenge_fq2() == resident_coin.challenge_fq2());
}

void test_highly_fragmented_external_commitment_uses_bounded_readers() {
    constexpr std::size_t kLogicalSize = 1024;
    const BaseFoldPcs pcs({.log_rate = 0, .query_count = 1});
    std::vector<Fq> logical(kLogicalSize, Fq::zero());
    std::vector<Fq> stored;
    laminate::spartan::BaseFoldArtifactColumn column{
        .array_name = "fragmented-witness",
        .logical_evaluation_count = kLogicalSize,
    };
    for (std::size_t logical_index = 0; logical_index < kLogicalSize;
         logical_index += 2U) {
        const Fq value(3U * logical_index + 1U);
        logical[logical_index] = value;
        column.segments.push_back({
            .logical_begin = logical_index,
            .stored_begin = stored.size(),
            .element_count = 1,
        });
        stored.push_back(value);
    }

    TemporaryDirectory source_directory("commit-fragmented-source");
    const auto source = write_external_commit_source(
        source_directory.path(), {column.array_name}, {stored});
    TemporaryDirectory destination("commit-fragmented-final");
    TemporaryDirectory scratch("commit-fragmented-scratch");
#if !defined(_WIN32)
    ScopedFileDescriptorLimit descriptor_limit(64);
#endif
    const auto external = pcs.commit_artifact_columns(
        source,
        std::span<const laminate::spartan::BaseFoldArtifactColumn>(
            &column, 1),
        external_commit_options(destination.path(), scratch.path(), 7));
    CHECK(external.externalization.commitment ==
          pcs.commit(logical).commitment);
    CHECK(external.report.selected_source_payload_bytes ==
          stored.size() * sizeof(Fq));
    CHECK(std::filesystem::is_empty(scratch.path()));
}

void test_factorized_transform_target_geometry() {
    const std::size_t message_size = std::size_t{1} << 32U;
    const std::size_t codeword_size = std::size_t{1} << 34U;
    const std::size_t block_elements = std::size_t{1} << 24U;
    const std::size_t conservative_radix = std::size_t{1} << 16U;
    const FactorizedTransformAccounting mobius =
        expected_factorized_mobius(message_size, block_elements,
                                    conservative_radix);
    const FactorizedTransformAccounting ntt =
        expected_factorized_ntt(codeword_size, block_elements,
                                conservative_radix);
    CHECK(mobius.pass_count == 4);
    CHECK(mobius.transpose_pass_count == 2);
    CHECK(ntt.pass_count == 9);
    CHECK(ntt.transpose_pass_count == 6);
    CHECK(mobius.pass_count + 1U + ntt.pass_count == 14);
    CHECK(mobius.pass_count + ntt.pass_count <
          (std::bit_width(message_size) - 1U) +
              (std::bit_width(codeword_size) - 1U));

    const BaseFoldPcs pcs({.log_rate = 2, .query_count = 4});
    const auto conservative_plan = pcs.plan_external_commit_storage(
        message_size, 1, false, std::uint64_t{512} << 20U,
        block_elements, conservative_radix);
    CHECK(conservative_plan.effective_block_elements == block_elements);
    CHECK(conservative_plan.effective_cache_radix_elements ==
          conservative_radix);
    CHECK(conservative_plan.peak_working_field_bytes ==
          2U * block_elements * sizeof(Fq));

    const auto balanced_plan = pcs.plan_external_commit_storage(
        message_size, 1, false, std::uint64_t{512} << 20U,
        block_elements, 0);
    const std::size_t balanced_radix = std::size_t{1} << 17U;
    CHECK(balanced_plan.effective_cache_radix_elements == balanced_radix);
    const FactorizedTransformAccounting balanced_mobius =
        expected_factorized_mobius(message_size, block_elements,
                                    balanced_radix);
    const FactorizedTransformAccounting balanced_ntt =
        expected_factorized_ntt(codeword_size, block_elements,
                                balanced_radix);
    CHECK(balanced_mobius.pass_count == 4);
    CHECK(balanced_ntt.pass_count == 5);
    CHECK(balanced_ntt.transpose_pass_count == 3);
    CHECK(balanced_ntt.local_operations == (std::uint64_t{1} << 18U));
    CHECK(balanced_mobius.pass_count + 1U +
              balanced_ntt.pass_count ==
          10);
}

void test_external_commitment_preflight_and_corruption() {
    const BaseFoldPcs pcs({.log_rate = 1, .query_count = 4});
    const std::vector<std::string> names{"left", "right"};
    std::vector<std::vector<Fq>> columns(2, std::vector<Fq>(16));
    for (std::size_t column = 0; column < columns.size(); ++column) {
        for (std::size_t index = 0; index < columns[column].size(); ++index) {
            columns[column][index] = Fq(13 * index + 19 * column + 1);
        }
    }
    TemporaryDirectory source_directory("commit-preflight-source");
    const auto source = write_external_commit_source(
        source_directory.path(), names, columns, true);
    const std::uint64_t source_bytes = source->physical_bytes();
    const auto source_arrays = source->arrays();

    std::uint64_t exact_final_bytes = 0;
    std::uint64_t exact_scratch_peak = 0;
    {
        TemporaryDirectory destination("commit-quota-baseline-final");
        TemporaryDirectory scratch("commit-quota-baseline-scratch");
        const auto baseline = pcs.commit_artifact_columns(
            source, names,
            external_commit_options(destination.path(), scratch.path()));
        exact_final_bytes = baseline.report.final_physical_bytes;
        exact_scratch_peak = baseline.report.scratch_peak_physical_bytes;
        CHECK(std::filesystem::is_empty(scratch.path()));
    }

    const auto fails_without_writes =
        [&](std::span<const std::string> selected_names,
            const auto &configure) {
            TemporaryDirectory destination("commit-preflight-final");
            TemporaryDirectory scratch("commit-preflight-scratch");
            BaseFoldExternalCommitOptions options = external_commit_options(
                destination.path(), scratch.path());
            configure(options, destination);
            CHECK(throws_exception([&] {
                (void)pcs.commit_artifact_columns(
                    source, selected_names, std::move(options));
            }));
            CHECK(std::filesystem::is_empty(destination.path()));
            CHECK(std::filesystem::is_empty(scratch.path()));
            CHECK(source->physical_bytes() == source_bytes);
            CHECK(source->arrays() == source_arrays);
            CHECK(recursive_file_bytes(source_directory.path()) ==
                  source_bytes);
        };

    const std::vector<std::string> missing{"missing"};
    fails_without_writes(missing, [](auto &, const auto &) {});
    const std::vector<std::string> wrong_kind{"extension"};
    fails_without_writes(wrong_kind, [](auto &, const auto &) {});
    const std::vector<std::string> duplicate{"left", "left"};
    fails_without_writes(duplicate, [](auto &, const auto &) {});
    fails_without_writes(names, [exact_final_bytes](auto &options,
                                                    const auto &) {
        options.max_final_bytes = exact_final_bytes - 1U;
    });
    fails_without_writes(names, [exact_scratch_peak](auto &options,
                                                     const auto &) {
        options.max_scratch_bytes = exact_scratch_peak - 1U;
    });
    fails_without_writes(names, [](auto &options, const auto &) {
        options.max_working_field_bytes = 1;
    });
    {
        TemporaryDirectory destination("commit-shared-space-final");
        TemporaryDirectory scratch("commit-shared-space-scratch");
        BaseFoldExternalCommitOptions options = external_commit_options(
            destination.path(), scratch.path());
        const std::uint64_t available = std::min(
            std::filesystem::space(destination.path()).available,
            std::filesystem::space(scratch.path()).available);
        const std::uint64_t larger =
            std::max(exact_final_bytes, exact_scratch_peak);
        const std::uint64_t smaller =
            std::min(exact_final_bytes, exact_scratch_peak);
        CHECK(available > larger + smaller / 2U + 1U);
        options.min_free_bytes = available - larger - smaller / 2U;
        CHECK(throws_exception([&] {
            (void)pcs.commit_artifact_columns(source, names, options);
        }));
        CHECK(std::filesystem::is_empty(destination.path()));
        CHECK(std::filesystem::is_empty(scratch.path()));
    }
#ifndef _WIN32
    {
        TemporaryDirectory destination("commit-cleanup-final");
        TemporaryDirectory scratch("commit-cleanup-scratch");
        std::filesystem::permissions(
            destination.path(),
            std::filesystem::perms::owner_read |
                std::filesystem::perms::owner_exec,
            std::filesystem::perm_options::replace);
        const bool failed_after_scratch = throws_exception([&] {
            (void)pcs.commit_artifact_columns(
                source, names,
                external_commit_options(destination.path(),
                                        scratch.path()));
        });
        std::filesystem::permissions(
            destination.path(), std::filesystem::perms::owner_all,
            std::filesystem::perm_options::replace);
        CHECK(failed_after_scratch);
        CHECK(std::filesystem::is_empty(destination.path()));
        CHECK(std::filesystem::is_empty(scratch.path()));
        CHECK(source->physical_bytes() == source_bytes);
        CHECK(source->arrays() == source_arrays);
        CHECK(recursive_file_bytes(source_directory.path()) ==
              source_bytes);
    }
#endif
    {
        TemporaryDirectory destination("commit-nonempty-final");
        TemporaryDirectory scratch("commit-nonempty-scratch");
        const std::filesystem::path marker_path =
            destination.path() / "occupied";
        std::ofstream marker(marker_path);
        marker << "occupied";
        marker.close();
        CHECK(throws_exception([&] {
            (void)pcs.commit_artifact_columns(
                source, names,
                external_commit_options(destination.path(),
                                        scratch.path()));
        }));
        CHECK(std::filesystem::exists(marker_path));
        CHECK(recursive_file_bytes(destination.path()) == 8);
        CHECK(std::filesystem::is_empty(scratch.path()));
    }

    TemporaryDirectory corrupt_directory("commit-corrupt-source");
    const auto corrupt = write_external_commit_source(
        corrupt_directory.path(), names, columns);
    (void)corrupt;
    const std::filesystem::path array =
        corrupt_directory.path() / "array-0000000000000000.bin";
    std::fstream bytes(array, std::ios::binary | std::ios::in |
                                  std::ios::out);
    CHECK(static_cast<bool>(bytes));
    bytes.seekg(-1, std::ios::end);
    char last = 0;
    bytes.read(&last, 1);
    bytes.seekp(-1, std::ios::end);
    last ^= 1;
    bytes.write(&last, 1);
    bytes.close();
    CHECK(throws_exception([&] {
        (void)laminate::storage::NativeFieldArtifact::open(
            corrupt_directory.path(), external_commit_source_identity());
    }));
}

} // namespace

int main() {
    laminate::test::Runner runner("test_basefold_pcs");
    runner.run("BaseFold IPCS opening", test_open_and_verify);
    runner.run("BaseFold selected rate-eight resident and external openings",
               test_default_rate_eight_resident_and_external_openings);
    runner.run("BaseFold IPCS mutation rejection", test_mutations_reject);
    runner.run("BaseFold IPCS batched linear combination",
               test_batched_linear_combination);
    runner.run("BaseFold IPCS singleton and shape checks",
               test_singleton_and_shape_checks);
    runner.run("BaseFold IPCS multiproof work bounds",
               test_multiproof_work_bounds);
    runner.run("BaseFold IPCS small domains at rates one through eight",
               test_small_domains_at_supported_rates);
    runner.run("BaseFold IPCS artifact opening matches resident bytes",
               test_external_opening_matches_resident);
    runner.run("BaseFold IPCS external limits and identity",
               test_external_opening_limits_and_identity);
    runner.run("BaseFold IPCS external commitment matches resident",
               test_external_commitment_matches_resident);
    runner.run("BaseFold IPCS segmented commitment matches resident",
               test_segmented_external_commitment_matches_resident);
    runner.run("BaseFold IPCS fragmented commitment bounds source readers",
               test_highly_fragmented_external_commitment_uses_bounded_readers);
    runner.run("BaseFold IPCS external commitment preflight",
               test_external_commitment_preflight_and_corruption);
    runner.run("BaseFold IPCS factorized transform target geometry",
               test_factorized_transform_target_geometry);
    return runner.summary();
}
