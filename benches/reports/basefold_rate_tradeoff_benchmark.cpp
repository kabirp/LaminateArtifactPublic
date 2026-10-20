/// @file basefold_rate_tradeoff_benchmark.cpp
/// @brief Measured bounded and formula-exact target BaseFold rate comparison.

#include "benchmark_support.hpp"

#include "laminate/params.hpp"
#include "laminate/basefold/soundness.hpp"
#include "laminate/field/serialization.hpp"
#include "laminate/spartan/basefold_pcs.hpp"
#include "laminate/transcript/hash.hpp"
#include "laminate/transcript/transcript.hpp"

#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

using laminate::Fq;
using laminate::Fq2;
using laminate::Transcript;
using laminate::bench::Record;
using laminate::bench::Timing;
using laminate::spartan::BaseFoldExternalCommitStoragePlan;
using laminate::spartan::BaseFoldExternalOpeningStoragePlan;
using laminate::spartan::BaseFoldPcs;
using laminate::spartan::BaseFoldPcsParameters;
using laminate::spartan::IPCS;
using laminate::spartan::PcsCommitment;
using laminate::spartan::PcsOpeningProof;

constexpr std::size_t kTargetMessageLog = 32;
constexpr std::size_t kTargetWidth = 1;
constexpr std::size_t kTargetBlockElements = std::size_t{1} << 24U;
constexpr std::size_t kTargetFoldChunkElements = std::size_t{1} << 24U;
constexpr std::uint64_t kTargetWorkingFieldBytes = 512ULL << 20U;

struct Options {
    std::size_t log_elements = 18;
    std::size_t iterations = 3;
};

struct Profile {
    std::string_view name;
    BaseFoldPcsParameters parameters;
};

constexpr std::array<Profile, 3> kProfiles{{
    {"inverse_rate_four_queries_60", {.log_rate = 2, .query_count = 60}},
    {"inverse_rate_two_queries_120", {.log_rate = 1, .query_count = 120}},
    {"inverse_rate_eight_queries_150",
     {.log_rate = laminate::kTranscriptPackingBaseFoldLogRate,
      .query_count = laminate::kTranscriptPackingBaseFoldQueries}},
}};

struct ProfileMeasurements {
    std::vector<double> commit_wall_ms;
    std::vector<double> commit_cpu_ms;
    std::vector<double> open_wall_ms;
    std::vector<double> open_cpu_ms;
    std::vector<double> verify_wall_ms;
    std::vector<double> verify_cpu_ms;
    std::size_t proof_bytes = 0;
    laminate::Digest proof_digest{};
};

struct TargetProjection {
    std::uint64_t codeword_elements = 0;
    std::uint64_t ntt_butterflies = 0;
    std::uint64_t codeword_payload_bytes = 0;
    std::uint64_t merkle_payload_bytes = 0;
    std::uint64_t two_pass_fold_output_elements = 0;
    std::uint64_t two_pass_fold_read_payload_bytes = 0;
    std::uint64_t opening_proof_max_bytes = 0;
    std::uint64_t opening_merkle_hashes_max = 0;
    BaseFoldExternalCommitStoragePlan commit_storage;
    BaseFoldExternalOpeningStoragePlan opening_storage;
};

std::optional<Options> parse_options(int argc, char **argv) {
    Options result;
    for (int index = 1; index < argc; ++index) {
        const std::string_view argument(argv[index]);
        if (argument == "--help" || argument == "-h") {
            std::cout
                << "Usage: laminate_basefold_rate_tradeoff_bench [options]\n"
                << "  --log-elements L  bounded resident measurement size\n"
                << "  --iterations I    repeated single-thread samples\n";
            return std::nullopt;
        }
        if (++index == argc) {
            throw std::invalid_argument("missing value after " +
                                        std::string(argument));
        }
        const std::size_t value =
            laminate::bench::parse_size(argv[index], argument);
        if (argument == "--log-elements") {
            result.log_elements = value;
        } else if (argument == "--iterations") {
            result.iterations = value;
        } else {
            throw std::invalid_argument("unknown option: " +
                                        std::string(argument));
        }
    }
    if (result.log_elements < 6 || result.log_elements > 22 ||
        result.iterations == 0) {
        throw std::invalid_argument("invalid rate-tradeoff dimensions");
    }
    return result;
}

void bind(const PcsCommitment &commitment, Transcript &transcript) {
    transcript.observe("laminate/benchmark/basefold-rate/commitment/v1",
                       laminate::spartan::encode_pcs_commitment(commitment));
}

void retain_timing(std::vector<double> &wall, std::vector<double> &cpu,
                   const Timing &timing) {
    wall.push_back(timing.wall_ms);
    cpu.push_back(timing.cpu_ms);
}

ProfileMeasurements measure_profile(const Profile &profile,
                                    std::span<const Fq> evaluations,
                                    std::size_t iterations) {
    ProfileMeasurements result;
    const std::size_t message_log =
        std::bit_width(evaluations.size()) - 1U;
    const std::vector<Fq2> point(message_log, Fq2::zero());
    const Fq2 claimed_value({evaluations.front(), Fq::zero()});
    BaseFoldPcs pcs(profile.parameters);
    for (std::size_t iteration = 0; iteration < iterations; ++iteration) {
        IPCS::CommitOutput committed;
        const Timing commit_timing = laminate::bench::timed_void(
            [&] { committed = pcs.commit(evaluations); });
        retain_timing(result.commit_wall_ms, result.commit_cpu_ms,
                      commit_timing);

        Transcript prover("laminate/benchmark/basefold-rate/v1");
        bind(committed.commitment, prover);
        PcsOpeningProof proof;
        const Timing open_timing = laminate::bench::timed_void([&] {
            proof = pcs.open(committed.prover_state, point, claimed_value,
                             prover);
        });
        retain_timing(result.open_wall_ms, result.open_cpu_ms, open_timing);

        Transcript verifier("laminate/benchmark/basefold-rate/v1");
        bind(committed.commitment, verifier);
        bool accepted = false;
        const Timing verify_timing = laminate::bench::timed_void([&] {
            accepted = pcs.verify(committed.commitment, point, claimed_value,
                                  proof, verifier);
        });
        if (!accepted) {
            throw std::runtime_error("BaseFold rate benchmark did not verify");
        }
        retain_timing(result.verify_wall_ms, result.verify_cpu_ms,
                      verify_timing);

        const laminate::Digest digest = laminate::sha256(proof.bytes);
        if (iteration != 0 &&
            (proof.bytes.size() != result.proof_bytes ||
             digest != result.proof_digest)) {
            throw std::runtime_error(
                "BaseFold rate benchmark output is not deterministic");
        }
        result.proof_bytes = proof.bytes.size();
        result.proof_digest = digest;
    }
    return result;
}

std::uint64_t checked_multiply(std::uint64_t left, std::uint64_t right) {
    if (left != 0 && right > std::numeric_limits<std::uint64_t>::max() / left) {
        throw std::overflow_error("rate-tradeoff projection overflows");
    }
    return left * right;
}

TargetProjection project_target(const Profile &profile) {
    BaseFoldPcs pcs(profile.parameters);
    const std::uint64_t message_elements =
        std::uint64_t{1} << kTargetMessageLog;
    const std::size_t codeword_log =
        kTargetMessageLog + profile.parameters.log_rate;
    const std::uint64_t codeword_elements =
        std::uint64_t{1} << codeword_log;
    const std::uint64_t leaves = codeword_elements / 64U;
    const std::uint64_t merkle_nodes = 2U * leaves - 1U;
    const std::uint64_t final_fold_predecessor =
        std::uint64_t{1} << (profile.parameters.log_rate + 1U);
    const std::uint64_t one_pass_fold_outputs =
        codeword_elements - final_fold_predecessor;
    const std::uint64_t one_pass_fold_reads =
        checked_multiply(codeword_elements, laminate::kSerializedFqBytes) +
        checked_multiply(one_pass_fold_outputs,
                         laminate::kSerializedFq2Bytes);

    const PcsCommitment commitment{
        .scheme = BaseFoldPcs::kSchemeIdentifier,
        .evaluation_count = message_elements,
        .width = kTargetWidth,
        .log_rate =
            static_cast<std::uint32_t>(profile.parameters.log_rate),
        .query_count =
            static_cast<std::uint32_t>(profile.parameters.query_count),
    };
    return {
        .codeword_elements = codeword_elements,
        .ntt_butterflies = checked_multiply(codeword_elements / 2U,
                                            codeword_log),
        .codeword_payload_bytes =
            checked_multiply(codeword_elements, laminate::kSerializedFqBytes),
        .merkle_payload_bytes = checked_multiply(
            merkle_nodes, laminate::spartan::PcsDigest{}.size()),
        .two_pass_fold_output_elements =
            checked_multiply(2U, one_pass_fold_outputs),
        .two_pass_fold_read_payload_bytes =
            checked_multiply(2U, one_pass_fold_reads),
        .opening_proof_max_bytes =
            laminate::spartan::basefold_opening_proof_max_size_bytes(
                kTargetMessageLog, kTargetWidth, profile.parameters),
        .opening_merkle_hashes_max =
            laminate::spartan::basefold_opening_max_merkle_hashes(
                kTargetMessageLog, profile.parameters),
        .commit_storage = pcs.plan_external_commit_storage(
            message_elements, kTargetWidth, true,
            kTargetWorkingFieldBytes, kTargetBlockElements),
        .opening_storage = pcs.plan_external_opening_storage(
            commitment, kTargetFoldChunkElements,
            kTargetWorkingFieldBytes),
    };
}

void emit_timing_samples(const Record &record, std::string_view prefix,
                         const std::vector<double> &wall,
                         const std::vector<double> &cpu) {
    laminate::bench::emit_samples(
        record, std::string(prefix) + ".wall_ms", wall);
    laminate::bench::emit_samples(
        record, std::string(prefix) + ".cpu_ms", cpu);
    const double wall_median = laminate::bench::summarize(wall).median;
    const double cpu_median = laminate::bench::summarize(cpu).median;
    record.real(std::string(prefix) + ".cpu_to_wall_ratio",
                cpu_median / wall_median);
}

void emit_target_projection(const Record &record, const Profile &profile,
                            const TargetProjection &projection) {
    const std::string prefix = "target." + std::string(profile.name);
    record.integer(prefix + ".log_rate", profile.parameters.log_rate);
    record.integer(prefix + ".query_count", profile.parameters.query_count);
    if (profile.parameters.log_rate == 3) {
        const auto bound = laminate::basefold::conservative_rbr_soundness_bound(
            kTargetMessageLog, 0,
            profile.parameters.log_rate, profile.parameters.query_count, 119);
        record.integer(prefix + ".rbr_error_bits", bound.rbr_bits);
    }
    record.integer(prefix + ".message_log", kTargetMessageLog);
    record.integer(prefix + ".codeword_log",
                   kTargetMessageLog + profile.parameters.log_rate);
    record.integer(prefix + ".codeword_elements",
                   projection.codeword_elements);
    record.integer(prefix + ".ntt_butterflies",
                   projection.ntt_butterflies);
    record.integer(prefix + ".codeword_payload_bytes",
                   projection.codeword_payload_bytes);
    record.integer(prefix + ".merkle_payload_bytes",
                   projection.merkle_payload_bytes);
    record.integer(prefix + ".commit_final_physical_bytes",
                   projection.commit_storage.final_physical_bytes);
    record.integer(prefix + ".commit_scratch_peak_physical_bytes",
                   projection.commit_storage.scratch_peak_physical_bytes);
    record.integer(prefix + ".commit_peak_working_field_bytes",
                   projection.commit_storage.peak_working_field_bytes);
    record.integer(prefix + ".commit_cache_radix_elements",
                   projection.commit_storage.effective_cache_radix_elements);
    record.integer(prefix + ".opening_two_pass_fold_output_elements",
                   projection.two_pass_fold_output_elements);
    record.integer(prefix + ".opening_two_pass_fold_read_payload_bytes",
                   projection.two_pass_fold_read_payload_bytes);
    record.integer(prefix + ".opening_proof_max_bytes",
                   projection.opening_proof_max_bytes);
    record.integer(prefix + ".opening_merkle_hashes_max",
                   projection.opening_merkle_hashes_max);
    record.integer(prefix + ".opening_scratch_peak_physical_bytes",
                   projection.opening_storage.scratch_peak_physical_bytes);
    record.integer(prefix + ".opening_required_working_field_bytes",
                   projection.opening_storage.required_working_field_bytes);
}

} // namespace

int main(int argc, char **argv) {
    try {
        const std::optional<Options> parsed = parse_options(argc, argv);
        if (!parsed) {
            return 0;
        }
        const Options &options = *parsed;
        const std::size_t element_count =
            std::size_t{1} << options.log_elements;
        std::vector<Fq> evaluations(element_count);
        for (std::size_t index = 0; index < element_count; ++index) {
            evaluations[index] = Fq(index * 1'000'003ULL + 97'531ULL);
        }

        std::array<ProfileMeasurements, kProfiles.size()> measurements;
        std::array<TargetProjection, kProfiles.size()> projections;
        for (std::size_t index = 0; index < kProfiles.size(); ++index) {
            measurements[index] =
                measure_profile(kProfiles[index], evaluations,
                                options.iterations);
            projections[index] = project_target(kProfiles[index]);
        }

        const Record record;
        record.text("format", "laminate-basefold-rate-tradeoff-v2");
        record.text("classification",
                    "measured-bounded-resident-plus-formula-target");
        record.integer("threads", 1);
        record.integer("iterations", options.iterations);
        record.integer("measured.message_log", options.log_elements);
        record.text("security.proximity_accounting",
                    "unique-decoding-rbr;excludes-merkle-binding-and-fiat-shamir-composition");
        record.integer("security.selected_log_rate",
                       laminate::kTranscriptPackingBaseFoldLogRate);
        record.integer("security.selected_query_count",
                       laminate::kTranscriptPackingBaseFoldQueries);
        record.integer("security.target_bits",
                       laminate::kBaseFoldIntegrityTargetBits);
        for (std::size_t index = 0; index < kProfiles.size(); ++index) {
            const std::string prefix =
                "measured." + std::string(kProfiles[index].name);
            emit_timing_samples(record, prefix + ".commit",
                                measurements[index].commit_wall_ms,
                                measurements[index].commit_cpu_ms);
            emit_timing_samples(record, prefix + ".open",
                                measurements[index].open_wall_ms,
                                measurements[index].open_cpu_ms);
            emit_timing_samples(record, prefix + ".verify",
                                measurements[index].verify_wall_ms,
                                measurements[index].verify_cpu_ms);
            record.integer(prefix + ".proof_bytes",
                           measurements[index].proof_bytes);
            record.text(prefix + ".proof_sha256",
                        laminate::bench::digest_hex(
                            measurements[index].proof_digest));
            emit_target_projection(record, kProfiles[index],
                                   projections[index]);
        }

        const double rate_four_commit = laminate::bench::summarize(
                                            measurements[0].commit_wall_ms)
                                            .median;
        const double rate_two_commit = laminate::bench::summarize(
                                           measurements[1].commit_wall_ms)
                                           .median;
        const double rate_four_open = laminate::bench::summarize(
                                          measurements[0].open_wall_ms)
                                          .median;
        const double rate_two_open = laminate::bench::summarize(
                                         measurements[1].open_wall_ms)
                                         .median;
        const double rate_four_verify = laminate::bench::summarize(
                                            measurements[0].verify_wall_ms)
                                            .median;
        const double rate_two_verify = laminate::bench::summarize(
                                           measurements[1].verify_wall_ms)
                                           .median;
        record.real("comparison.rate_two_over_rate_four.measured_commit_time",
                    rate_two_commit / rate_four_commit);
        record.real("comparison.rate_two_over_rate_four.measured_open_time",
                    rate_two_open / rate_four_open);
        record.real("comparison.rate_two_over_rate_four.measured_verify_time",
                    rate_two_verify / rate_four_verify);
        record.real("comparison.rate_two_over_rate_four.measured_proof_bytes",
                    static_cast<double>(measurements[1].proof_bytes) /
                        static_cast<double>(measurements[0].proof_bytes));
        record.real("comparison.rate_two_over_rate_four.target_ntt_butterflies",
                    static_cast<double>(projections[1].ntt_butterflies) /
                        static_cast<double>(projections[0].ntt_butterflies));
        record.real("comparison.rate_two_over_rate_four.target_codeword_bytes",
                    static_cast<double>(projections[1].codeword_payload_bytes) /
                        static_cast<double>(projections[0].codeword_payload_bytes));
        record.real("comparison.rate_two_over_rate_four.target_open_fold_reads",
                    static_cast<double>(
                        projections[1].two_pass_fold_read_payload_bytes) /
                        static_cast<double>(
                            projections[0].two_pass_fold_read_payload_bytes));
        record.real("comparison.rate_two_over_rate_four.target_proof_max_bytes",
                    static_cast<double>(projections[1].opening_proof_max_bytes) /
                        static_cast<double>(
                            projections[0].opening_proof_max_bytes));
        record.real("comparison.rate_two_over_rate_four.target_merkle_hashes",
                    static_cast<double>(
                        projections[1].opening_merkle_hashes_max) /
                        static_cast<double>(
                            projections[0].opening_merkle_hashes_max));
        laminate::bench::emit_benchmark_provenance(record, argc, argv);
        return 0;
    } catch (const std::exception &error) {
        std::cerr << "error: " << error.what() << '\n';
        return 1;
    }
}
