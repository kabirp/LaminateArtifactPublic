/// @file outer_relation_packing_matrix_benchmark.cpp
/// @brief Full-schedule fixed packing-matrix generation benchmark.

#include "benchmark_support.hpp"

#include "laminate/fhe/seal_backend.hpp"
#include "laminate/packing/outer_relation/packing_r1cs.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#ifndef LAMINATE_GIT_COMMIT
#define LAMINATE_GIT_COMMIT "unknown"
#endif
#ifndef LAMINATE_GIT_DIRTY
#define LAMINATE_GIT_DIRTY "unknown"
#endif
#ifndef LAMINATE_BUILD_TYPE
#define LAMINATE_BUILD_TYPE "unknown"
#endif
#ifndef LAMINATE_COMPILER
#define LAMINATE_COMPILER "unknown"
#endif

using namespace laminate;
using namespace laminate::bench;
using namespace laminate::fhe;
using namespace laminate::packing;

namespace {

struct ScheduleCase {
    std::string_view name;
    std::size_t ring_degree = 0;
    std::size_t aligned_ciphertexts = 0;
    int data_prime_bits = 0;
    seal::sec_level_type security_level = seal::sec_level_type::tc128;
};

constexpr std::array<ScheduleCase, 5> kScheduleCases{{
    {"unit", 1U << 10U, 8, 40, seal::sec_level_type::none},
    {"laned-b1", 1U << 14U, 287, 60, seal::sec_level_type::tc128},
    {"laned-b128", 1U << 14U, 399, 60, seal::sec_level_type::tc128},
    {"laned-b16384", 1U << 14U, 517, 60, seal::sec_level_type::tc128},
    {"folded", 1U << 14U, 517, 60, seal::sec_level_type::tc128},
}};

struct Options {
    std::string_view schedule = "folded";
    std::size_t iterations = 1;
};

struct StreamSample {
    Timing total;
    Timing centered_encoding;
    Timing native_ntt_encoding;
    FixedPackingR1csStreamStatistics statistics;
    std::uint64_t checksum = 0;
};

void print_usage(std::ostream &output) {
    output
        << "Usage: laminate_outer_relation_packing_matrix_bench [options]\n"
        << "  --case unit|laned-b1|laned-b128|laned-b16384|folded\n"
        << "  --iterations I    complete full-matrix traversals\n";
}

std::optional<Options> parse_options(int argc, char **argv) {
    Options result;
    for (int index = 1; index < argc; ++index) {
        const std::string_view argument(argv[index]);
        if (argument == "--help" || argument == "-h") {
            print_usage(std::cout);
            return std::nullopt;
        }
        if (index + 1 == argc) {
            throw std::invalid_argument(
                "missing value after " + std::string(argument));
        }
        const std::string_view value(argv[++index]);
        if (argument == "--case") {
            result.schedule = value;
        } else if (argument == "--iterations") {
            result.iterations = parse_size(value, argument);
        } else {
            throw std::invalid_argument(
                "unknown option: " + std::string(argument));
        }
    }
    if (result.iterations == 0) {
        throw std::invalid_argument("iterations must be nonzero");
    }
    return result;
}

const ScheduleCase &find_schedule(std::string_view name) {
    const auto found = std::find_if(
        kScheduleCases.begin(), kScheduleCases.end(),
        [=](const ScheduleCase &candidate) {
            return candidate.name == name;
        });
    if (found == kScheduleCases.end()) {
        throw std::invalid_argument(
            "unknown packing-matrix case: " + std::string(name));
    }
    return *found;
}

SealBackend::Contexts make_contexts(const ScheduleCase &schedule) {
    return SealBackend::create(SealParameters{
        .poly_modulus_degree = schedule.ring_degree,
        .fresh_rns_limbs = 1,
        .bits_per_data_prime = schedule.data_prime_bits,
        .special_prime_bits = schedule.data_prime_bits,
        .security_level = schedule.security_level,
    });
}

void accumulate(Timing &total, const Timing &sample) {
    total.wall_ms += sample.wall_ms;
    total.cpu_ms += sample.cpu_ms;
}

std::uint64_t consume_entry(
    std::uint64_t checksum,
    const OuterRelationR1csMatrixEntry &entry) {
    checksum = std::rotl(checksum, 9);
    checksum ^= entry.constraint_index;
    checksum += entry.variable.index * 1'099'511'628'211ULL;
    checksum ^= entry.coefficient;
    checksum += static_cast<std::uint8_t>(entry.matrix);
    checksum ^= static_cast<std::uint8_t>(entry.variable.kind) << 5U;
    return checksum;
}

StreamSample measure_stream(
    const SealBackend::EvalContext &eval,
    const OuterRelationPlan &plan,
    const PackingLinearOperator &packing_operator,
    const BalancedRadix &radix) {
    StreamSample result;
    Stopwatch total_timer;
    FixedPackingR1csEntryCursor cursor(
        plan, packing_operator,
        {.centered_coefficients =
             [&](const fhe::SlotVector &mask) {
                 Stopwatch timer;
                 SignedCoefficientMask encoded =
                     SealBackend::encode_centered_plaintext_coefficients(
                         eval, mask);
                 accumulate(result.centered_encoding, timer.stop());
                 return encoded;
             },
         .native_ntt =
             [&](std::span<const std::int64_t> coefficients) {
                 Stopwatch timer;
                 std::vector<std::uint64_t> encoded =
                     SealBackend::encode_lowest_plaintext_ntt_coordinates(
                         eval, coefficients);
                 accumulate(result.native_ntt_encoding, timer.stop());
                 return encoded;
             }},
        radix);
    while (!cursor.empty()) {
        result.checksum = consume_entry(result.checksum, cursor.next());
    }
    result.statistics = cursor.statistics();
    result.total = total_timer.stop();
    return result;
}

void require_consistent_sample(
    const StreamSample &expected, const StreamSample &actual) {
    const auto &left = expected.statistics;
    const auto &right = actual.statistics;
    if (!right.complete || left.aligned_masks_encoded !=
                               right.aligned_masks_encoded ||
        left.native_digit_polynomials_encoded !=
            right.native_digit_polynomials_encoded ||
        left.a_nonzero_entries != right.a_nonzero_entries ||
        left.b_nonzero_entries != right.b_nonzero_entries ||
        left.c_nonzero_entries != right.c_nonzero_entries ||
        left.total_nonzero_entries != right.total_nonzero_entries ||
        expected.checksum != actual.checksum) {
        throw std::logic_error(
            "fixed packing matrix stream changed between iterations");
    }
}

void emit_timing_samples(const Record &record, std::string_view prefix,
                         const std::vector<StreamSample> &samples,
                         Timing StreamSample::*member) {
    std::vector<double> wall;
    std::vector<double> cpu;
    wall.reserve(samples.size());
    cpu.reserve(samples.size());
    for (const StreamSample &sample : samples) {
        wall.push_back((sample.*member).wall_ms);
        cpu.push_back((sample.*member).cpu_ms);
    }
    emit_samples(record, std::string(prefix) + ".wall_ms", wall);
    emit_samples(record, std::string(prefix) + ".cpu_ms", cpu);
}

void run_benchmark(int argc, char **argv, const Options &options) {
    const ScheduleCase &schedule = find_schedule(options.schedule);
    const SealBackend::Contexts contexts = make_contexts(schedule);
    const PackingLayout layout =
        make_fixed_message_coset_packing_layout(
            schedule.ring_degree, schedule.aligned_ciphertexts,
            schedule.aligned_ciphertexts);
    const PackingLinearOperator packing_operator =
        make_packing_linear_operator(layout);
    const BalancedRadix radix =
        make_minimal_balanced_radix(kBaseFieldOrder,
                                    kSelectedPackingRadixBase);
    const std::uint64_t native_modulus =
        SealBackend::lowest_coefficient_modulus(contexts.eval);
    const OuterRelationPlan plan = make_outer_relation_plan(
        OuterRelationShape{
            .native_modulus = native_modulus,
            .ring_degree = schedule.ring_degree,
            .aligned_ciphertexts = schedule.aligned_ciphertexts,
            .repetitions = kPackingWellFormednessRepetitions,
            .logical_packed_outputs = packing_operator.rows.size(),
            .packing_digit_count = radix.digit_count,
            .ciphertext_components = 2,
            .public_input_capacity_bits =
                outer_relation_public_input_capacity(native_modulus),
        });

    std::vector<StreamSample> samples;
    samples.reserve(options.iterations);
    for (std::size_t iteration = 0; iteration < options.iterations;
         ++iteration) {
        samples.push_back(measure_stream(
            contexts.eval, plan, packing_operator, radix));
        if (!samples.front().statistics.complete) {
            throw std::logic_error(
                "fixed packing matrix stream did not complete");
        }
        require_consistent_sample(samples.front(), samples.back());
    }

    const StreamSample &retained = samples.front();
    const FixedPackingR1csStorageEstimate storage =
        estimate_fixed_packing_r1cs_storage(plan);
    const SystemInfo system = system_info();
    const Record record;

    record.text("format", "laminate-outer-fixed-packing-r1cs-v2");
    record.text("classification.result_kind",
                "measured-fixed-matrix-generation-only");
    record.text("classification.security", "not-a-proof");
    record.text("classification.proof_backend", "not-run");
    record.text("classification.matrix_sink",
                "checksum-only-no-matrix-storage");
    record.text("classification.emission_order",
                "contribution-major-A-then-row-major-B-C");
    record.text("classification.extrapolation", "none-full-schedule");
    record.text("environment.git_commit", LAMINATE_GIT_COMMIT);
    record.text("environment.git_dirty", LAMINATE_GIT_DIRTY);
    record.text("environment.date_utc", utc_timestamp());
    record.text("environment.os", system.os);
    record.text("environment.cpu", system.cpu);
    record.text("environment.compiler", LAMINATE_COMPILER);
    record.text("environment.build_type", LAMINATE_BUILD_TYPE);
    record.text("environment.command", exact_command(argc, argv));
    record.integer("environment.peak_rss_bytes", system.peak_rss_bytes);

    record.text("shape.case", std::string(schedule.name));
    record.integer("shape.N", plan.shape.ring_degree);
    record.integer("shape.r", plan.shape.aligned_ciphertexts);
    record.integer("shape.logical_outputs",
                   plan.shape.logical_packed_outputs);
    record.integer("shape.packing_digits",
                   plan.shape.packing_digit_count);
    record.integer("shape.native_modulus", plan.shape.native_modulus);
    record.integer("shape.fixed_constraints",
                   plan.constraints.revealed_packing_equalities.count);
    record.integer("sample.iterations", options.iterations);

    record.integer("storage.materialized_multiplier_coordinates",
                   storage.materialized_multiplier_coordinates);
    record.integer("storage.materialized_multiplier_bytes",
                   storage.materialized_multiplier_bytes);
    record.integer("storage.streamed_digit_and_ntt_coordinates",
                   storage.streamed_digit_and_ntt_coordinates);
    record.integer("storage.streamed_digit_and_ntt_bytes",
                   storage.streamed_digit_and_ntt_bytes);
    record.real(
        "storage.coefficient_payload_reduction_factor",
        static_cast<double>(storage.materialized_multiplier_bytes) /
            static_cast<double>(storage.streamed_digit_and_ntt_bytes));

    record.integer("stream.aligned_masks_encoded",
                   retained.statistics.aligned_masks_encoded);
    record.integer("stream.native_digit_polynomials_encoded",
                   retained.statistics.native_digit_polynomials_encoded);
    record.integer("stream.A_nonzero_entries",
                   retained.statistics.a_nonzero_entries);
    record.integer("stream.B_nonzero_entries",
                   retained.statistics.b_nonzero_entries);
    record.integer("stream.C_nonzero_entries",
                   retained.statistics.c_nonzero_entries);
    record.integer("stream.total_nonzero_entries",
                   retained.statistics.total_nonzero_entries);
    record.integer("stream.checksum", retained.checksum);

    emit_timing_samples(record, "timing.total_stream", samples,
                        &StreamSample::total);
    emit_timing_samples(record, "timing.centered_encoding", samples,
                        &StreamSample::centered_encoding);
    emit_timing_samples(record, "timing.native_ntt_encoding", samples,
                        &StreamSample::native_ntt_encoding);
    const Samples total_wall = [&] {
        std::vector<double> values;
        values.reserve(samples.size());
        for (const StreamSample &sample : samples) {
            values.push_back(sample.total.wall_ms);
        }
        return summarize(std::move(values));
    }();
    record.real(
        "stream.throughput.entries_per_second",
        static_cast<double>(retained.statistics.total_nonzero_entries) /
            (total_wall.median / 1'000.0));
    record.text("timing.proof_time_status",
                "unavailable-matrix-generation-is-not-proving");
}

} // namespace

int main(int argc, char **argv) {
    try {
        const std::optional<Options> options = parse_options(argc, argv);
        if (!options) {
            return 0;
        }
        run_benchmark(argc, argv, *options);
        return 0;
    } catch (const std::exception &error) {
        std::cerr << "fixed packing matrix benchmark failed: "
                  << error.what() << '\n';
        return 1;
    }
}
