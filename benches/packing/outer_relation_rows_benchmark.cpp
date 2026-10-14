/// @file outer_relation_rows_benchmark.cpp
/// @brief Sparse outer-R1CS row-generation microbenchmark.

#include "benchmark_support.hpp"

#include "laminate/packing/outer_relation/r1cs.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <limits>
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
using namespace laminate::packing;

namespace {

constexpr std::size_t kTargetRingDegree = std::size_t{1} << 14U;
constexpr std::size_t kTargetRepetitions =
    kPackingWellFormednessRepetitions;
constexpr std::size_t kTargetPackingDigits = 4;
constexpr std::uint64_t kRepresentativeNativeModulus = kOuterFieldOrder;

struct ScheduleCase {
    std::string_view name;
    std::size_t aligned_ciphertexts = 0;
    std::size_t logical_outputs = 0;
};

constexpr std::array<ScheduleCase, 4> kScheduleCases{{
    {"laned-b1", 287, 1},
    {"laned-b128", 399, 1},
    {"laned-b16384", 517, 1},
    {"folded", 517, 1},
}};

struct Options {
    std::string_view schedule = "folded";
    std::size_t sample_entries = 100'000'000;
    std::size_t iterations = 3;
};

struct RowFamily {
    std::string_view name;
    OuterRelationRange range;
    std::uint64_t exact_sparse_entries = 0;
    std::uint64_t regular_sparse_entries_per_row = 0;
    bool sample_complete_range = false;
};

struct MaterializationSample {
    Timing timing;
    std::uint64_t rows = 0;
    std::uint64_t sparse_entries = 0;
    std::uint64_t checksum = 0;
};

void print_usage(std::ostream &output) {
    output
        << "Usage: laminate_outer_relation_rows_bench [options]\n"
        << "  --case laned-b1|laned-b128|laned-b16384|folded\n"
        << "  --sample-entries E  target sparse entries per large family\n"
        << "  --iterations I    repeated samples per family\n";
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
        } else if (argument == "--sample-entries") {
            result.sample_entries = parse_size(value, argument);
        } else if (argument == "--iterations") {
            result.iterations = parse_size(value, argument);
        } else {
            throw std::invalid_argument(
                "unknown option: " + std::string(argument));
        }
    }
    if (result.sample_entries == 0 || result.iterations == 0) {
        throw std::invalid_argument(
            "sample entries and iterations must both be nonzero");
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
            "unknown outer-relation case: " + std::string(name));
    }
    return *found;
}

std::uint64_t checked_add(std::uint64_t left, std::uint64_t right) {
    if (right > std::numeric_limits<std::uint64_t>::max() - left) {
        throw std::overflow_error("outer row benchmark count overflows u64");
    }
    return left + right;
}

std::uint64_t checked_mul(std::uint64_t left, std::uint64_t right) {
    if (left != 0 &&
        right > std::numeric_limits<std::uint64_t>::max() / left) {
        throw std::overflow_error("outer row benchmark count overflows u64");
    }
    return left * right;
}

OuterRelationPlan make_target_plan(const ScheduleCase &schedule) {
    return make_outer_relation_plan(OuterRelationShape{
        .native_modulus = kRepresentativeNativeModulus,
        .ring_degree = kTargetRingDegree,
        .aligned_ciphertexts = schedule.aligned_ciphertexts,
        .repetitions = kTargetRepetitions,
        .logical_packed_outputs = schedule.logical_outputs,
        .packing_digit_count = kTargetPackingDigits,
        .ciphertext_components = 2,
        .public_input_capacity_bits = 59,
    });
}

std::array<RowFamily, 4> dynamic_families(
    const OuterRelationPlan &plan) {
    const std::uint64_t bits =
        plan.variables.witness.derived_challenge_bits.count;
    const std::uint64_t words =
        plan.variables.public_inputs.packed_challenge_words.count;
    const std::uint64_t products =
        plan.variables.witness.well_formedness_products.count;
    const std::uint64_t tests =
        plan.variables.public_inputs.revealed_test_coordinates.count;
    const std::uint64_t inputs = plan.shape.aligned_ciphertexts;
    return {{
        {"challenge_booleanity",
         plan.constraints.challenge_bit_booleanity,
         checked_mul(3, bits), 3, false},
        {"challenge_recomposition",
         plan.constraints.challenge_word_recomposition,
         checked_add(bits, checked_mul(2, words)), 0, true},
        {"online_products",
         plan.constraints.well_formedness_products,
         checked_mul(4, products), 4, false},
        {"test_equalities",
         plan.constraints.revealed_test_equalities,
         checked_mul(checked_add(inputs, 2), tests),
         checked_add(inputs, 2), false},
    }};
}

std::uint64_t consume_row(const OuterRelationR1csRow &row) {
    std::uint64_t result = row.constraint_index;
    result ^= static_cast<std::uint64_t>(row.a.size()) << 1U;
    result ^= static_cast<std::uint64_t>(row.b.size()) << 21U;
    result ^= static_cast<std::uint64_t>(row.c.size()) << 42U;
    if (!row.a.empty()) {
        result ^= row.a.front().variable.index;
        result ^= row.a.back().coefficient;
    }
    return result;
}

MaterializationSample measure_family(
    const OuterRelationPlan &plan, const RowFamily &family,
    std::size_t target_sparse_entries) {
    if (!family.sample_complete_range &&
        family.regular_sparse_entries_per_row == 0) {
        throw std::logic_error(
            "sampled outer row family has no per-row entry count");
    }
    const std::uint64_t rows_for_target =
        family.sample_complete_range
            ? family.range.count
            : checked_add(
                  target_sparse_entries /
                      family.regular_sparse_entries_per_row,
                  target_sparse_entries %
                              family.regular_sparse_entries_per_row !=
                          0
                      ? 1
                      : 0);
    const std::uint64_t sample_rows =
        family.sample_complete_range
            ? family.range.count
            : std::min(family.range.count, rows_for_target);
    OuterRelationR1csCursor cursor(
        plan, family.range.begin, family.range.begin + sample_rows);
    MaterializationSample result;
    result.rows = sample_rows;
    result.timing = timed_void([&] {
        while (!cursor.empty()) {
            const OuterRelationR1csRow &row = cursor.next();
            result.sparse_entries = checked_add(
                result.sparse_entries,
                checked_add(row.a.size(),
                            checked_add(row.b.size(), row.c.size())));
            // Intentional unsigned wrap keeps the materialized row observable
            // without scanning every term a second time.
            result.checksum = result.checksum * 1'099'511'628'211ULL +
                              consume_row(row);
        }
    });
    return result;
}

void emit_family(const Record &record, const OuterRelationPlan &plan,
                 const RowFamily &family, const Options &options,
                 double &dynamic_extrapolation_seconds) {
    std::vector<double> wall_samples;
    std::vector<double> cpu_samples;
    wall_samples.reserve(options.iterations);
    cpu_samples.reserve(options.iterations);
    MaterializationSample retained;
    for (std::size_t iteration = 0; iteration < options.iterations;
         ++iteration) {
        MaterializationSample sample =
            measure_family(plan, family, options.sample_entries);
        wall_samples.push_back(sample.timing.wall_ms);
        cpu_samples.push_back(sample.timing.cpu_ms);
        retained = sample;
    }

    const Samples wall = summarize(wall_samples);
    const std::string prefix =
        "row_generation." + std::string(family.name) + '.';
    record.integer(prefix + "rows.total", family.range.count);
    record.integer(prefix + "rows.measured", retained.rows);
    record.integer(prefix + "entries.total", family.exact_sparse_entries);
    record.integer(prefix + "entries.measured", retained.sparse_entries);
    record.integer(prefix + "checksum", retained.checksum);
    emit_samples(record, prefix + "wall_ms", wall_samples);
    emit_samples(record, prefix + "cpu_ms", cpu_samples);

    const double measured_seconds = wall.median / 1'000.0;
    if (!(measured_seconds > 0)) {
        throw std::runtime_error(
            "outer row benchmark timer did not advance");
    }
    const double scale = static_cast<double>(family.range.count) /
                         static_cast<double>(retained.rows);
    const double extrapolated_seconds = measured_seconds * scale;
    dynamic_extrapolation_seconds += extrapolated_seconds;
    record.real(prefix + "throughput.rows_per_second",
                static_cast<double>(retained.rows) / measured_seconds);
    record.real(prefix + "throughput.entries_per_second",
                static_cast<double>(retained.sparse_entries) /
                    measured_seconds);
    record.real(prefix + "extrapolated_full_family_seconds",
                extrapolated_seconds);
}

void run_benchmark(int argc, char **argv, const Options &options) {
    const ScheduleCase &schedule = find_schedule(options.schedule);
    const OuterRelationPlan plan = make_target_plan(schedule);
    const Record record;
    const SystemInfo system = system_info();

    record.text("format", "laminate-outer-r1cs-row-generation-v2");
    record.text("classification.result_kind",
                "measured-row-materialization-only");
    record.text("classification.security", "not-a-proof");
    record.text("classification.proof_backend", "not-run");
    record.text("classification.extrapolation",
                "linear-same-family-single-thread");
    record.text("environment.git_commit", LAMINATE_GIT_COMMIT);
    record.text("environment.git_dirty", LAMINATE_GIT_DIRTY);
    record.text("environment.date_utc", utc_timestamp());
    record.text("environment.os", system.os);
    record.text("environment.cpu", system.cpu);
    record.text("environment.compiler", LAMINATE_COMPILER);
    record.text("environment.build_type", LAMINATE_BUILD_TYPE);
    record.text("environment.command", exact_command(argc, argv));
    record.text("shape.case", std::string(schedule.name));
    record.integer("shape.N", plan.shape.ring_degree);
    record.integer("shape.r", plan.shape.aligned_ciphertexts);
    record.integer("shape.tests", plan.shape.repetitions);
    record.integer("shape.logical_outputs",
                   plan.shape.logical_packed_outputs);
    record.integer("shape.packing_digits", plan.shape.packing_digit_count);
    record.integer("shape.constraints.total", plan.constraints.total);
    record.integer("shape.constraints.dynamic_prefix",
                   plan.constraints.revealed_packing_equalities.begin);
    record.integer("shape.constraints.fixed_packing",
                   plan.constraints.revealed_packing_equalities.count);
    record.integer("sample.target_sparse_entries_per_large_family",
                   options.sample_entries);
    record.integer("sample.iterations", options.iterations);

    double dynamic_extrapolation_seconds = 0;
    for (const RowFamily &family : dynamic_families(plan)) {
        emit_family(record, plan, family, options,
                    dynamic_extrapolation_seconds);
    }
    record.real("extrapolation.dynamic_prefix_seconds",
                dynamic_extrapolation_seconds);
    record.text("extrapolation.fixed_packing_status",
                "not-in-this-benchmark-use-fixed-packing-matrix-benchmark");
    record.text("extrapolation.proof_time_status",
                "unavailable-row-generation-is-not-proving");
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
        std::cerr << "outer relation row benchmark failed: "
                  << error.what() << '\n';
        return 1;
    }
}
