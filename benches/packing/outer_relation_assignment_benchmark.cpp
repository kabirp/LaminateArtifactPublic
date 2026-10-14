/// @file outer_relation_assignment_benchmark.cpp
/// @brief Lazy outer-witness generation microbenchmark.

#include "benchmark_support.hpp"

#include "laminate/packing/outer_relation/assignment.hpp"

#include <algorithm>
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

using namespace laminate::bench;
using namespace laminate::packing;

namespace {

constexpr std::uint64_t kRepresentativeNativeModulus =
    laminate::kOuterFieldOrder;

struct ScheduleCase {
    std::string_view name;
    std::size_t ring_degree = 0;
    std::size_t aligned_ciphertexts = 0;
    std::size_t repetitions = 0;
    std::size_t logical_outputs = 0;
};

constexpr std::array<ScheduleCase, 5> kScheduleCases{{
    {"unit", 16, 3, 2, 1},
    {"laned-b1", 1U << 14U, 287,
     laminate::kPackingWellFormednessRepetitions, 1},
    {"laned-b128", 1U << 14U, 399,
     laminate::kPackingWellFormednessRepetitions, 1},
    {"laned-b16384", 1U << 14U, 517,
     laminate::kPackingWellFormednessRepetitions, 1},
    {"folded", 1U << 14U, 517,
     laminate::kPackingWellFormednessRepetitions, 1},
}};

struct Options {
    std::string_view schedule = "folded";
    std::size_t sample_values = 100'000'000;
    std::size_t iterations = 3;
};

struct SyntheticInputs {
    OuterRelationPublicInputs public_inputs;
    OuterRelationWitnessInputs witness_inputs;
};

struct GenerationSample {
    Timing timing;
    std::uint64_t values = 0;
    std::uint64_t checksum = 0;
};

struct WitnessFamily {
    std::string_view name;
    OuterRelationRange range;
    bool always_complete = false;
};

void print_usage(std::ostream &output) {
    output
        << "Usage: laminate_outer_relation_assignment_bench [options]\n"
        << "  --case unit|laned-b1|laned-b128|laned-b16384|folded\n"
        << "  --sample-values V  values per large witness family\n"
        << "  --iterations I     repeated cursor traversals\n";
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
        } else if (argument == "--sample-values") {
            result.sample_values = parse_size(value, argument);
        } else if (argument == "--iterations") {
            result.iterations = parse_size(value, argument);
        } else {
            throw std::invalid_argument(
                "unknown option: " + std::string(argument));
        }
    }
    if (result.sample_values == 0 || result.iterations == 0) {
        throw std::invalid_argument(
            "sample values and iterations must be nonzero");
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
            "unknown outer-assignment case: " + std::string(name));
    }
    return *found;
}

std::size_t as_size(std::uint64_t value, std::string_view label) {
    if (value > std::numeric_limits<std::size_t>::max()) {
        throw std::overflow_error(std::string(label) + " exceeds size_t");
    }
    return static_cast<std::size_t>(value);
}

OuterRelationPlan make_plan(const ScheduleCase &schedule) {
    return make_outer_relation_plan(OuterRelationShape{
        .native_modulus = kRepresentativeNativeModulus,
        .ring_degree = schedule.ring_degree,
        .aligned_ciphertexts = schedule.aligned_ciphertexts,
        .repetitions = schedule.repetitions,
        .logical_packed_outputs = schedule.logical_outputs,
        .packing_digit_count = 4,
        .ciphertext_components = 2,
        .public_input_capacity_bits = 59,
    });
}

std::uint64_t synthetic_residue(std::uint64_t index) {
    constexpr std::uint64_t kMask = (std::uint64_t{1} << 59U) - 1;
    return (index * 1'000'003ULL + 97'531ULL) & kMask;
}

void clear_unused_challenge_bits(
    const OuterRelationPlan &plan,
    std::vector<std::uint64_t> &words) {
    const std::uint64_t bit_count =
        plan.variables.witness.derived_challenge_bits.count;
    const std::size_t used = static_cast<std::size_t>(
        bit_count % plan.shape.public_input_capacity_bits);
    if (used != 0) {
        words.back() &= (std::uint64_t{1} << used) - 1;
    }
}

SyntheticInputs make_inputs(const OuterRelationPlan &plan) {
    SyntheticInputs result;
    result.public_inputs.packed_challenge_words.resize(as_size(
        plan.variables.public_inputs.packed_challenge_words.count,
        "challenge words"));
    for (std::size_t index = 0;
         index < result.public_inputs.packed_challenge_words.size(); ++index) {
        result.public_inputs.packed_challenge_words[index] =
            synthetic_residue(index);
    }
    clear_unused_challenge_bits(
        plan, result.public_inputs.packed_challenge_words);
    result.public_inputs.revealed_test_coordinates.resize(as_size(
        plan.variables.public_inputs.revealed_test_coordinates.count,
        "test coordinates"));
    result.public_inputs.revealed_packing_coordinates.resize(as_size(
        plan.variables.public_inputs.revealed_packing_coordinates.count,
        "packing coordinates"));
    result.witness_inputs.aligned_ciphertext_coordinates.resize(as_size(
        plan.variables.witness.aligned_ciphertext_coordinates.count,
        "aligned coordinates"));
    for (std::size_t index = 0;
         index < result.witness_inputs.aligned_ciphertext_coordinates.size();
         ++index) {
        result.witness_inputs.aligned_ciphertext_coordinates[index] =
            synthetic_residue(index + 11);
    }
    return result;
}

std::array<WitnessFamily, 3> witness_families(
    const OuterRelationPlan &plan) {
    return {{
        {"challenge_bits",
         plan.variables.witness.derived_challenge_bits, true},
        {"aligned_coordinates",
         plan.variables.witness.aligned_ciphertext_coordinates, false},
        {"well_formedness_products",
         plan.variables.witness.well_formedness_products, false},
    }};
}

std::uint64_t consume_value(
    std::uint64_t checksum,
    const OuterRelationWitnessValue &value) {
    checksum = std::rotl(checksum, 7);
    checksum ^= value.index;
    checksum += value.value * 1'099'511'628'211ULL;
    checksum ^= static_cast<std::uint8_t>(value.family) << 13U;
    return checksum;
}

GenerationSample measure_family(
    const OuterRelationR1csAssignmentView &assignment,
    const WitnessFamily &family, std::size_t requested_values) {
    const std::uint64_t measured =
        family.always_complete
            ? family.range.count
            : std::min<std::uint64_t>(family.range.count, requested_values);
    OuterRelationWitnessValueCursor cursor(
        assignment, family.range.begin, family.range.begin + measured);
    GenerationSample result;
    result.values = measured;
    result.timing = timed_void([&] {
        while (!cursor.empty()) {
            result.checksum = consume_value(result.checksum, cursor.next());
        }
    });
    return result;
}

void emit_family(
    const Record &record,
    const OuterRelationR1csAssignmentView &assignment,
    const WitnessFamily &family, const Options &options) {
    std::vector<double> wall;
    std::vector<double> cpu;
    wall.reserve(options.iterations);
    cpu.reserve(options.iterations);
    GenerationSample retained;
    for (std::size_t iteration = 0; iteration < options.iterations;
         ++iteration) {
        const GenerationSample sample = measure_family(
            assignment, family, options.sample_values);
        if (iteration != 0 &&
            (sample.values != retained.values ||
             sample.checksum != retained.checksum)) {
            throw std::logic_error(
                "outer witness generation changed between iterations");
        }
        wall.push_back(sample.timing.wall_ms);
        cpu.push_back(sample.timing.cpu_ms);
        retained = sample;
    }

    const Samples wall_summary = summarize(wall);
    const std::string prefix =
        "witness_generation." + std::string(family.name) + '.';
    record.integer(prefix + "values.total", family.range.count);
    record.integer(prefix + "values.measured", retained.values);
    record.integer(prefix + "checksum", retained.checksum);
    emit_samples(record, prefix + "wall_ms", wall);
    emit_samples(record, prefix + "cpu_ms", cpu);
    const double seconds = wall_summary.median / 1'000.0;
    record.real(prefix + "throughput.values_per_second",
                static_cast<double>(retained.values) / seconds);
    record.real(
        prefix + "extrapolated_full_family_seconds",
        seconds * static_cast<double>(family.range.count) /
            static_cast<double>(retained.values));
}

void run_benchmark(int argc, char **argv, const Options &options) {
    const ScheduleCase &schedule = find_schedule(options.schedule);
    const OuterRelationPlan plan = make_plan(schedule);
    const auto [inputs, input_timing] = timed([&] {
        return make_inputs(plan);
    });
    Stopwatch validation_timer;
    const OuterRelationR1csAssignmentView assignment(
        plan, inputs.public_inputs, inputs.witness_inputs);
    const Timing validation_timing = validation_timer.stop();
    const OuterRelationR1csAssignmentStorage storage =
        estimate_outer_relation_r1cs_assignment_storage(plan);
    const SystemInfo system = system_info();
    const Record record;

    record.text("format", "laminate-outer-lazy-assignment-v3");
    record.text("classification.result_kind",
                "measured-lazy-assignment-generation-only");
    record.text("classification.security", "not-a-proof");
    record.text("classification.proof_backend", "not-run");
    record.text("classification.source_values",
                "synthetic-native-q-residues-not-ciphertexts");
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
    record.integer("environment.peak_rss_bytes", system.peak_rss_bytes);

    record.text("shape.case", std::string(schedule.name));
    record.integer("shape.N", plan.shape.ring_degree);
    record.integer("shape.r", plan.shape.aligned_ciphertexts);
    record.integer("shape.tests", plan.shape.repetitions);
    record.integer("shape.public_values",
                   plan.variables.public_inputs.total);
    record.integer("shape.witness_values",
                   plan.variables.witness.total);
    record.integer("sample.target_values_per_large_family",
                   options.sample_values);
    record.integer("sample.iterations", options.iterations);

    record.integer("storage.public_source_bytes",
                   storage.public_source_bytes);
    record.integer("storage.aligned_source_bytes",
                   storage.aligned_source_bytes);
    record.integer("storage.challenge_word_source_bytes",
                   storage.challenge_word_source_bytes);
    record.integer("storage.borrowed_ciphertext_coordinate_bytes",
                   storage.borrowed_ciphertext_coordinate_bytes);
    record.integer("storage.borrowed_slice_descriptor_bytes",
                   storage.borrowed_slice_descriptor_bytes);
    record.integer("storage.flattened_coordinate_copy_bytes_avoided",
                   storage.flattened_coordinate_copy_bytes_avoided);
    record.integer("storage.eager_product_auxiliary_bytes",
                   storage.eager_product_auxiliary_bytes);
    record.integer("storage.eager_flat_assignment_bytes",
                   storage.eager_flat_assignment_bytes);
    record.integer("storage.lazy_derived_witness_bytes",
                   storage.lazy_derived_witness_bytes);
    emit_timing(record, "synthetic_source_construction", input_timing);
    emit_timing(record, "source_validation", validation_timing);

    for (const WitnessFamily &family : witness_families(plan)) {
        emit_family(record, assignment, family, options);
    }
    record.text("timing.proof_time_status",
                "unavailable-witness-generation-is-not-proving");
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
        std::cerr << "outer assignment benchmark failed: "
                  << error.what() << '\n';
        return 1;
    }
}
