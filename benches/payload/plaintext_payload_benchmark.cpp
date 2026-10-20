/// @file plaintext_payload_benchmark.cpp
/// @brief Single-thread calibration for direct plaintext payload evaluation.

#include "benchmark_support.hpp"

#include "laminate/field/fp.hpp"
#include "laminate/params.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

using namespace laminate;
using namespace laminate::bench;

namespace {

struct Options {
    std::size_t logical_value_width = 1;
    std::size_t sampled_value_width = 0;
    std::size_t depth = kMaximumPayloadMultiplicativeDepth;
    std::size_t width = kBenchmarkDiamondMiddleWidth;
    std::size_t repetitions = 5;
};

/// Two-layer storage is sufficient because every gate at depth `d+1` reads
/// only the preceding layer. Values for one wire occupy a contiguous block.
struct LayerState {
    std::size_t wire_count = 0;
    std::size_t value_width = 0;
    std::size_t input_count = 0;
    std::size_t output_count = 0;
    std::vector<Fp> current;
    std::vector<Fp> next;
};

void initialize_inputs(LayerState &state) {
    for (std::size_t wire = 0; wire < state.wire_count; ++wire) {
        const std::size_t input = wire % state.input_count;
        for (std::size_t lane = 0; lane < state.value_width; ++lane) {
            state.current[wire * state.value_width + lane] =
                Fp(29 * input + 17 * lane + 3);
        }
    }
}

LayerState make_initial_state(std::size_t wire_count,
                              std::size_t value_width) {
    const std::size_t values = wire_count * value_width;
    LayerState result{
        wire_count,
        value_width,
        std::min(wire_count, kBenchmarkDiamondInputCiphertexts),
        std::min(wire_count, kBenchmarkDiamondOutputCiphertexts),
        std::vector<Fp>(values),
        std::vector<Fp>(values)};
    initialize_inputs(result);
    return result;
}

void evaluate_diamond_wire(LayerState &state, std::size_t left,
                           std::size_t right, const Fp &bias) {
    for (std::size_t lane = 0; lane < state.value_width; ++lane) {
        state.next[left + lane] =
            state.current[left + lane] *
            (state.current[right + lane] + bias);
    }
}

/// Evaluate one constant-width multiplicative layer of the Diamond workload.
///
/// Preconditions:
/// - `state.current` and `state.next` each contain
///   `wire_count * value_width` field elements;
/// - `wire_count` and `value_width` are nonzero.
///
/// Postcondition:
/// - `state.current` contains the next layer defined by
///   `next[i,l] = current[i,l] * (current[(i+1) mod w,l] + bias)`.
void evaluate_diamond_layer(LayerState &state, const Fp &bias) {
    for (std::size_t wire = 0; wire + 1 < state.wire_count; ++wire) {
        const std::size_t left = wire * state.value_width;
        evaluate_diamond_wire(state, left, left + state.value_width, bias);
    }
    const std::size_t last =
        (state.wire_count - 1) * state.value_width;
    evaluate_diamond_wire(state, last, 0, bias);
    state.current.swap(state.next);
}

Fp balanced_group_sum(const LayerState &state, std::size_t first_wire,
                      std::size_t wire_stride, std::size_t wire_count,
                      std::size_t lane) {
    if (wire_count == 1) {
        return state.current[first_wire * state.value_width + lane];
    }
    const std::size_t left_count = (wire_count + 1) / 2;
    return balanced_group_sum(state, first_wire, wire_stride, left_count,
                              lane) +
           balanced_group_sum(state, first_wire + left_count * wire_stride,
                              wire_stride, wire_count - left_count, lane);
}

void reduce_diamond_outputs(LayerState &state) {
    for (std::size_t output = 0; output < state.output_count; ++output) {
        const std::size_t group_size =
            (state.wire_count - 1 - output) / state.output_count + 1;
        for (std::size_t lane = 0; lane < state.value_width; ++lane) {
            state.next[output * state.value_width + lane] =
                balanced_group_sum(state, output, state.output_count,
                                   group_size, lane);
        }
    }
    state.current.swap(state.next);
}

void evaluate_diamond_payload(LayerState &state, std::size_t depth,
                              const Fp &bias) {
    for (std::size_t layer = 0; layer < depth; ++layer) {
        evaluate_diamond_layer(state, bias);
    }
    reduce_diamond_outputs(state);
}

std::uint64_t checksum(const LayerState &state) {
    std::uint64_t result = 0;
    for (std::size_t wire = 0; wire < state.output_count; ++wire) {
        result ^= state.current[wire * state.value_width].value() + wire;
    }
    return result;
}

std::vector<double> measure_payload(LayerState &state, std::size_t depth,
                                    std::size_t repetitions,
                                    const Fp &bias) {
    std::vector<double> samples;
    samples.reserve(repetitions);
    for (std::size_t repetition = 0; repetition < repetitions;
         ++repetition) {
        initialize_inputs(state);
        samples.push_back(
            timed_void([&] { evaluate_diamond_payload(state, depth, bias); })
                .wall_ms);
    }
    return samples;
}

int run(const Options &options, int argc, char **argv) {
    const std::size_t sampled_width =
        options.sampled_value_width == 0
            ? options.logical_value_width
            : options.sampled_value_width;

    // Step 1: allocate only the preceding and next payload layers.
    LayerState state = make_initial_state(options.width, sampled_width);
    const Fp bias(29);

    // Step 2: warm instruction and data paths before retaining samples.
    evaluate_diamond_payload(state, options.depth, bias);

    // Step 3: measure the exact target equation at the sampled value width.
    const std::vector<double> samples = measure_payload(
        state, options.depth, options.repetitions, bias);
    const Samples summary = summarize(samples);

    // Step 4: scale only across independent payload coordinates. This is
    // exact operation counting, but a timing estimate when the widths differ.
    const double scale = static_cast<double>(options.logical_value_width) /
                         static_cast<double>(sampled_width);
    const double median_estimate_ms = summary.median * scale;
    const double mean_estimate_ms = summary.mean * scale;
    const std::uint64_t middle_operations =
        options.depth * options.width * options.logical_value_width;
    const std::uint64_t terminal_additions =
        (options.width - state.output_count) *
        options.logical_value_width;
    const std::uint64_t field_additions =
        middle_operations + terminal_additions;
    const std::uint64_t field_multiplications = middle_operations;
    const std::uint64_t field_operations =
        field_additions + field_multiplications;

    const Record record;
    record.text("format", "laminate-plaintext-payload-calibration-v2");
    record.text("classification.result_kind",
                sampled_width == options.logical_value_width
                    ? "measured-exact-single-thread"
                    : "single-thread-linear-width-projection");
    emit_benchmark_provenance(record, argc, argv);
    record.text("workload.kind", "diamond");
    record.text(
        "workload.equation",
        "d constant-width multiply layers followed by a four-output sum tree");
    record.integer("parameters.depth", options.depth);
    record.integer("parameters.width", options.width);
    record.integer("parameters.input_ciphertexts", state.input_count);
    record.integer("parameters.output_ciphertexts", state.output_count);
    record.integer("parameters.logical_value_width",
                   options.logical_value_width);
    record.integer("parameters.sampled_value_width", sampled_width);
    record.integer("parameters.repetitions", options.repetitions);
    record.integer("counts.logical_input_elements",
                   state.input_count * options.logical_value_width);
    record.integer("counts.logical_output_elements",
                   state.output_count * options.logical_value_width);
    record.integer("counts.logical_field_additions", field_additions);
    record.integer("counts.logical_field_multiplications",
                   field_multiplications);
    record.integer("counts.logical_field_operations", field_operations);
    record.integer("memory.sample_streaming_bytes",
                   2ULL * options.width * sampled_width * sizeof(Fp));
    record.integer("memory.target_streaming_bytes",
                   2ULL * options.width * options.logical_value_width *
                       sizeof(Fp));
    emit_samples(record, "timing.sample_wall_ms", samples);
    record.real("timing.logical_width_scale", scale);
    record.real("timing.payload_median_estimate_ms", median_estimate_ms);
    record.real("timing.payload_mean_estimate_ms", mean_estimate_ms);
    record.integer("result.checksum", checksum(state));
    return 0;
}

// Command-line handling lives below the payload evaluator so the target
// equation and its two-layer evaluation remain the first readable path.
std::optional<Options> parse_options(int argc, char **argv) {
    Options result;
    for (int index = 1; index < argc; ++index) {
        const std::string_view argument(argv[index]);
        if (argument == "--help" || argument == "-h") {
            std::cout
                << "Usage: laminate_plaintext_payload_bench [options]\n"
                << "  --value-width B [--sample-value-width S]\n"
                << "  --depth d --width W --repetitions I\n";
            return std::nullopt;
        }
        if (index + 1 == argc) {
            throw std::invalid_argument(std::string(argument) +
                                        " requires a value");
        }
        const std::string_view value(argv[++index]);
        if (argument == "--value-width") {
            result.logical_value_width = parse_size(value, argument);
        } else if (argument == "--sample-value-width") {
            result.sampled_value_width = parse_size(value, argument);
        } else if (argument == "--depth") {
            result.depth = parse_size(value, argument);
        } else if (argument == "--width") {
            result.width = parse_size(value, argument);
        } else if (argument == "--repetitions") {
            result.repetitions = parse_size(value, argument);
        } else {
            throw std::invalid_argument("unknown option: " +
                                        std::string(argument));
        }
    }

    const std::size_t sampled_width =
        result.sampled_value_width == 0
            ? result.logical_value_width
            : result.sampled_value_width;
    if (result.logical_value_width == 0 || sampled_width == 0 ||
        sampled_width > result.logical_value_width || result.depth == 0 ||
        result.depth > kMaximumPayloadMultiplicativeDepth ||
        result.width == 0 || result.repetitions == 0) {
        throw std::invalid_argument("invalid payload-calibration dimensions");
    }
    return result;
}

} // namespace

int main(int argc, char **argv) {
    try {
        const std::optional<Options> options = parse_options(argc, argv);
        return options ? run(*options, argc, argv) : 0;
    } catch (const std::exception &error) {
        std::cerr << "error: " << error.what() << '\n';
        return 1;
    }
}
