/// @file laned_payload_benchmark.cpp
/// @brief Single-thread real-SEAL benchmark and target-width projection.

#include "benchmark_support.hpp"

#include "laminate/fhe/seal_backend.hpp"
#include "laminate/fhe/storage/value_codec.hpp"
#include "laminate/payload/compiler.hpp"
#include "laminate/payload/evaluator.hpp"
#include "laminate/payload/laned_fhe_evaluator.hpp"
#include "laminate/payload/input_encryption.hpp"
#include "laminate/payload/trace/trace_crypto.hpp"
#include "laminate/payload/fixtures/workloads.hpp"

#include <algorithm>
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

using namespace laminate;
using namespace laminate::bench;
using namespace laminate::fhe;
using namespace laminate::payload;

namespace {

struct Options {
    std::size_t slots = std::size_t{1} << 14;
    std::size_t lanes = std::size_t{1} << 14;
    std::size_t depth = kMaximumPayloadMultiplicativeDepth;
    std::size_t width = 8;
    std::size_t projected_width = kBenchmarkDiamondMiddleWidth;
    std::vector<int> data_prime_bit_sizes;
    std::vector<std::uint64_t> exact_data_primes;
    std::size_t special_prime_bits = 34;
    std::uint64_t exact_special_prime = 0;
    std::size_t max_ciphertext_modulus_bits = 420;
    std::size_t max_key_modulus_bits = 0;
    std::size_t payload_switches = std::numeric_limits<std::size_t>::max();
    std::string run_tier = "target-measured";

    Options() {
        const SealParameters profile =
            make_depth8_diagnostic_parameters(false);
        exact_data_primes = profile.exact_data_primes;
        exact_special_prime = profile.exact_special_prime;
        special_prime_bits =
            static_cast<std::size_t>(profile.special_prime_bits);
        max_ciphertext_modulus_bits =
            profile.max_fresh_ciphertext_modulus_bits;
    }
};

std::vector<int> parse_bit_sizes(std::string_view value,
                                 std::string_view option) {
    std::vector<int> result;
    while (!value.empty()) {
        const std::size_t comma = value.find(',');
        const std::string_view part = value.substr(0, comma);
        const std::size_t bits = parse_size(part, option);
        if (bits > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
            throw std::invalid_argument(std::string(option) +
                                        " entry is too large");
        }
        result.push_back(static_cast<int>(bits));
        if (comma == std::string_view::npos) {
            break;
        }
        value.remove_prefix(comma + 1);
    }
    return result;
}

std::vector<std::uint64_t> parse_primes(std::string_view value,
                                        std::string_view option) {
    std::vector<std::uint64_t> result;
    while (!value.empty()) {
        const std::size_t comma = value.find(',');
        result.push_back(static_cast<std::uint64_t>(
            parse_size(value.substr(0, comma), option)));
        if (comma == std::string_view::npos) {
            break;
        }
        value.remove_prefix(comma + 1);
    }
    return result;
}

std::optional<Options> parse_options(int argc, char **argv) {
    Options result;
    for (int index = 1; index < argc; ++index) {
        const std::string_view argument(argv[index]);
        if (argument == "--help" || argument == "-h") {
            std::cout
                << "Usage: laminate_laned_payload_bench [options]\n"
                << "  --slots N --lanes B --depth d --width W\n"
                << "  --project-width W  target width for count projection\n"
                << "  --data-prime-bits b0,b1,...,bL  bottom-to-top\n"
                << "  --data-primes q0,q1,...,qL  exact bottom-to-top\n"
                << "  --special-prime-bits B\n"
                << "  --special-prime q  exact key-switching prime\n"
                << "  --payload-switches S  early CT-CT layers switched\n"
                << "  --max-ciphertext-modulus-bits B\n"
                << "  --max-key-modulus-bits B\n"
                << "  --run-tier unit|target-measured\n";
            return std::nullopt;
        }
        if (index + 1 == argc) {
            throw std::invalid_argument("missing value after " +
                                        std::string(argument));
        }
        const std::string_view value(argv[++index]);
        if (argument == "--slots") {
            result.slots = parse_size(value, argument);
        } else if (argument == "--lanes") {
            result.lanes = parse_size(value, argument);
        } else if (argument == "--depth") {
            result.depth = parse_size(value, argument);
        } else if (argument == "--width") {
            result.width = parse_size(value, argument);
        } else if (argument == "--project-width") {
            result.projected_width = parse_size(value, argument);
        } else if (argument == "--data-prime-bits") {
            result.data_prime_bit_sizes = parse_bit_sizes(value, argument);
            result.exact_data_primes.clear();
            result.exact_special_prime = 0;
        } else if (argument == "--data-primes") {
            result.exact_data_primes = parse_primes(value, argument);
            result.data_prime_bit_sizes.clear();
        } else if (argument == "--special-prime-bits") {
            result.special_prime_bits = parse_size(value, argument);
        } else if (argument == "--special-prime") {
            result.exact_special_prime =
                static_cast<std::uint64_t>(parse_size(value, argument));
        } else if (argument == "--payload-switches") {
            result.payload_switches = parse_size(value, argument);
        } else if (argument == "--max-ciphertext-modulus-bits") {
            result.max_ciphertext_modulus_bits = parse_size(value, argument);
        } else if (argument == "--max-key-modulus-bits") {
            result.max_key_modulus_bits = parse_size(value, argument);
        } else if (argument == "--run-tier") {
            result.run_tier = value;
        } else {
            throw std::invalid_argument("unknown option: " +
                                        std::string(argument));
        }
    }

    if (result.slots < 1024 || !std::has_single_bit(result.slots) ||
        result.lanes == 0 || !std::has_single_bit(result.lanes) ||
        result.lanes > result.slots || result.slots % result.lanes != 0 ||
        result.depth == 0 ||
        result.depth > kMaximumPayloadMultiplicativeDepth ||
        result.width == 0 ||
        !std::has_single_bit(result.width) ||
        result.projected_width < result.width ||
        (result.data_prime_bit_sizes.empty() &&
         result.exact_data_primes.empty()) ||
        (!result.data_prime_bit_sizes.empty() &&
         (result.data_prime_bit_sizes.front() != 60 ||
          std::any_of(result.data_prime_bit_sizes.begin() + 1,
                      result.data_prime_bit_sizes.end(),
                      [](int bits) { return bits < 18 || bits > 60; }))) ||
        (!result.exact_data_primes.empty() &&
         (result.exact_data_primes.front() != kOuterFieldOrder ||
          result.exact_special_prime == 0)) ||
        result.special_prime_bits < 20 ||
        result.special_prime_bits > 60) {
        throw std::invalid_argument("invalid Laned or SEAL dimensions");
    }
    const std::size_t data_limbs = result.data_prime_bit_sizes.empty()
                                       ? result.exact_data_primes.size()
                                       : result.data_prime_bit_sizes.size();
    if (result.payload_switches ==
        std::numeric_limits<std::size_t>::max()) {
        result.payload_switches = result.depth - 1;
    }
    if (result.payload_switches > result.depth ||
        result.payload_switches >= data_limbs) {
        throw std::invalid_argument(
            "payload switch count exceeds the circuit or data chain");
    }
    if (result.run_tier != "unit" &&
        result.run_tier != "target-measured") {
        throw std::invalid_argument(
            "--run-tier must be unit or target-measured");
    }
    if (result.run_tier == "unit" && result.slots > 1024) {
        throw std::invalid_argument(
            "N above 1024 requires --run-tier target-measured");
    }
    return result;
}

struct BenchmarkPayload {
    PayloadCircuit circuit;
    std::vector<SlotVector> inputs;
};

std::uint64_t checked_scale(std::uint64_t value, std::size_t scale,
                            std::string_view quantity) {
    if (scale != 0 &&
        value > std::numeric_limits<std::uint64_t>::max() / scale) {
        throw std::overflow_error(std::string(quantity) +
                                  " projection exceeds uint64");
    }
    return value * scale;
}

std::uint64_t checked_add(std::uint64_t left, std::uint64_t right,
                          std::string_view quantity) {
    if (right > std::numeric_limits<std::uint64_t>::max() - left) {
        throw std::overflow_error(std::string(quantity) +
                                  " projection exceeds uint64");
    }
    return left + right;
}

std::uint64_t logical_gate_count(const PayloadStats &stats) {
    return static_cast<std::uint64_t>(stats.add_gates) +
           static_cast<std::uint64_t>(stats.add_plain_gates) +
           static_cast<std::uint64_t>(stats.mul_gates) +
           static_cast<std::uint64_t>(stats.mul_plain_gates) +
           static_cast<std::uint64_t>(stats.rotate_gates);
}

BenchmarkPayload make_payload(const Options &options) {
    const PayloadShape shape =
        PayloadShape::laned(options.lanes, options.slots);
    Workload workload = make_workload(WorkloadSpec{
        .kind = WorkloadKind::Diamond,
        .shape = shape,
        .multiplicative_depth = options.depth,
        .width = options.width,
        .seed = 7,
    });
    return BenchmarkPayload{std::move(workload.circuit),
                            std::move(workload.inputs)};
}

struct PayloadGeometry {
    PayloadStats operations;
    std::size_t input_ciphertexts = 0;
    std::size_t output_ciphertexts = 0;
    std::vector<std::size_t> layer_ciphertexts;
};

PayloadGeometry make_payload_geometry(const Options &options,
                                      std::size_t width) {
    Options geometry_options = options;
    geometry_options.width = width;
    geometry_options.projected_width = width;
    BenchmarkPayload payload = make_payload(geometry_options);
    const LayeredCircuit circuit = compile(payload.circuit);

    PayloadGeometry result;
    result.operations = analyze(payload.circuit);
    result.input_ciphertexts = payload.circuit.input_count;
    result.output_ciphertexts = payload.circuit.outputs.size();
    result.layer_ciphertexts.reserve(circuit.layers.size());
    for (const Layer &layer : circuit.layers) {
        result.layer_ciphertexts.push_back(
            layer_dimensions(layer).padded_size);
    }
    return result;
}

void emit_counts(const Record &record,
                 const SealBackend::OperationCounts &counts) {
    for (std::size_t index = 0;
         index < static_cast<std::size_t>(
                     SealBackend::OperationKind::Count);
         ++index) {
        const auto kind = static_cast<SealBackend::OperationKind>(index);
        const std::string operation = SealBackend::operation_name(kind);
        const std::string prefix = "operations.payload." + operation;
        record.integer(prefix + ".calls", counts.calls(kind));
        record.integer(prefix + ".limb_operations",
                       counts.limb_operations(kind));
        std::vector<std::string> buckets;
        for (const auto &[limbs, calls] : counts.buckets(kind)) {
            buckets.push_back(std::to_string(limbs) + ':' +
                              std::to_string(calls));
        }
        record.text(prefix + ".by_rns_limb",
                    buckets.empty() ? "none" : join(buckets));
    }
}

int run(const Options &options, int argc, char **argv) {
    const auto [payload, construction_timing] =
        timed([&] { return make_payload(options); });
    const auto [circuit, compilation_timing] =
        timed([&] { return compile(payload.circuit); });
    const PayloadStats payload_stats = analyze(payload.circuit);
    const auto [contexts, setup_timing] = timed([&] {
        return SealBackend::create(SealParameters{
            .poly_modulus_degree = options.slots,
            .fresh_rns_limbs = options.data_prime_bit_sizes.empty()
                                   ? options.exact_data_primes.size()
                                   : options.data_prime_bit_sizes.size(),
            .data_prime_bit_sizes = options.data_prime_bit_sizes,
            .exact_data_primes = options.exact_data_primes,
            .exact_special_prime = options.exact_special_prime,
            .bits_per_data_prime = 60,
            .special_prime_bits =
                static_cast<int>(options.special_prime_bits),
            .security_level = seal::sec_level_type::none,
            .max_fresh_ciphertext_modulus_bits =
                options.max_ciphertext_modulus_bits,
            .max_key_modulus_bits = options.max_key_modulus_bits,
            .generate_galois_keys = false,
        });
    });

    SealBackend::reset_counts(contexts.eval);
    SealBackend::set_counting(contexts.eval, true);
    const auto [encrypted_inputs, encryption_timing] = timed([&] {
        return encrypt_laned_payload_inputs<SealBackend>(
            contexts.client, payload.circuit, payload.inputs);
    });
    SealBackend::set_counting(contexts.eval, false);

    std::vector<double> fresh_noise;
    for (const auto &ciphertext : encrypted_inputs) {
        fresh_noise.push_back(static_cast<double>(
            SealBackend::invariant_noise_budget(contexts.client,
                                                ciphertext)));
    }

    SealBackend::reset_counts(contexts.eval);
    SealBackend::set_counting(contexts.eval, true);
    const auto [trace, evaluation_timing] = timed([&] {
        return evaluate_laned_fhe_trace<SealBackend>(
            contexts.eval, payload.circuit, circuit, encrypted_inputs,
            FheEvaluationPlan::at_evaluation_levels(
                circuit,
                (options.data_prime_bit_sizes.empty()
                     ? options.exact_data_primes.size()
                     : options.data_prime_bit_sizes.size()) -
                    1,
                1, options.payload_switches));
    });
    SealBackend::set_counting(contexts.eval, false);
    const SealBackend::OperationCounts counts =
        SealBackend::counts(contexts.eval);
    if (counts.calls(SealBackend::OperationKind::Decrypt) != 0) {
        throw std::logic_error("server payload evaluation decrypted");
    }

    const auto [output, decryption_timing] = timed([&] {
        return decrypt_trace_layer<SealBackend>(contexts.client, circuit,
                                                trace, 0);
    });
    const std::vector<SlotVector> expected =
        evaluate(payload.circuit, payload.inputs).output_values(
            payload.circuit);
    if (output != expected) {
        throw std::runtime_error(
            "homomorphic payload output differs from plaintext evaluation");
    }

    std::vector<std::size_t> layer_rns_limbs;
    std::vector<std::size_t> layer_modulus_bits;
    std::vector<int> layer_minimum_noise;
    std::vector<std::uint64_t> layer_serialized_bytes;
    std::vector<std::size_t> layer_encrypted_record_bytes;
    std::vector<std::size_t> layer_record_counts;
    std::vector<std::size_t> layer_ciphertext_counts;
    std::vector<std::size_t> layer_public_value_counts;
    std::uint64_t retained_trace_bytes = 0;
    std::uint64_t retained_trace_ciphertexts = 0;
    std::uint64_t retained_trace_public_values = 0;
    for (std::size_t layer_index = 0; layer_index < trace.layers.size();
         ++layer_index) {
        const EncryptedTraceLayer<SealBackend> &layer =
            trace.layers[layer_index];
        std::size_t minimum_limbs = std::numeric_limits<std::size_t>::max();
        std::size_t minimum_modulus =
            std::numeric_limits<std::size_t>::max();
        int minimum_noise = std::numeric_limits<int>::max();
        std::uint64_t serialized_layer_bytes = 0;
        std::optional<std::size_t> serialized_encrypted_record_bytes;
        std::size_t ciphertext_count = 0;
        std::size_t public_value_count = 0;
        for (const FheValue<SealBackend> &value : layer.wires) {
            const std::size_t serialized_bytes =
                encode_canonical_fhe_value<SealBackend>(
                    value, "payload benchmark trace value")
                    .size();
            serialized_layer_bytes = checked_add(
                serialized_layer_bytes, serialized_bytes,
                "serialized trace layer");
            if (value.is_public()) {
                ++public_value_count;
                ++retained_trace_public_values;
                continue;
            }
            const SealBackend::Ciphertext &ciphertext = value.ciphertext();
            minimum_limbs = std::min(
                minimum_limbs,
                SealBackend::rns_limb_count(contexts.eval, ciphertext));
            minimum_modulus = std::min(
                minimum_modulus,
                SealBackend::coeff_modulus_bits(contexts.eval, ciphertext));
            minimum_noise = std::min(
                minimum_noise,
                SealBackend::invariant_noise_budget(contexts.client,
                                                    ciphertext));
            if (serialized_encrypted_record_bytes &&
                *serialized_encrypted_record_bytes != serialized_bytes) {
                throw std::logic_error(
                    "uncompressed encrypted record size varies within a "
                    "layer");
            }
            serialized_encrypted_record_bytes = serialized_bytes;
            ++ciphertext_count;
            ++retained_trace_ciphertexts;
        }
        retained_trace_bytes = checked_add(
            retained_trace_bytes, serialized_layer_bytes,
            "serialized trace");
        layer_serialized_bytes.push_back(serialized_layer_bytes);
        layer_encrypted_record_bytes.push_back(
            serialized_encrypted_record_bytes.value_or(0));
        layer_record_counts.push_back(layer.wires.size());
        layer_ciphertext_counts.push_back(ciphertext_count);
        layer_public_value_counts.push_back(public_value_count);
        layer_rns_limbs.push_back(
            ciphertext_count == 0 ? 0 : minimum_limbs);
        layer_modulus_bits.push_back(
            ciphertext_count == 0 ? 0 : minimum_modulus);
        layer_minimum_noise.push_back(
            ciphertext_count == 0 ? -1 : minimum_noise);
    }
    for (std::size_t layer = 0; layer < trace.layers.size(); ++layer) {
        if (layer_ciphertext_counts[layer] != 0 &&
            layer_minimum_noise[layer] <= 0) {
            throw std::runtime_error(
                "retained trace exhausted invariant noise");
        }
    }

    const std::vector<std::uint64_t> primes =
        SealBackend::coefficient_moduli(contexts.eval);
    std::vector<std::size_t> prime_bits;
    prime_bits.reserve(primes.size());
    for (const std::uint64_t prime : primes) {
        prime_bits.push_back(std::bit_width(prime));
    }

    // Capture the measured run's high-water mark before constructing the
    // target circuit. Target construction is geometry work, not part of the
    // sampled resident execution.
    const SystemInfo system = system_info();
    const PayloadGeometry target_geometry =
        make_payload_geometry(options, options.projected_width);
    if (target_geometry.layer_ciphertexts.size() != trace.layers.size()) {
        throw std::logic_error(
            "sample and target Diamond circuits have different layer counts");
    }

    const double width_scale =
        static_cast<double>(options.projected_width) /
        static_cast<double>(options.width);
    const std::uint64_t measured_payload_operations =
        logical_gate_count(payload_stats);
    const std::uint64_t target_payload_operations =
        logical_gate_count(target_geometry.operations);
    if (measured_payload_operations == 0 ||
        payload.circuit.input_count == 0 || payload.circuit.outputs.empty()) {
        throw std::logic_error("payload measurement denominator is zero");
    }
    const double input_ciphertext_scale =
        static_cast<double>(target_geometry.input_ciphertexts) /
        static_cast<double>(payload.circuit.input_count);
    const double output_ciphertext_scale =
        static_cast<double>(target_geometry.output_ciphertexts) /
        static_cast<double>(payload.circuit.outputs.size());

    std::uint64_t projected_trace_bytes = 0;
    std::uint64_t projected_trace_ciphertexts = 0;
    std::vector<std::uint64_t> projected_layer_serialized_bytes;
    projected_layer_serialized_bytes.reserve(trace.layers.size());
    for (std::size_t layer = 0; layer < trace.layers.size(); ++layer) {
        if (target_geometry.layer_ciphertexts[layer] != 0 &&
            layer_encrypted_record_bytes[layer] == 0) {
            throw std::logic_error(
                "sample layer has no encrypted record for target trace "
                "projection");
        }
        const std::uint64_t target_layer_bytes = checked_scale(
            layer_encrypted_record_bytes[layer],
            target_geometry.layer_ciphertexts[layer],
            "target trace layer bytes");
        projected_layer_serialized_bytes.push_back(target_layer_bytes);
        projected_trace_bytes = checked_add(projected_trace_bytes,
                                            target_layer_bytes,
                                            "target trace bytes");
        projected_trace_ciphertexts = checked_add(
            projected_trace_ciphertexts,
            target_geometry.layer_ciphertexts[layer],
            "target trace ciphertexts");
    }

    const Record record;
    record.text("format", "laminate-fhe-payload-benchmark-v4");
    record.text("classification.result_kind",
                "measured-width-sample-plus-exact-target-geometry-and-io-"
                "count-projections");
    record.text("classification.measurement",
                "single-thread-real-seal-bgv-diamond-width-sample");
    record.text("classification.runtime_projection",
                "client-io-count-ratios-only;server-target-requires-cross-"
                "width-slope-intercept-fit");
    record.text("classification.trace_projection",
                "exact-target-layer-counts-times-uncompressed-tagged-"
                "encrypted-record-bytes-at-matching-level");
    record.text("classification.trace_source", "fhe-evaluated");
    record.text("classification.payload_shape", "laned");
    record.text("classification.security_level", "none");
    record.text("classification.privacy_claim",
                "none-not-a-privacy-parameter-set");
    record.text("classification.run_tier", options.run_tier);
    record.text("environment.command", exact_command(argc, argv));
    record.integer("environment.thread_count", 1);
    record.text("environment.os", system.os);
    record.text("environment.cpu", system.cpu);
    record.integer("environment.peak_rss_bytes", system.peak_rss_bytes);

    record.integer("parameters.N", options.slots);
    record.integer("parameters.lane_count_B", options.lanes);
    record.integer("parameters.payload_multiplicative_depth",
                   options.depth);
    record.integer("parameters.payload_ctct_depth",
                   payload_stats.ct_ct_multiplicative_depth);
    record.integer("parameters.payload_alternating_depth",
                   payload_stats.alternating_multiplicative_depth);
    record.integer("parameters.measured_payload_width", options.width);
    record.integer("parameters.projected_payload_width",
                   options.projected_width);
    record.real("parameters.projection_width_scale", width_scale);
    record.real("parameters.projection_input_ciphertext_scale",
                input_ciphertext_scale);
    record.real("parameters.projection_output_ciphertext_scale",
                output_ciphertext_scale);
    record.integer("parameters.measured_input_ciphertexts",
                   payload.circuit.input_count);
    record.integer("parameters.target_input_ciphertexts",
                   target_geometry.input_ciphertexts);
    record.integer("parameters.measured_output_ciphertexts",
                   payload.circuit.outputs.size());
    record.integer("parameters.target_output_ciphertexts",
                   target_geometry.output_ciphertexts);
    record.integer("parameters.fresh_rns_limbs",
                   options.data_prime_bit_sizes.empty()
                       ? options.exact_data_primes.size()
                       : options.data_prime_bit_sizes.size());
    record.text("parameters.coeff_modulus_bit_widths", join(prime_bits));
    record.integer("parameters.fresh_ciphertext_modulus_bits",
                   SealBackend::fresh_ciphertext_modulus_bits(contexts.eval));
    record.integer("parameters.fresh_ciphertext_modulus_width_sum_bits",
                   SealBackend::fresh_ciphertext_modulus_width_sum_bits(
                       contexts.eval));
    record.integer("parameters.key_modulus_bits",
                   SealBackend::key_modulus_bits(contexts.eval));
    record.integer("parameters.key_modulus_width_sum_bits",
                   SealBackend::key_modulus_width_sum_bits(contexts.eval));
    record.integer("parameters.max_fresh_ciphertext_modulus_bits",
                   options.max_ciphertext_modulus_bits);
    record.integer("parameters.max_key_modulus_bits",
                   options.max_key_modulus_bits);
    record.text("parameters.payload_mod_switch_policy",
                "one-after-each-selected-early-ctct-layer;proof-snapshots-retain-natural-level");
    record.integer("parameters.payload_switched_ctct_layers",
                   options.payload_switches);
    record.text("parameters.key_material_scope",
                "payload-only-public-relinearization-keys;rotation-keys-omitted");
    record.text("parameters.laned_plaintext_multiplication",
                "uniform-scalar-only");

    record.integer("logical_operations.measured.add",
                   payload_stats.add_gates);
    record.integer("logical_operations.measured.add_plain",
                   payload_stats.add_plain_gates);
    record.integer("logical_operations.measured.mul",
                   payload_stats.mul_gates);
    record.integer("logical_operations.measured.mul_plain",
                   payload_stats.mul_plain_gates);
    record.integer("logical_operations.measured.rotate",
                   payload_stats.rotate_gates);
    record.integer("logical_operations.measured.total",
                   logical_gate_count(payload_stats));
    record.integer("parameters.measured_n_FHE",
                   logical_gate_count(payload_stats));
    record.integer("logical_operations.target.add",
                   target_geometry.operations.add_gates);
    record.integer("logical_operations.target.add_plain",
                   target_geometry.operations.add_plain_gates);
    record.integer("logical_operations.target.mul",
                   target_geometry.operations.mul_gates);
    record.integer("logical_operations.target.mul_plain",
                   target_geometry.operations.mul_plain_gates);
    record.integer("logical_operations.target.rotate",
                   target_geometry.operations.rotate_gates);
    record.integer("logical_operations.target.total",
                   target_payload_operations);
    record.integer("parameters.target_n_FHE", target_payload_operations);

    emit_timing(record, "circuit_construction", construction_timing);
    emit_timing(record, "circuit_compilation", compilation_timing);
    emit_timing(record, "fhe_key_setup", setup_timing);
    emit_timing(record, "client_input_encryption", encryption_timing);
    record.real("ratio_projection.client_input_encryption.wall_ms",
                encryption_timing.wall_ms * input_ciphertext_scale);
    record.real("ratio_projection.client_input_encryption.cpu_ms",
                encryption_timing.cpu_ms * input_ciphertext_scale);
    emit_timing(record, "server_payload_evaluation_and_trace_preparation",
                evaluation_timing);
    emit_timing(record, "client_output_decryption", decryption_timing);
    record.real("ratio_projection.client_output_decryption.wall_ms",
                decryption_timing.wall_ms * output_ciphertext_scale);
    record.real("ratio_projection.client_output_decryption.cpu_ms",
                decryption_timing.cpu_ms * output_ciphertext_scale);
    emit_samples(record, "noise.fresh_input_invariant_bits", fresh_noise);
    record.text("trace.layers.order", "output-to-input");
    record.text("trace.layers.rns_limbs", join(layer_rns_limbs));
    record.text("trace.layers.coeff_modulus_bits", join(layer_modulus_bits));
    record.text("trace.layers.minimum_invariant_noise_bits",
                join(layer_minimum_noise));
    record.text("trace.layers.records", join(layer_record_counts));
    record.text("trace.layers.ciphertexts", join(layer_ciphertext_counts));
    record.text("trace.layers.public_values",
                join(layer_public_value_counts));
    record.text("trace.layers.serialized_bytes",
                join(layer_serialized_bytes));
    record.integer("trace.retained_serialized_bytes", retained_trace_bytes);
    record.integer("trace.retained_ciphertexts",
                   retained_trace_ciphertexts);
    record.integer("trace.retained_public_values",
                   retained_trace_public_values);
    record.text("target_trace.layers.ciphertexts",
                join(target_geometry.layer_ciphertexts));
    record.text("target_trace.layers.serialized_bytes",
                join(projected_layer_serialized_bytes));
    record.integer("target_trace.retained_serialized_bytes",
                   projected_trace_bytes);
    record.integer("target_trace.retained_ciphertexts",
                   projected_trace_ciphertexts);
    emit_counts(record, counts);
    record.text("verification.result", "PASS");
    return 0;
}

} // namespace

int main(int argc, char **argv) {
    try {
        const std::optional<Options> options = parse_options(argc, argv);
        return options ? run(*options, argc, argv) : 0;
    } catch (const std::exception &error) {
        std::cerr << "laminate_laned_payload_bench: " << error.what()
                  << '\n';
        return 1;
    }
}
