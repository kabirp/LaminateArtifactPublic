#include "laminate/payload/trace.hpp"

#include "laminate/field/serialization.hpp"

#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

namespace laminate::payload {
namespace {

using Bytes = std::vector<std::uint8_t>;

void append_u64(Bytes &output, std::size_t value) {
    if (value > std::numeric_limits<std::uint64_t>::max()) {
        throw std::overflow_error("PlainTrace digest: size does not fit u64");
    }
    const auto encoded = static_cast<std::uint64_t>(value);
    for (std::size_t byte = 0; byte < 8; ++byte) {
        output.push_back(static_cast<std::uint8_t>(
            (encoded >> (8U * byte)) & std::uint64_t{0xff}));
    }
}

void append_label(Bytes &output, std::string_view label) {
    append_u64(output, label.size());
    output.insert(output.end(), label.begin(), label.end());
}

fhe::SlotVector zero_value(std::size_t width) {
    return fhe::SlotVector(width, Fp::zero());
}

fhe::SlotVector evaluate_affine_gate(const AffineGate &gate,
                                     const std::vector<fhe::SlotVector> &source,
                                     const LayeredCircuit &circuit) {
    const std::size_t width = circuit.shape.value_width();
    fhe::SlotVector result = materialize(gate.constant, width);
    for (const AffineTerm &term : gate.terms) {
        const fhe::SlotVector *values = &source[term.source];
        fhe::SlotVector rotated;
        if (term.rotation != 0) {
            rotated = fhe::grid_rotate(*values, term.rotation);
            values = &rotated;
        }
        for (std::size_t slot = 0; slot < width; ++slot) {
            result[slot] += (*values)[slot] * term.coefficient *
                (term.plaintext_index
                    ? circuit.plaintexts[*term.plaintext_index][slot]
                    : Fp::one());
        }
    }
    return result;
}

fhe::SlotVector evaluate_multiplication_gate(
    std::size_t gate, std::size_t pair_count,
    const std::vector<fhe::SlotVector> &source) {
    const fhe::SlotVector &left = source[gate];
    const fhe::SlotVector &right = source[pair_count + gate];
    fhe::SlotVector result(left.size());
    for (std::size_t slot = 0; slot < result.size(); ++slot) {
        result[slot] = left[slot] * right[slot];
    }
    return result;
}

std::vector<fhe::SlotVector>
evaluate_relation(const Layer &layer,
                  const std::vector<fhe::SlotVector> &source,
                  const LayeredCircuit &circuit) {
    std::vector<fhe::SlotVector> result;
    const std::size_t output_size = layer_dimensions(layer).padded_size;
    result.reserve(output_size);
    if (const auto *affine = std::get_if<AffineLayer>(&layer)) {
        std::vector<fhe::SlotVector> values = source;
        values.reserve(source.size() + affine->intermediate_gates.size());
        for (const AffineGate &gate : affine->intermediate_gates) {
            values.push_back(evaluate_affine_gate(gate, values, circuit));
        }
        for (const AffineGate &gate : affine->gates) {
            result.push_back(evaluate_affine_gate(gate, values, circuit));
        }
    } else if (const auto *multiplication =
                   std::get_if<MultiplicationLayer>(&layer)) {
        for (std::size_t gate = 0; gate < multiplication->gates.size();
             ++gate) {
            result.push_back(
                evaluate_multiplication_gate(
                    gate, multiplication->dimensions.padded_size, source));
        }
    } else {
        throw std::logic_error(
            "evaluate_relation: input layer has no predecessor relation");
    }
    return result;
}

void validate_layer_shapes(const LayeredCircuit &circuit,
                           const PlainTrace &trace) {
    if (!(trace.shape == circuit.shape)) {
        throw std::invalid_argument(
            "validate_trace: trace and circuit shapes differ");
    }
    if (trace.layers.size() != circuit.layers.size()) {
        throw std::invalid_argument(
            "validate_trace: trace has the wrong layer count");
    }
    const std::size_t width = circuit.shape.value_width();
    for (std::size_t layer = 0; layer < trace.layers.size(); ++layer) {
        if (trace.layers[layer].size() !=
            layer_dimensions(circuit.layers[layer]).padded_size) {
            throw std::invalid_argument(
                "validate_trace: layer has the wrong padded size");
        }
        for (const fhe::SlotVector &wire : trace.layers[layer]) {
            if (wire.size() != width) {
                throw std::invalid_argument(
                    "validate_trace: layer wire has the wrong width");
            }
        }
    }
}

} // namespace

std::string_view provenance_name(TraceProvenance provenance) {
    switch (provenance) {
    case TraceProvenance::SyntheticTrace:
        return "synthetic-trace";
    case TraceProvenance::FheEvaluated:
        return "fhe-evaluated";
    }
    throw std::invalid_argument("provenance_name: unknown provenance");
}

std::vector<fhe::SlotVector>
prevalidated_plain_trace::make_plain_input_layer_from_validated_circuit(
    const LayeredCircuit &circuit,
    std::span<const fhe::SlotVector> inputs) {
    if (inputs.size() != circuit.payload_input_count) {
        throw std::invalid_argument(
            "make_plain_input_layer: input count does not match payload");
    }
    const std::size_t width = circuit.shape.value_width();
    for (const fhe::SlotVector &input : inputs) {
        if (input.size() != width) {
            throw std::invalid_argument(
                "make_plain_input_layer: input has the wrong logical width");
        }
    }
    std::vector<fhe::SlotVector> result(inputs.begin(), inputs.end());
    result.resize(layer_dimensions(circuit.layers.back()).padded_size,
                  zero_value(width));
    return result;
}

std::vector<fhe::SlotVector> make_plain_input_layer(
    const LayeredCircuit &circuit,
    std::span<const fhe::SlotVector> inputs) {
    circuit.validate();
    return prevalidated_plain_trace::make_plain_input_layer_from_validated_circuit(
        circuit, inputs);
}

std::vector<std::vector<fhe::SlotVector>>
evaluate_layers(const LayeredCircuit &circuit,
                std::span<const fhe::SlotVector> inputs) {
    std::vector<std::vector<fhe::SlotVector>> layers(circuit.layers.size());
    layers.back() = make_plain_input_layer(circuit, inputs);

    for (std::size_t index = circuit.layers.size() - 1; index > 0; --index) {
        layers[index - 1] =
            evaluate_relation(circuit.layers[index - 1], layers[index], circuit);
    }
    return layers;
}

PlainTrace synthesize_trace(const PayloadCircuit &payload,
                            const LayeredCircuit &layered,
                            std::span<const fhe::SlotVector> inputs) {
    payload.validate();
    layered.validate();
    if (!(payload.shape == layered.shape) ||
        payload.input_count != layered.payload_input_count ||
        payload.outputs.size() != layered.payload_output_count) {
        throw std::invalid_argument(
            "synthesize_trace: payload and layered circuit disagree");
    }

    PayloadEvaluation payload_evaluation = evaluate(payload, inputs);
    PlainTrace trace;
    trace.shape = payload.shape;
    trace.provenance = TraceProvenance::SyntheticTrace;
    trace.payload_wires = std::move(payload_evaluation.wires);
    trace.payload_outputs.reserve(payload.outputs.size());
    for (WireId output : payload.outputs) {
        trace.payload_outputs.push_back(trace.payload_wires[output]);
    }
    trace.layers = evaluate_layers(layered, inputs);
    validate_trace(payload, layered, trace);
    return trace;
}

void validate_trace(const PayloadCircuit &payload,
                    const LayeredCircuit &layered,
                    const PlainTrace &trace) {
    payload.validate();
    layered.validate();
    if (!(payload.shape == layered.shape) ||
        payload.input_count != layered.payload_input_count ||
        payload.outputs.size() != layered.payload_output_count) {
        throw std::invalid_argument(
            "validate_trace: payload and layered circuit disagree");
    }
    validate_layer_shapes(layered, trace);

    if (trace.payload_wires.size() != payload.wire_count()) {
        throw std::invalid_argument(
            "validate_trace: payload assignment has the wrong size");
    }
    const std::size_t width = payload.shape.value_width();
    for (const fhe::SlotVector &wire : trace.payload_wires) {
        if (wire.size() != width) {
            throw std::invalid_argument(
                "validate_trace: payload wire has the wrong width");
        }
    }

    std::vector<fhe::SlotVector> inputs(
        trace.payload_wires.begin(),
        trace.payload_wires.begin() +
            static_cast<std::ptrdiff_t>(payload.input_count));
    const PayloadEvaluation expected_payload = evaluate(payload, inputs);
    if (expected_payload.wires != trace.payload_wires) {
        throw std::invalid_argument(
            "validate_trace: payload wire relation failed");
    }
    const std::vector<fhe::SlotVector> expected_outputs =
        expected_payload.output_values(payload);
    if (trace.payload_outputs != expected_outputs) {
        throw std::invalid_argument(
            "validate_trace: recorded payload outputs are incorrect");
    }

    const std::vector<fhe::SlotVector> &input_layer = trace.layers.back();
    for (std::size_t input = 0; input < payload.input_count; ++input) {
        if (input_layer[input] != trace.payload_wires[input]) {
            throw std::invalid_argument(
                "validate_trace: alternating input disagrees with payload");
        }
    }
    for (std::size_t padding = payload.input_count;
         padding < input_layer.size(); ++padding) {
        if (input_layer[padding] != zero_value(width)) {
            throw std::invalid_argument(
                "validate_trace: input-layer padding is nonzero");
        }
    }

    for (std::size_t index = trace.layers.size() - 1; index > 0; --index) {
        const std::vector<fhe::SlotVector> expected = evaluate_relation(
            layered.layers[index - 1], trace.layers[index], layered);
        if (trace.layers[index - 1] != expected) {
            throw std::invalid_argument(
                "validate_trace: alternating relation failed at layer " +
                std::to_string(index - 1));
        }
    }

    const std::size_t output_count = payload.outputs.size();
    for (std::size_t output = 0; output < output_count; ++output) {
        if (trace.layers.front()[output] != trace.payload_outputs[output]) {
            throw std::invalid_argument(
                "validate_trace: alternating output disagrees with payload");
        }
    }
}

Digest digest(const PlainTrace &trace, const Digest &circuit_digest) {
    trace.shape.validate();
    Bytes encoded;
    append_label(encoded, "LaminateImpl/PlainTrace/v1");
    encoded.insert(encoded.end(), circuit_digest.begin(), circuit_digest.end());
    encoded.push_back(static_cast<std::uint8_t>(trace.provenance));
    encoded.push_back(static_cast<std::uint8_t>(trace.shape.kind));
    append_u64(encoded, trace.shape.slot_count);
    append_u64(encoded, trace.shape.lane_count);
    append_u64(encoded, trace.layers.size());
    for (const auto &layer : trace.layers) {
        append_u64(encoded, layer.size());
        for (const fhe::SlotVector &wire : layer) {
            append_u64(encoded, wire.size());
            for (const Fp &value : wire) {
                const SerializedFp field = serialize(value);
                encoded.insert(encoded.end(), field.begin(), field.end());
            }
        }
    }
    return sha256(encoded);
}

} // namespace laminate::payload
