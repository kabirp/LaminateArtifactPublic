#include "laminate/payload/ir/layered.hpp"
#include "laminate/diagnostics/setup_validation.hpp"

#include <algorithm>
#include <limits>
#include <stdexcept>
#include <string>

namespace laminate::payload {
namespace {

bool is_uniform_constant(const AffineGate &gate, const Fp &expected) {
    if (!gate.terms.empty()) {
        return false;
    }
    if (const auto *scalar = std::get_if<Fp>(&gate.constant)) {
        return *scalar == expected;
    }
    const fhe::SlotVector &slots =
        std::get<fhe::SlotVector>(gate.constant);
    return std::all_of(slots.begin(), slots.end(), [&](const Fp &value) {
        return value == expected;
    });
}

bool is_power_of_two(std::size_t value) {
    return value != 0 && (value & (value - 1)) == 0;
}

void validate_dimensions(const LayerDimensions &dimensions,
                         const char *layer_name) {
    if (dimensions.logical_size == 0 ||
        dimensions.logical_size > dimensions.padded_size ||
        !is_power_of_two(dimensions.padded_size)) {
        throw std::invalid_argument(std::string("LayeredCircuit: invalid ") +
                                    layer_name + " dimensions");
    }
    if (dimensions.payload_size + dimensions.forward_size !=
        dimensions.logical_size) {
        throw std::invalid_argument(
            std::string("LayeredCircuit: inconsistent ") + layer_name +
            " logical gate counts");
    }
}

void validate_origins(const LayerDimensions &dimensions,
                      const auto &gates, const char *layer_name) {
    std::size_t payload = 0;
    std::size_t forward = 0;
    std::size_t padding = 0;
    for (const auto &gate : gates) {
        switch (gate.origin) {
        case GateOrigin::Payload:
            ++payload;
            break;
        case GateOrigin::Forward:
            ++forward;
            break;
        case GateOrigin::Padding:
            ++padding;
            break;
        }
    }
    if (payload != dimensions.payload_size ||
        forward != dimensions.forward_size ||
        padding != dimensions.padding_size()) {
        throw std::invalid_argument(std::string("LayeredCircuit: ") +
                                    layer_name + " origin counts disagree");
    }
}

} // namespace

LayerKind layer_kind(const Layer &layer) {
    if (std::holds_alternative<AffineLayer>(layer)) {
        return LayerKind::Affine;
    }
    if (std::holds_alternative<MultiplicationLayer>(layer)) {
        return LayerKind::Multiplication;
    }
    return LayerKind::Input;
}

const LayerDimensions &layer_dimensions(const Layer &layer) {
    return std::visit(
        [](const auto &typed_layer) -> const LayerDimensions & {
            return typed_layer.dimensions;
        },
        layer);
}

fhe::SlotVector materialize(const AffineConstant &constant,
                            std::size_t width) {
    if (const auto *scalar = std::get_if<Fp>(&constant)) {
        return fhe::SlotVector(width, *scalar);
    }
    const fhe::SlotVector &slots = std::get<fhe::SlotVector>(constant);
    if (slots.size() != width) {
        throw std::invalid_argument(
            "materialize: affine constant has the wrong width");
    }
    return slots;
}

void LayeredCircuit::validate() const {
    diagnostics::detail::observe_layered_circuit_validation();
    shape.validate();
    if (payload_input_count == 0 || payload_output_count == 0) {
        throw std::invalid_argument(
            "LayeredCircuit: payload input/output counts must be nonzero");
    }
    if (layers.size() != 2 * proof_multiplication_depth + 2) {
        throw std::invalid_argument(
            "LayeredCircuit: layer count does not match proof depth");
    }
    if (layers.empty() || layer_kind(layers.back()) != LayerKind::Input) {
        throw std::invalid_argument(
            "LayeredCircuit: final layer must be the input layer");
    }

    const std::size_t width = shape.value_width();
    for (const fhe::SlotVector &plaintext : plaintexts) {
        if (plaintext.size() != width) {
            throw std::invalid_argument(
                "LayeredCircuit: plaintext has the wrong logical width");
        }
    }

    for (std::size_t index = 0; index < layers.size(); ++index) {
        const bool is_last = index + 1 == layers.size();
        const LayerKind expected =
            is_last ? LayerKind::Input
                    : (index % 2 == 0 ? LayerKind::Affine
                                      : LayerKind::Multiplication);
        if (layer_kind(layers[index]) != expected) {
            throw std::invalid_argument(
                "LayeredCircuit: layers do not alternate from affine output");
        }

        const LayerDimensions &dimensions =
            layer_dimensions(layers[index]);
        validate_dimensions(dimensions, "layer");
        if (is_last) {
            if (dimensions.logical_size != payload_input_count ||
                dimensions.payload_size != payload_input_count ||
                dimensions.forward_size != 0) {
                throw std::invalid_argument(
                    "LayeredCircuit: input dimensions disagree with payload");
            }
            continue;
        }

        const std::size_t source_size =
            layer_dimensions(layers[index + 1]).padded_size;
        if (const auto *affine =
                std::get_if<AffineLayer>(&layers[index])) {
            validate_dimensions(affine->dimensions, "affine layer");
            if (affine->gates.size() != affine->dimensions.padded_size) {
                throw std::invalid_argument(
                    "LayeredCircuit: affine gate vector has wrong size");
            }
            validate_origins(affine->dimensions, affine->gates,
                             "affine layer");
            if (shape.kind == PayloadKind::Laned &&
                !affine->intermediate_gates.empty()) {
                throw std::invalid_argument(
                    "LayeredCircuit: Laned layer contains affine intermediates");
            }
            if (affine->intermediate_gates.size() >
                std::numeric_limits<std::size_t>::max() - source_size) {
                throw std::invalid_argument(
                    "LayeredCircuit: affine intermediate domain overflows");
            }
            const auto validate_gate = [&](const AffineGate &gate,
                                            std::size_t available) {
                if (const auto *slots =
                        std::get_if<fhe::SlotVector>(&gate.constant);
                    slots && slots->size() != width) {
                    throw std::invalid_argument(
                        "LayeredCircuit: affine constant has wrong width");
                }
                for (const AffineTerm &term : gate.terms) {
                    if (term.source >= available ||
                        term.rotation >= shape.slot_count) {
                        throw std::invalid_argument(
                            "LayeredCircuit: affine term is out of range");
                    }
                    if (term.plaintext_index &&
                        *term.plaintext_index >= plaintexts.size()) {
                        throw std::invalid_argument(
                            "LayeredCircuit: affine plaintext is out of range");
                    }
                    if (shape.kind == PayloadKind::Laned &&
                        (term.rotation != 0 || term.plaintext_index)) {
                        throw std::invalid_argument(
                            "LayeredCircuit: Laned affine term has a Wide operator");
                    }
                }
            };
            for (std::size_t node = 0;
                 node < affine->intermediate_gates.size(); ++node) {
                const auto &gate = affine->intermediate_gates[node];
                if (gate.origin != GateOrigin::Payload) {
                    throw std::invalid_argument(
                        "LayeredCircuit: affine intermediate is not a payload gate");
                }
                validate_gate(gate, source_size + node);
            }
            for (const AffineGate &gate : affine->gates) {
                validate_gate(gate,
                              source_size + affine->intermediate_gates.size());
            }
        } else {
            const auto &multiplication =
                std::get<MultiplicationLayer>(layers[index]);
            validate_dimensions(multiplication.dimensions,
                                "multiplication layer");
            if (multiplication.gates.size() !=
                multiplication.dimensions.padded_size) {
                throw std::invalid_argument(
                    "LayeredCircuit: multiplication gate vector has wrong size");
            }
            validate_origins(multiplication.dimensions, multiplication.gates,
                             "multiplication layer");
            const auto *source_affine =
                std::get_if<AffineLayer>(&layers[index + 1]);
            if (source_affine == nullptr ||
                multiplication.dimensions.padded_size >
                    std::numeric_limits<std::size_t>::max() / 2U ||
                source_size !=
                    2U * multiplication.dimensions.padded_size ||
                source_affine->dimensions.logical_size % 2 != 0 ||
                source_affine->dimensions.logical_size / 2 !=
                    multiplication.dimensions.logical_size ||
                source_affine->dimensions.payload_size % 2 != 0 ||
                source_affine->dimensions.payload_size / 2 !=
                    multiplication.dimensions.payload_size ||
                source_affine->dimensions.forward_size % 2 != 0 ||
                source_affine->dimensions.forward_size / 2 !=
                    multiplication.dimensions.forward_size) {
                throw std::invalid_argument(
                    "LayeredCircuit: multiplication source does not contain "
                    "two complete logical halves");
            }
            for (std::size_t gate_index = 0;
                 gate_index < multiplication.gates.size(); ++gate_index) {
                const MultiplicationGate &gate =
                    multiplication.gates[gate_index];
                const std::size_t left = gate_index;
                const std::size_t right =
                    multiplication.dimensions.padded_size + gate_index;
                const AffineGate &left_gate = source_affine->gates[left];
                const AffineGate &right_gate = source_affine->gates[right];
                if (left_gate.origin != gate.origin ||
                    right_gate.origin != gate.origin) {
                    throw std::invalid_argument(
                        "LayeredCircuit: dense operand origins disagree with "
                        "their multiplication gate");
                }
                if (gate.origin == GateOrigin::Forward &&
                    !is_uniform_constant(right_gate, Fp::one())) {
                    throw std::invalid_argument(
                        "LayeredCircuit: forwarding multiplier is not one");
                }
                if (gate.origin == GateOrigin::Padding &&
                    (!is_uniform_constant(left_gate, Fp::zero()) ||
                     !is_uniform_constant(right_gate, Fp::zero()))) {
                    throw std::invalid_argument(
                        "LayeredCircuit: padding product is not zero");
                }
            }
        }
    }

    const LayerDimensions &output = layer_dimensions(layers.front());
    if (output.logical_size != payload_output_count ||
        output.payload_size != payload_output_count ||
        output.forward_size != 0) {
        throw std::invalid_argument(
            "LayeredCircuit: output dimensions disagree with payload");
    }
}

} // namespace laminate::payload
