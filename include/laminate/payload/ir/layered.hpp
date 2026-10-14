#ifndef LAMINATE_PAYLOAD_IR_LAYERED_HPP
#define LAMINATE_PAYLOAD_IR_LAYERED_HPP

/// @file layered.hpp
/// @brief Strict alternating circuit representation used by Laminate GKR.

#include "laminate/payload/circuit.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <variant>
#include <vector>

namespace laminate::payload {

enum class GateOrigin : std::uint8_t { Payload, Forward, Padding };

struct LayerDimensions {
    std::size_t logical_size = 0;
    std::size_t padded_size = 0;
    std::size_t payload_size = 0;
    std::size_t forward_size = 0;

    std::size_t padding_size() const { return padded_size - logical_size; }

    bool operator==(const LayerDimensions &other) const = default;
};

struct AffineTerm {
    std::size_t source = 0;
    std::size_t rotation = 0;
    Fp coefficient = Fp::zero();
    /// Optional diagonal multiplier, applied after the source rotation:
    /// coefficient * plaintext[slot] * rotate(source)[slot]. Wide only.
    std::optional<std::size_t> plaintext_index = std::nullopt;

    bool operator==(const AffineTerm &other) const = default;
};

/// A base-field value denotes a uniform constant. A SlotVector denotes an
/// explicitly slot-varying constant.
using AffineConstant = std::variant<Fp, fhe::SlotVector>;

struct AffineGate {
    std::vector<AffineTerm> terms;
    AffineConstant constant = Fp::zero();
    GateOrigin origin = GateOrigin::Padding;
};

struct AffineLayer {
    LayerDimensions dimensions;
    std::vector<AffineGate> gates;
    /// Wide affine programs preserve shared intermediate computations. IDs
    /// below the preceding layer's padded size denote its source wires;
    /// subsequent IDs denote these nodes in topological order. Output gates
    /// may reference any intermediate. Laned layers leave this vector empty.
    std::vector<AffineGate> intermediate_gates = {};
};

struct MultiplicationGate {
    GateOrigin origin = GateOrigin::Padding;
    /// Payload gates are CT-CT products. Structural forwarding and padding
    /// retain dense products by public one and zero, respectively.
};

struct MultiplicationLayer {
    LayerDimensions dimensions;
    std::vector<MultiplicationGate> gates;
};

struct InputLayer {
    LayerDimensions dimensions;
};

using Layer = std::variant<AffineLayer, MultiplicationLayer, InputLayer>;

enum class LayerKind : std::uint8_t { Affine, Multiplication, Input };

LayerKind layer_kind(const Layer &layer);
const LayerDimensions &layer_dimensions(const Layer &layer);

/// Materialize a uniform or explicit affine constant at the logical width.
fhe::SlotVector materialize(const AffineConstant &constant,
                            std::size_t width);

struct LayeredCircuit {
    PayloadShape shape;
    std::size_t payload_input_count = 0;
    std::size_t payload_output_count = 0;
    std::size_t proof_multiplication_depth = 0;
    /// Plaintext table copied from the payload circuit. Wide affine terms
    /// retain nonuniform MulPlain source-table indices. Laned rejects
    /// nonuniform MulPlain. Compiler-created
    /// forwarding and padding constants live directly in affine gates.
    std::vector<fhe::SlotVector> plaintexts;
    /// GKR order: L0 is the output layer and layers.back() is the input layer.
    std::vector<Layer> layers;

    void validate() const;
};

} // namespace laminate::payload

#endif // LAMINATE_PAYLOAD_IR_LAYERED_HPP
