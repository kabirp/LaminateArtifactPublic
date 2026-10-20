#include "laminate/payload/setup/encoding.hpp"

#include "laminate/field/serialization.hpp"

#include <algorithm>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

namespace laminate::payload {
namespace {

using Bytes = std::vector<std::uint8_t>;

void append_u8(Bytes &output, std::uint8_t value) {
    output.push_back(value);
}

void append_u64(Bytes &output, std::size_t value) {
    if (value > std::numeric_limits<std::uint64_t>::max()) {
        throw std::overflow_error("encode_canonical: size does not fit u64");
    }
    const std::uint64_t word = static_cast<std::uint64_t>(value);
    for (std::size_t byte = 0; byte < 8; ++byte) {
        output.push_back(
            static_cast<std::uint8_t>((word >> (8U * byte)) & 0xffU));
    }
}

void append_label(Bytes &output, std::string_view label) {
    append_u64(output, label.size());
    output.insert(output.end(), label.begin(), label.end());
}

void append_fp(Bytes &output, const Fp &value) {
    const SerializedFp encoded = serialize(value);
    output.insert(output.end(), encoded.begin(), encoded.end());
}

void append_slots(Bytes &output, const fhe::SlotVector &slots) {
    append_u64(output, slots.size());
    for (const Fp &slot : slots) {
        append_fp(output, slot);
    }
}

void append_shape(Bytes &output, const PayloadShape &shape) {
    append_u8(output, shape.kind == PayloadKind::Laned ? 0 : 1);
    append_u64(output, shape.slot_count);
    append_u64(output, shape.lane_count);
}

std::uint8_t gate_op_code(GateOp operation) {
    switch (operation) {
    case GateOp::Add:
        return 0;
    case GateOp::AddPlain:
        return 1;
    case GateOp::Mul:
        return 2;
    case GateOp::MulPlain:
        return 3;
    case GateOp::Rotate:
        return 4;
    }
    throw std::invalid_argument("encode_canonical: unknown payload gate");
}

std::uint8_t origin_code(GateOrigin origin) {
    switch (origin) {
    case GateOrigin::Payload:
        return 0;
    case GateOrigin::Forward:
        return 1;
    case GateOrigin::Padding:
        return 2;
    }
    throw std::invalid_argument("encode_canonical: unknown gate origin");
}

void append_dimensions(Bytes &output, const LayerDimensions &dimensions) {
    append_u64(output, dimensions.logical_size);
    append_u64(output, dimensions.padded_size);
    append_u64(output, dimensions.payload_size);
    append_u64(output, dimensions.forward_size);
}

Digest labeled_hash(std::string_view label, const Bytes &first,
                    const Bytes *second = nullptr) {
    Bytes input;
    append_label(input, label);
    append_u64(input, first.size());
    input.insert(input.end(), first.begin(), first.end());
    if (second) {
        append_u64(input, second->size());
        input.insert(input.end(), second->begin(), second->end());
    }
    return sha256(input);
}

bool same_bytes(const Bytes &left,
                std::span<const std::uint8_t> right) {
    return left.size() == right.size() &&
           std::equal(left.begin(), left.end(), right.begin());
}

class CircuitReader {
  public:
    CircuitReader(std::span<const std::uint8_t> input,
                  const CircuitDecodeLimits &limits)
        : input_(input), limits_(limits) {}

    std::uint8_t u8(std::string_view description) {
        require(1, description);
        return input_[position_++];
    }

    std::uint64_t u64(std::string_view description) {
        require(sizeof(std::uint64_t), description);
        std::uint64_t result = 0;
        for (std::size_t byte = 0; byte < sizeof(result); ++byte) {
            result |= static_cast<std::uint64_t>(input_[position_++])
                      << (8U * byte);
        }
        return result;
    }

    std::size_t size(std::size_t maximum,
                     std::string_view description) {
        const std::uint64_t value = u64(description);
        if (value > maximum ||
            value > std::numeric_limits<std::size_t>::max()) {
            throw std::invalid_argument(std::string(description) +
                                        " exceeds its decode limit");
        }
        return static_cast<std::size_t>(value);
    }

    std::span<const std::uint8_t> take(
        std::size_t count, std::string_view description) {
        require(count, description);
        const auto result = input_.subspan(position_, count);
        position_ += count;
        return result;
    }

    std::span<const std::uint8_t> blob(
        std::size_t maximum, std::string_view description) {
        return take(size(maximum, description), description);
    }

    Fp fp(std::string_view description) {
        return deserialize_fp(take(kSerializedFpBytes, description));
    }

    fhe::SlotVector slots(std::string_view description) {
        const std::size_t count = size(limits_.max_slots, description);
        fhe::SlotVector result;
        result.reserve(count);
        for (std::size_t index = 0; index < count; ++index) {
            result.push_back(fp(description));
        }
        return result;
    }

    void add_affine_terms(std::size_t count) {
        if (count > limits_.max_affine_terms ||
            affine_terms_ > limits_.max_affine_terms - count) {
            throw std::invalid_argument(
                "canonical layered affine terms exceed their decode limit");
        }
        affine_terms_ += count;
    }

    void finish() const {
        if (position_ != input_.size()) {
            throw std::invalid_argument(
                "canonical circuit encoding has trailing data");
        }
    }

  private:
    void require(std::size_t count,
                 std::string_view description) const {
        if (position_ > input_.size() ||
            count > input_.size() - position_) {
            throw std::invalid_argument(std::string(description) +
                                        " is truncated");
        }
    }

    std::span<const std::uint8_t> input_;
    const CircuitDecodeLimits &limits_;
    std::size_t position_ = 0;
    std::size_t affine_terms_ = 0;
};

void require_decode_limits(const CircuitDecodeLimits &limits,
                           std::size_t encoded_bytes) {
    if (limits.max_encoded_bytes == 0 ||
        encoded_bytes > limits.max_encoded_bytes ||
        limits.max_slots == 0 || limits.max_payload_inputs == 0 ||
        limits.max_payload_gates == 0 ||
        limits.max_payload_outputs == 0 || limits.max_layers == 0 ||
        limits.max_layer_gates == 0 || limits.max_affine_terms == 0) {
        throw std::invalid_argument(
            "canonical circuit decode limits or byte length are invalid");
    }
}

void require_decode_label(CircuitReader &reader,
                          std::string_view expected,
                          std::string_view description) {
    const auto encoded = reader.blob(128, description);
    const std::string_view actual(
        reinterpret_cast<const char *>(encoded.data()), encoded.size());
    if (actual != expected) {
        throw std::invalid_argument(std::string(description) +
                                    " is unsupported");
    }
}

PayloadShape decode_shape(CircuitReader &reader,
                          const CircuitDecodeLimits &limits) {
    const std::uint8_t kind = reader.u8("payload kind");
    if (kind > 1U) {
        throw std::invalid_argument("unknown canonical payload kind");
    }
    PayloadShape result{
        kind == 0U ? PayloadKind::Laned : PayloadKind::Wide,
        reader.size(limits.max_slots, "slot count"),
        reader.size(limits.max_slots, "lane count")};
    result.validate();
    return result;
}

GateOp decode_gate_op(CircuitReader &reader) {
    switch (reader.u8("payload gate operation")) {
    case 0:
        return GateOp::Add;
    case 1:
        return GateOp::AddPlain;
    case 2:
        return GateOp::Mul;
    case 3:
        return GateOp::MulPlain;
    case 4:
        return GateOp::Rotate;
    default:
        throw std::invalid_argument("unknown canonical payload gate");
    }
}

GateOrigin decode_origin(CircuitReader &reader) {
    switch (reader.u8("layered gate origin")) {
    case 0:
        return GateOrigin::Payload;
    case 1:
        return GateOrigin::Forward;
    case 2:
        return GateOrigin::Padding;
    default:
        throw std::invalid_argument("unknown canonical gate origin");
    }
}

LayerDimensions decode_dimensions(CircuitReader &reader,
                                  std::size_t maximum) {
    return LayerDimensions{
        reader.size(maximum, "logical layer size"),
        reader.size(maximum, "padded layer size"),
        reader.size(maximum, "payload layer size"),
        reader.size(maximum, "forward layer size")};
}

PayloadCircuit decode_payload_impl(
    std::span<const std::uint8_t> encoded,
    const CircuitDecodeLimits &limits) {
    if (limits.max_payload_inputs >
        std::numeric_limits<std::size_t>::max() -
            limits.max_payload_gates) {
        throw std::invalid_argument("canonical payload wire limit overflows");
    }
    const std::size_t max_wires =
        limits.max_payload_inputs + limits.max_payload_gates;
    CircuitReader reader(encoded, limits);
    require_decode_label(reader, "LaminateImpl/PayloadCircuit/v1",
                         "payload encoding label");
    PayloadCircuit result;
    result.shape = decode_shape(reader, limits);
    result.input_count =
        reader.size(limits.max_payload_inputs, "payload input count");
    const std::size_t plaintexts =
        reader.size(limits.max_plaintexts, "payload plaintext count");
    result.plaintexts.reserve(plaintexts);
    for (std::size_t index = 0; index < plaintexts; ++index) {
        result.plaintexts.push_back(reader.slots("payload plaintext"));
    }
    const std::size_t gates =
        reader.size(limits.max_payload_gates, "payload gate count");
    result.gates.reserve(gates);
    for (std::size_t index = 0; index < gates; ++index) {
        result.gates.push_back(Gate{
            decode_gate_op(reader),
            reader.size(max_wires, "payload left wire"),
            reader.size(std::numeric_limits<std::size_t>::max(),
                        "payload right wire"),
            reader.size(std::numeric_limits<std::size_t>::max(),
                        "payload gate parameter")});
    }
    const std::size_t outputs =
        reader.size(limits.max_payload_outputs, "payload output count");
    result.outputs.reserve(outputs);
    for (std::size_t index = 0; index < outputs; ++index) {
        result.outputs.push_back(
            reader.size(max_wires, "payload output wire"));
    }
    reader.finish();
    result.validate();
    return result;
}

LayeredCircuit decode_layered_impl(
    std::span<const std::uint8_t> encoded,
    const CircuitDecodeLimits &limits) {
    CircuitReader reader(encoded, limits);
    require_decode_label(reader, "LaminateImpl/LayeredCircuit/v5",
                         "layered encoding label");
    LayeredCircuit result;
    result.shape = decode_shape(reader, limits);
    result.payload_input_count =
        reader.size(limits.max_payload_inputs, "layered input count");
    result.payload_output_count =
        reader.size(limits.max_payload_outputs, "layered output count");
    result.proof_multiplication_depth =
        reader.size(limits.max_layers, "layered multiplication depth");
    const std::size_t plaintexts =
        reader.size(limits.max_plaintexts, "layered plaintext count");
    result.plaintexts.reserve(plaintexts);
    for (std::size_t index = 0; index < plaintexts; ++index) {
        result.plaintexts.push_back(reader.slots("layered plaintext"));
    }
    const std::size_t layers =
        reader.size(limits.max_layers, "layer count");
    result.layers.reserve(layers);
    for (std::size_t layer = 0; layer < layers; ++layer) {
        const std::uint8_t kind = reader.u8("layer kind");
        const LayerDimensions dimensions =
            decode_dimensions(reader, limits.max_layer_gates);
        if (kind == static_cast<std::uint8_t>(LayerKind::Affine)) {
            AffineLayer affine;
            affine.dimensions = dimensions;
            const auto read_gates = [&](std::vector<AffineGate> &destination) {
                const std::size_t gates = reader.size(
                    limits.max_layer_gates, "affine gate count");
                destination.reserve(gates);
                for (std::size_t gate = 0; gate < gates; ++gate) {
                    AffineGate decoded;
                    decoded.origin = decode_origin(reader);
                    const std::size_t terms = reader.size(
                        limits.max_affine_terms, "affine term count");
                    reader.add_affine_terms(terms);
                    decoded.terms.reserve(terms);
                    for (std::size_t term = 0; term < terms; ++term) {
                        AffineTerm value{
                            reader.size(limits.max_layer_gates,
                                        "affine source"),
                            reader.size(limits.max_slots, "affine rotation"),
                            reader.fp("affine coefficient")};
                        const auto present = reader.u8("affine plaintext presence");
                        if (present > 1U) {
                            throw std::invalid_argument(
                                "noncanonical affine plaintext flag");
                        }
                        if (present != 0U) {
                            value.plaintext_index = reader.size(
                                limits.max_plaintexts, "affine plaintext index");
                        }
                        decoded.terms.push_back(std::move(value));
                    }
                    const std::uint8_t constant = reader.u8("affine constant kind");
                    if (constant == 0U) {
                        decoded.constant = reader.fp("affine scalar constant");
                    } else if (constant == 1U) {
                        decoded.constant = reader.slots("affine slot constant");
                    } else {
                        throw std::invalid_argument(
                            "unknown canonical affine constant kind");
                    }
                    destination.push_back(std::move(decoded));
                }
            };
            read_gates(affine.intermediate_gates);
            read_gates(affine.gates);
            result.layers.emplace_back(std::move(affine));
        } else if (kind ==
                   static_cast<std::uint8_t>(LayerKind::Multiplication)) {
            MultiplicationLayer multiplication;
            multiplication.dimensions = dimensions;
            const std::size_t gates = reader.size(
                limits.max_layer_gates, "multiplication gate count");
            multiplication.gates.reserve(gates);
            for (std::size_t gate = 0; gate < gates; ++gate) {
                multiplication.gates.push_back(
                    MultiplicationGate{decode_origin(reader)});
            }
            result.layers.emplace_back(std::move(multiplication));
        } else if (kind == static_cast<std::uint8_t>(LayerKind::Input)) {
            result.layers.emplace_back(InputLayer{dimensions});
        } else {
            throw std::invalid_argument("unknown canonical layer kind");
        }
    }
    reader.finish();
    result.validate();
    return result;
}

} // namespace

std::vector<std::uint8_t> encode_canonical(const PayloadCircuit &circuit) {
    circuit.validate();
    Bytes output;
    append_label(output, "LaminateImpl/PayloadCircuit/v1");
    append_shape(output, circuit.shape);
    append_u64(output, circuit.input_count);
    append_u64(output, circuit.plaintexts.size());
    for (const fhe::SlotVector &plaintext : circuit.plaintexts) {
        append_slots(output, plaintext);
    }
    append_u64(output, circuit.gates.size());
    for (const Gate &gate : circuit.gates) {
        append_u8(output, gate_op_code(gate.op));
        append_u64(output, gate.left);
        append_u64(output, gate.right);
        append_u64(output, gate.parameter);
    }
    append_u64(output, circuit.outputs.size());
    for (WireId output_wire : circuit.outputs) {
        append_u64(output, output_wire);
    }
    return output;
}

std::vector<std::uint8_t> encode_canonical(const LayeredCircuit &circuit) {
    circuit.validate();
    Bytes output;
    append_label(output, "LaminateImpl/LayeredCircuit/v5");
    append_shape(output, circuit.shape);
    append_u64(output, circuit.payload_input_count);
    append_u64(output, circuit.payload_output_count);
    append_u64(output, circuit.proof_multiplication_depth);
    append_u64(output, circuit.plaintexts.size());
    for (const fhe::SlotVector &plaintext : circuit.plaintexts) {
        append_slots(output, plaintext);
    }
    append_u64(output, circuit.layers.size());
    for (const Layer &layer : circuit.layers) {
        append_u8(output, static_cast<std::uint8_t>(layer_kind(layer)));
        append_dimensions(output, layer_dimensions(layer));
        if (const auto *affine = std::get_if<AffineLayer>(&layer)) {
            const auto append_gates = [&](const std::vector<AffineGate> &gates) {
                append_u64(output, gates.size());
                for (const AffineGate &gate : gates) {
                    append_u8(output, origin_code(gate.origin));
                    append_u64(output, gate.terms.size());
                    for (const AffineTerm &term : gate.terms) {
                        append_u64(output, term.source);
                        append_u64(output, term.rotation);
                        append_fp(output, term.coefficient);
                        append_u8(output, term.plaintext_index ? 1 : 0);
                        if (term.plaintext_index) {
                            append_u64(output, *term.plaintext_index);
                        }
                    }
                    append_u8(output,
                              std::holds_alternative<Fp>(gate.constant) ? 0 : 1);
                    if (const auto *scalar = std::get_if<Fp>(&gate.constant)) {
                        append_fp(output, *scalar);
                    } else {
                        append_slots(output,
                                     std::get<fhe::SlotVector>(gate.constant));
                    }
                }
            };
            append_gates(affine->intermediate_gates);
            append_gates(affine->gates);
        } else if (const auto *multiplication =
                       std::get_if<MultiplicationLayer>(&layer)) {
            append_u64(output, multiplication->gates.size());
            for (const MultiplicationGate &gate : multiplication->gates) {
                append_u8(output, origin_code(gate.origin));
            }
        }
    }
    return output;
}

PayloadCircuit decode_canonical_payload(
    std::span<const std::uint8_t> encoded,
    const CircuitDecodeLimits &limits) {
    require_decode_limits(limits, encoded.size());
    PayloadCircuit result = decode_payload_impl(encoded, limits);
    if (!same_bytes(encode_canonical(result), encoded)) {
        throw std::invalid_argument(
            "payload circuit does not use its canonical encoding");
    }
    return result;
}

LayeredCircuit decode_canonical_layered(
    std::span<const std::uint8_t> encoded,
    const CircuitDecodeLimits &limits) {
    require_decode_limits(limits, encoded.size());
    LayeredCircuit result = decode_layered_impl(encoded, limits);
    if (!same_bytes(encode_canonical(result), encoded)) {
        throw std::invalid_argument(
            "layered circuit does not use its canonical encoding");
    }
    return result;
}

Digest digest(const PayloadCircuit &circuit) {
    const Bytes encoded = encode_canonical(circuit);
    return labeled_hash("LaminateImpl/PayloadDigest/v1", encoded);
}

Digest digest(const LayeredCircuit &circuit) {
    const Bytes encoded = encode_canonical(circuit);
    return labeled_hash("LaminateImpl/LayeredDigest/v1", encoded);
}

Digest combined_digest(const PayloadCircuit &payload,
                       const LayeredCircuit &layered) {
    const Bytes encoded_payload = encode_canonical(payload);
    const Bytes encoded_layered = encode_canonical(layered);
    return labeled_hash("LaminateImpl/CircuitPairDigest/v1", encoded_payload,
                        &encoded_layered);
}

CircuitPairDigests circuit_pair_digests(const PayloadCircuit &payload,
                                        const LayeredCircuit &layered) {
    const Bytes encoded_payload = encode_canonical(payload);
    const Bytes encoded_layered = encode_canonical(layered);
    return CircuitPairDigests{
        .payload = labeled_hash("LaminateImpl/PayloadDigest/v1",
                                encoded_payload),
        .layered = labeled_hash("LaminateImpl/LayeredDigest/v1",
                                encoded_layered),
        .combined = labeled_hash("LaminateImpl/CircuitPairDigest/v1",
                                 encoded_payload, &encoded_layered),
    };
}

} // namespace laminate::payload
