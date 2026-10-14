/// @file base_client.cpp
/// @brief Authenticated persistence for immutable Base client metadata.

#include "laminate/protocol/setup/base_client.hpp"

#include "laminate/field/serialization.hpp"
#include "laminate/payload/setup/encoding.hpp"

#include "../codec/bounded_binary.hpp"

#include <algorithm>
#include <array>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <variant>

namespace laminate::protocol {
namespace {

using Bytes = codec::Bytes;

constexpr std::array<std::uint8_t, 8> kMagic{
    'L', 'M', 'B', 'C', 'S', 'T', '0', '1'};
constexpr std::uint8_t kVersion = 1;

class Writer final : public codec::Writer {
  public:
    void size(std::size_t value) {
        codec::Writer::size(value, "Base client static setup size");
    }

    void digest(const Digest &value) { raw(value); }

    void fp(const Fp &value) {
        const SerializedFp encoded = serialize(value);
        raw(encoded);
    }

    void blob(std::span<const std::uint8_t> value) {
        size(value.size());
        raw(value);
    }

    void slots(const fhe::SlotVector &values) {
        size(values.size());
        for (const Fp &value : values) {
            fp(value);
        }
    }
};

class Reader final : public codec::Reader {
  public:
    Reader(std::span<const std::uint8_t> input,
           const BaseClientStaticSetupDecodeLimits &limits)
        : codec::Reader(input), limits_(limits) {}

    std::span<const std::uint8_t> bytes(
        std::size_t count, std::string_view description) {
        return take(count, description);
    }

    std::span<const std::uint8_t> blob(
        std::size_t maximum, std::string_view description) {
        return bytes(size(maximum, description), description);
    }

    Digest digest(std::string_view description) {
        Digest result{};
        const auto encoded = bytes(result.size(), description);
        std::copy(encoded.begin(), encoded.end(), result.begin());
        return result;
    }

    Fp fp(std::string_view description) {
        return deserialize_fp(bytes(kSerializedFpBytes, description));
    }

    fhe::SlotVector slots(std::size_t maximum,
                          std::string_view description) {
        const std::size_t count = size(maximum, description);
        fhe::SlotVector result;
        result.reserve(count);
        for (std::size_t index = 0; index < count; ++index) {
            result.push_back(fp(description));
        }
        return result;
    }

    void add_storage_entries(std::size_t count) {
        add_total(storage_entries_, count, limits_.max_storage_entries,
                  "Base client static storage entries");
    }

    void finish() const {
        codec::Reader::finish(
            "Base client static setup has trailing data");
    }

  private:
    static void add_total(std::size_t &total, std::size_t count,
                          std::size_t maximum,
                          std::string_view description) {
        if (count > maximum || total > maximum - count) {
            throw std::invalid_argument(std::string(description) +
                                        " exceed their decode limit");
        }
        total += count;
    }

    const BaseClientStaticSetupDecodeLimits &limits_;
    std::size_t storage_entries_ = 0;
};

payload::CircuitDecodeLimits circuit_decode_limits(
    const BaseClientStaticSetupDecodeLimits &limits) {
    return payload::CircuitDecodeLimits{
        .max_encoded_bytes = limits.max_artifact_bytes,
        .max_slots = limits.max_slots,
        .max_plaintexts = limits.max_payload_plaintexts,
        .max_payload_inputs = limits.max_layer_gates,
        .max_payload_gates = limits.max_payload_gates,
        .max_payload_outputs = limits.max_payload_outputs,
        .max_layers = limits.max_layers,
        .max_layer_gates = limits.max_layer_gates,
        .max_affine_terms = limits.max_affine_terms,
    };
}
void encode_support(Writer &writer,
                    const payload::LayerWireSupport &support) {
    writer.size(support.padded_wire_count);
    writer.size(support.live_wire_count);
    writer.size(support.live_ranges.size());
    for (const payload::LiveWireRange &range : support.live_ranges) {
        writer.size(range.padded_begin);
        writer.size(range.wire_count);
    }
}

payload::LayerWireSupport decode_support(
    Reader &reader, const BaseClientStaticSetupDecodeLimits &limits) {
    payload::LayerWireSupport result;
    result.padded_wire_count =
        reader.size(limits.max_layer_gates, "support padded wires");
    result.live_wire_count =
        reader.size(limits.max_layer_gates, "support live wires");
    const std::size_t ranges = reader.size(
        limits.max_layer_gates, "support range count");
    result.live_ranges.reserve(ranges);
    for (std::size_t range = 0; range < ranges; ++range) {
        result.live_ranges.push_back(payload::LiveWireRange{
            reader.size(limits.max_layer_gates, "support range begin"),
            reader.size(limits.max_layer_gates, "support range size")});
    }
    payload::validate_layer_wire_support(result);
    return result;
}

void encode_storage(Writer &writer,
                    const payload::LayerStorageLayout &storage) {
    writer.size(storage.padded_wire_count);
    writer.size(storage.stored_wire_count);
    writer.size(storage.padded_to_stored.size());
    for (const std::optional<std::size_t> &ordinal :
         storage.padded_to_stored) {
        writer.u8(ordinal.has_value() ? 1U : 0U);
        if (ordinal) {
            writer.size(*ordinal);
        }
    }
    writer.size(storage.representative_padded_indices.size());
    for (std::size_t representative :
         storage.representative_padded_indices) {
        writer.size(representative);
    }
}

payload::LayerStorageLayout decode_storage(
    Reader &reader, const BaseClientStaticSetupDecodeLimits &limits) {
    payload::LayerStorageLayout result;
    result.padded_wire_count =
        reader.size(limits.max_layer_gates, "storage padded wires");
    result.stored_wire_count =
        reader.size(limits.max_layer_gates, "stored wire count");
    const std::size_t mappings = reader.size(
        limits.max_layer_gates, "storage mapping count");
    reader.add_storage_entries(mappings);
    result.padded_to_stored.reserve(mappings);
    for (std::size_t mapping = 0; mapping < mappings; ++mapping) {
        const std::uint8_t present =
            reader.u8("stored ordinal presence");
        if (present > 1U) {
            throw std::invalid_argument(
                "Base client static setup has a noncanonical stored "
                "ordinal flag");
        }
        result.padded_to_stored.push_back(
            present == 0U
                ? std::nullopt
                : std::optional<std::size_t>(reader.size(
                      limits.max_layer_gates, "stored ordinal")));
    }
    const std::size_t representatives = reader.size(
        limits.max_layer_gates, "storage representative count");
    result.representative_padded_indices.reserve(representatives);
    for (std::size_t index = 0; index < representatives; ++index) {
        result.representative_padded_indices.push_back(reader.size(
            limits.max_layer_gates, "storage representative"));
    }
    payload::validate_layer_storage_layout(result);
    return result;
}

void encode_public_plaintext(Writer &writer,
                             const fhe::PublicPlaintext &plaintext) {
    writer.u8(plaintext.is_scalar() ? 0U : 1U);
    if (plaintext.is_scalar()) {
        writer.fp(plaintext.scalar());
    } else {
        writer.slots(plaintext.slots());
    }
}

payload::ClassifiedTraceValue decode_classification(
    Reader &reader, const BaseClientStaticSetupDecodeLimits &limits) {
    const std::uint8_t present =
        reader.u8("trace classification presence");
    if (present == 0U) {
        return std::nullopt;
    }
    if (present != 1U) {
        throw std::invalid_argument(
            "Base client static setup has a noncanonical classification "
            "flag");
    }
    const std::uint8_t kind =
        reader.u8("public plaintext classification kind");
    if (kind == 0U) {
        return fhe::PublicPlaintext::from_scalar(
            reader.fp("public scalar classification"));
    }
    if (kind == 1U) {
        return fhe::PublicPlaintext::from_slots(
            reader.slots(limits.max_slots,
                         "public slot classification"));
    }
    throw std::invalid_argument(
        "Base client static setup has an unknown public classification");
}

void validate_layout_consistency(
    const payload::LayeredCircuit &circuit,
    const payload::CanonicalTraceLayout &layout) {
    const std::size_t layers = circuit.layers.size();
    if (layout.wire_support.size() != layers ||
        layout.storage.size() != layers ||
        layout.stored_value_classifications.size() != layers ||
        layout.value_counts.size() != layers) {
        throw std::invalid_argument(
            "Base client static layout has the wrong layer count");
    }
    for (std::size_t layer = 0; layer < layers; ++layer) {
        const payload::LayerDimensions &dimensions =
            payload::layer_dimensions(circuit.layers[layer]);
        const payload::LayerWireSupport &support =
            layout.wire_support[layer];
        const payload::LayerStorageLayout &storage =
            layout.storage[layer];
        const auto &classifications =
            layout.stored_value_classifications[layer];
        const payload::LayerTraceValueCounts &counts =
            layout.value_counts[layer];
        if (support.padded_wire_count != dimensions.padded_size ||
            storage.padded_wire_count != dimensions.padded_size ||
            classifications.size() != storage.stored_wire_count) {
            throw std::invalid_argument(
                "Base client static layout disagrees with layer geometry");
        }
        std::size_t encrypted = 0;
        for (const payload::ClassifiedTraceValue &classification :
             classifications) {
            if (!classification) {
                ++encrypted;
            } else {
                classification->validate_slot_count(
                    circuit.shape.slot_count,
                    "Base client static classification");
            }
        }
        for (std::size_t padded = 0;
             padded < dimensions.padded_size; ++padded) {
            if (support.is_live(padded) !=
                storage.stored_ordinal_of(padded).has_value()) {
                throw std::invalid_argument(
                    "Base client static support and storage disagree");
            }
        }
        if (counts.virtual_wire_positions != dimensions.padded_size ||
            counts.logical_live_wires != support.live_wire_count ||
            counts.stored_values != storage.stored_wire_count ||
            counts.encrypted_ciphertexts != encrypted) {
            throw std::invalid_argument(
                "Base client static value counts disagree with layout");
        }
    }
}

} // namespace

namespace base_client_static_setup_detail {

std::vector<std::uint8_t> encode(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const payload::CanonicalTraceLayout &layout,
    const Digest &setup_id, const Digest &circuit_id) {
    validate_layout_consistency(circuit, layout);
    Writer writer;
    for (std::uint8_t byte : kMagic) {
        writer.u8(byte);
    }
    writer.u8(kVersion);
    writer.u8(0);
    writer.digest(setup_id);
    writer.digest(circuit_id);
    const Bytes payload_bytes = payload::encode_canonical(payload);
    const Bytes circuit_bytes = payload::encode_canonical(circuit);
    writer.blob(payload_bytes);
    writer.blob(circuit_bytes);

    writer.size(layout.wire_support.size());
    for (const payload::LayerWireSupport &support : layout.wire_support) {
        encode_support(writer, support);
    }
    writer.size(layout.storage.size());
    for (const payload::LayerStorageLayout &storage : layout.storage) {
        encode_storage(writer, storage);
    }
    writer.size(layout.stored_value_classifications.size());
    for (const auto &layer : layout.stored_value_classifications) {
        writer.size(layer.size());
        for (const payload::ClassifiedTraceValue &classification : layer) {
            writer.u8(classification.has_value() ? 1U : 0U);
            if (classification) {
                encode_public_plaintext(writer, *classification);
            }
        }
    }
    writer.size(layout.value_counts.size());
    for (const payload::LayerTraceValueCounts &counts :
         layout.value_counts) {
        writer.size(counts.virtual_wire_positions);
        writer.size(counts.logical_live_wires);
        writer.size(counts.stored_values);
        writer.size(counts.encrypted_ciphertexts);
    }
    return std::move(writer).finish();
}

} // namespace base_client_static_setup_detail

AuthenticatedBaseClientStaticSetup
decode_authenticated_base_client_static_setup(
    std::span<const std::uint8_t> encoded,
    const Digest &expected_artifact_digest,
    const Digest &expected_setup_id,
    const Digest &expected_circuit_id,
    const BaseClientStaticSetupDecodeLimits &limits) {
    if (limits.max_artifact_bytes == 0 ||
        encoded.size() > limits.max_artifact_bytes ||
        limits.max_slots == 0 || limits.max_payload_gates == 0 ||
        limits.max_layers == 0 || limits.max_layer_gates == 0 ||
        limits.max_affine_terms == 0 ||
        limits.max_storage_entries == 0) {
        throw std::invalid_argument(
            "Base client static setup decode limits are invalid");
    }
    if (sha256(encoded) != expected_artifact_digest) {
        throw std::invalid_argument(
            "Base client static setup differs from its authenticated "
            "digest");
    }

    Reader reader(encoded, limits);
    if (!std::equal(kMagic.begin(), kMagic.end(),
                    reader.bytes(kMagic.size(), "static setup magic")
                        .begin()) ||
        reader.u8("static setup version") != kVersion ||
        reader.u8("static setup flags") != 0U) {
        throw std::invalid_argument(
            "Base client static setup has an unsupported format");
    }
    const Digest setup_id = reader.digest("static setup identifier");
    const Digest circuit_id = reader.digest("static circuit identifier");
    if (setup_id != expected_setup_id ||
        circuit_id != expected_circuit_id) {
        throw std::invalid_argument(
            "Base client static setup has the wrong public binding");
    }

    const payload::CircuitDecodeLimits circuit_limits =
        circuit_decode_limits(limits);
    payload::PayloadCircuit payload = payload::decode_canonical_payload(
        reader.blob(limits.max_artifact_bytes, "payload bytes"),
        circuit_limits);
    payload::LayeredCircuit circuit = payload::decode_canonical_layered(
        reader.blob(limits.max_artifact_bytes, "layered bytes"),
        circuit_limits);
    const std::size_t support_layers =
        reader.size(limits.max_layers, "support layer count");
    payload::CanonicalTraceLayout layout;
    layout.wire_support.reserve(support_layers);
    for (std::size_t layer = 0; layer < support_layers; ++layer) {
        layout.wire_support.push_back(decode_support(reader, limits));
    }
    const std::size_t storage_layers =
        reader.size(limits.max_layers, "storage layer count");
    layout.storage.reserve(storage_layers);
    for (std::size_t layer = 0; layer < storage_layers; ++layer) {
        layout.storage.push_back(decode_storage(reader, limits));
    }
    const std::size_t classification_layers =
        reader.size(limits.max_layers, "classification layer count");
    layout.stored_value_classifications.reserve(classification_layers);
    for (std::size_t layer = 0; layer < classification_layers; ++layer) {
        const std::size_t values = reader.size(
            limits.max_layer_gates, "classification count");
        reader.add_storage_entries(values);
        std::vector<payload::ClassifiedTraceValue> classifications;
        classifications.reserve(values);
        for (std::size_t value = 0; value < values; ++value) {
            classifications.push_back(
                decode_classification(reader, limits));
        }
        layout.stored_value_classifications.push_back(
            std::move(classifications));
    }
    const std::size_t count_layers =
        reader.size(limits.max_layers, "value-count layer count");
    layout.value_counts.reserve(count_layers);
    for (std::size_t layer = 0; layer < count_layers; ++layer) {
        layout.value_counts.push_back(payload::LayerTraceValueCounts{
            reader.size(limits.max_layer_gates,
                        "virtual wire positions"),
            reader.size(limits.max_layer_gates, "logical live wires"),
            reader.size(limits.max_layer_gates, "stored values"),
            reader.size(limits.max_layer_gates,
                        "encrypted ciphertexts")});
    }
    reader.finish();

    if (payload.shape.kind != payload::PayloadKind::Wide ||
        circuit.shape.kind != payload::PayloadKind::Wide ||
        !(payload.shape == circuit.shape) ||
        payload.input_count != circuit.payload_input_count ||
        payload.outputs.size() != circuit.payload_output_count ||
        circuit.layers.empty()) {
        throw std::invalid_argument(
            "Base client static setup has inconsistent circuit metadata");
    }
    validate_layout_consistency(circuit, layout);
    const payload::LayerDimensions output_dimensions =
        payload::layer_dimensions(circuit.layers.front());
    return AuthenticatedBaseClientStaticSetup(
        std::move(payload), std::move(circuit), std::move(layout), setup_id,
        circuit_id, output_dimensions);
}

} // namespace laminate::protocol
