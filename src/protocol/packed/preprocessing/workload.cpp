/// @file workload.cpp
/// @brief Canonical authenticated workload-static packed preprocessing.

#include "laminate/protocol/packed/preprocessing/workload.hpp"

#include "laminate/field/serialization.hpp"
#include "laminate/gates/canonical_tables.hpp"
#include "laminate/gates/outsourced.hpp"
#include "laminate/payload/setup/encoding.hpp"
#include "laminate/setup/gate_mle.hpp"

#include "../../codec/bounded_binary.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <limits>
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
    'L', 'M', 'P', 'W', 'S', 'T', '0', '1'};
constexpr std::string_view kSemanticDomain =
    "LaminateImpl/PackedWorkloadStaticSemantic/v1";
constexpr std::string_view kChecksumDomain =
    "LaminateImpl/PackedWorkloadStaticChecksum/v1";

std::span<const std::uint8_t> bytes(std::string_view value) {
    return {reinterpret_cast<const std::uint8_t *>(value.data()),
            value.size()};
}

Digest domain_hash(std::string_view domain,
                   std::span<const std::uint8_t> input) {
    Sha256Hasher hasher;
    hasher.update(bytes(domain));
    hasher.update(input);
    return hasher.finish();
}

bool same_bytes(const Bytes &left,
                std::span<const std::uint8_t> right) {
    return left.size() == right.size() &&
           std::equal(left.begin(), left.end(), right.begin());
}

template <typename Array> bool all_zero(const Array &value) {
    return std::all_of(value.begin(), value.end(),
                       [](std::uint8_t byte) { return byte == 0; });
}

class Writer final : public codec::Writer {
  public:
    void size(std::size_t value) {
        codec::Writer::size(value, "packed workload size");
    }

    void digest(const Digest &value) { raw(value); }

    void blob(std::span<const std::uint8_t> value) {
        size(value.size());
        raw(value);
    }

    void fp(const Fp &value) {
        const SerializedFp encoded = serialize(value);
        raw(encoded);
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
           const PackedWorkloadStaticDecodeLimits &limits)
        : codec::Reader(input), limits_(limits) {}

    std::span<const std::uint8_t> blob(
        std::size_t maximum, std::string_view description) {
        return take(size(maximum, description), description);
    }

    Digest digest(std::string_view description) {
        Digest result{};
        const auto encoded = take(result.size(), description);
        std::copy(encoded.begin(), encoded.end(), result.begin());
        return result;
    }

    basefold::Digest basefold_digest(std::string_view description) {
        basefold::Digest result{};
        const auto encoded = take(result.size(), description);
        std::copy(encoded.begin(), encoded.end(), result.begin());
        return result;
    }

    Fp fp(std::string_view description) {
        return deserialize_fp(take(kSerializedFpBytes, description));
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
        add_total(storage_entries_, count,
                  limits_.max_storage_entries,
                  "packed workload storage entries");
    }

    void finish() const {
        codec::Reader::finish(
            "packed workload artifact has trailing data");
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

    const PackedWorkloadStaticDecodeLimits &limits_;
    std::size_t storage_entries_ = 0;
};

void require_label(Reader &reader, std::string_view expected,
                   std::string_view description) {
    const auto encoded = reader.blob(128, description);
    const std::string_view actual(
        reinterpret_cast<const char *>(encoded.data()), encoded.size());
    if (actual != expected) {
        throw std::invalid_argument(std::string(description) +
                                    " is unsupported");
    }
}

payload::LayerDimensions read_dimensions(
    Reader &reader, std::size_t maximum) {
    return payload::LayerDimensions{
        reader.size(maximum, "logical layer size"),
        reader.size(maximum, "padded layer size"),
        reader.size(maximum, "payload layer size"),
        reader.size(maximum, "forward layer size")};
}

payload::PayloadShape read_public_shape(
    Reader &reader, const PackedWorkloadStaticDecodeLimits &limits) {
    const std::uint8_t kind = reader.u8("public-setup payload kind");
    if (kind > 1U) {
        throw std::invalid_argument("unknown public-setup payload kind");
    }
    payload::PayloadShape result{
        kind == 0U ? payload::PayloadKind::Laned
                   : payload::PayloadKind::Wide,
        reader.size(limits.max_slots, "public-setup slot count"),
        reader.size(limits.max_slots, "public-setup lane count")};
    result.validate();
    return result;
}

payload::CircuitDecodeLimits circuit_decode_limits(
    const PackedWorkloadStaticDecodeLimits &limits) {
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
gates::GateTableLayout decode_gate_layout(
    std::span<const std::uint8_t> encoded,
    const PackedWorkloadStaticDecodeLimits &limits) {
    Reader reader(encoded, limits);
    require_label(reader, "LaminateImpl/GateTableLayout/v4",
                  "gate-table layout label");
    gates::GateTableLayout result;
    const std::uint8_t set = reader.u8("gate-table set");
    if (set > 1U) {
        throw std::invalid_argument("unknown gate-table set");
    }
    result.table_set = static_cast<gates::GateTableSet>(set);
    const std::size_t max_variables =
        std::numeric_limits<std::size_t>::digits - 1U;
    const std::size_t tables =
        reader.size(limits.max_gate_tables, "gate-table count");
    result.tables.reserve(tables);
    for (std::size_t index = 0; index < tables; ++index) {
        gates::GateTableDescriptor table;
        table.layer_index =
            reader.size(limits.max_layers, "gate-table layer");
        const std::uint8_t kind = reader.u8("gate-table kind");
        if (kind > static_cast<std::uint8_t>(
                       gates::GateTableKind::WideMaskDictionary)) {
            throw std::invalid_argument("unknown gate-table kind");
        }
        table.kind = static_cast<gates::GateTableKind>(kind);
        table.selector =
            reader.size(limits.max_gate_tables, "gate-table selector");
        table.local_variables =
            reader.size(max_variables, "gate-table local variables");
        table.support_size =
            reader.size(limits.max_storage_entries,
                        "gate-table sparse support");
        if (table.selector != index) {
            throw std::invalid_argument(
                "noncanonical gate-table selector order");
        }
        result.tables.push_back(table);
    }
    const auto layers = reader.size(limits.max_layers, "Wide layer count");
    result.wide_layers.reserve(layers);
    for (std::size_t i = 0; i < layers; ++i) {
        gates::WideLayerMetadata layer;
        layer.layer_index = reader.size(limits.max_layers, "Wide layer index");
        layer.node_count = reader.size(limits.max_affine_terms, "Wide node count");
        auto &d = layer.dimensions;
        for (auto *value : {&d.slots, &d.input_width, &d.output_width,
             &d.internal_width, &d.row_width, &d.source_width, &d.mask_width,
             &d.internal_scalars, &d.uniform_edge_domain, &d.mask_edge_domain,
             &d.uniform_constant_domain, &d.slot_constant_domain,
             &d.dictionary_domain}) {
            *value = reader.size(std::numeric_limits<std::size_t>::max(),
                                 "Wide Boolean domain");
            if (!std::has_single_bit(*value))
                throw std::invalid_argument("invalid Wide Boolean domain");
        }
        if (d.slots > limits.max_slots || layer.node_count > d.internal_width)
            throw std::invalid_argument("Wide layer dimensions exceed limits");
        layer.program_digest = reader.digest("Wide program digest");
        result.wide_layers.push_back(layer);
    }
    result.wide_masks.slots = reader.size(limits.max_slots, "Wide mask slots");
    result.wide_masks.mask_count = reader.size(limits.max_payload_plaintexts,
                                               "Wide mask count");
    result.wide_masks.mask_width = reader.size(limits.max_storage_entries,
                                               "Wide mask domain");
    result.wide_masks.dictionary_digest = reader.digest("Wide dictionary digest");
    if (result.table_set == gates::GateTableSet::Laned &&
        (!result.wide_layers.empty() || result.wide_masks != gates::WideMaskMetadata{}))
        throw std::invalid_argument("Laned layout carries Wide program metadata");
    reader.finish();
    for (const auto &table : result.tables) {
        const bool compatible_kind =
            table.kind == gates::GateTableKind::AffineConstantUniform ||
            table.kind == gates::GateTableKind::AffineConstantSlot ||
            (result.table_set == gates::GateTableSet::Wide &&
             (table.kind == gates::GateTableKind::WideLocalUniformEdges ||
              table.kind == gates::GateTableKind::WideLocalMaskEdges ||
              table.kind == gates::GateTableKind::WideMaskDictionary)) ||
            (result.table_set == gates::GateTableSet::Laned &&
             table.kind == gates::GateTableKind::LanedAffineWire);
        if (!compatible_kind || table.support_size == 0) {
            throw std::invalid_argument(
                "gate-table kind disagrees with its table set");
        }
    }
    if (!same_bytes(gates::encode_canonical(result), encoded)) {
        throw std::invalid_argument("noncanonical gate-table layout");
    }
    return result;
}

gates::GateTableVerifierKey decode_gate_key(
    std::span<const std::uint8_t> encoded,
    const PackedWorkloadStaticDecodeLimits &limits) {
    Reader reader(encoded, limits);
    require_label(reader, "LaminateImpl/GateTableVerifierKey/v5",
                  "gate-table verifier-key label");
    gates::GateTableVerifierKey result;
    result.layout = decode_gate_layout(
        reader.blob(limits.max_artifact_bytes, "gate-table layout"),
        limits);
    result.basefold_parameters.log_rate = reader.size(
        std::numeric_limits<std::size_t>::digits - 1U,
        "BaseFold log rate");
    result.basefold_parameters.num_queries = reader.size(
        limits.max_storage_entries, "BaseFold query count");
    result.foldable_parameters.num_queries = reader.size(
        limits.max_storage_entries, "foldable query count");
    result.layout_digest = reader.digest("gate-table layout digest");
    const std::size_t table_count = reader.size(
        limits.max_gate_tables, "sparse gate commitment count");
    result.tables.reserve(table_count);
    for (std::size_t table = 0; table < table_count; ++table) {
        gates::SparseTableCommitment commitment;
        commitment.message_size = reader.size(
            limits.max_storage_entries, "sparse gate message size");
        commitment.shard_size = reader.size(
            limits.max_storage_entries, "sparse gate shard size");
        commitment.shard_count = reader.size(
            limits.max_storage_entries, "sparse gate shard count");
        commitment.logical_width = reader.size(
            limits.max_storage_entries, "sparse gate logical width");
        commitment.physical_width = reader.size(
            limits.max_storage_entries, "sparse gate physical width");
        commitment.root = reader.basefold_digest("sparse gate-table root");
        // The canonical schema reserves this per-table field. Validation
        // below requires it to be empty; Wide binds one shared public index.
        const auto generic = reader.u8("foldable commitment presence");
        if (generic > 1) throw std::invalid_argument("invalid foldable presence");
        if (generic) {
            basefold::foldable::Metadata metadata;
            metadata.root = commitment.root;
            metadata.m = reader.size(std::size_t{1} << basefold::foldable::kMaxVariables,
                                      "foldable message length");
            metadata.width = reader.size(256, "foldable width");
            metadata.hierarchy_version = reader.u64("foldable hierarchy version");
            commitment.foldable = metadata;
        }
        const auto block = reader.u8("Wide block offset presence");
        if (block > 1) throw std::invalid_argument("invalid Wide block presence");
        if (block) commitment.wide_block_offset = reader.size(
            limits.max_storage_entries, "Wide block offset");
        result.tables.push_back(std::move(commitment));
    }
    const auto shared = reader.u8("Wide public commitment presence");
    if (shared > 1) throw std::invalid_argument("invalid Wide public presence");
    if (shared) {
        basefold::foldable::Metadata metadata;
        metadata.root = reader.basefold_digest("Wide public root");
        metadata.m = reader.size(limits.max_storage_entries,
                                 "Wide public message length");
        metadata.width = reader.size(256, "Wide public width");
        metadata.hierarchy_version = reader.u64("Wide public hierarchy version");
        result.wide_public_commitment = metadata;
    }
    reader.finish();
    bool valid_tables = gates::valid_wide_public_index(result);
    for (std::size_t table = 0;
         valid_tables && table < result.tables.size(); ++table) {
        valid_tables = !all_zero(result.tables[table].root) &&
            (result.tables[table].wide_block_offset.has_value() ==
             (result.layout.table_set == gates::GateTableSet::Wide)) &&
            gates::valid_sparse_table_commitment(
                result.layout.tables[table], result.tables[table],
                result.basefold_parameters);
    }
    if (result.layout_digest != gates::digest(result.layout) ||
        result.basefold_parameters.log_rate == 0 ||
        result.basefold_parameters.num_queries == 0 ||
        !valid_tables ||
        !same_bytes(gates::encode_canonical(result), encoded)) {
        throw std::invalid_argument("noncanonical gate-table verifier key");
    }
    return result;
}

PublicSetup decode_public_setup(
    std::span<const std::uint8_t> encoded,
    const PackedWorkloadStaticDecodeLimits &limits) {
    Reader reader(encoded, limits);
    require_label(reader, "LaminateImpl/PublicSetup/v4",
                  "public-setup label");
    PublicSetup result;
    const std::uint8_t profile = reader.u8("GateMLE profile");
    if (profile > static_cast<std::uint8_t>(
                      GateMleProfile::OutsourcedBaseFold)) {
        throw std::invalid_argument("unknown GateMLE profile");
    }
    result.gate_mle_profile = static_cast<GateMleProfile>(profile);
    result.shape = read_public_shape(reader, limits);
    result.layer_count = reader.size(limits.max_layers, "setup layer count");
    result.plaintext_modulus = reader.u64("plaintext modulus");
    result.extension_degree = reader.size(
        std::numeric_limits<std::size_t>::max(), "extension degree");
    result.target_security_bits = reader.size(
        std::numeric_limits<std::size_t>::max(), "target security bits");
    result.payload_digest = reader.digest("setup payload digest");
    result.layered_digest = reader.digest("setup layered digest");
    result.circuit_digest = reader.digest("setup circuit digest");
    const auto optional_digest = [&reader](std::string_view description)
        -> std::optional<Digest> {
        const std::uint8_t present = reader.u8(description);
        if (present > 1U) {
            throw std::invalid_argument(
                "noncanonical optional setup-digest flag");
        }
        return present == 0U
                   ? std::nullopt
                   : std::optional<Digest>(reader.digest(description));
    };
    result.honest_payload_noise_schedule_digest =
        optional_digest("payload-schedule digest presence");
    result.honest_base_proof_noise_assessment_digest =
        optional_digest("proof-noise digest presence");
    const std::size_t dummy_count = reader.size(
        limits.max_layers, "dummy GateMLE commitment count");
    result.dummy_gate_commitments.reserve(dummy_count);
    for (std::size_t index = 0; index < dummy_count; ++index) {
        result.dummy_gate_commitments.push_back(DummyGateMleCommitment{
            reader.size(limits.max_layers, "dummy GateMLE layer"),
            reader.digest("dummy GateMLE digest")});
    }
    const std::uint8_t has_outsourced =
        reader.u8("outsourced GateMLE key presence");
    if (has_outsourced > 1U) {
        throw std::invalid_argument(
            "noncanonical outsourced GateMLE flag");
    }
    if (has_outsourced != 0U) {
        result.outsourced_gate_mle = decode_gate_key(
            reader.blob(limits.max_artifact_bytes,
                        "outsourced GateMLE verifier key"),
            limits);
    }
    reader.finish();

    const bool direct = result.gate_mle_profile == GateMleProfile::Direct;
    const bool dummy = result.gate_mle_profile ==
                       GateMleProfile::DummyCommittedDirect;
    const bool outsourced = result.gate_mle_profile ==
                            GateMleProfile::OutsourcedBaseFold;
    bool dummy_indices_are_canonical = true;
    for (std::size_t index = 0;
         index < result.dummy_gate_commitments.size(); ++index) {
        dummy_indices_are_canonical &=
            result.dummy_gate_commitments[index].layer_index == index;
    }
    bool outsourced_is_strong_enough = true;
    if (result.outsourced_gate_mle) {
        const auto &parameters =
            result.outsourced_gate_mle->basefold_parameters;
        outsourced_is_strong_enough =
            parameters.log_rate == kGateMleBaseFoldLogRate &&
            gate_mle_basefold_soundness_bits(*result.outsourced_gate_mle) >=
                result.target_security_bits &&
            std::all_of(
                result.outsourced_gate_mle->layout.tables.begin(),
                result.outsourced_gate_mle->layout.tables.end(),
                [&result](const gates::GateTableDescriptor &table) {
                    return table.layer_index < result.layer_count;
                });
    }
    if (result.plaintext_modulus != kBaseFieldOrder ||
        result.extension_degree != kExtensionDegree ||
        result.target_security_bits != kTargetSecurityBits ||
        result.layer_count == 0 || !dummy_indices_are_canonical ||
        !outsourced_is_strong_enough ||
        (direct && (!result.dummy_gate_commitments.empty() ||
                    result.outsourced_gate_mle)) ||
        (dummy && (result.outsourced_gate_mle ||
                   result.dummy_gate_commitments.size() + 1U !=
                       result.layer_count)) ||
        (outsourced && (!result.dummy_gate_commitments.empty() ||
                        !result.outsourced_gate_mle)) ||
        (result.honest_base_proof_noise_assessment_digest &&
         !result.honest_payload_noise_schedule_digest) ||
        !same_bytes(encode_canonical(result), encoded)) {
        throw std::invalid_argument("inconsistent canonical public setup");
    }
    return result;
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
    Reader &reader, const PackedWorkloadStaticDecodeLimits &limits) {
    payload::LayerWireSupport result;
    result.padded_wire_count =
        reader.size(limits.max_layer_gates, "support padded wires");
    result.live_wire_count =
        reader.size(limits.max_layer_gates, "support live wires");
    const std::size_t ranges =
        reader.size(limits.max_layer_gates, "support range count");
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
        writer.u8(ordinal ? 1U : 0U);
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
    Reader &reader, const PackedWorkloadStaticDecodeLimits &limits) {
    payload::LayerStorageLayout result;
    result.padded_wire_count =
        reader.size(limits.max_layer_gates, "storage padded wires");
    result.stored_wire_count =
        reader.size(limits.max_layer_gates, "stored wire count");
    const std::size_t mappings =
        reader.size(limits.max_layer_gates, "storage mapping count");
    reader.add_storage_entries(mappings);
    result.padded_to_stored.reserve(mappings);
    for (std::size_t mapping = 0; mapping < mappings; ++mapping) {
        const std::uint8_t present =
            reader.u8("stored ordinal presence");
        if (present > 1U) {
            throw std::invalid_argument(
                "noncanonical stored-ordinal flag");
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
    Reader &reader, const PackedWorkloadStaticDecodeLimits &limits) {
    const std::uint8_t present =
        reader.u8("trace classification presence");
    if (present == 0U) {
        return std::nullopt;
    }
    if (present != 1U) {
        throw std::invalid_argument(
            "noncanonical trace-classification flag");
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
    throw std::invalid_argument("unknown public trace classification");
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
            "packed trace layout has the wrong layer count");
    }
    for (std::size_t layer = 0; layer < layers; ++layer) {
        const auto &dimensions =
            payload::layer_dimensions(circuit.layers[layer]);
        const auto &support = layout.wire_support[layer];
        const auto &storage = layout.storage[layer];
        const auto &classifications =
            layout.stored_value_classifications[layer];
        const auto &counts = layout.value_counts[layer];
        if (support.padded_wire_count != dimensions.padded_size ||
            storage.padded_wire_count != dimensions.padded_size ||
            classifications.size() != storage.stored_wire_count) {
            throw std::invalid_argument(
                "packed trace layout disagrees with layer geometry");
        }
        std::size_t encrypted = 0;
        for (const auto &classification : classifications) {
            if (!classification) {
                ++encrypted;
            } else {
                classification->validate_slot_count(
                    circuit.shape.slot_count,
                    "packed trace classification");
            }
        }
        for (std::size_t padded = 0;
             padded < dimensions.padded_size; ++padded) {
            if (support.is_live(padded) !=
                storage.stored_ordinal_of(padded).has_value()) {
                throw std::invalid_argument(
                    "packed trace support and storage disagree");
            }
        }
        if (counts.virtual_wire_positions != dimensions.padded_size ||
            counts.logical_live_wires != support.live_wire_count ||
            counts.stored_values != storage.stored_wire_count ||
            counts.encrypted_ciphertexts != encrypted) {
            throw std::invalid_argument(
                "packed trace counts disagree with its layout");
        }
    }
}

void encode_layout(Writer &writer,
                   const payload::CanonicalTraceLayout &layout) {
    writer.size(layout.wire_support.size());
    for (const auto &support : layout.wire_support) {
        encode_support(writer, support);
    }
    writer.size(layout.storage.size());
    for (const auto &storage : layout.storage) {
        encode_storage(writer, storage);
    }
    writer.size(layout.stored_value_classifications.size());
    for (const auto &layer : layout.stored_value_classifications) {
        writer.size(layer.size());
        for (const auto &classification : layer) {
            writer.u8(classification ? 1U : 0U);
            if (classification) {
                encode_public_plaintext(writer, *classification);
            }
        }
    }
    writer.size(layout.value_counts.size());
    for (const auto &counts : layout.value_counts) {
        writer.size(counts.virtual_wire_positions);
        writer.size(counts.logical_live_wires);
        writer.size(counts.stored_values);
        writer.size(counts.encrypted_ciphertexts);
    }
}

payload::CanonicalTraceLayout decode_layout(
    Reader &reader, const PackedWorkloadStaticDecodeLimits &limits) {
    payload::CanonicalTraceLayout result;
    const std::size_t support_layers =
        reader.size(limits.max_layers, "support layer count");
    result.wire_support.reserve(support_layers);
    for (std::size_t layer = 0; layer < support_layers; ++layer) {
        result.wire_support.push_back(decode_support(reader, limits));
    }
    const std::size_t storage_layers =
        reader.size(limits.max_layers, "storage layer count");
    result.storage.reserve(storage_layers);
    for (std::size_t layer = 0; layer < storage_layers; ++layer) {
        result.storage.push_back(decode_storage(reader, limits));
    }
    const std::size_t classification_layers = reader.size(
        limits.max_layers, "classification layer count");
    result.stored_value_classifications.reserve(classification_layers);
    for (std::size_t layer = 0; layer < classification_layers; ++layer) {
        const std::size_t values = reader.size(
            limits.max_layer_gates, "classification count");
        reader.add_storage_entries(values);
        std::vector<payload::ClassifiedTraceValue> decoded;
        decoded.reserve(values);
        for (std::size_t value = 0; value < values; ++value) {
            decoded.push_back(decode_classification(reader, limits));
        }
        result.stored_value_classifications.push_back(std::move(decoded));
    }
    const std::size_t count_layers =
        reader.size(limits.max_layers, "value-count layer count");
    result.value_counts.reserve(count_layers);
    for (std::size_t layer = 0; layer < count_layers; ++layer) {
        result.value_counts.push_back(payload::LayerTraceValueCounts{
            reader.size(limits.max_layer_gates,
                        "virtual wire positions"),
            reader.size(limits.max_layer_gates, "logical live wires"),
            reader.size(limits.max_layer_gates, "stored values"),
            reader.size(limits.max_layer_gates,
                        "encrypted ciphertexts")});
    }
    return result;
}

void append_header_and_body(
    Writer &writer, const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const payload::CanonicalTraceLayout &layout,
    const payload::LayerDimensions &output_dimensions,
    const PublicSetup &public_setup, const Digest &payload_digest,
    const Digest &layered_digest, const Digest &circuit_digest,
    const Digest &setup_id) {
    writer.raw(kMagic);
    writer.u64(kPackedWorkloadStaticVersion);
    writer.u64(0);
    writer.digest(payload_digest);
    writer.digest(layered_digest);
    writer.digest(circuit_digest);
    writer.digest(setup_id);
    writer.size(output_dimensions.logical_size);
    writer.size(output_dimensions.padded_size);
    writer.size(output_dimensions.payload_size);
    writer.size(output_dimensions.forward_size);
    writer.blob(payload::encode_canonical(payload));
    writer.blob(payload::encode_canonical(circuit));
    writer.blob(encode_canonical(public_setup));
    encode_layout(writer, layout);
}

bool valid_limits(const PackedWorkloadStaticDecodeLimits &limits) {
    return limits.max_artifact_bytes != 0 && limits.max_slots != 0 &&
           limits.max_payload_plaintexts != 0 &&
           limits.max_payload_gates != 0 &&
           limits.max_payload_outputs != 0 && limits.max_layers != 0 &&
           limits.max_layer_gates != 0 &&
           limits.max_affine_terms != 0 &&
           limits.max_storage_entries != 0 &&
           limits.max_gate_tables != 0;
}

void include_limit(std::size_t &limit, std::size_t value) {
    limit = std::max(limit, value);
}

void add_limit(std::size_t &total, std::size_t value,
               std::string_view description) {
    if (total > std::numeric_limits<std::size_t>::max() - value) {
        throw std::overflow_error(std::string(description) + " overflows");
    }
    total += value;
}

void include_shape_limit(std::size_t &max_slots,
                         const payload::PayloadShape &shape) {
    include_limit(max_slots, shape.slot_count);
    include_limit(max_slots, shape.lane_count);
}

void include_dimensions_limit(
    std::size_t &max_layer_gates,
    const payload::LayerDimensions &dimensions) {
    include_limit(max_layer_gates, dimensions.logical_size);
    include_limit(max_layer_gates, dimensions.padded_size);
    include_limit(max_layer_gates, dimensions.payload_size);
    include_limit(max_layer_gates, dimensions.forward_size);
}

std::size_t at_least_one(std::size_t value) {
    return std::max<std::size_t>(1, value);
}

} // namespace

struct CertifiedPackedWorkloadStatic::State {
    const payload::PayloadCircuit payload;
    const payload::LayeredCircuit circuit;
    const payload::CanonicalTraceLayout layout;
    const payload::LayerDimensions output_dimensions;
    const PublicSetup public_setup;
    const Digest payload_id;
    const Digest layered_id;
    const Digest circuit_id;
    const Digest setup_id;
    const Digest semantic_id;
};

CertifiedPackedWorkloadStatic::CertifiedPackedWorkloadStatic(
    std::shared_ptr<const State> state)
    : state_(std::move(state)) {}

const CertifiedPackedWorkloadStatic::State &
CertifiedPackedWorkloadStatic::state() const {
    if (!state_) {
        throw std::logic_error("packed workload token is moved from");
    }
    return *state_;
}

const payload::PayloadCircuit &
CertifiedPackedWorkloadStatic::payload() const {
    return state().payload;
}
const payload::LayeredCircuit &
CertifiedPackedWorkloadStatic::circuit() const {
    return state().circuit;
}
const payload::CanonicalTraceLayout &
CertifiedPackedWorkloadStatic::trace_layout() const {
    return state().layout;
}
const payload::LayerDimensions &
CertifiedPackedWorkloadStatic::output_dimensions() const {
    return state().output_dimensions;
}
const PublicSetup &CertifiedPackedWorkloadStatic::public_setup() const {
    return state().public_setup;
}
const Digest &CertifiedPackedWorkloadStatic::payload_digest() const {
    return state().payload_id;
}
const Digest &CertifiedPackedWorkloadStatic::layered_digest() const {
    return state().layered_id;
}
const Digest &CertifiedPackedWorkloadStatic::circuit_digest() const {
    return state().circuit_id;
}
const Digest &CertifiedPackedWorkloadStatic::setup_digest() const {
    return state().setup_id;
}
const Digest &CertifiedPackedWorkloadStatic::semantic_identity() const {
    return state().semantic_id;
}

CertifiedPackedWorkloadStatic certify_packed_workload_static(
    payload::PayloadCircuit payload, payload::LayeredCircuit circuit,
    PublicSetup public_setup) {
    public_setup.validate(payload, circuit);
    payload::CanonicalTraceLayout layout =
        payload::canonical_trace_layout(circuit);
    if (circuit.layers.empty()) {
        throw std::invalid_argument("packed workload has no circuit layers");
    }
    const payload::LayerDimensions output_dimensions =
        payload::layer_dimensions(circuit.layers.front());
    const payload::CircuitPairDigests digests =
        payload::circuit_pair_digests(payload, circuit);
    const Digest setup_id = laminate::setup_digest(public_setup);
    Writer semantic;
    append_header_and_body(semantic, payload, circuit, layout,
                           output_dimensions, public_setup,
                           digests.payload, digests.layered,
                           digests.combined, setup_id);
    const Digest semantic_id =
        domain_hash(kSemanticDomain, semantic.view());
    return CertifiedPackedWorkloadStatic(std::make_shared<const
        CertifiedPackedWorkloadStatic::State>(
        CertifiedPackedWorkloadStatic::State{
            std::move(payload), std::move(circuit), std::move(layout),
            output_dimensions, std::move(public_setup), digests.payload,
            digests.layered, digests.combined, setup_id, semantic_id}));
}

std::vector<std::uint8_t> encode_packed_workload_static(
    const CertifiedPackedWorkloadStatic &workload) {
    Writer writer;
    append_header_and_body(
        writer, workload.payload(), workload.circuit(),
        workload.trace_layout(), workload.output_dimensions(),
        workload.public_setup(), workload.payload_digest(),
        workload.layered_digest(), workload.circuit_digest(),
        workload.setup_digest());
    const Digest semantic = domain_hash(kSemanticDomain, writer.view());
    if (semantic != workload.semantic_identity()) {
        throw std::logic_error(
            "packed workload state has an inconsistent semantic identity");
    }
    writer.digest(semantic);
    const Digest checksum = domain_hash(kChecksumDomain, writer.view());
    writer.digest(checksum);
    return std::move(writer).finish();
}

PackedWorkloadStaticDecodeLimits
packed_workload_static_decode_requirements(
    const CertifiedPackedWorkloadStatic &workload,
    std::size_t encoded_artifact_bytes) {
    if (encoded_artifact_bytes == 0) {
        throw std::invalid_argument(
            "packed workload artifact byte size must be nonzero");
    }

    const payload::PayloadCircuit &payload = workload.payload();
    const payload::LayeredCircuit &circuit = workload.circuit();
    const payload::CanonicalTraceLayout &layout = workload.trace_layout();
    const PublicSetup &public_setup = workload.public_setup();

    PackedWorkloadStaticDecodeLimits result;
    result.max_artifact_bytes = encoded_artifact_bytes;

    include_shape_limit(result.max_slots, payload.shape);
    include_shape_limit(result.max_slots, circuit.shape);
    include_shape_limit(result.max_slots, public_setup.shape);
    for (const fhe::SlotVector &plaintext : payload.plaintexts) {
        include_limit(result.max_slots, plaintext.size());
    }
    for (const fhe::SlotVector &plaintext : circuit.plaintexts) {
        include_limit(result.max_slots, plaintext.size());
    }

    include_limit(result.max_payload_plaintexts,
                  payload.plaintexts.size());
    include_limit(result.max_payload_plaintexts,
                  circuit.plaintexts.size());
    result.max_payload_gates = payload.gates.size();
    include_limit(result.max_payload_outputs, payload.outputs.size());
    include_limit(result.max_payload_outputs,
                  circuit.payload_output_count);

    include_limit(result.max_layers, circuit.layers.size());
    include_limit(result.max_layers,
                  circuit.proof_multiplication_depth);
    include_limit(result.max_layers, public_setup.layer_count);
    include_limit(result.max_layers,
                  public_setup.dummy_gate_commitments.size());
    include_limit(result.max_layer_gates, payload.input_count);
    include_limit(result.max_layer_gates, circuit.payload_input_count);
    include_dimensions_limit(result.max_layer_gates,
                             workload.output_dimensions());

    for (const payload::Layer &layer : circuit.layers) {
        include_dimensions_limit(result.max_layer_gates,
                                 payload::layer_dimensions(layer));
        if (const auto *affine =
                std::get_if<payload::AffineLayer>(&layer)) {
            include_limit(result.max_layer_gates, affine->gates.size());
            include_limit(result.max_layer_gates,
                          affine->intermediate_gates.size());
            const auto layer_index =
                static_cast<std::size_t>(&layer - circuit.layers.data());
            std::size_t affine_addresses = payload::layer_dimensions(
                circuit.layers.at(layer_index + 1U)).padded_size;
            add_limit(affine_addresses, affine->intermediate_gates.size(),
                      "packed affine local address space");
            include_limit(result.max_layer_gates, affine_addresses);
            const auto include_affine_gate = [&](const payload::AffineGate &gate) {
                add_limit(result.max_affine_terms, gate.terms.size(),
                          "packed workload affine-term total");
                for (const payload::AffineTerm &term : gate.terms) {
                    include_limit(result.max_layer_gates, term.source);
                    include_limit(result.max_slots, term.rotation);
                    if (term.plaintext_index) {
                        include_limit(result.max_payload_plaintexts,
                                      *term.plaintext_index);
                    }
                }
                if (const auto *slots =
                        std::get_if<fhe::SlotVector>(&gate.constant)) {
                    include_limit(result.max_slots, slots->size());
                }
            };
            for (const auto &gate : affine->gates) {
                include_affine_gate(gate);
            }
            for (const auto &gate : affine->intermediate_gates) {
                include_affine_gate(gate);
            }
        } else if (const auto *multiplication =
                       std::get_if<payload::MultiplicationLayer>(&layer)) {
            include_limit(result.max_layer_gates,
                          multiplication->gates.size());
        }
    }

    include_limit(result.max_layers, layout.wire_support.size());
    for (const payload::LayerWireSupport &support :
         layout.wire_support) {
        include_limit(result.max_layer_gates,
                      support.padded_wire_count);
        include_limit(result.max_layer_gates,
                      support.live_wire_count);
        include_limit(result.max_layer_gates,
                      support.live_ranges.size());
        for (const payload::LiveWireRange &range :
             support.live_ranges) {
            include_limit(result.max_layer_gates, range.padded_begin);
            include_limit(result.max_layer_gates, range.wire_count);
        }
    }

    include_limit(result.max_layers, layout.storage.size());
    for (const payload::LayerStorageLayout &storage : layout.storage) {
        include_limit(result.max_layer_gates,
                      storage.padded_wire_count);
        include_limit(result.max_layer_gates,
                      storage.stored_wire_count);
        include_limit(result.max_layer_gates,
                      storage.padded_to_stored.size());
        add_limit(result.max_storage_entries,
                  storage.padded_to_stored.size(),
                  "packed workload storage-entry total");
        for (const std::optional<std::size_t> &ordinal :
             storage.padded_to_stored) {
            if (ordinal) {
                include_limit(result.max_layer_gates, *ordinal);
            }
        }
        include_limit(result.max_layer_gates,
                      storage.representative_padded_indices.size());
        for (std::size_t representative :
             storage.representative_padded_indices) {
            include_limit(result.max_layer_gates, representative);
        }
    }

    include_limit(result.max_layers,
                  layout.stored_value_classifications.size());
    for (const auto &classifications :
         layout.stored_value_classifications) {
        include_limit(result.max_layer_gates, classifications.size());
        add_limit(result.max_storage_entries, classifications.size(),
                  "packed workload storage-entry total");
        for (const payload::ClassifiedTraceValue &classification :
             classifications) {
            if (classification && !classification->is_scalar()) {
                include_limit(result.max_slots,
                              classification->slots().size());
            }
        }
    }

    include_limit(result.max_layers, layout.value_counts.size());
    for (const payload::LayerTraceValueCounts &counts :
         layout.value_counts) {
        include_limit(result.max_layer_gates,
                      counts.virtual_wire_positions);
        include_limit(result.max_layer_gates,
                      counts.logical_live_wires);
        include_limit(result.max_layer_gates, counts.stored_values);
        include_limit(result.max_layer_gates,
                      counts.encrypted_ciphertexts);
    }

    for (const DummyGateMleCommitment &commitment :
         public_setup.dummy_gate_commitments) {
        include_limit(result.max_layers, commitment.layer_index);
    }
    if (public_setup.outsourced_gate_mle) {
        const gates::GateTableVerifierKey &key =
            *public_setup.outsourced_gate_mle;
        include_limit(result.max_storage_entries,
                      key.basefold_parameters.num_queries);
        include_limit(result.max_storage_entries,
                      key.foldable_parameters.num_queries);
        include_limit(result.max_slots, key.layout.wide_masks.slots);
        include_limit(result.max_payload_plaintexts, key.layout.wide_masks.mask_count);
        include_limit(result.max_storage_entries, key.layout.wide_masks.mask_width);
        for (const auto &layer : key.layout.wide_layers) {
            include_limit(result.max_layers, layer.layer_index);
            include_limit(result.max_affine_terms, layer.node_count);
        }
        include_limit(result.max_gate_tables,
                      key.layout.tables.size());
        for (const gates::GateTableDescriptor &table : key.layout.tables) {
            include_limit(result.max_layers, table.layer_index);
            include_limit(result.max_gate_tables, table.selector);
            include_limit(result.max_storage_entries, table.support_size);
        }
        for (const gates::SparseTableCommitment &table : key.tables) {
            include_limit(result.max_storage_entries, table.message_size);
            include_limit(result.max_storage_entries, table.shard_size);
            include_limit(result.max_storage_entries, table.shard_count);
            include_limit(result.max_storage_entries, table.logical_width);
            include_limit(result.max_storage_entries, table.physical_width);
            if (table.wide_block_offset)
                include_limit(result.max_storage_entries, *table.wide_block_offset);
        }
        if (key.wide_public_commitment)
            include_limit(result.max_storage_entries, key.wide_public_commitment->m);
    }

    result.max_slots = at_least_one(result.max_slots);
    result.max_payload_plaintexts =
        at_least_one(result.max_payload_plaintexts);
    result.max_payload_gates = at_least_one(result.max_payload_gates);
    result.max_payload_outputs =
        at_least_one(result.max_payload_outputs);
    result.max_layers = at_least_one(result.max_layers);
    result.max_layer_gates = at_least_one(result.max_layer_gates);
    result.max_affine_terms = at_least_one(result.max_affine_terms);
    result.max_storage_entries =
        at_least_one(result.max_storage_entries);
    result.max_gate_tables = at_least_one(result.max_gate_tables);
    return result;
}

CertifiedPackedWorkloadStatic decode_authenticated_packed_workload_static(
    std::span<const std::uint8_t> encoded,
    const Digest &expected_file_digest,
    const Digest &expected_semantic_identity,
    const PackedWorkloadStaticDecodeLimits &limits) {
    if (!valid_limits(limits) || encoded.size() > limits.max_artifact_bytes ||
        encoded.size() < kMagic.size() + 2U * sizeof(std::uint64_t) +
                             2U * Digest{}.size()) {
        throw std::invalid_argument(
            "packed workload decode limits or artifact size are invalid");
    }
    if (sha256(encoded) != expected_file_digest) {
        throw std::invalid_argument(
            "packed workload differs from its authenticated file digest");
    }
    const std::size_t checksum_offset = encoded.size() - Digest{}.size();
    Digest encoded_checksum{};
    std::copy(encoded.begin() + static_cast<std::ptrdiff_t>(checksum_offset),
              encoded.end(), encoded_checksum.begin());
    if (domain_hash(kChecksumDomain, encoded.first(checksum_offset)) !=
        encoded_checksum) {
        throw std::invalid_argument("packed workload checksum mismatch");
    }

    Reader reader(encoded, limits);
    const auto magic = reader.take(kMagic.size(), "packed workload magic");
    if (!std::equal(kMagic.begin(), kMagic.end(), magic.begin()) ||
        reader.u64("packed workload version") !=
            kPackedWorkloadStaticVersion ||
        reader.u64("packed workload flags") != 0U) {
        throw std::invalid_argument("unsupported packed workload format");
    }
    const Digest payload_id = reader.digest("payload digest");
    const Digest layered_id = reader.digest("layered digest");
    const Digest circuit_id = reader.digest("circuit digest");
    const Digest setup_id = reader.digest("setup digest");
    const payload::LayerDimensions output_dimensions =
        read_dimensions(reader, limits.max_layer_gates);
    const payload::CircuitDecodeLimits circuit_limits =
        circuit_decode_limits(limits);
    payload::PayloadCircuit payload = payload::decode_canonical_payload(
        reader.blob(limits.max_artifact_bytes, "payload bytes"),
        circuit_limits);
    payload::LayeredCircuit circuit = payload::decode_canonical_layered(
        reader.blob(limits.max_artifact_bytes, "layered bytes"),
        circuit_limits);
    PublicSetup public_setup = decode_public_setup(
        reader.blob(limits.max_artifact_bytes, "public-setup bytes"),
        limits);
    payload::CanonicalTraceLayout layout = decode_layout(reader, limits);
    const std::size_t semantic_offset = reader.position();
    const Digest semantic_id = reader.digest("workload semantic identity");
    const Digest checksum = reader.digest("workload checksum");
    reader.finish();
    if (semantic_id != expected_semantic_identity ||
        semantic_id !=
            domain_hash(kSemanticDomain, encoded.first(semantic_offset)) ||
        checksum != encoded_checksum) {
        throw std::invalid_argument(
            "packed workload has the wrong semantic identity");
    }

    const payload::CircuitPairDigests digests =
        payload::circuit_pair_digests(payload, circuit);
    if (digests.payload != payload_id || digests.layered != layered_id ||
        digests.combined != circuit_id ||
        laminate::setup_digest(public_setup) != setup_id ||
        public_setup.payload_digest != payload_id ||
        public_setup.layered_digest != layered_id ||
        public_setup.circuit_digest != circuit_id ||
        !(payload.shape == circuit.shape) ||
        !(public_setup.shape == payload.shape) ||
        payload.input_count != circuit.payload_input_count ||
        payload.outputs.size() != circuit.payload_output_count ||
        public_setup.layer_count != circuit.layers.size() ||
        circuit.layers.empty() ||
        !(output_dimensions ==
          payload::layer_dimensions(circuit.layers.front()))) {
        throw std::invalid_argument(
            "packed workload has inconsistent circuit/setup metadata");
    }
    validate_layout_consistency(circuit, layout);

    auto restored = CertifiedPackedWorkloadStatic(
        std::make_shared<const CertifiedPackedWorkloadStatic::State>(
            CertifiedPackedWorkloadStatic::State{
                std::move(payload), std::move(circuit), std::move(layout),
                output_dimensions, std::move(public_setup), payload_id,
                layered_id, circuit_id, setup_id, semantic_id}));
    if (!same_bytes(encode_packed_workload_static(restored), encoded)) {
        throw std::invalid_argument(
            "packed workload does not use its canonical encoding");
    }
    return restored;
}

} // namespace laminate::protocol
