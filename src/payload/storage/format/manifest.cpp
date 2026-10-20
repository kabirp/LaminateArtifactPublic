/// @file manifest.cpp
/// @brief Trace-store manifest encoding and validation.

#include "manifest.hpp"

#include "laminate/transcript/hash.hpp"

#include <algorithm>
#include <stdexcept>
#include <string>

namespace laminate::payload {
namespace trace_store_format {

std::vector<std::uint8_t> encode_manifest(
    const Digest &backend_context_id,
    const EncryptedTraceDescriptor &descriptor,
    const FileTraceStoreWriteReport &report,
    std::span<const LayerFileSummary> layers) {
    if (layers.size() != descriptor.layers.size()) {
        throw std::logic_error("manifest layer summaries are incomplete");
    }
    std::vector<std::uint8_t> result;
    append_magic(result, kManifestMagic);
    append_u64(result, kFormatVersion);
    append_u64(result, shape_code(descriptor.shape.kind));
    append_u64(result,
               checked_u64(descriptor.shape.slot_count, "slot count"));
    append_u64(result,
               checked_u64(descriptor.shape.lane_count, "lane count"));
    append_u64(result, provenance_code(descriptor.provenance));
    append_digest(result, backend_context_id);
    append_digest(result, descriptor.circuit_id);
    append_digest(result, descriptor.trace_id);
    append_u64(result,
               checked_u64(descriptor.layers.size(), "layer count"));
    append_u64(result, report.logical_record_bytes);
    append_u64(result, report.physical_bytes);
    for (std::size_t index = 0; index < descriptor.layers.size(); ++index) {
        const EncryptedTraceLayerDescriptor &layer = descriptor.layers[index];
        append_u64(result, layout_code(layer.layout));
        append_u64(result, checked_u64(layer.dimensions.logical_size,
                                       "logical layer size"));
        append_u64(result, checked_u64(layer.dimensions.padded_size,
                                       "padded layer size"));
        append_u64(result, checked_u64(layer.dimensions.payload_size,
                                       "payload layer size"));
        append_u64(result, checked_u64(layer.dimensions.forward_size,
                                       "forward layer size"));
        append_u64(result, checked_u64(layer.required_mult_depth,
                                       "required multiplication depth"));
        append_u64(result,
                   checked_u64(layer.record_count, "record count"));
        append_u64(result, layers[index].file_size);
        append_digest(result, layers[index].digest);
    }
    append_digest(result, sha256(result));
    return result;
}

void validate_open_limits(const FileTraceStoreOpenLimits &limits) {
    if (limits.max_manifest_bytes == 0 || limits.max_total_bytes == 0 ||
        limits.max_record_bytes == 0 || limits.max_layers == 0 ||
        limits.max_records_per_layer == 0) {
        throw std::invalid_argument(
            "FileTraceStoreOpenLimits: every limit must be nonzero");
    }
}

ParsedManifest parse_manifest(std::span<const std::uint8_t> bytes,
                              const FileTraceStoreOpenLimits &limits) {
    if (bytes.size() < Digest{}.size()) {
        throw std::runtime_error("truncated trace-store manifest");
    }
    const std::size_t body_size = bytes.size() - Digest{}.size();
    const Digest computed = sha256(bytes.first(body_size));
    Digest recorded{};
    std::copy_n(bytes.begin() + static_cast<std::ptrdiff_t>(body_size),
                recorded.size(), recorded.begin());
    if (computed != recorded) {
        throw std::runtime_error("corrupt trace-store manifest digest");
    }

    ByteReader reader(bytes.first(body_size));
    reader.magic(kManifestMagic, "trace-store manifest magic");
    if (reader.u64("trace-store manifest version") != kFormatVersion) {
        throw std::runtime_error("unsupported trace-store manifest version");
    }

    ParsedManifest result;
    result.descriptor.shape.kind =
        parse_shape(reader.u64("payload shape"));
    result.descriptor.shape.slot_count =
        checked_size(reader.u64("slot count"), "slot count");
    result.descriptor.shape.lane_count =
        checked_size(reader.u64("lane count"), "lane count");
    result.descriptor.provenance =
        parse_provenance(reader.u64("trace provenance"));
    result.backend_context_id =
        reader.digest("backend encryption-context digest");
    if (std::all_of(result.backend_context_id.begin(),
                    result.backend_context_id.end(),
                    [](std::uint8_t byte) { return byte == 0; })) {
        throw std::runtime_error(
            "trace store has an empty backend context identity");
    }
    result.descriptor.circuit_id = reader.digest("circuit digest");
    result.descriptor.trace_id = reader.digest("trace digest");
    const std::size_t layer_count =
        checked_size(reader.u64("layer count"), "layer count");
    if (layer_count == 0 || layer_count > kMaximumTraceLayers ||
        layer_count > limits.max_layers) {
        throw std::runtime_error("trace-store layer count exceeds v4 limits");
    }
    result.report.logical_record_bytes = reader.u64("logical record bytes");
    result.report.physical_bytes = reader.u64("physical store bytes");

    if (layer_count > (body_size - reader.position()) /
                          static_cast<std::size_t>(kLayerManifestBytes)) {
        throw std::runtime_error("invalid trace-store manifest length");
    }
    const std::size_t expected_body =
        reader.position() +
        layer_count * static_cast<std::size_t>(kLayerManifestBytes);
    if (expected_body != body_size) {
        throw std::runtime_error("invalid trace-store manifest length");
    }

    result.descriptor.layers.reserve(layer_count);
    result.layers.reserve(layer_count);
    for (std::size_t index = 0; index < layer_count; ++index) {
        EncryptedTraceLayerDescriptor layer;
        layer.layout = parse_layout(reader.u64("layer layout"));
        layer.dimensions.logical_size = checked_size(
            reader.u64("logical layer size"), "logical layer size");
        layer.dimensions.padded_size = checked_size(
            reader.u64("padded layer size"), "padded layer size");
        layer.dimensions.payload_size = checked_size(
            reader.u64("payload layer size"), "payload layer size");
        layer.dimensions.forward_size = checked_size(
            reader.u64("forward layer size"), "forward layer size");
        layer.required_mult_depth = checked_size(
            reader.u64("required multiplication depth"),
            "required multiplication depth");
        layer.record_count =
            checked_size(reader.u64("record count"), "record count");
        if (layer.record_count > limits.max_records_per_layer) {
            throw std::runtime_error(
                "trace-store layer exceeds caller record limit");
        }
        result.descriptor.layers.push_back(layer);
        result.layers.push_back(LayerFileSummary{
            reader.u64("layer file size"),
            reader.digest("layer file digest"),
        });
    }
    return result;
}

} // namespace trace_store_format
} // namespace laminate::payload
