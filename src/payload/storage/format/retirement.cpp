/// @file retirement.cpp
/// @brief Immutable retirement-session and event-chain codecs.

#include "retirement.hpp"

#include "laminate/transcript/hash.hpp"

#include <algorithm>
#include <stdexcept>

namespace laminate::payload {
namespace trace_store_format {

std::vector<std::uint8_t> encode_retirement_session(
    const Digest &manifest_id, const ParsedManifest &manifest) {
    std::vector<std::uint8_t> result;
    result.reserve(static_cast<std::size_t>(kRetirementSessionBytes));
    append_magic(result, kRetirementSessionMagic);
    append_u64(result, kFormatVersion);
    append_digest(result, manifest_id);
    append_digest(result, manifest.backend_context_id);
    append_digest(result, manifest.descriptor.circuit_id);
    append_digest(result, manifest.descriptor.trace_id);
    append_u64(result, checked_u64(manifest.descriptor.layers.size(),
                                   "retirement layer count"));
    append_u64(result, manifest.report.physical_bytes);
    append_digest(result, sha256(result));
    if (result.size() != kRetirementSessionBytes) {
        throw std::logic_error("invalid retirement-session encoding length");
    }
    return result;
}

ParsedRetirementSession parse_retirement_session(
    std::span<const std::uint8_t> bytes,
    const FileTraceStoreOpenLimits &limits) {
    if (bytes.size() != kRetirementSessionBytes) {
        throw std::runtime_error("invalid retirement-session length");
    }
    const std::size_t body_size = bytes.size() - Digest{}.size();
    ByteReader reader(bytes.first(body_size));
    reader.magic(kRetirementSessionMagic, "retirement-session magic");
    if (reader.u64("retirement-session version") != kFormatVersion) {
        throw std::runtime_error("unsupported retirement-session version");
    }
    ParsedRetirementSession result;
    result.manifest_id = reader.digest("retirement manifest identity");
    result.backend_context_id =
        reader.digest("retirement backend identity");
    result.circuit_id = reader.digest("retirement circuit identity");
    result.trace_id = reader.digest("retirement trace identity");
    result.layer_count = checked_size(
        reader.u64("retirement layer count"), "retirement layer count");
    result.original_physical_bytes =
        reader.u64("retirement original physical bytes");
    Digest recorded{};
    std::copy_n(bytes.begin() + static_cast<std::ptrdiff_t>(body_size),
                recorded.size(), recorded.begin());
    if (sha256(bytes.first(body_size)) != recorded) {
        throw std::runtime_error("corrupt retirement-session digest");
    }
    if (result.layer_count == 0 || result.layer_count > limits.max_layers ||
        result.layer_count > kMaximumTraceLayers) {
        throw std::runtime_error("retirement-session layer count is invalid");
    }
    return result;
}

std::vector<std::uint8_t> encode_retirement_event(
    std::uint64_t generation, std::size_t layer_index,
    std::uint64_t reclaimed_layer_bytes,
    std::uint64_t cumulative_reclaimed_bytes, const Digest &previous_id,
    const Digest &session_id) {
    std::vector<std::uint8_t> result;
    result.reserve(static_cast<std::size_t>(kRetirementEventBytes));
    append_magic(result, kRetirementEventMagic);
    append_u64(result, kFormatVersion);
    append_u64(result, generation);
    append_u64(result, checked_u64(layer_index, "retired layer index"));
    append_u64(result, reclaimed_layer_bytes);
    append_u64(result, cumulative_reclaimed_bytes);
    append_digest(result, previous_id);
    append_digest(result, session_id);
    append_digest(result, sha256(result));
    if (result.size() != kRetirementEventBytes) {
        throw std::logic_error("invalid retirement-event encoding length");
    }
    return result;
}

ParsedRetirementEvent parse_retirement_event(
    std::span<const std::uint8_t> bytes) {
    if (bytes.size() != kRetirementEventBytes) {
        throw std::runtime_error("invalid retirement-event length");
    }
    const std::size_t body_size = bytes.size() - Digest{}.size();
    Digest recorded{};
    std::copy_n(bytes.begin() + static_cast<std::ptrdiff_t>(body_size),
                recorded.size(), recorded.begin());
    if (sha256(bytes.first(body_size)) != recorded) {
        throw std::runtime_error("corrupt retirement-event digest");
    }
    ByteReader reader(bytes.first(body_size));
    reader.magic(kRetirementEventMagic, "retirement-event magic");
    if (reader.u64("retirement-event version") != kFormatVersion) {
        throw std::runtime_error("unsupported retirement-event version");
    }
    ParsedRetirementEvent result;
    result.generation = reader.u64("retirement generation");
    result.layer_index = checked_size(reader.u64("retired layer index"),
                                      "retired layer index");
    result.reclaimed_layer_bytes =
        reader.u64("retired layer physical bytes");
    result.cumulative_reclaimed_bytes =
        reader.u64("cumulative reclaimed physical bytes");
    result.previous_id = reader.digest("previous retirement event identity");
    result.session_id = reader.digest("retirement-session identity");
    return result;
}

} // namespace trace_store_format
} // namespace laminate::payload
