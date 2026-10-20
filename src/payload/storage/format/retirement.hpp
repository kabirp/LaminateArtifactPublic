#ifndef LAMINATE_PAYLOAD_STORAGE_TRACE_STORE_RETIREMENT_FORMAT_HPP
#define LAMINATE_PAYLOAD_STORAGE_TRACE_STORE_RETIREMENT_FORMAT_HPP

/// @file retirement.hpp
/// @brief Private retirement-session and event-chain codec.

#include "manifest.hpp"

namespace laminate::payload::trace_store_format {

std::vector<std::uint8_t> encode_retirement_session(
    const Digest &manifest_id, const ParsedManifest &manifest);

struct ParsedRetirementSession {
    Digest manifest_id{};
    Digest backend_context_id{};
    Digest circuit_id{};
    Digest trace_id{};
    std::size_t layer_count = 0;
    std::uint64_t original_physical_bytes = 0;
};

ParsedRetirementSession parse_retirement_session(
    std::span<const std::uint8_t> bytes,
    const FileTraceStoreOpenLimits &limits);
std::vector<std::uint8_t> encode_retirement_event(
    std::uint64_t generation, std::size_t layer_index,
    std::uint64_t reclaimed_layer_bytes,
    std::uint64_t cumulative_reclaimed_bytes,
    const Digest &previous_id, const Digest &session_id);

struct ParsedRetirementEvent {
    std::uint64_t generation = 0;
    std::size_t layer_index = 0;
    std::uint64_t reclaimed_layer_bytes = 0;
    std::uint64_t cumulative_reclaimed_bytes = 0;
    Digest previous_id{};
    Digest session_id{};
};

ParsedRetirementEvent parse_retirement_event(
    std::span<const std::uint8_t> bytes);

} // namespace laminate::payload::trace_store_format

#endif // LAMINATE_PAYLOAD_STORAGE_TRACE_STORE_RETIREMENT_FORMAT_HPP
