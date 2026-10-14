#ifndef LAMINATE_DELEGATION_FOLDED_WIRE_DETAIL_ENVELOPE_HPP
#define LAMINATE_DELEGATION_FOLDED_WIRE_DETAIL_ENVELOPE_HPP

/// @file wire/detail/envelope.hpp
/// @brief Folded domain framing, output shape, and proof-tag checks.

#include "laminate/delegation/folded/wire/types.hpp"
#include "laminate/delegation/packed/wire/detail/primitives.hpp"

#include <algorithm>
#include <array>
#include <limits>

namespace laminate::delegation::folded_wire_detail {

inline std::size_t begin_envelope(
    wire_detail::Bytes &output, FoldedWireMessageType type,
    std::size_t reserve_bytes, const char *operation) {
    output.clear();
    output.reserve(std::max(reserve_bytes, kFoldedDelegationWireHeaderBytes));
    output.insert(output.end(), kFoldedDelegationWireDomain.begin(),
                  kFoldedDelegationWireDomain.end());
    output.push_back(kFoldedDelegationWireVersion);
    output.push_back(static_cast<std::uint8_t>(type));
    wire_detail::append_u16(output, 0);
    wire_detail::append_size(output, 0, operation);
    return output.size();
}

inline void finish_envelope(wire_detail::Bytes &output,
                            std::size_t payload_start,
                            const char *operation) {
    if (payload_start != kFoldedDelegationWireHeaderBytes ||
        output.size() < payload_start) {
        wire_detail::reject(operation,
                            "invalid envelope construction state");
    }
    wire_detail::patch_size(output, payload_start - 8U,
                            output.size() - payload_start, operation);
}

inline wire_detail::Reader open_envelope(
    std::span<const std::uint8_t> encoded,
    FoldedWireMessageType expected,
    const FoldedWireDecodeLimits &limits, const char *operation) {
    if (encoded.size() > limits.max_message_bytes) {
        wire_detail::reject(operation,
                            "message exceeds configured byte limit");
    }
    wire_detail::Reader reader(encoded, operation);
    const auto domain = reader.read_bytes(kFoldedDelegationWireDomain.size());
    if (!std::equal(domain.begin(), domain.end(),
                    kFoldedDelegationWireDomain.begin())) {
        wire_detail::reject(operation, "wrong wire domain");
    }
    if (reader.read_u8() != kFoldedDelegationWireVersion) {
        wire_detail::reject(operation, "unsupported wire version");
    }
    if (reader.read_u8() != static_cast<std::uint8_t>(expected)) {
        wire_detail::reject(operation, "wrong message type");
    }
    if (reader.read_u16() != 0) {
        wire_detail::reject(operation, "unsupported wire flags");
    }
    if (reader.read_size() != reader.remaining()) {
        wire_detail::reject(
            operation, "truncated or trailing envelope data");
    }
    return reader;
}

inline void validate_dimensions(
    const payload::LayerDimensions &dimensions, const char *operation) {
    if (dimensions.logical_size == 0 ||
        dimensions.logical_size > dimensions.padded_size ||
        !wire_detail::is_power_of_two(dimensions.padded_size) ||
        dimensions.payload_size >
            std::numeric_limits<std::size_t>::max() -
                dimensions.forward_size ||
        dimensions.payload_size + dimensions.forward_size !=
            dimensions.logical_size) {
        wire_detail::reject(operation, "invalid output dimensions");
    }
}

inline void validate_compact_output_count(
    const payload::LayerDimensions &dimensions, std::size_t value_count,
    const char *operation) {
    validate_dimensions(dimensions, operation);
    if (value_count == 0 || value_count > dimensions.logical_size) {
        wire_detail::reject(operation, "invalid compact output count");
    }
}

inline constexpr std::array<std::uint8_t, 14> kCanonicalFoldedProofPrefix{
    'L', 'M', '/', 'P', 'A', 'C', 'K', 'E', 'D', '/', 'F', '/', 'v', '7'};

inline void validate_proof_prefix(
    std::span<const std::uint8_t> proof, const char *operation) {
    if (proof.size() < kCanonicalFoldedProofPrefix.size() ||
        !std::equal(kCanonicalFoldedProofPrefix.begin(),
                    kCanonicalFoldedProofPrefix.end(), proof.begin())) {
        wire_detail::reject(
            operation, "wrong canonical Folded proof encoding tag");
    }
}

} // namespace laminate::delegation::folded_wire_detail

#endif // LAMINATE_DELEGATION_FOLDED_WIRE_DETAIL_ENVELOPE_HPP
