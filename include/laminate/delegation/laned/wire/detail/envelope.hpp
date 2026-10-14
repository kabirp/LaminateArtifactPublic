#ifndef LAMINATE_DELEGATION_LANED_WIRE_DETAIL_ENVELOPE_HPP
#define LAMINATE_DELEGATION_LANED_WIRE_DETAIL_ENVELOPE_HPP

/// @file wire/detail/envelope.hpp
/// @brief Laned domain framing and canonical proof-tag checks.

#include "laminate/delegation/laned/wire/types.hpp"
#include "laminate/delegation/packed/wire/detail/primitives.hpp"

#include <algorithm>
#include <array>
#include <span>

namespace laminate::delegation::wire_detail {

inline std::size_t begin_laned_envelope(
    Bytes &output, LanedWireMessageType type, std::size_t reserve_bytes,
    const char *operation) {
    output.clear();
    output.reserve(std::max(reserve_bytes, kLanedDelegationWireHeaderBytes));
    output.insert(output.end(), kLanedDelegationWireDomain.begin(),
                  kLanedDelegationWireDomain.end());
    output.push_back(kLanedDelegationWireVersion);
    output.push_back(static_cast<std::uint8_t>(type));
    append_u16(output, 0);
    append_size(output, 0, operation);
    return output.size();
}

inline void finish_laned_envelope(Bytes &output, std::size_t payload_start,
                                  const char *operation) {
    if (payload_start != kLanedDelegationWireHeaderBytes ||
        output.size() < payload_start) {
        reject(operation, "invalid envelope construction state");
    }
    patch_size(output, payload_start - 8U,
               output.size() - payload_start, operation);
}

inline Reader open_laned_envelope(
    std::span<const std::uint8_t> encoded,
    LanedWireMessageType expected, const LanedWireDecodeLimits &limits,
    const char *operation) {
    if (encoded.size() > limits.max_message_bytes) {
        reject(operation, "message exceeds configured byte limit");
    }
    Reader reader(encoded, operation);
    const auto domain = reader.read_bytes(kLanedDelegationWireDomain.size());
    if (!std::equal(domain.begin(), domain.end(),
                    kLanedDelegationWireDomain.begin())) {
        reject(operation, "wrong wire domain");
    }
    if (reader.read_u8() != kLanedDelegationWireVersion) {
        reject(operation, "unsupported wire version");
    }
    if (reader.read_u8() != static_cast<std::uint8_t>(expected)) {
        reject(operation, "wrong message type");
    }
    if (reader.read_u16() != 0) {
        reject(operation, "unsupported wire flags");
    }
    if (reader.read_size() != reader.remaining()) {
        reject(operation, "truncated or trailing envelope data");
    }
    return reader;
}

inline constexpr std::array<std::uint8_t, 14> kCanonicalLanedProofPrefix{
    'L', 'M', '/', 'P', 'A', 'C', 'K', 'E', 'D', '/', 'L', '/', 'v', '7'};

inline void validate_opaque_laned_proof_prefix(
    std::span<const std::uint8_t> proof, const char *operation) {
    if (proof.size() < kCanonicalLanedProofPrefix.size() ||
        !std::equal(kCanonicalLanedProofPrefix.begin(),
                    kCanonicalLanedProofPrefix.end(), proof.begin())) {
        reject(operation, "wrong canonical Laned proof encoding tag");
    }
}

} // namespace laminate::delegation::wire_detail

#endif // LAMINATE_DELEGATION_LANED_WIRE_DETAIL_ENVELOPE_HPP
