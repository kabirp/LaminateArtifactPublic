#ifndef LAMINATE_DELEGATION_LANED_WIRE_TYPES_HPP
#define LAMINATE_DELEGATION_LANED_WIRE_TYPES_HPP

/// @file wire/types.hpp
/// @brief Laned envelope tags, limits, and bounded response views.

#include "laminate/delegation/laned/transport/messages.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

namespace laminate::delegation {

struct LanedWireDecodeLimits {
    std::size_t max_message_bytes = 0;
    std::size_t max_ciphertexts = 0;
    std::size_t max_ciphertext_bytes = 0;
    std::size_t max_total_ciphertext_bytes = 0;
    std::size_t max_proof_bytes = 0;
};

enum class LanedWireMessageType : std::uint8_t {
    EvaluationRequest = 1,
    Response = 2,
};

inline constexpr std::string_view kLanedDelegationWireDomain =
    "LaminateImpl/LanedDelegationWire";
inline constexpr std::uint8_t kLanedDelegationWireVersion = 3;
inline constexpr std::size_t kLanedDelegationWireHeaderBytes =
    kLanedDelegationWireDomain.size() + 1U + 1U + 2U + 8U;

template <fhe::FheBackend Backend>
struct OpaqueLanedResponseEnvelope {
    Digest setup_id{};
    Digest session_id{};
    Digest circuit_id{};
    Digest trace_id{};
    LanedFheOutput<Backend> output;
    std::vector<std::uint8_t> opaque_proof_bytes;
};

/// Output values are owned while proof bytes borrow the bounded input buffer.
template <fhe::FheBackend Backend>
struct BorrowedLanedResponseEnvelope {
    Digest setup_id{};
    Digest session_id{};
    Digest circuit_id{};
    Digest trace_id{};
    LanedFheOutput<Backend> output;
    std::span<const std::uint8_t> opaque_proof_bytes;
};

} // namespace laminate::delegation

#endif // LAMINATE_DELEGATION_LANED_WIRE_TYPES_HPP
