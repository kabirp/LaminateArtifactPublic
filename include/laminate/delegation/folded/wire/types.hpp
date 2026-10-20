#ifndef LAMINATE_DELEGATION_FOLDED_WIRE_TYPES_HPP
#define LAMINATE_DELEGATION_FOLDED_WIRE_TYPES_HPP

/// @file wire/types.hpp
/// @brief Folded envelope tags, limits, and bounded response views.

#include "laminate/delegation/folded/transport/messages.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

namespace laminate::delegation {

struct FoldedWireDecodeLimits {
    std::size_t max_message_bytes = 0;
    std::size_t max_ciphertexts = 0;
    std::size_t max_ciphertext_bytes = 0;
    std::size_t max_total_ciphertext_bytes = 0;
    std::size_t max_proof_bytes = 0;
};

enum class FoldedWireMessageType : std::uint8_t {
    EvaluationRequest = 1,
    Response = 2,
};

inline constexpr std::string_view kFoldedDelegationWireDomain =
    "LaminateImpl/FoldedDelegationWire";
inline constexpr std::uint8_t kFoldedDelegationWireVersion = 1;
inline constexpr std::size_t kFoldedDelegationWireHeaderBytes =
    kFoldedDelegationWireDomain.size() + 1U + 1U + 2U + 8U;

template <fhe::FheBackend Backend>
struct OpaqueFoldedResponseEnvelope {
    Digest setup_id{};
    Digest session_id{};
    Digest circuit_id{};
    Digest trace_id{};
    FoldedFheOutput<Backend> output;
    std::vector<std::uint8_t> opaque_proof_bytes;
};

template <fhe::FheBackend Backend>
struct BorrowedFoldedResponseEnvelope {
    Digest setup_id{};
    Digest session_id{};
    Digest circuit_id{};
    Digest trace_id{};
    FoldedFheOutput<Backend> output;
    std::span<const std::uint8_t> opaque_proof_bytes;
};

} // namespace laminate::delegation

#endif // LAMINATE_DELEGATION_FOLDED_WIRE_TYPES_HPP
