#ifndef LAMINATE_DELEGATION_BASE_WIRE_TYPES_HPP
#define LAMINATE_DELEGATION_BASE_WIRE_TYPES_HPP

/// @file types.hpp
/// @brief Public decode limits and transport accounting for Base messages.

#include <cstddef>
#include <cstdint>

namespace laminate::delegation {

/// Application-owned resource policy for Base message decoding. There is no
/// permissive default: even trusted circuit-derived lengths must fit it.
struct BaseWireDecodeLimits {
    std::size_t max_message_bytes = 0;
    std::size_t max_ciphertexts = 0;
    std::size_t max_ciphertext_bytes = 0;
    std::size_t max_total_ciphertext_bytes = 0;
    std::size_t max_claim_coordinates = 0;
    std::size_t max_proof_bytes = 0;
    std::size_t max_reductions = 0;
    /// Rounds in one encrypted GKR layer reduction.
    std::size_t max_rounds_per_reduction = 0;
    /// Rounds or product-tree layers in one structured GateMLE subproof.
    /// GateMLE ranges over SIMD slots and sparse-table addresses, so this is
    /// intentionally independent of the GKR ciphertext-index bound above.
    std::size_t max_gate_proof_rounds = 0;
    std::size_t max_partial_gate_values = 0;
    std::size_t max_gate_claims = 0;
    /// Aggregate entries across sparse table targets and, for Wide, the
    /// complete shared honest-column target matrix.
    std::size_t max_gate_target_values = 0;
    std::size_t max_basefold_queries = 0;
    std::size_t max_merkle_path_digests = 0;
    std::size_t max_total_field_elements = 0;
    std::size_t max_total_digests = 0;

    bool operator==(const BaseWireDecodeLimits &) const = default;
};

enum class BaseWireMessageType : std::uint8_t {
    Request = 1,
    Response = 2,
};

namespace base_wire_detail {

/// Exact encoded ciphertext footprint of one logical transport component.
struct CiphertextFootprint {
    std::size_t count = 0;
    std::size_t bytes = 0;
};

/// Per-message ciphertext bounds derived from request and response geometry.
struct BaseWireCiphertextBudget {
    std::size_t max_count_per_message = 0;
    std::size_t max_bytes_per_message = 0;
};

/// Exact byte and message counts collected while writing a Base proof. This
/// is transport diagnostics, not protocol state.
struct ProofTransportSizeBreakdown {
    std::size_t total_bytes = 0;
    std::size_t statement_and_metadata_bytes = 0;
    std::size_t round_message_bytes = 0;
    std::size_t terminal_message_bytes = 0;
    std::size_t partial_gate_mle_bytes = 0;
    std::size_t gate_mle_opening_bytes = 0;
    std::size_t logical_round_messages = 0;
    std::size_t partial_gate_mle_field_elements = 0;
    std::size_t extension_ciphertexts = 0;
    std::size_t base_ciphertexts = 0;
    std::size_t public_plaintext_coefficients = 0;
    std::size_t public_plaintext_field_elements = 0;
};

} // namespace base_wire_detail
} // namespace laminate::delegation

#endif // LAMINATE_DELEGATION_BASE_WIRE_TYPES_HPP
