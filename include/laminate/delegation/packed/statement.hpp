#ifndef LAMINATE_DELEGATION_PACKED_STATEMENT_HPP
#define LAMINATE_DELEGATION_PACKED_STATEMENT_HPP

/// @file statement.hpp
/// @brief One-round encrypted-statement binding shared by Folded and Laned.

#include "laminate/fhe/storage/value_codec.hpp"
#include "laminate/gkr/challenge_limits.hpp"
#include "laminate/payload/trace/encrypted_trace.hpp"
#include "laminate/transcript/transcript.hpp"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace laminate::delegation {

enum class PackedProtocolVariant : std::uint8_t { Folded = 1, Laned = 2 };

inline std::string_view
packed_protocol_variant_name(PackedProtocolVariant variant) {
    switch (variant) {
    case PackedProtocolVariant::Folded:
        return "folded";
    case PackedProtocolVariant::Laned:
        return "laned";
    }
    throw std::invalid_argument("unknown packed protocol variant");
}

namespace packed_statement_detail {

inline void hash_u64(Sha256Hasher &hasher, std::uint64_t value) {
    std::uint8_t encoded[8]{};
    for (std::size_t byte = 0; byte < sizeof(encoded); ++byte) {
        encoded[byte] = static_cast<std::uint8_t>(
            (value >> (8U * byte)) & std::uint64_t{0xff});
    }
    hasher.update(encoded);
}

inline void hash_size(Sha256Hasher &hasher, std::size_t value,
                      const char *operation) {
    if constexpr (sizeof(std::size_t) > sizeof(std::uint64_t)) {
        if (value > std::numeric_limits<std::uint64_t>::max()) {
            throw std::overflow_error(std::string(operation) +
                                      ": size does not fit u64");
        }
    }
    hash_u64(hasher, static_cast<std::uint64_t>(value));
}

inline void hash_bytes(Sha256Hasher &hasher,
                       std::span<const std::uint8_t> bytes,
                       const char *operation) {
    hash_size(hasher, bytes.size(), operation);
    hasher.update(bytes);
}

inline void hash_label(Sha256Hasher &hasher, std::string_view label,
                       const char *operation) {
    hash_bytes(
        hasher,
        std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t *>(label.data()),
            label.size()),
        operation);
}

inline void hash_bindings(Sha256Hasher &hasher,
                          PackedProtocolVariant variant,
                          const Digest &setup_id,
                          const Digest &session_id,
                          const Digest &circuit_id,
                          const Digest &trace_id) {
    const std::uint8_t encoded_variant =
        static_cast<std::uint8_t>(variant);
    hasher.update(std::span<const std::uint8_t>(&encoded_variant, 1));
    hasher.update(setup_id);
    hasher.update(session_id);
    hasher.update(circuit_id);
    hasher.update(trace_id);
}

inline void hash_dimensions(Sha256Hasher &hasher,
                            const payload::LayerDimensions &dimensions,
                            const char *operation) {
    hash_size(hasher, dimensions.logical_size, operation);
    hash_size(hasher, dimensions.padded_size, operation);
    hash_size(hasher, dimensions.payload_size, operation);
    hash_size(hasher, dimensions.forward_size, operation);
}

} // namespace packed_statement_detail

/// Commit to the sole client request. Both roles retain this digest; it is not
/// an additional protocol message. `trace_id` already commits to the exact
/// ordered ciphertext encodings, so hashing those encodings again here would
/// add serialization work without adding a binding.
template <fhe::FheBackend Backend>
Digest packed_request_commitment(
    PackedProtocolVariant variant, const Digest &setup_id,
    const Digest &session_id, const Digest &circuit_id,
    const Digest &trace_id) {
    constexpr const char *operation = "packed_request_commitment";
    Sha256Hasher hasher;
    packed_statement_detail::hash_label(
        hasher, "LaminateImpl/PackedDelegationRequestStatement/v2",
        operation);
    packed_statement_detail::hash_bindings(
        hasher, variant, setup_id, session_id, circuit_id, trace_id);
    return hasher.finish();
}

/// Bind the request commitment and exact ordered encrypted output. The server
/// can derive the proof point from this digest without decrypting anything.
template <fhe::FheBackend Backend>
Digest packed_encrypted_statement_digest(
    PackedProtocolVariant variant, const Digest &request_commitment,
    const Digest &setup_id, const Digest &session_id,
    const Digest &circuit_id, const Digest &trace_id,
    const payload::LayerDimensions &output_dimensions,
    std::span<const fhe::FheValue<Backend>> output_values) {
    constexpr const char *operation =
        "packed_encrypted_statement_digest";
    Sha256Hasher hasher;
    packed_statement_detail::hash_label(
        hasher, "LaminateImpl/PackedDelegationEncryptedStatement/v1",
        operation);
    packed_statement_detail::hash_bindings(
        hasher, variant, setup_id, session_id, circuit_id, trace_id);
    hasher.update(request_commitment);
    packed_statement_detail::hash_dimensions(
        hasher, output_dimensions, operation);
    packed_statement_detail::hash_size(
        hasher, output_values.size(), operation);
    for (const fhe::FheValue<Backend> &value : output_values) {
        const std::vector<std::uint8_t> encoded =
            fhe::encode_canonical_fhe_value<Backend>(value, operation);
        packed_statement_detail::hash_bytes(hasher, encoded, operation);
    }
    return hasher.finish();
}

/// Derive the initial packed-GKR point from the complete encrypted statement.
/// The variant is absorbed a second time as explicit transcript domain
/// separation, so a digest cannot be replayed across Folded and Laned.
inline std::vector<Fpk> derive_packed_output_point(
    Transcript &transcript, PackedProtocolVariant variant,
    const Digest &statement_digest, std::size_t coordinate_count) {
    gkr::validate_challenge_block_size(coordinate_count);
    if constexpr (sizeof(std::size_t) > sizeof(std::uint64_t)) {
        if (coordinate_count >
            std::numeric_limits<std::uint64_t>::max()) {
            throw std::overflow_error(
                "derive_packed_output_point: coordinate count does not fit "
                "u64");
        }
    }
    transcript.observe(
        "laminate/packed/variant/v1",
        std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t *>(
                packed_protocol_variant_name(variant).data()),
            packed_protocol_variant_name(variant).size()));
    transcript.observe(
        "laminate/packed/encrypted-statement/v1",
        std::span<const std::uint8_t>(statement_digest));
    transcript.observe(
        "laminate/packed/output-point-coordinate-count/v1",
        static_cast<std::uint64_t>(coordinate_count));
    return transcript.challenge_vector(coordinate_count);
}

/// Bind one delegation session before deriving either the encrypted
/// statement point or any proof challenges.
inline void observe_packed_delegation_bindings(
    Transcript &transcript, const Digest &setup_id,
    const Digest &session_id) {
    transcript.observe(
        "delegation-setup-id",
        std::span<const std::uint8_t>(setup_id));
    transcript.observe(
        "delegation-session-id",
        std::span<const std::uint8_t>(session_id));
}

} // namespace laminate::delegation

#endif // LAMINATE_DELEGATION_PACKED_STATEMENT_HPP
