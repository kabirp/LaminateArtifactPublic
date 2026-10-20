#ifndef LAMINATE_DELEGATION_BASE_STATEMENT_DIGEST_HPP
#define LAMINATE_DELEGATION_BASE_STATEMENT_DIGEST_HPP

/// @file statement/digest.hpp
/// @brief Canonical encrypted-statement binding for one-round Base delegation.

#include "laminate/delegation/base/transport/messages.hpp"
#include "laminate/fhe/storage/value_codec.hpp"
#include "laminate/gkr/challenge_limits.hpp"
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
namespace base_statement_detail {

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

inline void hash_bindings(Sha256Hasher &hasher, const Digest &setup_id,
                          const Digest &session_id,
                          const Digest &circuit_id,
                          const Digest &trace_id) {
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

} // namespace base_statement_detail

/// Commit to the exact ordered input ciphertext statement using the same
/// canonical protocol ciphertext encoding used by the Base transcript. This
/// digest is retained privately by both roles; it is not a third wire value.
template <fhe::FheBackend Backend>
Digest base_request_commitment(const BaseRequest<Backend> &request) {
    constexpr const char *operation = "base_request_commitment";
    Sha256Hasher hasher;
    base_statement_detail::hash_label(
        hasher, "LaminateImpl/BaseDelegationRequestStatement/v1", operation);
    base_statement_detail::hash_bindings(
        hasher, request.setup_id, request.session_id, request.circuit_id,
        request.trace_id);
    base_statement_detail::hash_size(
        hasher, request.encrypted_inputs.size(), operation);
    for (const typename Backend::Ciphertext &ciphertext :
         request.encrypted_inputs) {
        const std::vector<std::uint8_t> encoded =
            Backend::serialize(ciphertext);
        if (encoded.empty()) {
            throw std::invalid_argument(
                "base_request_commitment: backend produced an empty "
                "ciphertext");
        }
        base_statement_detail::hash_bytes(hasher, encoded, operation);
    }
    return hasher.finish();
}

/// Bind the complete encrypted instance: the committed request, all public
/// execution identifiers, exact output geometry, and every canonical public-
/// or-encrypted output value in live-wire order.
template <fhe::FheBackend Backend>
Digest base_encrypted_statement_digest(
    const Digest &request_commitment, const Digest &setup_id,
    const Digest &session_id, const Digest &circuit_id,
    const Digest &trace_id, const BaseFheOutput<Backend> &output) {
    constexpr const char *operation =
        "base_encrypted_statement_digest";
    Sha256Hasher hasher;
    base_statement_detail::hash_label(
        hasher, "LaminateImpl/BaseDelegationEncryptedStatement/v1",
        operation);
    hasher.update(request_commitment);
    base_statement_detail::hash_bindings(
        hasher, setup_id, session_id, circuit_id, trace_id);
    base_statement_detail::hash_dimensions(
        hasher, output.dimensions, operation);
    base_statement_detail::hash_size(
        hasher, output.values.size(), operation);
    for (const fhe::FheValue<Backend> &value : output.values) {
        const std::vector<std::uint8_t> encoded =
            fhe::encode_canonical_fhe_value<Backend>(value, operation);
        base_statement_detail::hash_bytes(hasher, encoded, operation);
    }
    return hasher.finish();
}

template <fhe::FheBackend Backend>
Digest base_encrypted_statement_digest(
    const BaseRequest<Backend> &request,
    const BaseFheOutput<Backend> &output) {
    return base_encrypted_statement_digest<Backend>(
        base_request_commitment(request), request.setup_id,
        request.session_id, request.circuit_id, request.trace_id, output);
}

/// Absorb the complete encrypted statement and sample the initial Base GKR
/// point. The server can derive this point without decrypting the output; the
/// client later computes only the corresponding plaintext claim value.
inline std::vector<Fpk> derive_base_output_point(
    Transcript &transcript, const Digest &statement_digest,
    std::size_t coordinate_count) {
    gkr::validate_challenge_block_size(coordinate_count);
    if constexpr (sizeof(std::size_t) > sizeof(std::uint64_t)) {
        if (coordinate_count >
            std::numeric_limits<std::uint64_t>::max()) {
            throw std::overflow_error(
                "derive_base_output_point: coordinate count does not fit "
                "u64");
        }
    }
    transcript.observe(
        "laminate/base/encrypted-statement/v1",
        std::span<const std::uint8_t>(statement_digest));
    transcript.observe(
        "laminate/base/output-point-coordinate-count/v1",
        static_cast<std::uint64_t>(coordinate_count));
    return transcript.challenge_vector(coordinate_count);
}

} // namespace laminate::delegation

#endif // LAMINATE_DELEGATION_BASE_STATEMENT_DIGEST_HPP
