#ifndef LAMINATE_FHE_STORAGE_CIPHERTEXT_HPP
#define LAMINATE_FHE_STORAGE_CIPHERTEXT_HPP

/// @file ciphertext.hpp
/// @brief Optional backend contract for persistent ciphertext encodings.

#include "laminate/fhe/backend.hpp"
#include "laminate/transcript/hash.hpp"

#include <concepts>
#include <cstdint>
#include <span>
#include <vector>

namespace laminate::fhe {

/// Backends satisfying this optional contract provide a persistent external-
/// memory encoding. The encoding is backend-specific. This base contract is
/// anchored to the retained or independently reloaded evaluation context;
/// `CiphertextStorageContext` below permits a backend to expose the identical
/// envelope through another matching role context as well.
///
/// This remains separate from `FheBackend`: bound-only and experimental
/// backends do not need to define a persistent ciphertext representation.
template <typename Backend>
concept PersistableFheBackend =
    FheBackend<Backend> &&
    requires(const typename Backend::EvalContext &eval,
             const typename Backend::Ciphertext &ciphertext,
             std::span<const std::uint8_t> bytes) {
        /// Stable, public fingerprint of the backend context that owns the
        /// ciphertexts. Real backends bind their encryption-key identity;
        /// key-free test backends bind their complete parameter profile.
        { Backend::storage_context_id(eval) } -> std::same_as<Digest>;
        /// Context-derived upper bound for any valid persistent ciphertext
        /// record. Readers enforce this before allocating an encoded record.
        { Backend::storage_ciphertext_byte_limit(eval) } ->
            std::convertible_to<std::uint64_t>;
        { Backend::serialize_for_storage(eval, ciphertext) } ->
            std::same_as<std::vector<std::uint8_t>>;
        { Backend::deserialize_from_storage(eval, bytes) } ->
            std::same_as<typename Backend::Ciphertext>;
    };

/// A role-owned context that can read and write the backend's canonical
/// ciphertext envelope. The ordinary persistence contract above guarantees
/// this for `EvalContext`; process-message codecs may additionally use a
/// matching client context without acquiring server evaluation keys.
template <typename Backend, typename Context>
concept CiphertextStorageContext =
    PersistableFheBackend<Backend> &&
    requires(const Context &context,
             const typename Backend::Ciphertext &ciphertext,
             std::span<const std::uint8_t> bytes) {
        { Backend::slot_count(context) } ->
            std::convertible_to<std::size_t>;
        { Backend::storage_context_id(context) } -> std::same_as<Digest>;
        { Backend::serialize_for_storage(context, ciphertext) } ->
            std::same_as<std::vector<std::uint8_t>>;
        { Backend::deserialize_from_storage(context, bytes) } ->
            std::same_as<typename Backend::Ciphertext>;
    };

/// Decode a ciphertext record that has already crossed a complete storage
/// validation boundary and remains in a caller-private artifact.
///
/// The ordinary persistence decoder is the trust-boundary API. This helper is
/// only for repeated reads of bytes that were either accepted by that decoder
/// during artifact open or emitted canonically by the same process. Backends
/// may skip redundant canonicality work on this path; backends without a
/// specialized implementation retain the strict decoder.
template <PersistableFheBackend Backend>
typename Backend::Ciphertext deserialize_validated_private_ciphertext(
    const typename Backend::EvalContext &eval,
    std::span<const std::uint8_t> bytes) {
    if constexpr (requires {
                      {
                          Backend::deserialize_validated_private_storage(
                              eval, bytes)
                      } -> std::same_as<typename Backend::Ciphertext>;
                  }) {
        return Backend::deserialize_validated_private_storage(eval, bytes);
    } else {
        return Backend::deserialize_from_storage(eval, bytes);
    }
}

} // namespace laminate::fhe

#endif // LAMINATE_FHE_STORAGE_CIPHERTEXT_HPP
