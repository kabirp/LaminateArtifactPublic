#ifndef LAMINATE_PROTOCOL_PACKED_WIRE_DETAIL_DECODE_POLICY_HPP
#define LAMINATE_PROTOCOL_PACKED_WIRE_DETAIL_DECODE_POLICY_HPP

/// @file decode_policy.hpp
/// @brief Public allocation policy and backend requirements for proof decoding.

#include "laminate/protocol/packed/proof.hpp"

#include <concepts>
#include <cstddef>
#include <cstdint>
#include <span>

namespace laminate::protocol {

/// Caller-owned allocation policy for one canonical packed proof. Trusted
/// circuit/setup dimensions still have to fit these bounds; there is no
/// permissive default suitable for an external process boundary.
struct PackedProofDecodeLimits {
    std::size_t max_proof_bytes = 0;
    std::size_t max_ciphertexts = 0;
    std::size_t max_ciphertext_bytes = 0;
    std::size_t max_total_ciphertext_bytes = 0;
    std::size_t max_collection_elements = 0;
    std::size_t max_total_field_elements = 0;
    std::size_t max_total_digests = 0;
};

template <typename Backend>
concept PackedProofDecodeBackend =
    packing::CoefficientWellFormednessBackend<Backend> &&
    requires(const typename Backend::EvalContext &eval,
             std::span<const std::uint8_t> encoded) {
        { Backend::deserialize_protocol(eval, encoded) } ->
            std::same_as<typename Backend::Ciphertext>;
    };

template <typename Backend, typename Context>
concept PackedProofDecodeContext =
    packing::CoefficientWellFormednessBackend<Backend> &&
    requires(const Context &context,
             std::span<const std::uint8_t> encoded) {
        { Backend::slot_count(context) } ->
            std::convertible_to<std::size_t>;
        // This is the strict inverse of the backend's canonical protocol
        // encoding; the backend must reject alternate encodings.
        { Backend::deserialize_protocol(context, encoded) } ->
            std::same_as<typename Backend::Ciphertext>;
    };

} // namespace laminate::protocol

#endif // LAMINATE_PROTOCOL_PACKED_WIRE_DETAIL_DECODE_POLICY_HPP
