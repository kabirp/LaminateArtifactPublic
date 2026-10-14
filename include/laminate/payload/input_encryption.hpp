#ifndef LAMINATE_PAYLOAD_INPUT_ENCRYPTION_HPP
#define LAMINATE_PAYLOAD_INPUT_ENCRYPTION_HPP

/// @file input_encryption.hpp
/// @brief Client-side encryption of logical payload inputs.

#include "laminate/payload/evaluation/detail/input_encryption_core.hpp"

#include <span>
#include <stdexcept>
#include <vector>

namespace laminate::payload {

/// Fast client encryption for role adapters whose payload was certified
/// during preprocessing.
namespace prevalidated_input_encryption {

/// Preprocessing and certified online states have already paid the linear
/// payload-validation cost. These typed adapters retain the cheap online path
/// while still enforcing the requested SIMD layout and input dimensions.
template <fhe::FheBackend Backend>
std::vector<typename Backend::Ciphertext>
encrypt_laned_inputs_from_validated_payload(
    const typename Backend::ClientContext &client,
    const PayloadCircuit &payload,
    std::span<const fhe::SlotVector> logical_inputs) {
    if (payload.shape.kind != PayloadKind::Laned) {
        throw std::invalid_argument(
            "encrypt_laned_payload_inputs requires a Laned payload");
    }
    return encrypt_payload_inputs<Backend>(client, payload, logical_inputs);
}

template <fhe::FheBackend Backend>
std::vector<typename Backend::Ciphertext>
encrypt_wide_inputs_from_validated_payload(
    const typename Backend::ClientContext &client,
    const PayloadCircuit &payload,
    std::span<const fhe::SlotVector> logical_inputs) {
    if (payload.shape.kind != PayloadKind::Wide) {
        throw std::invalid_argument(
            "encrypt_wide_payload_inputs: expected a Wide payload");
    }
    return encrypt_payload_inputs<Backend>(client, payload, logical_inputs);
}

} // namespace prevalidated_input_encryption

/// Encrypt the logical inputs for a Laned payload. Each B-lane value is
/// repeated over all physical SIMD chunks before encryption.
template <fhe::FheBackend Backend>
std::vector<typename Backend::Ciphertext> encrypt_laned_payload_inputs(
    const typename Backend::ClientContext &client,
    const PayloadCircuit &payload,
    std::span<const fhe::SlotVector> logical_inputs) {
    payload.validate();
    return prevalidated_input_encryption::
        encrypt_laned_inputs_from_validated_payload<Backend>(
            client, payload, logical_inputs);
}

/// Encrypt one complete SIMD vector per Wide payload input wire.
template <fhe::FheBackend Backend>
std::vector<typename Backend::Ciphertext> encrypt_wide_payload_inputs(
    const typename Backend::ClientContext &client,
    const PayloadCircuit &payload,
    std::span<const fhe::SlotVector> logical_inputs) {
    payload.validate();
    return prevalidated_input_encryption::
        encrypt_wide_inputs_from_validated_payload<Backend>(
            client, payload, logical_inputs);
}

} // namespace laminate::payload

#endif // LAMINATE_PAYLOAD_INPUT_ENCRYPTION_HPP
