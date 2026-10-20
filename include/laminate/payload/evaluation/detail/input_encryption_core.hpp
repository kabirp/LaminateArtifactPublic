#ifndef LAMINATE_PAYLOAD_EVALUATION_DETAIL_INPUT_ENCRYPTION_CORE_HPP
#define LAMINATE_PAYLOAD_EVALUATION_DETAIL_INPUT_ENCRYPTION_CORE_HPP

/// @file input_encryption_core.hpp
/// @brief Shared physical-slot expansion and encryption for payload inputs.

#include "laminate/fhe/backend.hpp"
#include "laminate/payload/evaluation/slot_encoding.hpp"

#include <span>
#include <stdexcept>
#include <vector>

namespace laminate::payload::prevalidated_input_encryption {

/// Encrypt already-validated logical inputs using the payload's physical SIMD
/// layout. Laned and Wide entry points supply their own protocol-facing shape
/// checks and diagnostics before reaching this common loop.
template <fhe::FheBackend Backend>
std::vector<typename Backend::Ciphertext> encrypt_payload_inputs(
    const typename Backend::ClientContext &client,
    const PayloadCircuit &payload,
    std::span<const fhe::SlotVector> logical_inputs) {
    if (Backend::slot_count(client) != payload.shape.slot_count ||
        logical_inputs.size() != payload.input_count) {
        throw std::invalid_argument(
            "payload input encryption: input or backend shape mismatch");
    }

    std::vector<typename Backend::Ciphertext> encrypted_inputs;
    encrypted_inputs.reserve(logical_inputs.size());
    for (const fhe::SlotVector &input : logical_inputs) {
        encrypted_inputs.push_back(
            Backend::encrypt(client,
                             expand_for_encryption(payload.shape, input)));
    }
    return encrypted_inputs;
}

} // namespace laminate::payload::prevalidated_input_encryption

#endif // LAMINATE_PAYLOAD_EVALUATION_DETAIL_INPUT_ENCRYPTION_CORE_HPP
