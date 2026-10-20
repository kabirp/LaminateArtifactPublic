#ifndef LAMINATE_PAYLOAD_TRACE_FHE_TRACE_ID_HPP
#define LAMINATE_PAYLOAD_TRACE_FHE_TRACE_ID_HPP

/// @file fhe_trace_id.hpp
/// @brief Public identifier for one encrypted-input payload execution.

#include "laminate/fhe/backend.hpp"
#include "laminate/payload/compiler.hpp"
#include "laminate/payload/setup/encoding.hpp"
#include "laminate/transcript/hash.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace laminate::payload {

/// Fast trace-identity construction for callers that already own a
/// setup-certified circuit identity and input count.
namespace prevalidated_trace_identity {

inline std::array<std::uint8_t, 8> encode_u64(std::size_t value) {
    if (value > std::numeric_limits<std::uint64_t>::max()) {
        throw std::overflow_error(
            "FHE-evaluated trace digest: size does not fit u64");
    }
    const auto encoded = static_cast<std::uint64_t>(value);
    std::array<std::uint8_t, 8> output{};
    for (std::size_t byte = 0; byte < 8; ++byte) {
        output[byte] = static_cast<std::uint8_t>(
            (encoded >> (8U * byte)) & std::uint64_t{0xff});
    }
    return output;
}

inline void hash_size(Sha256Hasher &hasher, std::size_t value) {
    const auto encoded = encode_u64(value);
    hasher.update(encoded);
}

inline void hash_label(Sha256Hasher &hasher, std::string_view label) {
    hash_size(hasher, label.size());
    hasher.update(std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t *>(label.data()),
        label.size()));
}

template <fhe::FheBackend Backend>
Digest validated_fhe_evaluated_trace_id(
    const Digest &circuit_id, std::size_t expected_input_count,
    std::span<const typename Backend::Ciphertext> encrypted_inputs) {
    if (encrypted_inputs.size() != expected_input_count) {
        throw std::invalid_argument(
            "fhe_evaluated_trace_id: encrypted input count mismatch");
    }

    Sha256Hasher hasher;
    hash_label(hasher, "LaminateImpl/FheEvaluatedTrace/v1");
    hasher.update(circuit_id);
    hash_size(hasher, encrypted_inputs.size());
    for (const typename Backend::Ciphertext &ciphertext : encrypted_inputs) {
        const std::vector<std::uint8_t> bytes = Backend::serialize(ciphertext);
        if (bytes.empty()) {
            throw std::invalid_argument(
                "fhe_evaluated_trace_id: backend produced an empty "
                "ciphertext encoding");
        }
        hash_size(hasher, bytes.size());
        hasher.update(bytes);
    }
    return hasher.finish();
}

} // namespace prevalidated_trace_identity

/// Stable identifier for the exact input ciphertexts supplied to one
/// homomorphic execution. The client can compute it before sending the inputs;
/// the server recomputes it without learning their plaintexts.
template <fhe::FheBackend Backend>
Digest fhe_evaluated_trace_id(
    const PayloadCircuit &payload, const LayeredCircuit &circuit,
    std::span<const typename Backend::Ciphertext> encrypted_inputs) {
    validate_compilation_pair(payload, circuit);
    if (!(payload.shape == circuit.shape) ||
        payload.input_count != circuit.payload_input_count ||
        encrypted_inputs.size() != payload.input_count) {
        throw std::invalid_argument(
            "fhe_evaluated_trace_id: circuit or input shape mismatch");
    }

    const Digest circuit_id = combined_digest(payload, circuit);
    return prevalidated_trace_identity::validated_fhe_evaluated_trace_id<Backend>(
        circuit_id, payload.input_count, encrypted_inputs);
}

} // namespace laminate::payload

#endif // LAMINATE_PAYLOAD_TRACE_FHE_TRACE_ID_HPP
