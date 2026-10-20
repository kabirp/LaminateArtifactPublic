#ifndef LAMINATE_DELEGATION_LANED_MESSAGES_HPP
#define LAMINATE_DELEGATION_LANED_MESSAGES_HPP

/// @file messages.hpp
/// @brief The sole request and response for one delegated Laned evaluation.

#include "laminate/payload/trace/encrypted_trace.hpp"
#include "laminate/protocol/packed/proof.hpp"

#include <vector>

namespace laminate::delegation {

/// Wire-facing payload result. Circuit-public values stay plaintext while
/// private values remain ciphertext-backed.
template <fhe::FheBackend Backend> struct LanedFheOutput {
    payload::LayerDimensions dimensions;
    std::vector<fhe::FheValue<Backend>> values;
};

/// Sole client-to-server message: ciphertexts for the declared payload
/// inputs, bound to the canonical payload/layered-circuit pair.
template <fhe::FheBackend Backend> struct LanedEvaluationRequest {
    Digest setup_id{};
    Digest session_id{};
    Digest circuit_id{};
    Digest trace_id{};
    std::vector<typename Backend::Ciphertext> encrypted_inputs;
};

/// Sole server-to-client message. The exact encrypted output and original
/// request commitment fix the initial proof point. The server therefore never
/// receives a plaintext output claim: the client reconstructs that claim
/// after decrypting this response and releases the output only after proof
/// verification succeeds.
template <packing::CoefficientWellFormednessBackend Backend>
struct LanedResponse {
    Digest setup_id{};
    Digest session_id{};
    Digest circuit_id{};
    Digest trace_id{};
    LanedFheOutput<Backend> output;
    protocol::LaminateLanedProof<Backend> proof;
};

} // namespace laminate::delegation

#endif // LAMINATE_DELEGATION_LANED_MESSAGES_HPP
