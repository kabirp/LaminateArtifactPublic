#ifndef LAMINATE_DELEGATION_FOLDED_MESSAGES_HPP
#define LAMINATE_DELEGATION_FOLDED_MESSAGES_HPP

/// @file messages.hpp
/// @brief The sole request and response for delegated Folded evaluation.

#include "laminate/payload/trace/encrypted_trace.hpp"
#include "laminate/protocol/folded.hpp"

#include <vector>

namespace laminate::delegation {

/// Compact Wide output in canonical stored-wire order. Public values remain
/// plaintext; private values remain ciphertext-backed.
template <fhe::FheBackend Backend> struct FoldedFheOutput {
    payload::LayerDimensions dimensions;
    std::vector<fhe::FheValue<Backend>> values;
};

/// Sole client-to-server message. It contains only encrypted Wide inputs and
/// the public bindings fixed during preprocessing and session creation.
template <fhe::FheBackend Backend> struct FoldedEvaluationRequest {
    Digest setup_id{};
    Digest session_id{};
    Digest circuit_id{};
    Digest trace_id{};
    std::vector<typename Backend::Ciphertext> encrypted_inputs;
};

/// Sole server-to-client message. The server derives the proof point from the
/// original request commitment and this exact encrypted output. The client
/// reconstructs the plaintext claim locally after decryption and releases
/// outputs only if the proof verifies.
template <packing::CoefficientWellFormednessBackend Backend>
struct FoldedResponse {
    Digest setup_id{};
    Digest session_id{};
    Digest circuit_id{};
    Digest trace_id{};
    FoldedFheOutput<Backend> output;
    protocol::LaminateFoldedProof<Backend> proof;
};

} // namespace laminate::delegation

#endif // LAMINATE_DELEGATION_FOLDED_MESSAGES_HPP
