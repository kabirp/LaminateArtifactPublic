#ifndef LAMINATE_DELEGATION_BASE_TRANSPORT_MESSAGES_HPP
#define LAMINATE_DELEGATION_BASE_TRANSPORT_MESSAGES_HPP

/// @file transport/messages.hpp
/// @brief Behavior-free messages for one delegated LaminateBase execution.

#include "laminate/payload/trace/encrypted_trace.hpp"
#include "laminate/protocol/base.hpp"

#include <vector>

namespace laminate::delegation {

/// Compact result returned by the evaluation role. Circuit-public values
/// remain plaintext; private values remain ciphertext-backed.
template <fhe::FheBackend Backend> struct BaseFheOutput {
    payload::LayerDimensions dimensions;
    std::vector<fhe::FheValue<Backend>> values;
};

/// Sole client-to-server message for one Wide payload execution.
template <fhe::FheBackend Backend> struct BaseRequest {
    Digest setup_id{};
    Digest session_id{};
    Digest circuit_id{};
    Digest trace_id{};
    std::vector<typename Backend::Ciphertext> encrypted_inputs;
};

/// Sole server-to-client message. The encrypted output fixes the public
/// Fiat--Shamir statement from which both roles derive the output point; the
/// client decrypts that output to recover the corresponding claim value.
template <fhe::FheBackend Backend> struct BaseResponse {
    Digest setup_id{};
    Digest session_id{};
    Digest circuit_id{};
    Digest trace_id{};
    BaseFheOutput<Backend> output;
    protocol::LaminateBaseProof<Backend> proof;
};

} // namespace laminate::delegation

#endif // LAMINATE_DELEGATION_BASE_TRANSPORT_MESSAGES_HPP
