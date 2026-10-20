#ifndef LAMINATE_DELEGATION_BASE_CLIENT_REQUEST_HPP
#define LAMINATE_DELEGATION_BASE_CLIENT_REQUEST_HPP

/// @file client/request.hpp
/// @brief Certified Base input encryption and request/session binding.

#include "laminate/delegation/base/client/state_access.hpp"
#include "laminate/delegation/base/statement/digest.hpp"
#include "laminate/payload/trace/fhe_trace_id.hpp"
#include "laminate/payload/input_encryption.hpp"
#include "laminate/payload/trace/trace_crypto.hpp"
#include "laminate/protocol/setup/base_client.hpp"

#include <span>
#include <utility>
#include <vector>

namespace laminate::delegation {
namespace base_client_detail {

template <fhe::FheBackend Backend>
BaseClientRequestStart<Backend> bind_validated_base_request_session(
    const protocol::CertifiedBaseClientSetup<Backend> &client,
    std::span<const fhe::SlotVector> logical_inputs,
    std::vector<typename Backend::Ciphertext> encrypted_inputs,
    BaseClientNonce nonce) {
    std::vector<fhe::SlotVector> plaintext_input_layer =
        payload::prevalidated_plain_trace::make_plain_input_layer_from_validated_circuit(
            client.circuit(), logical_inputs);
    const Digest trace_id =
        payload::prevalidated_trace_identity::validated_fhe_evaluated_trace_id<Backend>(
            client.circuit_id(), client.payload().input_count,
            encrypted_inputs);
    const Digest nonce_bytes = ClientStateAccess::consume_nonce(nonce);
    if (all_zero(nonce_bytes)) {
        throw std::invalid_argument(
            "begin_base_request: client nonce was already consumed");
    }
    const Digest session_id = derive_session_id(
        nonce_bytes, client.setup_id(), client.circuit_id(), trace_id);
    BaseRequest<Backend> request{
        client.setup_id(), session_id, client.circuit_id(), trace_id,
        std::move(encrypted_inputs)};
    const Digest request_commitment = base_request_commitment<Backend>(request);
    return BaseClientRequestStart<Backend>{
        std::move(request),
        BaseClientAwaitingResponse{
            client.setup_id(), session_id, client.circuit_id(), trace_id,
            request_commitment, std::move(plaintext_input_layer)}};
}

} // namespace base_client_detail

template <fhe::FheBackend Backend>
BaseClientRequestStart<Backend> begin_base_request(
    const protocol::CertifiedBaseClientSetup<Backend> &client,
    std::span<const fhe::SlotVector> logical_inputs,
    BaseClientNonce nonce) {
    std::vector<typename Backend::Ciphertext> encrypted_inputs =
        payload::prevalidated_input_encryption::
            encrypt_wide_inputs_from_validated_payload<Backend>(
                client.context(), client.payload(), logical_inputs);
    return base_client_detail::bind_validated_base_request_session(
        client, logical_inputs, std::move(encrypted_inputs),
        std::move(nonce));
}

} // namespace laminate::delegation

#endif // LAMINATE_DELEGATION_BASE_CLIENT_REQUEST_HPP
