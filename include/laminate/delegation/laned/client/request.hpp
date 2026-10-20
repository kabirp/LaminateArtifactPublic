#ifndef LAMINATE_DELEGATION_LANED_CLIENT_REQUEST_HPP
#define LAMINATE_DELEGATION_LANED_CLIENT_REQUEST_HPP

/// @file client/request.hpp
/// @brief Laned input encryption and one-request session binding.

#include "laminate/delegation/laned/client/state_access.hpp"
#include "laminate/delegation/packed/statement.hpp"
#include "laminate/payload/trace/fhe_trace_id.hpp"
#include "laminate/payload/input_encryption.hpp"
#include "laminate/payload/trace/trace_crypto.hpp"

#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

namespace laminate::delegation {
namespace laned_client_detail {

template <fhe::FheBackend Backend>
void validate_evaluation_start(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const ClientSetup<Backend> &client) {
    client.public_setup.validate(payload, circuit);
}

/// Bind an already-encrypted request. Benchmark adapters use this boundary to
/// time encryption separately from transcript/session bookkeeping.
template <fhe::FheBackend Backend>
LanedClientRequestStart<Backend> bind_validated_request_session(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const ClientSetup<Backend> &client,
    std::span<const fhe::SlotVector> logical_inputs,
    std::vector<typename Backend::Ciphertext> encrypted_inputs,
    LanedClientNonce nonce) {
    const Digest circuit_id = client.public_setup.circuit_digest;
    const Digest trace_id =
        payload::prevalidated_trace_identity::validated_fhe_evaluated_trace_id<Backend>(
            circuit_id, payload.input_count, encrypted_inputs);
    const Digest setup_id = setup_digest(client.public_setup);
    const Digest nonce_bytes = ClientStateAccess::consume_nonce(nonce);
    if (all_zero(nonce_bytes)) {
        throw std::invalid_argument(
            "begin_laned_request: client nonce was already consumed");
    }
    const Digest session_id = derive_session_id(
        nonce_bytes, setup_id, circuit_id, trace_id);
    LanedEvaluationRequest<Backend> request{
        setup_id, session_id, circuit_id, trace_id,
        std::move(encrypted_inputs)};
    const Digest request_commitment = packed_request_commitment<Backend>(
        PackedProtocolVariant::Laned, setup_id, session_id, circuit_id,
        trace_id);
    return LanedClientRequestStart<Backend>{
        std::move(request),
        LanedClientAwaitingResponse{
            setup_id, session_id, circuit_id, trace_id, request_commitment,
            payload::prevalidated_plain_trace::make_plain_input_layer_from_validated_circuit(
                circuit, logical_inputs)}};
}

template <fhe::FheBackend Backend>
LanedClientRequestStart<Backend> begin_with_client_setup(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const ClientSetup<Backend> &client,
    std::span<const fhe::SlotVector> logical_inputs,
    LanedClientNonce nonce) {
    validate_evaluation_start(payload, circuit, client);
    std::vector<typename Backend::Ciphertext> encrypted_inputs =
        payload::prevalidated_input_encryption::
            encrypt_laned_inputs_from_validated_payload<Backend>(
                client.context, payload, logical_inputs);
    return bind_validated_request_session(
        payload, circuit, client, logical_inputs,
        std::move(encrypted_inputs), std::move(nonce));
}

} // namespace laned_client_detail

template <fhe::PublicVerifierFheBackend Backend>
LanedClientRequestStart<Backend> begin_laned_request(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const PackedClientSetup<Backend> &client,
    std::span<const fhe::SlotVector> logical_inputs,
    LanedClientNonce nonce) {
    return laned_client_detail::begin_with_client_setup(
        payload, circuit, client.client_setup(), logical_inputs,
        std::move(nonce));
}

} // namespace laminate::delegation

#endif // LAMINATE_DELEGATION_LANED_CLIENT_REQUEST_HPP
