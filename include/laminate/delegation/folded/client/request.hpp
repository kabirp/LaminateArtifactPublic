#ifndef LAMINATE_DELEGATION_FOLDED_CLIENT_REQUEST_HPP
#define LAMINATE_DELEGATION_FOLDED_CLIENT_REQUEST_HPP

/// @file client/request.hpp
/// @brief Folded input encryption and one-request session binding.

#include "laminate/delegation/folded/client/state_access.hpp"
#include "laminate/delegation/packed/statement.hpp"
#include "laminate/payload/trace/fhe_trace_id.hpp"
#include "laminate/payload/input_encryption.hpp"
#include "laminate/payload/trace/trace_crypto.hpp"

#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

namespace laminate::delegation {
namespace folded_client_detail {

template <fhe::FheBackend Backend>
void validate_evaluation_start(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const ClientSetup<Backend> &client) {
    client.public_setup.validate(payload, circuit);
    if (payload.shape.kind != payload::PayloadKind::Wide ||
        circuit.shape.kind != payload::PayloadKind::Wide) {
        throw std::invalid_argument(
            "begin_folded_request: expected a Wide payload");
    }
}

/// Bind an already-encrypted request. Benchmark adapters use this boundary to
/// time encryption separately from transcript/session bookkeeping.
template <fhe::FheBackend Backend>
FoldedClientRequestStart<Backend> bind_validated_request_session(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const ClientSetup<Backend> &client,
    std::span<const fhe::SlotVector> logical_inputs,
    std::vector<typename Backend::Ciphertext> encrypted_inputs,
    FoldedClientNonce nonce) {
    const Digest circuit_id = client.public_setup.circuit_digest;
    const Digest trace_id =
        payload::prevalidated_trace_identity::validated_fhe_evaluated_trace_id<Backend>(
            circuit_id, payload.input_count, encrypted_inputs);
    const Digest setup_id = setup_digest(client.public_setup);
    const Digest nonce_bytes = ClientStateAccess::consume_nonce(nonce);
    if (all_zero(nonce_bytes)) {
        throw std::invalid_argument(
            "begin_folded_request: client nonce was already consumed");
    }
    const Digest session_id = derive_session_id(
        nonce_bytes, setup_id, circuit_id, trace_id);
    FoldedEvaluationRequest<Backend> request{
        setup_id, session_id, circuit_id, trace_id,
        std::move(encrypted_inputs)};
    const Digest request_commitment = packed_request_commitment<Backend>(
        PackedProtocolVariant::Folded, setup_id, session_id, circuit_id,
        trace_id);
    return FoldedClientRequestStart<Backend>{
        std::move(request),
        FoldedClientAwaitingResponse{
            setup_id, session_id, circuit_id, trace_id, request_commitment,
            payload::prevalidated_plain_trace::make_plain_input_layer_from_validated_circuit(
                circuit, logical_inputs)}};
}

template <fhe::FheBackend Backend>
FoldedClientRequestStart<Backend> begin_with_client_setup(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const ClientSetup<Backend> &client,
    std::span<const fhe::SlotVector> logical_inputs,
    FoldedClientNonce nonce) {
    validate_evaluation_start(payload, circuit, client);
    std::vector<typename Backend::Ciphertext> encrypted_inputs =
        payload::prevalidated_input_encryption::
            encrypt_wide_inputs_from_validated_payload<Backend>(
                client.context, payload, logical_inputs);
    return bind_validated_request_session(
        payload, circuit, client, logical_inputs,
        std::move(encrypted_inputs), std::move(nonce));
}

} // namespace folded_client_detail

template <fhe::PublicVerifierFheBackend Backend>
FoldedClientRequestStart<Backend> begin_folded_request(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const PackedClientSetup<Backend> &client,
    std::span<const fhe::SlotVector> logical_inputs,
    FoldedClientNonce nonce) {
    return folded_client_detail::begin_with_client_setup(
        payload, circuit, client.client_setup(), logical_inputs,
        std::move(nonce));
}

} // namespace laminate::delegation

#endif // LAMINATE_DELEGATION_FOLDED_CLIENT_REQUEST_HPP
