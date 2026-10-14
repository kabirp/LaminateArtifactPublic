#ifndef LAMINATE_DELEGATION_BASE_REFERENCE_CLIENT_HPP
#define LAMINATE_DELEGATION_BASE_REFERENCE_CLIENT_HPP

/// @file reference/client.hpp
/// @brief Uncached Base client transitions for small resident test fixtures.
///
/// Production callers use the canonical functions in `base/client.hpp`, which
/// require a `CertifiedBaseClientSetup`. These explicit reference functions
/// intentionally repeat static validation on every call.

#include "laminate/delegation/base/client.hpp"
#include "laminate/gkr/detail/base/geometry/circuit.hpp"
#include "laminate/protocol/reference/base.hpp"

namespace laminate::delegation::reference {

namespace resident_client_detail {

template <fhe::FheBackend Backend>
void validate_start(const payload::PayloadCircuit &payload,
                    const payload::LayeredCircuit &circuit,
                    const ClientSetup<Backend> &client) {
    client.public_setup.validate(payload, circuit);
    if (payload.shape.kind != payload::PayloadKind::Wide ||
        circuit.shape.kind != payload::PayloadKind::Wide) {
        throw std::invalid_argument(
            "begin_base_request_resident_reference: expected a Wide payload");
    }
}

template <fhe::FheBackend Backend>
BaseClientRequestStart<Backend> bind_session(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const ClientSetup<Backend> &client,
    std::span<const fhe::SlotVector> logical_inputs,
    std::vector<typename Backend::Ciphertext> encrypted_inputs,
    BaseClientNonce nonce) {
    std::vector<fhe::SlotVector> plaintext_input_layer =
        payload::prevalidated_plain_trace::make_plain_input_layer_from_validated_circuit(
            circuit, logical_inputs);
    const Digest circuit_id = client.public_setup.circuit_digest;
    const Digest trace_id =
        payload::prevalidated_trace_identity::validated_fhe_evaluated_trace_id<Backend>(
            circuit_id, payload.input_count, encrypted_inputs);
    const Digest setup_id = setup_digest(client.public_setup);
    const Digest nonce_bytes =
        base_client_detail::ClientStateAccess::consume_nonce(nonce);
    if (base_client_detail::all_zero(nonce_bytes)) {
        throw std::invalid_argument(
            "begin_base_request_resident_reference: nonce was consumed");
    }
    const Digest session_id = base_client_detail::derive_session_id(
        nonce_bytes, setup_id, circuit_id, trace_id);
    BaseRequest<Backend> request{
        setup_id, session_id, circuit_id, trace_id,
        std::move(encrypted_inputs)};
    const Digest request_commitment = base_request_commitment<Backend>(request);
    return BaseClientRequestStart<Backend>{
        std::move(request),
        BaseClientAwaitingResponse{
            setup_id, session_id, circuit_id, trace_id,
            request_commitment, std::move(plaintext_input_layer)}};
}

} // namespace resident_client_detail

/// Encrypt one complete SIMD vector per Wide input for a resident reference
/// fixture and bind it to a one-use session.
template <fhe::FheBackend Backend>
BaseClientRequestStart<Backend> begin_base_request_resident_reference(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const ClientSetup<Backend> &client,
    std::span<const fhe::SlotVector> logical_inputs,
    BaseClientNonce nonce) {
    resident_client_detail::validate_start(payload, circuit, client);
    std::vector<typename Backend::Ciphertext> encrypted_inputs =
        payload::prevalidated_input_encryption::
            encrypt_wide_inputs_from_validated_payload<Backend>(
                client.context, payload, logical_inputs);
    return resident_client_detail::bind_session(
        payload, circuit, client, logical_inputs,
        std::move(encrypted_inputs), std::move(nonce));
}

template <fhe::FheBackend Backend>
std::optional<BaseClientOpenedResponse>
open_base_response_resident_reference(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const ClientSetup<Backend> &client,
    BaseClientAwaitingResponse state,
    const BaseResponse<Backend> &response, Transcript &transcript) {
    try {
        client.public_setup.validate(payload, circuit);
        const Digest setup_id = setup_digest(client.public_setup);
        const Digest circuit_id = payload::combined_digest(payload, circuit);
        const payload::LayerDimensions output_dimensions =
            payload::layer_dimensions(circuit.layers.front());
        const payload::LayerWireSupport output_support =
            payload::canonical_layer_wire_support(circuit, 0);
        if (base_client_detail::ClientStateAccess::setup_id(state) !=
                setup_id ||
            response.setup_id != setup_id ||
            base_client_detail::ClientStateAccess::session_id(state) !=
                response.session_id ||
            base_client_detail::ClientStateAccess::circuit_id(state) !=
                circuit_id ||
            response.circuit_id != circuit_id ||
            base_client_detail::ClientStateAccess::trace_id(state) !=
                response.trace_id ||
            response.output.dimensions != output_dimensions ||
            response.output.values.size() != output_support.live_wire_count) {
            return std::nullopt;
        }
        transcript.observe("delegation-setup-id",
                           std::span<const std::uint8_t>(setup_id));
        transcript.observe(
            "delegation-session-id",
            std::span<const std::uint8_t>(response.session_id));
        const Digest statement_digest =
            base_encrypted_statement_digest<Backend>(
                base_client_detail::ClientStateAccess::request_commitment(
                    state),
                setup_id, response.session_id, circuit_id,
                response.trace_id, response.output);
        std::vector<Fpk> output_point = derive_base_output_point(
            transcript, statement_digest,
            gkr::base_detail::layer_vars(circuit, 0));
        std::vector<fhe::SlotVector> output_layer =
            payload::decrypt_trace_layer<Backend>(
                client.context, circuit, circuit.shape,
                payload::EncryptedTraceLayerView<Backend>{
                    payload::TraceLayerLayout::Wide,
                    response.output.dimensions, 0,
                    response.output.values},
                0);
        gkr::SingleClaim output_claim =
            gkr::make_layer_claim(output_layer, std::move(output_point));
        return base_client_detail::ClientStateAccess::open(
            std::move(state), statement_digest, std::move(output_layer),
            std::move(output_claim));
    } catch (const std::exception &) {
        return std::nullopt;
    }
}

template <fhe::FheBackend Backend>
std::optional<std::vector<fhe::SlotVector>>
verify_opened_base_response_resident_reference(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const ClientSetup<Backend> &client,
    BaseClientOpenedResponse state,
    const BaseResponse<Backend> &response, Transcript &transcript) {
    try {
        client.public_setup.validate(payload, circuit);
        const Digest setup_id = setup_digest(client.public_setup);
        const Digest circuit_id = payload::combined_digest(payload, circuit);
        const payload::LayerDimensions output_dimensions =
            payload::layer_dimensions(circuit.layers.front());
        const payload::LayerWireSupport output_support =
            payload::canonical_layer_wire_support(circuit, 0);
        if (base_client_detail::ClientStateAccess::setup_id(state) !=
                setup_id ||
            response.setup_id != setup_id ||
            base_client_detail::ClientStateAccess::session_id(state) !=
                response.session_id ||
            base_client_detail::ClientStateAccess::circuit_id(state) !=
                circuit_id ||
            response.circuit_id != circuit_id ||
            base_client_detail::ClientStateAccess::trace_id(state) !=
                response.trace_id ||
            response.output.dimensions != output_dimensions ||
            response.output.values.size() != output_support.live_wire_count ||
            circuit.payload_output_count >
                base_client_detail::ClientStateAccess::output_count(state)) {
            return std::nullopt;
        }
        const Digest statement_digest =
            base_encrypted_statement_digest<Backend>(
                base_client_detail::ClientStateAccess::request_commitment(
                    state),
                setup_id, response.session_id, circuit_id,
                response.trace_id, response.output);
        if (statement_digest !=
                base_client_detail::ClientStateAccess::statement_digest(
                    state) ||
            !protocol::reference::verify_base<Backend>(
                payload, circuit,
                base_client_detail::ClientStateAccess::inputs(state), client,
                payload::TraceProvenance::FheEvaluated, response.trace_id,
                base_client_detail::ClientStateAccess::output_claim(state),
                response.proof, transcript)) {
            return std::nullopt;
        }
        std::vector<fhe::SlotVector> output_layer =
            base_client_detail::ClientStateAccess::take_outputs(state);
        return std::vector<fhe::SlotVector>(
            output_layer.begin(),
            output_layer.begin() + static_cast<std::ptrdiff_t>(
                                       circuit.payload_output_count));
    } catch (const std::exception &) {
        return std::nullopt;
    }
}

template <fhe::FheBackend Backend>
std::optional<std::vector<fhe::SlotVector>>
verify_base_response_resident_reference(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const ClientSetup<Backend> &client,
    BaseClientAwaitingResponse state,
    const BaseResponse<Backend> &response, Transcript &transcript) {
    std::optional<BaseClientOpenedResponse> opened =
        open_base_response_resident_reference<Backend>(
            payload, circuit, client, std::move(state), response, transcript);
    if (!opened) {
        return std::nullopt;
    }
    return verify_opened_base_response_resident_reference<Backend>(
        payload, circuit, client, std::move(*opened), response, transcript);
}

} // namespace laminate::delegation::reference

#endif // LAMINATE_DELEGATION_BASE_REFERENCE_CLIENT_HPP
