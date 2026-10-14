#ifndef LAMINATE_DELEGATION_LANED_CLIENT_RESPONSE_HPP
#define LAMINATE_DELEGATION_LANED_CLIENT_RESPONSE_HPP

/// @file client/response.hpp
/// @brief Laned response binding, proof verification, and output release.

#include "laminate/delegation/laned/client/request.hpp"
#include "laminate/delegation/packed/statement.hpp"
#include "laminate/protocol/laned.hpp"

#include <optional>
#include <utility>
#include <vector>

namespace laminate::delegation {
namespace laned_client_detail {

template <packing::CoefficientWellFormednessBackend Backend>
std::optional<LanedClientOpenedResponse> open_with_client_setup(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const ClientSetup<Backend> &client,
    LanedClientAwaitingResponse state,
    const LanedResponse<Backend> &response, Transcript &transcript) {
    return packed_client_detail::open_response<
        Backend, LanedClientAwaitingResponse,
        LanedClientOpenedResponse, LanedResponse<Backend>,
        ClientStateAccess>(
        payload, circuit, client, std::move(state), response, transcript,
        PackedProtocolVariant::Laned, payload::PayloadKind::Laned,
        payload::TraceLayerLayout::BPeriodic,
        gkr::laned_layer_variables(circuit, 0),
        [&](const std::vector<fhe::SlotVector> &output_layer,
           std::vector<Fpk> output_point) {
            return gkr::make_packed_laned_claim(
                output_layer, gkr::laned_layout(circuit, 0),
                std::move(output_point));
        });
}

template <packing::SignedDigitPackingBackend Backend,
          typename VerifyProof>
std::optional<std::vector<fhe::SlotVector>> verify_opened_with(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const ClientSetup<Backend> &client, LanedClientOpenedResponse state,
    const LanedResponse<Backend> &response, Transcript &transcript,
    VerifyProof &&verify_proof) {
    return packed_client_detail::verify_opened_response<
        Backend, LanedClientOpenedResponse, LanedResponse<Backend>,
        ClientStateAccess>(
        payload, circuit, client, std::move(state), response, transcript,
        PackedProtocolVariant::Laned,
        std::forward<VerifyProof>(verify_proof));
}

template <packing::SignedDigitPackingBackend Backend,
          typename VerifierContext>
    requires packing::PublicCoefficientVerifierContext<
        Backend, VerifierContext>
std::optional<std::vector<fhe::SlotVector>>
verify_opened_with_client_setup(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const VerifierContext &verifier,
    const protocol::LanedVerifierSetup &packing_setup,
    const ClientSetup<Backend> &client, LanedClientOpenedResponse state,
    const LanedResponse<Backend> &response, Transcript &transcript) {
    return verify_opened_with<Backend>(
        payload, circuit, client, std::move(state), response, transcript,
        [&](const LanedClientOpenedResponse &opened,
            Transcript &verification_transcript) {
            return protocol::verify_laned<Backend>(
                payload, circuit, ClientStateAccess::inputs(opened),
                verifier, packing_setup, client,
                payload::TraceProvenance::FheEvaluated, response.trace_id,
                ClientStateAccess::output_claim(opened), response.proof,
                verification_transcript);
        });
}

} // namespace laned_client_detail

template <typename Backend>
    requires packing::CoefficientWellFormednessBackend<Backend> &&
             fhe::PublicVerifierFheBackend<Backend>
std::optional<LanedClientOpenedResponse> open_laned_response(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const PackedClientSetup<Backend> &client,
    LanedClientAwaitingResponse state,
    const LanedResponse<Backend> &response, Transcript &transcript) {
    return laned_client_detail::open_with_client_setup<Backend>(
        payload, circuit, client.client_setup(), std::move(state), response,
        transcript);
}

template <packing::SignedDigitPackingBackend Backend>
    requires fhe::PublicVerifierFheBackend<Backend>
std::optional<std::vector<fhe::SlotVector>>
verify_opened_laned_response(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const protocol::LanedVerifierSetup &packing_setup,
    const PackedClientSetup<Backend> &client,
    LanedClientOpenedResponse state,
    const LanedResponse<Backend> &response, Transcript &transcript) {
    return laned_client_detail::verify_opened_with_client_setup<Backend>(
        payload, circuit, client.verifier_context(), packing_setup,
        client.client_setup(), std::move(state), response, transcript);
}

template <packing::SignedDigitPackingBackend Backend>
    requires fhe::PublicVerifierFheBackend<Backend>
std::optional<std::vector<fhe::SlotVector>> verify_laned_response(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const protocol::LanedVerifierSetup &packing_setup,
    const PackedClientSetup<Backend> &client,
    LanedClientAwaitingResponse state,
    const LanedResponse<Backend> &response, Transcript &transcript) {
    auto opened = open_laned_response<Backend>(
        payload, circuit, client, std::move(state), response, transcript);
    if (!opened) {
        return std::nullopt;
    }
    return verify_opened_laned_response<Backend>(
        payload, circuit, packing_setup, client, std::move(*opened),
        response, transcript);
}

} // namespace laminate::delegation

#endif // LAMINATE_DELEGATION_LANED_CLIENT_RESPONSE_HPP
