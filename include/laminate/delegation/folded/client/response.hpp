#ifndef LAMINATE_DELEGATION_FOLDED_CLIENT_RESPONSE_HPP
#define LAMINATE_DELEGATION_FOLDED_CLIENT_RESPONSE_HPP

/// @file client/response.hpp
/// @brief Folded response binding, proof verification, and output release.

#include "laminate/delegation/folded/client/request.hpp"
#include "laminate/delegation/packed/statement.hpp"
#include "laminate/gkr/detail/base/geometry/circuit.hpp"
#include "laminate/protocol/folded.hpp"

#include <optional>
#include <utility>
#include <vector>

namespace laminate::delegation {
namespace folded_client_detail {

template <packing::CoefficientWellFormednessBackend Backend>
std::optional<FoldedClientOpenedResponse> open_with_client_setup(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const ClientSetup<Backend> &client,
    FoldedClientAwaitingResponse state,
    const FoldedResponse<Backend> &response, Transcript &transcript) {
    return packed_client_detail::open_response<
        Backend, FoldedClientAwaitingResponse,
        FoldedClientOpenedResponse, FoldedResponse<Backend>,
        ClientStateAccess>(
        payload, circuit, client, std::move(state), response, transcript,
        PackedProtocolVariant::Folded, payload::PayloadKind::Wide,
        payload::TraceLayerLayout::Wide,
        gkr::base_detail::layer_vars(circuit, 0),
        [](const std::vector<fhe::SlotVector> &output_layer,
           std::vector<Fpk> output_point) {
            return gkr::make_layer_claim(
                output_layer, std::move(output_point));
        });
}

template <packing::SignedDigitPackingBackend Backend,
          typename VerifyProof>
std::optional<std::vector<fhe::SlotVector>> verify_opened_with(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const ClientSetup<Backend> &client, FoldedClientOpenedResponse state,
    const FoldedResponse<Backend> &response, Transcript &transcript,
    VerifyProof &&verify_proof) {
    return packed_client_detail::verify_opened_response<
        Backend, FoldedClientOpenedResponse, FoldedResponse<Backend>,
        ClientStateAccess>(
        payload, circuit, client, std::move(state), response, transcript,
        PackedProtocolVariant::Folded,
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
    const protocol::FoldedVerifierSetup &packing_setup,
    const ClientSetup<Backend> &client, FoldedClientOpenedResponse state,
    const FoldedResponse<Backend> &response, Transcript &transcript) {
    return verify_opened_with<Backend>(
        payload, circuit, client, std::move(state), response, transcript,
        [&](const FoldedClientOpenedResponse &opened,
            Transcript &verification_transcript) {
            return protocol::verify_folded<Backend>(
                payload, circuit, ClientStateAccess::inputs(opened),
                verifier, packing_setup, client,
                payload::TraceProvenance::FheEvaluated, response.trace_id,
                ClientStateAccess::output_claim(opened), response.proof,
                verification_transcript);
        });
}

} // namespace folded_client_detail

template <typename Backend>
    requires packing::CoefficientWellFormednessBackend<Backend> &&
             fhe::PublicVerifierFheBackend<Backend>
std::optional<FoldedClientOpenedResponse> open_folded_response(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const PackedClientSetup<Backend> &client,
    FoldedClientAwaitingResponse state,
    const FoldedResponse<Backend> &response, Transcript &transcript) {
    return folded_client_detail::open_with_client_setup<Backend>(
        payload, circuit, client.client_setup(), std::move(state), response,
        transcript);
}

template <packing::SignedDigitPackingBackend Backend>
    requires fhe::PublicVerifierFheBackend<Backend>
std::optional<std::vector<fhe::SlotVector>>
verify_opened_folded_response(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const protocol::FoldedVerifierSetup &packing_setup,
    const PackedClientSetup<Backend> &client,
    FoldedClientOpenedResponse state,
    const FoldedResponse<Backend> &response, Transcript &transcript) {
    return folded_client_detail::verify_opened_with_client_setup<Backend>(
        payload, circuit, client.verifier_context(), packing_setup,
        client.client_setup(), std::move(state), response, transcript);
}

template <packing::SignedDigitPackingBackend Backend>
    requires fhe::PublicVerifierFheBackend<Backend>
std::optional<std::vector<fhe::SlotVector>> verify_folded_response(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const protocol::FoldedVerifierSetup &packing_setup,
    const PackedClientSetup<Backend> &client,
    FoldedClientAwaitingResponse state,
    const FoldedResponse<Backend> &response, Transcript &transcript) {
    auto opened = open_folded_response<Backend>(
        payload, circuit, client, std::move(state), response, transcript);
    if (!opened) {
        return std::nullopt;
    }
    return verify_opened_folded_response<Backend>(
        payload, circuit, packing_setup, client, std::move(*opened),
        response, transcript);
}

} // namespace laminate::delegation

#endif // LAMINATE_DELEGATION_FOLDED_CLIENT_RESPONSE_HPP
