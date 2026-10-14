#ifndef LAMINATE_DELEGATION_FOLDED_REFERENCE_CLIENT_HPP
#define LAMINATE_DELEGATION_FOLDED_REFERENCE_CLIENT_HPP

/// @file reference/client.hpp
/// @brief Raw-setup Folded client transitions for resident test fixtures.
///
/// Production callers use `folded/client.hpp` and a `PackedClientSetup`.
/// These explicitly named helpers preserve the uncached reference path used by
/// small tests without placing a same-name overload in the production API.

#include "laminate/delegation/folded/client.hpp"

namespace laminate::delegation::reference {

template <fhe::FheBackend Backend>
FoldedClientRequestStart<Backend> begin_folded_request_resident_reference(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const ClientSetup<Backend> &client,
    std::span<const fhe::SlotVector> logical_inputs,
    FoldedClientNonce nonce) {
    return folded_client_detail::begin_with_client_setup(
        payload, circuit, client, logical_inputs, std::move(nonce));
}

template <packing::CoefficientWellFormednessBackend Backend>
std::optional<FoldedClientOpenedResponse>
open_folded_response_resident_reference(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const ClientSetup<Backend> &client,
    FoldedClientAwaitingResponse state,
    const FoldedResponse<Backend> &response, Transcript &transcript) {
    return folded_client_detail::open_with_client_setup<Backend>(
        payload, circuit, client, std::move(state), response, transcript);
}

template <packing::SignedDigitPackingBackend Backend,
          typename VerifierContext>
    requires packing::PublicCoefficientVerifierContext<
        Backend, VerifierContext>
std::optional<std::vector<fhe::SlotVector>>
verify_opened_folded_response_resident_reference(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const VerifierContext &verifier,
    const protocol::FoldedVerifierSetup &packing_setup,
    const ClientSetup<Backend> &client, FoldedClientOpenedResponse state,
    const FoldedResponse<Backend> &response, Transcript &transcript) {
    return folded_client_detail::verify_opened_with_client_setup<Backend>(
        payload, circuit, verifier, packing_setup, client,
        std::move(state), response, transcript);
}

template <packing::SignedDigitPackingBackend Backend,
          typename VerifierContext>
    requires packing::PublicCoefficientVerifierContext<
        Backend, VerifierContext>
std::optional<std::vector<fhe::SlotVector>>
verify_folded_response_resident_reference(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const VerifierContext &verifier,
    const protocol::FoldedVerifierSetup &packing_setup,
    const ClientSetup<Backend> &client,
    FoldedClientAwaitingResponse state,
    const FoldedResponse<Backend> &response, Transcript &transcript) {
    auto opened = open_folded_response_resident_reference<Backend>(
        payload, circuit, client, std::move(state), response, transcript);
    if (!opened) {
        return std::nullopt;
    }
    return verify_opened_folded_response_resident_reference<Backend>(
        payload, circuit, verifier, packing_setup, client,
        std::move(*opened), response, transcript);
}

} // namespace laminate::delegation::reference

#endif // LAMINATE_DELEGATION_FOLDED_REFERENCE_CLIENT_HPP
