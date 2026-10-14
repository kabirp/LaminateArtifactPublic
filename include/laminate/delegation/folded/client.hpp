#ifndef LAMINATE_DELEGATION_FOLDED_CLIENT_HPP
#define LAMINATE_DELEGATION_FOLDED_CLIENT_HPP

/// @file client.hpp
/// @brief Declaration-first one-request/one-response Folded client lifecycle.
///
/// Read this file in order: create one-use entropy, encrypt one request, open
/// the sole response without releasing plaintext, then verify and release.
/// The open and verify transitions consume their move-only state even on
/// rejection. Continue with the same transcript after a successful open;
/// failed attempts must not reuse that session or its partially used transcript.

#include "laminate/delegation/folded/session/state.hpp"
#include "laminate/protocol/folded.hpp"

#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace laminate::delegation {

/// Condense at least 256 bits of client CSPRNG output into a one-use nonce.
inline FoldedClientNonce
make_folded_client_nonce(std::span<const std::uint8_t> random_bytes);

// ---- Request: encrypt Wide inputs and bind the sole request.

template <fhe::PublicVerifierFheBackend Backend>
FoldedClientRequestStart<Backend> begin_folded_request(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const PackedClientSetup<Backend> &client,
    std::span<const fhe::SlotVector> logical_inputs,
    FoldedClientNonce nonce);

// ---- Open: bind and decrypt the response, but expose no plaintext yet.

template <typename Backend>
    requires packing::CoefficientWellFormednessBackend<Backend> &&
             fhe::PublicVerifierFheBackend<Backend>
std::optional<FoldedClientOpenedResponse> open_folded_response(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const PackedClientSetup<Backend> &client,
    FoldedClientAwaitingResponse state,
    const FoldedResponse<Backend> &response, Transcript &transcript);

// ---- Verify: check GKR and transcript packing, then release outputs.

template <packing::SignedDigitPackingBackend Backend>
    requires fhe::PublicVerifierFheBackend<Backend>
std::optional<std::vector<fhe::SlotVector>>
verify_opened_folded_response(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const protocol::FoldedVerifierSetup &packing_setup,
    const PackedClientSetup<Backend> &client,
    FoldedClientOpenedResponse state,
    const FoldedResponse<Backend> &response, Transcript &transcript);

/// Convenience composition of open and verify. Output decryption still occurs
/// exactly once and plaintext is released only after complete acceptance.
template <packing::SignedDigitPackingBackend Backend>
    requires fhe::PublicVerifierFheBackend<Backend>
std::optional<std::vector<fhe::SlotVector>> verify_folded_response(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const protocol::FoldedVerifierSetup &packing_setup,
    const PackedClientSetup<Backend> &client,
    FoldedClientAwaitingResponse state,
    const FoldedResponse<Backend> &response, Transcript &transcript);

} // namespace laminate::delegation

#include "laminate/delegation/folded/client/api_impl.hpp"

#endif // LAMINATE_DELEGATION_FOLDED_CLIENT_HPP
