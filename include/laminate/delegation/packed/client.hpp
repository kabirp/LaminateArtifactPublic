#ifndef LAMINATE_DELEGATION_PACKED_CLIENT_HPP
#define LAMINATE_DELEGATION_PACKED_CLIENT_HPP

/// @file client.hpp
/// @brief Recurring authenticated Folded/Laned client transitions.
///
/// Both variants follow the same visible lifecycle: encrypt and bind one
/// request, decode the sole response, open its encrypted output, then verify
/// before releasing plaintext. Decoding establishes canonical structure and
/// bounds; only successful verification authenticates the computation.
/// Variant-specific definitions live in `client/api_impl.hpp`.

#include "laminate/delegation/folded/client.hpp"
#include "laminate/delegation/folded/profiling/client.hpp"
#include "laminate/delegation/folded/wire/codec.hpp"
#include "laminate/delegation/laned/client.hpp"
#include "laminate/delegation/laned/profiling/client.hpp"
#include "laminate/delegation/laned/wire/codec.hpp"
#include "laminate/protocol/packed/online/client.hpp"

#include <optional>
#include <span>
#include <vector>

namespace laminate::delegation {

template <protocol::PackedProofDecodeBackend Backend>
    requires protocol::PackedRolePreprocessingBackend<Backend>
FoldedResponse<Backend> decode_folded_response(
    const protocol::AuthenticatedPackedClientOnlineState<Backend> &client,
    std::span<const std::uint8_t> encoded,
    const FoldedWireDecodeLimits &wire_limits,
    const protocol::PackedProofDecodeLimits &proof_limits,
    payload::TraceProvenance expected_provenance);

template <protocol::PackedProofDecodeBackend Backend>
    requires protocol::PackedRolePreprocessingBackend<Backend>
LanedResponse<Backend> decode_laned_response(
    const protocol::AuthenticatedPackedClientOnlineState<Backend> &client,
    std::span<const std::uint8_t> encoded,
    const LanedWireDecodeLimits &wire_limits,
    const protocol::PackedProofDecodeLimits &proof_limits,
    payload::TraceProvenance expected_provenance);

template <protocol::PackedRolePreprocessingBackend Backend>
std::vector<typename Backend::Ciphertext> encrypt_folded_request_inputs(
    const protocol::AuthenticatedPackedClientOnlineState<Backend> &client,
    std::span<const fhe::SlotVector> logical_inputs);

template <protocol::PackedRolePreprocessingBackend Backend>
FoldedClientRequestStart<Backend> bind_folded_request_session(
    const protocol::AuthenticatedPackedClientOnlineState<Backend> &client,
    std::span<const fhe::SlotVector> logical_inputs,
    std::vector<typename Backend::Ciphertext> encrypted_inputs,
    FoldedClientNonce nonce);

template <protocol::PackedRolePreprocessingBackend Backend>
FoldedClientRequestStart<Backend> begin_folded_request(
    const protocol::AuthenticatedPackedClientOnlineState<Backend> &client,
    std::span<const fhe::SlotVector> logical_inputs,
    FoldedClientNonce nonce);

template <protocol::PackedRolePreprocessingBackend Backend>
std::optional<FoldedClientOpenedResponse> open_folded_response(
    const protocol::AuthenticatedPackedClientOnlineState<Backend> &client,
    FoldedClientAwaitingResponse state,
    const FoldedResponse<Backend> &response, Transcript &transcript);

template <protocol::PackedRolePreprocessingBackend Backend>
std::optional<std::vector<fhe::SlotVector>> verify_opened_folded_response(
    const protocol::AuthenticatedPackedClientOnlineState<Backend> &client,
    FoldedClientOpenedResponse state,
    const FoldedResponse<Backend> &response, Transcript &transcript);

template <protocol::PackedRolePreprocessingBackend Backend>
std::optional<std::vector<fhe::SlotVector>>
verify_opened_folded_response_profiled(
    const protocol::AuthenticatedPackedClientOnlineState<Backend> &client,
    FoldedClientOpenedResponse state,
    const FoldedResponse<Backend> &response, Transcript &transcript,
    protocol::FoldedVerifierTimings &timings,
    RuntimeProgressCallback progress = {});

template <protocol::PackedRolePreprocessingBackend Backend>
std::optional<std::vector<fhe::SlotVector>> verify_folded_response(
    const protocol::AuthenticatedPackedClientOnlineState<Backend> &client,
    FoldedClientAwaitingResponse state,
    const FoldedResponse<Backend> &response, Transcript &transcript);

template <protocol::PackedRolePreprocessingBackend Backend>
std::vector<typename Backend::Ciphertext> encrypt_laned_request_inputs(
    const protocol::AuthenticatedPackedClientOnlineState<Backend> &client,
    std::span<const fhe::SlotVector> logical_inputs);

template <protocol::PackedRolePreprocessingBackend Backend>
LanedClientRequestStart<Backend> bind_laned_request_session(
    const protocol::AuthenticatedPackedClientOnlineState<Backend> &client,
    std::span<const fhe::SlotVector> logical_inputs,
    std::vector<typename Backend::Ciphertext> encrypted_inputs,
    LanedClientNonce nonce);

template <protocol::PackedRolePreprocessingBackend Backend>
LanedClientRequestStart<Backend> begin_laned_request(
    const protocol::AuthenticatedPackedClientOnlineState<Backend> &client,
    std::span<const fhe::SlotVector> logical_inputs,
    LanedClientNonce nonce);

template <protocol::PackedRolePreprocessingBackend Backend>
std::optional<LanedClientOpenedResponse> open_laned_response(
    const protocol::AuthenticatedPackedClientOnlineState<Backend> &client,
    LanedClientAwaitingResponse state,
    const LanedResponse<Backend> &response, Transcript &transcript);

template <protocol::PackedRolePreprocessingBackend Backend>
std::optional<std::vector<fhe::SlotVector>> verify_opened_laned_response(
    const protocol::AuthenticatedPackedClientOnlineState<Backend> &client,
    LanedClientOpenedResponse state,
    const LanedResponse<Backend> &response, Transcript &transcript);

template <protocol::PackedRolePreprocessingBackend Backend>
std::optional<std::vector<fhe::SlotVector>>
verify_opened_laned_response_profiled(
    const protocol::AuthenticatedPackedClientOnlineState<Backend> &client,
    LanedClientOpenedResponse state,
    const LanedResponse<Backend> &response, Transcript &transcript,
    protocol::LanedVerifierTimings &timings,
    RuntimeProgressCallback progress = {});

template <protocol::PackedRolePreprocessingBackend Backend>
std::optional<std::vector<fhe::SlotVector>> verify_laned_response(
    const protocol::AuthenticatedPackedClientOnlineState<Backend> &client,
    LanedClientAwaitingResponse state,
    const LanedResponse<Backend> &response, Transcript &transcript);

} // namespace laminate::delegation

#include "laminate/delegation/packed/client/api_impl.hpp"

#endif // LAMINATE_DELEGATION_PACKED_CLIENT_HPP
