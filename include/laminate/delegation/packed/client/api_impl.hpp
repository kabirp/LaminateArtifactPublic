#ifndef LAMINATE_DELEGATION_PACKED_CLIENT_API_IMPL_HPP
#define LAMINATE_DELEGATION_PACKED_CLIENT_API_IMPL_HPP

/// @file api_impl.hpp
/// @brief Definitions of certified recurring Folded/Laned client transitions.

#include "laminate/delegation/laned/client.hpp"
#include "laminate/gkr/detail/base/geometry/circuit.hpp"
#include "laminate/delegation/folded/client.hpp"
#include "laminate/delegation/folded/profiling/client.hpp"
#include "laminate/delegation/folded/wire/codec.hpp"
#include "laminate/delegation/laned/profiling/client.hpp"
#include "laminate/delegation/laned/wire/codec.hpp"
#include "laminate/protocol/packed/online/client.hpp"
#include "laminate/verification_profile.hpp"

#include <optional>
#include <span>
#include <utility>
#include <vector>

namespace laminate::delegation {

/// Decode a Folded response against static metadata already authenticated by
/// the owning online state. The setup-shaped parser and wire bindings remain
/// fully checked; GKR verification performs the proof-dependent structural
/// check before using the decoded reductions.
template <protocol::PackedProofDecodeBackend Backend>
    requires protocol::PackedRolePreprocessingBackend<Backend>
FoldedResponse<Backend> decode_folded_response(
    const protocol::AuthenticatedPackedClientOnlineState<Backend> &client,
    std::span<const std::uint8_t> encoded,
    const FoldedWireDecodeLimits &wire_limits,
    const protocol::PackedProofDecodeLimits &proof_limits,
    payload::TraceProvenance expected_provenance) {
    constexpr const char *operation =
        "decode_authenticated_folded_response";
    const auto &workload = client.workload();
    BorrowedFoldedResponseEnvelope<Backend> opaque =
        decode_borrowed_folded_response_envelope<Backend>(
            client.verifier_context(), encoded, wire_limits);
    protocol::LaminateFoldedProof<Backend> proof =
        protocol::decode_canonical_certified_folded_proof<Backend>(
            client.verifier_context(), opaque.opaque_proof_bytes,
            client.certified_static(), proof_limits);
    const auto &output_support =
        workload.trace_layout().wire_support.front();
    if (opaque.setup_id != workload.setup_digest() ||
        opaque.circuit_id != workload.circuit_digest() ||
        opaque.output.dimensions != workload.output_dimensions() ||
        opaque.output.values.size() != output_support.live_wire_count ||
        proof.gkr.header.setup_id != opaque.setup_id ||
        proof.gkr.header.circuit_id != opaque.circuit_id ||
        proof.gkr.header.trace_id != opaque.trace_id ||
        proof.gkr.header.provenance != expected_provenance) {
        wire_detail::reject(
            operation, "proof structure or public bindings mismatch");
    }
    return FoldedResponse<Backend>{
        opaque.setup_id, opaque.session_id, opaque.circuit_id,
        opaque.trace_id, std::move(opaque.output), std::move(proof)};
}

template <protocol::PackedProofDecodeBackend Backend>
    requires protocol::PackedRolePreprocessingBackend<Backend>
LanedResponse<Backend> decode_laned_response(
    const protocol::AuthenticatedPackedClientOnlineState<Backend> &client,
    std::span<const std::uint8_t> encoded,
    const LanedWireDecodeLimits &wire_limits,
    const protocol::PackedProofDecodeLimits &proof_limits,
    payload::TraceProvenance expected_provenance) {
    constexpr const char *operation =
        "decode_authenticated_laned_response";
    const auto &workload = client.workload();
    BorrowedLanedResponseEnvelope<Backend> opaque =
        decode_borrowed_laned_response_envelope<Backend>(
            client.verifier_context(), encoded, wire_limits);
    protocol::LaminateLanedProof<Backend> proof =
        protocol::decode_canonical_certified_laned_proof<Backend>(
            client.verifier_context(), opaque.opaque_proof_bytes,
            client.certified_static(), proof_limits);
    const auto &output_support =
        workload.trace_layout().wire_support.front();
    if (opaque.setup_id != workload.setup_digest() ||
        opaque.circuit_id != workload.circuit_digest() ||
        opaque.output.dimensions != workload.output_dimensions() ||
        opaque.output.values.size() != output_support.live_wire_count ||
        proof.gkr.header.setup_id != opaque.setup_id ||
        proof.gkr.header.circuit_id != opaque.circuit_id ||
        proof.gkr.header.trace_id != opaque.trace_id ||
        proof.gkr.header.provenance != expected_provenance) {
        wire_detail::reject(
            operation, "proof structure or public bindings mismatch");
    }
    return LanedResponse<Backend>{
        opaque.setup_id, opaque.session_id, opaque.circuit_id,
        opaque.trace_id, std::move(opaque.output), std::move(proof)};
}

/// Encrypt one request under the Folded authority certified during client
/// preprocessing. Static workload validation is intentionally absent.
template <protocol::PackedRolePreprocessingBackend Backend>
std::vector<typename Backend::Ciphertext> encrypt_folded_request_inputs(
    const protocol::AuthenticatedPackedClientOnlineState<Backend> &client,
    std::span<const fhe::SlotVector> logical_inputs) {
    (void)client.folded_verifier_setup();
    return payload::prevalidated_input_encryption::
        encrypt_wide_inputs_from_validated_payload<Backend>(
            client.client_context(), client.workload().payload(),
            logical_inputs);
}

/// Bind encrypted Folded inputs using the setup and circuit digests cached in
/// the authenticated workload token.
template <protocol::PackedRolePreprocessingBackend Backend>
FoldedClientRequestStart<Backend> bind_folded_request_session(
    const protocol::AuthenticatedPackedClientOnlineState<Backend> &client,
    std::span<const fhe::SlotVector> logical_inputs,
    std::vector<typename Backend::Ciphertext> encrypted_inputs,
    FoldedClientNonce nonce) {
    (void)client.folded_verifier_setup();
    const auto &workload = client.workload();
    const Digest trace_id =
        payload::prevalidated_trace_identity::
            validated_fhe_evaluated_trace_id<Backend>(
                workload.circuit_digest(), workload.payload().input_count,
                encrypted_inputs);
    const Digest nonce_bytes =
        folded_client_detail::ClientStateAccess::consume_nonce(nonce);
    if (folded_client_detail::all_zero(nonce_bytes)) {
        throw std::invalid_argument(
            "bind_folded_request_session: client nonce was already "
            "consumed");
    }
    const Digest session_id = folded_client_detail::derive_session_id(
        nonce_bytes, workload.setup_digest(), workload.circuit_digest(),
        trace_id);
    FoldedEvaluationRequest<Backend> request{
        workload.setup_digest(), session_id, workload.circuit_digest(),
        trace_id, std::move(encrypted_inputs)};
    const Digest request_commitment = packed_request_commitment<Backend>(
        PackedProtocolVariant::Folded, workload.setup_digest(), session_id,
        workload.circuit_digest(), trace_id);
    return FoldedClientRequestStart<Backend>{
        std::move(request),
        FoldedClientAwaitingResponse{
            workload.setup_digest(), session_id,
            workload.circuit_digest(), trace_id, request_commitment,
            payload::prevalidated_plain_trace::
                make_plain_input_layer_from_validated_circuit(
                    workload.circuit(), logical_inputs)}};
}

template <protocol::PackedRolePreprocessingBackend Backend>
FoldedClientRequestStart<Backend> begin_folded_request(
    const protocol::AuthenticatedPackedClientOnlineState<Backend> &client,
    std::span<const fhe::SlotVector> logical_inputs,
    FoldedClientNonce nonce) {
    return bind_folded_request_session<Backend>(
        client, logical_inputs,
        encrypt_folded_request_inputs<Backend>(client, logical_inputs),
        std::move(nonce));
}

/// Open one Folded response using cached output layout metadata. Only dynamic
/// session/statement checks and output decryption occur online.
template <protocol::PackedRolePreprocessingBackend Backend>
std::optional<FoldedClientOpenedResponse> open_folded_response(
    const protocol::AuthenticatedPackedClientOnlineState<Backend> &client,
    FoldedClientAwaitingResponse state,
    const FoldedResponse<Backend> &response, Transcript &transcript) {
    try {
        (void)client.folded_verifier_setup();
        const auto &workload = client.workload();
        const auto &circuit = workload.circuit();
        const auto &output_support =
            workload.trace_layout().wire_support.front();
        if (folded_client_detail::ClientStateAccess::setup_id(state) !=
                workload.setup_digest() ||
            response.setup_id != workload.setup_digest() ||
            folded_client_detail::ClientStateAccess::session_id(state) !=
                response.session_id ||
            folded_client_detail::ClientStateAccess::circuit_id(state) !=
                workload.circuit_digest() ||
            response.circuit_id != workload.circuit_digest() ||
            folded_client_detail::ClientStateAccess::trace_id(state) !=
                response.trace_id ||
            response.output.dimensions != workload.output_dimensions() ||
            response.output.values.size() !=
                output_support.live_wire_count) {
            return std::nullopt;
        }
        Digest statement_digest{};
        std::vector<Fpk> output_point;
        {
            verification_profile::ScopedVerificationPhase phase(
                verification_profile::Category::Recovery);
            transcript.observe(
                "delegation-setup-id",
                std::span<const std::uint8_t>(workload.setup_digest()));
            transcript.observe(
                "delegation-session-id",
                std::span<const std::uint8_t>(response.session_id));
            statement_digest =
                packed_encrypted_statement_digest<Backend>(
                    PackedProtocolVariant::Folded,
                    folded_client_detail::ClientStateAccess::request_commitment(
                        state),
                    workload.setup_digest(), response.session_id,
                    workload.circuit_digest(), response.trace_id,
                    response.output.dimensions, response.output.values);
            output_point = derive_packed_output_point(
                transcript, PackedProtocolVariant::Folded, statement_digest,
                gkr::base_detail::layer_vars(circuit, 0));
        }
        std::vector<fhe::SlotVector> output_layer;
        {
            verification_profile::ScopedVerificationPhase phase(
                verification_profile::Category::OutputDecryption);
            output_layer =
                payload::prevalidated_trace_crypto::
                    decrypt_trace_layer_with_layout<Backend>(
                        client.client_context(), circuit, circuit.shape,
                        payload::EncryptedTraceLayerView<Backend>{
                            payload::TraceLayerLayout::Wide,
                            response.output.dimensions, 0,
                            response.output.values},
                        0, workload.trace_layout().storage.front());
        }
        gkr::SingleClaim output_claim =
            gkr::make_layer_claim(output_layer, std::move(output_point));
        return folded_client_detail::ClientStateAccess::open(
            std::move(state), statement_digest, std::move(output_layer),
            std::move(output_claim));
    } catch (const std::exception &) {
        return std::nullopt;
    }
}

namespace packed_client_online_detail {

template <protocol::PackedRolePreprocessingBackend Backend,
          typename VerifyProof>
std::optional<std::vector<fhe::SlotVector>>
verify_opened_folded_response_with(
    const protocol::AuthenticatedPackedClientOnlineState<Backend> &client,
    FoldedClientOpenedResponse state,
    const FoldedResponse<Backend> &response, Transcript &transcript,
    VerifyProof &&verify_proof) {
    try {
        (void)client.folded_verifier_setup();
        const auto &workload = client.workload();
        const auto &output_support =
            workload.trace_layout().wire_support.front();
        if (folded_client_detail::ClientStateAccess::setup_id(state) !=
                workload.setup_digest() ||
            response.setup_id != workload.setup_digest() ||
            folded_client_detail::ClientStateAccess::session_id(state) !=
                response.session_id ||
            folded_client_detail::ClientStateAccess::circuit_id(state) !=
                workload.circuit_digest() ||
            response.circuit_id != workload.circuit_digest() ||
            folded_client_detail::ClientStateAccess::trace_id(state) !=
                response.trace_id ||
            response.output.dimensions != workload.output_dimensions() ||
            response.output.values.size() !=
                output_support.live_wire_count ||
            workload.circuit().payload_output_count >
                folded_client_detail::ClientStateAccess::output_count(
                    state)) {
            return std::nullopt;
        }
        Digest statement_digest{};
        {
            verification_profile::ScopedVerificationPhase phase(
                verification_profile::Category::Recovery);
            statement_digest =
                packed_encrypted_statement_digest<Backend>(
                    PackedProtocolVariant::Folded,
                    folded_client_detail::ClientStateAccess::request_commitment(
                        state),
                    workload.setup_digest(), response.session_id,
                    workload.circuit_digest(), response.trace_id,
                    response.output.dimensions, response.output.values);
        }
        if (statement_digest !=
                folded_client_detail::ClientStateAccess::statement_digest(
                    state) ||
            !std::forward<VerifyProof>(verify_proof)(state, transcript)) {
            return std::nullopt;
        }
        std::vector<fhe::SlotVector> output_layer =
            folded_client_detail::ClientStateAccess::take_outputs(state);
        return std::vector<fhe::SlotVector>(
            output_layer.begin(),
            output_layer.begin() + static_cast<std::ptrdiff_t>(
                                       workload.circuit()
                                           .payload_output_count));
    } catch (const std::exception &) {
        return std::nullopt;
    }
}

} // namespace packed_client_online_detail

template <protocol::PackedRolePreprocessingBackend Backend>
std::optional<std::vector<fhe::SlotVector>>
verify_opened_folded_response(
    const protocol::AuthenticatedPackedClientOnlineState<Backend> &client,
    FoldedClientOpenedResponse state,
    const FoldedResponse<Backend> &response, Transcript &transcript) {
    return packed_client_online_detail::
        verify_opened_folded_response_with<Backend>(
            client, std::move(state), response, transcript,
            [&](const FoldedClientOpenedResponse &opened,
                Transcript &verification_transcript) {
                return protocol::folded_protocol_detail::
                    verify_certified_protocol<Backend>(
                        client.certified_static(),
                        folded_client_detail::ClientStateAccess::inputs(
                            opened),
                        client.verifier_context(),
                        client.client_context(),
                        payload::TraceProvenance::FheEvaluated,
                        response.trace_id,
                        folded_client_detail::ClientStateAccess::output_claim(
                            opened),
                        response.proof, verification_transcript);
            });
}

template <protocol::PackedRolePreprocessingBackend Backend>
std::optional<std::vector<fhe::SlotVector>>
verify_opened_folded_response_profiled(
    const protocol::AuthenticatedPackedClientOnlineState<Backend> &client,
    FoldedClientOpenedResponse state,
    const FoldedResponse<Backend> &response, Transcript &transcript,
    protocol::FoldedVerifierTimings &timings,
    RuntimeProgressCallback progress) {
    return packed_client_online_detail::
        verify_opened_folded_response_with<Backend>(
            client, std::move(state), response, transcript,
            [&](const FoldedClientOpenedResponse &opened,
                Transcript &verification_transcript) {
                return protocol::profiling_detail::
                    verify_certified_folded<Backend>(
                        client.certified_static(),
                        folded_client_detail::ClientStateAccess::inputs(
                            opened),
                        client.verifier_context(),
                        client.client_context(),
                        payload::TraceProvenance::FheEvaluated,
                        response.trace_id,
                        folded_client_detail::ClientStateAccess::output_claim(
                            opened),
                        response.proof, verification_transcript, timings,
                        progress);
            });
}

template <protocol::PackedRolePreprocessingBackend Backend>
std::optional<std::vector<fhe::SlotVector>> verify_folded_response(
    const protocol::AuthenticatedPackedClientOnlineState<Backend> &client,
    FoldedClientAwaitingResponse state,
    const FoldedResponse<Backend> &response, Transcript &transcript) {
    auto opened = open_folded_response<Backend>(
        client, std::move(state), response, transcript);
    if (!opened) {
        return std::nullopt;
    }
    return verify_opened_folded_response<Backend>(
        client, std::move(*opened), response, transcript);
}

template <protocol::PackedRolePreprocessingBackend Backend>
std::vector<typename Backend::Ciphertext> encrypt_laned_request_inputs(
    const protocol::AuthenticatedPackedClientOnlineState<Backend> &client,
    std::span<const fhe::SlotVector> logical_inputs) {
    (void)client.laned_verifier_setup();
    return payload::prevalidated_input_encryption::
        encrypt_laned_inputs_from_validated_payload<Backend>(
            client.client_context(), client.workload().payload(),
            logical_inputs);
}

template <protocol::PackedRolePreprocessingBackend Backend>
LanedClientRequestStart<Backend> bind_laned_request_session(
    const protocol::AuthenticatedPackedClientOnlineState<Backend> &client,
    std::span<const fhe::SlotVector> logical_inputs,
    std::vector<typename Backend::Ciphertext> encrypted_inputs,
    LanedClientNonce nonce) {
    (void)client.laned_verifier_setup();
    const auto &workload = client.workload();
    const Digest trace_id =
        payload::prevalidated_trace_identity::
            validated_fhe_evaluated_trace_id<Backend>(
                workload.circuit_digest(), workload.payload().input_count,
                encrypted_inputs);
    const Digest nonce_bytes =
        laned_client_detail::ClientStateAccess::consume_nonce(nonce);
    if (laned_client_detail::all_zero(nonce_bytes)) {
        throw std::invalid_argument(
            "bind_laned_request_session: client nonce was already consumed");
    }
    const Digest session_id = laned_client_detail::derive_session_id(
        nonce_bytes, workload.setup_digest(), workload.circuit_digest(),
        trace_id);
    LanedEvaluationRequest<Backend> request{
        workload.setup_digest(), session_id, workload.circuit_digest(),
        trace_id, std::move(encrypted_inputs)};
    const Digest request_commitment = packed_request_commitment<Backend>(
        PackedProtocolVariant::Laned, workload.setup_digest(), session_id,
        workload.circuit_digest(), trace_id);
    return LanedClientRequestStart<Backend>{
        std::move(request),
        LanedClientAwaitingResponse{
            workload.setup_digest(), session_id,
            workload.circuit_digest(), trace_id, request_commitment,
            payload::prevalidated_plain_trace::
                make_plain_input_layer_from_validated_circuit(
                    workload.circuit(), logical_inputs)}};
}

template <protocol::PackedRolePreprocessingBackend Backend>
LanedClientRequestStart<Backend> begin_laned_request(
    const protocol::AuthenticatedPackedClientOnlineState<Backend> &client,
    std::span<const fhe::SlotVector> logical_inputs,
    LanedClientNonce nonce) {
    return bind_laned_request_session<Backend>(
        client, logical_inputs,
        encrypt_laned_request_inputs<Backend>(client, logical_inputs),
        std::move(nonce));
}

template <protocol::PackedRolePreprocessingBackend Backend>
std::optional<LanedClientOpenedResponse> open_laned_response(
    const protocol::AuthenticatedPackedClientOnlineState<Backend> &client,
    LanedClientAwaitingResponse state,
    const LanedResponse<Backend> &response, Transcript &transcript) {
    try {
        (void)client.laned_verifier_setup();
        const auto &workload = client.workload();
        const auto &circuit = workload.circuit();
        const auto &output_support =
            workload.trace_layout().wire_support.front();
        if (laned_client_detail::ClientStateAccess::setup_id(state) !=
                workload.setup_digest() ||
            response.setup_id != workload.setup_digest() ||
            laned_client_detail::ClientStateAccess::session_id(state) !=
                response.session_id ||
            laned_client_detail::ClientStateAccess::circuit_id(state) !=
                workload.circuit_digest() ||
            response.circuit_id != workload.circuit_digest() ||
            laned_client_detail::ClientStateAccess::trace_id(state) !=
                response.trace_id ||
            response.output.dimensions != workload.output_dimensions() ||
            response.output.values.size() !=
                output_support.live_wire_count) {
            return std::nullopt;
        }
        Digest statement_digest{};
        std::vector<Fpk> output_point;
        {
            verification_profile::ScopedVerificationPhase phase(
                verification_profile::Category::Recovery);
            transcript.observe(
                "delegation-setup-id",
                std::span<const std::uint8_t>(workload.setup_digest()));
            transcript.observe(
                "delegation-session-id",
                std::span<const std::uint8_t>(response.session_id));
            statement_digest =
                packed_encrypted_statement_digest<Backend>(
                    PackedProtocolVariant::Laned,
                    laned_client_detail::ClientStateAccess::request_commitment(state),
                    workload.setup_digest(), response.session_id,
                    workload.circuit_digest(), response.trace_id,
                    response.output.dimensions, response.output.values);
            output_point = derive_packed_output_point(
                transcript, PackedProtocolVariant::Laned, statement_digest,
                gkr::laned_layer_variables(circuit, 0));
        }
        std::vector<fhe::SlotVector> output_layer;
        {
            verification_profile::ScopedVerificationPhase phase(
                verification_profile::Category::OutputDecryption);
            output_layer =
                payload::prevalidated_trace_crypto::
                    decrypt_trace_layer_with_layout<Backend>(
                        client.client_context(), circuit, circuit.shape,
                        payload::EncryptedTraceLayerView<Backend>{
                            payload::TraceLayerLayout::BPeriodic,
                            response.output.dimensions, 0,
                            response.output.values},
                        0, workload.trace_layout().storage.front());
        }
        gkr::SingleClaim output_claim = gkr::make_packed_laned_claim(
            output_layer, gkr::laned_layout(circuit, 0),
            std::move(output_point));
        return laned_client_detail::ClientStateAccess::open(
            std::move(state), statement_digest, std::move(output_layer),
            std::move(output_claim));
    } catch (const std::exception &) {
        return std::nullopt;
    }
}

namespace packed_client_online_detail {

template <protocol::PackedRolePreprocessingBackend Backend,
          typename VerifyProof>
std::optional<std::vector<fhe::SlotVector>>
verify_opened_laned_response_with(
    const protocol::AuthenticatedPackedClientOnlineState<Backend> &client,
    LanedClientOpenedResponse state,
    const LanedResponse<Backend> &response, Transcript &transcript,
    VerifyProof &&verify_proof) {
    try {
        (void)client.laned_verifier_setup();
        const auto &workload = client.workload();
        const auto &output_support =
            workload.trace_layout().wire_support.front();
        if (laned_client_detail::ClientStateAccess::setup_id(state) !=
                workload.setup_digest() ||
            response.setup_id != workload.setup_digest() ||
            laned_client_detail::ClientStateAccess::session_id(state) !=
                response.session_id ||
            laned_client_detail::ClientStateAccess::circuit_id(state) !=
                workload.circuit_digest() ||
            response.circuit_id != workload.circuit_digest() ||
            laned_client_detail::ClientStateAccess::trace_id(state) !=
                response.trace_id ||
            response.output.dimensions != workload.output_dimensions() ||
            response.output.values.size() !=
                output_support.live_wire_count ||
            workload.circuit().payload_output_count >
                laned_client_detail::ClientStateAccess::output_count(state)) {
            return std::nullopt;
        }
        Digest statement_digest{};
        {
            verification_profile::ScopedVerificationPhase phase(
                verification_profile::Category::Recovery);
            statement_digest =
                packed_encrypted_statement_digest<Backend>(
                    PackedProtocolVariant::Laned,
                    laned_client_detail::ClientStateAccess::request_commitment(state),
                    workload.setup_digest(), response.session_id,
                    workload.circuit_digest(), response.trace_id,
                    response.output.dimensions, response.output.values);
        }
        if (statement_digest !=
                laned_client_detail::ClientStateAccess::statement_digest(state) ||
            !std::forward<VerifyProof>(verify_proof)(state, transcript)) {
            return std::nullopt;
        }
        std::vector<fhe::SlotVector> output_layer =
            laned_client_detail::ClientStateAccess::take_outputs(state);
        return std::vector<fhe::SlotVector>(
            output_layer.begin(),
            output_layer.begin() + static_cast<std::ptrdiff_t>(
                                       workload.circuit()
                                           .payload_output_count));
    } catch (const std::exception &) {
        return std::nullopt;
    }
}

} // namespace packed_client_online_detail

template <protocol::PackedRolePreprocessingBackend Backend>
std::optional<std::vector<fhe::SlotVector>> verify_opened_laned_response(
    const protocol::AuthenticatedPackedClientOnlineState<Backend> &client,
    LanedClientOpenedResponse state,
    const LanedResponse<Backend> &response, Transcript &transcript) {
    return packed_client_online_detail::
        verify_opened_laned_response_with<Backend>(
            client, std::move(state), response, transcript,
            [&](const LanedClientOpenedResponse &opened,
                Transcript &verification_transcript) {
                return protocol::laned_protocol_detail::
                    verify_certified_protocol<Backend>(
                        client.certified_static(),
                        laned_client_detail::ClientStateAccess::inputs(opened),
                        client.verifier_context(),
                        client.client_context(),
                        payload::TraceProvenance::FheEvaluated,
                        response.trace_id,
                        laned_client_detail::ClientStateAccess::output_claim(
                            opened),
                        response.proof, verification_transcript);
            });
}

template <protocol::PackedRolePreprocessingBackend Backend>
std::optional<std::vector<fhe::SlotVector>>
verify_opened_laned_response_profiled(
    const protocol::AuthenticatedPackedClientOnlineState<Backend> &client,
    LanedClientOpenedResponse state,
    const LanedResponse<Backend> &response, Transcript &transcript,
    protocol::LanedVerifierTimings &timings,
    RuntimeProgressCallback progress) {
    return packed_client_online_detail::
        verify_opened_laned_response_with<Backend>(
            client, std::move(state), response, transcript,
            [&](const LanedClientOpenedResponse &opened,
                Transcript &verification_transcript) {
                return protocol::profiling_detail::
                    verify_certified_laned<Backend>(
                        client.certified_static(),
                        laned_client_detail::ClientStateAccess::inputs(opened),
                        client.verifier_context(),
                        client.client_context(),
                        payload::TraceProvenance::FheEvaluated,
                        response.trace_id,
                        laned_client_detail::ClientStateAccess::output_claim(
                            opened),
                        response.proof, verification_transcript, timings,
                        progress);
            });
}

template <protocol::PackedRolePreprocessingBackend Backend>
std::optional<std::vector<fhe::SlotVector>> verify_laned_response(
    const protocol::AuthenticatedPackedClientOnlineState<Backend> &client,
    LanedClientAwaitingResponse state,
    const LanedResponse<Backend> &response, Transcript &transcript) {
    auto opened = open_laned_response<Backend>(
        client, std::move(state), response, transcript);
    if (!opened) {
        return std::nullopt;
    }
    return verify_opened_laned_response<Backend>(
        client, std::move(*opened), response, transcript);
}

} // namespace laminate::delegation

#endif // LAMINATE_DELEGATION_PACKED_CLIENT_API_IMPL_HPP
