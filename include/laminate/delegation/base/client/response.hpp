#ifndef LAMINATE_DELEGATION_BASE_CLIENT_RESPONSE_HPP
#define LAMINATE_DELEGATION_BASE_CLIENT_RESPONSE_HPP

/// @file client/response.hpp
/// @brief Certified Base response binding, verification, and output release.

#include "laminate/delegation/base/client/request.hpp"
#include "laminate/gkr/detail/base/geometry/circuit.hpp"
#include "laminate/payload/trace/trace_crypto.hpp"
#include "laminate/payload/trace/trace_wire_support.hpp"
#include "laminate/protocol/base.hpp"
#include "laminate/verification_profile.hpp"

#include <cstddef>
#include <optional>
#include <span>
#include <utility>
#include <vector>

namespace laminate::delegation {

template <fhe::FheBackend Backend>
std::optional<BaseClientOpenedResponse> open_base_response(
    const protocol::CertifiedBaseClientSetup<Backend> &client,
    BaseClientAwaitingResponse state,
    const BaseResponse<Backend> &response, Transcript &transcript) {
    try {
        if (base_client_detail::ClientStateAccess::setup_id(state) !=
                client.setup_id() ||
            response.setup_id != client.setup_id() ||
            base_client_detail::ClientStateAccess::session_id(state) !=
                response.session_id ||
            base_client_detail::ClientStateAccess::circuit_id(state) !=
                client.circuit_id() ||
            response.circuit_id != client.circuit_id() ||
            base_client_detail::ClientStateAccess::trace_id(state) !=
                response.trace_id ||
            response.output.dimensions != client.output_dimensions() ||
            response.output.values.size() !=
                client.output_support().live_wire_count) {
            return std::nullopt;
        }

        Digest statement_digest{};
        std::vector<Fpk> output_point;
        {
            verification_profile::ScopedVerificationPhase phase(
                verification_profile::Category::Recovery);
            transcript.observe(
                "delegation-setup-id",
                std::span<const std::uint8_t>(client.setup_id()));
            transcript.observe(
                "delegation-session-id",
                std::span<const std::uint8_t>(response.session_id));
            statement_digest =
                base_encrypted_statement_digest<Backend>(
                    base_client_detail::ClientStateAccess::request_commitment(
                        state),
                    client.setup_id(), response.session_id, client.circuit_id(),
                    response.trace_id, response.output);
            output_point = derive_base_output_point(
                transcript, statement_digest,
                gkr::base_detail::layer_vars(client.circuit(), 0));
        }
        std::vector<fhe::SlotVector> output_layer;
        {
            verification_profile::ScopedVerificationPhase phase(
                verification_profile::Category::OutputDecryption);
            output_layer =
                payload::prevalidated_trace_crypto::decrypt_trace_layer_with_layout<
                    Backend>(
                    client.context(), client.circuit(), client.circuit().shape,
                    payload::EncryptedTraceLayerView<Backend>{
                        payload::TraceLayerLayout::Wide,
                        response.output.dimensions, 0, response.output.values},
                    0, client.layout().storage.front());
        }
        gkr::SingleClaim output_claim =
            gkr::make_layer_claim(output_layer, std::move(output_point));
        return base_client_detail::ClientStateAccess::open(
            std::move(state), statement_digest, std::move(output_layer),
            std::move(output_claim));
    } catch (const std::exception &) {
        return std::nullopt;
    }
}

namespace base_client_detail {

template <fhe::FheBackend Backend, typename VerifyProof>
std::optional<std::vector<fhe::SlotVector>>
verify_certified_opened_base_response(
    const protocol::CertifiedBaseClientSetup<Backend> &client,
    BaseClientOpenedResponse state, const BaseResponse<Backend> &response,
    Transcript &transcript, VerifyProof &&verify_proof) {
    try {
        if (ClientStateAccess::setup_id(state) != client.setup_id() ||
            response.setup_id != client.setup_id() ||
            ClientStateAccess::session_id(state) != response.session_id ||
            ClientStateAccess::circuit_id(state) != client.circuit_id() ||
            response.circuit_id != client.circuit_id() ||
            ClientStateAccess::trace_id(state) != response.trace_id ||
            response.output.dimensions != client.output_dimensions() ||
            response.output.values.size() !=
                client.output_support().live_wire_count ||
            client.payload_output_count() >
                ClientStateAccess::output_count(state)) {
            return std::nullopt;
        }
        Digest statement_digest{};
        {
            verification_profile::ScopedVerificationPhase phase(
                verification_profile::Category::Recovery);
            statement_digest =
                base_encrypted_statement_digest<Backend>(
                    ClientStateAccess::request_commitment(state),
                    client.setup_id(), response.session_id, client.circuit_id(),
                    response.trace_id, response.output);
        }
        if (statement_digest != ClientStateAccess::statement_digest(state) ||
            !std::forward<VerifyProof>(verify_proof)(state, transcript)) {
            return std::nullopt;
        }
        std::vector<fhe::SlotVector> output_layer =
            ClientStateAccess::take_outputs(state);
        return std::vector<fhe::SlotVector>(
            output_layer.begin(),
            output_layer.begin() + static_cast<std::ptrdiff_t>(
                                       client.payload_output_count()));
    } catch (const std::exception &) {
        return std::nullopt;
    }
}

} // namespace base_client_detail

template <fhe::FheBackend Backend>
std::optional<std::vector<fhe::SlotVector>> verify_opened_base_response(
    const protocol::CertifiedBaseClientSetup<Backend> &client,
    BaseClientOpenedResponse state,
    const BaseResponse<Backend> &response, Transcript &transcript) {
    return base_client_detail::verify_certified_opened_base_response<Backend>(
        client, std::move(state), response, transcript,
        [&](const BaseClientOpenedResponse &opened,
            Transcript &verification_transcript) {
            return protocol::verify_base<Backend>(
                client,
                base_client_detail::ClientStateAccess::inputs(opened),
                payload::TraceProvenance::FheEvaluated, response.trace_id,
                base_client_detail::ClientStateAccess::output_claim(opened),
                response.proof, verification_transcript);
        });
}

template <fhe::FheBackend Backend>
std::optional<std::vector<fhe::SlotVector>> verify_base_response(
    const protocol::CertifiedBaseClientSetup<Backend> &client,
    BaseClientAwaitingResponse state,
    const BaseResponse<Backend> &response, Transcript &transcript) {
    std::optional<BaseClientOpenedResponse> opened =
        open_base_response<Backend>(client, std::move(state), response,
                                    transcript);
    if (!opened) {
        return std::nullopt;
    }
    return verify_opened_base_response<Backend>(
        client, std::move(*opened), response, transcript);
}

} // namespace laminate::delegation

#endif // LAMINATE_DELEGATION_BASE_CLIENT_RESPONSE_HPP
