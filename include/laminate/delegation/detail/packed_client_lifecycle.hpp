#ifndef LAMINATE_DELEGATION_DETAIL_PACKED_CLIENT_LIFECYCLE_HPP
#define LAMINATE_DELEGATION_DETAIL_PACKED_CLIENT_LIFECYCLE_HPP

/// @file packed_client_lifecycle.hpp
/// @brief Shared one-request/one-response client transitions.

#include "laminate/delegation/packed/statement.hpp"
#include "laminate/payload/compiler.hpp"
#include "laminate/payload/trace/trace_crypto.hpp"
#include "laminate/payload/trace/trace_wire_support.hpp"
#include "laminate/setup.hpp"
#include "laminate/verification_profile.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

namespace laminate::delegation::packed_client_detail {

inline Digest derive_session_id(
    std::string_view domain, const Digest &nonce, const Digest &setup_id,
    const Digest &circuit_id, const Digest &trace_id) {
    std::vector<std::uint8_t> encoded(domain.begin(), domain.end());
    encoded.insert(encoded.end(), nonce.begin(), nonce.end());
    encoded.insert(encoded.end(), setup_id.begin(), setup_id.end());
    encoded.insert(encoded.end(), circuit_id.begin(), circuit_id.end());
    encoded.insert(encoded.end(), trace_id.begin(), trace_id.end());
    return sha256(encoded);
}

inline bool is_zero_digest(const Digest &value) {
    return std::all_of(value.begin(), value.end(),
                       [](std::uint8_t byte) { return byte == 0; });
}

/// Validate the dynamic response bindings, decrypt the output once, and
/// derive the initial GKR claim. `StateAccess` owns the variant-specific
/// move-only state representation; `make_claim` owns only the difference
/// between Wide and Laned output MLEs.
template <fhe::FheBackend Backend,
          typename AwaitingResponse, typename OpenedResponse,
          typename Response, typename StateAccess, typename MakeClaim>
std::optional<OpenedResponse> open_response(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const ClientSetup<Backend> &client, AwaitingResponse state,
    const Response &response, Transcript &transcript,
    PackedProtocolVariant variant, payload::PayloadKind payload_kind,
    payload::TraceLayerLayout trace_layout,
    std::size_t output_point_coordinates, MakeClaim &&make_claim) {
    try {
        client.public_setup.validate(payload, circuit);
        const Digest setup_id = setup_digest(client.public_setup);
        const Digest circuit_id = payload::combined_digest(payload, circuit);
        const payload::LayerDimensions output_dimensions =
            payload::layer_dimensions(circuit.layers.front());
        const payload::LayerWireSupport output_support =
            payload::canonical_layer_wire_support(circuit, 0);
        if (payload.shape.kind != payload_kind ||
            circuit.shape.kind != payload_kind ||
            StateAccess::setup_id(state) != setup_id ||
            response.setup_id != setup_id ||
            StateAccess::session_id(state) != response.session_id ||
            StateAccess::circuit_id(state) != circuit_id ||
            response.circuit_id != circuit_id ||
            StateAccess::trace_id(state) != response.trace_id ||
            response.output.dimensions != output_dimensions ||
            response.output.values.size() !=
                output_support.live_wire_count) {
            return std::nullopt;
        }

        Digest statement_digest{};
        std::vector<Fpk> output_point;
        {
            verification_profile::ScopedVerificationPhase phase(
                verification_profile::Category::Recovery);
            observe_packed_delegation_bindings(
                transcript, setup_id, response.session_id);
            statement_digest =
                packed_encrypted_statement_digest<Backend>(
                    variant, StateAccess::request_commitment(state), setup_id,
                    response.session_id, circuit_id, response.trace_id,
                    response.output.dimensions, response.output.values);
            output_point = derive_packed_output_point(
                transcript, variant, statement_digest,
                output_point_coordinates);
        }
        std::vector<fhe::SlotVector> output_layer;
        {
            verification_profile::ScopedVerificationPhase phase(
                verification_profile::Category::OutputDecryption);
            output_layer =
                payload::decrypt_trace_layer<Backend>(
                    client.context, circuit, circuit.shape,
                    payload::EncryptedTraceLayerView<Backend>{
                        trace_layout, response.output.dimensions, 0,
                        response.output.values},
                    0);
        }
        auto output_claim = std::forward<MakeClaim>(make_claim)(
            output_layer, std::move(output_point));
        return StateAccess::open(
            std::move(state), statement_digest, std::move(output_layer),
            std::move(output_claim));
    } catch (const std::exception &) {
        return std::nullopt;
    }
}

/// Recheck the response binding and release plaintext outputs only after the
/// variant-specific proof verifier succeeds.
template <fhe::FheBackend Backend,
          typename OpenedResponse, typename Response,
          typename StateAccess, typename VerifyProof>
std::optional<std::vector<fhe::SlotVector>> verify_opened_response(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const ClientSetup<Backend> &client, OpenedResponse state,
    const Response &response, Transcript &transcript,
    PackedProtocolVariant variant, VerifyProof &&verify_proof) {
    try {
        client.public_setup.validate(payload, circuit);
        const Digest setup_id = setup_digest(client.public_setup);
        const Digest circuit_id = payload::combined_digest(payload, circuit);
        const payload::LayerDimensions output_dimensions =
            payload::layer_dimensions(circuit.layers.front());
        const payload::LayerWireSupport output_support =
            payload::canonical_layer_wire_support(circuit, 0);
        if (StateAccess::setup_id(state) != setup_id ||
            response.setup_id != setup_id ||
            StateAccess::session_id(state) != response.session_id ||
            StateAccess::circuit_id(state) != circuit_id ||
            response.circuit_id != circuit_id ||
            StateAccess::trace_id(state) != response.trace_id ||
            response.output.dimensions != output_dimensions ||
            response.output.values.size() !=
                output_support.live_wire_count ||
            circuit.payload_output_count > StateAccess::output_count(state)) {
            return std::nullopt;
        }

        Digest statement_digest{};
        {
            verification_profile::ScopedVerificationPhase phase(
                verification_profile::Category::Recovery);
            statement_digest =
                packed_encrypted_statement_digest<Backend>(
                    variant, StateAccess::request_commitment(state), setup_id,
                    response.session_id, circuit_id, response.trace_id,
                    response.output.dimensions, response.output.values);
        }
        if (statement_digest != StateAccess::statement_digest(state) ||
            !std::forward<VerifyProof>(verify_proof)(state, transcript)) {
            return std::nullopt;
        }
        std::vector<fhe::SlotVector> output_layer =
            StateAccess::take_outputs(state);
        return std::vector<fhe::SlotVector>(
            output_layer.begin(),
            output_layer.begin() + static_cast<std::ptrdiff_t>(
                                       circuit.payload_output_count));
    } catch (const std::exception &) {
        return std::nullopt;
    }
}

} // namespace laminate::delegation::packed_client_detail

#endif // LAMINATE_DELEGATION_DETAIL_PACKED_CLIENT_LIFECYCLE_HPP
