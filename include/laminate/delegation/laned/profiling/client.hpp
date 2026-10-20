#ifndef LAMINATE_DELEGATION_LANED_PROFILING_CLIENT_HPP
#define LAMINATE_DELEGATION_LANED_PROFILING_CLIENT_HPP

/// @file profiling/client.hpp
/// @brief Opt-in timing adapter for packed Laned client verification.

#include "laminate/delegation/laned/client.hpp"
#include "laminate/protocol/metrics/profiling.hpp"

namespace laminate::delegation {

/// Verify an already-opened response with the key-free verifier projection
/// while collecting diagnostic-only GKR and transcript-packing timings.
template <packing::SignedDigitPackingBackend Backend>
    requires fhe::PublicVerifierFheBackend<Backend>
std::optional<std::vector<fhe::SlotVector>>
verify_opened_laned_response_profiled(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const protocol::LanedVerifierSetup &packing_setup,
    const PackedClientSetup<Backend> &client,
    LanedClientOpenedResponse state,
    const LanedResponse<Backend> &response, Transcript &transcript,
    protocol::LanedVerifierTimings &timings,
    RuntimeProgressCallback progress = {}) {
    return laned_client_detail::verify_opened_with<Backend>(
        payload, circuit, client.client_setup(), std::move(state), response,
        transcript,
        [&](const LanedClientOpenedResponse &opened,
            Transcript &verification_transcript) {
            return protocol::verify_laned_profiled<Backend>(
                payload, circuit,
                laned_client_detail::ClientStateAccess::inputs(opened),
                client.verifier_context(), packing_setup,
                client.client_setup(),
                payload::TraceProvenance::FheEvaluated,
                response.trace_id,
                laned_client_detail::ClientStateAccess::output_claim(opened),
                response.proof, verification_transcript, timings,
                std::move(progress));
        });
}

} // namespace laminate::delegation

#endif // LAMINATE_DELEGATION_LANED_PROFILING_CLIENT_HPP
