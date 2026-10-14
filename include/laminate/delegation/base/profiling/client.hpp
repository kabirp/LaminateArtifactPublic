#ifndef LAMINATE_DELEGATION_BASE_PROFILING_CLIENT_HPP
#define LAMINATE_DELEGATION_BASE_PROFILING_CLIENT_HPP

/// @file profiling/client.hpp
/// @brief Opt-in timing adapter for Base client proof verification.

#include "laminate/delegation/base/client.hpp"
#include "laminate/protocol/metrics/profiling.hpp"

namespace laminate::delegation {

/// Verify an opened response through the certified client path while
/// collecting diagnostic-only per-layer, decryption, and GateMLE timings.
template <fhe::FheBackend Backend>
std::optional<std::vector<fhe::SlotVector>>
verify_opened_base_response_profiled(
    const protocol::CertifiedBaseClientSetup<Backend> &client,
    BaseClientOpenedResponse state, const BaseResponse<Backend> &response,
    Transcript &transcript, protocol::BaseVerifierTimings &timings) {
    return base_client_detail::verify_certified_opened_base_response<Backend>(
        client, std::move(state), response, transcript,
        [&](const BaseClientOpenedResponse &opened,
            Transcript &verification_transcript) {
            return protocol::verify_base_profiled<Backend>(
                client,
                base_client_detail::ClientStateAccess::inputs(opened),
                payload::TraceProvenance::FheEvaluated,
                response.trace_id,
                base_client_detail::ClientStateAccess::output_claim(opened),
                response.proof, verification_transcript, timings);
        });
}

} // namespace laminate::delegation

#endif // LAMINATE_DELEGATION_BASE_PROFILING_CLIENT_HPP
