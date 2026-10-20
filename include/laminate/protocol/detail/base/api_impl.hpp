#ifndef LAMINATE_PROTOCOL_DETAIL_BASE_API_IMPL_HPP
#define LAMINATE_PROTOCOL_DETAIL_BASE_API_IMPL_HPP

/// @file api_impl.hpp
/// @brief Template implementations for the LaminateBase public API.

#include "laminate/gkr/detail/base/prover.hpp"
#include "laminate/gkr/detail/base/verifier.hpp"

namespace laminate::protocol {

template <fhe::PersistableFheBackend Backend>
void preflight_base(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const payload::PayloadCheckpointReplayTrace<Backend> &trace,
    const EvaluationSetup<Backend> &setup,
    std::span<const Fpk> output_point,
    const BaseProverOptions &options) {
    if (!trace.report().checkpoint_set_published ||
        trace.report().all_payload_artifacts_retired ||
        trace.proof_attempt_started()) {
        throw std::invalid_argument(
            "Base checkpoint replay is not a fresh published session");
    }
    gkr::base_detail::validate_base_gkr_irreversible_request<
        Backend>(payload, circuit, trace, setup, output_point, options);
}

template <fhe::PersistableFheBackend Backend>
BaseProofResult<Backend> prove_base(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    payload::PayloadCheckpointReplayTrace<Backend> &trace,
    const EvaluationSetup<Backend> &setup,
    std::span<const Fpk> output_point, Transcript &transcript,
    BaseProverOptions options) {
    gkr::base_detail::FileBaseGkrResult<Backend> proved =
        gkr::base_detail::prove_base_gkr_irreversible<Backend>(
            payload, circuit, trace, setup, output_point, transcript,
            std::move(options));
    if (!trace.report().all_payload_artifacts_retired ||
        trace.report().live_physical_bytes != 0) {
        throw std::logic_error(
            "Base checkpoint replay left a payload artifact live");
    }
    return BaseProofResult<Backend>{
        std::move(proved.proof), std::move(proved.report), trace.report()};
}

template <fhe::FheBackend Backend>
bool verify_base(
    const CertifiedBaseClientSetup<Backend> &setup,
    std::span<const fhe::SlotVector> input_layer,
    payload::TraceProvenance expected_provenance,
    const Digest &expected_trace_id,
    const gkr::SingleClaim &expected_output_claim,
    const LaminateBaseProof<Backend> &proof, Transcript &transcript) {
    return gkr::base_detail::verify_base_gkr<Backend>(
        setup, input_layer, expected_provenance, expected_trace_id,
        expected_output_claim, proof, transcript);
}

} // namespace laminate::protocol

#endif // LAMINATE_PROTOCOL_DETAIL_BASE_API_IMPL_HPP
