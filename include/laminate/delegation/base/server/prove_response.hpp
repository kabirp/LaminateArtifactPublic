#ifndef LAMINATE_DELEGATION_BASE_SERVER_PROVE_RESPONSE_HPP
#define LAMINATE_DELEGATION_BASE_SERVER_PROVE_RESPONSE_HPP

/// @file server/prove_response.hpp
/// @brief Destructive file-backed Base proving and response publication.

#include "laminate/delegation/base/server/evaluate_payload.hpp"
#include "laminate/gkr/detail/base/geometry/circuit.hpp"

#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

namespace laminate::delegation::base_server_detail {

template <fhe::PersistableFheBackend Backend>
Digest validate_retained_proof_state(
    const payload::LayeredCircuit &circuit,
    const EvaluationSetup<Backend> &server,
    const Digest &setup_id, const Digest &circuit_id,
    CheckpointReplayBaseServerEvaluationResult<Backend> &evaluated) {
    auto &state = evaluated.state;
    auto &trace = BaseServerStateAccess<Backend>::trace(state);
    const payload::EncryptedTraceDescriptor &descriptor = trace.descriptor();
    if (BaseServerStateAccess<Backend>::setup_id(state) != setup_id ||
        BaseServerStateAccess<Backend>::session_id(state) == Digest{} ||
        BaseServerStateAccess<Backend>::circuit_id(state) != circuit_id ||
        BaseServerStateAccess<Backend>::trace_id(state) != descriptor.trace_id ||
        descriptor.circuit_id != circuit_id ||
        descriptor.provenance != payload::TraceProvenance::FheEvaluated ||
        descriptor.shape.kind != payload::PayloadKind::Wide ||
        trace.backend_context_id() !=
            Backend::storage_context_id(server.context) ||
        trace.layered_circuit_id() != payload::digest(circuit) ||
        !trace.report().checkpoint_set_published ||
        trace.report().all_payload_artifacts_retired ||
        trace.proof_attempt_started() ||
        evaluated.output.dimensions != descriptor.layers.front().dimensions ||
        evaluated.output.values.size() !=
            descriptor.layers.front().record_count) {
        throw std::invalid_argument(
            "Base checkpoint proof retained-state binding mismatch");
    }
    return descriptor.trace_id;
}

template <fhe::PersistableFheBackend Backend>
protocol::BaseServerCapacityAdmission readmit_capacity(
    const CheckpointReplayBaseServerEvaluated<Backend> &state) {
    const CheckpointReplayBaseServerResources &resources = state.resources();
    const protocol::BaseServerCapacityAdmission readmitted =
        protocol::admit_base_server_capacity(
            resources.capacity_caps(), resources.capacity_components());
    if (readmitted != resources.capacity_admission()) {
        throw std::logic_error("Base checkpoint capacity admission drifted");
    }
    return readmitted;
}

template <fhe::PersistableFheBackend Backend>
std::vector<Fpk> bind_response_and_derive_output_point(
    const payload::LayeredCircuit &circuit,
    const Digest &setup_id, const Digest &circuit_id, const Digest &trace_id,
    const CheckpointReplayBaseServerEvaluated<Backend> &state,
    const BaseFheOutput<Backend> &output, Transcript &proof_transcript) {
    proof_transcript.observe(
        "delegation-setup-id", std::span<const std::uint8_t>(setup_id));
    proof_transcript.observe(
        "delegation-session-id",
        std::span<const std::uint8_t>(
            BaseServerStateAccess<Backend>::session_id(state)));
    const Digest statement_digest =
        base_encrypted_statement_digest<Backend>(
            BaseServerStateAccess<Backend>::request_commitment(state),
            setup_id, BaseServerStateAccess<Backend>::session_id(state),
            circuit_id, trace_id, output);
    if (statement_digest !=
        BaseServerStateAccess<Backend>::statement_digest(state)) {
        throw std::invalid_argument(
            "Base checkpoint proof output changed after evaluation");
    }
    return derive_base_output_point(
        proof_transcript, statement_digest,
        gkr::base_detail::layer_vars(circuit, 0));
}

} // namespace laminate::delegation::base_server_detail

namespace laminate::delegation {

template <fhe::PersistableFheBackend Backend>
CheckpointReplayBaseServerProofResult<Backend>
prove_base_response_irreversible(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const EvaluationSetup<Backend> &server,
    CheckpointReplayBaseServerEvaluationResult<Backend> &evaluated,
    Transcript &transcript) {
    server.public_setup.validate(payload, circuit);
    const Digest setup_id = setup_digest(server.public_setup);
    const Digest circuit_id = payload::combined_digest(payload, circuit);
    const Digest trace_id = base_server_detail::validate_retained_proof_state(
        circuit, server, setup_id, circuit_id, evaluated);
    const protocol::BaseServerCapacityAdmission readmitted =
        base_server_detail::readmit_capacity(evaluated.state);

    // Work on a transcript copy until all deterministic rejection checks pass.
    Transcript proof_transcript = transcript;
    const std::vector<Fpk> output_point =
        base_server_detail::bind_response_and_derive_output_point(
            circuit, setup_id, circuit_id, trace_id, evaluated.state,
            evaluated.output, proof_transcript);
    auto &trace = BaseServerStateAccess<Backend>::trace(evaluated.state);
    const CheckpointReplayBaseServerResources &resources =
        evaluated.state.resources();
    protocol::preflight_base<Backend>(
        payload, circuit, trace, server, output_point,
        resources.proof_options());

    // From here onward the replay and reduction artifacts are one-shot.
    protocol::BaseProofResult<Backend> proved = protocol::prove_base<Backend>(
        payload, circuit, trace, server, output_point, proof_transcript,
        resources.proof_options());
    CheckpointReplayBaseServerProofResult<Backend> result{
        BaseResponse<Backend>{
            setup_id,
            BaseServerStateAccess<Backend>::session_id(evaluated.state),
            circuit_id, trace_id, std::move(evaluated.output),
            std::move(proved.proof)},
        std::move(proved.gkr_report),
        std::move(proved.payload_replay_report), readmitted};
    transcript = std::move(proof_transcript);
    return result;
}

} // namespace laminate::delegation

#endif // LAMINATE_DELEGATION_BASE_SERVER_PROVE_RESPONSE_HPP
