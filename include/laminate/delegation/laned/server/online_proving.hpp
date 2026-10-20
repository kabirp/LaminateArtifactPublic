#ifndef LAMINATE_DELEGATION_LANED_SERVER_ONLINE_PROVING_HPP
#define LAMINATE_DELEGATION_LANED_SERVER_ONLINE_PROVING_HPP

/// @file server/online_proving.hpp
/// @brief Authenticated Laned GKR and transcript-packing response.

#include "laminate/delegation/laned/server/online_evaluation.hpp"

namespace laminate::delegation {

/// Prepared recurring Laned proof transition. Immutable workload/setup work
/// was certified before request timing; dynamic bindings and one-shot
/// resource freshness remain checked here.
template <protocol::PackedRolePreprocessingBackend Backend>
CheckpointReplayLanedExternalServerProofResult<Backend>
prove_laned_response_irreversible(
    const protocol::AuthenticatedPackedServerOnlineState<Backend> &server,
    CheckpointReplayLanedServerEvaluationResult<Backend> &evaluated,
    Transcript &transcript) {
    auto &state = evaluated.state;
    const auto &checkpoint = server.checkpoint_replay();
    const auto &evaluation = server.evaluation();
    const auto &packing_setup = server.prover_setup();
    if (server.variant() != protocol::PackingGkrVariant::Laned ||
        !state.resources().uses_external_packing() ||
        !state.resources().matches_external_packing_setup(packing_setup) ||
        state.resources().external_packing_setup_identity() !=
            packing_setup.identity()) {
        throw std::invalid_argument(
            "prepared Laned proof setup does not match its retained "
            "admission");
    }
    const LanedServerProofOptions &proof_options =
        state.resources().proof_options();
    if (proof_options.lifecycle !=
            payload::FileTraceSessionLifecycle::IrreversibleNoRetry ||
        !proof_options.reclaim_completed_multiplication_scratch) {
        throw std::invalid_argument(
            "prepared Laned proof resources lost no-retry semantics");
    }
    const payload::EncryptedTraceDescriptor &descriptor =
        state.trace.descriptor();
    if (state.setup_id != server.setup_id() ||
        state.session_id == Digest{} ||
        state.circuit_id != server.circuit_id() ||
        state.trace_id != descriptor.trace_id ||
        descriptor.circuit_id != server.circuit_id() ||
        descriptor.provenance != payload::TraceProvenance::FheEvaluated ||
        descriptor.shape.kind != payload::PayloadKind::Laned ||
        descriptor.layers.empty() ||
        evaluated.output.dimensions != descriptor.layers.front().dimensions ||
        evaluated.output.values.size() !=
            descriptor.layers.front().record_count ||
        state.trace.backend_context_id() !=
            Backend::storage_context_id(evaluation.context) ||
        state.trace.layered_circuit_id() !=
            checkpoint.layered_circuit_id() ||
        !state.trace.report().checkpoint_set_published ||
        state.trace.report().all_payload_artifacts_retired ||
        state.trace.proof_attempt_started()) {
        throw std::invalid_argument(
            "prepared Laned proof retained-state binding mismatch");
    }
    const Digest encrypted_statement = laned_server_detail::laned_statement_digest(
        state.request_commitment, server.setup_id(), state.session_id,
        server.circuit_id(), state.trace_id, evaluated.output);
    if (encrypted_statement != state.statement_digest) {
        throw std::invalid_argument(
            "prepared Laned encrypted output changed after evaluation");
    }

    Transcript proof_transcript = transcript;
    observe_packed_delegation_bindings(
        proof_transcript, server.setup_id(), state.session_id);
    const std::vector<Fpk> output_point = derive_packed_output_point(
        proof_transcript, PackedProtocolVariant::Laned,
        encrypted_statement,
        gkr::laned_layer_variables(checkpoint.circuit(), 0));
    protocol::TranscriptPackingExternalAdmission packing =
        state.resources().take_external_packing_admission();
    protocol::preflight_laned_packed_external_resource_roots(
        state.trace.directory(), proof_options, packing);
    auto admission =
        protocol::
            admit_prepared_laned_checkpoint_replay_external_irreversible<
                Backend>(
                server.workload().payload(), server.workload().circuit(),
                state.trace, evaluation, packing_setup,
                server.gkr_static(), output_point, proof_options,
                std::move(packing));
    protocol::LanedCheckpointReplayExternalResult<Backend> proved =
        protocol::prove_laned_checkpoint_replay_external_irreversible<
            Backend>(std::move(admission), proof_transcript);

    CheckpointReplayLanedExternalServerProofResult<Backend> result{
        LanedResponse<Backend>{
            server.setup_id(), state.session_id, server.circuit_id(),
            state.trace_id, std::move(evaluated.output),
            std::move(proved.proof)},
        std::move(proved.gkr_report),
        std::move(proved.payload_replay_report),
        std::move(proved.transcript_packing_report),
        proved.phase_timings,
        state.resources().admission()};
    transcript = std::move(proof_transcript);
    return result;
}

} // namespace laminate::delegation

#endif // LAMINATE_DELEGATION_LANED_SERVER_ONLINE_PROVING_HPP
