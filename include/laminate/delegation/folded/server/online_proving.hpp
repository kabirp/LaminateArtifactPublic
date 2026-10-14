#ifndef LAMINATE_DELEGATION_FOLDED_SERVER_ONLINE_PROVING_HPP
#define LAMINATE_DELEGATION_FOLDED_SERVER_ONLINE_PROVING_HPP

/// @file server/online_proving.hpp
/// @brief Authenticated Folded GKR and transcript-packing response.

#include "laminate/delegation/folded/server/online_evaluation.hpp"
#include "laminate/gkr/detail/base/geometry/circuit.hpp"

namespace laminate::delegation {

/// Prepared recurring Folded proof transition. The authenticated server and
/// retained evaluation state already bind every immutable workload, setup,
/// ingress, replay-plan, and storage fact; the checks below are exclusively
/// request/output/freshness/resource checks at the destructive boundary.
template <protocol::PackedRolePreprocessingBackend Backend>
CheckpointReplayFoldedExternalServerProofResult<Backend>
prove_folded_response_irreversible(
    const protocol::AuthenticatedPackedServerOnlineState<Backend> &server,
    CheckpointReplayFoldedServerEvaluationResult<Backend> &evaluated,
    Transcript &transcript) {
    auto &state = evaluated.state;
    const auto &checkpoint = server.checkpoint_replay();
    const auto &evaluation = server.evaluation();
    const auto &packing_setup = server.prover_setup();
    if (server.variant() != protocol::PackingGkrVariant::Folded ||
        !state.resources().uses_external_packing() ||
        !state.resources().matches_external_packing_setup(packing_setup) ||
        state.resources().external_packing_setup_identity() !=
            packing_setup.identity()) {
        throw std::invalid_argument(
            "prepared Folded proof setup does not match its retained "
            "admission");
    }
    const FoldedServerProofOptions &proof_options =
        state.resources().proof_options();
    if (proof_options.lifecycle !=
            payload::FileTraceSessionLifecycle::IrreversibleNoRetry ||
        !proof_options.reclaim_completed_multiplication_scratch) {
        throw std::invalid_argument(
            "prepared Folded proof resources lost no-retry semantics");
    }
    const payload::EncryptedTraceDescriptor &descriptor =
        state.trace.descriptor();
    if (state.setup_id != server.setup_id() ||
        state.session_id == Digest{} ||
        state.circuit_id != server.circuit_id() ||
        state.trace_id != descriptor.trace_id ||
        descriptor.circuit_id != server.circuit_id() ||
        descriptor.provenance != payload::TraceProvenance::FheEvaluated ||
        descriptor.shape.kind != payload::PayloadKind::Wide ||
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
            "prepared Folded proof retained-state binding mismatch");
    }
    const Digest encrypted_statement =
        folded_server_detail::folded_statement_digest(
            state.request_commitment, server.setup_id(), state.session_id,
            server.circuit_id(), state.trace_id, evaluated.output);
    if (encrypted_statement != state.statement_digest) {
        throw std::invalid_argument(
            "prepared Folded encrypted output changed after evaluation");
    }

    Transcript proof_transcript = transcript;
    observe_packed_delegation_bindings(
        proof_transcript, server.setup_id(), state.session_id);
    const std::vector<Fpk> output_point = derive_packed_output_point(
        proof_transcript, PackedProtocolVariant::Folded,
        encrypted_statement,
        gkr::base_detail::layer_vars(checkpoint.circuit(), 0));
    protocol::TranscriptPackingExternalAdmission packing =
        state.resources().take_external_packing_admission();
    protocol::preflight_folded_packed_external_resource_roots(
        state.trace.directory(), proof_options, packing);
    auto admission =
        protocol::
            admit_prepared_folded_checkpoint_replay_external_irreversible<
                Backend>(
                server.workload().payload(), server.workload().circuit(),
                state.trace, evaluation, packing_setup,
                server.gkr_static(), output_point, proof_options,
                std::move(packing));
    protocol::FoldedCheckpointReplayExternalResult<Backend> proved =
        protocol::prove_folded_checkpoint_replay_external_irreversible<
            Backend>(std::move(admission), proof_transcript);

    CheckpointReplayFoldedExternalServerProofResult<Backend> result{
        FoldedResponse<Backend>{
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

#endif // LAMINATE_DELEGATION_FOLDED_SERVER_ONLINE_PROVING_HPP
