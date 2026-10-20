#ifndef LAMINATE_DELEGATION_LANED_SERVER_ONLINE_EVALUATION_HPP
#define LAMINATE_DELEGATION_LANED_SERVER_ONLINE_EVALUATION_HPP

/// @file server/online_evaluation.hpp
/// @brief Authenticated Laned payload evaluation into sparse replay state.

#include "laminate/delegation/laned/server/admission.hpp"

namespace laminate::delegation {

/// Recurring Laned evaluation against setup-certified static state and
/// one-request resource admission.
template <protocol::PackedRolePreprocessingBackend Backend>
CheckpointReplayLanedServerEvaluationResult<Backend>
evaluate_laned_request(
    const protocol::AuthenticatedPackedServerOnlineState<Backend> &server,
    const LanedEvaluationRequest<Backend> &request,
    PreparedCheckpointReplayLanedServerResources prepared) {
    const auto &checkpoint = server.checkpoint_replay();
    const auto &evaluation = server.evaluation();
    if (server.variant() != protocol::PackingGkrVariant::Laned ||
        !prepared.resources_.uses_external_packing() ||
        !prepared.resources_.matches_external_packing_setup(
            server.prover_setup()) ||
        prepared.resources_.external_packing_setup_identity() !=
            server.prover_setup().identity() ||
        request.setup_id != server.setup_id() ||
        request.session_id == Digest{} ||
        request.circuit_id != server.circuit_id() ||
        request.encrypted_inputs.size() != checkpoint.input_count()) {
        throw std::invalid_argument(
            "authenticated Laned request binding mismatch");
    }

    CheckpointReplayLanedServerResources resources =
        std::move(prepared.resources_);
    std::vector<fhe::FheValue<Backend>> output;
    auto trace =
        payload::PayloadCheckpointReplayTrace<Backend>::publish_certified(
            evaluation.context, checkpoint, request.trace_id,
            request.encrypted_inputs,
            std::move(prepared.replay_), output);
    const payload::EncryptedTraceDescriptor &descriptor = trace.descriptor();
    if (descriptor.provenance != payload::TraceProvenance::FheEvaluated ||
        descriptor.circuit_id != server.circuit_id() ||
        descriptor.trace_id != request.trace_id ||
        descriptor.shape.kind != payload::PayloadKind::Laned ||
        descriptor.layers.empty() ||
        output.size() != descriptor.layers.front().record_count ||
        trace.backend_context_id() !=
            Backend::storage_context_id(evaluation.context) ||
        trace.layered_circuit_id() != checkpoint.layered_circuit_id() ||
        !trace.report().checkpoint_set_published ||
        trace.report().all_payload_artifacts_retired) {
        throw std::logic_error(
            "authenticated Laned checkpoint evaluator returned a "
            "mismatched session");
    }
    LanedFheOutput<Backend> encrypted_output{
        descriptor.layers.front().dimensions, std::move(output)};
    const Digest request_digest = laned_server_detail::laned_request_commitment(request);
    const Digest encrypted_statement = laned_server_detail::laned_statement_digest(
        request_digest, server.setup_id(), request.session_id,
        server.circuit_id(), request.trace_id, encrypted_output);
    return CheckpointReplayLanedServerEvaluationResult<Backend>{
        std::move(encrypted_output),
        CheckpointReplayLanedServerReadyToProve<Backend>{
            server.setup_id(), request.session_id, server.circuit_id(),
            request.trace_id, request_digest, encrypted_statement,
            std::move(trace), std::move(resources)}};
}

} // namespace laminate::delegation

#endif // LAMINATE_DELEGATION_LANED_SERVER_ONLINE_EVALUATION_HPP
