#ifndef LAMINATE_DELEGATION_FOLDED_SERVER_ONLINE_EVALUATION_HPP
#define LAMINATE_DELEGATION_FOLDED_SERVER_ONLINE_EVALUATION_HPP

/// @file server/online_evaluation.hpp
/// @brief Authenticated Folded payload evaluation into sparse replay state.

#include "laminate/delegation/folded/server/admission.hpp"

namespace laminate::delegation {

/// Recurring Folded evaluation against setup-certified static state and
/// one-request resource admission. Only dynamic request bindings,
/// ciphertext-derived trace identity, mutable-root checks in publication,
/// FHE evaluation, and produced-artifact ledgers remain on this path.
template <protocol::PackedRolePreprocessingBackend Backend>
CheckpointReplayFoldedServerEvaluationResult<Backend>
evaluate_folded_request(
    const protocol::AuthenticatedPackedServerOnlineState<Backend> &server,
    const FoldedEvaluationRequest<Backend> &request,
    PreparedCheckpointReplayFoldedServerResources prepared) {
    const auto &checkpoint = server.checkpoint_replay();
    const auto &evaluation = server.evaluation();
    if (server.variant() != protocol::PackingGkrVariant::Folded ||
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
            "authenticated Folded request binding mismatch");
    }

    CheckpointReplayFoldedServerResources resources =
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
        descriptor.shape.kind != payload::PayloadKind::Wide ||
        descriptor.layers.empty() ||
        output.size() != descriptor.layers.front().record_count ||
        trace.backend_context_id() !=
            Backend::storage_context_id(evaluation.context) ||
        trace.layered_circuit_id() != checkpoint.layered_circuit_id() ||
        !trace.report().checkpoint_set_published ||
        trace.report().all_payload_artifacts_retired) {
        throw std::logic_error(
            "authenticated Folded checkpoint evaluator returned a "
            "mismatched session");
    }
    FoldedFheOutput<Backend> encrypted_output{
        descriptor.layers.front().dimensions, std::move(output)};
    const Digest request_digest =
        folded_server_detail::folded_request_commitment(request);
    const Digest encrypted_statement =
        folded_server_detail::folded_statement_digest(
            request_digest, server.setup_id(), request.session_id,
            server.circuit_id(), request.trace_id, encrypted_output);
    return CheckpointReplayFoldedServerEvaluationResult<Backend>{
        std::move(encrypted_output),
        CheckpointReplayFoldedServerReadyToProve<Backend>{
            server.setup_id(), request.session_id, server.circuit_id(),
            request.trace_id, request_digest, encrypted_statement,
            std::move(trace), std::move(resources)}};
}

} // namespace laminate::delegation

#endif // LAMINATE_DELEGATION_FOLDED_SERVER_ONLINE_EVALUATION_HPP
