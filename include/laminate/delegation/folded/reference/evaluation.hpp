#ifndef LAMINATE_DELEGATION_FOLDED_REFERENCE_EVALUATION_HPP
#define LAMINATE_DELEGATION_FOLDED_REFERENCE_EVALUATION_HPP

/// @file reference/evaluation.hpp
/// @brief Folded resident, file, and uncached replay evaluation paths.

#include "laminate/delegation/folded/server/admission.hpp"
#include "laminate/protocol/reference/folded.hpp"

namespace laminate::delegation::reference {

/// Evaluate into a compact resident Wide trace. This bounded reference path
/// and the production replay path preserve the same canonical stored order.
template <fhe::FheBackend Backend>
FoldedServerEvaluationResult<Backend> evaluate_folded_request_resident_reference(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const EvaluationSetup<Backend> &server,
    const FoldedEvaluationRequest<Backend> &request,
    const payload::FheEvaluationPlan &plan) {
    folded_server_detail::validate_folded_evaluation_request(
        payload, circuit, server, request);
    const Digest setup_id = setup_digest(server.public_setup);
    const Digest circuit_id = payload::combined_digest(payload, circuit);
    auto trace = std::make_shared<payload::EncryptedTrace<Backend>>(
        payload::evaluate_wide_fhe_trace_into<Backend>(
            server.context, payload, circuit, request.encrypted_inputs,
            plan,
            payload::InMemoryTraceSink<Backend>{server.context}));
    if (trace->circuit_id != circuit_id ||
        trace->trace_id != request.trace_id || trace->layers.empty() ||
        trace->layers.front().layout != payload::TraceLayerLayout::Wide) {
        throw std::logic_error(
            "evaluate_folded_request_resident_reference: evaluator returned a mismatched "
            "trace");
    }
    const payload::LayerWireSupport output_support =
        payload::canonical_layer_wire_support(circuit, 0);
    if (trace->layers.front().wires.size() !=
        output_support.live_wire_count) {
        throw std::logic_error(
            "evaluate_folded_request_resident_reference: output support mismatch");
    }
    FoldedFheOutput<Backend> output{
        trace->layers.front().dimensions, trace->layers.front().wires};
    const Digest request_digest =
        folded_server_detail::folded_request_commitment(request);
    const Digest encrypted_statement =
        folded_server_detail::folded_statement_digest(
            request_digest, setup_id, request.session_id, circuit_id,
            trace->trace_id, output);
    return FoldedServerEvaluationResult<Backend>{
        std::move(output),
        FoldedServerReadyToProve<Backend>{
            setup_id, request.session_id, circuit_id, trace->trace_id,
            request_digest, encrypted_statement, std::move(trace)}};
}

/// Evaluate directly into a compact file trace while retaining only the
/// response output in memory. The store's publication contract detects
/// incomplete files but does not promise power-loss durability.
template <fhe::PersistableFheBackend Backend>
FileFoldedServerEvaluationResult<Backend>
evaluate_folded_request_file_reference(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const EvaluationSetup<Backend> &server,
    const FoldedEvaluationRequest<Backend> &request,
    const payload::FheEvaluationPlan &plan,
    const std::filesystem::path &trace_directory,
    payload::FileTraceStoreOptions storage_options) {
    folded_server_detail::validate_folded_evaluation_request(
        payload, circuit, server, request);
    const Digest setup_id = setup_digest(server.public_setup);
    const Digest circuit_id = payload::combined_digest(payload, circuit);
    const std::filesystem::path durable_trace_directory =
        std::filesystem::absolute(trace_directory).lexically_normal();
    auto evaluated = payload::evaluate_wide_fhe_trace_into<Backend>(
        server.context, payload, circuit, request.encrypted_inputs, plan,
        server_storage_detail::FileTraceAndOutputSink<
            Backend, FoldedFheOutput<Backend>>{
            server.context, durable_trace_directory, storage_options});
    if (evaluated.trace_store.descriptor.provenance !=
            payload::TraceProvenance::FheEvaluated ||
        evaluated.trace_store.descriptor.circuit_id != circuit_id ||
        evaluated.trace_store.descriptor.trace_id != request.trace_id ||
        evaluated.trace_store.descriptor.shape.kind !=
            payload::PayloadKind::Wide ||
        evaluated.trace_store.descriptor.layers.empty() ||
        evaluated.output.dimensions !=
            evaluated.trace_store.descriptor.layers.front().dimensions ||
        evaluated.output.values.size() !=
            evaluated.trace_store.descriptor.layers.front().record_count) {
        throw std::logic_error(
            "evaluate_folded_request_file_reference: evaluator returned a "
            "mismatched trace");
    }
    const Digest request_digest =
        folded_server_detail::folded_request_commitment(request);
    const Digest encrypted_statement =
        folded_server_detail::folded_statement_digest(
            request_digest, setup_id, request.session_id, circuit_id,
            request.trace_id, evaluated.output);
    return FileFoldedServerEvaluationResult<Backend>{
        std::move(evaluated.output),
        FileFoldedServerReadyToProve{
            setup_id, request.session_id, circuit_id, request.trace_id,
            request_digest, encrypted_statement,
            std::move(evaluated.trace_store)}};
}

/// Evaluate while publishing only the admitted sparse checkpoint set. Proof
/// setup, scratch, and whole-server limits are fixed before FHE and retained
/// immutably until the destructive proof transition.
template <typename Backend>
    requires packing::SignedDigitPackingBackend<Backend> &&
             fhe::PersistableFheBackend<Backend>
CheckpointReplayFoldedServerEvaluationResult<Backend>
evaluate_folded_request_with_resident_packing_reference(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const EvaluationSetup<Backend> &server,
    const protocol::FoldedSetup &packing_setup,
    const FoldedEvaluationRequest<Backend> &request,
    const payload::FheEvaluationPlan &evaluation,
    const payload::PayloadCheckpointReplayProblem &problem,
    const payload::PayloadCheckpointReplayBudgets &budgets,
    const payload::PayloadCheckpointReplayPlan &replay_plan,
    payload::PayloadCheckpointReplayExecutionOptions options,
    protocol::reference::IrreversibleFoldedFileProofOptions proof_options,
    protocol::CheckpointReplayServerStorageLimits storage_limits) {
    folded_server_detail::validate_folded_evaluation_request(
        payload, circuit, server, request);
    protocol::preflight_folded_packing_setup<Backend>(
        circuit, server, packing_setup);
    if (options.lifecycle !=
        payload::FileTraceSessionLifecycle::IrreversibleNoRetry) {
        throw std::invalid_argument(
            "evaluate_folded_request_resident_reference_with_reference_packing: explicit "
            "IrreversibleNoRetry lifecycle is required");
    }
    if (proof_options.lifecycle !=
            payload::FileTraceSessionLifecycle::IrreversibleNoRetry ||
        !proof_options.reclaim_completed_multiplication_scratch) {
        throw std::invalid_argument(
            "evaluate_folded_request_resident_reference_with_reference_packing: proof "
            "resources require IrreversibleNoRetry and completed scratch "
            "reclamation");
    }
    options.directory =
        payload::preflight_and_normalize_payload_checkpoint_replay_root(
            options.directory);
    proof_options.proof =
        gkr::folded_detail::
            preflight_and_normalize_file_folded_gkr_scratch(
                circuit, options.directory, proof_options.proof);
    const protocol::CheckpointReplayServerStorageAdmission admission =
        protocol::admit_checkpoint_replay_server_storage(
            problem, budgets, replay_plan, proof_options.proof,
            proof_options.reclaim_completed_multiplication_scratch,
            storage_limits);
    CheckpointReplayFoldedServerResources resources{
        packing_setup, std::move(proof_options), std::move(storage_limits),
        admission};
    const Digest setup_id = setup_digest(server.public_setup);
    const Digest circuit_id = payload::combined_digest(payload, circuit);
    std::vector<fhe::FheValue<Backend>> output;
    auto trace = payload::PayloadCheckpointReplayTrace<Backend>::publish(
        server.context, payload, circuit, request.encrypted_inputs,
        evaluation, problem, budgets, replay_plan, std::move(options),
        output);
    const payload::EncryptedTraceDescriptor &descriptor = trace.descriptor();
    if (descriptor.provenance != payload::TraceProvenance::FheEvaluated ||
        descriptor.circuit_id != circuit_id ||
        descriptor.trace_id != request.trace_id ||
        descriptor.shape.kind != payload::PayloadKind::Wide ||
        descriptor.layers.empty() ||
        output.size() != descriptor.layers.front().record_count ||
        trace.backend_context_id() !=
            Backend::storage_context_id(server.context) ||
        trace.layered_circuit_id() != payload::digest(circuit) ||
        !trace.report().checkpoint_set_published ||
        trace.report().all_payload_artifacts_retired) {
        throw std::logic_error(
            "Folded checkpoint replay evaluator returned a mismatched "
            "session");
    }
    FoldedFheOutput<Backend> encrypted_output{
        descriptor.layers.front().dimensions, std::move(output)};
    const Digest request_digest =
        folded_server_detail::folded_request_commitment(request);
    const Digest encrypted_statement =
        folded_server_detail::folded_statement_digest(
            request_digest, setup_id, request.session_id, circuit_id,
            request.trace_id, encrypted_output);
    return CheckpointReplayFoldedServerEvaluationResult<Backend>{
        std::move(encrypted_output),
        CheckpointReplayFoldedServerReadyToProve<Backend>{
            setup_id, request.session_id, circuit_id, request.trace_id,
            request_digest, encrypted_statement, std::move(trace),
            std::move(resources)}};
}

/// External-preprocessing counterpart. The complete packing artifact scan,
/// mutable-root separation, and exact storage admission all finish before
/// payload FHE begins. The returned one-shot state retains that admission;
/// proving consumes it without reconstructing a resident packing setup or
/// rescanning immutable preprocessing. `packing_setup` must outlive the
/// returned state and proof transition.
template <typename Backend>
    requires packing::SignedDigitPackingBackend<Backend> &&
             fhe::PersistableFheBackend<Backend>
CheckpointReplayFoldedServerEvaluationResult<Backend>
evaluate_folded_request_with_external_packing_reference(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const EvaluationSetup<Backend> &server,
    const protocol::PackedExternalProverSetup &packing_setup,
    const FoldedEvaluationRequest<Backend> &request,
    const payload::FheEvaluationPlan &evaluation,
    const payload::PayloadCheckpointReplayProblem &problem,
    const payload::PayloadCheckpointReplayBudgets &budgets,
    const payload::PayloadCheckpointReplayPlan &replay_plan,
    payload::PayloadCheckpointReplayExecutionOptions options,
    protocol::reference::IrreversibleFoldedFileProofOptions proof_options,
    protocol::TranscriptPackingExternalAdmission packing_admission,
    protocol::CheckpointReplayServerStorageLimits storage_limits) {
    folded_server_detail::validate_folded_evaluation_request(
        payload, circuit, server, request);
    protocol::preflight_packed_external_prover_setup<Backend>(
        protocol::PackingGkrVariant::Folded, payload, circuit, server,
        packing_setup);
    if (!packing_admission.matches(
            protocol::PackingGkrVariant::Folded,
            packing_setup.transcript_packing())) {
        throw std::invalid_argument(
            "Folded external packing admission belongs to a different "
            "preprocessed setup");
    }
    if (options.lifecycle !=
        payload::FileTraceSessionLifecycle::IrreversibleNoRetry) {
        throw std::invalid_argument(
            "evaluate_folded_request_resident_reference_with_reference_packing: explicit "
            "IrreversibleNoRetry lifecycle is required");
    }
    if (proof_options.lifecycle !=
            payload::FileTraceSessionLifecycle::IrreversibleNoRetry ||
        !proof_options.reclaim_completed_multiplication_scratch) {
        throw std::invalid_argument(
            "evaluate_folded_request_resident_reference_with_reference_packing: proof "
            "resources require IrreversibleNoRetry and completed scratch "
            "reclamation");
    }
    options.directory =
        payload::preflight_and_normalize_payload_checkpoint_replay_root(
            options.directory);
    proof_options.proof =
        gkr::folded_detail::
            preflight_and_normalize_file_folded_gkr_scratch(
                circuit, options.directory, proof_options.proof);
    protocol::preflight_folded_packed_external_resource_roots(
        options.directory, proof_options, packing_admission);
    const protocol::CheckpointReplayServerStorageAdmission admission =
        protocol::admit_checkpoint_replay_server_storage(
            problem, budgets, replay_plan, proof_options.proof,
            proof_options.reclaim_completed_multiplication_scratch,
            storage_limits);
    CheckpointReplayFoldedServerResources resources{
        packing_setup, packing_setup.identity(),
        std::move(packing_admission),
        std::move(proof_options), std::move(storage_limits), admission};
    const Digest setup_id = setup_digest(server.public_setup);
    const Digest circuit_id = payload::combined_digest(payload, circuit);
    std::vector<fhe::FheValue<Backend>> output;
    auto trace = payload::PayloadCheckpointReplayTrace<Backend>::publish(
        server.context, payload, circuit, request.encrypted_inputs,
        evaluation, problem, budgets, replay_plan, std::move(options),
        output);
    const payload::EncryptedTraceDescriptor &descriptor = trace.descriptor();
    if (descriptor.provenance != payload::TraceProvenance::FheEvaluated ||
        descriptor.circuit_id != circuit_id ||
        descriptor.trace_id != request.trace_id ||
        descriptor.shape.kind != payload::PayloadKind::Wide ||
        descriptor.layers.empty() ||
        output.size() != descriptor.layers.front().record_count ||
        trace.backend_context_id() !=
            Backend::storage_context_id(server.context) ||
        trace.layered_circuit_id() != payload::digest(circuit) ||
        !trace.report().checkpoint_set_published ||
        trace.report().all_payload_artifacts_retired) {
        throw std::logic_error(
            "external Folded checkpoint replay evaluator returned a "
            "mismatched session");
    }
    FoldedFheOutput<Backend> encrypted_output{
        descriptor.layers.front().dimensions, std::move(output)};
    const Digest request_digest =
        folded_server_detail::folded_request_commitment(request);
    const Digest encrypted_statement =
        folded_server_detail::folded_statement_digest(
            request_digest, setup_id, request.session_id, circuit_id,
            request.trace_id, encrypted_output);
    return CheckpointReplayFoldedServerEvaluationResult<Backend>{
        std::move(encrypted_output),
        CheckpointReplayFoldedServerReadyToProve<Backend>{
            setup_id, request.session_id, circuit_id, request.trace_id,
            request_digest, encrypted_statement, std::move(trace),
            std::move(resources)}};
}

template <fhe::PersistableFheBackend Backend>
payload::FileEncryptedTraceStore<Backend> open_folded_server_trace_reference(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const EvaluationSetup<Backend> &server,
    const FileFoldedServerReadyToProve &state,
    payload::FileTraceStoreOpenLimits limits) {
    server.public_setup.validate(payload, circuit);
    const Digest setup_id = setup_digest(server.public_setup);
    const Digest circuit_id = payload::combined_digest(payload, circuit);
    if (state.setup_id != setup_id || state.session_id == Digest{} ||
        state.circuit_id != circuit_id ||
        state.trace_id != state.trace_store.descriptor.trace_id ||
        state.trace_store.descriptor.circuit_id != circuit_id ||
        state.trace_store.descriptor.provenance !=
            payload::TraceProvenance::FheEvaluated ||
        state.trace_store.descriptor.shape.kind !=
            payload::PayloadKind::Wide ||
        state.trace_store.backend_context_id !=
            Backend::storage_context_id(server.context)) {
        throw std::invalid_argument(
            "open_folded_server_trace_reference: retained-state binding mismatch");
    }
    return payload::FileEncryptedTraceStore<Backend>::open(
        server.context, state.trace_store.directory, payload, circuit,
        payload::TraceProvenance::FheEvaluated, state.trace_id, limits);
}

} // namespace laminate::delegation::reference

#endif // LAMINATE_DELEGATION_FOLDED_REFERENCE_EVALUATION_HPP
