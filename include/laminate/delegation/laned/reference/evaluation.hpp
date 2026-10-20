#ifndef LAMINATE_DELEGATION_LANED_REFERENCE_EVALUATION_HPP
#define LAMINATE_DELEGATION_LANED_REFERENCE_EVALUATION_HPP

/// @file reference/evaluation.hpp
/// @brief Laned resident, file, and uncached replay evaluation paths.

#include "laminate/delegation/laned/server/admission.hpp"
#include "laminate/protocol/reference/laned.hpp"

namespace laminate::delegation::reference {

/// Evaluate encrypted inputs and retain the exact output and compact trace
/// required by proving. Structural padding remains virtual in every path.
template <fhe::FheBackend Backend>
LanedServerEvaluationResult<Backend> evaluate_laned_request_resident_reference(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const EvaluationSetup<Backend> &server,
    const LanedEvaluationRequest<Backend> &request,
    const payload::FheEvaluationPlan &plan) {
    laned_server_detail::validate_laned_evaluation_request(
        payload, circuit, server, request);
    const Digest setup_id = setup_digest(server.public_setup);
    const Digest circuit_id = payload::combined_digest(payload, circuit);

    auto trace = std::make_shared<payload::EncryptedTrace<Backend>>(
        payload::evaluate_laned_fhe_trace_into<Backend>(
            server.context, payload, circuit, request.encrypted_inputs,
            plan,
            payload::InMemoryTraceSink<Backend>{
                server.context}));
    if (trace->circuit_id != circuit_id ||
        trace->trace_id != request.trace_id || trace->layers.empty()) {
        throw std::logic_error(
            "evaluate_laned_request_resident_reference: evaluator returned a mismatched trace");
    }

    const payload::LayerWireSupport output_support =
        payload::canonical_layer_wire_support(circuit, 0);
    if (trace->layers.front().wires.size() !=
        output_support.live_wire_count) {
        throw std::logic_error(
            "evaluate_laned_request_resident_reference: output support mismatch");
    }

    LanedFheOutput<Backend> output{
        trace->layers.front().dimensions, trace->layers.front().wires};
    const Digest request_digest =
        laned_server_detail::laned_request_commitment(request);
    const Digest encrypted_statement = laned_server_detail::laned_statement_digest(
        request_digest, setup_id, request.session_id, circuit_id,
        trace->trace_id, output);
    return LanedServerEvaluationResult<Backend>{
        std::move(output),
        LanedServerReadyToProve<Backend>{
            setup_id, request.session_id, circuit_id, trace->trace_id,
            request_digest, encrypted_statement,
            std::move(trace)}};
}

/// Evaluate a request while writing the complete encrypted trace directly to
/// a caller-owned directory. The returned response retains only layer zero;
/// the move-only server state retains the validated store description needed
/// to reopen the private trace in a later process phase.
template <fhe::PersistableFheBackend Backend>
FileLanedServerEvaluationResult<Backend>
evaluate_laned_request_file_reference(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const EvaluationSetup<Backend> &server,
    const LanedEvaluationRequest<Backend> &request,
    const payload::FheEvaluationPlan &plan,
    const std::filesystem::path &trace_directory,
    payload::FileTraceStoreOptions storage_options) {
    laned_server_detail::validate_laned_evaluation_request(
        payload, circuit, server, request);
    const Digest setup_id = setup_digest(server.public_setup);
    const Digest circuit_id = payload::combined_digest(payload, circuit);
    const std::filesystem::path durable_trace_directory =
        std::filesystem::absolute(trace_directory).lexically_normal();

    auto evaluated = payload::evaluate_laned_fhe_trace_into<Backend>(
        server.context, payload, circuit, request.encrypted_inputs, plan,
        server_storage_detail::FileTraceAndOutputSink<
            Backend, LanedFheOutput<Backend>>{
            server.context, durable_trace_directory, storage_options});
    if (evaluated.trace_store.descriptor.provenance !=
            payload::TraceProvenance::FheEvaluated ||
        evaluated.trace_store.descriptor.circuit_id != circuit_id ||
        evaluated.trace_store.descriptor.trace_id != request.trace_id ||
        evaluated.trace_store.descriptor.layers.empty() ||
        evaluated.output.dimensions !=
            evaluated.trace_store.descriptor.layers.front().dimensions ||
        evaluated.output.values.size() !=
            evaluated.trace_store.descriptor.layers.front()
                .record_count) {
        throw std::logic_error(
            "evaluate_laned_request_file_reference: evaluator returned a "
            "mismatched trace");
    }

    const Digest request_digest =
        laned_server_detail::laned_request_commitment(request);
    const Digest encrypted_statement = laned_server_detail::laned_statement_digest(
        request_digest, setup_id, request.session_id, circuit_id,
        request.trace_id, evaluated.output);
    return FileLanedServerEvaluationResult<Backend>{
        std::move(evaluated.output),
        FileLanedServerReadyToProve{
            setup_id, request.session_id, circuit_id, request.trace_id,
            request_digest, encrypted_statement,
            std::move(evaluated.trace_store)}};
}

/// Evaluate a Laned request while publishing only the admitted sparse
/// checkpoint set. The evaluation result retains the complete live
/// output-layer ciphertext batch until proof publication;
/// the move-only server state retains the backend-bound replay session. This
/// transition is intentionally in-process and not crash-resumable. `server`
/// (including its evaluation context) and `circuit` must outlive the returned
/// state and proof call. The packing setup is shallow-copied before FHE:
/// heavyweight immutable preprocessing is shared, while mutable wrapper
/// values become private retained state. The state cannot be rebound or
/// reopened. Its proof transition requires immediate reclamation of every
/// completed multiplication scratch artifact. Proof scratch and whole-server
/// resource limits are supplied now, before FHE evaluation, and become
/// immutable retained state; no later online message can replace them.
template <typename Backend>
    requires packing::SignedDigitPackingBackend<Backend> &&
             fhe::PersistableFheBackend<Backend>
CheckpointReplayLanedServerEvaluationResult<Backend>
evaluate_laned_request_with_resident_packing_reference(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const EvaluationSetup<Backend> &server,
    const protocol::LanedSetup &packing_setup,
    const LanedEvaluationRequest<Backend> &request,
    const payload::FheEvaluationPlan &evaluation,
    const payload::PayloadCheckpointReplayProblem &problem,
    const payload::PayloadCheckpointReplayBudgets &budgets,
    const payload::PayloadCheckpointReplayPlan &replay_plan,
    payload::PayloadCheckpointReplayExecutionOptions options,
    protocol::reference::IrreversibleLanedFileProofOptions proof_options,
    protocol::CheckpointReplayServerStorageLimits storage_limits) {
    laned_server_detail::validate_laned_evaluation_request(
        payload, circuit, server, request);
    protocol::preflight_laned_packing_setup<Backend>(
        circuit, server, packing_setup);
    if (options.lifecycle !=
        payload::FileTraceSessionLifecycle::IrreversibleNoRetry) {
        throw std::invalid_argument(
            "evaluate_laned_request_resident_reference_with_reference_packing: explicit "
            "IrreversibleNoRetry lifecycle is required");
    }
    if (proof_options.lifecycle !=
            payload::FileTraceSessionLifecycle::IrreversibleNoRetry ||
        !proof_options.reclaim_completed_multiplication_scratch) {
        throw std::invalid_argument(
            "evaluate_laned_request_resident_reference_with_reference_packing: proof "
            "resources require IrreversibleNoRetry and completed scratch "
            "reclamation");
    }
    options.directory =
        payload::preflight_and_normalize_payload_checkpoint_replay_root(
            options.directory);
    proof_options.proof =
        gkr::laned_detail::
            preflight_and_normalize_laned_gkr_scratch(
                circuit, options.directory, proof_options.proof);
    laned_server_detail::include_eager_laned_execution_peak(
        circuit, problem, budgets, replay_plan,
        options.eager_laned_witness_packing, storage_limits);
    const protocol::CheckpointReplayServerStorageAdmission admission =
        protocol::admit_checkpoint_replay_server_storage(
            problem, budgets, replay_plan, proof_options.proof,
            proof_options.reclaim_completed_multiplication_scratch,
            storage_limits);
    CheckpointReplayLanedServerResources resources{
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
        descriptor.layers.empty() ||
        output.size() !=
            descriptor.layers.front().record_count ||
        trace.backend_context_id() !=
            Backend::storage_context_id(server.context) ||
        trace.layered_circuit_id() != payload::digest(circuit) ||
        !trace.report().checkpoint_set_published ||
        trace.report().all_payload_artifacts_retired) {
        throw std::logic_error(
            "checkpoint replay evaluator returned a mismatched session");
    }

    LanedFheOutput<Backend> encrypted_output{
        descriptor.layers.front().dimensions, std::move(output)};
    const Digest request_digest =
        laned_server_detail::laned_request_commitment(request);
    const Digest encrypted_statement = laned_server_detail::laned_statement_digest(
        request_digest, setup_id, request.session_id, circuit_id,
        request.trace_id, encrypted_output);
    return CheckpointReplayLanedServerEvaluationResult<Backend>{
        std::move(encrypted_output),
        CheckpointReplayLanedServerReadyToProve<Backend>{
            setup_id, request.session_id, circuit_id, request.trace_id,
            request_digest, encrypted_statement,
            std::move(trace), std::move(resources)}};
}

/// External-preprocessing counterpart. Every immutable packing artifact and
/// mutable proof namespace is authenticated/admitted before payload FHE. The
/// resulting one-shot server state consumes that retained admission during
/// proving, without reconstructing resident R1CS preprocessing or rescanning
/// external state. `packing_setup` must outlive the state and proof call.
template <typename Backend>
    requires packing::SignedDigitPackingBackend<Backend> &&
             fhe::PersistableFheBackend<Backend>
CheckpointReplayLanedServerEvaluationResult<Backend>
evaluate_laned_request_with_external_packing_reference(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const EvaluationSetup<Backend> &server,
    const protocol::PackedExternalProverSetup &packing_setup,
    const LanedEvaluationRequest<Backend> &request,
    const payload::FheEvaluationPlan &evaluation,
    const payload::PayloadCheckpointReplayProblem &problem,
    const payload::PayloadCheckpointReplayBudgets &budgets,
    const payload::PayloadCheckpointReplayPlan &replay_plan,
    payload::PayloadCheckpointReplayExecutionOptions options,
    protocol::reference::IrreversibleLanedFileProofOptions proof_options,
    protocol::TranscriptPackingExternalAdmission packing_admission,
    protocol::CheckpointReplayServerStorageLimits storage_limits) {
    laned_server_detail::validate_laned_evaluation_request(
        payload, circuit, server, request);
    protocol::preflight_packed_external_prover_setup<Backend>(
        protocol::PackingGkrVariant::Laned, payload, circuit, server,
        packing_setup);
    if (!packing_admission.matches(
            protocol::PackingGkrVariant::Laned,
            packing_setup.transcript_packing())) {
        throw std::invalid_argument(
            "Laned external packing admission belongs to a different "
            "preprocessed setup");
    }
    if (options.lifecycle !=
        payload::FileTraceSessionLifecycle::IrreversibleNoRetry) {
        throw std::invalid_argument(
            "evaluate_laned_request_resident_reference_with_reference_packing: explicit "
            "IrreversibleNoRetry lifecycle is required");
    }
    if (proof_options.lifecycle !=
            payload::FileTraceSessionLifecycle::IrreversibleNoRetry ||
        !proof_options.reclaim_completed_multiplication_scratch) {
        throw std::invalid_argument(
            "evaluate_laned_request_resident_reference_with_reference_packing: proof "
            "resources require IrreversibleNoRetry and completed scratch "
            "reclamation");
    }
    options.directory =
        payload::preflight_and_normalize_payload_checkpoint_replay_root(
            options.directory);
    proof_options.proof =
        gkr::laned_detail::
            preflight_and_normalize_laned_gkr_scratch(
                circuit, options.directory, proof_options.proof);
    protocol::preflight_laned_packed_external_resource_roots(
        options.directory, proof_options, packing_admission);
    laned_server_detail::include_eager_laned_execution_peak(
        circuit, problem, budgets, replay_plan,
        options.eager_laned_witness_packing, storage_limits);
    const protocol::CheckpointReplayServerStorageAdmission admission =
        protocol::admit_checkpoint_replay_server_storage(
            problem, budgets, replay_plan, proof_options.proof,
            proof_options.reclaim_completed_multiplication_scratch,
            storage_limits);
    CheckpointReplayLanedServerResources resources{
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
        descriptor.shape.kind != payload::PayloadKind::Laned ||
        descriptor.layers.empty() ||
        output.size() != descriptor.layers.front().record_count ||
        trace.backend_context_id() !=
            Backend::storage_context_id(server.context) ||
        trace.layered_circuit_id() != payload::digest(circuit) ||
        !trace.report().checkpoint_set_published ||
        trace.report().all_payload_artifacts_retired) {
        throw std::logic_error(
            "external Laned checkpoint replay evaluator returned a "
            "mismatched session");
    }
    LanedFheOutput<Backend> encrypted_output{
        descriptor.layers.front().dimensions, std::move(output)};
    const Digest request_digest = laned_server_detail::laned_request_commitment(request);
    const Digest encrypted_statement = laned_server_detail::laned_statement_digest(
        request_digest, setup_id, request.session_id, circuit_id,
        request.trace_id, encrypted_output);
    return CheckpointReplayLanedServerEvaluationResult<Backend>{
        std::move(encrypted_output),
        CheckpointReplayLanedServerReadyToProve<Backend>{
            setup_id, request.session_id, circuit_id, request.trace_id,
            request_digest, encrypted_statement, std::move(trace),
            std::move(resources)}};
}

template <fhe::PersistableFheBackend Backend>
payload::FileEncryptedTraceStore<Backend>
open_laned_server_trace_reference(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const EvaluationSetup<Backend> &server,
    const FileLanedServerReadyToProve &state,
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
        state.trace_store.backend_context_id !=
            Backend::storage_context_id(server.context)) {
        throw std::invalid_argument(
            "open_laned_server_trace_reference: retained-state binding mismatch");
    }
    return payload::FileEncryptedTraceStore<Backend>::open(
        server.context, state.trace_store.directory, payload, circuit,
        payload::TraceProvenance::FheEvaluated, state.trace_id, limits);
}

} // namespace laminate::delegation::reference

#endif // LAMINATE_DELEGATION_LANED_REFERENCE_EVALUATION_HPP
