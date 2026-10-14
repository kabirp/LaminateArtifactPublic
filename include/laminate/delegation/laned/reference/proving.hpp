#ifndef LAMINATE_DELEGATION_LANED_REFERENCE_PROVING_HPP
#define LAMINATE_DELEGATION_LANED_REFERENCE_PROVING_HPP

/// @file reference/proving.hpp
/// @brief Laned resident, file, and uncached replay proving paths.

#include "laminate/delegation/laned/reference/evaluation.hpp"
#include "laminate/protocol/reference/laned.hpp"

namespace laminate::delegation::reference {

/// Prove against the exact encrypted output retained from evaluation. The
/// server and client derive the same output point from the encrypted statement.
template <packing::SignedDigitPackingBackend Backend>
LanedResponse<Backend> prove_laned_request_resident_reference(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const EvaluationSetup<Backend> &server,
    const protocol::LanedSetup &packing_setup,
    LanedServerEvaluationResult<Backend> evaluated,
    Transcript &transcript) {
    server.public_setup.validate(payload, circuit);
    const Digest setup_id = setup_digest(server.public_setup);
    const Digest circuit_id = payload::combined_digest(payload, circuit);
    auto &state = evaluated.state;
    if (state.setup_id != setup_id || state.session_id == Digest{} ||
        state.circuit_id != circuit_id || !state.trace ||
        state.trace->circuit_id != circuit_id ||
        state.trace_id != state.trace->trace_id ||
        state.trace->provenance != payload::TraceProvenance::FheEvaluated ||
        evaluated.output.dimensions !=
            state.trace->layers.front().dimensions ||
        evaluated.output.values.size() !=
            state.trace->layers.front().wires.size()) {
        throw std::invalid_argument(
            "prove_laned_request_resident_reference: retained-state binding mismatch");
    }
    const Digest encrypted_statement = laned_server_detail::laned_statement_digest(
        state.request_commitment, setup_id, state.session_id, circuit_id,
        state.trace_id, evaluated.output);
    if (encrypted_statement != state.statement_digest) {
        throw std::invalid_argument(
            "prove_laned_request_resident_reference: encrypted output changed after "
            "evaluation");
    }
    observe_packed_delegation_bindings(
        transcript, setup_id, state.session_id);
    const std::vector<Fpk> output_point = derive_packed_output_point(
        transcript, PackedProtocolVariant::Laned, encrypted_statement,
        gkr::laned_layer_variables(circuit, 0));
    protocol::LaminateLanedProof<Backend> proof =
        protocol::reference::prove_laned<Backend>(
            payload, circuit, *state.trace, server, packing_setup,
            output_point, transcript);
    return LanedResponse<Backend>{
        setup_id, state.session_id, circuit_id, state.trace_id,
        std::move(evaluated.output),
        std::move(proof)};
}

/// One-shot file-backed proving transition. The exact encrypted output remains
/// server-owned until it is combined with the completed proof. The default
/// lifecycle fails closed. Once `IrreversibleNoRetry` is selected, any later
/// GKR, transcript-packing, or scratch-cleanup failure is terminal; the
/// retirement journal is diagnostic rather than resumable state.
template <packing::SignedDigitPackingBackend Backend>
FileLanedServerProofResult<Backend>
prove_laned_request_file_irreversible_reference(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const EvaluationSetup<Backend> &server,
    const protocol::LanedSetup &packing_setup,
    FileLanedServerEvaluationResult<Backend> evaluated,
    Transcript &transcript,
    protocol::reference::IrreversibleLanedFileProofOptions options,
    payload::FileTraceStoreOpenLimits open_limits) {
    if (options.lifecycle !=
        payload::FileTraceSessionLifecycle::IrreversibleNoRetry) {
        throw std::invalid_argument(
            "prove_laned_request_file_irreversible_reference: explicit "
            "IrreversibleNoRetry lifecycle is required");
    }
    server.public_setup.validate(payload, circuit);
    const Digest setup_id = setup_digest(server.public_setup);
    const Digest circuit_id = payload::combined_digest(payload, circuit);
    auto &state = evaluated.state;
    if (state.setup_id != setup_id || state.session_id == Digest{} ||
        state.circuit_id != circuit_id ||
        state.trace_id != state.trace_store.descriptor.trace_id ||
        state.trace_store.descriptor.provenance !=
            payload::TraceProvenance::FheEvaluated ||
        state.trace_store.descriptor.layers.empty() ||
        evaluated.output.dimensions !=
            state.trace_store.descriptor.layers.front().dimensions ||
        evaluated.output.values.size() !=
            state.trace_store.descriptor.layers.front().record_count) {
        throw std::invalid_argument(
            "prove_laned_request_file_irreversible_reference: retained-state "
            "binding mismatch");
    }

    const Digest encrypted_statement = laned_server_detail::laned_statement_digest(
        state.request_commitment, setup_id, state.session_id, circuit_id,
        state.trace_id, evaluated.output);
    if (encrypted_statement != state.statement_digest) {
        throw std::invalid_argument(
            "prove_laned_request_file_irreversible_reference: encrypted output "
            "changed after evaluation");
    }
    Transcript proof_transcript = transcript;
    observe_packed_delegation_bindings(
        proof_transcript, setup_id, state.session_id);
    const std::vector<Fpk> output_point = derive_packed_output_point(
        proof_transcript, PackedProtocolVariant::Laned,
        encrypted_statement, gkr::laned_layer_variables(circuit, 0));

    auto stored_trace = open_laned_server_trace_reference<Backend>(
        payload, circuit, server, state, open_limits);
    protocol::reference::preflight_laned_file_irreversible_reference<Backend>(
        payload, circuit, stored_trace, server, packing_setup,
        output_point, options);
    auto trace =
        payload::FileEncryptedTraceReclamationSession<Backend>::begin(
            std::move(stored_trace),
            payload::FileTraceReclamationOptions{options.lifecycle});
    protocol::reference::LanedFileProofResult<Backend> proved =
        protocol::reference::prove_laned_file_irreversible_reference<Backend>(
            payload, circuit, trace, server, packing_setup,
            output_point, proof_transcript, std::move(options));
    FileLanedServerProofResult<Backend> result{
        LanedResponse<Backend>{
            setup_id, state.session_id, circuit_id, state.trace_id,
            std::move(evaluated.output), std::move(proved.proof)},
        std::move(proved.gkr_report)};
    transcript = std::move(proof_transcript);
    return result;
}

/// One-shot sparse-checkpoint proving transition. The caller retains the
/// state while all deterministic bindings, setup geometry, scratch
/// destinations, and the explicit no-retry lifecycle are checked. A rejected
/// preflight leaves both state and caller transcript reusable. Once GKR
/// begins, any replay, packing, or cleanup failure is terminal for the state;
/// proof work is staged on a transcript copy and published only on success.
/// The evaluation-time input and sole response output are already charged to
/// the payload/GKR reserve. No client message is accepted between evaluation
/// and this proof transition.
template <typename Backend>
    requires packing::SignedDigitPackingBackend<Backend> &&
             fhe::PersistableFheBackend<Backend>
CheckpointReplayLanedServerProofResult<Backend>
prove_laned_request_checkpoint_replay_irreversible_reference(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const EvaluationSetup<Backend> &server,
    CheckpointReplayLanedServerEvaluationResult<Backend> &evaluated,
    Transcript &transcript) {
    auto &state = evaluated.state;
    if (state.resources().uses_external_packing()) {
        throw std::invalid_argument(
            "resident Laned proof cannot consume external packing "
            "resources");
    }
    const protocol::reference::IrreversibleLanedFileProofOptions &proof_options =
        state.resources().proof_options();
    const protocol::LanedSetup &packing_setup =
        state.resources().packing_setup();
    if (proof_options.lifecycle !=
            payload::FileTraceSessionLifecycle::IrreversibleNoRetry) {
        throw std::invalid_argument(
            "prove_laned_request_checkpoint_replay_irreversible_reference: "
            "explicit IrreversibleNoRetry lifecycle is required");
    }
    server.public_setup.validate(payload, circuit);
    const Digest setup_id = setup_digest(server.public_setup);
    const Digest circuit_id = payload::combined_digest(payload, circuit);
    const payload::EncryptedTraceDescriptor &descriptor =
        state.trace.descriptor();
    if (state.setup_id != setup_id || state.session_id == Digest{} ||
        state.circuit_id != circuit_id ||
        state.trace_id != descriptor.trace_id ||
        descriptor.circuit_id != circuit_id ||
        descriptor.provenance != payload::TraceProvenance::FheEvaluated ||
        descriptor.layers.empty() ||
        evaluated.output.dimensions !=
            descriptor.layers.front().dimensions ||
        evaluated.output.values.size() !=
            descriptor.layers.front().record_count ||
        state.trace.backend_context_id() !=
            Backend::storage_context_id(server.context) ||
        state.trace.layered_circuit_id() != payload::digest(circuit) ||
        !state.trace.report().checkpoint_set_published ||
        state.trace.report().all_payload_artifacts_retired) {
        throw std::invalid_argument(
            "checkpoint replay proof retained-state binding mismatch");
    }
    protocol::preflight_laned_packing_setup<Backend>(
        circuit, server, packing_setup);
    const protocol::CheckpointReplayServerStorageAdmission readmitted =
        protocol::admit_checkpoint_replay_server_storage(
            state.trace.problem(), state.trace.budgets(),
            state.trace.plan(), proof_options.proof,
            proof_options.reclaim_completed_multiplication_scratch,
            state.resources().storage_limits());
    if (readmitted != state.resources().admission()) {
        throw std::logic_error(
            "checkpoint replay retained storage admission drifted");
    }
    const Digest encrypted_statement = laned_server_detail::laned_statement_digest(
        state.request_commitment, setup_id, state.session_id, circuit_id,
        state.trace_id, evaluated.output);
    if (encrypted_statement != state.statement_digest) {
        throw std::invalid_argument(
            "checkpoint replay encrypted output changed after evaluation");
    }
    Transcript proof_transcript = transcript;
    observe_packed_delegation_bindings(
        proof_transcript, setup_id, state.session_id);
    const std::vector<Fpk> output_point = derive_packed_output_point(
        proof_transcript, PackedProtocolVariant::Laned,
        encrypted_statement, gkr::laned_layer_variables(circuit, 0));
    protocol::reference::preflight_laned_checkpoint_replay_irreversible_reference<Backend>(
        payload, circuit, state.trace, server, packing_setup,
        output_point, proof_options);
    protocol::reference::LanedCheckpointReplayProofResult<Backend> proved =
        protocol::reference::prove_laned_checkpoint_replay_irreversible_reference<Backend>(
            payload, circuit, state.trace, server, packing_setup,
            output_point, proof_transcript, proof_options);
    CheckpointReplayLanedServerProofResult<Backend> result{
        LanedResponse<Backend>{
            setup_id, state.session_id, circuit_id, state.trace_id,
            std::move(evaluated.output), std::move(proved.proof)},
        std::move(proved.gkr_report),
        std::move(proved.payload_replay_report),
        state.resources().admission()};
    transcript = std::move(proof_transcript);
    return result;
}

/// One-round Laned server transition with artifact-backed transcript packing.
/// Complete request, setup, session, circuit, trace, output, storage, and
/// scratch admission precedes destructive replay. A failure after replay
/// starts is terminal and publishes no response; success returns the same
/// sole `LanedResponse` consumed by the existing client and wire codec.
template <typename Backend>
    requires packing::SignedDigitPackingBackend<Backend> &&
             fhe::PersistableFheBackend<Backend>
CheckpointReplayLanedExternalServerProofResult<Backend>
prove_laned_request_external_checkpoint_replay_irreversible_reference(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const EvaluationSetup<Backend> &server,
    const protocol::PackedExternalProverSetup &packing_setup,
    CheckpointReplayLanedServerEvaluationResult<Backend> &evaluated,
    Transcript &transcript) {
    auto &state = evaluated.state;
    if (!state.resources().uses_external_packing() ||
        !state.resources().matches_external_packing_setup(packing_setup) ||
        state.resources().external_packing_setup_identity() !=
            packing_setup.identity()) {
        throw std::invalid_argument(
            "external Laned proof setup does not match its retained "
            "pre-payload admission");
    }
    const protocol::reference::IrreversibleLanedFileProofOptions &proof_options =
        state.resources().proof_options();
    if (proof_options.lifecycle !=
            payload::FileTraceSessionLifecycle::IrreversibleNoRetry ||
        !proof_options.reclaim_completed_multiplication_scratch) {
        throw std::invalid_argument(
            "prove_laned_request_resident_reference_from_checkpoint_replay_external_"
            "irreversible: explicit IrreversibleNoRetry and immediate "
            "scratch reclamation are required");
    }
    server.public_setup.validate(payload, circuit);
    const Digest setup_id = setup_digest(server.public_setup);
    const Digest circuit_id = payload::combined_digest(payload, circuit);
    const payload::EncryptedTraceDescriptor &descriptor =
        state.trace.descriptor();
    if (state.setup_id != setup_id || state.session_id == Digest{} ||
        state.circuit_id != circuit_id ||
        state.trace_id != descriptor.trace_id ||
        descriptor.circuit_id != circuit_id ||
        descriptor.provenance != payload::TraceProvenance::FheEvaluated ||
        descriptor.shape.kind != payload::PayloadKind::Laned ||
        descriptor.layers.empty() ||
        evaluated.output.dimensions !=
            descriptor.layers.front().dimensions ||
        evaluated.output.values.size() !=
            descriptor.layers.front().record_count ||
        state.trace.backend_context_id() !=
            Backend::storage_context_id(server.context) ||
        state.trace.layered_circuit_id() != payload::digest(circuit) ||
        !state.trace.report().checkpoint_set_published ||
        state.trace.report().all_payload_artifacts_retired ||
        state.trace.proof_attempt_started()) {
        throw std::invalid_argument(
            "external Laned checkpoint replay retained-state binding "
            "mismatch");
    }
    const protocol::CheckpointReplayServerStorageAdmission readmitted =
        protocol::admit_checkpoint_replay_server_storage(
            state.trace.problem(), state.trace.budgets(), state.trace.plan(),
            proof_options.proof,
            proof_options.reclaim_completed_multiplication_scratch,
            state.resources().storage_limits());
    if (readmitted != state.resources().admission()) {
        throw std::logic_error(
            "external Laned checkpoint replay retained storage admission "
            "drifted");
    }
    const Digest encrypted_statement = laned_server_detail::laned_statement_digest(
        state.request_commitment, setup_id, state.session_id, circuit_id,
        state.trace_id, evaluated.output);
    if (encrypted_statement != state.statement_digest) {
        throw std::invalid_argument(
            "external Laned checkpoint replay encrypted output changed "
            "after evaluation");
    }

    Transcript proof_transcript = transcript;
    observe_packed_delegation_bindings(
        proof_transcript, setup_id, state.session_id);
    const std::vector<Fpk> output_point = derive_packed_output_point(
        proof_transcript, PackedProtocolVariant::Laned,
        encrypted_statement, gkr::laned_layer_variables(circuit, 0));
    protocol::TranscriptPackingExternalAdmission packing_admission =
        state.resources().take_external_packing_admission();
    auto admission =
        protocol::
            admit_laned_checkpoint_replay_with_packing_admission_irreversible<
                Backend>(payload, circuit, state.trace, server,
                         packing_setup, output_point, proof_options,
                         std::move(packing_admission));
    protocol::LanedCheckpointReplayExternalResult<Backend> proved =
        protocol::prove_laned_checkpoint_replay_external_irreversible<
            Backend>(std::move(admission), proof_transcript);

    CheckpointReplayLanedExternalServerProofResult<Backend> result{
        LanedResponse<Backend>{
            setup_id, state.session_id, circuit_id, state.trace_id,
            std::move(evaluated.output), std::move(proved.proof)},
        std::move(proved.gkr_report),
        std::move(proved.payload_replay_report),
        std::move(proved.transcript_packing_report),
        proved.phase_timings,
        state.resources().admission()};
    transcript = std::move(proof_transcript);
    return result;
}


} // namespace laminate::delegation::reference

#endif // LAMINATE_DELEGATION_LANED_REFERENCE_PROVING_HPP
