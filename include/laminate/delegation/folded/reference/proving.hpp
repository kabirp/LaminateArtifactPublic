#ifndef LAMINATE_DELEGATION_FOLDED_REFERENCE_PROVING_HPP
#define LAMINATE_DELEGATION_FOLDED_REFERENCE_PROVING_HPP

/// @file reference/proving.hpp
/// @brief Folded resident, file, and uncached replay proving paths.

#include "laminate/delegation/folded/reference/evaluation.hpp"
#include "laminate/gkr/detail/base/geometry/circuit.hpp"
#include "laminate/protocol/reference/folded.hpp"

namespace laminate::delegation::reference {

/// Produce the sole response from the exact trace and output fixed by
/// evaluation.
template <packing::SignedDigitPackingBackend Backend>
FoldedResponse<Backend> prove_folded_request_resident_reference(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const EvaluationSetup<Backend> &server,
    const protocol::FoldedSetup &packing_setup,
    FoldedServerEvaluationResult<Backend> evaluated,
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
        state.trace->layers.empty() ||
        state.trace->layers.front().layout !=
            payload::TraceLayerLayout::Wide ||
        evaluated.output.dimensions !=
            state.trace->layers.front().dimensions ||
        evaluated.output.values.size() !=
            state.trace->layers.front().wires.size()) {
        throw std::invalid_argument(
            "prove_folded_request_resident_reference: retained-state binding mismatch");
    }
    const Digest encrypted_statement =
        folded_server_detail::folded_statement_digest(
            state.request_commitment, setup_id, state.session_id, circuit_id,
            state.trace_id, evaluated.output);
    if (encrypted_statement != state.statement_digest) {
        throw std::invalid_argument(
            "prove_folded_request_resident_reference: encrypted output changed after "
            "evaluation");
    }
    observe_packed_delegation_bindings(
        transcript, setup_id, state.session_id);
    const std::vector<Fpk> output_point = derive_packed_output_point(
        transcript, PackedProtocolVariant::Folded, encrypted_statement,
        gkr::base_detail::layer_vars(circuit, 0));
    protocol::LaminateFoldedProof<Backend> proof =
        protocol::reference::prove_folded<Backend>(
            payload, circuit, *state.trace, server, packing_setup,
            output_point, transcript);
    return FoldedResponse<Backend>{
        setup_id, state.session_id, circuit_id, state.trace_id,
        std::move(evaluated.output), std::move(proof)};
}

template <packing::SignedDigitPackingBackend Backend>
FileFoldedServerProofResult<Backend>
prove_folded_request_file_irreversible_reference(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const EvaluationSetup<Backend> &server,
    const protocol::FoldedSetup &packing_setup,
    FileFoldedServerEvaluationResult<Backend> evaluated,
    Transcript &transcript,
    protocol::reference::IrreversibleFoldedFileProofOptions options,
    payload::FileTraceStoreOpenLimits open_limits) {
    if (options.lifecycle !=
        payload::FileTraceSessionLifecycle::IrreversibleNoRetry) {
        throw std::invalid_argument(
            "prove_folded_request_file_irreversible_reference: explicit "
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
        state.trace_store.descriptor.shape.kind !=
            payload::PayloadKind::Wide ||
        state.trace_store.descriptor.layers.empty() ||
        evaluated.output.dimensions !=
            state.trace_store.descriptor.layers.front().dimensions ||
        evaluated.output.values.size() !=
            state.trace_store.descriptor.layers.front().record_count) {
        throw std::invalid_argument(
            "prove_folded_request_file_irreversible_reference: retained-state "
            "binding mismatch");
    }
    const Digest encrypted_statement =
        folded_server_detail::folded_statement_digest(
            state.request_commitment, setup_id, state.session_id, circuit_id,
            state.trace_id, evaluated.output);
    if (encrypted_statement != state.statement_digest) {
        throw std::invalid_argument(
            "prove_folded_request_file_irreversible_reference: encrypted output "
            "changed after evaluation");
    }
    Transcript proof_transcript = transcript;
    observe_packed_delegation_bindings(
        proof_transcript, setup_id, state.session_id);
    const std::vector<Fpk> output_point = derive_packed_output_point(
        proof_transcript, PackedProtocolVariant::Folded,
        encrypted_statement, gkr::base_detail::layer_vars(circuit, 0));
    auto stored_trace = open_folded_server_trace_reference<Backend>(
        payload, circuit, server, state, open_limits);
    protocol::reference::preflight_folded_file_irreversible_reference<Backend>(
        payload, circuit, stored_trace, server, packing_setup,
        output_point, options);
    auto trace =
        payload::FileEncryptedTraceReclamationSession<Backend>::begin(
            std::move(stored_trace),
            payload::FileTraceReclamationOptions{options.lifecycle});
    protocol::reference::FoldedFileProofResult<Backend> proved =
        protocol::reference::prove_folded_file_irreversible_reference<Backend>(
            payload, circuit, trace, server, packing_setup,
            output_point, proof_transcript, std::move(options));
    FileFoldedServerProofResult<Backend> result{
        FoldedResponse<Backend>{
            setup_id, state.session_id, circuit_id, state.trace_id,
            std::move(evaluated.output), std::move(proved.proof)},
        std::move(proved.gkr_report)};
    transcript = std::move(proof_transcript);
    return result;
}

template <typename Backend>
    requires packing::SignedDigitPackingBackend<Backend> &&
             fhe::PersistableFheBackend<Backend>
CheckpointReplayFoldedServerProofResult<Backend>
prove_folded_request_checkpoint_replay_irreversible_reference(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const EvaluationSetup<Backend> &server,
    CheckpointReplayFoldedServerEvaluationResult<Backend> &evaluated,
    Transcript &transcript) {
    auto &state = evaluated.state;
    if (state.resources().uses_external_packing()) {
        throw std::invalid_argument(
            "resident Folded proof cannot consume external packing "
            "resources");
    }
    const protocol::reference::IrreversibleFoldedFileProofOptions &proof_options =
        state.resources().proof_options();
    const protocol::FoldedSetup &packing_setup =
        state.resources().packing_setup();
    if (proof_options.lifecycle !=
        payload::FileTraceSessionLifecycle::IrreversibleNoRetry) {
        throw std::invalid_argument(
            "prove_folded_request_checkpoint_replay_irreversible_reference: "
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
        descriptor.shape.kind != payload::PayloadKind::Wide ||
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
            "Folded checkpoint replay proof retained-state binding "
            "mismatch");
    }
    protocol::preflight_folded_packing_setup<Backend>(
        circuit, server, packing_setup);
    const protocol::CheckpointReplayServerStorageAdmission readmitted =
        protocol::admit_checkpoint_replay_server_storage(
            state.trace.problem(), state.trace.budgets(), state.trace.plan(),
            proof_options.proof,
            proof_options.reclaim_completed_multiplication_scratch,
            state.resources().storage_limits());
    if (readmitted != state.resources().admission()) {
        throw std::logic_error(
            "Folded checkpoint replay retained storage admission drifted");
    }
    const Digest encrypted_statement =
        folded_server_detail::folded_statement_digest(
            state.request_commitment, setup_id, state.session_id, circuit_id,
            state.trace_id, evaluated.output);
    if (encrypted_statement != state.statement_digest) {
        throw std::invalid_argument(
            "Folded checkpoint replay encrypted output changed after "
            "evaluation");
    }
    Transcript proof_transcript = transcript;
    observe_packed_delegation_bindings(
        proof_transcript, setup_id, state.session_id);
    const std::vector<Fpk> output_point = derive_packed_output_point(
        proof_transcript, PackedProtocolVariant::Folded,
        encrypted_statement, gkr::base_detail::layer_vars(circuit, 0));
    protocol::reference::preflight_folded_checkpoint_replay_irreversible_reference<Backend>(
        payload, circuit, state.trace, server, packing_setup,
        output_point, proof_options);
    protocol::reference::FoldedCheckpointReplayProofResult<Backend> proved =
        protocol::reference::prove_folded_checkpoint_replay_irreversible_reference<Backend>(
            payload, circuit, state.trace, server, packing_setup,
            output_point, proof_transcript, proof_options);
    CheckpointReplayFoldedServerProofResult<Backend> result{
        FoldedResponse<Backend>{
            setup_id, state.session_id, circuit_id, state.trace_id,
            std::move(evaluated.output), std::move(proved.proof)},
        std::move(proved.gkr_report),
        std::move(proved.payload_replay_report),
        state.resources().admission()};
    transcript = std::move(proof_transcript);
    return result;
}

/// One-round Folded server transition with artifact-backed transcript
/// packing. All delegation, checkpoint, setup, scratch, and encrypted-output
/// bindings are rechecked before the checkpoint trace crosses its no-retry
/// boundary. The external packing preflight is part of that no-write check;
/// once replay starts, any GKR or packing failure is terminal for `evaluated`
/// and no response is produced. There is no message between the request and
/// the ordinary `FoldedResponse` returned on success.
template <typename Backend>
    requires packing::SignedDigitPackingBackend<Backend> &&
             fhe::PersistableFheBackend<Backend>
CheckpointReplayFoldedExternalServerProofResult<Backend>
prove_folded_request_external_checkpoint_replay_irreversible_reference(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const EvaluationSetup<Backend> &server,
    const protocol::PackedExternalProverSetup &packing_setup,
    CheckpointReplayFoldedServerEvaluationResult<Backend> &evaluated,
    Transcript &transcript) {
    auto &state = evaluated.state;
    if (!state.resources().uses_external_packing() ||
        !state.resources().matches_external_packing_setup(packing_setup) ||
        state.resources().external_packing_setup_identity() !=
            packing_setup.identity()) {
        throw std::invalid_argument(
            "external Folded proof setup does not match its retained "
            "pre-payload admission");
    }
    const protocol::reference::IrreversibleFoldedFileProofOptions &proof_options =
        state.resources().proof_options();
    if (proof_options.lifecycle !=
            payload::FileTraceSessionLifecycle::IrreversibleNoRetry ||
        !proof_options.reclaim_completed_multiplication_scratch) {
        throw std::invalid_argument(
            "prove_folded_request_resident_reference_from_checkpoint_replay_external_"
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
        descriptor.shape.kind != payload::PayloadKind::Wide ||
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
            "external Folded checkpoint replay retained-state binding "
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
            "external Folded checkpoint replay retained storage "
            "admission drifted");
    }
    const Digest encrypted_statement =
        folded_server_detail::folded_statement_digest(
            state.request_commitment, setup_id, state.session_id, circuit_id,
            state.trace_id, evaluated.output);
    if (encrypted_statement != state.statement_digest) {
        throw std::invalid_argument(
            "external Folded checkpoint replay encrypted output changed "
            "after evaluation");
    }

    Transcript proof_transcript = transcript;
    observe_packed_delegation_bindings(
        proof_transcript, setup_id, state.session_id);
    const std::vector<Fpk> output_point = derive_packed_output_point(
        proof_transcript, PackedProtocolVariant::Folded,
        encrypted_statement, gkr::base_detail::layer_vars(circuit, 0));
    protocol::TranscriptPackingExternalAdmission packing_admission =
        state.resources().take_external_packing_admission();
    auto admission =
        protocol::
            admit_folded_checkpoint_replay_with_packing_admission_irreversible<
                Backend>(payload, circuit, state.trace, server,
                         packing_setup, output_point, proof_options,
                         std::move(packing_admission));
    protocol::FoldedCheckpointReplayExternalResult<Backend> proved =
        protocol::prove_folded_checkpoint_replay_external_irreversible<
            Backend>(std::move(admission), proof_transcript);

    CheckpointReplayFoldedExternalServerProofResult<Backend> result{
        FoldedResponse<Backend>{
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

#endif // LAMINATE_DELEGATION_FOLDED_REFERENCE_PROVING_HPP
