#ifndef LAMINATE_DELEGATION_LANED_SERVER_ADMISSION_HPP
#define LAMINATE_DELEGATION_LANED_SERVER_ADMISSION_HPP

/// @file server/admission.hpp
/// @brief Laned request validation and whole-session resource admission.

#include "laminate/delegation/detail/file_trace_and_output_sink.hpp"
#include "laminate/delegation/detail/packed_server_lifecycle.hpp"
#include "laminate/delegation/packed/statement.hpp"
#include "laminate/delegation/laned/session/state.hpp"
#include "laminate/delegation/laned/server/admission/options.hpp"
#include "laminate/payload/checkpoint/laned_witness_packing.hpp"
#include "laminate/payload/laned_fhe_evaluator.hpp"
#include "laminate/protocol/laned.hpp"
#include "laminate/protocol/packed/external/prover.hpp"
#include "laminate/protocol/packed/online/server.hpp"
#include "laminate/protocol/storage/checkpoint_replay.hpp"

#include <algorithm>
#include <filesystem>
#include <memory>
#include <span>
#include <stdexcept>
#include <utility>

namespace laminate::delegation {

namespace laned_server_detail {

inline void include_eager_laned_execution_peak(
    const payload::LayeredCircuit &circuit,
    const payload::PayloadCheckpointReplayProblem &problem,
    const payload::PayloadCheckpointReplayBudgets &budgets,
    const payload::PayloadCheckpointReplayPlan &plan, bool eager,
    protocol::CheckpointReplayServerStorageLimits &limits) {
    if (!eager) {
        return;
    }
    const auto admission = payload::admit_eager_laned_witness_packing(
        circuit, problem, budgets, plan);
    if (admission.resources.eligible) {
        limits.payload_execution_peak.local_disk_bytes = std::max(
            limits.payload_execution_peak.local_disk_bytes,
            admission.peak_live_scratch_bytes);
        limits.payload_execution_peak.resident_ram_bytes = std::max(
            limits.payload_execution_peak.resident_ram_bytes,
            admission.peak_resident_bytes);
    }
}

template <fhe::FheBackend Backend>
void validate_laned_evaluation_request(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const EvaluationSetup<Backend> &server,
    const LanedEvaluationRequest<Backend> &request) {
    packed_server_detail::validate_request<Backend>(
        payload, circuit, server, request, payload::PayloadKind::Laned,
        "evaluate_laned_request");
}

template <fhe::FheBackend Backend>
Digest laned_request_commitment(
    const LanedEvaluationRequest<Backend> &request) {
    return packed_server_detail::request_commitment<Backend>(
        PackedProtocolVariant::Laned, request);
}

template <fhe::FheBackend Backend>
Digest laned_statement_digest(
    const Digest &request_commitment, const Digest &setup_id,
    const Digest &session_id, const Digest &circuit_id,
    const Digest &trace_id, const LanedFheOutput<Backend> &output) {
    return packed_server_detail::statement_digest<Backend>(
        PackedProtocolVariant::Laned, request_commitment, setup_id,
        session_id, circuit_id, trace_id, output);
}

} // namespace laned_server_detail

/// Response and local report from the destructive file-backed GKR path.
/// Only `response` is sent to the client. `gkr_report` accounts for inner-GKR
/// trace and scratch reclamation; resident transcript packing is outside it.
template <packing::CoefficientWellFormednessBackend Backend>
struct FileLanedServerProofResult {
    LanedResponse<Backend> response;
    gkr::laned_detail::FileLanedGkrReport gkr_report;
};

/// Final response from the in-process sparse-checkpoint path. Only `response`
/// is sent to the client; all reports are server-local diagnostics. Storage
/// admission records the caller-declared evaluation-time bounds
/// retained by the typed server state and rechecked before destructive
/// proving; it is not a measurement of process RSS.
template <packing::CoefficientWellFormednessBackend Backend>
    requires fhe::PersistableFheBackend<Backend>
struct CheckpointReplayLanedServerProofResult {
    LanedResponse<Backend> response;
    gkr::laned_detail::FileLanedGkrReport gkr_report;
    payload::PayloadCheckpointReplayExecutionReport payload_replay_report;
    protocol::CheckpointReplayServerStorageAdmission storage_admission;
};

/// Artifact-backed transcript-packing counterpart. Only `response` is sent
/// to the client; the remaining fields are server-local measurements from the
/// same one-shot proof transition.
template <packing::CoefficientWellFormednessBackend Backend>
    requires fhe::PersistableFheBackend<Backend>
struct CheckpointReplayLanedExternalServerProofResult {
    LanedResponse<Backend> response;
    gkr::laned_detail::FileLanedGkrReport gkr_report;
    payload::PayloadCheckpointReplayExecutionReport payload_replay_report;
    protocol::TranscriptPackingExternalProverReport
        transcript_packing_report;
    protocol::PackedExternalProverPhaseTimings phase_timings;
    protocol::CheckpointReplayServerStorageAdmission storage_admission;
};

/// One-request mutable-resource admission. A server may reserve it before
/// waiting for that request, but must charge its root, capacity, and packing
/// admission work to recurring throughput.
class PreparedCheckpointReplayLanedServerResources {
  public:
    PreparedCheckpointReplayLanedServerResources(
        PreparedCheckpointReplayLanedServerResources &&) noexcept = default;
    PreparedCheckpointReplayLanedServerResources &operator=(
        PreparedCheckpointReplayLanedServerResources &&) noexcept = default;
    PreparedCheckpointReplayLanedServerResources(
        const PreparedCheckpointReplayLanedServerResources &) = delete;
    PreparedCheckpointReplayLanedServerResources &operator=(
        const PreparedCheckpointReplayLanedServerResources &) = delete;

    const protocol::CheckpointReplayServerStorageAdmission &
    storage_admission() const {
        return resources_.admission();
    }

  private:
    PreparedCheckpointReplayLanedServerResources(
        payload::PayloadCheckpointReplayExecutionOptions replay,
        CheckpointReplayLanedServerResources resources)
        : replay_(std::move(replay)), resources_(std::move(resources)) {}

    payload::PayloadCheckpointReplayExecutionOptions replay_;
    CheckpointReplayLanedServerResources resources_;

    template <protocol::PackedRolePreprocessingBackend Backend>
    friend PreparedCheckpointReplayLanedServerResources
    prepare_laned_request_resources(
        const protocol::AuthenticatedPackedServerOnlineState<Backend> &,
        payload::PayloadCheckpointReplayExecutionOptions,
        LanedServerProofOptions,
        protocol::TranscriptPackingExternalAdmission,
        protocol::CheckpointReplayServerStorageLimits);

    template <protocol::PackedRolePreprocessingBackend Backend>
    friend CheckpointReplayLanedServerEvaluationResult<Backend>
    evaluate_laned_request(
        const protocol::AuthenticatedPackedServerOnlineState<Backend> &,
        const LanedEvaluationRequest<Backend> &,
        PreparedCheckpointReplayLanedServerResources);
};

template <protocol::PackedRolePreprocessingBackend Backend>
PreparedCheckpointReplayLanedServerResources
prepare_laned_request_resources(
    const protocol::AuthenticatedPackedServerOnlineState<Backend> &server,
    payload::PayloadCheckpointReplayExecutionOptions replay,
    LanedServerProofOptions proof_options,
    protocol::TranscriptPackingExternalAdmission packing,
    protocol::CheckpointReplayServerStorageLimits storage_limits) {
    if (server.variant() != protocol::PackingGkrVariant::Laned ||
        replay.lifecycle !=
            payload::FileTraceSessionLifecycle::IrreversibleNoRetry ||
        proof_options.lifecycle !=
            payload::FileTraceSessionLifecycle::IrreversibleNoRetry ||
        !proof_options.reclaim_completed_multiplication_scratch ||
        !packing.matches(protocol::PackingGkrVariant::Laned,
                         server.prover_setup().transcript_packing())) {
        throw std::invalid_argument(
            "Laned request resources do not match the authenticated "
            "server");
    }
    // Setup and trace publication use the same value-free eager check. Keep
    // its envelope in the retained limits so later readmission is identical.
    laned_server_detail::include_eager_laned_execution_peak(
        server.checkpoint_replay().circuit(),
        server.checkpoint_replay().problem(),
        server.checkpoint_replay().budgets(),
        server.checkpoint_replay().plan(),
        replay.eager_laned_witness_packing, storage_limits);
    replay.directory =
        payload::preflight_and_normalize_payload_checkpoint_replay_root(
            replay.directory);
    proof_options.proof =
        gkr::laned_detail::
            preflight_and_normalize_laned_gkr_scratch(
                server.checkpoint_replay().circuit(), replay.directory,
                proof_options.proof);
    protocol::preflight_laned_packed_external_resource_roots(
        replay.directory, proof_options, packing);
    const auto admission = protocol::admit_checkpoint_replay_server_storage(
        server.checkpoint_replay().problem(),
        server.checkpoint_replay().budgets(),
        server.checkpoint_replay().plan(), proof_options.proof,
        proof_options.reclaim_completed_multiplication_scratch,
        storage_limits);
    return PreparedCheckpointReplayLanedServerResources(
        std::move(replay),
        CheckpointReplayLanedServerResources{
            server.prover_setup(), server.prover_setup().identity(),
            std::move(packing), std::move(proof_options),
            std::move(storage_limits), admission});
}

} // namespace laminate::delegation

#endif // LAMINATE_DELEGATION_LANED_SERVER_ADMISSION_HPP
