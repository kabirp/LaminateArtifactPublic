#ifndef LAMINATE_DELEGATION_FOLDED_SERVER_ADMISSION_HPP
#define LAMINATE_DELEGATION_FOLDED_SERVER_ADMISSION_HPP

/// @file server/admission.hpp
/// @brief Folded request validation and whole-session resource admission.

#include "laminate/delegation/detail/file_trace_and_output_sink.hpp"
#include "laminate/delegation/detail/packed_server_lifecycle.hpp"
#include "laminate/delegation/folded/session/state.hpp"
#include "laminate/delegation/folded/server/admission/options.hpp"
#include "laminate/delegation/packed/statement.hpp"
#include "laminate/payload/wide_fhe_evaluator.hpp"
#include "laminate/protocol/folded.hpp"
#include "laminate/protocol/packed/external/prover.hpp"
#include "laminate/protocol/packed/online/server.hpp"
#include "laminate/protocol/storage/checkpoint_replay.hpp"

#include <filesystem>
#include <memory>
#include <span>
#include <stdexcept>
#include <utility>

namespace laminate::delegation {
namespace folded_server_detail {

template <fhe::FheBackend Backend>
void validate_folded_evaluation_request(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const EvaluationSetup<Backend> &server,
    const FoldedEvaluationRequest<Backend> &request) {
    packed_server_detail::validate_request<Backend>(
        payload, circuit, server, request, payload::PayloadKind::Wide,
        "evaluate_folded_request");
}

template <fhe::FheBackend Backend>
Digest folded_request_commitment(
    const FoldedEvaluationRequest<Backend> &request) {
    return packed_server_detail::request_commitment<Backend>(
        PackedProtocolVariant::Folded, request);
}

template <fhe::FheBackend Backend>
Digest folded_statement_digest(
    const Digest &request_commitment, const Digest &setup_id,
    const Digest &session_id, const Digest &circuit_id,
    const Digest &trace_id, const FoldedFheOutput<Backend> &output) {
    return packed_server_detail::statement_digest<Backend>(
        PackedProtocolVariant::Folded, request_commitment, setup_id,
        session_id, circuit_id, trace_id, output);
}

} // namespace folded_server_detail

template <packing::CoefficientWellFormednessBackend Backend>
struct FileFoldedServerProofResult {
    FoldedResponse<Backend> response;
    gkr::folded_detail::FileFoldedGkrReport gkr_report;
};

template <packing::CoefficientWellFormednessBackend Backend>
    requires fhe::PersistableFheBackend<Backend>
struct CheckpointReplayFoldedServerProofResult {
    FoldedResponse<Backend> response;
    gkr::folded_detail::FileFoldedGkrReport gkr_report;
    payload::PayloadCheckpointReplayExecutionReport payload_replay_report;
    protocol::CheckpointReplayServerStorageAdmission storage_admission;
};

/// External-packing counterpart of the checkpoint-replay result. The wire
/// response remains the ordinary single Folded response; every additional
/// field is server-local accounting for the one destructive proof call.
template <packing::CoefficientWellFormednessBackend Backend>
    requires fhe::PersistableFheBackend<Backend>
struct CheckpointReplayFoldedExternalServerProofResult {
    FoldedResponse<Backend> response;
    gkr::folded_detail::FileFoldedGkrReport gkr_report;
    payload::PayloadCheckpointReplayExecutionReport payload_replay_report;
    protocol::TranscriptPackingExternalProverReport
        transcript_packing_report;
    protocol::PackedExternalProverPhaseTimings phase_timings;
    protocol::CheckpointReplayServerStorageAdmission storage_admission;
};

/// One-request mutable-resource admission. A server may reserve it before
/// waiting for that request, but must charge its root, capacity, and packing
/// admission work to recurring throughput. It binds normalized replay/GKR
/// roots and the exact storage contract; evaluation consumes it once.
class PreparedCheckpointReplayFoldedServerResources {
  public:
    PreparedCheckpointReplayFoldedServerResources(
        PreparedCheckpointReplayFoldedServerResources &&) noexcept = default;
    PreparedCheckpointReplayFoldedServerResources &operator=(
        PreparedCheckpointReplayFoldedServerResources &&) noexcept = default;
    PreparedCheckpointReplayFoldedServerResources(
        const PreparedCheckpointReplayFoldedServerResources &) = delete;
    PreparedCheckpointReplayFoldedServerResources &operator=(
        const PreparedCheckpointReplayFoldedServerResources &) = delete;

    const protocol::CheckpointReplayServerStorageAdmission &
    storage_admission() const {
        return resources_.admission();
    }

  private:
    PreparedCheckpointReplayFoldedServerResources(
        payload::PayloadCheckpointReplayExecutionOptions replay,
        CheckpointReplayFoldedServerResources resources)
        : replay_(std::move(replay)), resources_(std::move(resources)) {}

    payload::PayloadCheckpointReplayExecutionOptions replay_;
    CheckpointReplayFoldedServerResources resources_;

    template <protocol::PackedRolePreprocessingBackend Backend>
    friend PreparedCheckpointReplayFoldedServerResources
    prepare_folded_request_resources(
        const protocol::AuthenticatedPackedServerOnlineState<Backend> &,
        payload::PayloadCheckpointReplayExecutionOptions,
        FoldedServerProofOptions,
        protocol::TranscriptPackingExternalAdmission,
        protocol::CheckpointReplayServerStorageLimits);

    template <protocol::PackedRolePreprocessingBackend Backend>
    friend CheckpointReplayFoldedServerEvaluationResult<Backend>
    evaluate_folded_request(
        const protocol::AuthenticatedPackedServerOnlineState<Backend> &,
        const FoldedEvaluationRequest<Backend> &,
        PreparedCheckpointReplayFoldedServerResources);
};

template <protocol::PackedRolePreprocessingBackend Backend>
PreparedCheckpointReplayFoldedServerResources
prepare_folded_request_resources(
    const protocol::AuthenticatedPackedServerOnlineState<Backend> &server,
    payload::PayloadCheckpointReplayExecutionOptions replay,
    FoldedServerProofOptions proof_options,
    protocol::TranscriptPackingExternalAdmission packing,
    protocol::CheckpointReplayServerStorageLimits storage_limits) {
    if (server.variant() != protocol::PackingGkrVariant::Folded ||
        replay.lifecycle !=
            payload::FileTraceSessionLifecycle::IrreversibleNoRetry ||
        proof_options.lifecycle !=
            payload::FileTraceSessionLifecycle::IrreversibleNoRetry ||
        !proof_options.reclaim_completed_multiplication_scratch ||
        !packing.matches(protocol::PackingGkrVariant::Folded,
                         server.prover_setup().transcript_packing())) {
        throw std::invalid_argument(
            "Folded request resources do not match the authenticated "
            "server");
    }
    replay.directory =
        payload::preflight_and_normalize_payload_checkpoint_replay_root(
            replay.directory);
    proof_options.proof =
        gkr::folded_detail::preflight_and_normalize_file_folded_gkr_scratch(
            server.checkpoint_replay().circuit(), replay.directory,
            proof_options.proof);
    protocol::preflight_folded_packed_external_resource_roots(
        replay.directory, proof_options, packing);
    const auto admission = protocol::admit_checkpoint_replay_server_storage(
        server.checkpoint_replay().problem(),
        server.checkpoint_replay().budgets(),
        server.checkpoint_replay().plan(), proof_options.proof,
        proof_options.reclaim_completed_multiplication_scratch,
        storage_limits);
    return PreparedCheckpointReplayFoldedServerResources(
        std::move(replay),
        CheckpointReplayFoldedServerResources{
            server.prover_setup(), server.prover_setup().identity(),
            std::move(packing), std::move(proof_options),
            std::move(storage_limits), admission});
}

} // namespace laminate::delegation

#endif // LAMINATE_DELEGATION_FOLDED_SERVER_ADMISSION_HPP
