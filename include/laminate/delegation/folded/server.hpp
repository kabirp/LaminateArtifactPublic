#ifndef LAMINATE_DELEGATION_FOLDED_SERVER_HPP
#define LAMINATE_DELEGATION_FOLDED_SERVER_HPP

/// @file server.hpp
/// @brief Declaration-first authenticated Folded server lifecycle.
///
/// The production path has three visible transitions: admit all resources,
/// evaluate the encrypted payload into sparse replay state, then prove and
/// publish the sole response. Resident/file experiments live in `reference/`.

#include "laminate/delegation/folded/session/state.hpp"
#include "laminate/delegation/folded/server/admission/options.hpp"
#include "laminate/protocol/packed/online/server.hpp"

namespace laminate::delegation {

template <packing::CoefficientWellFormednessBackend Backend>
    requires fhe::PersistableFheBackend<Backend>
struct CheckpointReplayFoldedExternalServerProofResult;

class PreparedCheckpointReplayFoldedServerResources;

// ---- Admission: reserve replay, GKR, packing, and storage before evaluation.

template <protocol::PackedRolePreprocessingBackend Backend>
PreparedCheckpointReplayFoldedServerResources
prepare_folded_request_resources(
    const protocol::AuthenticatedPackedServerOnlineState<Backend> &server,
    payload::PayloadCheckpointReplayExecutionOptions replay,
    FoldedServerProofOptions proof,
    protocol::TranscriptPackingExternalAdmission packing,
    protocol::CheckpointReplayServerStorageLimits storage_limits);

// ---- Evaluation: consume the admitted request into sparse replay state.

template <protocol::PackedRolePreprocessingBackend Backend>
CheckpointReplayFoldedServerEvaluationResult<Backend>
evaluate_folded_request(
    const protocol::AuthenticatedPackedServerOnlineState<Backend> &server,
    const FoldedEvaluationRequest<Backend> &request,
    PreparedCheckpointReplayFoldedServerResources prepared);

// ---- Proving: consume replay state and publish the sole server response.

template <protocol::PackedRolePreprocessingBackend Backend>
CheckpointReplayFoldedExternalServerProofResult<Backend>
prove_folded_response_irreversible(
    const protocol::AuthenticatedPackedServerOnlineState<Backend> &server,
    CheckpointReplayFoldedServerEvaluationResult<Backend> &evaluated,
    Transcript &transcript);

} // namespace laminate::delegation

#include "laminate/delegation/folded/server/api_impl.hpp"

#endif // LAMINATE_DELEGATION_FOLDED_SERVER_HPP
