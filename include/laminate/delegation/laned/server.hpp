#ifndef LAMINATE_DELEGATION_LANED_SERVER_HPP
#define LAMINATE_DELEGATION_LANED_SERVER_HPP

/// @file server.hpp
/// @brief Declaration-first authenticated Laned server lifecycle.
///
/// The production path has three visible transitions: admit all resources,
/// evaluate the encrypted payload into sparse replay state, then prove and
/// publish the sole response. Resident/file experiments live in `reference/`.

#include "laminate/delegation/laned/session/state.hpp"
#include "laminate/delegation/laned/server/admission/options.hpp"
#include "laminate/protocol/packed/online/server.hpp"

namespace laminate::delegation {

template <packing::CoefficientWellFormednessBackend Backend>
    requires fhe::PersistableFheBackend<Backend>
struct CheckpointReplayLanedExternalServerProofResult;

class PreparedCheckpointReplayLanedServerResources;

// ---- Admission: reserve replay, GKR, packing, and storage before evaluation.

template <protocol::PackedRolePreprocessingBackend Backend>
PreparedCheckpointReplayLanedServerResources
prepare_laned_request_resources(
    const protocol::AuthenticatedPackedServerOnlineState<Backend> &server,
    payload::PayloadCheckpointReplayExecutionOptions replay,
    LanedServerProofOptions proof,
    protocol::TranscriptPackingExternalAdmission packing,
    protocol::CheckpointReplayServerStorageLimits storage_limits);

// ---- Evaluation: consume the admitted request into sparse replay state.

template <protocol::PackedRolePreprocessingBackend Backend>
CheckpointReplayLanedServerEvaluationResult<Backend>
evaluate_laned_request(
    const protocol::AuthenticatedPackedServerOnlineState<Backend> &server,
    const LanedEvaluationRequest<Backend> &request,
    PreparedCheckpointReplayLanedServerResources prepared);

// ---- Proving: consume replay state and publish the sole server response.

template <protocol::PackedRolePreprocessingBackend Backend>
CheckpointReplayLanedExternalServerProofResult<Backend>
prove_laned_response_irreversible(
    const protocol::AuthenticatedPackedServerOnlineState<Backend> &server,
    CheckpointReplayLanedServerEvaluationResult<Backend> &evaluated,
    Transcript &transcript);

} // namespace laminate::delegation

#include "laminate/delegation/laned/server/api_impl.hpp"

#endif // LAMINATE_DELEGATION_LANED_SERVER_HPP
