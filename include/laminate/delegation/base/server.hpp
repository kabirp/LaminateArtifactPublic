#ifndef LAMINATE_DELEGATION_BASE_SERVER_HPP
#define LAMINATE_DELEGATION_BASE_SERVER_HPP

/// @file server.hpp
/// @brief Declaration-first Base server lifecycle.
///
/// The scale path has two explicit transitions: evaluate the Wide payload into
/// admitted compact checkpoints, then consume those checkpoints to prove and
/// publish the one encrypted-output-and-proof response.

#include "laminate/delegation/base/session/state.hpp"
#include "laminate/payload/noise/honest_noise_schedule.hpp"
#include "laminate/transcript/transcript.hpp"

#include <utility>

namespace laminate::delegation {

/// Result of the destructive proof transition, including exact artifact and
/// capacity reports used by benchmark telemetry.
template <fhe::PersistableFheBackend Backend>
struct CheckpointReplayBaseServerProofResult {
    BaseResponse<Backend> response;
    gkr::base_detail::FileBaseGkrReport gkr_report;
    payload::PayloadCheckpointReplayExecutionReport payload_replay_report;
    protocol::BaseServerCapacityAdmission capacity_admission;
};

// ---- Evaluate: authenticate schedule/request, admit resources, write compact
//      checkpoints, and retain the encrypted output for the response.

template <fhe::PersistableFheBackend Backend>
CheckpointReplayBaseServerEvaluationResult<Backend>
evaluate_base_request(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const EvaluationSetup<Backend> &server,
    const BaseRequest<Backend> &request,
    const payload::CertifiedHonestPayloadSchedule &certified_schedule,
    const payload::PayloadCheckpointReplayProblem &problem,
    const payload::PayloadCheckpointReplayBudgets &budgets,
    const payload::PayloadCheckpointReplayPlan &replay_plan,
    payload::PayloadCheckpointReplayExecutionOptions replay_options,
    protocol::BaseProverOptions proof_options,
    protocol::BaseServerCapacityCaps capacity_caps,
    protocol::BaseServerCapacityComponents capacity_components);

// ---- Prove/respond: revalidate retained state, derive the output point,
//      stream GKR while retiring artifacts, and move output plus proof into the
//      sole response. Any failure after retirement begins is terminal.

template <fhe::PersistableFheBackend Backend>
CheckpointReplayBaseServerProofResult<Backend>
prove_base_response_irreversible(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const EvaluationSetup<Backend> &server,
    CheckpointReplayBaseServerEvaluationResult<Backend> &evaluated,
    Transcript &transcript);

} // namespace laminate::delegation

#include "laminate/delegation/base/server/api_impl.hpp"

#endif // LAMINATE_DELEGATION_BASE_SERVER_HPP
