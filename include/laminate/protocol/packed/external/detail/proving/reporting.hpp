#ifndef LAMINATE_PROTOCOL_PACKED_EXTERNAL_DETAIL_PROVING_REPORTING_HPP
#define LAMINATE_PROTOCOL_PACKED_EXTERNAL_DETAIL_PROVING_REPORTING_HPP

/// @file reporting.hpp
/// @brief Assemble protocol proofs and completed artifact reports.

#include "laminate/protocol/packed/external/detail/proving/gkr.hpp"

#include <utility>

namespace laminate::protocol::packed_external_detail {

template <typename Backend>
FoldedCheckpointReplayExternalResult<Backend> make_folded_result(
    FoldedGkrPhaseResult<Backend> &&gkr_phase,
    TranscriptPackingExternalProverResult<Backend> &&packing_phase,
    payload::PayloadCheckpointReplayExecutionReport replay_report,
    PackedExternalProverPhaseTimings phase_timings) {
    LaminateFoldedProof<Backend> proof{
        .gkr = std::move(gkr_phase.proof),
        .transcript_packing = std::move(packing_phase.proof),
    };
    return {
        .proof = std::move(proof),
        .gkr_report = std::move(gkr_phase.report),
        .payload_replay_report = std::move(replay_report),
        .transcript_packing_report = std::move(packing_phase.report),
        .phase_timings = phase_timings,
    };
}

template <typename Backend>
LanedCheckpointReplayExternalResult<Backend> make_laned_result(
    LanedGkrPhaseResult<Backend> &&gkr_phase,
    TranscriptPackingExternalProverResult<Backend> &&packing_phase,
    payload::PayloadCheckpointReplayExecutionReport replay_report,
    PackedExternalProverPhaseTimings phase_timings) {
    LaminateLanedProof<Backend> proof{
        .gkr = std::move(gkr_phase.proof),
        .transcript_packing = std::move(packing_phase.proof),
    };
    return {
        .proof = std::move(proof),
        .gkr_report = std::move(gkr_phase.report),
        .payload_replay_report = std::move(replay_report),
        .transcript_packing_report = std::move(packing_phase.report),
        .phase_timings = phase_timings,
    };
}

} // namespace laminate::protocol::packed_external_detail

#endif // LAMINATE_PROTOCOL_PACKED_EXTERNAL_DETAIL_PROVING_REPORTING_HPP
