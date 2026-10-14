#ifndef LAMINATE_PROTOCOL_PACKED_EXTERNAL_DETAIL_PROVER_IMPL_HPP
#define LAMINATE_PROTOCOL_PACKED_EXTERNAL_DETAIL_PROVER_IMPL_HPP

/// @file prover_impl.hpp
/// @brief Protocol-ordered checkpoint-replay and transcript-packing proof.

#include "laminate/protocol/packed/external/detail/admission/api.hpp"
#include "laminate/protocol/detail/profiling/clock.hpp"
#include "laminate/protocol/fiat_shamir.hpp"
#include "laminate/protocol/packed/external/detail/proving/gkr.hpp"
#include "laminate/protocol/packed/external/detail/proving/reporting.hpp"
#include "laminate/protocol/packed/external/detail/proving/transcript_packing.hpp"

#include <utility>

namespace laminate::protocol {

/// LaminateFolded online proving, in protocol order:
/// encrypted GKR -> committed aligned messages -> assignment -> Spartan.
template <typename Backend>
    requires packing::SignedDigitPackingBackend<Backend> &&
             fhe::PersistableFheBackend<Backend>
FoldedCheckpointReplayExternalResult<Backend>
prove_folded_checkpoint_replay_external_irreversible(
    FoldedCheckpointReplayExternalAdmission<Backend> admission,
    Transcript &transcript,
    gkr::ProofTransportPolicy transport) {
    auto admitted = detail::PackedExternalAdmissionAccess::take(
        std::move(admission));
    packed_external_detail::require_live_consumed_admission(
        admitted, "Folded");
    const auto packing_preflight = admitted.packing.report();
    // Advance the caller's transcript only after the complete proof succeeds.
    Transcript protocol_transcript = transcript;
    observe_packed_fiat_shamir_schedule(protocol_transcript);

    const profiling_detail::Stopwatch gkr_timer;
    auto gkr_phase = packed_external_detail::run_folded_gkr_phase(
        admitted, protocol_transcript, transport);
    const profiling_detail::Elapsed gkr_elapsed = gkr_timer.stop();
    const profiling_detail::Stopwatch packing_timer;
    auto packing_phase =
        packed_external_detail::run_assignment_and_spartan_suffix<Backend>(
            admitted.evaluation->context,
            admitted.setup->transcript_packing(),
            std::move(admitted.packing),
            std::move(gkr_phase.packing_sources), gkr_phase.proof,
            protocol_transcript, admitted.gkr_options.proof.progress,
            packing_preflight, "Folded");
    const profiling_detail::Elapsed packing_elapsed =
        packing_timer.stop();
    auto result = packed_external_detail::make_folded_result<Backend>(
        std::move(gkr_phase), std::move(packing_phase),
        admitted.trace->report(),
        {.gkr_wall_ms = gkr_elapsed.wall_ms,
         .gkr_cpu_ms = gkr_elapsed.cpu_ms,
         .transcript_packing_wall_ms = packing_elapsed.wall_ms,
         .transcript_packing_cpu_ms = packing_elapsed.cpu_ms});
    transcript = std::move(protocol_transcript);
    return result;
}

/// LaminateLaned reaches the same transcript-packing suffix through the Laned
/// GKR arithmetic path. Keeping the two phases explicit makes that shared
/// boundary visible without hiding either variant's GKR constructor.
template <typename Backend>
    requires packing::SignedDigitPackingBackend<Backend> &&
             fhe::PersistableFheBackend<Backend>
LanedCheckpointReplayExternalResult<Backend>
prove_laned_checkpoint_replay_external_irreversible(
    LanedCheckpointReplayExternalAdmission<Backend> admission,
    Transcript &transcript,
    gkr::ProofTransportPolicy transport) {
    auto admitted = detail::PackedExternalAdmissionAccess::take(
        std::move(admission));
    packed_external_detail::require_live_consumed_admission(
        admitted, "Laned");
    const auto packing_preflight = admitted.packing.report();
    // Advance the caller's transcript only after the complete proof succeeds.
    Transcript protocol_transcript = transcript;
    observe_packed_fiat_shamir_schedule(protocol_transcript);

    const profiling_detail::Stopwatch gkr_timer;
    auto gkr_phase = packed_external_detail::run_laned_gkr_phase(
        admitted, protocol_transcript, transport);
    const profiling_detail::Elapsed gkr_elapsed = gkr_timer.stop();
    const profiling_detail::Stopwatch packing_timer;
    auto packing_phase =
        packed_external_detail::run_assignment_and_spartan_suffix<Backend>(
            admitted.evaluation->context,
            admitted.setup->transcript_packing(),
            std::move(admitted.packing),
            std::move(gkr_phase.packing_sources), gkr_phase.proof,
            protocol_transcript, admitted.gkr_options.proof.progress,
            packing_preflight, "Laned");
    const profiling_detail::Elapsed packing_elapsed =
        packing_timer.stop();
    auto result = packed_external_detail::make_laned_result<Backend>(
        std::move(gkr_phase), std::move(packing_phase),
        admitted.trace->report(),
        {.gkr_wall_ms = gkr_elapsed.wall_ms,
         .gkr_cpu_ms = gkr_elapsed.cpu_ms,
         .transcript_packing_wall_ms = packing_elapsed.wall_ms,
         .transcript_packing_cpu_ms = packing_elapsed.cpu_ms});
    transcript = std::move(protocol_transcript);
    return result;
}

} // namespace laminate::protocol

#endif // LAMINATE_PROTOCOL_PACKED_EXTERNAL_DETAIL_PROVER_IMPL_HPP
