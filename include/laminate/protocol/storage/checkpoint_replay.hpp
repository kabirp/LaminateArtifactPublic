#ifndef LAMINATE_PROTOCOL_STORAGE_CHECKPOINT_REPLAY_HPP
#define LAMINATE_PROTOCOL_STORAGE_CHECKPOINT_REPLAY_HPP

/// @file checkpoint_replay.hpp
/// @brief Paired disk/RAM admission for checkpoint-replay proving.

#include "laminate/payload/checkpoint/plan.hpp"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace laminate::gkr::laned_detail {
struct FileLanedGkrOptions;
}

namespace laminate::gkr::folded_detail {
struct FileFoldedGkrOptions;
}

namespace laminate::protocol {

/// Bytes that coexist in one protocol phase. Disk and RAM are independent
/// resources; their sum is retained so a caller may also enforce a bound on
/// the instantaneous physical footprint of one phase.
struct ServerResourcePair {
    std::uint64_t local_disk_bytes = 0;
    std::uint64_t resident_ram_bytes = 0;

    bool operator==(const ServerResourcePair &) const = default;
};

/// Independent capacity bounds plus an optional stricter bound on a paired
/// phase footprint. The combined bound is checked against disk plus RAM from
/// the same phase, never against the sum of maxima from different phases.
struct CheckpointReplayServerResourceCaps {
    std::uint64_t max_total_local_disk_bytes = 0;
    std::uint64_t max_resident_ram_bytes = 0;
    std::uint64_t max_phase_combined_bytes = 0;

    bool operator==(
        const CheckpointReplayServerResourceCaps &) const = default;
};

/// Complete phase-local resident state exclusive of the payload/GKR reserve.
///
/// There must be one declaration for every reduction, in circuit order.
/// Each bound includes every source-reader ciphertext, encoded/decoded chunk,
/// writer buffer, accumulator, and backend temporary live in that subphase.
/// Affine reductions require a zero multiplication-builder bound. The common
/// and payload/GKR-only resident state declared below is the only state not
/// included in these phase-local values.
struct CheckpointReplayReductionResidentWorkspace {
    std::size_t reduction_layer = 0;
    payload::LayerKind kind = payload::LayerKind::Affine;
    std::uint64_t multiplication_builder_phase_bytes = 0;
    std::uint64_t reduction_phase_bytes = 0;

    bool operator==(
        const CheckpointReplayReductionResidentWorkspace &) const = default;
};

/// Caller-supplied phase components and hard caps.
///
/// `common` remains live through payload/GKR and transcript packing. It must
/// include the retained setup wrapper and its by-value metadata; heavyweight
/// immutable preprocessing shared by that wrapper is charged according to
/// its actual resident or serialized representation, not duplicated merely
/// because another `shared_ptr` exists. The current proof path also keeps the
/// indivisible FHE evaluation context, its keys/caches, the accumulated GKR
/// proof, and aligned ciphertexts across the packing handoff, so those are
/// common. They may move to a phase-only field only after an implementation
/// supplies and measures a smaller packing context or earlier last consumer.
///
/// `payload_gkr_only` includes truly payload-local state, including the
/// complete decoded encrypted-input request, which is not one of the
/// planner's bounded relation chunks. The sum of `common` and
/// `payload_gkr_only` must exactly equal both checkpoint-planner reserves, on
/// their respective resource axes. `transcript_packing_only` is the complete
/// peak exclusive to that later phase; the admission composer adds `common`
/// exactly once.
///
/// The replay planner charges the complete output response during evaluation,
/// but does not charge the complete input request. The latter must therefore
/// be part of `payload_gkr_only`. The planner then takes a maximum with later
/// GKR residency. The normal lifecycle transfers the output and releases the
/// input before GKR begins; the fixed reserve conservatively continues to
/// charge the input. Any additional server-owned request or response copy also
/// belongs in `payload_gkr_only.resident_ram_bytes`.
struct CheckpointReplayServerStorageLimits {
    CheckpointReplayServerResourceCaps caps;
    ServerResourcePair common;
    ServerResourcePair payload_gkr_only;
    ServerResourcePair transcript_packing_only;
    std::vector<CheckpointReplayReductionResidentWorkspace>
        reduction_workspaces;

    /// Additional complete payload-execution envelope, including the common
    /// and payload/GKR reserves. Zero retains ordinary checkpoint admission.
    /// Eager Laned execution supplies its packed-source and adjacent-natural
    /// artifact peak here. Conservatively retain this disk envelope during
    /// GKR and add the current multiplication artifact; the generic replay
    /// plan can otherwise understate retained packed sources in sparse plans.
    /// The RAM envelope already includes the eager workspace in the caller's
    /// replay reserve and must not add that workspace a second time.
    ServerResourcePair payload_execution_peak;

    bool operator==(
        const CheckpointReplayServerStorageLimits &) const = default;
};

/// Disk and RAM observed together in one admitted phase envelope.
struct CheckpointReplayServerPhasePeak {
    std::uint64_t local_disk_bytes = 0;
    std::uint64_t resident_ram_bytes = 0;
    std::uint64_t combined_bytes = 0;

    bool operator==(
        const CheckpointReplayServerPhasePeak &) const = default;
};

/// One replay-and-reduction envelope. The replayed source remains on disk
/// until a multiplication source artifact has been published. Affine rows
/// have a zero multiplication artifact and builder-phase bound. Disk and RAM
/// are each maximized over the envelope before they are paired, so the
/// combined value is intentionally conservative when those maxima occur in
/// different substeps.
struct CheckpointReplayReductionStoragePeak {
    std::size_t reduction_layer = 0;
    payload::LayerKind kind = payload::LayerKind::Affine;
    std::size_t required_source_layer = 0;
    std::size_t checkpoint_layer = 0;
    std::uint64_t payload_gkr_disk_reserve_bytes = 0;
    std::uint64_t live_checkpoint_bytes = 0;
    std::uint64_t transient_source_bytes = 0;
    std::uint64_t multiplication_source_artifact_bytes = 0;
    std::uint64_t replay_peak_local_disk_bytes = 0;
    std::uint64_t post_replay_local_disk_bytes = 0;
    std::uint64_t replay_peak_resident_bytes = 0;
    std::uint64_t payload_gkr_ram_reserve_bytes = 0;
    std::uint64_t multiplication_builder_phase_bytes = 0;
    std::uint64_t reduction_phase_bytes = 0;
    CheckpointReplayServerPhasePeak peak;

    bool source_is_checkpoint() const {
        return checkpoint_layer == required_source_layer;
    }

    bool operator==(
        const CheckpointReplayReductionStoragePeak &) const = default;
};

/// Admitted phase pairs and independent process maxima.
///
/// The three maxima need not describe one phase. In particular,
/// `max_phase_combined_bytes` is the largest reported phase sum and is not
/// `max_local_disk_bytes + max_resident_ram_bytes`.
struct CheckpointReplayServerStorageAdmission {
    ServerResourcePair payload_gkr_reserve;
    /// The planner and any supplemental payload-execution envelope maximize
    /// disk and RAM independently over forward and reverse replay. Their
    /// paired sum is conservative; both maxima need not occur in one step.
    CheckpointReplayServerPhasePeak replay_peak;
    std::vector<CheckpointReplayReductionStoragePeak> reduction_peaks;
    CheckpointReplayServerPhasePeak transcript_packing_peak;
    std::uint64_t max_local_disk_bytes = 0;
    std::uint64_t max_resident_ram_bytes = 0;
    std::uint64_t max_phase_combined_bytes = 0;

    bool operator==(
        const CheckpointReplayServerStorageAdmission &) const = default;
};

/// Validate and report the checkpoint-replay, file-backed GKR, and later
/// transcript-packing resource envelopes without writing files or changing a
/// proof transcript.
///
/// Completed multiplication artifacts must be reclaimed before the next
/// reduction. `FileTraceStoreOptions::max_total_bytes` is both the admitted
/// disk bound and writer cap for one multiplication-source artifact.
CheckpointReplayServerStorageAdmission
admit_checkpoint_replay_server_storage(
    const payload::PayloadCheckpointReplayProblem &problem,
    const payload::PayloadCheckpointReplayBudgets &budgets,
    const payload::PayloadCheckpointReplayPlan &plan,
    const gkr::laned_detail::FileLanedGkrOptions &gkr_options,
    bool reclaim_completed_multiplication_scratch,
    const CheckpointReplayServerStorageLimits &limits);

/// Folded counterpart of the same phase-local admission. Folded and Laned
/// multiplication scratch carry identical resource fields, but remain
/// distinct protocol types so a caller cannot accidentally cross-bind a
/// setup-selected schedule.
CheckpointReplayServerStorageAdmission
admit_checkpoint_replay_server_storage(
    const payload::PayloadCheckpointReplayProblem &problem,
    const payload::PayloadCheckpointReplayBudgets &budgets,
    const payload::PayloadCheckpointReplayPlan &plan,
    const gkr::folded_detail::FileFoldedGkrOptions &gkr_options,
    bool reclaim_completed_multiplication_scratch,
    const CheckpointReplayServerStorageLimits &limits);

} // namespace laminate::protocol

#endif // LAMINATE_PROTOCOL_STORAGE_CHECKPOINT_REPLAY_HPP
