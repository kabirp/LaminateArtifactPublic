#ifndef LAMINATE_RUNTIME_PROGRESS_HPP
#define LAMINATE_RUNTIME_PROGRESS_HPP

/// @file runtime_progress.hpp
/// @brief Optional, transcript-independent progress notifications.

#include <cstddef>
#include <cstdint>
#include <functional>
#include <utility>

namespace laminate {

enum class RuntimeProgressBoundary : std::uint8_t {
    Begin,
    /// A non-nesting progress sample for an already-active span. Updates are
    /// diagnostic only and do not open or close a timed span.
    Update,
    End,
};

enum class RuntimeProgressLayerKind : std::uint8_t {
    Unspecified,
    Affine,
    Multiplication,
};

enum class RuntimeProgressSide : std::uint8_t {
    Unspecified,
    Left,
    Right,
};

/// Coordinate family reduced by a sumcheck round. This keeps progress output
/// in protocol language even when both families share one arithmetic kernel.
enum class RuntimeProgressCoordinateDomain : std::uint8_t {
    Unspecified,
    CiphertextIndex,
    SlotIndex,
};

/// Storage/arithmetic detail for a long-running operation. These labels are
/// diagnostic and remain below the protocol-facing stage name.
enum class RuntimeProgressSubpass : std::uint8_t {
    Unspecified,
    SourceLocalMobius,
    LocalMobius,
    RateExpansion,
    Transpose,
    TwiddleTranspose,
    LocalNtt,
    MerkleTree,
    MessagePublication,
    CodewordPublication,
    MerklePublication,
    ArtifactPublication,
};

enum class RuntimeProgressWorkUnit : std::uint8_t {
    Unspecified,
    FieldElements,
    NttButterflies,
    MerkleItems,
    PublicationSteps,
};

/// Public execution phases exposed by payload checkpoint replay and the
/// compact GKR paths. Notifications are diagnostics only: none of these
/// values are observed by Fiat--Shamir, serialized into a proof, or used to
/// select protocol work.
enum class RuntimeProgressStage : std::uint8_t {
    /// No protocol phase has been selected. This is the only safe default:
    /// a partially initialized event must not be reported as Base work.
    Unspecified,
    PayloadForwardRelation,
    PayloadReplaySegment,
    PayloadProofIngress,
    PayloadReplayRelation,
    LanedWitnessPacking,
    BaseReduction,
    BaseTraceLayerRetirement,
    BaseAffineSumcheckRound,
    BaseAffineTerminalEvaluation,
    BaseMultiplicationSourceBuild,
    BaseMultiplicationSumcheckRound,
    BaseMultiplicationTerminalSourceEvaluation,
    BaseMultiplicationSourceReclaim,
    BaseGateMleFinish,
    FoldedReduction,
    FoldedTraceLayerRetirement,
    FoldedAffineSumcheckRound,
    FoldedAffineSlotCheckpoint,
    FoldedMultiplicationSourceBuild,
    FoldedMultiplicationSumcheckRound,
    FoldedMultiplicationSlotCheckpoint,
    FoldedMultiplicationSourceReclaim,
    FoldedGateMleFinish,
    LanedReduction,
    LanedTraceLayerRetirement,
    LanedAffineSourcePacking,
    LanedAffineSumcheckRound,
    LanedAffineSlotCheckpoint,
    LanedMultiplicationSourceBuild,
    LanedMultiplicationSumcheckRound,
    LanedMultiplicationSlotCheckpoint,
    LanedMultiplicationSourceReclaim,
    LanedGateMleFinish,
    TranscriptPackingRevealEvaluation,
    TranscriptPackingAssignment,
    TranscriptPackingAlignedSourceRetirement,
    TranscriptPackingSpartanProve,
    TranscriptPackingSpartanAssignment,
    TranscriptPackingSpartanWitnessCommitment,
    TranscriptPackingSpartanWitnessCommitmentMobius,
    TranscriptPackingSpartanWitnessCommitmentRateExpansion,
    TranscriptPackingSpartanWitnessCommitmentNtt,
    TranscriptPackingSpartanWitnessCommitmentMerkleTree,
    TranscriptPackingSpartanWitnessCommitmentFinalPublication,
    TranscriptPackingSpartanMatrixProducts,
    TranscriptPackingSpartanConstraintCheck,
    TranscriptPackingSpartanWiringMatrix,
    TranscriptPackingSpartanWiringCheck,
    TranscriptPackingSpartanFactoredOpenings,
    TranscriptPackingSpartanWitnessOpening,
    TranscriptPackingSpartanRetirement,
    TranscriptPackingOuterAssignmentRetirement,
    TranscriptPackingVerifierStatement,
    TranscriptPackingSpartanVerify,
    TranscriptPackingThresholdChecks,
    TranscriptPackingUnpack,
};

inline constexpr std::size_t kRuntimeProgressNoIndex =
    static_cast<std::size_t>(-1);

/// One phase boundary. Index fields which do not apply retain
/// `kRuntimeProgressNoIndex`. `round` is zero-based and `round_count` is the
/// total number of rounds in that reduction.
struct RuntimeProgressEvent {
    RuntimeProgressBoundary boundary = RuntimeProgressBoundary::Begin;
    RuntimeProgressStage stage = RuntimeProgressStage::Unspecified;
    RuntimeProgressLayerKind layer_kind =
        RuntimeProgressLayerKind::Unspecified;
    RuntimeProgressSide side = RuntimeProgressSide::Unspecified;
    RuntimeProgressCoordinateDomain coordinate_domain =
        RuntimeProgressCoordinateDomain::Unspecified;
    std::size_t reduction_layer = kRuntimeProgressNoIndex;
    std::size_t source_layer = kRuntimeProgressNoIndex;
    std::size_t output_layer = kRuntimeProgressNoIndex;
    std::size_t checkpoint_layer = kRuntimeProgressNoIndex;
    std::size_t round = kRuntimeProgressNoIndex;
    std::size_t round_count = 0;
    std::uint64_t work_units = 0;
    /// Generic cumulative progress for long-running stages which do not have
    /// protocol rounds. A zero total leaves the corresponding pair absent.
    std::uint64_t completed_steps = 0;
    std::uint64_t total_steps = 0;
    std::uint64_t completed_work_units = 0;
    std::uint64_t total_work_units = 0;
    std::size_t column_index = kRuntimeProgressNoIndex;
    std::size_t column_count = 0;
    RuntimeProgressSubpass subpass = RuntimeProgressSubpass::Unspecified;
    RuntimeProgressWorkUnit progress_work_unit =
        RuntimeProgressWorkUnit::Unspecified;
    /// Whole-operation passes are counts, not a percentage: different passes
    /// may have radically different arithmetic cost.
    std::uint64_t phase_completed_steps = 0;
    std::uint64_t phase_total_steps = 0;
    std::uint64_t completed_read_bytes = 0;
    std::uint64_t total_read_bytes = 0;
    std::uint64_t completed_write_bytes = 0;
    std::uint64_t total_write_bytes = 0;
    std::uint64_t phase_completed_read_bytes = 0;
    std::uint64_t phase_total_read_bytes = 0;
    std::uint64_t phase_completed_write_bytes = 0;
    std::uint64_t phase_total_write_bytes = 0;
    std::uint64_t completed_butterflies = 0;
    std::uint64_t total_butterflies = 0;
    std::uint64_t phase_completed_butterflies = 0;
    std::uint64_t phase_total_butterflies = 0;
    std::size_t radix_elements = 0;
    std::size_t row_count = 0;
    std::size_t row_size = 0;
    std::uint64_t recent_work_units = 0;
    std::uint64_t recent_elapsed_milliseconds = 0;
    std::uint64_t estimated_remaining_milliseconds = 0;
    /// Phase-local timing and storage counters. Payload-relation update events
    /// carry cumulative snapshots since that relation began; end events carry
    /// the final snapshot. Other stages may leave them zero.
    double phase_wall_ms = 0.0;
    double phase_cpu_ms = 0.0;
    double fhe_wall_ms = 0.0;
    double fhe_cpu_ms = 0.0;
    double modulus_switch_wall_ms = 0.0;
    double modulus_switch_cpu_ms = 0.0;
    double serialization_wall_ms = 0.0;
    double serialization_cpu_ms = 0.0;
    double buffer_assembly_wall_ms = 0.0;
    double buffer_assembly_cpu_ms = 0.0;
    double hashing_wall_ms = 0.0;
    double hashing_cpu_ms = 0.0;
    double deserialization_wall_ms = 0.0;
    double deserialization_cpu_ms = 0.0;
    double storage_read_wall_ms = 0.0;
    double storage_read_cpu_ms = 0.0;
    double storage_write_wall_ms = 0.0;
    double storage_write_cpu_ms = 0.0;
    double prefetch_wall_ms = 0.0;
    double prefetch_cpu_ms = 0.0;
    double storage_wait_wall_ms = 0.0;
    double storage_wait_cpu_ms = 0.0;
    double writeback_submission_wall_ms = 0.0;
    double writeback_submission_cpu_ms = 0.0;
    double writeback_wait_wall_ms = 0.0;
    double writeback_wait_cpu_ms = 0.0;
    std::uint64_t capacity_probes = 0;
    std::uint64_t read_batches = 0;
    std::uint64_t read_syscalls = 0;
    /// Bytes returned by application read syscalls; not physical device I/O.
    std::uint64_t application_read_bytes = 0;
    std::uint64_t prefetch_requests = 0;
    std::uint64_t prefetch_bytes_requested = 0;
    std::uint64_t prefetch_fallbacks = 0;
    std::uint64_t prefetch_seek_disables = 0;
    std::uint64_t prefetch_window_bytes = 0;
    std::uint64_t maximum_prefetch_request_bytes = 0;
    std::uint64_t write_batches = 0;
    std::uint64_t write_syscalls = 0;
    /// Bytes submitted by application write syscalls; not physical device I/O.
    std::uint64_t application_write_bytes = 0;
    std::uint64_t authenticated_record_bytes = 0;
    std::uint64_t same_process_unhashed_record_bytes = 0;
    std::uint64_t record_copy_bytes = 0;
    std::uint64_t writeback_submission_attempts = 0;
    std::uint64_t writeback_submission_successes = 0;
    std::uint64_t writeback_wait_attempts = 0;
    std::uint64_t writeback_wait_successes = 0;
    std::uint64_t writeback_range_bytes_submitted = 0;
    std::uint64_t writeback_range_bytes_waited = 0;
    std::uint64_t maximum_writeback_submission_bytes = 0;
    std::uint64_t writeback_window_bytes = 0;
    std::uint64_t maximum_unwaited_writeback_range_bytes = 0;
    std::uint64_t writeback_files_submit_only = 0;
    std::uint64_t writeback_drains = 0;
    std::uint64_t writeback_drain_range_bytes = 0;
    std::uint64_t writeback_drains_skipped = 0;
    std::uint64_t writeback_range_bytes_without_explicit_wait = 0;
    std::uint64_t positional_write_calls = 0;
    std::uint64_t positional_write_bytes = 0;
    std::uint64_t maximum_read_batch_bytes = 0;
    std::uint64_t maximum_write_batch_bytes = 0;
    std::uint64_t identity_affine_alias_relations = 0;
    std::uint64_t identity_affine_alias_fallbacks = 0;
    std::uint64_t identity_affine_alias_records_reused = 0;
    std::uint64_t identity_affine_alias_layer_bytes_reused = 0;
    std::uint64_t identity_affine_alias_unique_bytes_written = 0;

    bool operator==(const RuntimeProgressEvent &) const = default;
};

using RuntimeProgressCallback =
    std::function<void(const RuntimeProgressEvent &)>;

/// Diagnostics must never change protocol execution. In particular, a
/// logging failure cannot make an irreversible proof attempt fail after it
/// has retired state.
inline void notify_runtime_progress(
    const RuntimeProgressCallback &callback,
    const RuntimeProgressEvent &event) noexcept {
    if (!callback) {
        return;
    }
    try {
        callback(event);
    } catch (...) {
    }
}

/// A diagnostic span kept deliberately separate from protocol control flow.
/// Construction emits `Begin`; `finish()` emits the matching `End`. There is
/// no automatic end event on destruction: an exception leaves the span open,
/// which tells an observer that the measured phase did not complete.
class RuntimeProgressSpan {
  public:
    /// `callback` is borrowed and must outlive the span. An rvalue overload is
    /// deleted below so a temporary `std::function` cannot leave a dangling
    /// reference while the measured operation runs.
    RuntimeProgressSpan(const RuntimeProgressCallback &callback,
                        RuntimeProgressEvent event)
        : callback_(&callback), event_(std::move(event)) {
        event_.boundary = RuntimeProgressBoundary::Begin;
        notify_runtime_progress(*callback_, event_);
    }

    RuntimeProgressSpan(RuntimeProgressCallback &&,
                        RuntimeProgressEvent) = delete;

    RuntimeProgressSpan(const RuntimeProgressSpan &) = delete;
    RuntimeProgressSpan &operator=(const RuntimeProgressSpan &) = delete;

    void finish() noexcept {
        if (finished_) {
            return;
        }
        event_.boundary = RuntimeProgressBoundary::End;
        notify_runtime_progress(*callback_, event_);
        finished_ = true;
    }

  private:
    const RuntimeProgressCallback *callback_;
    RuntimeProgressEvent event_;
    bool finished_ = false;
};

} // namespace laminate

#endif // LAMINATE_RUNTIME_PROGRESS_HPP
