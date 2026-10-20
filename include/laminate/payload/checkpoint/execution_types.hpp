#ifndef LAMINATE_PAYLOAD_CHECKPOINT_EXECUTION_TYPES_HPP
#define LAMINATE_PAYLOAD_CHECKPOINT_EXECUTION_TYPES_HPP

/// @file execution_types.hpp
/// @brief Public options and accounting reports for checkpoint replay.

#include "laminate/payload/checkpoint/plan.hpp"
#include "laminate/payload/storage/file_trace_store.hpp"
#include "laminate/runtime_progress.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <vector>

namespace laminate::payload {

struct PayloadCheckpointReplayExecutionOptions {
    /// Caller-owned, existing, empty private directory. The caller must
    /// retain exclusive ownership and prevent concurrent mutation until the
    /// session ends. One child directory is reserved per logical layer.
    /// Successful execution leaves the root and empty child directories in
    /// place.
    std::filesystem::path directory;
    /// Logical free-space floor enforced by every one-layer writer.
    std::uint64_t min_free_bytes = 0;
    /// Allocation cap for the checkpoint-set encoding. Mandatory and
    /// nonzero; checked before directories are created or FHE work starts.
    std::uint64_t max_checkpoint_metadata_bytes = 0;
    /// Replay and source retirement delete inputs to future retry attempts.
    /// The default therefore fails closed.
    FileTraceSessionLifecycle lifecycle =
        FileTraceSessionLifecycle::PreserveForRetry;
    FileTraceStoreOpenLimits open_limits;
    /// Build bounded challenge-independent Laned S' artifacts beside each
    /// forward layer. Callers must select this only for a Laned proof whose
    /// packed source count is within the fixed 64-ciphertext bound.
    bool eager_laned_witness_packing = false;
    /// Optional diagnostics only. Callback failures are ignored and events
    /// never enter the proof transcript or any persisted protocol artifact.
    RuntimeProgressCallback progress;
};

struct PayloadCheckpointReplayIoReport {
    /// Phase-local process timing. `relation` encloses source reads, FHE,
    /// modulus switching, serialization, hashing, and output publication.
    FileTraceStoreOperationTiming relation;
    FileTraceStoreOperationTiming deserialization;
    FileTraceStoreOperationTiming fhe_evaluation;
    FileTraceStoreOperationTiming modulus_switching;
    FileTraceStoreReadDiagnostics storage_reads;
    FileTraceStoreWriteDiagnostics storage_writes;
    /// Backend ciphertext payload returned by range readers. Framing and
    /// indexes are reported separately. Each stored value has one eight-byte
    /// length field in addition to its tagged public-or-encrypted encoding;
    /// manifest, index, digest, and boundary reads are charged by the full-
    /// artifact validation counter.
    std::uint64_t encoded_ciphertext_bytes_read = 0;
    std::uint64_t framed_record_bytes_read = 0;
    std::uint64_t encoded_ciphertext_bytes_written = 0;
    /// Complete manifest-last artifact bytes written and validated.
    std::uint64_t physical_bytes_written = 0;
    std::uint64_t physical_validation_bytes_read = 0;
    std::uint64_t physical_bytes_deleted = 0;
    std::uint64_t range_readers_opened = 0;
    /// Alias-free dense multiplication relations consumed as two persistent
    /// monotone source streams instead of reopening one range per chunk.
    std::uint64_t monotone_dense_multiplication_relations = 0;
    std::uint64_t monotone_dense_multiplication_range_readers_opened = 0;
    std::uint64_t monotone_dense_multiplication_source_records_read = 0;
    /// Alias-heavy dense multiplication relations whose complete distinct
    /// source fits inside the already-admitted relation residency envelope.
    /// The cache removes repeated reads and decodes; logical FHE work is
    /// unchanged.
    std::uint64_t alias_cached_dense_multiplication_relations = 0;
    std::uint64_t
        alias_cached_dense_multiplication_range_readers_opened = 0;
    std::uint64_t
        alias_cached_dense_multiplication_distinct_source_records_read = 0;
    std::uint64_t
        alias_cached_dense_multiplication_logical_source_uses = 0;
    std::uint64_t
        alias_cached_dense_multiplication_fallback_source_records = 0;
    /// Exact singleton affine relations published by a same-filesystem hard
    /// link instead of decoding and rewriting their canonical stored values.
    std::uint64_t identity_affine_alias_relations = 0;
    /// Eligible relations whose filesystem could not provide the optional
    /// hard link and which therefore used the fully admitted materializer.
    std::uint64_t identity_affine_alias_fallbacks = 0;
    std::uint64_t identity_affine_alias_records_reused = 0;
    /// Existing layer-file lengths referenced without allocating or writing
    /// those bytes again.
    std::uint64_t identity_affine_alias_layer_bytes_reused = 0;
    /// Newly allocated manifest bytes for aliased one-layer namespaces.
    std::uint64_t identity_affine_alias_unique_bytes_written = 0;

    bool operator==(const PayloadCheckpointReplayIoReport &) const =
        default;
};

struct PayloadCheckpointReplaySegmentExecutionReport {
    std::size_t reduction_layer = 0;
    std::size_t required_source_layer = 0;
    std::size_t checkpoint_layer = 0;
    std::uint64_t replay_work_units = 0;
    PayloadCheckpointReplayIoReport replay;
    std::uint64_t transient_source_bytes_retired_after_use = 0;
    std::uint64_t checkpoint_bytes_retired_after_use = 0;
    /// Compact eager Laned S' artifact reclaimed after its reduction.
    std::uint64_t packed_witness_bytes_retired_after_use = 0;
    /// Staged proof-ingress copy reclaimed with this source. The natural-level
    /// checkpoint/replay artifact is accounted by the preceding two fields.
    std::uint64_t proof_ingress_bytes_retired_after_use = 0;
    std::uint64_t checkpoint_metadata_bytes_retired_after_use = 0;
    std::uint64_t live_physical_bytes_after = 0;

    bool operator==(
        const PayloadCheckpointReplaySegmentExecutionReport &) const =
        default;
};

/// Exact controlled-storage and deterministic buffer-residency ledger. The
/// RAM fields are exact arithmetic over the caller-supplied encoded and
/// decoded per-ciphertext bounds for retained input/output buffers. Fixed
/// backend arithmetic temporaries, allocator metadata, and operating-system
/// RSS are outside this counter.
struct PayloadCheckpointReplayExecutionReport {
    PayloadCheckpointReplayIoReport forward;
    PayloadCheckpointReplayIoReport reverse_replay;
    PayloadCheckpointReplayIoReport gkr_source_reads;
    /// One-time natural-source reads and compact proof-ingress writes. These
    /// operations are also part of the owning reverse-replay segment's I/O.
    std::uint64_t proof_ingress_ciphertexts = 0;
    std::uint64_t proof_ingress_modulus_switches = 0;
    std::uint64_t proof_ingress_physical_bytes_written = 0;
    std::uint64_t proof_ingress_physical_bytes_retired = 0;
    /// Challenge-independent Laned S' layers constructed beside forward
    /// payload evaluation. Natural-level copies are placed without rotations;
    /// only the compact outputs are reduced to their setup-selected proof
    /// level before publication.
    std::uint64_t laned_witness_source_values = 0;
    std::uint64_t laned_witness_logical_values_packed = 0;
    std::uint64_t laned_witness_mask_preparations = 0;
    std::uint64_t laned_witness_mask_cache_hits = 0;
    std::uint64_t laned_witness_prepared_mask_ntt_bytes = 0;
    std::uint64_t laned_witness_peak_mask_cache_ntt_bytes = 0;
    std::uint64_t laned_witness_modulus_switches = 0;
    std::uint64_t laned_witness_plain_multiplications = 0;
    std::uint64_t laned_witness_additions = 0;
    std::uint64_t laned_witness_rotations = 0;
    std::uint64_t laned_witness_packed_ciphertexts = 0;
    std::uint64_t laned_witness_physical_bytes_written = 0;
    std::uint64_t laned_witness_physical_bytes_retired = 0;
    double laned_witness_packing_wall_ms = 0.0;
    double laned_witness_packing_cpu_ms = 0.0;
    std::uint64_t initial_forward_work_units = 0;
    std::uint64_t replay_work_units = 0;
    std::uint64_t peak_live_physical_bytes = 0;
    std::uint64_t peak_live_scratch_bytes = 0;
    std::uint64_t live_physical_bytes = 0;
    std::uint64_t peak_controlled_resident_bytes = 0;
    /// Peak simultaneous logical bytes in checkpoint metadata buffers. The
    /// validation path holds one full encoding plus its small identity
    /// prefix; it never holds two full encodings.
    std::uint64_t peak_checkpoint_metadata_buffer_bytes = 0;
    std::size_t peak_live_layer_artifacts = 0;
    std::uint64_t checkpoint_metadata_physical_bytes = 0;
    std::uint64_t checkpoint_metadata_bytes_retired = 0;
    std::uint64_t checkpoint_layer_physical_bytes = 0;
    std::uint64_t checkpoint_layer_bytes_retired = 0;
    std::uint64_t transient_layer_bytes_retired = 0;
    std::uint64_t total_reclaimed_physical_bytes = 0;
    std::vector<std::size_t> checkpoint_retirement_order;
    std::vector<PayloadCheckpointReplaySegmentExecutionReport> segments;
    /// Proof-source set is complete. In eager Laned mode this denotes the
    /// compact per-layer S' artifacts rather than replay checkpoints.
    bool checkpoint_set_published = false;
    bool all_payload_artifacts_retired = false;
};


} // namespace laminate::payload

#endif // LAMINATE_PAYLOAD_CHECKPOINT_EXECUTION_TYPES_HPP
