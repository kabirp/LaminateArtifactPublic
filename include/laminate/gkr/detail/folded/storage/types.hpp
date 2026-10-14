#ifndef LAMINATE_GKR_DETAIL_FOLDED_STORAGE_TYPES_HPP
#define LAMINATE_GKR_DETAIL_FOLDED_STORAGE_TYPES_HPP

/// @file types.hpp
/// @brief Storage policy and reports for file-backed LaminateFolded GKR.

#include "laminate/gkr/folded.hpp"
#include "laminate/gkr/detail/folded/affine/diagnostics/statistics.hpp"
#include "laminate/gkr/detail/shared/dense_multiplication/statistics.hpp"
#include "laminate/gkr/detail/shared/dense_multiplication/source/file.hpp"
#include "laminate/payload/storage/file_trace_store.hpp"
#include "laminate/runtime_progress.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <vector>

namespace laminate::gkr::folded_detail {

/// Caller-owned directory and disk quota for one dense multiplication
/// artifact. Entries are ordered by reduction layer.
struct FileFoldedMultiplicationScratch {
    /// Multiplication layer whose canonical pair artifact uses this directory.
    std::size_t reduction_layer = 0;
    /// Caller-owned directory removed only in explicit no-retry mode.
    std::filesystem::path directory;
    /// Hard admission bounds for construction and retained artifact bytes.
    payload::FileTraceStoreOptions storage_limits;
    /// Setup-derived encoded-record buffer for the bit-reversal reorder.
    std::uint64_t sort_buffer_payload_bytes =
        ::laminate::gkr::detail::
            kDenseMultiplicationSortMaxBufferedPayloadBytes;
};

/// Storage plan and telemetry sink for one file-backed Folded GKR proof.
/// Neither field enters the proof or Fiat--Shamir transcript.
struct FileFoldedGkrOptions {
    /// One entry per multiplication layer, ordered output to input.
    std::vector<FileFoldedMultiplicationScratch> multiplication_scratch;
    /// Optional measurement callback around named protocol operations.
    RuntimeProgressCallback progress;
};

/// Explicit destructive-lifecycle policy for a no-retry file-backed proof.
struct IrreversibleFileFoldedGkrOptions {
    /// Must be `IrreversibleNoRetry` before any source is retired.
    payload::FileTraceSessionLifecycle lifecycle =
        payload::FileTraceSessionLifecycle::PreserveForRetry;
    /// Ordinary scratch and telemetry options used by the proof.
    FileFoldedGkrOptions proof;
    /// Must be true: each multiplication artifact dies after its reduction.
    bool reclaim_completed_multiplication_scratch = true;
};

/// Storage report for the canonical pair artifact of one multiplication layer.
struct FileFoldedMultiplicationArtifactReport {
    /// Caller-selected scratch directory; diagnostic only.
    std::filesystem::path directory;
    /// Content/metadata identity of the completed artifact.
    Digest artifact_id{};
    /// Evaluation setup identity recorded in the artifact descriptor.
    Digest setup_id{};
    /// Final retained artifact only. External-sort runs can raise peak disk
    /// above this retained size during construction.
    ::laminate::gkr::detail::FileDenseMultiplicationSourceReport storage;
    ::laminate::gkr::detail::
        FileDenseMultiplicationSourceBuildStatistics build;
    std::uint64_t peak_build_live_physical_bytes = 0;
};

struct FileFoldedReductionReport {
    /// Circuit reduction described by this report.
    std::size_t reduction_layer = 0;
    /// Determines which one of `affine` or `multiplication` is populated.
    payload::LayerKind kind = payload::LayerKind::Affine;
    /// Sequential scans and FHE work for an affine reduction.
    std::optional<FoldedAffineStatistics> affine;
    /// Build accounting for a multiplication pair artifact.
    std::optional<FileFoldedMultiplicationArtifactReport>
        multiplication_artifact;
    /// Sequential scans and FHE work for a multiplication reduction.
    std::optional<::laminate::gkr::detail::
                      FileBackedMultiplicationStatistics>
        multiplication;
    /// Source trace retirement performed after the proof owns its next claim.
    std::optional<payload::FileTraceLayerRetirementReport>
        trace_retirement;
    /// Physical artifact bytes removed after a no-retry reduction.
    std::uint64_t scratch_reclaimed_physical_bytes = 0;
};

struct FileFoldedGkrReport {
    /// Layer-zero trace retirement after the output claim is bound.
    std::optional<payload::FileTraceLayerRetirementReport>
        output_trace_retirement;
    /// One report per output-to-input circuit reduction.
    std::vector<FileFoldedReductionReport> reductions;
};

template <fhe::PersistableFheBackend Backend>
struct FileFoldedGkrResult {
    /// Canonical encrypted GKR proof; independent of storage policy.
    EncryptedFoldedProof<Backend> proof;
    /// Non-transcript storage and operation accounting for this execution.
    FileFoldedGkrReport report;
};

} // namespace laminate::gkr::folded_detail

#endif // LAMINATE_GKR_DETAIL_FOLDED_STORAGE_TYPES_HPP
