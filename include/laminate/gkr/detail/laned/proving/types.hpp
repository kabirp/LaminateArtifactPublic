#ifndef LAMINATE_GKR_DETAIL_LANED_PROVING_TYPES_HPP
#define LAMINATE_GKR_DETAIL_LANED_PROVING_TYPES_HPP

/// @file types.hpp
/// @brief File-backed proving policy and reports for LaminateLaned GKR.

#include "laminate/gkr/laned.hpp"
#include "laminate/gkr/detail/laned/affine/diagnostics/statistics.hpp"
#include "laminate/gkr/detail/shared/dense_multiplication/source/file.hpp"
#include "laminate/gkr/detail/shared/dense_multiplication/statistics.hpp"
#include "laminate/payload/storage/file_trace_store.hpp"
#include "laminate/runtime_progress.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <vector>

namespace laminate::gkr::laned_detail {

/// Caller-owned scratch for one multiplication reduction. Entries follow
/// circuit order and name an existing, empty, private directory.
struct FileLanedMultiplicationScratch {
    /// Multiplication reduction that owns this scratch directory.
    std::size_t reduction_layer = 0;
    /// Existing empty private directory for the dense pair artifact.
    std::filesystem::path directory;
    /// Hard disk-capacity and free-space admission limits.
    payload::FileTraceStoreOptions storage_limits;
    /// Setup-derived encoded-record buffer for the bit-reversal reorder.
    std::uint64_t sort_buffer_payload_bytes =
        ::laminate::gkr::detail::
            kDenseMultiplicationSortMaxBufferedPayloadBytes;
};

struct FileLanedGkrOptions {
    /// One ordered scratch declaration per multiplication layer.
    std::vector<FileLanedMultiplicationScratch> multiplication_scratch;
    /// Optional observer for named protocol and storage phases.
    RuntimeProgressCallback progress;
};

/// Admitted artifact identity and storage policy for one multiplication
/// reduction. Unlike `FileLanedMultiplicationScratch`, this type is complete:
/// request admission has already bound the expected descriptor to the trace,
/// layered circuit, FHE context, and setup.
struct LanedMultiplicationArtifactPlan {
    /// Multiplication layer served by this artifact.
    std::size_t reduction_layer = 0;
    /// Empty private directory that will own the dense pair artifact.
    std::filesystem::path directory;
    /// Hard live-disk and free-space limits checked before construction.
    payload::FileTraceStoreOptions storage_limits;
    /// Encoded-record buffer admitted for this artifact build.
    std::uint64_t sort_buffer_payload_bytes =
        ::laminate::gkr::detail::
            kDenseMultiplicationSortMaxBufferedPayloadBytes;
    /// Exact dense `[left | right]` artifact expected after construction.
    ::laminate::gkr::detail::FileDenseMultiplicationSourceDescriptor
        descriptor;
};

struct IrreversibleFileLanedGkrOptions {
    /// Explicit no-retry authorization required before trace retirement.
    payload::FileTraceSessionLifecycle lifecycle =
        payload::FileTraceSessionLifecycle::PreserveForRetry;
    /// File-backed GKR scratch, telemetry, and artifact policy.
    FileLanedGkrOptions proof;
    /// Remove each dense pair artifact after its reduction succeeds.
    bool reclaim_completed_multiplication_scratch = false;
};

struct FileLanedReductionReport {
    /// Circuit layer reduced by this report entry.
    std::size_t reduction_layer = 0;
    /// Affine or multiplication reduction selected by the circuit.
    payload::LayerKind kind = payload::LayerKind::Affine;
    /// Affine scan and FHE counters, present only for affine layers.
    std::optional<LanedAffineStatistics> affine;
    /// Dense pair artifact construction report for multiplication layers.
    std::optional<::laminate::gkr::detail::
                      FileDenseMultiplicationSourceWriteResult>
        multiplication_artifact;
    /// Multiplication scan and FHE counters, present only for products.
    std::optional<::laminate::gkr::detail::
                      FileBackedMultiplicationStatistics>
        multiplication;
    /// Compact source-layer retirement, when the trace supports reclamation.
    std::optional<payload::FileTraceLayerRetirementReport>
        trace_retirement;
    /// Physical bytes removed from the completed multiplication artifact.
    std::uint64_t scratch_reclaimed_physical_bytes = 0;
};

struct FileLanedGkrReport {
    /// Retirement of the output trace layer after its claim is bound.
    std::optional<payload::FileTraceLayerRetirementReport>
        output_trace_retirement;
    /// Reduction reports in output-to-input proof order.
    std::vector<FileLanedReductionReport> reductions;
};

template <fhe::PersistableFheBackend Backend>
struct FileLanedGkrResult {
    /// Canonical encrypted GKR proof messages.
    EncryptedLanedProof<Backend> proof;
    /// Storage and arithmetic diagnostics excluded from Fiat--Shamir.
    FileLanedGkrReport report;
};

} // namespace laminate::gkr::laned_detail

#endif // LAMINATE_GKR_DETAIL_LANED_PROVING_TYPES_HPP
