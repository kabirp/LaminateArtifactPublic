#ifndef LAMINATE_GKR_DETAIL_BASE_PROVING_TYPES_HPP
#define LAMINATE_GKR_DETAIL_BASE_PROVING_TYPES_HPP

/// @file types.hpp
/// @brief Scratch declarations and reports for file-backed LaminateBase GKR.

#include "laminate/gkr/base.hpp"
#include "laminate/gkr/detail/base/affine/diagnostics/statistics.hpp"
#include "laminate/gkr/detail/shared/dense_multiplication/source/file.hpp"
#include "laminate/gkr/detail/shared/dense_multiplication/statistics.hpp"
#include "laminate/payload/storage/file_trace_store.hpp"
#include "laminate/runtime_progress.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <vector>

namespace laminate::gkr::base_detail {

/// Caller-owned scratch for one multiplication reduction. Entries follow
/// circuit order. Every directory must already exist, be empty, and be
/// disjoint from the trace/replay root and every other scratch directory.
struct FileBaseMultiplicationScratch {
    std::size_t reduction_layer = 0;
    std::filesystem::path directory;
    payload::FileTraceStoreOptions storage_limits;
    /// Setup-derived encoded-record buffer for the bit-reversal reorder.
    std::uint64_t sort_buffer_payload_bytes =
        detail::kDenseMultiplicationSortMaxBufferedPayloadBytes;
};

struct FileEncryptedBaseGkrOptions {
    std::vector<FileBaseMultiplicationScratch> multiplication_scratch;
    /// Optional diagnostics only. Callback failures are ignored and events
    /// never enter the transcript or proof.
    RuntimeProgressCallback progress;
};

/// Constant-size summary retained after a multiplication artifact is deleted.
/// Alias metadata is intentionally absent because it is linear in layer width.
struct FileBaseMultiplicationArtifactReport {
    std::filesystem::path directory;
    Digest artifact_id{};
    Digest setup_id{};
    detail::FileDenseMultiplicationSourceReport storage;
    detail::FileDenseMultiplicationSourceBuildStatistics build;
};

struct FileBaseReductionReport {
    std::size_t reduction_layer = 0;
    payload::LayerKind kind = payload::LayerKind::Affine;
    std::optional<BaseAffineStatistics> affine;
    std::optional<FileBaseMultiplicationArtifactReport>
        multiplication_artifact;
    std::optional<detail::FileBackedMultiplicationStatistics> multiplication;
    std::optional<payload::FileTraceLayerRetirementReport> trace_retirement;
    std::uint64_t scratch_reclaimed_physical_bytes = 0;
};

struct FileBaseGkrReport {
    std::optional<payload::FileTraceLayerRetirementReport>
        output_trace_retirement;
    std::vector<FileBaseReductionReport> reductions;
};

template <fhe::PersistableFheBackend Backend> struct FileBaseGkrResult {
    EncryptedBaseProof<Backend> proof;
    FileBaseGkrReport report;
};

} // namespace laminate::gkr::base_detail

#endif // LAMINATE_GKR_DETAIL_BASE_PROVING_TYPES_HPP
