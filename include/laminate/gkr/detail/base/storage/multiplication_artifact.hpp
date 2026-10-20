#ifndef LAMINATE_GKR_DETAIL_BASE_STORAGE_MULTIPLICATION_ARTIFACT_HPP
#define LAMINATE_GKR_DETAIL_BASE_STORAGE_MULTIPLICATION_ARTIFACT_HPP

/// @file multiplication_artifact.hpp
/// @brief Build/open/reclaim lifecycle for one Base multiplication source.
///
/// The multiplication sumcheck needs bit-reversed logical pairs, while the
/// payload trace stores compact live wires. This file owns that storage
/// conversion. The layer-reduction prover only sees the finalized source.

#include "laminate/gkr/detail/base/proving/types.hpp"

#include <cstdint>
#include <stdexcept>
#include <utility>

namespace laminate::gkr::base_detail::storage {

inline RuntimeProgressEvent multiplication_artifact_event(
    RuntimeProgressStage stage, std::size_t layer) {
    return RuntimeProgressEvent{
        .stage = stage,
        .layer_kind = RuntimeProgressLayerKind::Multiplication,
        .reduction_layer = layer,
        .source_layer = layer + 1U,
    };
}

template <fhe::PersistableFheBackend Backend>
struct PreparedMultiplicationArtifact {
    detail::FileDenseMultiplicationSource<Backend> source;
    FileBaseMultiplicationArtifactReport report;
};

template <fhe::PersistableFheBackend Backend, typename TraceSource>
PreparedMultiplicationArtifact<Backend> prepare_multiplication_artifact(
    const typename Backend::EvalContext &eval,
    const TraceSource &trace,
    const detail::DenseMultiplicationSourcePlan &source_plan,
    const FileBaseMultiplicationScratch &scratch,
    const RuntimeProgressCallback &progress) {
    const std::size_t layer = scratch.reduction_layer;
    const RuntimeProgressEvent build_event = multiplication_artifact_event(
        RuntimeProgressStage::BaseMultiplicationSourceBuild, layer);
    RuntimeProgressSpan build_progress(progress, build_event);
    auto built =
        detail::build_file_dense_multiplication_source<Backend>(
            eval, trace, source_plan, scratch.directory,
            scratch.storage_limits,
            scratch.sort_buffer_payload_bytes,
            [&](std::uint64_t completed, std::uint64_t total) {
                RuntimeProgressEvent update = build_event;
                update.boundary = RuntimeProgressBoundary::Update;
                update.completed_steps = completed;
                update.total_steps = total;
                notify_runtime_progress(progress, update);
            });
    build_progress.finish();
    if (built.source.descriptor().artifact_id !=
            built.written.descriptor.artifact_id ||
        built.source.report() != built.written.report) {
        throw std::logic_error(
            "Base multiplication artifact build handoff drifted");
    }

    return PreparedMultiplicationArtifact<Backend>{
        std::move(built.source),
        FileBaseMultiplicationArtifactReport{
            built.written.directory,
            built.written.descriptor.artifact_id,
            built.written.descriptor.setup_id,
            built.written.report,
            built.written.statistics,
        }};
}

template <fhe::PersistableFheBackend Backend>
std::uint64_t reclaim_multiplication_artifact(
    detail::FileDenseMultiplicationSource<Backend> source,
    std::size_t layer, std::uint64_t expected_bytes,
    const RuntimeProgressCallback &progress) {
    RuntimeProgressSpan reclaim_progress(
        progress, multiplication_artifact_event(
                      RuntimeProgressStage::BaseMultiplicationSourceReclaim,
                      layer));
    const std::uint64_t reclaimed =
        std::move(source).remove_validated_files();
    reclaim_progress.finish();
    if (reclaimed != expected_bytes) {
        throw std::logic_error(
            "Base scratch reclamation ledger drifted");
    }
    return reclaimed;
}

} // namespace laminate::gkr::base_detail::storage

#endif // LAMINATE_GKR_DETAIL_BASE_STORAGE_MULTIPLICATION_ARTIFACT_HPP
