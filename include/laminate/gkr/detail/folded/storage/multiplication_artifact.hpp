#ifndef LAMINATE_GKR_DETAIL_FOLDED_STORAGE_MULTIPLICATION_ARTIFACT_HPP
#define LAMINATE_GKR_DETAIL_FOLDED_STORAGE_MULTIPLICATION_ARTIFACT_HPP

/// @file multiplication_artifact.hpp
/// @brief Disk lifecycle for one Folded multiplication source artifact.
///
/// A Folded multiplication sumcheck reads the canonical dense `[left | right]`
/// pair ordering, whereas the payload trace stores compact live wires. This
/// file owns that representation change and its build/open/reclaim telemetry.
/// No function here publishes a proof message or advances Fiat--Shamir.

#include "laminate/gkr/detail/folded/storage/types.hpp"

#include <cstdint>
#include <stdexcept>
#include <utility>

namespace laminate::gkr::folded_detail::storage {

inline RuntimeProgressEvent multiplication_artifact_event(
    RuntimeProgressStage stage, std::size_t reduction_layer) {
    return RuntimeProgressEvent{
        .stage = stage,
        .layer_kind = RuntimeProgressLayerKind::Multiplication,
        .reduction_layer = reduction_layer,
        .source_layer = reduction_layer + 1U,
    };
}

/// Authenticated pair artifact plus the fixed-size report retained after the
/// artifact is reclaimed.
template <fhe::PersistableFheBackend Backend>
struct PreparedMultiplicationArtifact {
    ::laminate::gkr::detail::FileDenseMultiplicationSource<Backend> source;
    FileFoldedMultiplicationArtifactReport report;
};

/// Build the canonical pair artifact and adopt the writer's validated private
/// file identities and indexes without rereading the completed ciphertexts.
template <fhe::PersistableFheBackend Backend, typename TraceSource>
PreparedMultiplicationArtifact<Backend> prepare_multiplication_artifact(
    const typename Backend::EvalContext &eval, const TraceSource &trace,
    const ::laminate::gkr::detail::DenseMultiplicationSourcePlan
        &source_plan,
    const FileFoldedMultiplicationScratch &scratch,
    const RuntimeProgressCallback &progress) {
    const std::size_t layer = scratch.reduction_layer;

    const RuntimeProgressEvent build_event = multiplication_artifact_event(
        RuntimeProgressStage::FoldedMultiplicationSourceBuild, layer);
    RuntimeProgressSpan build_progress(progress, build_event);
    auto built =
        ::laminate::gkr::detail::
            build_file_dense_multiplication_source<Backend>(
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
            "LaminateFolded multiplication artifact build handoff drifted");
    }

    return PreparedMultiplicationArtifact<Backend>{
        std::move(built.source),
        FileFoldedMultiplicationArtifactReport{
            built.written.directory,
            built.written.descriptor.artifact_id,
            built.written.descriptor.setup_id,
            built.written.report,
            built.written.statistics,
            built.written.statistics.external_sort_peak_combined_artifact_bytes,
        }};
}

/// Delete a consumed pair artifact when the caller owns an irreversible
/// no-retry attempt. Returning zero makes the retryable policy explicit.
template <fhe::PersistableFheBackend Backend>
std::uint64_t reclaim_multiplication_artifact(
    ::laminate::gkr::detail::FileDenseMultiplicationSource<Backend> source,
    std::size_t layer, std::uint64_t expected_bytes, bool reclaim,
    const RuntimeProgressCallback &progress) {
    if (!reclaim) {
        return 0;
    }

    RuntimeProgressSpan reclaim_progress(
        progress, multiplication_artifact_event(
                      RuntimeProgressStage::
                          FoldedMultiplicationSourceReclaim,
                      layer));
    const std::uint64_t reclaimed =
        std::move(source).remove_validated_files();
    reclaim_progress.finish();
    if (reclaimed != expected_bytes) {
        throw std::logic_error(
            "LaminateFolded scratch reclamation ledger drifted");
    }
    return reclaimed;
}

} // namespace laminate::gkr::folded_detail::storage

#endif // LAMINATE_GKR_DETAIL_FOLDED_STORAGE_MULTIPLICATION_ARTIFACT_HPP
