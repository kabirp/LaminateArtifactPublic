#ifndef LAMINATE_GKR_DETAIL_LANED_STORAGE_MULTIPLICATION_ARTIFACT_HPP
#define LAMINATE_GKR_DETAIL_LANED_STORAGE_MULTIPLICATION_ARTIFACT_HPP

/// @file multiplication_artifact.hpp
/// @brief Disk lifecycle for one Laned multiplication source artifact.
///
/// A Laned multiplication sumcheck reads the canonical dense `[left | right]`
/// pair ordering, whereas the payload trace stores compact live wires. This
/// file owns that representation change and its build/open/reclaim telemetry.
/// No function here publishes a proof message or advances Fiat--Shamir.

#include "laminate/gkr/detail/laned/proving/types.hpp"

#include <cstdint>
#include <stdexcept>
#include <utility>

namespace laminate::gkr::laned_detail::storage {

inline RuntimeProgressEvent multiplication_artifact_event(
    RuntimeProgressStage stage, std::size_t reduction_layer,
    std::uint64_t source_values = 0) {
    return RuntimeProgressEvent{
        .stage = stage,
        .layer_kind = RuntimeProgressLayerKind::Multiplication,
        .reduction_layer = reduction_layer,
        .source_layer = reduction_layer + 1U,
        .work_units = source_values,
        .total_steps = source_values,
        .total_work_units = source_values,
    };
}

/// Authenticated pair artifact and the write report retained for diagnostics.
template <fhe::PersistableFheBackend Backend>
struct PreparedMultiplicationArtifact {
    ::laminate::gkr::detail::FileDenseMultiplicationSource<Backend> source;
    ::laminate::gkr::detail::FileDenseMultiplicationSourceWriteResult
        write_report;
};

/// Build the canonical pair artifact and adopt the writer's validated private
/// file identities and indexes without rereading the completed ciphertexts.
template <fhe::PersistableFheBackend Backend, typename TraceSource>
PreparedMultiplicationArtifact<Backend> prepare_multiplication_artifact(
    const typename Backend::EvalContext &eval, const TraceSource &trace,
    const ::laminate::gkr::detail::DenseMultiplicationSourcePlan
        &source_plan,
    const LanedMultiplicationArtifactPlan &artifact_plan,
    const RuntimeProgressCallback &progress) {
    const std::size_t layer = artifact_plan.reduction_layer;
    std::uint64_t source_values = static_cast<std::uint64_t>(
        artifact_plan.descriptor.source_dimensions.logical_size);
    if constexpr (requires {
                      trace.uses_eager_laned_witness_packing();
                      trace.laned_packed_layer_layout(layer + 1U);
                  }) {
        if (trace.uses_eager_laned_witness_packing()) {
            source_values = static_cast<std::uint64_t>(
                trace.laned_packed_layer_layout(layer + 1U)
                    .logical_ciphertext_count);
        }
    }

    const RuntimeProgressEvent build_event = multiplication_artifact_event(
        RuntimeProgressStage::LanedMultiplicationSourceBuild, layer,
        source_values);
    RuntimeProgressSpan build_progress(progress, build_event);
    auto built = ::laminate::gkr::detail::
        build_file_dense_multiplication_source<Backend>(
            eval, trace, source_plan, artifact_plan.directory,
            artifact_plan.storage_limits,
            artifact_plan.sort_buffer_payload_bytes,
            [&](std::uint64_t completed, std::uint64_t total) {
                RuntimeProgressEvent update = build_event;
                update.boundary = RuntimeProgressBoundary::Update;
                update.completed_steps = completed;
                update.total_steps = total;
                update.completed_work_units = completed;
                update.total_work_units = total;
                notify_runtime_progress(progress, update);
            });
    build_progress.finish();
    if (built.written.descriptor != artifact_plan.descriptor) {
        throw std::logic_error(
            "LaminateLaned multiplication artifact descriptor drifted");
    }
    if (built.source.descriptor().artifact_id !=
            built.written.descriptor.artifact_id ||
        built.source.report() != built.written.report) {
        throw std::logic_error(
            "LaminateLaned multiplication artifact build handoff drifted");
    }

    return PreparedMultiplicationArtifact<Backend>{
        std::move(built.source), std::move(built.written)};
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
                          LanedMultiplicationSourceReclaim,
                      layer));
    const std::uint64_t reclaimed =
        std::move(source).remove_validated_files();
    reclaim_progress.finish();
    if (reclaimed != expected_bytes) {
        throw std::logic_error(
            "LaminateLaned scratch reclamation ledger drifted");
    }
    return reclaimed;
}

} // namespace laminate::gkr::laned_detail::storage

#endif // LAMINATE_GKR_DETAIL_LANED_STORAGE_MULTIPLICATION_ARTIFACT_HPP
