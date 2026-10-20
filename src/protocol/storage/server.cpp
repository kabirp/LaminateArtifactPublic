/// @file server.cpp

#include "laminate/protocol/storage/checkpoint_replay.hpp"

#include "laminate/gkr/detail/folded/prover.hpp"
#include "laminate/gkr/detail/laned/prover.hpp"

#include <algorithm>
#include <ios>
#include <limits>
#include <stdexcept>
#include <string>

namespace laminate::protocol {
namespace {

std::uint64_t checked_add(std::uint64_t left, std::uint64_t right,
                          const char *label) {
    if (right > std::numeric_limits<std::uint64_t>::max() - left) {
        throw std::overflow_error(std::string(label) + " overflows");
    }
    return left + right;
}

ServerResourcePair checked_add(ServerResourcePair left,
                               ServerResourcePair right,
                               const char *label) {
    return ServerResourcePair{
        checked_add(left.local_disk_bytes, right.local_disk_bytes, label),
        checked_add(left.resident_ram_bytes, right.resident_ram_bytes,
                    label),
    };
}

CheckpointReplayServerPhasePeak phase_peak(ServerResourcePair resources,
                                            const char *label) {
    return CheckpointReplayServerPhasePeak{
        resources.local_disk_bytes,
        resources.resident_ram_bytes,
        checked_add(resources.local_disk_bytes,
                    resources.resident_ram_bytes, label),
    };
}

void require_within_caps(
    const CheckpointReplayServerPhasePeak &peak,
    const CheckpointReplayServerResourceCaps &caps, const char *label) {
    if (peak.local_disk_bytes > caps.max_total_local_disk_bytes) {
        throw std::invalid_argument(
            std::string(label) + " exceeds the total local-disk cap");
    }
    if (peak.resident_ram_bytes > caps.max_resident_ram_bytes) {
        throw std::invalid_argument(
            std::string(label) + " exceeds the resident-RAM cap");
    }
    if (peak.combined_bytes > caps.max_phase_combined_bytes) {
        throw std::invalid_argument(
            std::string(label) + " exceeds the paired phase cap");
    }
}

void update_maxima(CheckpointReplayServerStorageAdmission &admission,
                   const CheckpointReplayServerPhasePeak &peak) {
    admission.max_local_disk_bytes =
        std::max(admission.max_local_disk_bytes, peak.local_disk_bytes);
    admission.max_resident_ram_bytes =
        std::max(admission.max_resident_ram_bytes,
                 peak.resident_ram_bytes);
    admission.max_phase_combined_bytes =
        std::max(admission.max_phase_combined_bytes,
                 peak.combined_bytes);
}

void validate_scratch_limits(
    const payload::FileTraceStoreOptions &limits) {
    if (limits.max_total_bytes == 0 || limits.min_free_bytes == 0) {
        throw std::invalid_argument(
            "multiplication scratch limits must be nonzero");
    }
    constexpr std::streamoff kMaxStreamOffset =
        std::numeric_limits<std::streamoff>::max();
    if constexpr (kMaxStreamOffset >= 0) {
        if (limits.max_total_bytes >
            static_cast<std::uint64_t>(kMaxStreamOffset)) {
            throw std::invalid_argument(
                "multiplication scratch byte limit exceeds stream range");
        }
    }
}

} // namespace

template <typename GkrOptions>
CheckpointReplayServerStorageAdmission
admit_checkpoint_replay_server_storage_impl(
    const payload::PayloadCheckpointReplayProblem &problem,
    const payload::PayloadCheckpointReplayBudgets &budgets,
    const payload::PayloadCheckpointReplayPlan &plan,
    const GkrOptions &gkr_options,
    bool reclaim_completed_multiplication_scratch,
    const CheckpointReplayServerStorageLimits &limits) {
    if (!reclaim_completed_multiplication_scratch) {
        throw std::invalid_argument(
            "server storage admission requires completed multiplication "
            "scratch reclamation");
    }
    if (limits.caps.max_total_local_disk_bytes == 0 ||
        limits.caps.max_resident_ram_bytes == 0 ||
        limits.caps.max_phase_combined_bytes == 0) {
        throw std::invalid_argument(
            "server resource caps must be nonzero");
    }
    if (limits.caps.max_total_local_disk_bytes !=
        budgets.max_live_scratch_bytes) {
        throw std::invalid_argument(
            "total local-disk cap does not match the replay budget");
    }
    if (limits.caps.max_resident_ram_bytes !=
        budgets.max_resident_ciphertext_bytes) {
        throw std::invalid_argument(
            "resident-RAM cap does not match the replay budget");
    }

    const ServerResourcePair payload_gkr_reserve = checked_add(
        limits.common, limits.payload_gkr_only,
        "common and payload/GKR resource reserve");
    if (payload_gkr_reserve.local_disk_bytes !=
        budgets.reserved_live_scratch_bytes) {
        throw std::invalid_argument(
            "payload/GKR disk components do not match the replay reserve");
    }
    if (payload_gkr_reserve.resident_ram_bytes !=
        budgets.reserved_resident_bytes) {
        throw std::invalid_argument(
            "payload/GKR RAM components do not match the replay reserve");
    }

    const payload::PayloadCheckpointReplayPlan admitted =
        payload::plan_payload_checkpoint_replay(problem, budgets);
    if (plan != admitted) {
        throw std::invalid_argument(
            "server storage admission requires the exact admitted replay "
            "plan");
    }

    const std::size_t reduction_count = problem.layers.size() - 1U;
    const bool planner_binds_consumer_artifacts =
        !budgets.post_replay_consumer_artifact_bytes_by_reduction.empty();
    if (planner_binds_consumer_artifacts &&
        budgets.post_replay_consumer_artifact_bytes_by_reduction.size() !=
            reduction_count) {
        throw std::invalid_argument(
            "server storage admission requires one planner-bound consumer "
            "artifact per reduction");
    }
    if (limits.reduction_workspaces.size() != reduction_count) {
        throw std::invalid_argument(
            "server storage admission requires one resident workspace per "
            "reduction");
    }

    std::size_t multiplication_count = 0;
    for (std::size_t layer = 0; layer < reduction_count; ++layer) {
        const auto &workspace = limits.reduction_workspaces[layer];
        const payload::LayerKind expected_kind = problem.layers[layer].kind;
        if (workspace.reduction_layer != layer ||
            workspace.kind != expected_kind) {
            throw std::invalid_argument(
                "reduction resident workspaces are not in circuit order");
        }
        if (expected_kind == payload::LayerKind::Affine) {
            if (planner_binds_consumer_artifacts &&
                budgets
                        .post_replay_consumer_artifact_bytes_by_reduction[
                            layer] != 0) {
                throw std::invalid_argument(
                    "affine reduction cannot declare a post-replay "
                    "consumer artifact");
            }
            if (workspace.multiplication_builder_phase_bytes != 0) {
                throw std::invalid_argument(
                    "affine reduction cannot declare multiplication "
                    "builder workspace");
            }
            continue;
        }
        if (expected_kind != payload::LayerKind::Multiplication) {
            throw std::logic_error(
                "admitted replay problem has an input reduction");
        }
        if (multiplication_count >=
            gkr_options.multiplication_scratch.size()) {
            throw std::invalid_argument(
                "server storage admission requires one scratch bound per "
                "multiplication layer");
        }
        const auto &scratch =
            gkr_options.multiplication_scratch[multiplication_count];
        if (scratch.reduction_layer != layer) {
            throw std::invalid_argument(
                "multiplication scratch bounds are not in circuit order");
        }
        validate_scratch_limits(scratch.storage_limits);
        if (planner_binds_consumer_artifacts &&
            budgets.post_replay_consumer_artifact_bytes_by_reduction[
                layer] != scratch.storage_limits.max_total_bytes) {
            throw std::invalid_argument(
                "planner-bound consumer artifact does not match the "
                "multiplication scratch bound");
        }
        ++multiplication_count;
    }
    if (multiplication_count !=
        gkr_options.multiplication_scratch.size()) {
        throw std::invalid_argument(
            "server storage admission requires one scratch bound per "
            "multiplication layer");
    }

    CheckpointReplayServerStorageAdmission result;
    result.payload_gkr_reserve = payload_gkr_reserve;
    result.replay_peak = phase_peak(
        ServerResourcePair{
            std::max(plan.selected.peak_live_scratch_bytes,
                     limits.payload_execution_peak.local_disk_bytes),
            std::max(plan.selected.peak_resident_bytes,
                     limits.payload_execution_peak.resident_ram_bytes)},
        "checkpoint replay paired peak");
    require_within_caps(result.replay_peak, limits.caps,
                        "checkpoint replay peak");
    update_maxima(result, result.replay_peak);

    const ServerResourcePair packing_resources = checked_add(
        limits.common, limits.transcript_packing_only,
        "common and transcript-packing resources");
    result.transcript_packing_peak = phase_peak(
        packing_resources, "transcript-packing paired peak");
    require_within_caps(result.transcript_packing_peak, limits.caps,
                        "transcript-packing peak");
    update_maxima(result, result.transcript_packing_peak);

    result.reduction_peaks.reserve(reduction_count);
    std::size_t multiplication_index = 0;
    for (std::size_t layer = 0; layer < reduction_count; ++layer) {
        const payload::PayloadReplaySegment &segment =
            plan.reverse_gkr_segments.at(layer);
        if (segment.reduction_layer != layer ||
            segment.required_source_layer != layer + 1U) {
            throw std::logic_error(
                "admitted replay segment order is inconsistent");
        }
        const auto &workspace = limits.reduction_workspaces[layer];
        const payload::LayerKind kind = problem.layers[layer].kind;
        const std::uint64_t transient_source =
            segment.checkpoint_layer == segment.required_source_layer
                ? 0
                : problem.layers[segment.required_source_layer]
                      .checkpoint_bytes;

        std::uint64_t post_replay_disk = checked_add(
            checked_add(payload_gkr_reserve.local_disk_bytes,
                        segment.artifact_peak.live_checkpoint_bytes,
                        "reduction checkpoint bytes"),
            transient_source, "reduction transient source bytes");
        std::uint64_t multiplication_artifact = 0;
        if (kind == payload::LayerKind::Multiplication) {
            multiplication_artifact =
                gkr_options.multiplication_scratch[multiplication_index]
                    .storage_limits.max_total_bytes;
            post_replay_disk = checked_add(
                post_replay_disk, multiplication_artifact,
                "multiplication edge artifact bytes");
            ++multiplication_index;
        }
        if (planner_binds_consumer_artifacts) {
            if (segment.post_replay_consumer_artifact_bytes !=
                    multiplication_artifact ||
                segment.post_replay_consumer_peak_live_scratch_bytes !=
                    post_replay_disk) {
                throw std::logic_error(
                    "planner post-replay consumer envelope drifted");
            }
        }
        std::uint64_t disk_peak = std::max(
            segment.artifact_peak.peak_live_scratch_bytes,
            post_replay_disk);
        if (limits.payload_execution_peak.local_disk_bytes != 0) {
            disk_peak = std::max(
                disk_peak,
                checked_add(limits.payload_execution_peak.local_disk_bytes,
                            multiplication_artifact,
                            "retained payload and multiplication artifacts"));
        }

        const std::uint64_t builder_ram = checked_add(
            payload_gkr_reserve.resident_ram_bytes,
            workspace.multiplication_builder_phase_bytes,
            "multiplication builder resident bytes");
        const std::uint64_t reduction_ram = checked_add(
            payload_gkr_reserve.resident_ram_bytes,
            workspace.reduction_phase_bytes,
            "streamed reduction resident bytes");
        std::uint64_t ram_peak = std::max(
            segment.peak_resident_bytes, reduction_ram);
        if (kind == payload::LayerKind::Multiplication) {
            ram_peak = std::max(ram_peak, builder_ram);
        }

        const CheckpointReplayServerPhasePeak peak = phase_peak(
            ServerResourcePair{disk_peak, ram_peak},
            "replay and reduction paired peak");
        require_within_caps(peak, limits.caps,
                            "replay and reduction peak");
        result.reduction_peaks.push_back(
            CheckpointReplayReductionStoragePeak{
                .reduction_layer = layer,
                .kind = kind,
                .required_source_layer = segment.required_source_layer,
                .checkpoint_layer = segment.checkpoint_layer,
                .payload_gkr_disk_reserve_bytes =
                    payload_gkr_reserve.local_disk_bytes,
                .live_checkpoint_bytes =
                    segment.artifact_peak.live_checkpoint_bytes,
                .transient_source_bytes = transient_source,
                .multiplication_source_artifact_bytes =
                    multiplication_artifact,
                .replay_peak_local_disk_bytes =
                    segment.artifact_peak.peak_live_scratch_bytes,
                .post_replay_local_disk_bytes = post_replay_disk,
                .replay_peak_resident_bytes =
                    segment.peak_resident_bytes,
                .payload_gkr_ram_reserve_bytes =
                    payload_gkr_reserve.resident_ram_bytes,
                .multiplication_builder_phase_bytes =
                    workspace.multiplication_builder_phase_bytes,
                .reduction_phase_bytes =
                    workspace.reduction_phase_bytes,
                .peak = peak,
            });
        update_maxima(result, peak);
    }

    return result;
}

CheckpointReplayServerStorageAdmission
admit_checkpoint_replay_server_storage(
    const payload::PayloadCheckpointReplayProblem &problem,
    const payload::PayloadCheckpointReplayBudgets &budgets,
    const payload::PayloadCheckpointReplayPlan &plan,
    const gkr::laned_detail::FileLanedGkrOptions &gkr_options,
    bool reclaim_completed_multiplication_scratch,
    const CheckpointReplayServerStorageLimits &limits) {
    return admit_checkpoint_replay_server_storage_impl(
        problem, budgets, plan, gkr_options,
        reclaim_completed_multiplication_scratch, limits);
}

CheckpointReplayServerStorageAdmission
admit_checkpoint_replay_server_storage(
    const payload::PayloadCheckpointReplayProblem &problem,
    const payload::PayloadCheckpointReplayBudgets &budgets,
    const payload::PayloadCheckpointReplayPlan &plan,
    const gkr::folded_detail::FileFoldedGkrOptions &gkr_options,
    bool reclaim_completed_multiplication_scratch,
    const CheckpointReplayServerStorageLimits &limits) {
    return admit_checkpoint_replay_server_storage_impl(
        problem, budgets, plan, gkr_options,
        reclaim_completed_multiplication_scratch, limits);
}

} // namespace laminate::protocol
