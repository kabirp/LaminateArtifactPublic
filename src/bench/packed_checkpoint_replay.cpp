/// @file packed_checkpoint_replay.cpp
/// @brief Formula-only replay resources for Folded/Laned process profiles.

#include "laminate/bench/packed_checkpoint_replay.hpp"

#include "laminate/gkr/detail/laned/affine/source/chunk_batches.hpp"
#include "laminate/payload/evaluation/fhe_evaluation_plan.hpp"
#include "laminate/payload/trace/trace_wire_support.hpp"

#include <algorithm>
#include <limits>
#include <stdexcept>
#include <string>
#include <utility>

namespace laminate::bench {

payload::PayloadCheckpointReplayProblem
make_packed_checkpoint_replay_problem(
    const payload::CertifiedCanonicalTraceLayout &trace_layout,
    const payload::FheEvaluationPlan &evaluation,
    const PackedCheckpointReplayResourceBounds &bounds) {
    const payload::LayeredCircuit &circuit = trace_layout.circuit();
    evaluation.validate(circuit);
    if (bounds.serialized_ciphertext_bytes_by_rns_limb.empty() ||
        bounds.resident_ciphertext_bytes_by_rns_limb.size() !=
            bounds.serialized_ciphertext_bytes_by_rns_limb.size()) {
        throw std::invalid_argument(
            "packed checkpoint replay requires matching nonempty "
            "ciphertext bounds");
    }

    const std::vector<std::uint64_t> work =
        payload::payload_replay_work_units(trace_layout);
    std::vector<payload::PayloadLayerResourceEstimate> resources;
    resources.reserve(circuit.layers.size());
    for (std::size_t layer = 0; layer < circuit.layers.size(); ++layer) {
        const std::size_t limbs =
            evaluation.trace.required_mult_depth_by_layer.at(layer) + 1U;
        const std::size_t proof_limbs =
            evaluation.proof_ingress_mult_depth_by_layer.at(layer) + 1U;
        if (limbs > bounds.serialized_ciphertext_bytes_by_rns_limb.size() ||
            proof_limbs >
                bounds.serialized_ciphertext_bytes_by_rns_limb.size()) {
            throw std::invalid_argument(
                "packed checkpoint replay ciphertext bounds omit an RNS "
                "level");
        }
        const std::uint64_t serialized =
            bounds.serialized_ciphertext_bytes_by_rns_limb.at(limbs - 1U);
        const std::uint64_t resident =
            bounds.resident_ciphertext_bytes_by_rns_limb.at(limbs - 1U);
        resources.push_back({
            .rns_limb_count = limbs,
            .checkpoint_bytes =
                payload::standalone_checkpoint_layer_artifact_bytes(
                    trace_layout.layout()
                        .storage.at(layer)
                        .stored_wire_count,
                    serialized),
            .serialized_ciphertext_bytes = serialized,
            .resident_ciphertext_bytes = resident,
            .replay_work_units = work.at(layer),
            .prefer_post_modulus_switch_checkpoint =
                layer != 0 &&
                evaluation.modulus_switches_after_layer.at(layer) != 0,
            .proof_ingress_serialized_ciphertext_bytes =
                bounds.serialized_ciphertext_bytes_by_rns_limb.at(
                    proof_limbs - 1U),
            .proof_ingress_resident_ciphertext_bytes =
                bounds.resident_ciphertext_bytes_by_rns_limb.at(
                    proof_limbs - 1U),
        });
    }
    payload::PayloadCheckpointReplayProblem problem =
        payload::make_payload_checkpoint_replay_problem(
            trace_layout, evaluation, resources,
            bounds.checkpoint_set_fixed_bytes,
            bounds.checkpoint_set_bytes_per_layer);
    payload::validate_executable_checkpoint_artifact_accounting(problem);
    return problem;
}

namespace {

std::uint64_t checked_add(std::uint64_t left, std::uint64_t right,
                          const char *label) {
    if (right > std::numeric_limits<std::uint64_t>::max() - left) {
        throw std::overflow_error(std::string(label) + " overflows");
    }
    return left + right;
}

std::uint64_t checked_multiply(std::uint64_t left, std::uint64_t right,
                               const char *label) {
    if (left != 0 &&
        right > std::numeric_limits<std::uint64_t>::max() / left) {
        throw std::overflow_error(std::string(label) + " overflows");
    }
    return left * right;
}

bool within_recomputation_limit(
    const payload::PayloadCheckpointStorageProfile &profile,
    payload::PayloadRecomputationFactorLimit limit) {
    if (profile.initial_forward_work_units == 0 || limit.denominator == 0) {
        return false;
    }
    const __uint128_t work =
        static_cast<__uint128_t>(profile.cumulative_work_units) *
        limit.denominator;
    const __uint128_t bound =
        static_cast<__uint128_t>(profile.initial_forward_work_units) *
        limit.numerator;
    return work <= bound;
}

} // namespace

std::uint64_t laned_affine_reduction_workspace_bytes(
    std::size_t slots, std::size_t lanes,
    const payload::PayloadCheckpointReplayProblem &problem) {
    if (lanes == 0 || slots == 0 || slots % lanes != 0) {
        throw std::invalid_argument(
            "Laned affine workspace requires valid lane geometry");
    }
    const std::uint64_t resident_ciphertexts =
        gkr::laned_detail::affine_detail::
            laned_affine_peak_resident_ciphertexts(slots / lanes);
    std::uint64_t result = 0;
    for (std::size_t reduction = 0;
         reduction + 1U < problem.layers.size(); ++reduction) {
        if (problem.layers[reduction].kind != payload::LayerKind::Affine) {
            continue;
        }
        const payload::PayloadReplayLayer &source =
            problem.layers[reduction + 1U];
        const std::uint64_t ciphertext_bytes =
            source.proof_ingress_resident_ciphertext_bytes == 0
                ? source.resident_ciphertext_bytes
                : source.proof_ingress_resident_ciphertext_bytes;
        result = std::max(
            result,
            checked_multiply(resident_ciphertexts, ciphertext_bytes,
                             "bounded Laned affine workspace"));
    }
    if (result == 0) {
        throw std::invalid_argument(
            "Laned affine workspace found no affine reduction");
    }
    return result;
}

PackedAdaptiveStoragePreflight plan_packed_adaptive_storage_preflight(
    const payload::PayloadCheckpointReplayProblem &problem,
    std::span<const std::uint64_t>
        multiplication_scratch_bytes_by_reduction,
    const HostResourceBudget &host_budget,
    std::uint64_t conservative_client_private_persistent_bytes,
    std::uint64_t conservative_client_peak_resident_bytes,
    std::uint64_t additional_server_disk_reserve_bytes,
    std::uint64_t server_resident_reserve_bytes) {
    if (problem.layers.empty() ||
        multiplication_scratch_bytes_by_reduction.size() !=
        problem.layers.size() - 1U) {
        throw std::invalid_argument(
            "packed planner preflight requires one multiplication scratch "
            "bound per reduction");
    }
    if (derive_host_resource_budget(
            host_budget.observed_available_disk_bytes,
            host_budget.observed_physical_ram_bytes) != host_budget) {
        throw std::invalid_argument(
            "packed planner preflight received a noncanonical host budget");
    }
    if (conservative_client_private_persistent_bytes == 0) {
        throw std::invalid_argument(
            "packed planner preflight requires a client-private persistence "
            "reserve");
    }
    const std::uint64_t max_server_live_disk_bytes =
        reserve_role_private_disk(
            host_budget,
            conservative_client_private_persistent_bytes);
    const std::uint64_t max_server_resident_bytes =
        reserve_concurrent_client_ram(
            host_budget, conservative_client_peak_resident_bytes);

    payload::PayloadCheckpointReplayBudgets budgets{
        .max_live_scratch_bytes = max_server_live_disk_bytes,
        .max_resident_ciphertext_bytes =
            max_server_resident_bytes,
        .max_ciphertexts_per_chunk =
            kPackedAdaptiveReplayChunkCiphertexts,
        .max_recomputation_factor = kPackedAdaptiveMaximumRecomputation,
        .reserved_live_scratch_bytes = checked_add(
            kPackedAdaptiveServerCommonDiskReserveBytes,
            additional_server_disk_reserve_bytes, "additional server disk reserve"),
        // Charge every server-resident term already known to the caller.
        // The final setup adds the exact materialized context/static sizes.
        .reserved_resident_bytes = server_resident_reserve_bytes,
        .selection_objective =
            payload::PayloadCheckpointSelectionObjective::MinimumReplayWork,
        .post_replay_consumer_artifact_bytes_by_reduction =
            std::vector<std::uint64_t>(
                multiplication_scratch_bytes_by_reduction.begin(),
                multiplication_scratch_bytes_by_reduction.end()),
    };
    payload::PayloadCheckpointReplayPlan replay =
        payload::plan_payload_checkpoint_replay(problem, budgets);
    if (!replay.selected.feasible() ||
        !within_recomputation_limit(replay.selected,
                                    kPackedAdaptiveMaximumRecomputation)) {
        throw std::logic_error(
            "packed planner preflight selected an infeasible replay plan");
    }
    const std::uint64_t gross_live_and_free = checked_add(
        checked_add(max_server_live_disk_bytes,
                    conservative_client_private_persistent_bytes,
                    "packed whole-filesystem live budget"),
        kPackedAdaptiveMinFreeDiskBytes,
        "packed required available disk");
    if (gross_live_and_free !=
        host_budget.observed_available_disk_bytes) {
        throw std::logic_error(
            "packed whole-filesystem budget does not reconstruct "
            "the host observation");
    }
    return {
        .host_budget = host_budget,
        .conservative_client_private_persistent_bytes =
            conservative_client_private_persistent_bytes,
        .conservative_client_peak_resident_bytes =
            conservative_client_peak_resident_bytes,
        .replay_budgets = std::move(budgets),
        .replay = std::move(replay),
        .required_available_disk_bytes = gross_live_and_free,
        .additional_server_disk_reserve_bytes = additional_server_disk_reserve_bytes,
    };
}

void require_packed_adaptive_storage_refinement(
    const PackedAdaptiveStoragePreflight &preflight,
    std::uint64_t exact_client_private_persistent_bytes,
    std::uint64_t exact_client_peak_resident_bytes,
    const payload::PayloadCheckpointReplayBudgets &exact_budgets,
    const payload::PayloadCheckpointReplayPlan &exact_replay) {
    const std::uint64_t preflight_server_live_disk_bytes =
        reserve_role_private_disk(
            preflight.host_budget,
            preflight.conservative_client_private_persistent_bytes);
    const std::uint64_t preflight_server_resident_bytes =
        reserve_concurrent_client_ram(
            preflight.host_budget,
            preflight.conservative_client_peak_resident_bytes);
    if (derive_host_resource_budget(
            preflight.host_budget.observed_available_disk_bytes,
            preflight.host_budget.observed_physical_ram_bytes) !=
            preflight.host_budget ||
        preflight.conservative_client_private_persistent_bytes == 0 ||
        preflight.replay_budgets.max_live_scratch_bytes !=
            preflight_server_live_disk_bytes ||
        preflight.replay_budgets.max_resident_ciphertext_bytes !=
            preflight_server_resident_bytes ||
        preflight.replay_budgets.reserved_live_scratch_bytes !=
            checked_add(kPackedAdaptiveServerCommonDiskReserveBytes,
                preflight.additional_server_disk_reserve_bytes,
                "bound additional server disk reserve") ||
        preflight.required_available_disk_bytes !=
            checked_add(
                checked_add(
                    preflight_server_live_disk_bytes,
                    preflight.conservative_client_private_persistent_bytes,
                    "packed whole-filesystem live budget"),
                kPackedAdaptiveMinFreeDiskBytes,
                "packed required available disk") ||
        preflight.required_available_disk_bytes !=
            preflight.host_budget.observed_available_disk_bytes ||
        !preflight.replay.selected.feasible()) {
        throw std::invalid_argument(
            "packed planner preflight does not use its bound host "
            "budget");
    }
    if (exact_client_private_persistent_bytes == 0 ||
        exact_client_private_persistent_bytes >
            preflight.conservative_client_private_persistent_bytes) {
        throw std::invalid_argument(
            "exact packed client-private persistence exceeds its early "
            "reserve");
    }
    if (exact_client_peak_resident_bytes == 0 ||
        exact_client_peak_resident_bytes >
            preflight.conservative_client_peak_resident_bytes) {
        throw std::invalid_argument(
            "exact packed client resident peak exceeds its early reserve");
    }
    const std::uint64_t exact_server_live_disk_bytes =
        reserve_role_private_disk(
            preflight.host_budget,
            exact_client_private_persistent_bytes);
    const std::uint64_t exact_server_resident_bytes =
        reserve_concurrent_client_ram(
            preflight.host_budget, exact_client_peak_resident_bytes);
    if (exact_budgets.max_live_scratch_bytes !=
            exact_server_live_disk_bytes ||
        exact_budgets.max_resident_ciphertext_bytes !=
            exact_server_resident_bytes ||
        exact_budgets.max_ciphertexts_per_chunk !=
            kPackedAdaptiveReplayChunkCiphertexts ||
        exact_budgets.max_recomputation_factor !=
            kPackedAdaptiveMaximumRecomputation ||
        exact_budgets.selection_objective !=
            payload::PayloadCheckpointSelectionObjective::MinimumReplayWork ||
        exact_budgets
                .post_replay_consumer_artifact_bytes_by_reduction !=
            preflight.replay_budgets
                .post_replay_consumer_artifact_bytes_by_reduction ||
        exact_budgets.reserved_live_scratch_bytes >
            preflight.replay_budgets.reserved_live_scratch_bytes ||
        !exact_replay.selected.feasible() ||
        exact_replay.selected.peak_live_scratch_bytes >
            exact_server_live_disk_bytes ||
        checked_add(exact_replay.selected.peak_live_scratch_bytes,
                    exact_client_private_persistent_bytes,
                    "exact packed whole-filesystem live peak") >
            preflight.host_budget.max_live_disk_bytes ||
        exact_replay.selected.peak_resident_bytes >
            exact_server_resident_bytes ||
        !within_recomputation_limit(exact_replay.selected,
                                    kPackedAdaptiveMaximumRecomputation) ||
        exact_replay.selected.initial_forward_work_units !=
            preflight.replay.selected.initial_forward_work_units ||
        exact_replay.selected.cumulative_work_units >
            preflight.replay.selected.cumulative_work_units) {
        throw std::invalid_argument(
            "exact packed replay admission exceeds its early "
            "storage envelope");
    }
}

} // namespace laminate::bench
