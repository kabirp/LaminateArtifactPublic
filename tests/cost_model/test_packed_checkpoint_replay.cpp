/// @file test_packed_checkpoint_replay.cpp
/// @brief Packed process replay-formula regressions.

#include "test_helpers.hpp"

#include "laminate/bench/packed_checkpoint_replay.hpp"
#include "laminate/bench/packed_process_profile.hpp"
#include "laminate/gkr/detail/shared/dense_multiplication/source/disk_bounds.hpp"
#include "laminate/gkr/detail/shared/dense_multiplication/source/plan.hpp"
#include "laminate/payload/checkpoint/session_engine.hpp"
#include "laminate/payload/compiler.hpp"
#include "laminate/payload/laned_fhe_evaluator.hpp"
#include "laminate/payload/trace/trace_wire_support.hpp"
#include "laminate/payload/fixtures/workloads.hpp"
#include "laminate/protocol/packed/setup/proof_ingress.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <utility>
#include <vector>

using namespace laminate;
using namespace laminate::bench;
using namespace laminate::payload;
using laminate::test::Runner;

namespace {

constexpr std::uint64_t kConservativeClientPrivateBytes =
    64'000'000'000ULL;
constexpr std::uint64_t kExactClientPrivateBytes =
    32'000'000'000ULL;
constexpr std::uint64_t kConservativeClientResidentBytes =
    24'000'000'000ULL;
constexpr std::uint64_t kExactClientResidentBytes =
    16'000'000'000ULL;

bool rejects_executable_artifact_accounting(
    const PayloadCheckpointReplayProblem &problem) {
    try {
        validate_executable_checkpoint_artifact_accounting(problem);
    } catch (const std::invalid_argument &) {
        return true;
    }
    return false;
}

struct ExactTargetStorageFixture {
    PayloadCheckpointReplayProblem problem;
    std::vector<std::uint64_t> multiplication_scratch;
};

ExactTargetStorageFixture exact_target_storage_fixture(
    PackedProcessVariant variant, std::size_t lanes,
    PackedProcessTier tier = PackedProcessTier::TargetBalanced) {
    const PackedProcessProfile profile = packed_process_profile(
        variant, tier, lanes);
    const PayloadShape shape =
        variant == PackedProcessVariant::Folded
            ? PayloadShape::wide(profile.slots)
            : PayloadShape::laned(lanes, profile.slots);
    PayloadCircuit payload = make_payload_circuit(
        benchmark_payload_workload_spec(
            benchmark_payload_profile(profile.tier), shape));
    LayeredCircuit circuit = compile(payload);

    const auto ingress = protocol::derive_conservative_packed_proof_ingress_schedule(
        variant == PackedProcessVariant::Folded
            ? protocol::PackingGkrVariant::Folded : protocol::PackingGkrVariant::Laned,
        payload, circuit, make_direct_setup(payload, circuit),
        packed_process_proof_ingress_policy(profile));
    std::vector<std::size_t> proof_depths;
    for (const auto limbs : ingress.rns_limbs_by_layer())
        proof_depths.push_back(limbs - 1U);
    const FheEvaluationPlan evaluation =
        packed_process_evaluation_plan(profile, circuit, proof_depths);
    if (packed_process_uses_folded_pyramid_headroom(profile)) {
        CHECK(ingress.policy() == protocol::kConservativePackedProofIngressPolicyV4);
        CHECK(evaluation.proof_ingress_mult_depth_by_layer ==
              (std::vector<std::size_t>{0,3,5,3,5,3,5,3,5,3,5,3,5,3,5,3,5,3}));
        CHECK(evaluation.trace.required_mult_depth_by_layer ==
              (std::vector<std::size_t>{0,3,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13}));
        CHECK(evaluation.modulus_switches_after_layer ==
              (std::vector<std::size_t>{3,3,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,0}));
    } else {
        const std::size_t extra = tier == PackedProcessTier::Quick ? 0U : 1U;
        const auto previous_evaluation = FheEvaluationPlan::packed_payload_with_prompt_switches(
            circuit, profile.fresh_rns_limbs() - 1U - extra, proof_depths);
        CHECK(evaluation.proof_ingress_mult_depth_by_layer ==
              previous_evaluation.proof_ingress_mult_depth_by_layer);
        for (std::size_t source = 1; source < circuit.layers.size(); ++source) {
            CHECK(evaluation.trace.required_mult_depth_by_layer[source] ==
                  previous_evaluation.trace.required_mult_depth_by_layer[source] + extra);
        }
    }

    PackedCheckpointReplayResourceBounds resources;
    resources.checkpoint_set_fixed_bytes = 159;
    resources.checkpoint_set_bytes_per_layer = 8;
    for (std::size_t limbs = 1; limbs <= profile.fresh_rns_limbs(); ++limbs) {
        const std::uint64_t raw =
            2ULL * profile.slots * limbs * sizeof(std::uint64_t);
        resources.serialized_ciphertext_bytes_by_rns_limb.push_back(
            raw + (64ULL << 10U));
        resources.resident_ciphertext_bytes_by_rns_limb.push_back(
            raw + (128ULL << 10U));
    }
    const CertifiedCanonicalTraceLayout trace =
        derive_certified_canonical_trace_layout(circuit);
    PayloadCheckpointReplayProblem problem =
        make_packed_checkpoint_replay_problem(trace, evaluation, resources);

    std::vector<std::uint64_t> scratch(problem.layers.size() - 1U, 0);
    for (std::size_t layer = 0; layer + 1U < circuit.layers.size(); ++layer) {
        if (layer_kind(circuit.layers[layer]) != LayerKind::Multiplication) {
            continue;
        }
        const auto aliases = gkr::detail::make_dense_multiplication_alias_plan(
            circuit, layer, trace.layout().wire_support.at(layer + 1U),
            trace.layout().storage.at(layer + 1U));
        const PayloadReplayLayer &source = problem.layers.at(layer + 1U);
        const auto bounds =
            gkr::detail::file_dense_multiplication_source_disk_bounds(
                aliases.operands.size(),
                source.proof_ingress_serialized_ciphertext_bytes,
                true);
        scratch[layer] = bounds.build_peak_bytes;
    }
    return {std::move(problem), std::move(scratch)};
}

void check_adaptive_storage_preflight(PackedProcessVariant variant,
                                      std::size_t lanes,
                                      PackedProcessTier tier =
                                          PackedProcessTier::TargetBalanced) {
    const ExactTargetStorageFixture fixture =
        exact_target_storage_fixture(variant, lanes, tier);
    const PackedAdaptiveStoragePreflight preflight =
        plan_packed_adaptive_storage_preflight(
            fixture.problem, fixture.multiplication_scratch,
            derive_host_resource_budget(3'100'000'000'000ULL,
                                          256'000'000'000ULL),
            kConservativeClientPrivateBytes,
            kConservativeClientResidentBytes);
    CHECK(preflight.replay_budgets.max_live_scratch_bytes ==
          2'936'000'000'000ULL);
    CHECK(preflight.replay_budgets.reserved_live_scratch_bytes ==
          128'000'000'000ULL);
    CHECK(preflight.replay_budgets.max_resident_ciphertext_bytes ==
          152'000'000'000ULL);
    CHECK(preflight.required_available_disk_bytes ==
          3'100'000'000'000ULL);
    CHECK(preflight.replay.full_trace_reference.peak_live_scratch_bytes >
          preflight.host_budget.max_live_disk_bytes);
    CHECK(preflight.replay.selected.feasible());
    CHECK(preflight.replay.selected.peak_live_scratch_bytes <=
          preflight.replay_budgets.max_live_scratch_bytes);
    CHECK(!preflight.replay.selected.checkpoint_layers.empty());
    CHECK(preflight.replay.selected.initial_forward_work_units > 0);
    CHECK(static_cast<unsigned __int128>(
              preflight.replay.selected.cumulative_work_units) *
              kPackedAdaptiveMaximumRecomputation.denominator <=
          static_cast<unsigned __int128>(
              preflight.replay.selected.initial_forward_work_units) *
              kPackedAdaptiveMaximumRecomputation.numerator);

    // Exact setup normally needs less than both deliberately conservative
    // persistence reserves. It may spend that released disk on more
    // checkpoints, but its replay work and fixed resource caps must refine
    // the early admission.
    PayloadCheckpointReplayBudgets exact_budgets =
        preflight.replay_budgets;
    exact_budgets.max_live_scratch_bytes =
        reserve_role_private_disk(preflight.host_budget,
                                         kExactClientPrivateBytes);
    exact_budgets.max_resident_ciphertext_bytes =
        reserve_concurrent_client_ram(
            preflight.host_budget, kExactClientResidentBytes);
    exact_budgets.reserved_live_scratch_bytes = 64'000'000'000ULL;
    const PayloadCheckpointReplayPlan exact =
        plan_payload_checkpoint_replay(fixture.problem, exact_budgets);
    require_packed_adaptive_storage_refinement(
        preflight, kExactClientPrivateBytes, kExactClientResidentBytes,
        exact_budgets, exact);
}

void check_mulheavy_nine_tb_has_zero_replay(
    PackedProcessVariant variant, std::size_t lanes) {
    constexpr std::uint64_t kAvailableDiskBytes =
        9'000'000'000'000ULL;
    const ExactTargetStorageFixture fixture = exact_target_storage_fixture(
        variant, lanes, PackedProcessTier::TargetMulHeavy);
    const PackedAdaptiveStoragePreflight preflight =
        plan_packed_adaptive_storage_preflight(
            fixture.problem, fixture.multiplication_scratch,
            derive_host_resource_budget(kAvailableDiskBytes,
                                          256'000'000'000ULL),
            kConservativeClientPrivateBytes,
            kConservativeClientResidentBytes);

    CHECK(preflight.replay_budgets.max_live_scratch_bytes ==
          8'836'000'000'000ULL);
    CHECK(preflight.required_available_disk_bytes ==
          kAvailableDiskBytes);
    CHECK(preflight.replay.full_trace_reference.feasible());
    CHECK(preflight.replay.selected.feasible());
    // Retaining the added target payload limb raises the full trace to
    // about 6.44 TB; it still fits without replay on the selected 9 TB host.
    CHECK(preflight.replay.full_trace_reference.peak_live_scratch_bytes <
          6'500'000'000'000ULL);
    CHECK(preflight.replay.selected.peak_live_scratch_bytes <
          6'500'000'000'000ULL);
    CHECK(preflight.replay.selected.replay_work_units == 0);
    CHECK(preflight.replay.selected.cumulative_work_units ==
          preflight.replay.selected.initial_forward_work_units);
    CHECK(preflight.replay.selected.checkpoint_layers.size() + 1U ==
          fixture.problem.layers.size());
    for (std::size_t layer = 1; layer < fixture.problem.layers.size();
         ++layer) {
        CHECK(preflight.replay.selected.checkpoint_layers[layer - 1U] ==
              layer);
    }
}

void check_adaptive_target_replay_budget() {
    const ExactTargetStorageFixture fixture = exact_target_storage_fixture(
        PackedProcessVariant::Folded, 0);
    const HostResourceBudget smaller_budget =
        derive_host_resource_budget(2'300'000'000'000ULL,
                                      256'000'000'000ULL);
    const HostResourceBudget larger_budget =
        derive_host_resource_budget(3'100'000'000'000ULL,
                                      256'000'000'000ULL);
    const PackedAdaptiveStoragePreflight smaller =
        plan_packed_adaptive_storage_preflight(
            fixture.problem, fixture.multiplication_scratch,
            smaller_budget, kConservativeClientPrivateBytes,
            kConservativeClientResidentBytes);
    const PackedAdaptiveStoragePreflight larger =
        plan_packed_adaptive_storage_preflight(
            fixture.problem, fixture.multiplication_scratch,
            larger_budget, kConservativeClientPrivateBytes,
            kConservativeClientResidentBytes);

    CHECK(smaller.replay.selected.feasible());
    CHECK(larger.replay.selected.feasible());
    CHECK(smaller.replay_budgets.max_live_scratch_bytes ==
          2'136'000'000'000ULL);
    CHECK(larger.replay_budgets.max_live_scratch_bytes ==
          2'936'000'000'000ULL);
    CHECK(smaller.replay.selected.checkpoint_layers !=
          larger.replay.selected.checkpoint_layers);
    CHECK(larger.replay.selected.cumulative_work_units <
          smaller.replay.selected.cumulative_work_units);
}

void check_client_private_persistence_changes_replay_plan() {
    const ExactTargetStorageFixture fixture = exact_target_storage_fixture(
        PackedProcessVariant::Folded, 0);
    const HostResourceBudget budget = derive_host_resource_budget(
        2'300'000'000'000ULL, 256'000'000'000ULL);
    const PackedAdaptiveStoragePreflight small_client =
        plan_packed_adaptive_storage_preflight(
            fixture.problem, fixture.multiplication_scratch, budget,
            32'000'000'000ULL, kConservativeClientResidentBytes);
    const PackedAdaptiveStoragePreflight large_client =
        plan_packed_adaptive_storage_preflight(
            fixture.problem, fixture.multiplication_scratch, budget,
            400'000'000'000ULL, kConservativeClientResidentBytes);

    CHECK(small_client.replay.selected.feasible());
    CHECK(large_client.replay.selected.feasible());
    CHECK(small_client.replay_budgets.max_live_scratch_bytes ==
          2'168'000'000'000ULL);
    CHECK(large_client.replay_budgets.max_live_scratch_bytes ==
          1'800'000'000'000ULL);
    CHECK(large_client.replay.selected.cumulative_work_units >
          small_client.replay.selected.cumulative_work_units);
    CHECK(large_client.replay.selected.peak_live_scratch_bytes +
              large_client.conservative_client_private_persistent_bytes <=
          budget.max_live_disk_bytes);
    CHECK(large_client.replay_budgets.max_live_scratch_bytes +
              large_client.conservative_client_private_persistent_bytes +
              kPackedAdaptiveMinFreeDiskBytes ==
          budget.observed_available_disk_bytes);
    CHECK(small_client.replay_budgets.max_resident_ciphertext_bytes +
              small_client.conservative_client_peak_resident_bytes ==
          budget.max_resident_ram_bytes);

    bool rejected_underflow = false;
    try {
        (void)plan_packed_adaptive_storage_preflight(
            fixture.problem, fixture.multiplication_scratch, budget,
            budget.max_live_disk_bytes, kConservativeClientResidentBytes);
    } catch (const std::invalid_argument &) {
        rejected_underflow = true;
    }
    CHECK(rejected_underflow);

    PayloadCheckpointReplayBudgets exact_budgets =
        small_client.replay_budgets;
    const PayloadCheckpointReplayPlan exact =
        plan_payload_checkpoint_replay(fixture.problem, exact_budgets);
    bool rejected_exceeded_reserve = false;
    try {
        require_packed_adaptive_storage_refinement(
            small_client,
            small_client.conservative_client_private_persistent_bytes + 1U,
            kExactClientResidentBytes, exact_budgets, exact);
    } catch (const std::invalid_argument &) {
        rejected_exceeded_reserve = true;
    }
    CHECK(rejected_exceeded_reserve);

    PayloadCheckpointReplayBudgets exact_ram_budgets =
        small_client.replay_budgets;
    exact_ram_budgets.max_resident_ciphertext_bytes =
        reserve_concurrent_client_ram(
            budget, kExactClientResidentBytes);
    const PayloadCheckpointReplayPlan exact_ram =
        plan_payload_checkpoint_replay(fixture.problem,
                                       exact_ram_budgets);
    bool rejected_exceeded_ram_reserve = false;
    try {
        require_packed_adaptive_storage_refinement(
            small_client, kExactClientPrivateBytes,
            small_client.conservative_client_peak_resident_bytes + 1U,
            exact_ram_budgets, exact_ram);
    } catch (const std::invalid_argument &) {
        rejected_exceeded_ram_reserve = true;
    }
    CHECK(rejected_exceeded_ram_reserve);
}

bool rejects_host_budget(std::uint64_t disk, std::uint64_t ram) {
    try {
        (void)derive_host_resource_budget(disk, ram);
    } catch (const std::invalid_argument &) {
        return true;
    }
    return false;
}

void check_packed_replay_adapter(PayloadShape shape) {
    const Workload workload = make_workload(WorkloadSpec{
        .kind = WorkloadKind::Diamond,
        .shape = shape,
        .multiplicative_depth = 2,
        .width = 4,
        .seed = 1,
        .input_count = 4,
    });
    const LayeredCircuit circuit = compile(workload.circuit);
    std::vector<std::size_t> proof_ingress(circuit.layers.size(), 2U);
    proof_ingress.front() = 0;
    const FheEvaluationPlan evaluation =
        FheEvaluationPlan::packed_payload_with_prompt_switches(
            circuit, 6, proof_ingress);
    CHECK(evaluation.modulus_switches_after_layer.front() > 0);

    PackedCheckpointReplayResourceBounds bounds;
    bounds.checkpoint_set_fixed_bytes = 159;
    bounds.checkpoint_set_bytes_per_layer = 8;
    for (std::uint64_t limbs = 1; limbs <= 7; ++limbs) {
        bounds.serialized_ciphertext_bytes_by_rns_limb.push_back(
            1'024 * limbs);
        bounds.resident_ciphertext_bytes_by_rns_limb.push_back(
            2'048 * limbs);
    }
    const auto trace_layout = derive_certified_canonical_trace_layout(circuit);
    const PayloadCheckpointReplayProblem problem =
        make_packed_checkpoint_replay_problem(
            trace_layout, evaluation, bounds);
    CHECK(problem.checkpoint_set_fixed_bytes == 159);
    CHECK(problem.checkpoint_set_bytes_per_layer == 8);
    CHECK(!problem.layers.front().preferred_checkpoint);

    bool saw_preferred_source = false;
    const std::vector<std::uint64_t> work =
        payload_replay_work_units(trace_layout);
    CHECK(file_trace_manifest_bytes(1) == 296);
    for (std::size_t layer = 0; layer < problem.layers.size(); ++layer) {
        const std::size_t limbs =
            evaluation.trace.required_mult_depth_by_layer.at(layer) + 1U;
        const std::size_t proof_limbs =
            evaluation.proof_ingress_mult_depth_by_layer.at(layer) + 1U;
        CHECK(problem.layers.at(layer).rns_limb_count == limbs);
        CHECK(problem.layers.at(layer).serialized_ciphertext_bytes ==
              bounds.serialized_ciphertext_bytes_by_rns_limb.at(limbs - 1U));
        CHECK(problem.layers.at(layer).resident_ciphertext_bytes ==
              bounds.resident_ciphertext_bytes_by_rns_limb.at(limbs - 1U));
        CHECK(problem.layers.at(layer)
                  .proof_ingress_serialized_ciphertext_bytes ==
              bounds.serialized_ciphertext_bytes_by_rns_limb.at(
                  proof_limbs - 1U));
        CHECK(problem.layers.at(layer)
                  .proof_ingress_resident_ciphertext_bytes ==
              bounds.resident_ciphertext_bytes_by_rns_limb.at(
                  proof_limbs - 1U));
        CHECK(problem.layers.at(layer).replay_work_units == work.at(layer));
        const std::size_t stored =
            trace_layout.layout().storage.at(layer).stored_wire_count;
        const std::uint64_t serialized =
            bounds.serialized_ciphertext_bytes_by_rns_limb.at(limbs - 1U);
        CHECK(problem.layers.at(layer).checkpoint_bytes ==
              file_trace_layer_artifact_bytes(stored, serialized) +
                  file_trace_manifest_bytes(1));
        CHECK(problem.layers.at(layer).checkpoint_bytes ==
              standalone_checkpoint_layer_artifact_bytes(stored,
                                                         serialized));

        const bool expected =
            layer != 0 &&
            evaluation.modulus_switches_after_layer.at(layer) != 0;
        CHECK(problem.layers.at(layer).preferred_checkpoint == expected);
        saw_preferred_source = saw_preferred_source || expected;
    }
    CHECK(saw_preferred_source);

    const PayloadCheckpointReplayBudgets budgets{
        .max_live_scratch_bytes = std::uint64_t{1} << 30U,
        .max_resident_ciphertext_bytes = std::uint64_t{1} << 30U,
        .max_ciphertexts_per_chunk = 128,
        .max_recomputation_factor = {100, 1},
    };
    const PayloadCheckpointReplayPlan plan =
        plan_payload_checkpoint_replay(problem, budgets);
    CHECK(std::find(plan.selected.checkpoint_layers.begin(),
                    plan.selected.checkpoint_layers.end(),
                    std::size_t{0}) ==
          plan.selected.checkpoint_layers.end());
    const CertifiedPayloadCheckpointReplayStatic certified =
        certify_payload_checkpoint_replay_static(
            workload.circuit, trace_layout, evaluation, problem,
            budgets, plan);
    CHECK(certified.problem().layers.size() == circuit.layers.size());

    PayloadCheckpointReplayProblem malformed = problem;
    malformed.layers.at(0).checkpoint_bytes -=
        file_trace_manifest_bytes(1);
    CHECK(rejects_executable_artifact_accounting(malformed));
}

} // namespace

int main() {
    Runner runner("packed checkpoint replay formulas");
    runner.run("additional GateMLE disk is bound into early admission and refinement", [] {
        const auto fixture = exact_target_storage_fixture(
            PackedProcessVariant::Folded, 0, PackedProcessTier::Quick);
        constexpr std::uint64_t extra = 500'000'000'000ULL;
        auto preflight = plan_packed_adaptive_storage_preflight(
            fixture.problem, fixture.multiplication_scratch,
            derive_host_resource_budget(3'100'000'000'000ULL, 256'000'000'000ULL),
            kConservativeClientPrivateBytes, kConservativeClientResidentBytes, extra);
        CHECK(preflight.additional_server_disk_reserve_bytes == extra);
        CHECK(preflight.replay_budgets.reserved_live_scratch_bytes ==
              kPackedAdaptiveServerCommonDiskReserveBytes + extra);
        require_packed_adaptive_storage_refinement(preflight,
            kConservativeClientPrivateBytes, kConservativeClientResidentBytes,
            preflight.replay_budgets, preflight.replay);
        auto malformed = preflight;
        malformed.additional_server_disk_reserve_bytes = 0;
        bool rejected = false;
        try {
            require_packed_adaptive_storage_refinement(malformed,
                kConservativeClientPrivateBytes, kConservativeClientResidentBytes,
                preflight.replay_budgets, preflight.replay);
        } catch (const std::invalid_argument &) { rejected = true; }
        CHECK(rejected);
    });
    runner.run("early packed admission charges known server residency", [] {
        const auto fixture = exact_target_storage_fixture(
            PackedProcessVariant::Folded, 0, PackedProcessTier::Quick);
        const auto host = derive_host_resource_budget(
            3'100'000'000'000ULL, 256'000'000'000ULL);
        constexpr std::uint64_t reserve = 16'000'000'000ULL;
        const auto admitted = plan_packed_adaptive_storage_preflight(
            fixture.problem, fixture.multiplication_scratch, host,
            kConservativeClientPrivateBytes, kConservativeClientResidentBytes,
            0, reserve);
        CHECK(admitted.replay_budgets.reserved_resident_bytes == reserve);
        CHECK(admitted.replay.selected.peak_resident_bytes >= reserve);
        bool rejected = false;
        try {
            (void)plan_packed_adaptive_storage_preflight(
                fixture.problem, fixture.multiplication_scratch, host,
                kConservativeClientPrivateBytes, kConservativeClientResidentBytes,
                0, host.max_resident_ram_bytes);
        } catch (const std::exception &) { rejected = true; }
        CHECK(rejected);
    });
    runner.run("Folded adapter emits executable standalone checkpoints", [] {
        check_packed_replay_adapter(PayloadShape::wide(16));
    });
    runner.run("Laned adapter emits executable standalone checkpoints", [] {
        check_packed_replay_adapter(PayloadShape::laned(4, 16));
    });
    runner.run("Folded target fits its observed host budget", [] {
        check_adaptive_storage_preflight(PackedProcessVariant::Folded, 0);
    });
    runner.run("Laned B=1 target fits its observed host budget", [] {
        const ExactTargetStorageFixture fixture = exact_target_storage_fixture(
            PackedProcessVariant::Laned, 1);
        const std::uint64_t affine_workspace =
            laned_affine_reduction_workspace_bytes(
                kDefaultPolyModulusDegree, 1, fixture.problem);
        CHECK(affine_workspace > 1'000'000'000ULL);
        CHECK(affine_workspace < 2'000'000'000ULL);
        check_adaptive_storage_preflight(PackedProcessVariant::Laned, 1);
    });
    runner.run("Laned B=128 target fits its observed host budget", [] {
        check_adaptive_storage_preflight(PackedProcessVariant::Laned, 128);
    });
    runner.run("Laned B=16384 target fits its observed host budget",
               [] {
                   check_adaptive_storage_preflight(
                       PackedProcessVariant::Laned,
                       kDefaultPolyModulusDegree);
               });
    runner.run("multiplication-heavy Folded target has zero replay at 9 TB", [] {
        check_mulheavy_nine_tb_has_zero_replay(
            PackedProcessVariant::Folded, 0);
    });
    runner.run("target capacity selects the minimum-work plan that fits", [] {
        check_adaptive_target_replay_budget();
    });
    runner.run("client-private persistence consumes target checkpoint budget",
               [] {
                   check_client_private_persistence_changes_replay_plan();
               });
    runner.run("target RAM preserves its host safety reserve", [] {
        const HostResourceBudget constrained =
            derive_host_resource_budget(3'100'000'000'000ULL,
                                          160'000'000'000ULL);
        const HostResourceBudget large =
            derive_host_resource_budget(3'100'000'000'000ULL,
                                          256'000'000'000ULL);
        CHECK(constrained.max_resident_ram_bytes == 80'000'000'000ULL);
        CHECK(large.max_resident_ram_bytes == 176'000'000'000ULL);
        CHECK(reserve_concurrent_client_ram(
                  constrained, 20'000'000'000ULL) ==
              60'000'000'000ULL);
        CHECK(reserve_concurrent_client_ram(
                  large, 20'000'000'000ULL) ==
              156'000'000'000ULL);
        CHECK(rejects_host_budget(100'000'000'000ULL,
                                    256'000'000'000ULL));
        CHECK(rejects_host_budget(3'100'000'000'000ULL,
                                    80'000'000'000ULL));
    });
    return runner.summary();
}
