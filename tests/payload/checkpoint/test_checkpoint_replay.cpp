#include "test_helpers.hpp"

#include "laminate/bench/host_resource_budget.hpp"
#include "laminate/payload/checkpoint/plan.hpp"
#include "laminate/payload/compiler.hpp"
#include "laminate/payload/laned_fhe_evaluator.hpp"
#include "laminate/payload/fixtures/workloads.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <stdexcept>
#include <vector>

namespace {

using laminate::Fp;
using laminate::bench::derive_host_resource_budget;
using laminate::bench::kBenchmarkFreeDiskReserveBytes;
using laminate::bench::kBenchmarkHostRamSafetyReserveBytes;
using laminate::bench::reserve_concurrent_client_ram;
using laminate::bench::reserve_role_private_disk;
using laminate::fhe::SlotVector;
using laminate::payload::AffineGate;
using laminate::payload::AffineLayer;
using laminate::payload::AffineTerm;
using laminate::payload::CanonicalTraceLayout;
using laminate::payload::CertifiedCanonicalTraceLayout;
using laminate::payload::FheEvaluationPlan;
using laminate::payload::GateOrigin;
using laminate::payload::InputLayer;
using laminate::payload::LayerKind;
using laminate::payload::LayerDimensions;
using laminate::payload::LayeredCircuit;
using laminate::payload::PayloadCheckpointReplayBudgets;
using laminate::payload::PayloadCheckpointReplayProblem;
using laminate::payload::PayloadCheckpointSelectionObjective;
using laminate::payload::PayloadLayerResourceEstimate;
using laminate::payload::PayloadReplayLayer;
using laminate::payload::PayloadShape;
using laminate::payload::WorkloadKind;
using laminate::payload::WorkloadSpec;
using laminate::payload::file_trace_layer_artifact_bytes;
using laminate::payload::file_trace_manifest_bytes;
using laminate::payload::file_trace_manifest_fixed_bytes;
using laminate::payload::file_trace_manifest_layer_descriptor_bytes;
using laminate::payload::certify_canonical_trace_layout;
using laminate::payload::derive_certified_canonical_trace_layout;
using laminate::payload::make_payload_checkpoint_replay_problem;
using laminate::payload::make_workload;
using laminate::payload::payload_replay_work_units;
using laminate::payload::plan_payload_checkpoint_replay;
using laminate::payload::standalone_checkpoint_layer_artifact_bytes;

bool throws_invalid_argument(const auto &body) {
    try {
        body();
    } catch (const std::invalid_argument &) {
        return true;
    }
    return false;
}
bool throws_logic_error(const auto &body) {
    try {
        body();
    } catch (const std::logic_error &) {
        return true;
    }
    return false;
}

bool throws_overflow_error(const auto &body) {
    try {
        body();
    } catch (const std::overflow_error &) {
        return true;
    }
    return false;
}

void test_live_affine_contribution_work_units() {
    const LayerDimensions output_dimensions{
        .logical_size = 4,
        .padded_size = 8,
        .payload_size = 4,
        .forward_size = 0,
    };
    std::vector<AffineGate> output_gates{
        // Two live terms, one structural-padding term, one zero-coefficient
        // term, and one nonzero constant: three units.
        AffineGate{{AffineTerm{0, 0, Fp::one()},
                    AffineTerm{1, 0, Fp(2)},
                    AffineTerm{3, 0, Fp(9)},
                    AffineTerm{2, 0, Fp::zero()}},
                   Fp(7), GateOrigin::Payload},
        // A semantically live public zero performs no FHE operation.
        AffineGate{{}, Fp::zero(), GateOrigin::Payload},
        // Depending only on structural padding also remains public zero.
        AffineGate{{AffineTerm{3, 0, Fp::one()}}, Fp::zero(),
                   GateOrigin::Payload},
        // A constant-only vector remains public and performs no FHE work.
        AffineGate{{}, SlotVector{Fp::zero(), Fp::one(), Fp::zero(),
                                  Fp::zero()},
                   GateOrigin::Payload},
    };
    output_gates.resize(
        output_dimensions.padded_size,
        AffineGate{{}, Fp::zero(), GateOrigin::Padding});

    LayeredCircuit circuit{
        .shape = PayloadShape::wide(4),
        .payload_input_count = 3,
        .payload_output_count = 4,
        .proof_multiplication_depth = 0,
        .plaintexts = {},
        .layers = {
            AffineLayer{output_dimensions, std::move(output_gates)},
            InputLayer{LayerDimensions{
                .logical_size = 3,
                .padded_size = 4,
                .payload_size = 3,
                .forward_size = 0,
            }},
        },
    };
    circuit.validate();
    CHECK(payload_replay_work_units(circuit) ==
          std::vector<std::uint64_t>({3, 0}));
}

PayloadCheckpointReplayBudgets budgets(
    std::uint64_t scratch, std::uint64_t resident,
    std::size_t chunk, std::uint64_t factor_numerator,
    std::uint64_t factor_denominator = 1) {
    return PayloadCheckpointReplayBudgets{
        .max_live_scratch_bytes = scratch,
        .max_resident_ciphertext_bytes = resident,
        .max_ciphertexts_per_chunk = chunk,
        .max_recomputation_factor =
            {.numerator = factor_numerator,
             .denominator = factor_denominator},
    };
}

PayloadCheckpointReplayProblem small_protocol_problem() {
    const auto workload = make_workload(WorkloadSpec{
        .kind = WorkloadKind::Diamond,
        .shape = PayloadShape::laned(4, 16),
        .multiplicative_depth = 2,
        .width = 4,
        .seed = 9,
    });
    const LayeredCircuit circuit =
        laminate::payload::compile(workload.circuit);
    const FheEvaluationPlan evaluation =
        FheEvaluationPlan::at_evaluation_levels(circuit, 4, 1, 2);
    const std::vector<std::uint64_t> work =
        payload_replay_work_units(circuit);

    std::vector<PayloadLayerResourceEstimate> resources;
    resources.reserve(circuit.layers.size());
    for (std::size_t layer = 0; layer < circuit.layers.size(); ++layer) {
        const std::size_t limbs =
            evaluation.trace.required_mult_depth_by_layer[layer] + 1U;
        const std::uint64_t serialized = 96U * limbs;
        const std::uint64_t ciphertexts =
            laminate::payload::canonical_layer_wire_support(circuit, layer)
                .live_wire_count;
        resources.push_back(PayloadLayerResourceEstimate{
            .rns_limb_count = limbs,
            .checkpoint_bytes =
                file_trace_layer_artifact_bytes(ciphertexts,
                                                   serialized),
            .serialized_ciphertext_bytes = serialized,
            .resident_ciphertext_bytes = 160U * limbs,
            .replay_work_units = work[layer],
            .prefer_post_modulus_switch_checkpoint =
                layer != 0 &&
                evaluation.modulus_switches_after_layer[layer] != 0,
        });
    }
    return make_payload_checkpoint_replay_problem(
        circuit, evaluation, resources,
        file_trace_manifest_fixed_bytes(),
        file_trace_manifest_layer_descriptor_bytes());
}

PayloadCheckpointReplayProblem preference_problem() {
    PayloadCheckpointReplayProblem problem;
    problem.checkpoint_set_fixed_bytes =
        file_trace_manifest_fixed_bytes();
    problem.checkpoint_set_bytes_per_layer =
        file_trace_manifest_layer_descriptor_bytes();
    problem.checkpoint_validation_identity_fixed_bytes =
        laminate::payload::checkpoint_replay_metadata_identity_bytes(0);
    problem.checkpoint_validation_identity_bytes_per_layer =
        laminate::payload::checkpoint_replay_metadata_identity_bytes(1) -
        laminate::payload::checkpoint_replay_metadata_identity_bytes(0);
    problem.layers.reserve(6);
    for (std::size_t layer = 0; layer < 6; ++layer) {
        const std::size_t limbs = layer <= 3 ? 2 : 3;
        const std::uint64_t serialized = layer == 3 ? 5 : 2;
        problem.layers.push_back(PayloadReplayLayer{
            .layer = layer,
            .kind = layer == 5 ? LayerKind::Input : LayerKind::Affine,
            .stored_value_count = 4,
            .virtual_wire_count = 4,
            .rns_limb_count = limbs,
            .required_proof_depth = limbs - 1U,
            .modulus_switches_after_layer = layer == 3 ? 1U : 0U,
            .checkpoint_bytes =
                file_trace_layer_artifact_bytes(4, serialized),
            .serialized_ciphertext_bytes = serialized,
            .resident_ciphertext_bytes = 10,
            .replay_work_units = layer == 5 ? 0U : 1U,
            .preferred_checkpoint = layer == 3,
        });
    }
    problem.validate();
    return problem;
}

PayloadCheckpointReplayProblem uniform_problem() {
    PayloadCheckpointReplayProblem problem;
    problem.checkpoint_set_fixed_bytes =
        file_trace_manifest_fixed_bytes();
    problem.checkpoint_set_bytes_per_layer =
        file_trace_manifest_layer_descriptor_bytes();
    problem.checkpoint_validation_identity_fixed_bytes =
        laminate::payload::checkpoint_replay_metadata_identity_bytes(0);
    problem.checkpoint_validation_identity_bytes_per_layer =
        laminate::payload::checkpoint_replay_metadata_identity_bytes(1) -
        laminate::payload::checkpoint_replay_metadata_identity_bytes(0);
    for (std::size_t layer = 0; layer < 5; ++layer) {
        problem.layers.push_back(PayloadReplayLayer{
            .layer = layer,
            .kind = layer == 4 ? LayerKind::Input : LayerKind::Affine,
            .stored_value_count = 8,
            .virtual_wire_count = 8,
            .rns_limb_count = 2,
            .required_proof_depth = 1,
            .checkpoint_bytes =
                file_trace_layer_artifact_bytes(8, 10),
            .serialized_ciphertext_bytes = 10,
            .resident_ciphertext_bytes = 100,
            .replay_work_units = layer == 4 ? 0U : 1U,
        });
    }
    problem.validate();
    return problem;
}

PayloadCheckpointReplayProblem limit_problem(
    std::span<const std::uint64_t> work) {
    PayloadCheckpointReplayProblem problem;
    problem.checkpoint_set_fixed_bytes =
        file_trace_manifest_fixed_bytes();
    problem.checkpoint_set_bytes_per_layer =
        file_trace_manifest_layer_descriptor_bytes();
    problem.layers.reserve(work.size());
    for (std::size_t layer = 0; layer < work.size(); ++layer) {
        problem.layers.push_back(PayloadReplayLayer{
            .layer = layer,
            .kind = layer + 1U == work.size() ? LayerKind::Input
                                              : LayerKind::Affine,
            .stored_value_count = 1,
            .virtual_wire_count = 1,
            .rns_limb_count = 1,
            .required_proof_depth = 0,
            .checkpoint_bytes =
                file_trace_layer_artifact_bytes(1, 1),
            .serialized_ciphertext_bytes = 1,
            .resident_ciphertext_bytes = 1,
            .replay_work_units = work[layer],
        });
    }
    return problem;
}

PayloadCheckpointReplayProblem location_sensitive_problem(
    std::span<const std::uint64_t> checkpoint_bytes,
    std::span<const std::uint64_t> work) {
    CHECK(checkpoint_bytes.size() == work.size());
    PayloadCheckpointReplayProblem problem;
    problem.layers.reserve(work.size());
    for (std::size_t layer = 0; layer < work.size(); ++layer) {
        problem.layers.push_back(PayloadReplayLayer{
            .layer = layer,
            .kind = layer + 1U == work.size() ? LayerKind::Input
                                              : LayerKind::Affine,
            .stored_value_count = 1,
            .virtual_wire_count = 1,
            .rns_limb_count = 1,
            .required_proof_depth = 0,
            .checkpoint_bytes = checkpoint_bytes[layer],
            .serialized_ciphertext_bytes = 1,
            .resident_ciphertext_bytes = 1,
            .replay_work_units = work[layer],
        });
    }
    problem.validate();
    return problem;
}

void test_circuit_adapter_and_reverse_segments() {
    const PayloadCheckpointReplayProblem problem = small_protocol_problem();
    const auto plan = plan_payload_checkpoint_replay(
        problem, budgets(1ULL << 30U, 1ULL << 30U, 4, 100));

    CHECK(plan.full_trace_reference.checkpoint_layers.size() ==
          problem.layers.size());
    CHECK(plan.selected.feasible());
    CHECK(plan.selected.chunk_ciphertexts == 4);
    CHECK(!plan.selected.checkpoint_layers.empty());
    CHECK(plan.selected.checkpoint_layers.back() + 1U ==
          problem.layers.size());
    CHECK(plan.reverse_gkr_segments.size() + 1U ==
          problem.layers.size());

    std::uint64_t replay = 0;
    for (std::size_t index = 0;
         index < plan.reverse_gkr_segments.size(); ++index) {
        const auto &segment = plan.reverse_gkr_segments[index];
        CHECK(segment.reduction_layer == index);
        CHECK(segment.required_source_layer == index + 1U);
        CHECK(segment.checkpoint_layer >= segment.required_source_layer);
        CHECK(segment.replay_output_layer_begin ==
              segment.required_source_layer);
        CHECK(segment.replay_output_layer_end == segment.checkpoint_layer);
        std::uint64_t expected = 0;
        for (std::size_t layer = segment.replay_output_layer_begin;
             layer < segment.replay_output_layer_end; ++layer) {
            expected += problem.layers[layer].replay_work_units;
        }
        CHECK(segment.replay_work_units == expected);
        CHECK(segment.artifact_peak.peak_live_scratch_bytes <=
              plan.selected.peak_live_scratch_bytes);
        CHECK(segment.peak_resident_bytes <=
              plan.selected.peak_resident_bytes);

        const auto &artifact = segment.artifact_peak;
        CHECK(artifact.input_artifact_bytes ==
              problem.layers[artifact.input_layer].checkpoint_bytes);
        CHECK(artifact.output_artifact_bytes ==
              problem.layers[artifact.output_layer].checkpoint_bytes ||
              artifact.output_artifact_bytes == 0);
        CHECK(artifact.additional_transient_input_bytes ==
              (artifact.input_counted_in_live_checkpoint_bytes
                   ? 0
                   : artifact.input_artifact_bytes));
        CHECK(artifact.transient_input_retired_after_output_publish ==
              !artifact.input_counted_in_live_checkpoint_bytes);
        CHECK(artifact.output_retired_after_next_layer_or_gkr ==
              (artifact.output_artifact_bytes != 0));
        CHECK(artifact.peak_live_scratch_bytes ==
              artifact.live_checkpoint_bytes +
                  artifact.additional_transient_input_bytes +
                  artifact.output_artifact_bytes);

        std::uint64_t expected_live =
            plan.selected.checkpoint_metadata_bytes;
        for (std::size_t checkpoint : plan.selected.checkpoint_layers) {
            if (checkpoint >= segment.required_source_layer) {
                expected_live +=
                    problem.layers[checkpoint].checkpoint_bytes;
            }
        }
        CHECK(artifact.live_checkpoint_bytes == expected_live);
        const bool source_is_checkpoint = std::binary_search(
            plan.selected.checkpoint_layers.begin(),
            plan.selected.checkpoint_layers.end(),
            segment.required_source_layer);
        CHECK(segment.checkpoint_bytes_retired_after ==
              (source_is_checkpoint
                   ? problem.layers[segment.required_source_layer]
                         .checkpoint_bytes
                   : 0));
        const bool final_source =
            segment.required_source_layer + 1U == problem.layers.size();
        CHECK(segment.fixed_metadata_bytes_retired_after ==
              (final_source
                   ? plan.selected.checkpoint_metadata_bytes
                   : 0));
        CHECK(segment.live_checkpoint_bytes_after ==
              expected_live - segment.checkpoint_bytes_retired_after -
                  segment.fixed_metadata_bytes_retired_after);
        replay += expected;
    }
    CHECK(replay == plan.selected.replay_work_units);
    CHECK(plan.reverse_gkr_segments.back().live_checkpoint_bytes_after == 0);

    const auto &forward = plan.selected.forward_artifact_peak;
    CHECK(forward.peak_live_scratch_bytes ==
          forward.live_checkpoint_bytes +
              forward.additional_transient_input_bytes +
              forward.output_artifact_bytes);
    const bool forward_output_is_checkpoint = std::binary_search(
        plan.selected.checkpoint_layers.begin(),
        plan.selected.checkpoint_layers.end(), forward.output_layer);
    CHECK(forward.output_retired_after_next_layer_or_gkr ==
          !forward_output_is_checkpoint);
}

void test_cached_trace_layout_adapters_match_and_validate() {
    const auto workload = make_workload(WorkloadSpec{
        .kind = WorkloadKind::Diamond,
        .shape = PayloadShape::laned(4, 16),
        .multiplicative_depth = 2,
        .width = 4,
        .seed = 19,
    });
    const LayeredCircuit circuit =
        laminate::payload::compile(workload.circuit);
    const FheEvaluationPlan evaluation =
        FheEvaluationPlan::at_evaluation_levels(circuit, 4, 1, 2);
    CertifiedCanonicalTraceLayout certified_trace_layout =
        derive_certified_canonical_trace_layout(circuit);
    const CanonicalTraceLayout &trace_layout =
        certified_trace_layout.layout();

    const std::vector<std::uint64_t> derived_work =
        payload_replay_work_units(circuit);
    const std::vector<std::uint64_t> cached_work =
        payload_replay_work_units(certified_trace_layout);
    CHECK(cached_work == derived_work);

    std::vector<PayloadLayerResourceEstimate> resources;
    resources.reserve(circuit.layers.size());
    for (std::size_t layer = 0; layer < circuit.layers.size(); ++layer) {
        const std::size_t limbs =
            evaluation.trace.required_mult_depth_by_layer[layer] + 1U;
        const std::uint64_t serialized = 96U * limbs;
        resources.push_back(PayloadLayerResourceEstimate{
            .rns_limb_count = limbs,
            .checkpoint_bytes = file_trace_layer_artifact_bytes(
                trace_layout.storage[layer].stored_wire_count,
                serialized),
            .serialized_ciphertext_bytes = serialized,
            .resident_ciphertext_bytes = 160U * limbs,
            .replay_work_units = cached_work[layer],
            .prefer_post_modulus_switch_checkpoint =
                layer != 0 &&
                evaluation.modulus_switches_after_layer[layer] != 0,
        });
    }

    const PayloadCheckpointReplayProblem derived_problem =
        make_payload_checkpoint_replay_problem(
            circuit, evaluation, resources,
            file_trace_manifest_fixed_bytes(),
            file_trace_manifest_layer_descriptor_bytes());
    const PayloadCheckpointReplayProblem cached_problem =
        make_payload_checkpoint_replay_problem(
            certified_trace_layout, evaluation, resources,
            file_trace_manifest_fixed_bytes(),
            file_trace_manifest_layer_descriptor_bytes());
    CHECK(cached_problem.layers == derived_problem.layers);
    CHECK(cached_problem.checkpoint_set_fixed_bytes ==
          derived_problem.checkpoint_set_fixed_bytes);
    CHECK(cached_problem.checkpoint_set_bytes_per_layer ==
          derived_problem.checkpoint_set_bytes_per_layer);
    CHECK(cached_problem.checkpoint_validation_identity_fixed_bytes ==
          derived_problem.checkpoint_validation_identity_fixed_bytes);
    CHECK(cached_problem.checkpoint_validation_identity_bytes_per_layer ==
          derived_problem.checkpoint_validation_identity_bytes_per_layer);

    CanonicalTraceLayout missing_layer = trace_layout;
    missing_layer.wire_support.pop_back();
    CHECK(throws_invalid_argument([&] {
        (void)certify_canonical_trace_layout(
            circuit, std::move(missing_layer));
    }));

    CanonicalTraceLayout inconsistent_counts = trace_layout;
    ++inconsistent_counts.value_counts.front().encrypted_ciphertexts;
    CHECK(throws_invalid_argument([&] {
        (void)certify_canonical_trace_layout(
            circuit, std::move(inconsistent_counts));
    }));

    // Merge distinct stored ordinals while preserving the range,
    // representative, live-support, and count invariants. These structural
    // checks still pass, so admission must compare against the circuit-derived
    // alias map.
    CanonicalTraceLayout alias_corruption = trace_layout;
    const auto corruptible = std::find_if(
        alias_corruption.storage.begin(),
        alias_corruption.storage.end(),
        [](const auto &storage) { return storage.stored_wire_count >= 2U; });
    CHECK(corruptible != alias_corruption.storage.end());
    const std::size_t corrupted_layer = static_cast<std::size_t>(
        std::distance(alias_corruption.storage.begin(), corruptible));
    for (std::optional<std::size_t> &ordinal :
         corruptible->padded_to_stored) {
        if (!ordinal) {
            continue;
        }
        if (*ordinal == 1U) {
            *ordinal = 0U;
        } else if (*ordinal > 1U) {
            --*ordinal;
        }
    }
    --corruptible->stored_wire_count;
    corruptible->representative_padded_indices.erase(
        corruptible->representative_padded_indices.begin() + 1);
    auto &classifications =
        alias_corruption.stored_value_classifications[corrupted_layer];
    const bool erased_was_encrypted = !classifications[1].has_value();
    classifications.erase(classifications.begin() + 1);
    auto &counts = alias_corruption.value_counts[corrupted_layer];
    --counts.stored_values;
    if (erased_was_encrypted) {
        --counts.encrypted_ciphertexts;
    }
    laminate::payload::validate_layer_storage_layout(*corruptible);
    CHECK(alias_corruption != trace_layout);
    CHECK(throws_invalid_argument([&] {
        (void)certify_canonical_trace_layout(
            circuit, std::move(alias_corruption));
    }));

    CertifiedCanonicalTraceLayout moved_trace_layout =
        std::move(certified_trace_layout);
    CHECK(payload_replay_work_units(moved_trace_layout) == derived_work);
    CHECK(throws_logic_error([&] {
        (void)payload_replay_work_units(certified_trace_layout);
    }));

    LayeredCircuit mutable_circuit = circuit;
    const CertifiedCanonicalTraceLayout mutation_isolated =
        derive_certified_canonical_trace_layout(mutable_circuit);
    mutable_circuit.layers.clear();
    mutable_circuit.payload_input_count = 0;
    CHECK(payload_replay_work_units(mutation_isolated) == derived_work);

    const CertifiedCanonicalTraceLayout lifetime_isolated = [&] {
        LayeredCircuit local =
            laminate::payload::compile(workload.circuit);
        return derive_certified_canonical_trace_layout(local);
    }();
    CHECK(payload_replay_work_units(lifetime_isolated) == derived_work);
}

void test_circuit_adapter_rejects_false_natural_rns_level() {
    const auto workload = make_workload(WorkloadSpec{
        .kind = WorkloadKind::Diamond,
        .shape = PayloadShape::laned(4, 16),
        .multiplicative_depth = 2,
        .width = 4,
        .seed = 10,
    });
    const LayeredCircuit circuit =
        laminate::payload::compile(workload.circuit);
    FheEvaluationPlan evaluation =
        FheEvaluationPlan::at_evaluation_levels(circuit, 4, 1, 2);
    CHECK(evaluation.trace.required_mult_depth_by_layer[1] > 0);
    --evaluation.proof_ingress_mult_depth_by_layer[1];
    evaluation.validate(circuit);

    const std::vector<std::uint64_t> work =
        payload_replay_work_units(circuit);
    std::vector<PayloadLayerResourceEstimate> resources;
    resources.reserve(circuit.layers.size());
    for (std::size_t layer = 0; layer < circuit.layers.size(); ++layer) {
        std::size_t limbs =
            evaluation.trace.required_mult_depth_by_layer[layer] + 1U;
        if (layer == 1) {
            // A caller could otherwise claim that the already-reduced level
            // is natural, making ingress look like a zero-cost alias.
            limbs = evaluation.proof_ingress_mult_depth_by_layer[layer] +
                    1U;
        }
        const std::uint64_t serialized = 96U * limbs;
        const std::uint64_t ciphertexts =
            laminate::payload::canonical_layer_wire_support(circuit, layer)
                .live_wire_count;
        resources.push_back(PayloadLayerResourceEstimate{
            .rns_limb_count = limbs,
            .checkpoint_bytes = file_trace_layer_artifact_bytes(
                ciphertexts, serialized),
            .serialized_ciphertext_bytes = serialized,
            .resident_ciphertext_bytes = 160U * limbs,
            .replay_work_units = work[layer],
        });
    }
    CHECK(throws_invalid_argument([&] {
        (void)make_payload_checkpoint_replay_problem(
            circuit, evaluation, resources,
            file_trace_manifest_fixed_bytes(),
            file_trace_manifest_layer_descriptor_bytes());
    }));
}

void test_post_switch_preference_is_effective() {
    const PayloadCheckpointReplayProblem problem = preference_problem();
    const auto plan = plan_payload_checkpoint_replay(
        problem, budgets(1U << 20U, 1U << 20U, 4, 2));
    CHECK(plan.selected.checkpoint_layers ==
          std::vector<std::size_t>({3, 5}));
    CHECK(!plan.used_nonpreferred_checkpoint);
    CHECK(plan.selected.replay_work_units == 4);
    CHECK(plan.selected.cumulative_work_units == 9);

    const auto strict = plan_payload_checkpoint_replay(
        problem, budgets(1U << 20U, 1U << 20U, 4, 6, 5));
    CHECK(strict.used_nonpreferred_checkpoint);
    CHECK(std::any_of(
        strict.selected.checkpoint_layers.begin(),
        strict.selected.checkpoint_layers.end(), [&](std::size_t layer) {
            return layer != problem.layers.size() - 1U &&
                   !problem.layers[layer].preferred_checkpoint;
        }));
}

void test_replay_work_objective_spends_only_admitted_disk() {
    const PayloadCheckpointReplayProblem problem = preference_problem();
    PayloadCheckpointReplayBudgets limits =
        budgets(1U << 20U, 1U << 20U, 4, 100);
    const auto storage_plan =
        plan_payload_checkpoint_replay(problem, limits);

    limits.selection_objective =
        PayloadCheckpointSelectionObjective::MinimumReplayWork;
    const auto replay_work_plan =
        plan_payload_checkpoint_replay(problem, limits);

    CHECK(storage_plan.selected.checkpoint_layers ==
          std::vector<std::size_t>({5}));
    CHECK(storage_plan.selected.replay_work_units == 10);
    CHECK(storage_plan.selected.cumulative_work_units == 15);
    CHECK(!storage_plan.used_nonpreferred_checkpoint);
    CHECK(replay_work_plan.selected.checkpoint_layers ==
          std::vector<std::size_t>({1, 2, 3, 4, 5}));
    CHECK(replay_work_plan.selected.replay_work_units == 0);
    CHECK(replay_work_plan.selected.replay_work_units <
          storage_plan.selected.replay_work_units);
    CHECK(replay_work_plan.selected.checkpoint_bytes >
          storage_plan.selected.checkpoint_bytes);
    CHECK(replay_work_plan.selected.peak_live_scratch_bytes <=
          limits.max_live_scratch_bytes);
    CHECK(replay_work_plan.selected.peak_resident_bytes <=
          limits.max_resident_ciphertext_bytes);
    CHECK(replay_work_plan.used_nonpreferred_checkpoint);

    PayloadCheckpointReplayBudgets invalid = limits;
    invalid.selection_objective =
        static_cast<PayloadCheckpointSelectionObjective>(255);
    CHECK(throws_invalid_argument([&] { invalid.validate(); }));
}

void test_output_only_objective_accounts_for_adjacent_layers() {
    const PayloadCheckpointReplayProblem problem = preference_problem();
    PayloadCheckpointReplayBudgets limits =
        budgets(1U << 20U, 1U << 20U, 4, 100);
    limits.reserved_live_scratch_bytes = 37;
    limits.reserved_resident_bytes = 41;
    limits.selection_objective =
        PayloadCheckpointSelectionObjective::OutputOnlyAdjacentLayers;

    std::uint64_t expected_disk_peak = 0;
    for (std::size_t source = 1; source < problem.layers.size(); ++source) {
        expected_disk_peak = std::max(
            expected_disk_peak,
            problem.layers[source].checkpoint_bytes +
                problem.layers[source - 1U].checkpoint_bytes);
    }
    expected_disk_peak += limits.reserved_live_scratch_bytes;

    const auto plan =
        plan_payload_checkpoint_replay(problem, limits);
    CHECK(plan.selected.feasible());
    CHECK(plan.selected.checkpoint_layers.empty());
    CHECK(plan.selected.checkpoint_metadata_bytes == 0);
    CHECK(plan.selected.checkpoint_metadata_validation_buffer_bytes == 0);
    CHECK(plan.selected.checkpoint_bytes == 0);
    CHECK(plan.selected.replay_work_units == 0);
    CHECK(plan.selected.cumulative_work_units ==
          plan.selected.initial_forward_work_units);
    CHECK(plan.selected.peak_live_scratch_bytes == expected_disk_peak);
    CHECK(plan.selected.forward_peak_live_scratch_bytes ==
          expected_disk_peak);
    CHECK(plan.reverse_gkr_segments.empty());
    CHECK(!plan.used_nonpreferred_checkpoint);

    PayloadCheckpointReplayBudgets insufficient_disk = limits;
    insufficient_disk.max_live_scratch_bytes = expected_disk_peak - 1U;
    CHECK(throws_invalid_argument([&] {
        (void)plan_payload_checkpoint_replay(problem, insufficient_disk);
    }));

    PayloadCheckpointReplayBudgets proof_consumer = limits;
    proof_consumer.post_replay_consumer_artifact_bytes_by_reduction.assign(
        problem.layers.size() - 1U, 1);
    CHECK(throws_invalid_argument([&] {
        (void)plan_payload_checkpoint_replay(problem, proof_consumer);
    }));
}

void test_target_role_persistence_is_reserved_before_selection() {
    const PayloadCheckpointReplayProblem problem = preference_problem();
    PayloadCheckpointReplayBudgets limits =
        budgets(1U << 20U, 1U << 20U, 4, 5, 2);
    limits.selection_objective =
        PayloadCheckpointSelectionObjective::MinimumReplayWork;
    const auto all_checkpoints =
        plan_payload_checkpoint_replay(problem, limits);
    CHECK(all_checkpoints.selected.replay_work_units == 0);

    // Model a host whose gross non-free envelope fits the fastest schedule
    // exactly. One byte of client-private persistence makes that schedule an
    // invalid all-role peak, but a slower sparse schedule still fits.
    const std::uint64_t gross_live_bytes =
        all_checkpoints.selected.peak_live_scratch_bytes;
    const auto host = derive_host_resource_budget(
        kBenchmarkFreeDiskReserveBytes + gross_live_bytes,
        256'000'000'000ULL);
    constexpr std::uint64_t kClientPrivateBytes = 1;
    CHECK(all_checkpoints.selected.peak_live_scratch_bytes +
              kClientPrivateBytes >
          host.max_live_disk_bytes);

    limits.max_live_scratch_bytes = reserve_role_private_disk(
        host, kClientPrivateBytes);
    const auto reserved =
        plan_payload_checkpoint_replay(problem, limits);
    CHECK(reserved.selected.feasible());
    CHECK(reserved.selected.replay_work_units > 0);
    CHECK(reserved.selected.cumulative_work_units >
          all_checkpoints.selected.cumulative_work_units);
    CHECK(reserved.selected.peak_live_scratch_bytes +
              kClientPrivateBytes <=
          host.max_live_disk_bytes);
}

void test_target_client_ram_is_reserved_before_selection() {
    const PayloadCheckpointReplayProblem problem = preference_problem();
    PayloadCheckpointReplayBudgets limits =
        budgets(1U << 20U, 1U << 20U, 4, 5, 2);
    limits.selection_objective =
        PayloadCheckpointSelectionObjective::MinimumReplayWork;
    const auto all_checkpoints =
        plan_payload_checkpoint_replay(problem, limits);
    CHECK(all_checkpoints.selected.replay_work_units == 0);

    // Give the all-checkpoint schedule exactly the gross resident envelope.
    // Reserving even one byte for the concurrently waiting client must make
    // the planner choose a feasible, more replay-heavy server schedule.
    const std::uint64_t gross_resident_bytes =
        all_checkpoints.selected.peak_resident_bytes;
    const auto host = derive_host_resource_budget(
        500'000'000'000ULL,
        kBenchmarkHostRamSafetyReserveBytes + gross_resident_bytes);
    constexpr std::uint64_t kClientPeakBytes = 1;
    limits.max_resident_ciphertext_bytes =
        reserve_concurrent_client_ram(host, kClientPeakBytes);
    const auto reserved =
        plan_payload_checkpoint_replay(problem, limits);
    CHECK(reserved.selected.feasible());
    CHECK(reserved.selected.replay_work_units > 0);
    CHECK(reserved.selected.cumulative_work_units >
          all_checkpoints.selected.cumulative_work_units);
    CHECK(reserved.selected.peak_resident_bytes + kClientPeakBytes <=
          host.max_resident_ram_bytes);
}

void test_replay_work_objective_accounts_for_downstream_artifact_overlap() {
    PayloadCheckpointReplayProblem problem;
    constexpr std::array<std::uint64_t, 4> kWork{1, 10, 100, 0};
    for (std::size_t layer = 0; layer < kWork.size(); ++layer) {
        problem.layers.push_back(PayloadReplayLayer{
            .layer = layer,
            .kind = layer + 1U == kWork.size() ? LayerKind::Input
                                               : LayerKind::Affine,
            .stored_value_count = 1,
            .virtual_wire_count = 1,
            .rns_limb_count = 1,
            .required_proof_depth = 0,
            .checkpoint_bytes = 40,
            .serialized_ciphertext_bytes = 1,
            .resident_ciphertext_bytes = 1,
            .replay_work_units = kWork[layer],
        });
    }
    problem.validate();

    PayloadCheckpointReplayBudgets limits{
        .max_live_scratch_bytes = 190,
        .max_resident_ciphertext_bytes = 1'024,
        .max_ciphertexts_per_chunk = 1,
        .max_recomputation_factor = {100, 1},
        .reserved_live_scratch_bytes = 10,
        .reserved_resident_bytes = 10,
        .selection_objective =
            PayloadCheckpointSelectionObjective::MinimumReplayWork,
    };
    const auto payload_only =
        plan_payload_checkpoint_replay(problem, limits);
    CHECK(payload_only.selected.checkpoint_layers ==
          std::vector<std::size_t>({1, 2, 3}));

    limits.post_replay_consumer_artifact_bytes_by_reduction =
        {100, 0, 0};
    const auto composed =
        plan_payload_checkpoint_replay(problem, limits);
    CHECK(composed.selected.checkpoint_layers ==
          std::vector<std::size_t>({1, 3}));
    CHECK(composed.selected.replay_work_units == 100);
    CHECK(composed.selected.post_replay_consumer_artifact_bytes_upper_bound ==
          100);
    CHECK(composed.selected.post_replay_consumer_peak_live_scratch_bytes ==
          190);
    CHECK(composed.selected.peak_live_scratch_bytes == 190);
    CHECK(composed.reverse_gkr_segments.front()
              .post_replay_consumer_peak_live_scratch_bytes == 190);

    limits.post_replay_consumer_artifact_bytes_by_reduction.pop_back();
    CHECK(throws_invalid_argument([&] {
        (void)plan_payload_checkpoint_replay(problem, limits);
    }));
}

void test_exact_proof_ingress_capacity_bounds() {
    PayloadCheckpointReplayProblem problem;
    problem.layers = {
        PayloadReplayLayer{
            .layer = 0,
            .kind = LayerKind::Affine,
            .stored_value_count = 1,
            .virtual_wire_count = 1,
            .rns_limb_count = 2,
            .required_proof_depth = 1,
            .checkpoint_bytes = 66,
            .serialized_ciphertext_bytes = 1,
            .resident_ciphertext_bytes = 1,
            .replay_work_units = 1,
        },
        PayloadReplayLayer{
            .layer = 1,
            .kind = LayerKind::Affine,
            .stored_value_count = 10,
            .virtual_wire_count = 10,
            .rns_limb_count = 2,
            .required_proof_depth = 0,
            .checkpoint_bytes = 1'050,
            .serialized_ciphertext_bytes = 100,
            .resident_ciphertext_bytes = 100,
            .replay_work_units = 1,
            .proof_ingress_serialized_ciphertext_bytes = 20,
            .proof_ingress_resident_ciphertext_bytes = 40,
        },
        PayloadReplayLayer{
            .layer = 2,
            .kind = LayerKind::Input,
            .stored_value_count = 1,
            .virtual_wire_count = 1,
            .rns_limb_count = 2,
            .required_proof_depth = 1,
            .checkpoint_bytes = 66,
            .serialized_ciphertext_bytes = 1,
            .resident_ciphertext_bytes = 1,
        },
    };
    problem.validate();
    PayloadCheckpointReplayBudgets limits =
        budgets(10'000, 10'000, 1, 100);
    limits.reserved_live_scratch_bytes = 7;
    limits.reserved_resident_bytes = 11;
    const auto plan = plan_payload_checkpoint_replay(problem, limits);
    const auto &segment = plan.reverse_gkr_segments.front();
    // Keep the natural artifact framing (50 bytes) and replace only its
    // ciphertext payload: 50 + 10 * 20 = 250 bytes.
    CHECK(segment.proof_ingress_artifact_bytes_upper_bound == 250);
    CHECK(segment.proof_ingress_peak_resident_bytes ==
          11 + (100 + 100) + (20 + 40));
    CHECK(plan.selected.proof_ingress_artifact_bytes_upper_bound == 250);

    PayloadCheckpointReplayBudgets insufficient_ram = limits;
    insufficient_ram.max_resident_ciphertext_bytes =
        segment.proof_ingress_peak_resident_bytes - 1U;
    CHECK(throws_invalid_argument([&] {
        (void)plan_payload_checkpoint_replay(problem, insufficient_ram);
    }));

    PayloadCheckpointReplayBudgets insufficient_disk = limits;
    insufficient_disk.max_live_scratch_bytes =
        segment.proof_ingress_peak_live_scratch_bytes - 1U;
    CHECK(throws_invalid_argument([&] {
        (void)plan_payload_checkpoint_replay(problem, insufficient_disk);
    }));
}

void test_chunk_bound_and_infeasible_preflight() {
    const PayloadCheckpointReplayProblem problem = uniform_problem();
    // The complete live output coexists with checkpoint metadata validation.
    // For one mandatory checkpoint, M=296 and I=135, so the exact peak is
    // reserve + 8 * (serialized + resident) + M + I.
    PayloadCheckpointReplayBudgets output_boundary =
        budgets(10'000, 1'324, 8, 4);
    output_boundary.reserved_resident_bytes = 13;
    const auto admitted =
        plan_payload_checkpoint_replay(problem, output_boundary);
    CHECK(admitted.selected.checkpoint_layers ==
          std::vector<std::size_t>({4}));
    CHECK(admitted.selected.chunk_ciphertexts == 5);
    CHECK(admitted.selected.checkpoint_metadata_bytes == 296);
    CHECK(admitted.selected.checkpoint_metadata_validation_buffer_bytes ==
          431);
    CHECK(admitted.selected.retained_output_peak_resident_bytes == 893);
    CHECK(admitted.selected.peak_resident_bytes == 1'324);

    --output_boundary.max_resident_ciphertext_bytes;
    CHECK(throws_invalid_argument([&] {
        (void)plan_payload_checkpoint_replay(problem, output_boundary);
    }));

    CHECK(throws_invalid_argument([&] {
        (void)plan_payload_checkpoint_replay(
            problem, budgets(1'111, 10'000, 8, 4));
    }));
    CHECK(throws_invalid_argument([&] {
        (void)plan_payload_checkpoint_replay(
            problem, budgets(1'800, 10'000, 1, 1));
    }));

    PayloadCheckpointReplayProblem bad = problem;
    bad.layers[2].preferred_checkpoint = true;
    CHECK(throws_invalid_argument([&] { bad.validate(); }));
}

void test_exact_file_framing_and_near_u64_recomputation() {
    CHECK(file_trace_layer_artifact_bytes(1, 100) == 180);
    CHECK(file_trace_manifest_fixed_bytes() == 200);
    CHECK(file_trace_manifest_layer_descriptor_bytes() == 96);
    CHECK(file_trace_manifest_bytes(1) == 296);
    CHECK(standalone_checkpoint_layer_artifact_bytes(1, 100) == 476);

    constexpr std::uint64_t kMax =
        std::numeric_limits<std::uint64_t>::max();
    CHECK(throws_overflow_error([&] {
        (void)standalone_checkpoint_layer_artifact_bytes(1, kMax - 100U);
    }));
    const std::array<std::uint64_t, 3> exact_ratio_work{
        kMax - 2U, 1, 0};
    const PayloadCheckpointReplayProblem exact_ratio =
        limit_problem(exact_ratio_work);
    exact_ratio.validate();
    const auto exact_plan = plan_payload_checkpoint_replay(
        exact_ratio, budgets(4'096, 4'096, 1, kMax, kMax - 1U));
    CHECK(exact_plan.selected.checkpoint_layers ==
          std::vector<std::size_t>({2}));
    CHECK(exact_plan.selected.initial_forward_work_units == kMax - 1U);
    CHECK(exact_plan.selected.replay_work_units == 1);
    CHECK(exact_plan.selected.cumulative_work_units == kMax);

    const std::array<std::uint64_t, 4> overflow_candidate_work{
        kMax - 2U, 1, 1, 0};
    const PayloadCheckpointReplayProblem overflow_candidate =
        limit_problem(overflow_candidate_work);
    overflow_candidate.validate();
    const auto overflow_plan = plan_payload_checkpoint_replay(
        overflow_candidate, budgets(4'096, 4'096, 1, kMax));
    CHECK(overflow_plan.selected.checkpoint_layers ==
          std::vector<std::size_t>({1, 2, 3}));
    CHECK(overflow_plan.selected.initial_forward_work_units == kMax);
    CHECK(overflow_plan.selected.replay_work_units == 0);
    CHECK(overflow_plan.selected.cumulative_work_units == kMax);

    // An overflowing replay interval must not abort selection when a
    // full-checkpoint schedule has zero replay and is otherwise feasible.
    const std::array<std::uint64_t, 4> unused_overflow_work{
        0, 0, kMax, 0};
    const PayloadCheckpointReplayProblem unused_overflow =
        limit_problem(unused_overflow_work);
    unused_overflow.validate();
    const auto unused_overflow_plan = plan_payload_checkpoint_replay(
        unused_overflow, budgets(4'096, 4'096, 1, 1));
    CHECK(unused_overflow_plan.selected.checkpoint_layers ==
          std::vector<std::size_t>({2, 3}));
    CHECK(unused_overflow_plan.selected.replay_work_units == 0);
    CHECK(unused_overflow_plan.selected.cumulative_work_units == kMax);

    const std::array<std::uint64_t, 3> overflowing_forward_work{
        kMax, 1, 0};
    const PayloadCheckpointReplayProblem overflowing_forward =
        limit_problem(overflowing_forward_work);
    CHECK(throws_overflow_error(
        [&] { overflowing_forward.validate(); }));
}

void test_location_sensitive_frontier_preserves_disk_feasibility() {
    constexpr std::array<std::uint64_t, 5> kCheckpointBytes{
        6, 25, 21, 4, 8};
    constexpr std::array<std::uint64_t, 5> kWork{6, 17, 5, 25, 0};
    const PayloadCheckpointReplayProblem problem =
        location_sensitive_problem(kCheckpointBytes, kWork);
    const auto plan = plan_payload_checkpoint_replay(
        problem, budgets(54, 16, 1, 108, 53));

    CHECK(plan.selected.checkpoint_layers ==
          std::vector<std::size_t>({1, 4}));
    CHECK(plan.selected.initial_forward_work_units == 53);
    CHECK(plan.selected.replay_work_units == 55);
    CHECK(plan.selected.cumulative_work_units == 108);
    CHECK(plan.selected.peak_live_scratch_bytes == 54);
}

} // namespace

int main() {
    laminate::test::Runner runner("test_checkpoint_replay");
    runner.run("work proxy counts live affine contributions only",
               test_live_affine_contribution_work_units);
    runner.run("circuit adapter emits exact reverse replay segments",
               test_circuit_adapter_and_reverse_segments);
    runner.run("cached trace layout adapters match and reject corruption",
               test_cached_trace_layout_adapters_match_and_validate);
    runner.run("circuit adapter binds natural RNS levels exactly",
               test_circuit_adapter_rejects_false_natural_rns_level);
    runner.run("post-switch checkpoints are preferred",
               test_post_switch_preference_is_effective);
    runner.run("replay-work objective spends only admitted disk",
               test_replay_work_objective_spends_only_admitted_disk);
    runner.run("output-only objective accounts for adjacent layers",
               test_output_only_objective_accounts_for_adjacent_layers);
    runner.run("target reserves role-private persistence before planning",
               test_target_role_persistence_is_reserved_before_selection);
    runner.run("target reserves concurrent-client RAM before planning",
               test_target_client_ram_is_reserved_before_selection);
    runner.run("replay-work objective composes downstream artifact overlap",
               test_replay_work_objective_accounts_for_downstream_artifact_overlap);
    runner.run("proof ingress uses exact reduced-level capacity bounds",
               test_exact_proof_ingress_capacity_bounds);
    runner.run("chunk shrinking and infeasible plans fail before execution",
               test_chunk_bound_and_infeasible_preflight);
    runner.run("file framing and u64 ratio comparisons are exact",
               test_exact_file_framing_and_near_u64_recomputation);
    runner.run("frontier retains location-dependent disk-feasible plans",
               test_location_sensitive_frontier_preserves_disk_feasibility);
    return runner.summary();
}
