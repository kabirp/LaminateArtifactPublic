#include "test_helpers.hpp"

#include "laminate/gkr/detail/folded/prover.hpp"
#include "laminate/gkr/detail/laned/prover.hpp"
#include "laminate/protocol/storage/checkpoint_replay.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <ios>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using laminate::gkr::laned_detail::FileLanedGkrOptions;
using laminate::gkr::laned_detail::FileLanedMultiplicationScratch;
using laminate::gkr::folded_detail::FileFoldedGkrOptions;
using laminate::gkr::folded_detail::FileFoldedMultiplicationScratch;
using laminate::payload::LayerKind;
using laminate::payload::PayloadCheckpointReplayBudgets;
using laminate::payload::PayloadCheckpointReplayPlan;
using laminate::payload::PayloadCheckpointReplayProblem;
using laminate::payload::PayloadReplayLayer;
using laminate::payload::plan_payload_checkpoint_replay;
using laminate::protocol::CheckpointReplayReductionResidentWorkspace;
using laminate::protocol::CheckpointReplayServerStorageLimits;
using laminate::protocol::ServerResourcePair;
using laminate::protocol::admit_checkpoint_replay_server_storage;

bool throws_invalid_argument(const auto &body) {
    try {
        body();
    } catch (const std::invalid_argument &) {
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

PayloadCheckpointReplayProblem mixed_problem() {
    PayloadCheckpointReplayProblem problem;
    problem.checkpoint_set_fixed_bytes = 5;
    problem.checkpoint_set_bytes_per_layer = 1;
    constexpr LayerKind kKinds[]{
        LayerKind::Affine,
        LayerKind::Multiplication,
        LayerKind::Affine,
        LayerKind::Multiplication,
        LayerKind::Input,
    };
    constexpr std::uint64_t kCheckpointBytes[]{10, 20, 30, 40, 50};
    for (std::size_t layer = 0; layer < 5; ++layer) {
        problem.layers.push_back(PayloadReplayLayer{
            .layer = layer,
            .kind = kKinds[layer],
            .stored_value_count = 1,
            .virtual_wire_count = 1,
            .rns_limb_count = 1,
            .required_proof_depth = 0,
            .checkpoint_bytes = kCheckpointBytes[layer],
            .serialized_ciphertext_bytes = 1,
            .resident_ciphertext_bytes = 1,
            .replay_work_units = layer == 4 ? 0U : 1U,
        });
    }
    problem.validate();
    return problem;
}

PayloadCheckpointReplayBudgets replay_budgets(
    std::uint64_t disk_cap = 300, std::uint64_t ram_cap = 120) {
    return PayloadCheckpointReplayBudgets{
        .max_live_scratch_bytes = disk_cap,
        .max_resident_ciphertext_bytes = ram_cap,
        .max_ciphertexts_per_chunk = 1,
        .max_recomputation_factor = {.numerator = 10, .denominator = 1},
        .reserved_live_scratch_bytes = 10,
        .reserved_resident_bytes = 20,
        .post_replay_consumer_artifact_bytes_by_reduction =
            {0, 7, 0, 9},
    };
}

FileLanedGkrOptions gkr_options(std::uint64_t first = 7,
                                    std::uint64_t second = 9) {
    FileLanedGkrOptions options;
    options.multiplication_scratch = {
        FileLanedMultiplicationScratch{
            .reduction_layer = 1,
            .directory = "unused-1",
            .storage_limits =
                {.max_total_bytes = first, .min_free_bytes = 1},
        },
        FileLanedMultiplicationScratch{
            .reduction_layer = 3,
            .directory = "unused-3",
            .storage_limits =
                {.max_total_bytes = second, .min_free_bytes = 1},
        },
    };
    return options;
}

FileFoldedGkrOptions folded_gkr_options(
    std::uint64_t first = 7, std::uint64_t second = 9) {
    FileFoldedGkrOptions options;
    options.multiplication_scratch = {
        FileFoldedMultiplicationScratch{
            .reduction_layer = 1,
            .directory = "unused-folded-1",
            .storage_limits =
                {.max_total_bytes = first, .min_free_bytes = 1},
        },
        FileFoldedMultiplicationScratch{
            .reduction_layer = 3,
            .directory = "unused-folded-3",
            .storage_limits =
                {.max_total_bytes = second, .min_free_bytes = 1},
        },
    };
    return options;
}

CheckpointReplayServerStorageLimits storage_limits(
    std::uint64_t disk_cap = 300, std::uint64_t ram_cap = 120,
    std::uint64_t combined_cap = 220) {
    return CheckpointReplayServerStorageLimits{
        .caps =
            {
                .max_total_local_disk_bytes = disk_cap,
                .max_resident_ram_bytes = ram_cap,
                .max_phase_combined_bytes = combined_cap,
            },
        .common = {.local_disk_bytes = 3, .resident_ram_bytes = 5},
        .payload_gkr_only =
            {.local_disk_bytes = 7, .resident_ram_bytes = 15},
        .transcript_packing_only =
            {.local_disk_bytes = 80, .resident_ram_bytes = 70},
        .reduction_workspaces =
            {
                CheckpointReplayReductionResidentWorkspace{
                    .reduction_layer = 0,
                    .kind = LayerKind::Affine,
                    .multiplication_builder_phase_bytes = 0,
                    .reduction_phase_bytes = 10,
                },
                CheckpointReplayReductionResidentWorkspace{
                    .reduction_layer = 1,
                    .kind = LayerKind::Multiplication,
                    .multiplication_builder_phase_bytes = 40,
                    .reduction_phase_bytes = 50,
                },
                CheckpointReplayReductionResidentWorkspace{
                    .reduction_layer = 2,
                    .kind = LayerKind::Affine,
                    .multiplication_builder_phase_bytes = 0,
                    .reduction_phase_bytes = 80,
                },
                CheckpointReplayReductionResidentWorkspace{
                    .reduction_layer = 3,
                    .kind = LayerKind::Multiplication,
                    .multiplication_builder_phase_bytes = 95,
                    .reduction_phase_bytes = 90,
                },
            },
    };
}

} // namespace

int main() {
    laminate::test::Runner runner("server storage admission");

    runner.run("reports disk and resident reduction envelopes", [] {
        const auto problem = mixed_problem();
        const auto budgets = replay_budgets();
        const auto plan = plan_payload_checkpoint_replay(problem, budgets);
        CHECK(plan.selected.checkpoint_layers ==
              std::vector<std::size_t>{4});

        const auto admission = admit_checkpoint_replay_server_storage(
            problem, budgets, plan, gkr_options(), true,
            storage_limits());
        CHECK(admission.payload_gkr_reserve ==
              (ServerResourcePair{10, 20}));
        CHECK(admission.replay_peak.local_disk_bytes ==
              plan.selected.peak_live_scratch_bytes);
        CHECK(admission.replay_peak.resident_ram_bytes ==
              plan.selected.peak_resident_bytes);
        CHECK(admission.reduction_peaks.size() == 4);

        const auto &replayed = admission.reduction_peaks[1];
        CHECK(replayed.kind == LayerKind::Multiplication);
        CHECK(!replayed.source_is_checkpoint());
        CHECK(replayed.transient_source_bytes ==
              problem.layers[2].checkpoint_bytes);
        CHECK(replayed.post_replay_local_disk_bytes ==
              replayed.payload_gkr_disk_reserve_bytes +
                  replayed.live_checkpoint_bytes +
                  replayed.transient_source_bytes +
                  replayed.multiplication_source_artifact_bytes);
        CHECK(replayed.peak.local_disk_bytes ==
              std::max(replayed.replay_peak_local_disk_bytes,
                       replayed.post_replay_local_disk_bytes));

        const auto &checkpoint = admission.reduction_peaks[3];
        CHECK(checkpoint.source_is_checkpoint());
        CHECK(checkpoint.transient_source_bytes == 0);
        CHECK(checkpoint.post_replay_local_disk_bytes ==
              checkpoint.payload_gkr_disk_reserve_bytes +
                  checkpoint.live_checkpoint_bytes +
                  checkpoint.multiplication_source_artifact_bytes);
        CHECK(checkpoint.peak.local_disk_bytes ==
              std::max(checkpoint.replay_peak_local_disk_bytes,
                       checkpoint.post_replay_local_disk_bytes));

        const auto &affine = admission.reduction_peaks[2];
        CHECK(affine.kind == LayerKind::Affine);
        CHECK(affine.multiplication_source_artifact_bytes == 0);
        CHECK(affine.multiplication_builder_phase_bytes == 0);
        CHECK(affine.peak.local_disk_bytes ==
              std::max(affine.replay_peak_local_disk_bytes,
                       affine.post_replay_local_disk_bytes));

        const auto &long_affine_replay = admission.reduction_peaks[0];
        CHECK(long_affine_replay.kind == LayerKind::Affine);
        CHECK(long_affine_replay.replay_peak_local_disk_bytes >
              long_affine_replay.post_replay_local_disk_bytes);
        CHECK(long_affine_replay.peak.local_disk_bytes ==
              long_affine_replay.replay_peak_local_disk_bytes);
    });

    runner.run("Folded and Laned compose the same replay envelope", [] {
        const auto problem = mixed_problem();
        const auto budgets = replay_budgets();
        const auto plan = plan_payload_checkpoint_replay(problem, budgets);
        const auto limits = storage_limits();
        const auto laned = admit_checkpoint_replay_server_storage(
            problem, budgets, plan, gkr_options(), true, limits);
        const auto folded = admit_checkpoint_replay_server_storage(
            problem, budgets, plan, folded_gkr_options(), true, limits);
        CHECK(folded == laned);
    });

    runner.run("optional payload execution envelope preserves ordinary admission", [] {
        const auto problem = mixed_problem();
        const auto budgets = replay_budgets();
        const auto plan = plan_payload_checkpoint_replay(problem, budgets);
        auto limits = storage_limits();
        CHECK(limits.payload_execution_peak == (ServerResourcePair{}));
        const auto ordinary = admit_checkpoint_replay_server_storage(
            problem, budgets, plan, gkr_options(), true, limits);
        limits.payload_execution_peak = {1, 1};
        CHECK(admit_checkpoint_replay_server_storage(
            problem, budgets, plan, gkr_options(), true, limits) == ordinary);
        limits.payload_execution_peak = {};
        CHECK(admit_checkpoint_replay_server_storage(
            problem, budgets, plan, folded_gkr_options(), true, limits) == ordinary);
    });

    runner.run("includes payload execution and retained sources in reported peaks", [] {
        const auto problem = mixed_problem();
        const auto budgets = replay_budgets();
        const auto plan = plan_payload_checkpoint_replay(problem, budgets);
        auto limits = storage_limits(300, 120, 400);
        const auto ordinary = admit_checkpoint_replay_server_storage(
            problem, budgets, plan, gkr_options(), true, limits);
        limits.payload_execution_peak = {250, 110};
        CHECK(limits.payload_execution_peak.local_disk_bytes >
              ordinary.max_local_disk_bytes);
        CHECK(limits.payload_execution_peak.resident_ram_bytes >
              ordinary.replay_peak.resident_ram_bytes);
        const auto admission = admit_checkpoint_replay_server_storage(
            problem, budgets, plan, gkr_options(), true, limits);
        CHECK(admission.payload_gkr_reserve == ordinary.payload_gkr_reserve);
        CHECK(admission.replay_peak.local_disk_bytes == 250);
        CHECK(admission.replay_peak.resident_ram_bytes == 110);
        CHECK(admission.replay_peak.combined_bytes == 360);
        for (const auto &reduction : admission.reduction_peaks) {
            CHECK(reduction.peak.local_disk_bytes ==
                  250 + reduction.multiplication_source_artifact_bytes);
        }
        CHECK(admission.max_local_disk_bytes == 259);
        CHECK(admission.transcript_packing_peak == ordinary.transcript_packing_peak);

        limits.caps.max_phase_combined_bytes =
            admission.max_phase_combined_bytes - 1U;
        CHECK(throws_invalid_argument([&] {
            (void)admit_checkpoint_replay_server_storage(
                problem, budgets, plan, gkr_options(), true, limits);
        }));
        limits.caps.max_phase_combined_bytes = 400;
        limits.payload_execution_peak = {250, 121};
        CHECK(throws_invalid_argument([&] {
            (void)admit_checkpoint_replay_server_storage(
                problem, budgets, plan, gkr_options(), true, limits);
        }));
        // The payload peak alone fits, but its retained sources coexist with
        // the second multiplication artifact during GKR.
        limits.payload_execution_peak = {295, 110};
        CHECK(throws_invalid_argument([&] {
            (void)admit_checkpoint_replay_server_storage(
                problem, budgets, plan, gkr_options(), true, limits);
        }));
    });

    runner.run("charges both replay reserves exactly once", [] {
        const auto problem = mixed_problem();
        const auto budgets = replay_budgets();
        const auto plan = plan_payload_checkpoint_replay(problem, budgets);
        const auto admission = admit_checkpoint_replay_server_storage(
            problem, budgets, plan, gkr_options(), true,
            storage_limits());

        CHECK(admission.payload_gkr_reserve.local_disk_bytes ==
              budgets.reserved_live_scratch_bytes);
        CHECK(admission.payload_gkr_reserve.resident_ram_bytes ==
              budgets.reserved_resident_bytes);
        CHECK(admission.replay_peak.local_disk_bytes ==
              plan.selected.peak_live_scratch_bytes);
        CHECK(admission.replay_peak.resident_ram_bytes ==
              plan.selected.peak_resident_bytes);
        CHECK(admission.replay_peak.local_disk_bytes !=
              plan.selected.peak_live_scratch_bytes +
                  budgets.reserved_live_scratch_bytes);
        CHECK(admission.replay_peak.resident_ram_bytes !=
              plan.selected.peak_resident_bytes +
                  budgets.reserved_resident_bytes);
    });

    runner.run("retires payload-only state before transcript packing", [] {
        const auto problem = mixed_problem();
        const auto budgets = replay_budgets();
        const auto plan = plan_payload_checkpoint_replay(problem, budgets);
        const auto limits = storage_limits();
        const auto admission = admit_checkpoint_replay_server_storage(
            problem, budgets, plan, gkr_options(), true, limits);

        CHECK(admission.transcript_packing_peak.local_disk_bytes ==
              limits.common.local_disk_bytes +
                  limits.transcript_packing_only.local_disk_bytes);
        CHECK(admission.transcript_packing_peak.resident_ram_bytes ==
              limits.common.resident_ram_bytes +
                  limits.transcript_packing_only.resident_ram_bytes);
        CHECK(admission.transcript_packing_peak.resident_ram_bytes == 75);
        CHECK(admission.transcript_packing_peak.resident_ram_bytes !=
              75 + limits.payload_gkr_only.resident_ram_bytes);
    });

    runner.run("uses phase-paired combined maxima", [] {
        const auto problem = mixed_problem();
        const auto budgets = replay_budgets();
        const auto plan = plan_payload_checkpoint_replay(problem, budgets);
        const auto admission = admit_checkpoint_replay_server_storage(
            problem, budgets, plan, gkr_options(), true,
            storage_limits());

        std::uint64_t expected_combined =
            std::max(admission.replay_peak.combined_bytes,
                     admission.transcript_packing_peak.combined_bytes);
        for (const auto &reduction : admission.reduction_peaks) {
            expected_combined =
                std::max(expected_combined, reduction.peak.combined_bytes);
        }
        CHECK(admission.max_phase_combined_bytes == expected_combined);
        CHECK(admission.max_phase_combined_bytes <
              admission.max_local_disk_bytes +
                  admission.max_resident_ram_bytes);

        auto too_small = storage_limits();
        too_small.caps.max_phase_combined_bytes =
            admission.max_phase_combined_bytes - 1U;
        CHECK(throws_invalid_argument([&] {
            (void)admit_checkpoint_replay_server_storage(
                problem, budgets, plan, gkr_options(), true, too_small);
        }));
    });

    runner.run("multiplication phase state can dominate resident RAM", [] {
        const auto problem = mixed_problem();
        const auto budgets = replay_budgets();
        const auto plan = plan_payload_checkpoint_replay(problem, budgets);
        const auto admission = admit_checkpoint_replay_server_storage(
            problem, budgets, plan, gkr_options(), true,
            storage_limits());

        const auto &first = admission.reduction_peaks[1];
        CHECK(first.peak.resident_ram_bytes == 70);
        CHECK(first.peak.resident_ram_bytes ==
              first.payload_gkr_ram_reserve_bytes +
                  first.reduction_phase_bytes);
        CHECK(first.peak.resident_ram_bytes >
              first.replay_peak_resident_bytes);

        const auto &second = admission.reduction_peaks[3];
        CHECK(second.peak.resident_ram_bytes == 115);
        CHECK(second.peak.resident_ram_bytes ==
              second.payload_gkr_ram_reserve_bytes +
                  second.multiplication_builder_phase_bytes);
        CHECK(admission.max_resident_ram_bytes == 115);
    });

    runner.run("rejects a resident-only cap violation", [] {
        const auto problem = mixed_problem();
        const auto budgets = replay_budgets(300, 60);
        const auto plan = plan_payload_checkpoint_replay(problem, budgets);
        auto limits = storage_limits(300, 60, 220);
        CHECK(plan.selected.peak_resident_bytes < 60);
        CHECK(throws_invalid_argument([&] {
            (void)admit_checkpoint_replay_server_storage(
                problem, budgets, plan, gkr_options(), true, limits);
        }));
    });

    runner.run("validates reduction layer kind and scratch order", [] {
        const auto problem = mixed_problem();
        const auto budgets = replay_budgets();
        const auto plan = plan_payload_checkpoint_replay(problem, budgets);

        auto missing = storage_limits();
        missing.reduction_workspaces.pop_back();
        CHECK(throws_invalid_argument([&] {
            (void)admit_checkpoint_replay_server_storage(
                problem, budgets, plan, gkr_options(), true, missing);
        }));

        auto wrong_layer = storage_limits();
        wrong_layer.reduction_workspaces[1].reduction_layer = 2;
        CHECK(throws_invalid_argument([&] {
            (void)admit_checkpoint_replay_server_storage(
                problem, budgets, plan, gkr_options(), true, wrong_layer);
        }));

        auto wrong_kind = storage_limits();
        wrong_kind.reduction_workspaces[1].kind = LayerKind::Affine;
        CHECK(throws_invalid_argument([&] {
            (void)admit_checkpoint_replay_server_storage(
                problem, budgets, plan, gkr_options(), true, wrong_kind);
        }));

        auto affine_builder = storage_limits();
        affine_builder.reduction_workspaces[0]
            .multiplication_builder_phase_bytes = 1;
        CHECK(throws_invalid_argument([&] {
            (void)admit_checkpoint_replay_server_storage(
                problem, budgets, plan, gkr_options(), true,
                affine_builder);
        }));

        auto scratch = gkr_options();
        scratch.multiplication_scratch[1].reduction_layer = 1;
        CHECK(throws_invalid_argument([&] {
            (void)admit_checkpoint_replay_server_storage(
                problem, budgets, plan, scratch, true, storage_limits());
        }));

        PayloadCheckpointReplayBudgets mismatched = budgets;
        ++mismatched
              .post_replay_consumer_artifact_bytes_by_reduction[1];
        const auto mismatched_plan =
            plan_payload_checkpoint_replay(problem, mismatched);
        CHECK(throws_invalid_argument([&] {
            (void)admit_checkpoint_replay_server_storage(
                problem, mismatched, mismatched_plan, gkr_options(), true,
                storage_limits());
        }));
    });

    runner.run("rejects disk RAM reserve plan and lifecycle mismatch", [] {
        const auto problem = mixed_problem();
        const auto budgets = replay_budgets();
        const auto plan = plan_payload_checkpoint_replay(problem, budgets);

        auto limits = storage_limits();
        --limits.caps.max_total_local_disk_bytes;
        CHECK(throws_invalid_argument([&] {
            (void)admit_checkpoint_replay_server_storage(
                problem, budgets, plan, gkr_options(), true, limits);
        }));

        limits = storage_limits();
        --limits.caps.max_resident_ram_bytes;
        CHECK(throws_invalid_argument([&] {
            (void)admit_checkpoint_replay_server_storage(
                problem, budgets, plan, gkr_options(), true, limits);
        }));

        limits = storage_limits();
        ++limits.payload_gkr_only.local_disk_bytes;
        CHECK(throws_invalid_argument([&] {
            (void)admit_checkpoint_replay_server_storage(
                problem, budgets, plan, gkr_options(), true, limits);
        }));

        limits = storage_limits();
        ++limits.payload_gkr_only.resident_ram_bytes;
        CHECK(throws_invalid_argument([&] {
            (void)admit_checkpoint_replay_server_storage(
                problem, budgets, plan, gkr_options(), true, limits);
        }));

        PayloadCheckpointReplayPlan changed = plan;
        ++changed.selected.peak_resident_bytes;
        CHECK(throws_invalid_argument([&] {
            (void)admit_checkpoint_replay_server_storage(
                problem, budgets, changed, gkr_options(), true,
                storage_limits());
        }));

        CHECK(throws_invalid_argument([&] {
            (void)admit_checkpoint_replay_server_storage(
                problem, budgets, plan, gkr_options(), false,
                storage_limits());
        }));
    });

    runner.run("rejects disk and packing capacity violations", [] {
        const auto problem = mixed_problem();
        const auto budgets = replay_budgets();
        const auto plan = plan_payload_checkpoint_replay(problem, budgets);
        CHECK(throws_invalid_argument([&] {
            (void)admit_checkpoint_replay_server_storage(
                problem, budgets, plan, gkr_options(250, 9), true,
                storage_limits());
        }));

        auto packing = storage_limits();
        packing.transcript_packing_only.local_disk_bytes = 300;
        CHECK(throws_invalid_argument([&] {
            (void)admit_checkpoint_replay_server_storage(
                problem, budgets, plan, gkr_options(), true, packing);
        }));
    });

    runner.run("requires stream-compatible multiplication scratch", [] {
        constexpr std::streamoff kMaxStreamOffset =
            std::numeric_limits<std::streamoff>::max();
        if constexpr (
            kMaxStreamOffset >= 0 &&
            static_cast<std::uint64_t>(kMaxStreamOffset) <
                std::numeric_limits<std::uint64_t>::max()) {
            const auto problem = mixed_problem();
            const auto budgets = replay_budgets(
                std::numeric_limits<std::uint64_t>::max(), 120);
            const auto plan =
                plan_payload_checkpoint_replay(problem, budgets);
            auto limits = storage_limits(
                std::numeric_limits<std::uint64_t>::max(), 120,
                std::numeric_limits<std::uint64_t>::max());
            auto scratch = gkr_options(
                static_cast<std::uint64_t>(kMaxStreamOffset) + 1U, 9);
            CHECK(throws_invalid_argument([&] {
                (void)admit_checkpoint_replay_server_storage(
                    problem, budgets, plan, scratch, true, limits);
            }));
        }
    });

    runner.run("rejects arithmetic overflow on either axis", [] {
        const auto problem = mixed_problem();
        const auto budgets = replay_budgets();
        const auto plan = plan_payload_checkpoint_replay(problem, budgets);

        auto component_overflow = storage_limits();
        component_overflow.common.local_disk_bytes =
            std::numeric_limits<std::uint64_t>::max();
        component_overflow.payload_gkr_only.local_disk_bytes = 1;
        CHECK(throws_overflow_error([&] {
            (void)admit_checkpoint_replay_server_storage(
                problem, budgets, plan, gkr_options(), true,
                component_overflow);
        }));

        auto workspace_overflow = storage_limits();
        workspace_overflow.reduction_workspaces[1].reduction_phase_bytes =
            std::numeric_limits<std::uint64_t>::max();
        CHECK(throws_overflow_error([&] {
            (void)admit_checkpoint_replay_server_storage(
                problem, budgets, plan, gkr_options(), true,
                workspace_overflow);
        }));

        const auto wide_budgets = replay_budgets(
            std::numeric_limits<std::uint64_t>::max(), 120);
        const auto wide_plan =
            plan_payload_checkpoint_replay(problem, wide_budgets);
        auto combined_overflow = storage_limits(
            std::numeric_limits<std::uint64_t>::max(), 120,
            std::numeric_limits<std::uint64_t>::max());
        combined_overflow.transcript_packing_only.local_disk_bytes =
            std::numeric_limits<std::uint64_t>::max() -
            combined_overflow.common.local_disk_bytes;
        CHECK(throws_overflow_error([&] {
            (void)admit_checkpoint_replay_server_storage(
                problem, wide_budgets, wide_plan, gkr_options(), true,
                combined_overflow);
        }));
    });

    return runner.summary();
}
