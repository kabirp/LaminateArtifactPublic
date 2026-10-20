#include "test_helpers.hpp"

#include "laminate/bench/host_resource_budget.hpp"
#include "laminate/protocol/storage/base_capacity.hpp"

#include <cstdint>
#include <limits>
#include <stdexcept>

namespace {

using laminate::protocol::BaseServerCapacityCaps;
using laminate::protocol::BaseServerCapacityComponents;
using laminate::protocol::BaseServerCapacityPhase;
using laminate::protocol::ServerResourcePair;
using laminate::protocol::admit_base_server_capacity;
using laminate::protocol::required_base_server_available_disk;
using laminate::protocol::required_base_setup_available_disk;
using laminate::bench::derive_host_resource_budget;
using laminate::bench::reserve_concurrent_client_ram;

constexpr std::uint64_t kDeploymentDiskCap = 3'000;
constexpr std::uint64_t kDeploymentRamCap = 128;

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

BaseServerCapacityComponents components() {
    return BaseServerCapacityComponents{
        .operational_reserve = {1, 2},
        .preprocessed_keys = {10, 20},
        .prepared_plaintext_cache = {3, 4},
        .gate_mle_preprocessing = {5, 6},
        .compact_replay_trace = {100, 40},
        .encrypted_input_request = {0, 10},
        .encrypted_output_response = {0, 11},
        .payload_replay_workspace = {0, 12},
        .affine_reduction_workspace = {0, 13},
        .multiplication_build_scratch = {200, 1},
        .multiplication_artifact = {80, 1},
        .multiplication_builder_workspace = {0, 15},
        .multiplication_reduction_workspace = {0, 16},
        .accumulated_proof = {20, 14},
        .gate_mle_opening_workspace = {7, 8},
        .proof_encoding = {30, 17},
        .transport_framing = {40, 18},
    };
}

BaseServerCapacityCaps small_caps() {
    return BaseServerCapacityCaps{
        .max_live_local_disk_bytes = 500,
        .max_resident_ram_bytes = 200,
    };
}

BaseServerCapacityCaps deployment_caps() {
    return {
        .max_live_local_disk_bytes = kDeploymentDiskCap,
        .max_resident_ram_bytes = kDeploymentRamCap,
    };
}

} // namespace

int main() {
    laminate::test::Runner runner("streamed Base server capacity");

    runner.run("reports exact phase-local coexistence", [] {
        const auto admission = admit_base_server_capacity(
            small_caps(), components());

        const auto &ready = admission.phase(
            BaseServerCapacityPhase::PreprocessedReady);
        CHECK(ready.live_local_disk_bytes == 19);
        CHECK(ready.resident_ram_bytes == 32);

        const auto &replay = admission.phase(
            BaseServerCapacityPhase::PayloadCheckpointReplay);
        CHECK(replay.live_local_disk_bytes == 119);
        CHECK(replay.resident_ram_bytes == 105);

        const auto &affine = admission.phase(
            BaseServerCapacityPhase::AffineReduction);
        CHECK(affine.live_local_disk_bytes == 139);
        CHECK(affine.resident_ram_bytes == 99);

        const auto &build = admission.phase(
            BaseServerCapacityPhase::MultiplicationScratchBuild);
        CHECK(build.live_local_disk_bytes == 339);
        CHECK(build.resident_ram_bytes == 102);

        const auto &reduction = admission.phase(
            BaseServerCapacityPhase::MultiplicationReduction);
        CHECK(reduction.live_local_disk_bytes == 219);
        CHECK(reduction.resident_ram_bytes == 103);

        const auto &publication = admission.phase(
            BaseServerCapacityPhase::ProofPublication);
        CHECK(publication.live_local_disk_bytes == 109);
        CHECK(publication.resident_ram_bytes == 81);

        const auto &gate_opening = admission.phase(
            BaseServerCapacityPhase::GateMleOpening);
        CHECK(gate_opening.live_local_disk_bytes == 46);
        CHECK(gate_opening.resident_ram_bytes == 54);

        CHECK(admission.max_live_local_disk_bytes == 339);
        CHECK(admission.max_resident_ram_bytes == 105);
        CHECK(admission.max_phase_combined_bytes == 441);
    });

    runner.run("checkpoint planner supplies an absolute phase floor", [] {
        BaseServerCapacityComponents value;
        value.operational_reserve = {10, 20};
        value.payload_replay_workspace = {5, 7};
        value.payload_replay_phase_floor = {123, 156};
        const auto admission = admit_base_server_capacity(
            small_caps(), value);
        const auto &replay = admission.phase(
            BaseServerCapacityPhase::PayloadCheckpointReplay);
        CHECK(replay.live_local_disk_bytes == 123);
        CHECK(replay.resident_ram_bytes == 156);
    });

    runner.run("host floors use predicted allocation rather than caps", [] {
        const auto admission = admit_base_server_capacity(
            small_caps(), components());
        CHECK(admission.max_live_local_disk_bytes == 339);
        CHECK(admission.caps.max_live_local_disk_bytes == 500);
        CHECK(admission.peak_live_local_disk_phase().phase ==
              BaseServerCapacityPhase::MultiplicationScratchBuild);
        CHECK(required_base_setup_available_disk(
                  admission, 23, 42, 7) == 369);
        CHECK(required_base_server_available_disk(
                  admission, 10, 7) == 336);
    });

    runner.run("moves output before proof publication", [] {
        BaseServerCapacityComponents value;
        value.encrypted_output_response = {1, 2};
        value.accumulated_proof = {3, 5};
        value.proof_encoding = {7, 11};
        value.transport_framing = {13, 17};
        const auto admission = admit_base_server_capacity(
            small_caps(), value);
        const auto &publication = admission.phase(
            BaseServerCapacityPhase::ProofPublication);
        CHECK(publication.live_local_disk_bytes == 23);
        CHECK(publication.resident_ram_bytes == 33);
        CHECK(publication.combined_bytes == 56);

        const auto &replay = admission.phase(
            BaseServerCapacityPhase::PayloadCheckpointReplay);
        CHECK(replay.live_local_disk_bytes == 1);
        CHECK(replay.resident_ram_bytes == 2);
        CHECK(admission.phase(BaseServerCapacityPhase::AffineReduction)
                  .resident_ram_bytes == 5);
        CHECK(admission.phase(
                  BaseServerCapacityPhase::MultiplicationReduction)
                  .resident_ram_bytes == 5);
    });

    runner.run("one multiplication artifact coexists with compact trace", [] {
        BaseServerCapacityComponents value;
        value.compact_replay_trace = {2'100, 60};
        value.multiplication_build_scratch = {
            900, 1};
        value.multiplication_artifact = {
            900, 1};
        value.multiplication_reduction_workspace =
            {0, 60};
        value.proof_encoding = {1'500, 100};

        const auto admission = admit_base_server_capacity(
            deployment_caps(), value);
        CHECK(admission.phase(
                  BaseServerCapacityPhase::MultiplicationReduction)
                  .live_local_disk_bytes ==
              kDeploymentDiskCap);
        CHECK(admission.phase(
                  BaseServerCapacityPhase::MultiplicationReduction)
                  .resident_ram_bytes == 121);
        CHECK(admission.phase(BaseServerCapacityPhase::ProofPublication)
                  .live_local_disk_bytes == 1'500);
        // Disjoint-phase maxima are not added across protocol phases.
        CHECK(admission.max_live_local_disk_bytes ==
              kDeploymentDiskCap);
    });

    runner.run("accepts caller-supplied decimal boundaries", [] {
        BaseServerCapacityComponents value;
        value.operational_reserve = {1, 1};
        value.preprocessed_keys = {
            kDeploymentDiskCap - 1U,
            kDeploymentRamCap - 1U,
        };
        const auto admission = admit_base_server_capacity(
            deployment_caps(), value);
        CHECK(admission.max_live_local_disk_bytes ==
              kDeploymentDiskCap);
        CHECK(admission.max_resident_ram_bytes == kDeploymentRamCap);
    });

    runner.run("rejects either caller-supplied boundary by one byte", [] {
        BaseServerCapacityComponents disk;
        disk.preprocessed_keys.local_disk_bytes =
            kDeploymentDiskCap + 1U;
        CHECK(throws_invalid_argument([&] {
            (void)admit_base_server_capacity(
                deployment_caps(), disk);
        }));

        BaseServerCapacityComponents ram;
        ram.preprocessed_keys.resident_ram_bytes =
            kDeploymentRamCap + 1U;
        CHECK(throws_invalid_argument([&] {
            (void)admit_base_server_capacity(
                deployment_caps(), ram);
        }));
    });

    runner.run("host-derived Base caps expand with available capacity", [] {
        const auto smaller = derive_host_resource_budget(
            500'000'000'000ULL, 160'000'000'000ULL);
        const auto larger = derive_host_resource_budget(
            800'000'000'000ULL, 256'000'000'000ULL);
        CHECK(smaller.max_live_disk_bytes == 400'000'000'000ULL);
        CHECK(smaller.max_resident_ram_bytes == 80'000'000'000ULL);
        CHECK(larger.max_live_disk_bytes == 700'000'000'000ULL);
        CHECK(larger.max_resident_ram_bytes == 176'000'000'000ULL);
        CHECK(reserve_concurrent_client_ram(
                  smaller, 20'000'000'000ULL) == 60'000'000'000ULL);
        CHECK(reserve_concurrent_client_ram(
                  larger, 20'000'000'000ULL) == 156'000'000'000ULL);

        BaseServerCapacityComponents value;
        value.preprocessed_keys = {
            500'000'000'000ULL, 100'000'000'000ULL};
        CHECK(throws_invalid_argument([&] {
            (void)admit_base_server_capacity(
                {smaller.max_live_disk_bytes,
                 smaller.max_resident_ram_bytes},
                value);
        }));
        (void)admit_base_server_capacity(
            {larger.max_live_disk_bytes, larger.max_resident_ram_bytes},
            value);
    });

    runner.run("host RAM charges the concurrent client before the server",
               [] {
                   const auto host = derive_host_resource_budget(
                       500'000'000'000ULL, 160'000'000'000ULL);
                   constexpr std::uint64_t client = 20'000'000'000ULL;
                   const std::uint64_t server =
                       reserve_concurrent_client_ram(host, client);
                   CHECK(server + client +
                             laminate::bench::
                                 kBenchmarkHostRamSafetyReserveBytes ==
                         host.observed_physical_ram_bytes);
                   CHECK(throws_invalid_argument([&] {
                       (void)reserve_concurrent_client_ram(host, 0);
                   }));
                   CHECK(throws_invalid_argument([&] {
                       (void)reserve_concurrent_client_ram(
                           host, host.max_resident_ram_bytes);
                   }));

                   // A small benchmark host may legitimately assign more of
                   // the gross envelope to the client than to the server.
                   // The accounting requires only that their sum preserves
                   // the fixed host reserve.
                   const auto client_heavy_host =
                       derive_host_resource_budget(
                           500'000'000'000ULL, 120'000'000'000ULL);
                   constexpr std::uint64_t client_heavy =
                       30'000'000'000ULL;
                   const std::uint64_t client_heavy_server =
                       reserve_concurrent_client_ram(
                           client_heavy_host, client_heavy);
                   CHECK(client_heavy > client_heavy_server);
                   CHECK(client_heavy + client_heavy_server ==
                         client_heavy_host.max_resident_ram_bytes);
               });

    runner.run("accepts exact computed maxima and rejects smaller caps", [] {
        const auto baseline = admit_base_server_capacity(
            small_caps(), components());
        const BaseServerCapacityCaps exact{
            .max_live_local_disk_bytes =
                baseline.max_live_local_disk_bytes,
            .max_resident_ram_bytes = baseline.max_resident_ram_bytes,
        };
        (void)admit_base_server_capacity(exact, components());

        auto disk_short = exact;
        --disk_short.max_live_local_disk_bytes;
        CHECK(throws_invalid_argument([&] {
            (void)admit_base_server_capacity(
                disk_short, components());
        }));

        auto ram_short = exact;
        --ram_short.max_resident_ram_bytes;
        CHECK(throws_invalid_argument([&] {
            (void)admit_base_server_capacity(
                ram_short, components());
        }));
    });

    runner.run("compact trace accounting has no padding ciphertext charge", [] {
        BaseServerCapacityComponents value;
        value.compact_replay_trace = {123, 156};
        const auto admission = admit_base_server_capacity(
            small_caps(), value);
        const auto &replay = admission.phase(
            BaseServerCapacityPhase::PayloadCheckpointReplay);
        CHECK(replay.live_local_disk_bytes == 123);
        CHECK(replay.resident_ram_bytes == 156);
        // Public-zero padding is absent from the capacity input by design.
        CHECK(admission.max_live_local_disk_bytes == 123);
        CHECK(admission.max_resident_ram_bytes == 156);
    });

    runner.run("rejects zero caps and arithmetic overflow", [] {
        CHECK(throws_invalid_argument([] {
            (void)admit_base_server_capacity(
                BaseServerCapacityCaps{0, 1}, {});
        }));
        CHECK(throws_invalid_argument([] {
            (void)admit_base_server_capacity(
                BaseServerCapacityCaps{1, 0}, {});
        }));

        BaseServerCapacityComponents overflow;
        overflow.operational_reserve.local_disk_bytes =
            std::numeric_limits<std::uint64_t>::max();
        overflow.preprocessed_keys.local_disk_bytes = 1;
        CHECK(throws_overflow_error([&] {
            (void)admit_base_server_capacity(
                BaseServerCapacityCaps{
                    std::numeric_limits<std::uint64_t>::max(),
                    std::numeric_limits<std::uint64_t>::max()},
                overflow);
        }));

        BaseServerCapacityComponents maximum;
        maximum.preprocessed_keys.local_disk_bytes =
            std::numeric_limits<std::uint64_t>::max();
        const auto maximum_admission =
            admit_base_server_capacity(
                BaseServerCapacityCaps{
                    std::numeric_limits<std::uint64_t>::max(), 1},
                maximum);
        CHECK(throws_overflow_error([&] {
            (void)required_base_setup_available_disk(
                maximum_admission, 1, 0, 0);
        }));
        CHECK(throws_invalid_argument([&] {
            (void)required_base_server_available_disk(
                admit_base_server_capacity(
                    small_caps(), components()),
                340, 0);
        }));
    });

    return runner.summary();
}
