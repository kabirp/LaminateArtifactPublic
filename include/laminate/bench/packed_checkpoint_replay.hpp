#ifndef LAMINATE_BENCH_PACKED_CHECKPOINT_REPLAY_HPP
#define LAMINATE_BENCH_PACKED_CHECKPOINT_REPLAY_HPP

/// @file packed_checkpoint_replay.hpp
/// @brief Formula-only replay resources for Folded/Laned process profiles.

#include "laminate/payload/checkpoint/plan.hpp"
#include "laminate/bench/host_resource_budget.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace laminate::bench {

/// Per-RNS-level ciphertext bounds used by the packed process benchmark.
/// Entry `i` describes a ciphertext with `i+1` data limbs.
struct PackedCheckpointReplayResourceBounds {
    std::vector<std::uint64_t> serialized_ciphertext_bytes_by_rns_limb;
    std::vector<std::uint64_t> resident_ciphertext_bytes_by_rns_limb;
    std::uint64_t checkpoint_set_fixed_bytes = 0;
    std::uint64_t checkpoint_set_bytes_per_layer = 0;
};

/// Construct the exact value-free replay problem used by packed process
/// setup. The returned output layer records its final modulus switch but is
/// never marked as a reverse-GKR checkpoint candidate.
payload::PayloadCheckpointReplayProblem
make_packed_checkpoint_replay_problem(
    const payload::CertifiedCanonicalTraceLayout &trace_layout,
    const payload::FheEvaluationPlan &evaluation,
    const PackedCheckpointReplayResourceBounds &bounds);

/// Conservative online workspace for the bounded Laned affine evaluator.
/// The replay problem supplies the proof-ingress ciphertext size at every
/// affine source layer; `slots / lanes` supplies the number of SIMD chunks.
std::uint64_t laned_affine_reduction_workspace_bytes(
    std::size_t slots, std::size_t lanes,
    const payload::PayloadCheckpointReplayProblem &problem);

/// Capacity-adaptive replay policy. Every benchmark profile derives its
/// live-disk and resident ceilings from the setup host. These constants are
/// the fixed server-side reserves inside that envelope; client-private
/// preprocessing is charged separately on the same filesystem.
inline constexpr std::uint64_t kPackedAdaptiveMinFreeDiskBytes =
    kBenchmarkFreeDiskReserveBytes;
inline constexpr std::uint64_t kPackedAdaptiveServerCommonDiskReserveBytes =
    128'000'000'000ULL;
inline constexpr std::size_t kPackedAdaptiveReplayChunkCiphertexts = 64;
inline constexpr payload::PayloadRecomputationFactorLimit
    kPackedAdaptiveMaximumRecomputation{5, 2};

/// Value-free admission derived before SEAL setup. `replay` is the exact
/// schedule for the compiled trace under deliberately
/// conservative server-common, client-private persistence, and concurrent
/// client-resident reserves.
/// `required_available_disk_bytes` equals the observed available bytes: the
/// selected server cap, client-private reserve, and fixed 100 GB free-space
/// floor. Later exact admission may safely spend unused headroom to reduce
/// replay work. The same refinement applies to the client-resident reserve:
/// exact setup may enlarge the server cap, but the 16-GB host reserve remains
/// outside the combined server/client envelope.
struct PackedAdaptiveStoragePreflight {
    HostResourceBudget host_budget;
    std::uint64_t conservative_client_private_persistent_bytes = 0;
    std::uint64_t conservative_client_peak_resident_bytes = 0;
    payload::PayloadCheckpointReplayBudgets replay_budgets;
    payload::PayloadCheckpointReplayPlan replay;
    std::uint64_t required_available_disk_bytes = 0;
    std::uint64_t additional_server_disk_reserve_bytes = 0;
};

/// Plan checkpoint replay without a backend context, ciphertext, or
/// file write. The caller supplies exact multiplication-source build bounds
/// for each reduction in the same compiled circuit used to make `problem`.
/// `server_resident_reserve_bytes` charges the context, codec, GateMLE and
/// process terms known at this boundary; exact setup supplies any remaining
/// materialized-state terms before cryptographic artifact publication.
PackedAdaptiveStoragePreflight plan_packed_adaptive_storage_preflight(
    const payload::PayloadCheckpointReplayProblem &problem,
    std::span<const std::uint64_t>
        multiplication_scratch_bytes_by_reduction,
    const HostResourceBudget &host_budget,
    std::uint64_t conservative_client_private_persistent_bytes,
    std::uint64_t conservative_client_peak_resident_bytes,
    std::uint64_t additional_server_disk_reserve_bytes = 0,
    std::uint64_t server_resident_reserve_bytes = 0);

/// Require the setup-derived online replay plan to remain within the earlier
/// host-derived envelope. Exact setup may use a smaller client-private reserve and
/// therefore select more checkpoints, but the complete same-filesystem peak
/// may not exceed the persisted gross disk budget. The exact server-common
/// disk reserve may not exceed the conservative 128 GB server-common
/// preflight disk reserve plus its explicit additional server disk reserve.
void require_packed_adaptive_storage_refinement(
    const PackedAdaptiveStoragePreflight &preflight,
    std::uint64_t exact_client_private_persistent_bytes,
    std::uint64_t exact_client_peak_resident_bytes,
    const payload::PayloadCheckpointReplayBudgets &exact_budgets,
    const payload::PayloadCheckpointReplayPlan &exact_replay);

} // namespace laminate::bench

#endif // LAMINATE_BENCH_PACKED_CHECKPOINT_REPLAY_HPP
