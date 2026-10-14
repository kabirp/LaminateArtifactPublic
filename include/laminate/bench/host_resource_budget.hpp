#ifndef LAMINATE_BENCH_HOST_RESOURCE_BUDGET_HPP
#define LAMINATE_BENCH_HOST_RESOURCE_BUDGET_HPP

/// @file host_resource_budget.hpp
/// @brief Host-derived disk and RAM budgets for benchmark replay.

#include <cstdint>
#include <stdexcept>

namespace laminate::bench {

/// Capacity-adaptive runs preserve this much available filesystem capacity
/// throughout execution. All byte counts are decimal, matching
/// std::filesystem::space.
inline constexpr std::uint64_t kBenchmarkFreeDiskReserveBytes =
    100'000'000'000ULL;

/// Physical RAM withheld from every benchmark role for the OS and benchmark
/// measurement machinery.
inline constexpr std::uint64_t kBenchmarkOperatingSystemRamReserveBytes =
    16'000'000'000ULL;

/// Explicit cache budget left to the kernel for sequential trace and proof
/// artifacts on the locked 372-GB host.
inline constexpr std::uint64_t kBenchmarkPageCacheRamReserveBytes =
    64'000'000'000ULL;

/// Combined fixed host reserve. The concurrently waiting client is charged
/// separately before a server replay plan is selected.
inline constexpr std::uint64_t kBenchmarkHostRamSafetyReserveBytes =
    kBenchmarkOperatingSystemRamReserveBytes +
    kBenchmarkPageCacheRamReserveBytes;

/// The setup-time host observation and gross usable host budgets derived from
/// it. `max_live_disk_bytes` excludes the fixed free-space floor but still
/// includes any client-private or other non-server files which persist on the
/// same filesystem. A server replay planner must reserve those files with
/// `reserve_role_private_disk` before selecting checkpoints.
struct HostResourceBudget {
    std::uint64_t observed_available_disk_bytes = 0;
    std::uint64_t observed_physical_ram_bytes = 0;
    std::uint64_t max_live_disk_bytes = 0;
    std::uint64_t max_resident_ram_bytes = 0;

    bool operator==(const HostResourceBudget &) const = default;
};

/// Reserve fixed disk and RAM safety margins, then expose the remaining gross
/// disk and resident-memory envelopes. Undersized observations fail before
/// subtraction can underflow.
inline HostResourceBudget derive_host_resource_budget(
    std::uint64_t available_disk_bytes,
    std::uint64_t physical_ram_bytes) {
    if (available_disk_bytes <= kBenchmarkFreeDiskReserveBytes) {
        throw std::invalid_argument(
            "benchmark host does not have disk capacity beyond the fixed "
            "free-space reserve");
    }
    if (physical_ram_bytes <= kBenchmarkHostRamSafetyReserveBytes) {
        throw std::invalid_argument(
            "benchmark host does not have RAM capacity beyond the fixed "
            "safety reserve");
    }
    return {
        .observed_available_disk_bytes = available_disk_bytes,
        .observed_physical_ram_bytes = physical_ram_bytes,
        .max_live_disk_bytes =
            available_disk_bytes - kBenchmarkFreeDiskReserveBytes,
        .max_resident_ram_bytes =
            physical_ram_bytes - kBenchmarkHostRamSafetyReserveBytes,
    };
}

/// Remove files owned by another role but persisted on the same filesystem
/// from the gross host disk envelope before planning server replay. This
/// makes a constrained host choose a more replay-heavy schedule instead of
/// selecting a near-cap plan which fails only after setup writes those files.
inline std::uint64_t reserve_role_private_disk(
    const HostResourceBudget &budget,
    std::uint64_t role_private_persistent_bytes) {
    if (role_private_persistent_bytes >= budget.max_live_disk_bytes) {
        throw std::invalid_argument(
            "benchmark host disk budget cannot cover role-private persistent "
            "files");
    }
    return budget.max_live_disk_bytes - role_private_persistent_bytes;
}

/// Remove the modeled peak of a concurrently live client from the gross
/// host resident envelope. A server planner must use this net cap so tighter
/// hosts choose more replay instead of consuming the 16-GB host reserve or
/// failing only after the client has started.
inline std::uint64_t reserve_concurrent_client_ram(
    const HostResourceBudget &budget,
    std::uint64_t client_peak_resident_bytes) {
    if (client_peak_resident_bytes == 0 ||
        client_peak_resident_bytes >= budget.max_resident_ram_bytes) {
        throw std::invalid_argument(
            "benchmark host RAM budget cannot cover the concurrent client");
    }
    return budget.max_resident_ram_bytes - client_peak_resident_bytes;
}

} // namespace laminate::bench

#endif // LAMINATE_BENCH_HOST_RESOURCE_BUDGET_HPP
