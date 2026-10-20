#ifndef LAMINATE_BENCH_PACKED_SETUP_ADMISSION_HPP
#define LAMINATE_BENCH_PACKED_SETUP_ADMISSION_HPP

/// @file packed_setup_admission.hpp
/// @brief Formula-only resource admission before packed setup construction.

#include <cstdint>
#include <functional>
#include <limits>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>

namespace laminate::bench {

/// Complete formula-derived demand at the point where the large packed role
/// tree has not yet been constructed. `already_present_persistent_bytes`
/// names files that have already reduced the host's reported free space. The
/// resident reserve covers only work that remains after this observation;
/// memory already consumed is represented by the capacity observation below.
struct PackedSetupPrepublicationDemand {
    std::uint64_t already_present_persistent_bytes = 0;
    std::uint64_t final_persistent_bytes = 0;
    std::uint64_t peak_live_bytes = 0;
    std::uint64_t remaining_setup_resident_reserve_bytes = 0;
};

/// Both configured process caps and the host resources observed immediately
/// before packed setup construction. The RSS observation is the whole-process
/// high-water mark through this boundary, not a formula-derived workspace.
struct PackedSetupPrepublicationCapacity {
    std::uint64_t max_live_disk_bytes = 0;
    std::uint64_t max_resident_ram_bytes = 0;
    std::uint64_t min_free_disk_bytes = 0;
    std::uint64_t host_available_disk_bytes = 0;
    std::uint64_t host_ram_bytes = 0;
    std::uint64_t observed_prepublication_peak_rss_bytes = 0;
};

/// Accepted formula and host-observation values. These are retained for setup
/// reporting; the final measured high-water remains a separate check.
struct PackedSetupPrepublicationAdmission {
    std::uint64_t already_present_persistent_bytes = 0;
    std::uint64_t final_persistent_bytes = 0;
    std::uint64_t peak_live_bytes = 0;
    std::uint64_t additional_live_bytes = 0;
    std::uint64_t required_available_disk_bytes = 0;
    std::uint64_t observed_available_disk_bytes = 0;
    std::uint64_t observed_prepublication_peak_rss_bytes = 0;
    std::uint64_t remaining_setup_resident_reserve_bytes = 0;
    std::uint64_t admitted_whole_setup_peak_resident_bytes = 0;

    bool operator==(
        const PackedSetupPrepublicationAdmission &) const = default;
};

namespace packed_setup_admission_detail {

inline std::uint64_t checked_add(std::uint64_t left, std::uint64_t right,
                                 const char *label) {
    if (right > std::numeric_limits<std::uint64_t>::max() - left) {
        throw std::overflow_error(std::string(label) + " overflows");
    }
    return left + right;
}

} // namespace packed_setup_admission_detail

/// Reject an infeasible packed setup using only scalar formulas and current
/// host capacity. In particular, this function performs no artifact writes.
inline PackedSetupPrepublicationAdmission
admit_packed_setup_prepublication(
    const PackedSetupPrepublicationDemand &demand,
    const PackedSetupPrepublicationCapacity &capacity) {
    if (demand.final_persistent_bytes <
            demand.already_present_persistent_bytes ||
        demand.peak_live_bytes < demand.final_persistent_bytes ||
        demand.remaining_setup_resident_reserve_bytes == 0 ||
        capacity.max_live_disk_bytes == 0 ||
        capacity.max_resident_ram_bytes == 0 ||
        capacity.host_ram_bytes == 0 ||
        capacity.observed_prepublication_peak_rss_bytes == 0) {
        throw std::invalid_argument(
            "packed setup prepublication demand or capacity is invalid");
    }
    const std::uint64_t admitted_whole_setup_peak_resident =
        packed_setup_admission_detail::checked_add(
            capacity.observed_prepublication_peak_rss_bytes,
            demand.remaining_setup_resident_reserve_bytes,
            "packed setup whole-process resident admission");
    if (demand.peak_live_bytes > capacity.max_live_disk_bytes) {
        throw std::runtime_error(
            "packed setup construction live-disk demand " +
            std::to_string(demand.peak_live_bytes) +
            " exceeds the profile cap " +
            std::to_string(capacity.max_live_disk_bytes));
    }
    if (admitted_whole_setup_peak_resident >
        capacity.max_resident_ram_bytes) {
        throw std::runtime_error(
            "packed setup whole-process RAM envelope " +
            std::to_string(admitted_whole_setup_peak_resident) +
            " exceeds the profile cap " +
            std::to_string(capacity.max_resident_ram_bytes));
    }
    if (admitted_whole_setup_peak_resident > capacity.host_ram_bytes) {
        throw std::runtime_error(
            "packed setup whole-process RAM envelope " +
            std::to_string(admitted_whole_setup_peak_resident) +
            " exceeds host RAM " +
            std::to_string(capacity.host_ram_bytes));
    }

    const std::uint64_t additional_live =
        demand.peak_live_bytes - demand.already_present_persistent_bytes;
    const std::uint64_t required_available =
        packed_setup_admission_detail::checked_add(
            additional_live, capacity.min_free_disk_bytes,
            "packed setup host-disk admission");
    if (capacity.host_available_disk_bytes < required_available) {
        throw std::runtime_error(
            "packed setup requires " +
            std::to_string(required_available) +
            " available host-disk bytes including the free-space reserve, "
            "but only " +
            std::to_string(capacity.host_available_disk_bytes) +
            " are available");
    }

    return {
        .already_present_persistent_bytes =
            demand.already_present_persistent_bytes,
        .final_persistent_bytes = demand.final_persistent_bytes,
        .peak_live_bytes = demand.peak_live_bytes,
        .additional_live_bytes = additional_live,
        .required_available_disk_bytes = required_available,
        .observed_available_disk_bytes =
            capacity.host_available_disk_bytes,
        .observed_prepublication_peak_rss_bytes =
            capacity.observed_prepublication_peak_rss_bytes,
        .remaining_setup_resident_reserve_bytes =
            demand.remaining_setup_resident_reserve_bytes,
        .admitted_whole_setup_peak_resident_bytes =
            admitted_whole_setup_peak_resident,
    };
}

/// Couple admission to construction so a rejected formula cannot reach the
/// artifact-producing callback. This small wrapper also makes that ordering
/// directly regression-testable.
template <typename Construct>
auto admit_then_construct_packed_setup(
    const PackedSetupPrepublicationDemand &demand,
    const PackedSetupPrepublicationCapacity &capacity,
    Construct &&construct) {
    using Result = std::invoke_result_t<Construct>;
    static_assert(!std::is_void_v<Result>);
    const PackedSetupPrepublicationAdmission admission =
        admit_packed_setup_prepublication(demand, capacity);
    return std::pair<PackedSetupPrepublicationAdmission, Result>{
        admission, std::invoke(std::forward<Construct>(construct))};
}

} // namespace laminate::bench

#endif // LAMINATE_BENCH_PACKED_SETUP_ADMISSION_HPP
