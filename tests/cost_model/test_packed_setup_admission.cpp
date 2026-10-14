/// @file test_packed_setup_admission.cpp
/// @brief Early packed-setup construction admission tests.

#include "test_helpers.hpp"

#include "laminate/bench/packed_setup_admission.hpp"

#include <cstdint>
#include <exception>
#include <functional>
#include <limits>

using namespace laminate::bench;
using laminate::test::Runner;

namespace {

bool rejects(const std::function<void()> &operation) {
    try {
        operation();
        return false;
    } catch (const std::exception &) {
        return true;
    }
}

constexpr PackedSetupPrepublicationDemand kDemand{
    .already_present_persistent_bytes = 100,
    .final_persistent_bytes = 700,
    .peak_live_bytes = 1'000,
    .remaining_setup_resident_reserve_bytes = 175,
};

constexpr PackedSetupPrepublicationCapacity kCapacity{
    .max_live_disk_bytes = 1'000,
    .max_resident_ram_bytes = 400,
    .min_free_disk_bytes = 250,
    .host_available_disk_bytes = 1'150,
    .host_ram_bytes = 400,
    .observed_prepublication_peak_rss_bytes = 225,
};

} // namespace

int main() {
    Runner runner("packed setup prepublication admission");

    runner.run("reports exact admitted formula values", [] {
        const PackedSetupPrepublicationAdmission admitted =
            admit_packed_setup_prepublication(kDemand, kCapacity);
        CHECK(admitted.already_present_persistent_bytes == 100);
        CHECK(admitted.final_persistent_bytes == 700);
        CHECK(admitted.peak_live_bytes == 1'000);
        CHECK(admitted.additional_live_bytes == 900);
        CHECK(admitted.required_available_disk_bytes == 1'150);
        CHECK(admitted.observed_available_disk_bytes == 1'150);
        CHECK(admitted.observed_prepublication_peak_rss_bytes == 225);
        CHECK(admitted.remaining_setup_resident_reserve_bytes == 175);
        // The admitted whole-setup peak is the observed setup-prefix HWM plus
        // the formula-derived reserve for all work that remains.
        CHECK(admitted.admitted_whole_setup_peak_resident_bytes ==
              225 + 175);
    });

    runner.run("rejects profile disk before artifact construction", [] {
        PackedSetupPrepublicationCapacity capacity = kCapacity;
        capacity.max_live_disk_bytes = kDemand.peak_live_bytes - 1;
        bool constructed = false;
        CHECK(rejects([&] {
            (void)admit_then_construct_packed_setup(
                kDemand, capacity, [&] {
                    constructed = true;
                    return std::uint64_t{1};
                });
        }));
        CHECK(!constructed);
    });

    runner.run("rejects host disk before artifact construction", [] {
        PackedSetupPrepublicationCapacity capacity = kCapacity;
        --capacity.host_available_disk_bytes;
        bool constructed = false;
        CHECK(rejects([&] {
            (void)admit_then_construct_packed_setup(
                kDemand, capacity, [&] {
                    constructed = true;
                    return std::uint64_t{1};
                });
        }));
        CHECK(!constructed);
    });

    runner.run("rejects whole-setup RAM caps before construction", [] {
        for (bool profile_limit : {true, false}) {
            PackedSetupPrepublicationCapacity capacity = kCapacity;
            if (profile_limit) {
                capacity.max_resident_ram_bytes =
                    kCapacity.max_resident_ram_bytes - 1;
            } else {
                capacity.host_ram_bytes = kCapacity.host_ram_bytes - 1;
            }
            bool constructed = false;
            CHECK(rejects([&] {
                (void)admit_then_construct_packed_setup(
                    kDemand, capacity, [&] {
                        constructed = true;
                        return std::uint64_t{1};
                    });
            }));
            CHECK(!constructed);
        }
    });

    runner.run("runs construction only after successful admission", [] {
        bool constructed = false;
        const auto [admitted, value] = admit_then_construct_packed_setup(
            kDemand, kCapacity, [&] {
                constructed = true;
                return std::uint64_t{17};
            });
        CHECK(constructed);
        CHECK(value == 17);
        CHECK(admitted.peak_live_bytes == kDemand.peak_live_bytes);
    });

    runner.run("rejects malformed and overflowing demand", [] {
        for (PackedSetupPrepublicationDemand malformed : {
                 PackedSetupPrepublicationDemand{
                     .already_present_persistent_bytes = 701,
                     .final_persistent_bytes = 700,
                     .peak_live_bytes = 1'000,
                     .remaining_setup_resident_reserve_bytes = 175,
                 },
                 PackedSetupPrepublicationDemand{
                     .already_present_persistent_bytes = 100,
                     .final_persistent_bytes = 1'001,
                     .peak_live_bytes = 1'000,
                     .remaining_setup_resident_reserve_bytes = 175,
                 },
                 PackedSetupPrepublicationDemand{
                     .already_present_persistent_bytes = 100,
                     .final_persistent_bytes = 700,
                     .peak_live_bytes = 1'000,
                     .remaining_setup_resident_reserve_bytes = 0,
                 },
             }) {
            CHECK(rejects([&] {
                (void)admit_packed_setup_prepublication(
                    malformed, kCapacity);
            }));
        }

        PackedSetupPrepublicationDemand demand = kDemand;
        demand.peak_live_bytes =
            std::numeric_limits<std::uint64_t>::max();
        PackedSetupPrepublicationCapacity capacity = kCapacity;
        capacity.max_live_disk_bytes = demand.peak_live_bytes;
        capacity.min_free_disk_bytes = 101;
        capacity.host_available_disk_bytes =
            std::numeric_limits<std::uint64_t>::max();
        CHECK(rejects([&] {
            (void)admit_packed_setup_prepublication(demand, capacity);
        }));

        capacity = kCapacity;
        capacity.observed_prepublication_peak_rss_bytes = 0;
        CHECK(rejects([&] {
            (void)admit_packed_setup_prepublication(kDemand, capacity);
        }));
    });

    runner.run("rejects resident equation overflow before construction", [] {
        PackedSetupPrepublicationDemand demand = kDemand;
        demand.remaining_setup_resident_reserve_bytes = 2;
        PackedSetupPrepublicationCapacity capacity = kCapacity;
        capacity.max_resident_ram_bytes =
            std::numeric_limits<std::uint64_t>::max();
        capacity.host_ram_bytes =
            std::numeric_limits<std::uint64_t>::max();
        capacity.observed_prepublication_peak_rss_bytes =
            std::numeric_limits<std::uint64_t>::max() - 1;
        bool constructed = false;
        CHECK(rejects([&] {
            (void)admit_then_construct_packed_setup(
                demand, capacity, [&] {
                    constructed = true;
                    return std::uint64_t{1};
                });
        }));
        CHECK(!constructed);
    });

    return runner.summary();
}
