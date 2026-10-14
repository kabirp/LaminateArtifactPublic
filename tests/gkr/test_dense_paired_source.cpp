#include "test_helpers.hpp"

#include "laminate/gkr/detail/shared/dense_multiplication/source/paired.hpp"
#include "laminate/gkr/detail/shared/dense_multiplication/source/file.hpp"
#include "laminate/payload/compiler.hpp"
#include "laminate/gkr/detail/shared/dense_multiplication/source/resource_bounds.hpp"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <stdexcept>
#include <vector>

namespace {

using laminate::gkr::detail::DensePairedLogicalRange;
using laminate::gkr::detail::make_dense_paired_source_metadata;
using laminate::payload::GateOrigin;
using laminate::payload::LayerDimensions;
using laminate::payload::LayerStorageLayout;
using laminate::payload::MultiplicationGate;
using laminate::payload::MultiplicationLayer;
using laminate::payload::PayloadBuilder;
using laminate::payload::PayloadShape;

MultiplicationLayer canonical_layer() {
    constexpr std::size_t kPairs = 8;
    MultiplicationLayer result;
    result.dimensions = LayerDimensions{7, kPairs, 6, 1};
    result.gates.reserve(kPairs);
    for (std::size_t logical = 0; logical < kPairs; ++logical) {
        result.gates.push_back(MultiplicationGate{
            .origin = logical == kPairs - 1U ? GateOrigin::Padding
                                              : GateOrigin::Payload});
    }
    return result;
}

LayerStorageLayout aliased_storage() {
    // Active logical pairs are A,A,B,A,C,B,C. The last pair is public padding.
    return LayerStorageLayout{
        .padded_wire_count = 16,
        .stored_wire_count = 6,
        .padded_to_stored =
            {0, 0, 1, 0, 2, 1, 2, std::nullopt,
             3, 3, 4, 3, 5, 4, 5, std::nullopt},
        .representative_padded_indices = {0, 2, 4, 8, 10, 12},
    };
}

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

void test_alias_groups_are_first_occurrence_ordered() {
    const auto metadata = make_dense_paired_source_metadata(
        canonical_layer(), 16, aliased_storage());

    CHECK(metadata.pair_count == 8);
    CHECK(metadata.source_padded_size == 16);
    CHECK(metadata.counts.logical_pairs == 8);
    CHECK(metadata.counts.active_logical_pairs == 7);
    CHECK(metadata.counts.omitted_public_padding_pairs == 1);
    CHECK(metadata.counts.unique_stored_pairs == 3);
    CHECK(metadata.counts.logical_index_entries == 7);
    CHECK(metadata.counts.logical_ranges == 6);
    CHECK(metadata.groups.size() == 3);

    CHECK(metadata.groups[0].stored_left == 0);
    CHECK(metadata.groups[0].stored_right == 3);
    CHECK(metadata.groups[0].logical_indices ==
          std::vector<std::size_t>({0, 1, 3}));
    CHECK(metadata.groups[0].logical_ranges ==
          std::vector<DensePairedLogicalRange>(
              {{0, 2}, {3, 4}}));

    CHECK(metadata.groups[1].stored_left == 1);
    CHECK(metadata.groups[1].stored_right == 4);
    CHECK(metadata.groups[1].logical_indices ==
          std::vector<std::size_t>({2, 5}));
    CHECK(metadata.groups[2].stored_left == 2);
    CHECK(metadata.groups[2].stored_right == 5);
    CHECK(metadata.groups[2].logical_indices ==
          std::vector<std::size_t>({4, 6}));
}

void test_malformed_geometry_is_rejected() {
    CHECK(throws_invalid_argument([&] {
        (void)make_dense_paired_source_metadata(
            canonical_layer(), 8, aliased_storage());
    }));

    LayerStorageLayout missing = aliased_storage();
    missing.padded_to_stored[2] = std::nullopt;
    CHECK(throws_invalid_argument([&] {
        (void)make_dense_paired_source_metadata(
            canonical_layer(), 16, missing);
    }));
}

void test_canonical_storage_collapses_repeated_operands() {
    PayloadBuilder builder(PayloadShape::wide(8), 2);
    const auto first = builder.mul(0, 1);
    const auto second = builder.mul(0, 1);
    const auto third = builder.mul(0, 1);
    builder.set_outputs({first, second, third});
    const auto circuit = laminate::payload::compile(builder.finish());
    const auto source_storage =
        laminate::payload::canonical_layer_storage_layout(circuit, 2);
    const auto metadata = make_dense_paired_source_metadata(
        circuit, 1, source_storage);

    CHECK(source_storage.padded_wire_count == 8);
    CHECK(source_storage.stored_wire_count == 2);
    CHECK(metadata.counts.logical_pairs == 4);
    CHECK(metadata.counts.active_logical_pairs == 3);
    CHECK(metadata.counts.omitted_public_padding_pairs == 1);
    CHECK(metadata.counts.unique_stored_pairs == 1);
    CHECK(metadata.groups.front().stored_left == 0);
    CHECK(metadata.groups.front().stored_right == 1);
    CHECK(metadata.groups.front().logical_indices ==
          std::vector<std::size_t>({0, 1, 2}));
    CHECK(metadata.groups.front().logical_ranges ==
          std::vector<DensePairedLogicalRange>({{0, 3}}));
}

void test_file_source_disk_bounds_follow_disjoint_build_phases() {
    using laminate::gkr::detail::
        file_dense_multiplication_source_disk_bounds;

    const auto alias = file_dense_multiplication_source_disk_bounds(
        3, 100, false);
    CHECK(alias.completed_artifact_bytes == 708);
    CHECK(alias.build_peak_bytes == alias.completed_artifact_bytes);

    // This wide Base proof-ingress fixture has 49,152 distinct operands,
    // each bounded by a three-limb serialized ciphertext plus codec slack.
    // The 4-GiB input buffer needs only ten initial runs at this record size;
    // the bound still covers the disjoint merge and final-publication peaks.
    const auto wide = file_dense_multiplication_source_disk_bounds(
        49'152, 851'968, true);
    CHECK(wide.completed_artifact_bytes == 41'876'717'928ULL);
    CHECK(wide.build_peak_bytes == 83'754'221'928ULL);
    CHECK(wide.build_peak_bytes < 3 * wide.completed_artifact_bytes);
    const auto constrained = file_dense_multiplication_source_disk_bounds(
        49'152, 851'968, true,
        laminate::gkr::detail::
            kDenseMultiplicationMinimumSortBufferBytes);
    CHECK(constrained.completed_artifact_bytes ==
          wide.completed_artifact_bytes);
    CHECK(constrained.build_peak_bytes > wide.build_peak_bytes);

    CHECK(throws_invalid_argument([&] {
        (void)file_dense_multiplication_source_disk_bounds(
            0, 100, true);
    }));
    (void)file_dense_multiplication_source_disk_bounds(
        1,
        laminate::gkr::detail::
            kDenseMultiplicationSortMaxBufferedPayloadBytes,
        true);
    CHECK(throws_invalid_argument([&] {
        (void)file_dense_multiplication_source_disk_bounds(
            1,
            laminate::gkr::detail::
                    kDenseMultiplicationSortMaxBufferedPayloadBytes +
                1,
            true);
    }));
    CHECK(throws_invalid_argument([&] {
        (void)file_dense_multiplication_source_disk_bounds(
            1, 100, true,
            laminate::gkr::detail::
                    kDenseMultiplicationMinimumSortBufferBytes -
                1);
    }));
    CHECK(throws_overflow_error([&] {
        (void)file_dense_multiplication_source_disk_bounds(
            std::numeric_limits<std::size_t>::max(),
            std::numeric_limits<std::uint64_t>::max(), false);
    }));
}

void test_builder_ram_does_not_retain_the_whole_source() {
    using namespace laminate::gkr::detail;
    constexpr std::uint64_t resident = 917'504;
    const auto small = dense_multiplication_builder_ram_bound(
        64, 128, 128, 128, resident);
    const auto large = dense_multiplication_builder_ram_bound(
        131'072, 131'072, 131'072, 131'072, resident);
    CHECK(large > small);
    CHECK(large < 512ULL * 1024 * 1024);
    CHECK(large < 131'072ULL * resident);
    CHECK(throws_overflow_error([&] {
        (void)dense_multiplication_builder_ram_bound(
            std::numeric_limits<std::uint64_t>::max(), 1, 1, 1, resident);
    }));
}

} // namespace

int main() {
    laminate::test::Runner runner("dense paired source metadata");
    runner.run("aliases group in deterministic first-occurrence order",
               test_alias_groups_are_first_occurrence_ordered);
    runner.run("malformed dense geometry is rejected",
               test_malformed_geometry_is_rejected);
    runner.run("canonical storage collapses repeated operand recipes",
               test_canonical_storage_collapses_repeated_operands);
    runner.run("file source disk bounds keep merge phases disjoint",
               test_file_source_disk_bounds_follow_disjoint_build_phases);
    runner.run("builder RAM grows with public metadata instead of ciphertext count",
               test_builder_ram_does_not_retain_the_whole_source);
    return runner.summary();
}
