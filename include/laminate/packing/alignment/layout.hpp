#ifndef LAMINATE_PACKING_ALIGNMENT_LAYOUT_HPP
#define LAMINATE_PACKING_ALIGNMENT_LAYOUT_HPP

/// @file layout.hpp
/// @brief Canonical grid placement schedules for transcript packing.

#include "laminate/fhe/backend.hpp"
#include "laminate/fhe/layout/fixed_message.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace laminate::packing {

enum class PackingSlotPattern : std::uint8_t {
    Prefix = 0,
    /// The 16 fixed-message cells occupy one subgroup coset in either BGV
    /// row. Each output contains only disjoint row/coset translates.
    FixedMessageCoset = 1,
};

const char *packing_slot_pattern_name(PackingSlotPattern pattern);

/// One grid rotation followed by one destination-slot mask.
struct PackingPlacement {
    std::size_t message_index = 0;
    std::size_t source_begin = 0;
    std::size_t packed_index = 0;
    std::size_t destination_begin = 0;
    std::size_t length = 0;
    std::size_t rotation_steps = 0;

    bool operator==(const PackingPlacement &) const = default;
};

/// Deterministic placement on the backend's 2 x (N/2) batching grid.
struct PackingLayout {
    std::size_t slot_count = 0;
    PackingSlotPattern slot_pattern = PackingSlotPattern::Prefix;
    std::size_t maximum_row_contributions = 0;
    std::vector<std::size_t> message_active_slots;
    std::vector<PackingPlacement> placements;
    std::size_t packed_ciphertext_count = 0;

    void validate() const;
    bool operator==(const PackingLayout &) const = default;
};

PackingLayout make_prefix_packing_layout(
    std::size_t slot_count,
    std::span<const std::size_t> message_active_slots);

/// Build the structured fixed-message layout used by transcript packing.
/// Every BhIP-round ciphertext has exactly 16 logical cells. Both rows of the
/// batching grid are used, for a hard capacity of `slot_count / 16` rounds.
/// At most `maximum_row_contributions` disjoint cosets are accumulated per
/// output.
PackingLayout make_fixed_message_coset_packing_layout(
    std::size_t slot_count, std::size_t bhip_round_count,
    std::size_t maximum_row_contributions = 8);

/// Resolve one logical cell to its physical source/destination SIMD slot.
std::size_t packing_source_slot(
    const PackingLayout &layout, const PackingPlacement &placement,
    std::size_t offset);
std::size_t packing_destination_slot(
    const PackingLayout &layout, const PackingPlacement &placement,
    std::size_t offset);

/// Return the exact 0/1 SIMD mask multiplied into one aligned placement.
fhe::SlotVector make_packing_destination_mask(
    const PackingLayout &layout, const PackingPlacement &placement);

struct PackingOperationCount {
    std::size_t rotations = 0;
    std::size_t plaintext_masks = 0;
    std::size_t additions = 0;
};

PackingOperationCount count_packing_operations(const PackingLayout &layout);

} // namespace laminate::packing

#endif // LAMINATE_PACKING_ALIGNMENT_LAYOUT_HPP
