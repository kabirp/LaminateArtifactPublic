/// @file layout.cpp
/// @brief Canonical grid placement schedules for transcript packing.

#include "laminate/packing/alignment/layout.hpp"

#include <algorithm>
#include <bit>
#include <limits>
#include <stdexcept>

namespace laminate::packing {
namespace {

std::size_t checked_add(std::size_t left, std::size_t right) {
    if (right > std::numeric_limits<std::size_t>::max() - left) {
        throw std::overflow_error("packing layout: slot-count overflow");
    }
    return left + right;
}

std::size_t row_end(std::size_t slot, std::size_t half) {
    return slot < half ? half : 2 * half;
}

std::size_t rotation_mapping(std::size_t source, std::size_t destination,
                             std::size_t half) {
    const std::size_t source_row = source / half;
    const std::size_t destination_row = destination / half;
    const std::size_t source_column = source % half;
    const std::size_t destination_column = destination % half;
    const std::size_t shift =
        (source_column + half - destination_column) % half;
    return (source_row == destination_row ? 0 : half) + shift;
}

void append_message_placements(PackingLayout &layout,
                               std::size_t message_index,
                               std::size_t &global_destination) {
    const std::size_t active = layout.message_active_slots[message_index];
    const std::size_t half = layout.slot_count / 2;
    std::size_t source = 0;
    while (source < active) {
        const std::size_t packed_index =
            global_destination / layout.slot_count;
        const std::size_t destination =
            global_destination % layout.slot_count;
        const std::size_t length = std::min(
            {active - source, row_end(source, half) - source,
             row_end(destination, half) - destination});
        layout.placements.push_back(PackingPlacement{
            message_index, source, packed_index, destination, length,
            rotation_mapping(source, destination, half)});
        source += length;
        global_destination = checked_add(global_destination, length);
    }
}

PackingLayout build_prefix_layout(
    std::size_t slot_count,
    std::span<const std::size_t> message_active_slots) {
    if (slot_count < 2 || !std::has_single_bit(slot_count) ||
        message_active_slots.empty()) {
        throw std::invalid_argument(
            "packing layout: slots must be a power of two and messages "
            "nonempty");
    }
    PackingLayout result;
    result.slot_count = slot_count;
    result.slot_pattern = PackingSlotPattern::Prefix;
    result.message_active_slots.assign(message_active_slots.begin(),
                                       message_active_slots.end());
    std::size_t global_destination = 0;
    for (std::size_t message = 0; message < message_active_slots.size();
         ++message) {
        if (message_active_slots[message] == 0 ||
            message_active_slots[message] > slot_count) {
            throw std::invalid_argument(
                "packing layout: active message width is out of range");
        }
        append_message_placements(result, message, global_destination);
    }
    result.packed_ciphertext_count =
        global_destination / slot_count +
        (global_destination % slot_count == 0 ? 0 : 1);
    return result;
}

PackingLayout build_fixed_message_coset_layout(
    std::size_t slot_count, std::size_t message_count,
    std::size_t maximum_row_contributions) {
    if (slot_count < 2 * fhe::kFixedMessageCellCount ||
        !std::has_single_bit(slot_count) || message_count == 0 ||
        maximum_row_contributions == 0) {
        throw std::invalid_argument(
            "fixed-message coset layout: invalid dimensions");
    }
    const std::size_t row_size = slot_count / 2;
    const std::size_t cosets_per_grid_row =
        row_size / fhe::kFixedMessageCellCount;
    const std::size_t available_cosets = 2 * cosets_per_grid_row;
    const std::size_t contributions_per_output =
        std::min(maximum_row_contributions, available_cosets);

    PackingLayout result;
    result.slot_count = slot_count;
    result.slot_pattern = PackingSlotPattern::FixedMessageCoset;
    result.maximum_row_contributions = contributions_per_output;
    result.message_active_slots.assign(message_count,
                                       fhe::kFixedMessageCellCount);
    result.packed_ciphertext_count =
        message_count / contributions_per_output +
        (message_count % contributions_per_output == 0 ? 0 : 1);
    result.placements.reserve(message_count);
    for (std::size_t message = 0; message < message_count; ++message) {
        const std::size_t output = message / contributions_per_output;
        const std::size_t coset = message % contributions_per_output;
        const std::size_t destination_row =
            coset / cosets_per_grid_row;
        const std::size_t destination_coset =
            coset % cosets_per_grid_row;
        const std::size_t destination_begin =
            destination_row * row_size + destination_coset;
        result.placements.push_back(PackingPlacement{
            .message_index = message,
            .source_begin = 0,
            .packed_index = output,
            .destination_begin = destination_begin,
            .length = fhe::kFixedMessageCellCount,
            .rotation_steps =
                rotation_mapping(0, destination_begin, row_size),
        });
    }
    return result;
}

} // namespace

const char *packing_slot_pattern_name(PackingSlotPattern pattern) {
    switch (pattern) {
    case PackingSlotPattern::Prefix:
        return "contiguous-prefix";
    case PackingSlotPattern::FixedMessageCoset:
        return "fixed-message-subgroup-cosets";
    }
    throw std::invalid_argument("packing layout: unknown slot pattern");
}

PackingLayout make_prefix_packing_layout(
    std::size_t slot_count,
    std::span<const std::size_t> message_active_slots) {
    PackingLayout result =
        build_prefix_layout(slot_count, message_active_slots);
    result.validate();
    return result;
}

PackingLayout make_fixed_message_coset_packing_layout(
    std::size_t slot_count, std::size_t bhip_round_count,
    std::size_t maximum_row_contributions) {
    PackingLayout result = build_fixed_message_coset_layout(
        slot_count, bhip_round_count, maximum_row_contributions);
    result.validate();
    return result;
}

std::size_t packing_source_slot(
    const PackingLayout &layout, const PackingPlacement &placement,
    std::size_t offset) {
    if (offset >= placement.length) {
        throw std::invalid_argument(
            "packing layout: source offset is outside the placement");
    }
    if (layout.slot_pattern == PackingSlotPattern::FixedMessageCoset) {
        return fhe::fixed_message_cell_slot(layout.slot_count, offset);
    }
    return placement.source_begin + offset;
}

std::size_t packing_destination_slot(
    const PackingLayout &layout, const PackingPlacement &placement,
    std::size_t offset) {
    const std::size_t source =
        packing_source_slot(layout, placement, offset);
    if (layout.slot_pattern == PackingSlotPattern::FixedMessageCoset) {
        return source + placement.destination_begin;
    }
    return placement.destination_begin + offset;
}

fhe::SlotVector make_packing_destination_mask(
    const PackingLayout &layout, const PackingPlacement &placement) {
    if (layout.slot_count == 0 ||
        placement.packed_index >= layout.packed_ciphertext_count ||
        placement.length == 0 ||
        placement.destination_begin >= layout.slot_count ||
        placement.length > layout.slot_count - placement.destination_begin) {
        throw std::invalid_argument(
            "packing layout: placement is outside the layout");
    }
    fhe::SlotVector mask(layout.slot_count, Fp::zero());
    for (std::size_t offset = 0; offset < placement.length; ++offset) {
        const std::size_t destination =
            packing_destination_slot(layout, placement, offset);
        if (destination >= layout.slot_count) {
            throw std::invalid_argument(
                "packing layout: destination slot is out of range");
        }
        mask[destination] = Fp::one();
    }
    return mask;
}

void PackingLayout::validate() const {
    if (slot_count < 2 || !std::has_single_bit(slot_count) ||
        message_active_slots.empty() || placements.empty() ||
        packed_ciphertext_count == 0) {
        throw std::invalid_argument("packing layout: malformed layout");
    }
    (void)packing_slot_pattern_name(slot_pattern);
    const PackingLayout expected =
        slot_pattern == PackingSlotPattern::FixedMessageCoset
            ? build_fixed_message_coset_layout(
                  slot_count, message_active_slots.size(),
                  maximum_row_contributions)
            : build_prefix_layout(slot_count, message_active_slots);
    if (expected != *this) {
        throw std::invalid_argument(
            "packing layout: layout is not the canonical grid placement");
    }
}

PackingOperationCount count_packing_operations(const PackingLayout &layout) {
    layout.validate();
    PackingOperationCount result;
    for (const PackingPlacement &placement : layout.placements) {
        result.rotations += placement.rotation_steps == 0 ? 0 : 1;
        result.plaintext_masks +=
            placement.destination_begin == 0 &&
                    placement.length == layout.slot_count
                ? 0
                : 1;
    }
    result.additions =
        layout.placements.size() - layout.packed_ciphertext_count;
    return result;
}

} // namespace laminate::packing
