#ifndef LAMINATE_FHE_LAYOUT_FIXED_MESSAGE_HPP
#define LAMINATE_FHE_LAYOUT_FIXED_MESSAGE_HPP

/// @file fixed_message.hpp
/// @brief SIMD cell positions for one Folded/Laned protocol message.

#include "laminate/params.hpp"

#include <bit>
#include <cstddef>
#include <stdexcept>

namespace laminate::fhe {

/// Every fixed message reserves room for two degree-eight extension values.
inline constexpr std::size_t kFixedMessageCellCount =
    2 * kExtensionDegree;

/// Return the SIMD slot holding one base-field cell of a fixed message.
///
/// At the minimum N=16 this is the ordinary contiguous layout. For N>=32,
/// the cells form the size-16 subgroup
///
///   H = { 0, N/32, 2N/32, ..., 15N/32 }
///
/// inside the first BGV row. Translates of H are disjoint cosets, which lets
/// transcript packing use coefficient-sparse coset masks while preserving one
/// grid rotation per round message.
inline std::size_t fixed_message_cell_slot(std::size_t slot_count,
                                           std::size_t cell) {
    if (slot_count < kFixedMessageCellCount ||
        !std::has_single_bit(slot_count) ||
        cell >= kFixedMessageCellCount) {
        throw std::invalid_argument(
            "fixed_message_cell_slot: invalid slot count or cell");
    }
    if (slot_count == kFixedMessageCellCount) {
        return cell;
    }
    const std::size_t row_size = slot_count / 2;
    return cell * (row_size / kFixedMessageCellCount);
}

} // namespace laminate::fhe

#endif // LAMINATE_FHE_LAYOUT_FIXED_MESSAGE_HPP
