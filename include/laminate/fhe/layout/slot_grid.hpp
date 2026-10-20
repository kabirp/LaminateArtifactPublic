#ifndef LAMINATE_FHE_LAYOUT_SLOT_GRID_HPP
#define LAMINATE_FHE_LAYOUT_SLOT_GRID_HPP

/// @file slot_grid.hpp
/// @brief Single source of truth for the BGV 2 x (N/2) batching grid.

#include "laminate/field/fp.hpp"

#include <cstddef>
#include <span>
#include <vector>

namespace laminate::fhe {

using SlotVector = std::vector<Fp>;

/// Source index read into `destination` by the public grid rotation. Reduce
/// steps modulo N: its high bit swaps the two rows and its remaining bits
/// rotate within each row. This is the BGV grid action, not a cyclic shift of
/// one length-N vector. Requires power-of-two N >= 2 and destination < N.
std::size_t grid_source(std::size_t slot_count, std::size_t steps,
                        std::size_t destination);

SlotVector grid_rotate(std::span<const Fp> slots, std::size_t steps);

/// Compose two rotations in application order:
/// grid_rotate(grid_rotate(x, first), second) == grid_rotate(x, result).
std::size_t grid_compose(std::size_t slot_count, std::size_t first,
                         std::size_t second);

std::size_t grid_inverse(std::size_t slot_count, std::size_t steps);

} // namespace laminate::fhe

#endif // LAMINATE_FHE_LAYOUT_SLOT_GRID_HPP
