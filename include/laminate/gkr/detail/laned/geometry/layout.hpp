#ifndef LAMINATE_GKR_DETAIL_LANED_GEOMETRY_LAYOUT_HPP
#define LAMINATE_GKR_DETAIL_LANED_GEOMETRY_LAYOUT_HPP

/// @file layout.hpp
/// @brief Multilinear-variable counts for one Laned packing layout.

#include "laminate/packing/alignment/laned.hpp"

#include <bit>
#include <cstddef>
#include <limits>
#include <stdexcept>
#include <string>

namespace laminate::gkr::laned_detail {

inline std::size_t log2_exact(std::size_t value, const char *operation) {
    if (value == 0 || (value & (value - 1U)) != 0U) {
        throw std::invalid_argument(std::string(operation) +
                                    ": dimension is not a power of two");
    }
    return std::bit_width(value) - 1U;
}

/// Number of variables in the padded `(ciphertext index, SIMD slot)` table.
inline std::size_t layout_variables(
    const packing::LanedPackingLayout &layout) {
    if (layout.padded_ciphertext_count >
        std::numeric_limits<std::size_t>::max() / layout.slot_count) {
        throw std::overflow_error("LaminateLaned: packed domain overflows");
    }
    return log2_exact(layout.padded_ciphertext_count * layout.slot_count,
                      "LaminateLaned packed variables");
}

} // namespace laminate::gkr::laned_detail

#endif // LAMINATE_GKR_DETAIL_LANED_GEOMETRY_LAYOUT_HPP
