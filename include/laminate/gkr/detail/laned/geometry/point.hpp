#ifndef LAMINATE_GKR_DETAIL_LANED_GEOMETRY_POINT_HPP
#define LAMINATE_GKR_DETAIL_LANED_GEOMETRY_POINT_HPP

/// @file point.hpp
/// @brief Split a packed Laned MLE point into padding, wire, and lane parts.

#include "laminate/field/fpk.hpp"
#include "laminate/gkr/detail/laned/geometry/layout.hpp"

#include <cstddef>
#include <limits>
#include <span>
#include <stdexcept>
#include <vector>

namespace laminate::gkr::laned_detail {

/// Coordinates that address the active `wire x lane` rectangle embedded in
/// the padded `(ciphertext, slot)` table. `padding_weight` is the equality
/// weight forcing every leading padding coordinate to zero.
struct LanedPointCoordinates {
    Fpk padding_weight = Fpk::one();
    std::vector<Fpk> wire;
    std::vector<Fpk> lane;
};

inline LanedPointCoordinates split_laned_point(
    const packing::LanedPackingLayout &layout,
    std::span<const Fpk> point) {
    const std::size_t total_variables = layout_variables(layout);
    const std::size_t wire_variables = log2_exact(
        layout.original_wire_count, "LaminateLaned original wire variables");
    const std::size_t lane_variables = log2_exact(
        layout.lane_count, "LaminateLaned lane variables");
    if (wire_variables >
            std::numeric_limits<std::size_t>::max() - lane_variables ||
        point.size() != total_variables ||
        wire_variables + lane_variables > total_variables) {
        throw std::invalid_argument(
            "LaminateLaned: packed point has the wrong dimension");
    }

    const std::size_t padding_variables =
        total_variables - wire_variables - lane_variables;
    LanedPointCoordinates result;
    for (std::size_t variable = 0; variable < padding_variables; ++variable) {
        result.padding_weight *= Fpk::one() - point[variable];
    }
    const auto wire_begin =
        point.begin() + static_cast<std::ptrdiff_t>(padding_variables);
    const auto lane_begin =
        wire_begin + static_cast<std::ptrdiff_t>(wire_variables);
    result.wire.assign(wire_begin, lane_begin);
    result.lane.assign(lane_begin, point.end());
    return result;
}

} // namespace laminate::gkr::laned_detail

#endif // LAMINATE_GKR_DETAIL_LANED_GEOMETRY_POINT_HPP
