#ifndef LAMINATE_GKR_DETAIL_LANED_AFFINE_GATE_CLAIM_HPP
#define LAMINATE_GKR_DETAIL_LANED_AFFINE_GATE_CLAIM_HPP

/// @file gate_claim.hpp
/// @brief Public GateMLE factors in a Laned affine layer reduction.

#include "laminate/gates/gate_mle.hpp"
#include "laminate/gkr/claims.hpp"
#include "laminate/gkr/detail/laned/geometry/point.hpp"

#include <span>
#include <stdexcept>
#include <vector>

namespace laminate::gkr::laned_detail {

template <typename Provider>
Fpk affine_wire_for_claim(
    Provider &provider, std::size_t layer,
    const packing::LanedPackingLayout &output_layout,
    const SingleClaim &claim, const LanedPointCoordinates &source) {
    const LanedPointCoordinates output =
        split_laned_point(output_layout, claim.point);
    return output.padding_weight * source.padding_weight *
           provider.evaluate(gates::GateMleQuery{
               gates::LanedAffineWireQuery{layer, output.wire, source.wire}});
}

/// Evaluate the batched affine wiring MLE at one packed source point.
template <typename Provider>
Fpk affine_wire_at(
    Provider &provider, std::size_t layer,
    const packing::LanedPackingLayout &output_layout,
    const packing::LanedPackingLayout &source_layout,
    const LayerClaim &claim, std::span<const Fpk> source_point) {
    const LanedPointCoordinates source =
        split_laned_point(source_layout, source_point);
    if (const auto *single = std::get_if<SingleClaim>(&claim)) {
        return affine_wire_for_claim(provider, layer, output_layout, *single,
                                     source);
    }
    const BatchedClaim &batched = std::get<BatchedClaim>(claim);
    return affine_wire_for_claim(provider, layer, output_layout,
                                 batched.first, source) +
           batched.challenge *
               affine_wire_for_claim(provider, layer, output_layout,
                                     batched.second, source);
}

template <typename Provider>
Fpk affine_constant_for_claim(
    Provider &provider, std::size_t layer,
    const packing::LanedPackingLayout &output_layout,
    const SingleClaim &claim) {
    const LanedPointCoordinates output =
        split_laned_point(output_layout, claim.point);
    std::vector<Fpk> active_output_point;
    active_output_point.reserve(output.wire.size() + output.lane.size());
    active_output_point.insert(active_output_point.end(),
                               output.wire.begin(), output.wire.end());
    active_output_point.insert(active_output_point.end(),
                               output.lane.begin(), output.lane.end());
    return output.padding_weight * provider.evaluate_affine_constant(
                                       layer, active_output_point);
}

/// Evaluate the public affine constant contribution to the current claim.
template <typename Provider>
Fpk affine_constant_at(
    Provider &provider, std::size_t layer,
    const packing::LanedPackingLayout &output_layout,
    const LayerClaim &claim) {
    if (const auto *single = std::get_if<SingleClaim>(&claim)) {
        return affine_constant_for_claim(provider, layer, output_layout,
                                         *single);
    }
    const BatchedClaim &batched = std::get<BatchedClaim>(claim);
    return affine_constant_for_claim(provider, layer, output_layout,
                                     batched.first) +
           batched.challenge * affine_constant_for_claim(
                                   provider, layer, output_layout,
                                   batched.second);
}

/// Return the lane point shared by every claim in one Laned affine batch.
inline std::vector<Fpk> common_lane_point(
    const packing::LanedPackingLayout &layout, const LayerClaim &claim) {
    if (const auto *single = std::get_if<SingleClaim>(&claim)) {
        return split_laned_point(layout, single->point).lane;
    }
    const BatchedClaim &batched = std::get<BatchedClaim>(claim);
    const std::vector<Fpk> first =
        split_laned_point(layout, batched.first.point).lane;
    const std::vector<Fpk> second =
        split_laned_point(layout, batched.second.point).lane;
    if (first != second) {
        throw std::invalid_argument(
            "LaminateLaned affine batch does not share a lane point");
    }
    return first;
}

} // namespace laminate::gkr::laned_detail

#endif // LAMINATE_GKR_DETAIL_LANED_AFFINE_GATE_CLAIM_HPP
