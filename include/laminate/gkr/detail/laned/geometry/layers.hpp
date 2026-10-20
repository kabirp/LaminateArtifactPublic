#ifndef LAMINATE_GKR_DETAIL_LANED_GEOMETRY_LAYERS_HPP
#define LAMINATE_GKR_DETAIL_LANED_GEOMETRY_LAYERS_HPP

/// @file layers.hpp
/// @brief Public packed-layer geometry helpers for LaminateLaned.

#include "laminate/fhe/value.hpp"
#include "laminate/gkr/claims.hpp"
#include "laminate/gkr/detail/laned/geometry/layout.hpp"
#include "laminate/payload/ir/layered.hpp"
#include "laminate/poly/eq.hpp"

#include <cstddef>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

namespace laminate::gkr {

inline packing::LanedPackingLayout
laned_layout(const payload::LayeredCircuit &circuit, std::size_t layer) {
    if (circuit.shape.kind != payload::PayloadKind::Laned ||
        layer >= circuit.layers.size()) {
        throw std::invalid_argument(
            "laned_layout: expected a valid laned layer");
    }
    return packing::LanedPackingLayout::create(
        circuit.shape,
        payload::layer_dimensions(circuit.layers[layer]).padded_size);
}

inline std::size_t
laned_layer_variables(const payload::LayeredCircuit &circuit,
                      std::size_t layer) {
    return laned_detail::layout_variables(laned_layout(circuit, layer));
}

inline Fpk evaluate_packed_laned_layer(
    std::span<const fhe::SlotVector> layer,
    const packing::LanedPackingLayout &layout,
    std::span<const Fpk> point) {
    if (layer.size() != layout.original_wire_count ||
        point.size() != laned_detail::layout_variables(layout)) {
        throw std::invalid_argument(
            "evaluate_packed_laned_layer: layer or point shape mismatch");
    }
    const std::size_t ciphertext_variables = laned_detail::log2_exact(
        layout.padded_ciphertext_count,
        "evaluate_packed_laned_layer ciphertext variables");
    const std::vector<Fpk> ciphertext_point(
        point.begin(), point.begin() +
                           static_cast<std::ptrdiff_t>(ciphertext_variables));
    const std::vector<Fpk> slot_point(
        point.begin() + static_cast<std::ptrdiff_t>(ciphertext_variables),
        point.end());
    const std::vector<Fpk> ciphertext_weights =
        poly::eq_evaluations(ciphertext_point);
    const std::vector<Fpk> slot_weights = poly::eq_evaluations(slot_point);

    // The packed address is (ciphertext, slot), so factor the terminal MLE as
    //
    //   V~(r_c,r_s) = sum_c eq(r_c,c)
    //                       * [sum_s eq(r_s,s) V_packed[c,s]].
    //
    // The inner sums need only extension-by-base products. Empty padded cells
    // contribute zero without ever materializing a padded plaintext table.
    std::vector<Fpk> slot_evaluations(
        layout.padded_ciphertext_count, Fpk::zero());
    for (std::size_t wire = 0; wire < layer.size(); ++wire) {
        if (layer[wire].size() != layout.lane_count) {
            throw std::invalid_argument(
                "evaluate_packed_laned_layer: logical lane width mismatch");
        }
        for (std::size_t lane = 0; lane < layout.lane_count; ++lane) {
            const packing::LanedPackedAddress address =
                layout.address(wire, lane);
            slot_evaluations[address.ciphertext] +=
                slot_weights[address.slot] * layer[wire][lane];
        }
    }
    Fpk result = Fpk::zero();
    for (std::size_t ciphertext = 0;
         ciphertext < slot_evaluations.size(); ++ciphertext) {
        result += ciphertext_weights[ciphertext] *
                  slot_evaluations[ciphertext];
    }
    return result;
}

inline SingleClaim make_packed_laned_claim(
    std::span<const fhe::SlotVector> layer,
    const packing::LanedPackingLayout &layout, std::vector<Fpk> point) {
    const Fpk value = evaluate_packed_laned_layer(layer, layout, point);
    return SingleClaim{std::move(point), value};
}

} // namespace laminate::gkr

#endif // LAMINATE_GKR_DETAIL_LANED_GEOMETRY_LAYERS_HPP
