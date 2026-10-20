#ifndef LAMINATE_GKR_DETAIL_BASE_AFFINE_PARTIAL_GATE_MLE_HPP
#define LAMINATE_GKR_DETAIL_BASE_AFFINE_PARTIAL_GATE_MLE_HPP

/// @file partial_gate_mle.hpp
/// @brief Structured Boolean tables for Base's remaining slot variables.

#include "laminate/fhe/layout/slot_grid.hpp"
#include "laminate/gates/gate_mle.hpp"
#include "laminate/gkr/base.hpp"
#include "laminate/gkr/claims.hpp"
#include "laminate/gkr/detail/base/geometry/circuit.hpp"
#include "laminate/poly/eq.hpp"

#include <map>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace laminate::gkr::base_detail {
namespace partial_gate_detail {

struct SplitPoint {
    std::span<const Fpk> wire;
    std::span<const Fpk> slot;
};

inline SplitPoint split_point(std::span<const Fpk> point,
                              std::size_t wire_count,
                              std::size_t slot_count,
                              const char *operation) {
    const std::size_t wire_variables = log2_exact(wire_count, operation);
    const std::size_t slot_variables = log2_exact(slot_count, operation);
    if (point.size() != wire_variables + slot_variables) {
        throw std::invalid_argument(std::string(operation) +
                                    ": point dimension mismatch");
    }
    return SplitPoint{
        point.first(wire_variables), point.subspan(wire_variables)};
}

inline const payload::AffineLayer &affine_layer(
    const payload::LayeredCircuit &circuit, std::size_t layer) {
    if (layer + 1 >= circuit.layers.size() ||
        !std::holds_alternative<payload::AffineLayer>(
            circuit.layers[layer])) {
        throw std::invalid_argument(
            "Base partial GateMLE: layer is not affine");
    }
    return std::get<payload::AffineLayer>(circuit.layers[layer]);
}


} // namespace partial_gate_detail

/// Construct `h(u)=G(claim; fixed_wire,u)` on the Boolean slot cube.
///
/// Preconditions:
/// - `layer` names an affine layer;
/// - `fixed_wire` has the source-wire dimension;
/// - every carried output claim has the layer's full wide dimension.
///
/// Postcondition: the result contains exactly `circuit.shape.value_width()`
/// extension-field values, derived by reverse propagation through the local
/// affine DAG without expanding source-to-output paths.
inline PartialGateMleVector make_affine_partial_gate_mle(
    const payload::LayeredCircuit &circuit, std::size_t layer,
    const LayerClaim &claim, std::span<const Fpk> fixed_wire) {
    (void)partial_gate_detail::affine_layer(circuit, layer);
    const std::size_t source_wires =
        payload::layer_dimensions(circuit.layers[layer + 1]).padded_size;
    if (fixed_wire.size() !=
        log2_exact(source_wires, "Base affine partial GateMLE source")) {
        throw std::invalid_argument(
            "Base affine partial GateMLE source dimension mismatch");
    }
    PartialGateMleVector result{
        std::vector<Fpk>(circuit.shape.value_width(), Fpk::zero())};
    const gates::DirectGateMle provider(circuit);
    const auto add_claim = [&](const SingleClaim &single, const Fpk &weight) {
        const auto values = provider.prepare_affine(layer, single.point)
                                .evaluate_boolean_source_slots(fixed_wire);
        for (std::size_t slot = 0; slot < values.size(); ++slot) {
            result.evaluations[slot] += weight * values[slot];
        }
    };
    if (const auto *single = std::get_if<SingleClaim>(&claim)) {
        add_claim(*single, Fpk::one());
    } else {
        const BatchedClaim &batch = std::get<BatchedClaim>(claim);
        add_claim(batch.first, Fpk::one());
        add_claim(batch.second, batch.challenge);
    }
    return result;
}

} // namespace laminate::gkr::base_detail

#endif // LAMINATE_GKR_DETAIL_BASE_AFFINE_PARTIAL_GATE_MLE_HPP
