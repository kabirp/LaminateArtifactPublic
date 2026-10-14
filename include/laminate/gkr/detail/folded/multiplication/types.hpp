#ifndef LAMINATE_GKR_DETAIL_FOLDED_MULTIPLICATION_TYPES_HPP
#define LAMINATE_GKR_DETAIL_FOLDED_MULTIPLICATION_TYPES_HPP

/// @file types.hpp
/// @brief Folded dense-multiplication result and public reduction geometry.

#include "laminate/gkr/folded.hpp"
#include "laminate/gkr/detail/shared/dense_multiplication/geometry.hpp"
#include "laminate/poly/eq.hpp"

#include <cstddef>
#include <stdexcept>
#include <vector>

namespace laminate::gkr::folded_detail {

/// Output of one encrypted Folded multiplication reduction.
///
/// `proof` contains the equality-stripped sumcheck messages and the two
/// terminal source evaluations. The encrypted prover knows the interpolated
/// next-claim point but cannot decrypt its value, so `next_claim` carries a
/// public-zero placeholder. Verification computes its plaintext value.
template <fhe::FheBackend Backend>
struct FoldedMultiplicationReductionResult {
    /// Messages appended to the enclosing Folded GKR proof.
    EncryptedFoldedMultiplicationLayerReduction<Backend> proof;
    /// Single source claim obtained by interpolating the left/right selector.
    SingleClaim next_claim;
};

/// Geometry of
///
///   Out(x,s) = Src(0,x,s) Src(1,x,s).
///
/// The leading source coordinate is structural and is not a sumcheck round.
struct FoldedMultiplicationReductionGeometry {
    /// Number of ciphertext-index coordinates reduced first.
    std::size_t ciphertext_index_variables = 0;
    /// Number of packed SIMD-slot coordinates reduced after the checkpoint.
    std::size_t slot_index_variables = 0;
    /// Total rounds: ciphertext-index plus slot-index coordinates.
    std::size_t round_count = 0;
    /// Padded number of logical `(left, right)` source pairs.
    std::size_t pair_count = 0;
    /// Slot suffix of the incoming output claim.
    std::vector<Fpk> output_slot;
    /// Boolean equality table `eq(output_slot, slot)` used for slot folding.
    std::vector<Fpk> output_slot_weights;

    static FoldedMultiplicationReductionGeometry create(
        const payload::LayeredCircuit &circuit, std::size_t layer,
        const SingleClaim &claim) {
        if (layer + 1U >= circuit.layers.size() ||
            payload::layer_kind(circuit.layers[layer]) !=
                payload::LayerKind::Multiplication) {
            throw std::invalid_argument(
                "LaminateFolded dense multiplication names no layer");
        }
        const payload::LayerDimensions output =
            payload::layer_dimensions(circuit.layers[layer]);
        const payload::LayerDimensions source =
            payload::layer_dimensions(circuit.layers[layer + 1U]);
        const auto dimensions =
            ::laminate::gkr::detail::DenseMultiplicationDimensions::create(
                output.padded_size, source.padded_size,
                circuit.shape.value_width());
        if (claim.point.size() != dimensions.round_count()) {
            throw std::invalid_argument(
                "LaminateFolded dense multiplication claim dimension "
                "mismatch");
        }

        FoldedMultiplicationReductionGeometry result;
        result.ciphertext_index_variables =
            dimensions.ciphertext_index_variables;
        result.slot_index_variables = dimensions.slot_index_variables;
        result.round_count = dimensions.round_count();
        result.pair_count = output.padded_size;
        result.output_slot.assign(
            claim.point.begin() +
                static_cast<std::ptrdiff_t>(result.ciphertext_index_variables),
            claim.point.end());
        result.output_slot_weights =
            poly::eq_evaluations(result.output_slot);
        return result;
    }
};

} // namespace laminate::gkr::folded_detail

#endif // LAMINATE_GKR_DETAIL_FOLDED_MULTIPLICATION_TYPES_HPP
