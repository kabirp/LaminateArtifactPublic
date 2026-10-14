#ifndef LAMINATE_GKR_DETAIL_LANED_MULTIPLICATION_TYPES_HPP
#define LAMINATE_GKR_DETAIL_LANED_MULTIPLICATION_TYPES_HPP

/// @file types.hpp
/// @brief Protocol objects shared by file-backed and reference multiplication.

#include "laminate/gkr/laned.hpp"
#include "laminate/gkr/detail/shared/dense_multiplication/geometry.hpp"
#include "laminate/poly/eq.hpp"

#include <cstddef>
#include <stdexcept>
#include <vector>

namespace laminate::gkr::laned_detail {

/// Result of proving one multiplication layer. `next_claim` carries plaintext
/// zero as a placeholder because the encrypted prover cannot decrypt its
/// terminal message; verification computes the interpolated source value.
template <fhe::FheBackend Backend>
struct LanedMultiplicationLayerReductionResult {
    EncryptedLanedMultiplicationLayerReduction<Backend> proof;
    SingleClaim next_claim;
};

/// Public geometry of `Out(x,s) = Src(0,x,s) * Src(1,x,s)` for Laned.
/// The structural left/right selector is not itself a sumcheck variable.
struct LanedMultiplicationLayerReductionGeometry {
    /// Packing of the multiplication outputs named by the input claim.
    packing::LanedPackingLayout output;
    /// Packing of the dense `[left | right]` source layer.
    packing::LanedPackingLayout source;
    /// Sumcheck variables selecting one left/right pair.
    std::size_t ciphertext_index_variables = 0;
    /// Sumcheck variables selecting one SIMD slot.
    std::size_t slot_index_variables = 0;
    /// Total ciphertext-index and slot-index rounds; the selector is not one.
    std::size_t round_count = 0;
    /// Number of componentwise products in the padded output layer.
    std::size_t pair_count = 0;
    /// Slot-coordinate suffix of the claimed output point.
    std::vector<Fpk> output_slot;
    /// Public equality weights applied during ciphertext-index rounds.
    std::vector<Fpk> output_slot_weights;

    static LanedMultiplicationLayerReductionGeometry create(
        const payload::LayeredCircuit &circuit, std::size_t layer,
        const SingleClaim &claim) {
        LanedMultiplicationLayerReductionGeometry result;
        result.output = laned_layout(circuit, layer);
        result.source = laned_layout(circuit, layer + 1U);
        const auto dimensions =
            ::laminate::gkr::detail::DenseMultiplicationDimensions::create(
                result.output.padded_ciphertext_count,
                result.source.padded_ciphertext_count,
                result.output.slot_count);
        result.ciphertext_index_variables =
            dimensions.ciphertext_index_variables;
        result.slot_index_variables = dimensions.slot_index_variables;
        result.round_count = dimensions.round_count();
        result.pair_count = result.output.padded_ciphertext_count;
        if (claim.point.size() != result.round_count) {
            throw std::invalid_argument(
                "LaminateLaned multiplication claim dimension mismatch");
        }
        result.output_slot.assign(
            claim.point.begin() +
                static_cast<std::ptrdiff_t>(result.ciphertext_index_variables),
            claim.point.end());
        result.output_slot_weights = poly::eq_evaluations(result.output_slot);
        return result;
    }
};

} // namespace laminate::gkr::laned_detail

#endif // LAMINATE_GKR_DETAIL_LANED_MULTIPLICATION_TYPES_HPP
