#ifndef LAMINATE_GKR_DETAIL_BASE_MULTIPLICATION_TYPES_HPP
#define LAMINATE_GKR_DETAIL_BASE_MULTIPLICATION_TYPES_HPP

/// @file types.hpp
/// @brief Semantic values and public geometry for Base multiplication layers.

#include "laminate/gkr/base.hpp"
#include "laminate/gkr/claims.hpp"
#include "laminate/gkr/detail/shared/dense_multiplication/geometry.hpp"
#include "laminate/gkr/detail/shared/dense_multiplication/rounds.hpp"
#include "laminate/gkr/detail/shared/dense_multiplication/source/paired.hpp"
#include "laminate/gkr/detail/shared/reduction/sumcheck.hpp"
#include "laminate/poly/eq.hpp"

#include <cstddef>
#include <stdexcept>
#include <vector>

namespace laminate::gkr::base_detail {

/// Public evaluation points carried by one equality-stripped multiplication
/// round. `primary_endpoint` is S_j(0), except when tau_j=0 where sending
/// S_j(1) avoids division by zero; the second value is always S_j(2).
inline ::laminate::gkr::detail::LayerReductionRoundPoints
multiplication_round_points(const Fpk &tau) {
    return {
        ::laminate::gkr::detail::dense_multiplication_primary_point(tau),
        Fpk::from_base(Fp(2))};
}

/// Encrypted values emitted by one multiplication FHE scan.
template <fhe::FheBackend Backend>
using EncryptedMultiplicationRoundEvaluations =
    ::laminate::gkr::detail::TransmittedLayerReductionRound<
        fhe::ExtensionValue<Backend>>;

/// Decrypted scalar values used to advance one verifier round.
struct DecodedMultiplicationRoundEvaluations {
    Fpk at_primary_endpoint;
    Fpk at_two;
};

/// Left and right source MLE vectors after all ciphertext-index coordinates
/// are fixed.
template <fhe::FheBackend Backend>
using EncryptedMultiplicationSourceValues =
    ::laminate::gkr::detail::MultiplicationSlotCheckpoints<Backend>;

/// Decrypted terminal left/right vectors, still indexed by SIMD slot.
struct DecodedMultiplicationSourceValues {
    std::vector<Fpk> left;
    std::vector<Fpk> right;
};

/// Mutable verifier state after fixing a prefix of source ciphertext-index
/// coordinates.
struct MultiplicationVerificationState {
    /// Current equality-stripped sumcheck claim S_j(r_0,...,r_{j-1}).
    Fpk reduced_claim;
    /// Fiat--Shamir ciphertext-index point fixed by verified rounds.
    std::vector<Fpk> ciphertext_index_challenges;
};

template <fhe::FheBackend Backend> struct ProvedMultiplication {
    /// Complete reduction message in canonical transcript order.
    EncryptedBaseMultiplicationLayerReduction<Backend> proof;
    /// Single source claim after interpolation in the selector coordinate.
    SingleClaim next_claim;
};

/// Public geometry of
///
///   output(x,s) = source(0,x,s) source(1,x,s).
///
/// The multiplication layer has M outputs and its source has exactly 2M
/// entries, laid out as `[left half | right half]`. Unlike the former sparse
/// gate relation, this fixed wiring has no multiplication GateMLE.
struct MultiplicationGeometry {
    /// Number of ciphertext-index coordinates reduced under FHE.
    std::size_t ciphertext_index_variables = 0;
    /// Number of SIMD coordinates completed by the client after decryption.
    std::size_t slot_index_variables = 0;
    /// Number of encrypted messages; equal to `ciphertext_index_variables`.
    std::size_t round_count = 0;
    /// Number M of active multiplication pairs `[L_i, R_i]`.
    std::size_t pair_count = 0;
    /// Output-claim coordinates tau restricted to the M ciphertext indices.
    std::vector<Fpk> output_ciphertext_index;
    /// Output-claim coordinates restricted to the SIMD slots.
    std::vector<Fpk> output_slot;
    /// Public eq(output_slot, s) weights used for client slot completion.
    std::vector<Fpk> output_slot_weights;

    static MultiplicationGeometry create(
        const payload::LayeredCircuit &circuit, std::size_t layer,
        const SingleClaim &claim) {
        const payload::LayerStorageLayout storage =
            payload::canonical_layer_storage_layout(circuit, layer + 1U);
        return create(circuit, layer, claim, storage);
    }

    static MultiplicationGeometry create(
        const payload::LayeredCircuit &circuit, std::size_t layer,
        const SingleClaim &claim,
        const payload::LayerStorageLayout &source_storage) {
        if (layer + 1U >= circuit.layers.size() ||
            !std::holds_alternative<payload::MultiplicationLayer>(
                circuit.layers[layer])) {
            throw std::invalid_argument(
                "LaminateBase dense multiplication layer mismatch");
        }
        const auto output =
            payload::layer_dimensions(circuit.layers[layer]);
        const auto source =
            payload::layer_dimensions(circuit.layers[layer + 1U]);
        const auto dimensions =
            ::laminate::gkr::detail::DenseMultiplicationDimensions::create(
                output.padded_size, source.padded_size,
                circuit.shape.value_width());
        if (claim.point.size() !=
            dimensions.ciphertext_index_variables +
                dimensions.slot_index_variables) {
            throw std::invalid_argument(
                "LaminateBase dense multiplication claim dimension "
                "mismatch");
        }
        MultiplicationGeometry result;
        result.ciphertext_index_variables =
            dimensions.ciphertext_index_variables;
        result.slot_index_variables = dimensions.slot_index_variables;
        // Base leaves the N SIMD slots packed. Only the M ciphertext indices
        // enter encrypted sumcheck; the client evaluates each decrypted slot
        // vector at the public output-slot point.
        result.round_count = dimensions.ciphertext_index_variables;
        result.pair_count = output.padded_size;
        result.output_ciphertext_index.assign(
            claim.point.begin(),
            claim.point.begin() +
                static_cast<std::ptrdiff_t>(result.ciphertext_index_variables));
        result.output_slot.assign(
            claim.point.begin() +
                static_cast<std::ptrdiff_t>(result.ciphertext_index_variables),
            claim.point.end());
        result.output_slot_weights =
            poly::eq_evaluations(result.output_slot);
        // This also validates every canonical `(i, M+i)` gate and excludes
        // structural padding from the active pair metadata.
        (void)::laminate::gkr::detail::make_dense_paired_source_metadata(
            std::get<payload::MultiplicationLayer>(circuit.layers[layer]),
            source.padded_size, source_storage);
        return result;
    }
};

} // namespace laminate::gkr::base_detail

#endif // LAMINATE_GKR_DETAIL_BASE_MULTIPLICATION_TYPES_HPP
