#ifndef LAMINATE_GKR_LAYER_REDUCTIONS_HPP
#define LAMINATE_GKR_LAYER_REDUCTIONS_HPP

/// @file layer_reductions.hpp
/// @brief Plaintext reference reductions for alternating Laminate layers.

#include "laminate/gates/gate_mle.hpp"
#include "laminate/gkr/claims.hpp"
#include "laminate/gkr/layer_reduction_sumcheck.hpp"
#include "laminate/payload/trace.hpp"

#include <cstddef>
#include <optional>

namespace laminate::gkr {

struct AffineLayerReductionProof {
    LayerReductionSumcheckProof sumcheck;
    Fpk source_value = Fpk::zero();

    bool operator==(const AffineLayerReductionProof &) const = default;
};

struct MultiplicationLayerReductionProof {
    LayerReductionSumcheckProof sumcheck;
    Fpk left_value = Fpk::zero();
    Fpk right_value = Fpk::zero();

    bool operator==(const MultiplicationLayerReductionProof &) const = default;
};

struct ProvedAffineLayerReduction {
    AffineLayerReductionProof proof;
    SingleClaim next_claim;
};

struct ProvedMultiplicationLayerReduction {
    MultiplicationLayerReductionProof proof;
    SingleClaim next_claim;
};

ProvedAffineLayerReduction prove_affine_layer_reduction(
    const payload::LayeredCircuit &circuit, const payload::PlainTrace &trace,
    std::size_t layer_index, const LayerClaim &current_claim,
    const gates::DirectGateMle &gate_mles, Transcript &transcript);

std::optional<SingleClaim> verify_affine_layer_reduction(
    const payload::LayeredCircuit &circuit, std::size_t layer_index,
    const LayerClaim &current_claim, const AffineLayerReductionProof &proof,
    const gates::DirectGateMle &gate_mles, Transcript &transcript);

ProvedMultiplicationLayerReduction prove_multiplication_layer_reduction(
    const payload::LayeredCircuit &circuit, const payload::PlainTrace &trace,
    std::size_t layer_index, const SingleClaim &current_claim,
    Transcript &transcript);

std::optional<SingleClaim> verify_multiplication_layer_reduction(
    const payload::LayeredCircuit &circuit, std::size_t layer_index,
    const SingleClaim &current_claim,
    const MultiplicationLayerReductionProof &proof, Transcript &transcript);

} // namespace laminate::gkr

#endif // LAMINATE_GKR_LAYER_REDUCTIONS_HPP
