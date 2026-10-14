#ifndef LAMINATE_GKR_LAYER_REDUCTION_SUMCHECK_HPP
#define LAMINATE_GKR_LAYER_REDUCTION_SUMCHECK_HPP

/// @file layer_reduction_sumcheck.hpp
/// @brief Plaintext reference sumchecks for Laminate layer reductions.
///
/// This is the plaintext correctness oracle for the encrypted prover. Each
/// round is recomputed from the original input tables using public prefix
/// weights; no table folded in one round is carried into the next. Affine
/// messages send R(1), R(2). Equality-stripped multiplication sends R(2) and
/// the nonsingular Boolean endpoint, from which the verifier recovers the
/// other endpoint.

#include "laminate/field/fpk.hpp"
#include "laminate/poly/multilinear.hpp"
#include "laminate/transcript/transcript.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <span>
#include <vector>

namespace laminate::gkr {

struct LayerReductionSumcheckRound {
    /// Affine rounds send R(1). Equality-stripped multiplication sends R(0),
    /// except at tau=0 where it sends R(1) to avoid division by zero.
    Fpk at_endpoint = Fpk::zero();
    /// Evaluation R(2), which completes the degree-two polynomial.
    Fpk at_two = Fpk::zero();

    bool operator==(const LayerReductionSumcheckRound &) const = default;
};

struct LayerReductionSumcheckProof {
    std::vector<LayerReductionSumcheckRound> rounds;

    bool operator==(const LayerReductionSumcheckProof &) const = default;
};

struct ProvedLayerReductionSumcheck {
    LayerReductionSumcheckProof proof;
    /// Fiat-Shamir state, not serialized proof data.
    std::vector<Fpk> challenges;
};

/// Sumcheck only reduces a hypercube-sum claim to an oracle claim at a random
/// point. Structural validity is not acceptance: callers must compare the
/// reduced claim with the terminal layer-reduction oracle via `accepts`.
struct VerifiedLayerReductionSumcheck {
    bool structurally_valid = false;
    std::vector<Fpk> challenges;
    Fpk final_claim = Fpk::zero();

    bool accepts(const Fpk &terminal_oracle) const {
        return structurally_valid && final_claim == terminal_oracle;
    }
};

/// Plaintext correctness oracle for the affine layer-reduction sumcheck.
/// The target-scale encrypted prover uses the same relation with a specialized
/// schedule; this reference implementation recomputes each round from source
/// tables so sumcheck rounds do not accumulate multiplicative depth.
class AffineLayerReductionSumcheck {
  public:
    static ProvedLayerReductionSumcheck
    prove(const poly::Multilinear<Fpk> &affine_coefficients,
          const poly::Multilinear<Fpk> &source_layer_values,
          Transcript &transcript);

    static VerifiedLayerReductionSumcheck
    verify(const LayerReductionSumcheckProof &proof,
           const Fpk &adjusted_claim, std::size_t source_variables,
           Transcript &transcript);
};

/// Plaintext correctness oracle for the dense multiplication layer reduction.
/// The public equality polynomial is stripped from the suffix rounds, so the
/// terminal claim is compared with the stripped relation. This is a Laminate
/// protocol detail; the
/// generic equality-stripping machinery remains private to the implementation.
class MultiplicationLayerReductionSumcheck {
  public:
    using Oracle = std::function<Fpk(std::span<const Fpk>)>;

    static ProvedLayerReductionSumcheck
    prove(std::size_t ciphertext_index_variables,
          const std::vector<Fpk> &output_claim_point,
          const Oracle &multiplication_relation,
          const Oracle &stripped_multiplication_relation,
          Transcript &transcript);

    static VerifiedLayerReductionSumcheck
    verify(const LayerReductionSumcheckProof &proof, const Fpk &claimed_sum,
           std::size_t ciphertext_index_variables,
           const std::vector<Fpk> &output_claim_point,
           Transcript &transcript);
};

} // namespace laminate::gkr

#endif // LAMINATE_GKR_LAYER_REDUCTION_SUMCHECK_HPP
