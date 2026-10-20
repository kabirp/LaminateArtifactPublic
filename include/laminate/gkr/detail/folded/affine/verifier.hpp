#ifndef LAMINATE_GKR_DETAIL_FOLDED_AFFINE_VERIFIER_HPP
#define LAMINATE_GKR_DETAIL_FOLDED_AFFINE_VERIFIER_HPP

/// @file verifier.hpp
/// @brief Plaintext verification of one LaminateFolded affine reduction.

#include "laminate/gkr/folded.hpp"
#include "laminate/gkr/detail/base/claims/evaluation.hpp"
#include "laminate/gkr/detail/folded/affine/types.hpp"
#include "laminate/gkr/detail/shared/packed/affine_verifier.hpp"

#include <cstddef>
#include <optional>
#include <utility>
#include <vector>

namespace laminate::gkr::folded_detail {

/// Folded-specific arithmetic for the packed affine verifier recurrence.
///
/// For source polynomial `W` and the public affine gate polynomial `G`, the
/// reduction starts from
///
///     claim_0 = output_claim - affine_constant
///             = sum_u G(output_point, u) W(u).
///
/// Each round reads `R_j(1), R_j(2)`, recovers
/// `R_j(0) = claim_j - R_j(1)`, and carries
/// `claim_{j+1} = R_j(r_j)`. At the terminal point, Folded checks
///
///     GateMLE(claim point, challenges) * SourceMLE(challenges)
///         == running claim.
template <typename GateProvider> class FoldedAffineVerifierArithmetic {
  public:
    FoldedAffineVerifierArithmetic(
        const payload::LayeredCircuit &circuit, std::size_t layer,
        const LayerClaim &claim, GateProvider &provider)
        : reduction_layer_(layer), output_claim_(claim),
          gate_mle_(provider),
          geometry_(FoldedAffineReductionGeometry::create(circuit, layer)) {}

    std::size_t round_count() const { return geometry_.round_count; }

    std::size_t ciphertext_index_round_count() const {
        return geometry_.ciphertext_index_variables;
    }

    std::size_t slot_index_round_count() const {
        return geometry_.slot_index_variables;
    }

    Fpk initial_claim() {
        // The provider records the public affine-constant opening before the
        // shared verifier binds the reduction header.
        return base_detail::claim_value(output_claim_) -
               base_detail::affine_constant_at(
                   gate_mle_, reduction_layer_, output_claim_);
    }

    Fpk sample_challenge(std::size_t, Transcript &transcript) const {
        return transcript.challenge_fpk();
    }

    std::optional<SingleClaim> finish_terminal(
        std::vector<Fpk> challenges, const Fpk &source,
        const Fpk &running_claim) {
        // After every source coordinate is fixed, the sumcheck identity is
        //   running_claim = G(output_point, challenges) * W(challenges).
        // `source` is the verifier-decoded terminal value W(challenges).
        const Fpk gate = base_detail::affine_gate_at(
            gate_mle_, reduction_layer_, output_claim_, challenges);
        if (gate * source != running_claim) {
            return std::nullopt;
        }
        return SingleClaim{std::move(challenges), source};
    }

  private:
    /// Circuit layer whose output claim is being reduced.
    std::size_t reduction_layer_;
    /// Claim at the output of `reduction_layer_`; immutable for all rounds.
    const LayerClaim &output_claim_;
    /// Public or outsourced GateMLE provider used at the two protocol edges.
    GateProvider &gate_mle_;
    /// Public ciphertext-index/slot-index split for this source layer.
    FoldedAffineReductionGeometry geometry_;
};

/// Verify one Folded affine reduction and return its source claim on success.
template <fhe::FheBackend Backend, typename Reader, typename Message,
          typename GateProvider>
std::optional<SingleClaim> verify_affine_reduction(
    Reader &reader,
    const payload::LayeredCircuit &circuit, std::size_t layer,
    const LayerClaim &claim,
    const FoldedAffineLayerReduction<Message> &proof,
    GateProvider &provider, Transcript &transcript) {
    // Step 1: Construct Folded's public GateMLE and terminal-claim arithmetic.
    using VerifierArithmetic = FoldedAffineVerifierArithmetic<GateProvider>;
    VerifierArithmetic arithmetic(circuit, layer, claim, provider);

    // Step 2: Replay the messages in proof order. The shared recurrence binds
    // R_j(1),R_j(2), reconstructs R_j(0)=claim_j-R_j(1), samples r_j, and
    // carries claim_{j+1}=R_j(r_j) into the next round.
    return ::laminate::gkr::detail::PackedAffineVerifier<
               ProtocolVariant::LaminateFolded, Backend, Reader, Message,
               VerifierArithmetic>(reader, layer, proof, transcript,
                                   std::move(arithmetic))
        .run();
}

} // namespace laminate::gkr::folded_detail

#endif // LAMINATE_GKR_DETAIL_FOLDED_AFFINE_VERIFIER_HPP
