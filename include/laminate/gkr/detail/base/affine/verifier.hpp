#ifndef LAMINATE_GKR_DETAIL_BASE_AFFINE_VERIFIER_HPP
#define LAMINATE_GKR_DETAIL_BASE_AFFINE_VERIFIER_HPP

/// @file verifier.hpp
/// @brief Client verification of one Base affine layer reduction.

#include "laminate/gkr/detail/base/affine/types.hpp"
#include "laminate/gkr/detail/base/arithmetic/reduction.hpp"
#include "laminate/gkr/detail/base/claims/evaluation.hpp"
#include "laminate/gkr/detail/base/transcript/reduction.hpp"
#include "laminate/gkr/detail/base/verification/diagnostic.hpp"
#include "laminate/gkr/detail/shared/reduction/gate_claims.hpp"
#include "laminate/poly/eq.hpp"

#include <optional>
#include <span>
#include <vector>

namespace laminate::gkr::base_detail {

/// Verifies one LaminateBase affine reduction:
///
///   claim - constant = sum_u GateMLE(output, u) W(u).
///
/// Base leaves SIMD slots packed in every proof message. The client decrypts
/// each vector, sums its slots for the ciphertext-index recurrence, then checks
/// the terminal source inner product and the authenticated partial GateMLE at
/// the fresh slot challenge.
template <fhe::FheBackend Backend, typename Reader,
          typename GateProvider>
class BaseAffineLayerVerifier {
  public:
    BaseAffineLayerVerifier(
        Reader &reader, const payload::LayeredCircuit &circuit,
        std::size_t layer, const LayerClaim &claim,
        const EncryptedBaseAffineLayerReduction<Backend> &proof,
        GateProvider &provider, Transcript &transcript)
        : reader_(reader), layer_(layer), claim_(claim), proof_(proof),
          provider_(provider), transcript_(transcript),
          geometry_(AffineGeometry::create(circuit, layer)) {
        state_.ciphertext_index_challenges.reserve(
            geometry_.ciphertext_index_variables);
    }

    /// Replay the ciphertext-index sumcheck, check its terminal source
    /// relation, and authenticate the partial GateMLE at a fresh slot point.
    std::optional<SingleClaim> run() {
        // Step 1: reject malformed round geometry before reading proof data.
        if (proof_.rounds.size() !=
            geometry_.ciphertext_index_variables) {
            base_verifier_diagnostic().detail =
                "sumcheck round count does not match the layer geometry";
            return std::nullopt;
        }

        // Step 2: subtract the public affine constant. Querying the provider
        // also records its opening, so this stays before the begin message.
        state_.reduced_claim = claim_value(claim_) -
                               affine_constant_at(provider_, layer_, claim_);

        // Step 3: bind and replay the ciphertext-index sumcheck.
        observe_begin(layer_, payload::LayerKind::Affine,
                      geometry_.ciphertext_index_variables, transcript_);
        verify_affine_layer_reduction_sumcheck();

        // Step 4: check the terminal source/GateMLE identity and return the
        // source claim consumed by the next GKR layer.
        return verify_terminal_and_make_source_claim();
    }

  private:
    void verify_affine_layer_reduction_sumcheck() {
        for (std::size_t round = 0;
             round < geometry_.ciphertext_index_variables;
             ++round) {
            base_verifier_diagnostic().round = round;
            // Step 1: transcript-bind and decode R_j(1), R_j(2). Slot
            // summation is client work and is hidden by this semantic read.
            const DecodedAffineRoundEvaluations evaluations =
                observe_and_decode_round(round);

            // Step 2: recover the omitted Boolean endpoint from the exact
            // affine sumcheck identity
            //        R_j(0) + R_j(1) = claim_j.
            const Fpk at_zero =
                state_.reduced_claim - evaluations.at_one;

            // Step 3: sample r_j only after the complete message is bound.
            const Fpk challenge = transcript_.challenge_fpk();

            // Step 4: continue with claim_{j+1} = R_j(r_j).
            const ::laminate::gkr::detail::LayerReductionRoundEvaluations
                polynomial{at_zero, evaluations.at_one,
                           evaluations.at_two};
            state_.reduced_claim = polynomial.interpolate_at(challenge);
            state_.ciphertext_index_challenges.push_back(challenge);
        }
    }

    DecodedAffineRoundEvaluations observe_and_decode_round(
        std::size_t round) {
        const EncryptedBaseLayerReductionSumcheckRound<Backend> &message =
            proof_.rounds[round];
        observe_round<Backend>(layer_, round, message, transcript_);
        // The proof schema stores the pair in the fixed order X=1, X=2.
        // Name both values immediately so positional transport details do not
        // escape into verifier arithmetic.
        const fhe::ExtensionValue<Backend> &at_one =
            message.evaluations.front();
        const fhe::ExtensionValue<Backend> &at_two =
            message.evaluations.back();
        return DecodedAffineRoundEvaluations{
            .at_one = sum_slots(reader_.read(at_one)),
            .at_two = sum_slots(reader_.read(at_two))};
    }

    bool partial_gate_mle_is_valid(
        std::span<const Fpk> slot,
        std::span<const Fpk> slot_weights) {
        const std::vector<Fpk> source_point =
            concatenate(state_.ciphertext_index_challenges, slot);
        const Fpk opened =
            affine_gate_at(provider_, layer_, claim_, source_point);
        return inner_product(
                   proof_.partial_gate_mle.evaluations, slot_weights) ==
               opened;
    }

    std::optional<SingleClaim> verify_terminal_and_make_source_claim() {
        // The terminal source/GateMLE identity is a distinct step after the
        // rounds, so report it as terminal rather than under the last round.
        base_verifier_diagnostic().round = BaseVerifierDiagnostic::kNoIndex;
        base_verifier_diagnostic().detail = "terminal source/GateMLE identity";
        // Step 1: bind and decrypt W(r_ct, slot).
        observe_terminal<Backend>(
            layer_,
            std::span<const fhe::ExtensionValue<Backend>>(
                &proof_.source_vector, 1),
            transcript_);
        const std::vector<Fpk> source = reader_.read(proof_.source_vector);

        // Step 2: bind the public partial GateMLE values.
        observe_partial_gate_mle(
            layer_, PartialGateMleKind::Affine,
            proof_.partial_gate_mle, transcript_);

        // Step 3: check
        //   claim_final = sum_s GateMLE(output,r_ct,s) W(r_ct,s).
        if (source.size() != proof_.partial_gate_mle.evaluations.size() ||
            inner_product(proof_.partial_gate_mle.evaluations, source) !=
                state_.reduced_claim) {
            base_verifier_diagnostic().detail =
                "terminal identity failed: sum GateMLE*W != reduced claim "
                "(a corrupt operand, e.g. exhausted noise budget, produces "
                "exactly this)";
            return std::nullopt;
        }

        // Step 4: sample the terminal SIMD-slot point.
        const std::vector<Fpk> slot =
            transcript_.challenge_vector(geometry_.slot_index_variables);

        // Step 5: authenticate the partial GateMLE at that point. The same
        // Lagrange vector evaluates both the GateMLE and the source vector.
        const std::vector<Fpk> slot_weights = poly::eq_evaluations(slot);
        if (!partial_gate_mle_is_valid(slot, slot_weights)) {
            base_verifier_diagnostic().detail =
                "terminal partial GateMLE authentication failed";
            return std::nullopt;
        }

        // Step 6: hand W(r_ct,r_slot) to the next layer.
        return SingleClaim{
            concatenate(state_.ciphertext_index_challenges, slot),
                           inner_product(source, slot_weights)};
    }

    Reader &reader_; ///< Decrypts each fixed-size Base proof message.
    std::size_t layer_; ///< Affine circuit layer being reduced.
    const LayerClaim &claim_; ///< Output-layer claim before this reduction.
    const EncryptedBaseAffineLayerReduction<Backend> &proof_;
    GateProvider &provider_; ///< Supplies authenticated public GateMLE values.
    Transcript &transcript_; ///< Fiat--Shamir state replayed in prover order.
    /// Public split between encrypted ciphertext-index rounds and client slot
    /// completion.
    AffineGeometry geometry_;
    /// Claim and Fiat--Shamir prefix advanced by each verified
    /// ciphertext-index round.
    AffineVerificationState state_;
};

template <fhe::FheBackend Backend, typename Reader,
          typename GateProvider>
std::optional<SingleClaim> verify_affine_reduction(
    Reader &reader,
    const payload::LayeredCircuit &circuit, std::size_t layer,
    const LayerClaim &claim,
    const EncryptedBaseAffineLayerReduction<Backend> &proof,
    GateProvider &provider, Transcript &transcript) {
    return BaseAffineLayerVerifier<Backend, Reader, GateProvider>(
               reader, circuit, layer, claim, proof, provider, transcript)
        .run();
}

} // namespace laminate::gkr::base_detail

#endif // LAMINATE_GKR_DETAIL_BASE_AFFINE_VERIFIER_HPP
