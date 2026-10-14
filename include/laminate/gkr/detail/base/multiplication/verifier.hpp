#ifndef LAMINATE_GKR_DETAIL_BASE_MULTIPLICATION_VERIFIER_HPP
#define LAMINATE_GKR_DETAIL_BASE_MULTIPLICATION_VERIFIER_HPP

/// @file verifier.hpp
/// @brief Client verification of one Base multiplication reduction.

#include "laminate/gkr/detail/base/arithmetic/reduction.hpp"
#include "laminate/gkr/detail/base/claims/evaluation.hpp"
#include "laminate/gkr/detail/base/multiplication/types.hpp"
#include "laminate/gkr/detail/base/transcript/reduction.hpp"
#include "laminate/gkr/detail/base/verification/diagnostic.hpp"
#include "laminate/gkr/detail/shared/dense_multiplication/rounds.hpp"
#include "laminate/poly/eq.hpp"

#include <cstddef>
#include <optional>
#include <vector>

namespace laminate::gkr::base_detail {

/// Verifies one LaminateBase dense multiplication reduction. Equality
/// stripping makes each ciphertext-index round satisfy
///
///   claim_j = (1 - tau_j) S_j(0) + tau_j S_j(1).
///
/// The prover keeps SIMD slots packed. The client decrypts the two round
/// vectors, completes the public slot inner products, reconstructs the missing
/// Boolean endpoint, and checks the terminal left/right product relation.
template <fhe::FheBackend Backend, typename Reader>
class BaseMultiplicationLayerVerifier {
  public:
    BaseMultiplicationLayerVerifier(
        Reader &reader, const payload::LayeredCircuit &circuit,
        std::size_t layer, const SingleClaim &claim,
        const EncryptedBaseMultiplicationLayerReduction<Backend> &proof,
        Transcript &transcript,
        const payload::LayerStorageLayout *source_storage = nullptr)
        : reader_(reader), layer_(layer), claim_(claim), proof_(proof),
          transcript_(transcript),
          geometry_(source_storage == nullptr
                        ? MultiplicationGeometry::create(circuit, layer,
                                                         claim)
                        : MultiplicationGeometry::create(
                              circuit, layer, claim, *source_storage)),
          state_{.reduced_claim = claim.value} {
        state_.ciphertext_index_challenges.reserve(geometry_.round_count);
    }

    std::optional<SingleClaim> run() {
        // Step 1: reject malformed round geometry before reading proof data.
        if (proof_.rounds.size() != geometry_.round_count) {
            base_verifier_diagnostic().detail =
                "sumcheck round count does not match the layer geometry";
            return std::nullopt;
        }

        // Step 2: bind and replay the equality-stripped ciphertext-index
        // sumcheck.
        observe_begin(layer_, payload::LayerKind::Multiplication,
                      geometry_.round_count, transcript_);
        if (!verify_multiplication_layer_reduction_sumcheck()) {
            return std::nullopt;
        }

        // Step 3: check the terminal L*R relation and interpolate a single
        // source claim consumed by the next GKR layer.
        return verify_terminal_and_make_source_claim();
    }

  private:
    /// Replay the ciphertext-index sumcheck. Base proof messages still hold a
    /// vector over SIMD slots, so the client decrypts each vector and takes
    /// its inner product with the public output-slot equality weights.
    bool verify_multiplication_layer_reduction_sumcheck() {
        for (std::size_t round = 0; round < geometry_.round_count; ++round) {
            base_verifier_diagnostic().round = round;
            // Step 1: transcript-bind, decrypt, and finish the public slot
            // inner products for S_j(endpoint) and S_j(2).
            const std::optional<DecodedMultiplicationRoundEvaluations>
                decoded = observe_and_decode_round(round);
            if (!decoded) {
                base_verifier_diagnostic().detail =
                    "round message decoded to the wrong slot count";
                return false;
            }

            const Fpk tau = claim_.point[round];

            // Step 2: recover the omitted Boolean endpoint from the exact
            // equality-stripped identity
            //   claim_j = (1-tau_j) S_j(0) + tau_j S_j(1).
            // The message sends S_j(0), except at tau_j=0 where it sends
            // S_j(1), so recovery never divides by zero.
            const ::laminate::gkr::detail::DenseMultiplicationEndpoints
                endpoints = ::laminate::gkr::detail::
                    recover_dense_multiplication_endpoints(
                        state_.reduced_claim, tau,
                        decoded->at_primary_endpoint);

            // Step 3: sample r_j only after the complete message is bound.
            const Fpk challenge = transcript_.challenge_fpk();

            // Step 4: continue with claim_{j+1} = S_j(r_j).
            const ::laminate::gkr::detail::LayerReductionRoundEvaluations
                polynomial{endpoints.zero, endpoints.one,
                           decoded->at_two};
            state_.reduced_claim = polynomial.interpolate_at(challenge);
            state_.ciphertext_index_challenges.push_back(challenge);
        }
        return true;
    }

    std::optional<DecodedMultiplicationRoundEvaluations>
    observe_and_decode_round(std::size_t round) {
        const EncryptedBaseLayerReductionSumcheckRound<Backend> &message =
            proof_.rounds[round];
        observe_round<Backend>(layer_, round, message, transcript_);
        const std::vector<Fpk> primary =
            reader_.read(message.evaluations[0]);
        const std::vector<Fpk> at_two =
            reader_.read(message.evaluations[1]);
        if (primary.size() != circuit_slot_count() ||
            at_two.size() != circuit_slot_count()) {
            return std::nullopt;
        }
        return DecodedMultiplicationRoundEvaluations{
            inner_product(primary, geometry_.output_slot_weights),
            inner_product(at_two, geometry_.output_slot_weights)};
    }

    std::size_t circuit_slot_count() const {
        return poly::hypercube_size(geometry_.slot_index_variables);
    }

    /// Check the terminal product identity, then interpolate the selector
    /// coordinate between the left and right source MLE evaluations.
    std::optional<SingleClaim> verify_terminal_and_make_source_claim() {
        // The terminal L*R relation is checked after every round, so report it
        // as its own step rather than under the last round.
        base_verifier_diagnostic().round = BaseVerifierDiagnostic::kNoIndex;
        base_verifier_diagnostic().detail = "terminal L*R relation";
        // Step 1: bind and decrypt L(r_ct,slot), R(r_ct,slot).
        const DecodedMultiplicationSourceValues source_values =
            observe_and_decode_terminal();
        if (source_values.left.size() != circuit_slot_count() ||
            source_values.right.size() != circuit_slot_count()) {
            base_verifier_diagnostic().detail =
                "terminal source vectors decoded to the wrong slot count";
            return std::nullopt;
        }

        // Step 2: complete the packed-slot terminal product
        //   sum_s eq(tau_slot,s) L(r_ct,s) R(r_ct,s).
        Fpk weighted_product = Fpk::zero();
        for (std::size_t slot = 0; slot < source_values.left.size(); ++slot) {
            weighted_product += geometry_.output_slot_weights[slot] *
                                source_values.left[slot] *
                                source_values.right[slot];
        }

        // Step 3: the ciphertext-index equality factors have been stripped.
        // Check the remaining weighted slot product directly, even when the
        // equality of output and source ciphertext points is zero.
        if (weighted_product != state_.reduced_claim) {
            base_verifier_diagnostic().detail =
                "terminal L*R product identity failed: product != "
                "claim (corrupt operand, e.g. exhausted noise budget, "
                "produces exactly this)";
            return std::nullopt;
        }

        // Step 4: sample the terminal SIMD-slot point and evaluate both
        // decrypted source vectors there.
        const std::vector<Fpk> slot =
            transcript_.challenge_vector(geometry_.slot_index_variables);
        const std::vector<Fpk> terminal_slot_weights =
            poly::eq_evaluations(slot);
        const Fpk left_value =
            inner_product(source_values.left, terminal_slot_weights);
        const Fpk right_value =
            inner_product(source_values.right, terminal_slot_weights);
        const std::vector<Fpk> shared =
            concatenate(state_.ciphertext_index_challenges, slot);

        // Step 5: the source MLE is affine in its selector coordinate.
        // Sample alpha after both source values are fixed and continue with
        // source(alpha, shared) = (1-alpha)*left_value + alpha*right_value.
        const Fpk selector_challenge = transcript_.challenge_fpk();
        return ::laminate::gkr::detail::make_dense_multiplication_source_claim(
            shared, left_value, right_value, selector_challenge);
    }

    DecodedMultiplicationSourceValues observe_and_decode_terminal() {
        observe_terminal<Backend>(layer_, proof_.source_vectors,
                                  transcript_);
        return DecodedMultiplicationSourceValues{
            reader_.read(proof_.source_vectors[0]),
            reader_.read(proof_.source_vectors[1])};
    }

    Reader &reader_; ///< Decrypts each fixed-size Base proof message.
    std::size_t layer_; ///< Multiplication circuit layer being reduced.
    const SingleClaim &claim_; ///< Output-layer claim before this reduction.
    const EncryptedBaseMultiplicationLayerReduction<Backend> &proof_;
    Transcript &transcript_; ///< Fiat--Shamir state replayed in prover order.
    /// Public dimensions and output equality point for this dense layer.
    MultiplicationGeometry geometry_;
    /// Claim and Fiat--Shamir point advanced each round.
    MultiplicationVerificationState state_;
};

template <fhe::FheBackend Backend, typename Reader>
    requires requires(
        Reader &reader,
        const fhe::ExtensionValue<Backend> &value) { reader.read(value); }
std::optional<SingleClaim> verify_multiplication_reduction(
    Reader &reader, const payload::LayeredCircuit &circuit,
    std::size_t layer, const SingleClaim &claim,
    const EncryptedBaseMultiplicationLayerReduction<Backend> &proof,
    Transcript &transcript) {
    return BaseMultiplicationLayerVerifier<Backend, Reader>(
               reader, circuit, layer, claim, proof, transcript)
        .run();
}

template <fhe::FheBackend Backend, typename Reader>
    requires requires(
        Reader &reader,
        const fhe::ExtensionValue<Backend> &value) { reader.read(value); }
std::optional<SingleClaim> verify_multiplication_reduction_with_storage(
    Reader &reader, const payload::LayeredCircuit &circuit,
    const payload::LayerStorageLayout &source_storage,
    std::size_t layer, const SingleClaim &claim,
    const EncryptedBaseMultiplicationLayerReduction<Backend> &proof,
    Transcript &transcript) {
    return BaseMultiplicationLayerVerifier<Backend, Reader>(
               reader, circuit, layer, claim, proof, transcript,
               &source_storage)
        .run();
}

} // namespace laminate::gkr::base_detail

#endif // LAMINATE_GKR_DETAIL_BASE_MULTIPLICATION_VERIFIER_HPP
