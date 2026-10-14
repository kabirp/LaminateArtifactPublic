#ifndef LAMINATE_GKR_DETAIL_SHARED_PACKED_AFFINE_VERIFIER_HPP
#define LAMINATE_GKR_DETAIL_SHARED_PACKED_AFFINE_VERIFIER_HPP

/// @file affine_verifier.hpp
/// @brief Shared Folded/Laned verifier sequencing for packed affine layers.

#include "laminate/gkr/detail/shared/packed/proof.hpp"
#include "laminate/gkr/detail/shared/packed/transcript.hpp"
#include "laminate/gkr/detail/shared/reduction/affine_round.hpp"
#include "laminate/gkr/detail/shared/reduction/sumcheck.hpp"

#include <concepts>
#include <cstddef>
#include <optional>
#include <utility>
#include <vector>

namespace laminate::gkr::detail {

/// Variant arithmetic for the common packed affine verifier.
///
/// This role owns only the arithmetic that genuinely differs between
/// Folded and Laned: public geometry/constant admission, challenge sampling,
/// and conversion of the terminal weighted source into the next claim.
template <typename Arithmetic>
concept PackedAffineVerifierArithmetic = requires(
    Arithmetic &arithmetic, std::size_t round, Transcript &transcript,
    std::vector<Fpk> challenges, const Fpk &source,
    const Fpk &running_claim) {
    { arithmetic.round_count() } -> std::convertible_to<std::size_t>;
    { arithmetic.ciphertext_index_round_count() } ->
        std::convertible_to<std::size_t>;
    { arithmetic.slot_index_round_count() } ->
        std::convertible_to<std::size_t>;
    { arithmetic.initial_claim() } -> std::same_as<Fpk>;
    { arithmetic.sample_challenge(round, transcript) } -> std::same_as<Fpk>;
    {
        arithmetic.finish_terminal(
            std::move(challenges), source, running_claim)
    } -> std::same_as<std::optional<SingleClaim>>;
};

/// Claim and source point carried between packed affine sumcheck rounds.
///
/// After round `j`, `reduced_claim` is `R_j(r_j)` and `source_point` is the
/// Fiat--Shamir prefix `(r_0, ..., r_j)` at which the next round is evaluated.
struct PackedAffineVerificationState {
    Fpk reduced_claim = Fpk::zero();
    std::vector<Fpk> source_point;
};

/// Variant-neutral packed affine verification.
///
/// This verifier fixes the fail-closed order shared by Folded and Laned:
/// admit the round count before touching the transcript, bind the reduction
/// header, observe/read/replay every degree-two message, observe/read the
/// terminal message, and only then ask the variant arithmetic to check and
/// convert the terminal claim.
template <ProtocolVariant Variant, fhe::FheBackend Backend,
          typename Reader, typename Message,
          PackedAffineVerifierArithmetic Arithmetic>
class PackedAffineVerifier {
  public:
    using Proof = PackedAffineReduction<Message, Variant>;
    using RoundEvaluations = AffineRoundPair<Fpk>;

    PackedAffineVerifier(Reader &reader, std::size_t layer,
                         const Proof &proof, Transcript &transcript,
                         Arithmetic arithmetic)
        : reader_(reader), layer_(layer), proof_(proof),
          transcript_(transcript), arithmetic_(std::move(arithmetic)) {
        static_assert(kIsPackedProofVariant<Variant>);
        state_.source_point.reserve(arithmetic_.round_count());
    }

    std::optional<SingleClaim> run() {
        // Step 1: Reject malformed geometry before changing Fiat--Shamir.
        const std::size_t ciphertext_index_rounds =
            arithmetic_.ciphertext_index_round_count();
        const std::size_t slot_index_rounds =
            arithmetic_.slot_index_round_count();
        if (ciphertext_index_rounds > arithmetic_.round_count() ||
            slot_index_rounds !=
                arithmetic_.round_count() - ciphertext_index_rounds ||
            proof_.rounds.size() != arithmetic_.round_count()) {
            return std::nullopt;
        }

        // Step 2: Establish the affine sumcheck's initial claim. The variant
        // may authenticate a public affine constant here, so this stays in the
        // visible transcript-ordered path.
        state_.reduced_claim = arithmetic_.initial_claim();

        // Step 3: Bind the admitted affine reduction.
        observe_packed_reduction_begin<Variant>(
            layer_, payload::LayerKind::Affine, arithmetic_.round_count(),
            transcript_);

        // Step 4: Fix the ciphertext-index coordinates first. These rounds
        // select among packed ciphertexts.
        for (std::size_t round = 0;
             round < ciphertext_index_rounds; ++round) {
            verify_affine_sumcheck_round(round);
        }

        // Step 5: Fix the slot-index coordinates next. Folded and Laned use
        // different challenge rules, supplied by their named arithmetic.
        const std::size_t slot_begin = ciphertext_index_rounds;
        for (std::size_t offset = 0;
             offset < slot_index_rounds; ++offset) {
            verify_affine_sumcheck_round(slot_begin + offset);
        }

        // Step 6: Check the terminal source evaluation and form the source
        // layer claim selected by the variant.
        return verify_terminal_and_make_source_claim();
    }

  private:
    /// Bind one fixed-size proof message, then end transport concerns by
    /// returning the two named scalar evaluations used by the recurrence.
    RoundEvaluations observe_and_decode_round(std::size_t round) {
        observe_packed_round_message<Variant, Backend>(
            layer_, round, proof_.rounds[round], transcript_);
        std::vector<Fpk> decoded = reader_.read(
            proof_.rounds[round].packed_evaluations, 2);
        return {
            .at_one = std::move(decoded[0]),
            .at_two = std::move(decoded[1]),
        };
    }

    void verify_affine_sumcheck_round(std::size_t round) {
        // Step 1: Bind and decode R_j(1), R_j(2). Transport details end at
        // this typed protocol value.
        const RoundEvaluations evaluations =
            observe_and_decode_round(round);

        // Step 2: Reconstruct the omitted endpoint from the sumcheck
        // invariant
        //
        //   claim_j = R_j(0) + R_j(1).
        //
        // The affine prover sends R_j(1), so R_j(0)=claim_j-R_j(1).
        const LayerReductionRoundEvaluations polynomial{
            state_.reduced_claim - evaluations.at_one,
            evaluations.at_one,
            evaluations.at_two};

        // Step 3: Sample r_j only after the message is bound.
        const Fpk challenge =
            arithmetic_.sample_challenge(round, transcript_);

        // Step 4: Carry claim_{j+1}=R_j(r_j) and the random source point into
        // the next round.
        state_.reduced_claim = polynomial.interpolate_at(challenge);
        state_.source_point.push_back(challenge);
    }

    std::optional<SingleClaim> verify_terminal_and_make_source_claim() {
        // Step 1: Bind and decode the terminal source evaluation. Folded
        // opens W(r); Laned opens the MLE of its lane-weighted source.
        const Message &terminal = proof_.packed_terminal_value;
        observe_packed_terminal_message<Variant, Backend>(
            layer_, terminal, transcript_);
        const Fpk source = reader_.read(terminal, 1).front();

        // Step 2: Check the product of the gate value and terminal source
        // evaluation. Laned then removes its lane weighting to obtain
        // the ordinary source claim at the transformed point.
        return arithmetic_.finish_terminal(
            std::move(state_.source_point), source, state_.reduced_claim);
    }

    Reader &reader_;             ///< Decrypts fixed-size packed messages.
    std::size_t layer_;          ///< Layer reduced by this proof.
    const Proof &proof_;         ///< Prover messages being replayed.
    Transcript &transcript_;     ///< Fiat--Shamir state for this variant.
    Arithmetic arithmetic_; ///< Variant geometry and terminal relation.
    PackedAffineVerificationState state_; ///< Round-to-round protocol state.
};

} // namespace laminate::gkr::detail

#endif // LAMINATE_GKR_DETAIL_SHARED_PACKED_AFFINE_VERIFIER_HPP
