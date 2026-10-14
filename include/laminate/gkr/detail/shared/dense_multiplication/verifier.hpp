#ifndef LAMINATE_GKR_DETAIL_SHARED_DENSE_MULTIPLICATION_VERIFIER_HPP
#define LAMINATE_GKR_DETAIL_SHARED_DENSE_MULTIPLICATION_VERIFIER_HPP

/// @file verifier.hpp
/// @brief Shared Folded/Laned verifier for packed dense multiplication.

#include "laminate/gkr/detail/shared/dense_multiplication/geometry.hpp"
#include "laminate/gkr/detail/shared/packed/proof.hpp"
#include "laminate/gkr/detail/shared/packed/transcript.hpp"
#include "laminate/gkr/detail/shared/reduction/sumcheck.hpp"

#include <concepts>
#include <cstddef>
#include <optional>
#include <utility>
#include <vector>

namespace laminate::gkr::detail {

/// The geometry adapter is the sole variant-specific boundary of the shared
/// verifier. It computes the number of rounds and admits the variant's exact
/// proof/claim shape before the transcript is changed.
template <typename Geometry, typename Proof>
concept PackedDenseMultiplicationVerificationGeometry = requires(
    const Geometry &geometry, const SingleClaim &claim,
    const Proof &proof) {
    { geometry.round_count() } -> std::convertible_to<std::size_t>;
    { geometry.ciphertext_index_round_count() } ->
        std::convertible_to<std::size_t>;
    { geometry.slot_index_round_count() } ->
        std::convertible_to<std::size_t>;
    { geometry.admits(claim, proof) } -> std::convertible_to<bool>;
};

/// Claim and source point carried between packed
/// dense-multiplication sumcheck rounds.
struct PackedDenseMultiplicationVerificationState {
    /// Current equality-stripped claim `S_j(r_0, ..., r_{j-1})`.
    Fpk reduced_claim = Fpk::zero();
    /// Fiat--Shamir point shared by the terminal left/right source MLEs.
    std::vector<Fpk> source_point;
};

/// Variant-neutral replay of the equality-stripped packed multiplication
/// sumcheck. `Geometry` retains only Folded/Laned shape validation; all
/// transcript, endpoint, terminal, and selector-interpolation steps live here.
template <ProtocolVariant Variant, fhe::FheBackend Backend,
          typename Reader, typename Message, typename Geometry>
    requires PackedDenseMultiplicationVerificationGeometry<
        Geometry, PackedMultiplicationReduction<Message, Variant>>
class PackedDenseMultiplicationVerifier {
  public:
    using Proof = PackedMultiplicationReduction<Message, Variant>;
    using RoundEvaluations = TransmittedLayerReductionRound<Fpk>;

    PackedDenseMultiplicationVerifier(
        Reader &reader, std::size_t layer, const SingleClaim &claim,
        const Proof &proof, Transcript &transcript, Geometry geometry)
        : reader_(reader), layer_(layer), claim_(claim), proof_(proof),
          transcript_(transcript), geometry_(std::move(geometry)),
          state_{.reduced_claim = claim.value} {
        state_.source_point.reserve(geometry_.round_count());
    }

    std::optional<SingleClaim> run() {
        // Step 1: Reject malformed geometry before changing Fiat--Shamir.
        const std::size_t ciphertext_index_rounds =
            geometry_.ciphertext_index_round_count();
        const std::size_t slot_index_rounds =
            geometry_.slot_index_round_count();
        if (ciphertext_index_rounds > geometry_.round_count() ||
            slot_index_rounds !=
                geometry_.round_count() - ciphertext_index_rounds ||
            !geometry_.admits(claim_, proof_)) {
            return std::nullopt;
        }

        // Step 2: Bind the admitted multiplication reduction.
        observe_packed_reduction_begin<Variant>(
            layer_, payload::LayerKind::Multiplication,
            geometry_.round_count(), transcript_);

        // Step 3: Fix the ciphertext-index coordinates first. These rounds
        // select one dense left/right pair across packed ciphertexts.
        for (std::size_t round = 0;
             round < ciphertext_index_rounds; ++round) {
            verify_multiplication_sumcheck_round(round);
        }

        // Step 4: Fix the SIMD slot-index coordinates next.
        const std::size_t slot_begin = ciphertext_index_rounds;
        for (std::size_t offset = 0;
             offset < slot_index_rounds; ++offset) {
            verify_multiplication_sumcheck_round(slot_begin + offset);
        }

        // Step 5: Check the terminal multiplication identity and form the
        // single claim carried to the source layer.
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
            .at_endpoint = std::move(decoded[0]),
            .at_two = std::move(decoded[1]),
        };
    }

    void verify_multiplication_sumcheck_round(std::size_t round) {
        // Step 1: Bind and decode S(endpoint) and S(2) in their stable
        // transcript order. Transport details end at this typed protocol
        // value.
        const RoundEvaluations evaluations =
            observe_and_decode_round(round);

        // Step 2: Reconstruct both Boolean endpoints. Equality stripping
        // maintains
        //
        //   claim_j = (1 - tau_j) S_j(0) + tau_j S_j(1).
        //
        // The proof sends the nonsingular endpoint, so this equation uniquely
        // determines the omitted endpoint even when tau_j=0.
        const Fpk &tau = claim_.point[round];
        const DenseMultiplicationEndpoints endpoints =
            recover_dense_multiplication_endpoints(
                state_.reduced_claim, tau, evaluations.at_endpoint);
        const LayerReductionRoundEvaluations polynomial{
            endpoints.zero, endpoints.one, evaluations.at_two};

        // Step 3: Sample r only after the round message is bound.
        const Fpk challenge = transcript_.challenge_fpk();

        // Step 4: Set claim_{j+1}=S_j(r) and extend the terminal source point.
        state_.reduced_claim = polynomial.interpolate_at(challenge);
        state_.source_point.push_back(challenge);
    }

    std::optional<SingleClaim> verify_terminal_and_make_source_claim() {
        // Step 1: Bind and decode L(r),R(r) at the shared random source
        // point fixed by the sumcheck rounds.
        observe_packed_terminal_message<Variant, Backend>(
            layer_, proof_.packed_source_values, transcript_);
        std::vector<Fpk> decoded =
            reader_.read(proof_.packed_source_values, 2);
        const DenseMultiplicationSourceValues<Fpk> source_values{
            .left = std::move(decoded[0]),
            .right = std::move(decoded[1]),
        };

        // Step 2: The running claim has no equality factor remaining.
        // Check reduced_claim = L(r) R(r), including at zero equality points.
        if (!dense_multiplication_terminal_is_valid(
                source_values.left, source_values.right,
                state_.reduced_claim)) {
            return std::nullopt;
        }

        // Step 3: Sample a fresh selector after both terminal values are
        // fixed. Multilinearity reduces them to the single claim
        // Src(alpha,r) = (1-alpha) L(r) + alpha R(r).
        return make_dense_multiplication_source_claim(
            state_.source_point, source_values.left, source_values.right,
            transcript_.challenge_fpk());
    }

    Reader &reader_;                ///< Decrypts fixed-size packed messages.
    std::size_t layer_;             ///< Layer reduced by this proof.
    const SingleClaim &claim_;      ///< Claim before the reduction.
    const Proof &proof_;            ///< Prover messages being replayed.
    Transcript &transcript_;        ///< Fiat--Shamir state for this variant.
    Geometry geometry_;              ///< Validated variant-specific shape.
    PackedDenseMultiplicationVerificationState state_;
};

} // namespace laminate::gkr::detail

#endif // LAMINATE_GKR_DETAIL_SHARED_DENSE_MULTIPLICATION_VERIFIER_HPP
