#ifndef LAMINATE_GKR_DETAIL_FOLDED_MULTIPLICATION_VERIFIER_HPP
#define LAMINATE_GKR_DETAIL_FOLDED_MULTIPLICATION_VERIFIER_HPP

/// @file verifier.hpp
/// @brief Plaintext verification of one Folded dense-multiplication reduction.

#include "laminate/gkr/detail/folded/multiplication/types.hpp"
#include "laminate/gkr/detail/shared/dense_multiplication/verifier.hpp"

#include <cstddef>
#include <optional>
#include <utility>

namespace laminate::gkr::folded_detail {

/// Folded admission for the dense relation
///
///     Output(i, slot) = Left(i, slot) * Right(i, slot).
///
/// The shared verifier explicitly replays each packed sumcheck message and
/// interpolates the two source evaluations into one next-layer claim.
/// `FoldedMultiplicationReductionGeometry::create` intentionally retains
/// Folded's existing exception behavior for a malformed circuit or claim
/// dimension.
class FoldedMultiplicationVerificationGeometry {
  public:
    FoldedMultiplicationVerificationGeometry(
        const payload::LayeredCircuit &circuit, std::size_t layer,
        const SingleClaim &claim)
        : geometry_(FoldedMultiplicationReductionGeometry::create(
              circuit, layer, claim)) {}

    std::size_t round_count() const { return geometry_.round_count; }

    std::size_t ciphertext_index_round_count() const {
        return geometry_.ciphertext_index_variables;
    }

    std::size_t slot_index_round_count() const {
        return geometry_.slot_index_variables;
    }

    template <typename Message>
    bool admits(
        const SingleClaim &,
        const FoldedMultiplicationLayerReduction<Message> &proof) const {
        return proof.rounds.size() == geometry_.round_count;
    }

  private:
    /// Public ciphertext-index/slot-index split fixed before transcript replay.
    FoldedMultiplicationReductionGeometry geometry_;
};

template <fhe::FheBackend Backend, typename Reader, typename Message>
std::optional<SingleClaim> verify_multiplication_reduction(
    Reader &reader, const payload::LayeredCircuit &circuit,
    std::size_t layer, const SingleClaim &claim,
    const FoldedMultiplicationLayerReduction<Message> &proof,
    Transcript &transcript) {
    // Step 1: Admit Folded's exact source geometry before touching the
    // transcript. The incoming claim must be single and have one coordinate
    // for every ciphertext-index and slot-index round.
    FoldedMultiplicationVerificationGeometry geometry(
        circuit, layer, claim);

    // Step 2: Replay the equality-stripped rounds. Locally, each round uses
    //   claim_j = (1-tau_j) S_j(0) + tau_j S_j(1),
    // reconstructs the omitted Boolean endpoint, and carries S_j(r_j).
    // The terminal check proves the decoded values are L(r) and R(r), then
    // interpolates their selector to return one source-layer claim.
    return detail::PackedDenseMultiplicationVerifier<
               ProtocolVariant::LaminateFolded, Backend, Reader, Message,
               FoldedMultiplicationVerificationGeometry>(
               reader, layer, claim, proof, transcript, std::move(geometry))
        .run();
}

} // namespace laminate::gkr::folded_detail

#endif // LAMINATE_GKR_DETAIL_FOLDED_MULTIPLICATION_VERIFIER_HPP
