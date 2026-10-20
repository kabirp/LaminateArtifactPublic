#ifndef LAMINATE_GKR_DETAIL_LANED_MULTIPLICATION_VERIFIER_HPP
#define LAMINATE_GKR_DETAIL_LANED_MULTIPLICATION_VERIFIER_HPP

/// @file verifier.hpp
/// @brief Plaintext verification of one Laned dense-multiplication reduction.

#include "laminate/gkr/laned.hpp"
#include "laminate/gkr/detail/shared/dense_multiplication/geometry.hpp"
#include "laminate/gkr/detail/shared/dense_multiplication/verifier.hpp"

#include <cstddef>
#include <optional>
#include <utility>

namespace laminate::gkr::laned_detail {

/// Public Laned shape supplied to the shared multiplication sumcheck replay.
/// Claim-shape mismatch remains an ordinary verification rejection; malformed
/// layer layouts fail while this object is constructed.
class LanedMultiplicationVerificationGeometry {
  public:
    LanedMultiplicationVerificationGeometry(
        const payload::LayeredCircuit &circuit, std::size_t layer,
        const SingleClaim &)
        : output_layout_(laned_layout(circuit, layer)),
          source_layout_(laned_layout(circuit, layer + 1)),
          dimensions_(::laminate::gkr::detail::
                          DenseMultiplicationDimensions::create(
                              output_layout_.padded_ciphertext_count,
                              source_layout_.padded_ciphertext_count,
                              output_layout_.slot_count)) {}

    std::size_t round_count() const { return dimensions_.round_count(); }

    std::size_t ciphertext_index_round_count() const {
        return dimensions_.ciphertext_index_variables;
    }

    std::size_t slot_index_round_count() const {
        return dimensions_.slot_index_variables;
    }

    template <typename Message>
    bool admits(
        const SingleClaim &claim,
        const LanedMultiplicationLayerReduction<Message> &proof) const {
        return proof.rounds.size() == round_count() &&
               claim.point.size() == round_count() &&
               source_layout_.padded_ciphertext_count ==
                   2 * output_layout_.padded_ciphertext_count;
    }

  private:
    /// Packing geometry of the claimed multiplication outputs.
    packing::LanedPackingLayout output_layout_;
    /// Packing geometry of the structural `[left | right]` source.
    packing::LanedPackingLayout source_layout_;
    /// Public split between ciphertext-index and slot-index rounds.
    ::laminate::gkr::detail::DenseMultiplicationDimensions dimensions_;
};

/// Verify one Laned dense multiplication layer and return one interpolated
/// source claim on success.
///
/// `PackedDenseMultiplicationVerifier::verify_multiplication_sumcheck_round`
/// contains the explicit plaintext recurrence
///
///   claim_j = (1-tau_j) S_j(0) + tau_j S_j(1),
///
/// followed by transcript binding, challenge sampling, and interpolation to
/// `S_j(r_j)`. The shape object above contributes no protocol control flow.
template <fhe::FheBackend Backend, typename Reader, typename Message>
std::optional<SingleClaim> verify_multiplication_reduction(
    Reader &reader,
    const payload::LayeredCircuit &circuit, std::size_t layer,
    const SingleClaim &claim,
    const LanedMultiplicationLayerReduction<Message> &proof,
    Transcript &transcript) {
    using LanedMultiplicationSumcheckVerifier =
        detail::PackedDenseMultiplicationVerifier<
               ProtocolVariant::LaminateLaned, Backend, Reader, Message,
               LanedMultiplicationVerificationGeometry>;

    // Step 1: Admit the exact Laned geometry
    // Out(x,s)=Left(x,s)*Right(x,s); the left/right selector is structural and
    // contributes no sumcheck round.
    LanedMultiplicationVerificationGeometry geometry(circuit, layer, claim);
    LanedMultiplicationSumcheckVerifier verifier(
        reader, layer, claim, proof, transcript, std::move(geometry));

    // Step 2: For each round, bind the transmitted endpoint and S_j(2),
    // reconstruct the omitted Boolean endpoint from
    // claim_j=(1-tau_j)S_j(0)+tau_j*S_j(1), sample r_j, and carry
    // claim_{j+1}=S_j(r_j). If the terminal product identity holds, sample a
    // fresh selector and interpolate the terminal values into one claim.
    return verifier.run();
}

} // namespace laminate::gkr::laned_detail

#endif // LAMINATE_GKR_DETAIL_LANED_MULTIPLICATION_VERIFIER_HPP
