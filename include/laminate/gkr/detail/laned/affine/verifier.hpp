#ifndef LAMINATE_GKR_DETAIL_LANED_AFFINE_VERIFIER_HPP
#define LAMINATE_GKR_DETAIL_LANED_AFFINE_VERIFIER_HPP

/// @file verifier.hpp
/// @brief Plaintext verification of one LaminateLaned affine reduction.

#include "laminate/gkr/laned.hpp"
#include "laminate/gkr/detail/laned/affine/internal/gate_claim.hpp"
#include "laminate/gkr/detail/laned/affine/internal/hadamard.hpp"
#include "laminate/gkr/detail/laned/geometry/layout.hpp"
#include "laminate/gkr/detail/shared/packed/affine_verifier.hpp"

#include <algorithm>
#include <cstddef>
#include <optional>
#include <utility>
#include <variant>
#include <vector>

namespace laminate::gkr::laned_detail {

/// Laned-specific arithmetic used by the shared affine sumcheck replay.
///
/// The shared loop in `detail/shared/packed/affine_verifier.hpp` reconstructs
/// each degree-two round from the local identity
///
///   claim_j = R_j(0) + R_j(1),
///   R_j(0) = claim_j - R_j(1),
///   claim_{j+1} = R_j(r_j).
///
/// The proof transmits `R_j(1)` and `R_j(2)`. This object supplies the Laned
/// affine-constant adjustment, Hadamard-safe lane challenges, terminal GateMLE
/// check, and inverse Hadamard claim transform. All verifier arithmetic is
/// plaintext.
template <typename GateProvider>
class LanedAffineVerifierArithmetic {
  public:
    LanedAffineVerifierArithmetic(
        const payload::LayeredCircuit &circuit, std::size_t layer,
        const LayerClaim &claim, GateProvider &provider)
        : reduction_layer_(layer), output_claim_(claim), gate_mle_(provider),
          output_layout_(laned_layout(circuit, layer)),
          source_layout_(laned_layout(circuit, layer + 1)),
          lane_point_(common_lane_point(output_layout_, claim)),
          ciphertext_index_round_count_(log2_exact(
              source_layout_.padded_ciphertext_count,
              "LaminateLaned affine ciphertext-index variables")),
          slot_index_round_count_(log2_exact(
              source_layout_.slot_count,
              "LaminateLaned affine slot-index variables")),
          round_count_(ciphertext_index_round_count_ +
                       slot_index_round_count_),
          lane_begin_(round_count_ - lane_point_.size()) {}

    std::size_t round_count() const { return round_count_; }

    std::size_t ciphertext_index_round_count() const {
        return ciphertext_index_round_count_;
    }

    std::size_t slot_index_round_count() const {
        return slot_index_round_count_;
    }

    /// Consume the optional outsourced constant claim only after the shared
    /// verifier has admitted the proof shape. This preserves the protocol
    /// order `constant claim -> reduction header -> round messages` without a
    /// transcript side effect in this object's constructor.
    Fpk initial_claim() {
        // Remove the public affine constant from the claimed output. This is
        // the sumcheck's initial claim before R_0 is reconstructed.
        return std::visit(
                   [](const auto &typed) { return typed.value; },
                   output_claim_) -
               affine_constant_at(
                   gate_mle_, reduction_layer_, output_layout_,
                   output_claim_);
    }

    Fpk sample_challenge(
        std::size_t round, Transcript &transcript) const {
        // Sample r_j after the shared verifier has bound the round message.
        // Lane coordinates exclude the Hadamard singular point.
        if (round < lane_begin_) {
            return transcript.challenge_fpk();
        }
        return challenge_hadamard_safe(
            transcript, lane_point_[round - lane_begin_]);
    }

    std::optional<SingleClaim> finish_terminal(
        std::vector<Fpk> challenges, const Fpk &weighted_source,
        const Fpk &running_claim) {
        // Check the terminal identity
        // running_claim = GateMLE(challenges) * weighted_source.
        const Fpk gate = affine_wire_at(
            gate_mle_, reduction_layer_, output_layout_, source_layout_,
            output_claim_, challenges);
        if (gate * weighted_source != running_claim) {
            return std::nullopt;
        }
        // Undo the lane-weight fusion and return the source claim.
        return transformed_next_claim(
            std::move(challenges), weighted_source);
    }

  private:
    SingleClaim transformed_next_claim(
        std::vector<Fpk> challenges,
        const Fpk &weighted_source) const {
        const std::vector<Fpk> raw_lane(
            challenges.begin() +
                static_cast<std::ptrdiff_t>(lane_begin_),
            challenges.end());
        const HadamardTransform transform =
            hadamard_transform(lane_point_, raw_lane);
        std::copy(
            transform.point.begin(), transform.point.end(),
            challenges.begin() +
                static_cast<std::ptrdiff_t>(lane_begin_));
        return SingleClaim{
            std::move(challenges),
            weighted_source * transform.factor.inverse()};
    }

    /// Reduction layer whose public affine table is being checked.
    std::size_t reduction_layer_;
    /// Output-layer claim reduced by this affine sumcheck.
    const LayerClaim &output_claim_;
    /// Source of the optional affine-constant and terminal GateMLE openings.
    GateProvider &gate_mle_;
    /// Packing geometry of the claimed output layer.
    packing::LanedPackingLayout output_layout_;
    /// Packing geometry of the source layer returned on success.
    packing::LanedPackingLayout source_layout_;
    /// Fixed output-lane suffix fused into the encrypted source values.
    std::vector<Fpk> lane_point_;
    /// Prefix rounds selecting among packed ciphertexts.
    std::size_t ciphertext_index_round_count_;
    /// Suffix rounds selecting within a SIMD ciphertext.
    std::size_t slot_index_round_count_;
    /// Number of degree-two round polynomials in this reduction.
    std::size_t round_count_;
    /// First challenge coordinate subject to the Hadamard transform.
    std::size_t lane_begin_;
};

/// Verify one Laned affine layer and return its transformed source claim.
template <fhe::FheBackend Backend, typename Reader, typename Message,
          typename GateProvider>
std::optional<SingleClaim> verify_affine_reduction(
    Reader &reader,
    const payload::LayeredCircuit &circuit, std::size_t layer,
    const LayerClaim &claim,
    const LanedAffineLayerReduction<Message> &proof,
    GateProvider &provider, Transcript &transcript) {
    using LanedAffineSumcheckVerifier =
        ::laminate::gkr::detail::PackedAffineVerifier<
               ProtocolVariant::LaminateLaned, Backend, Reader, Message,
               LanedAffineVerifierArithmetic<GateProvider>>;

    // Step 1: Bind the Laned arithmetic, geometry, and GateMLE provider to the
    // admitted reduction. Construction has no transcript side effect.
    LanedAffineVerifierArithmetic<GateProvider> arithmetic(
        circuit, layer, claim, provider);
    LanedAffineSumcheckVerifier verifier(
        reader, layer, proof, transcript, std::move(arithmetic));

    // Step 2: Replay the round messages in proof order and return the
    // Hadamard-transformed source claim only after the terminal identity holds.
    return verifier.run();
}

} // namespace laminate::gkr::laned_detail

#endif // LAMINATE_GKR_DETAIL_LANED_AFFINE_VERIFIER_HPP
