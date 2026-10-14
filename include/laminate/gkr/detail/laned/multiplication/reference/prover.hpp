#ifndef LAMINATE_GKR_DETAIL_LANED_MULTIPLICATION_REFERENCE_PROVER_HPP
#define LAMINATE_GKR_DETAIL_LANED_MULTIPLICATION_REFERENCE_PROVER_HPP

/// @file prover.hpp
/// @brief Resident reference multiplication proving for LaminateLaned.

#include "laminate/gkr/detail/laned/multiplication/reference/packing.hpp"
#include "laminate/gkr/detail/laned/multiplication/types.hpp"
#include "laminate/gkr/detail/shared/dense_multiplication/reference/prover.hpp"
#include "laminate/runtime_progress.hpp"

#include <cstddef>
#include <utility>

namespace laminate::gkr::laned_detail {

struct LanedResidentMultiplicationLayerReductionTraits {
    static constexpr ProtocolVariant variant =
        ProtocolVariant::LaminateLaned;
    static constexpr RuntimeProgressStage checkpoint_stage =
        RuntimeProgressStage::LanedMultiplicationSlotCheckpoint;
    static constexpr RuntimeProgressStage sumcheck_stage =
        RuntimeProgressStage::LanedMultiplicationSumcheckRound;
    static constexpr const char *protocol_name = "LaminateLaned";

    template <fhe::FheBackend Backend>
    using Result = LanedMultiplicationLayerReductionResult<Backend>;
    using Geometry = LanedMultiplicationLayerReductionGeometry;
};

/// Resident prover for
///
///   Out(x,s) = Left(x,s) * Right(x,s).
///
/// `pack_resident_dense_source` first forms the compact Laned left/right pair
/// view. `run()` then enters the explicit ciphertext-index, checkpoint,
/// slot-index,
/// and terminal recurrence in
/// `detail/shared/dense_multiplication/reference/prover.hpp`. Its
/// ciphertext-index evaluator methods contain the exact
/// ciphertext-ciphertext FHE products; checkpoint construction is linear.
template <fhe::FheBackend Backend>
class LanedResidentMultiplicationLayerReductionProver {
  private:
    using PackedSource =
        reference_multiplication_detail::PackedSource<Backend>;
    using LanedDenseMultiplicationSumcheck = ::laminate::gkr::detail::
        ReferencePackedDenseMultiplicationProver<
            Backend, LanedResidentMultiplicationLayerReductionTraits,
            PackedSource>;

  public:
    LanedResidentMultiplicationLayerReductionProver(
        const typename Backend::EvalContext &eval,
        const payload::LayeredCircuit &circuit,
        const payload::EncryptedTrace<Backend> &trace, std::size_t layer,
        const SingleClaim &claim, Transcript &transcript,
        std::size_t source_proof_ingress_rns_limbs,
        std::size_t reserved_transport_depth,
        PackedMessageCommitmentFunction<Backend> commitment_function = {},
        RuntimeProgressCallback progress = {})
        : eval_(eval), circuit_(circuit), trace_(trace), layer_(layer),
          claim_(claim), transcript_(transcript),
          source_proof_ingress_rns_limbs_(
              source_proof_ingress_rns_limbs),
          reserved_transport_depth_(reserved_transport_depth),
          commitment_function_(std::move(commitment_function)),
          progress_(std::move(progress)) {}

    LanedMultiplicationLayerReductionResult<Backend> run() {
        // Step 1: Establish the domain for
        // Out(x,s)=Left(x,s)*Right(x,s). The left/right selector is structural
        // and is not an additional sumcheck variable.
        const LanedMultiplicationLayerReductionGeometry geometry =
            LanedMultiplicationLayerReductionGeometry::create(
                circuit_, layer_, claim_);

        // Step 2: Form the resident dense pair source. Public padding remains
        // null, and packing consumes FHE work only when several chunks must be
        // combined into one operand ciphertext.
        const PackedSource packed =
            reference_multiplication_detail::
                pack_resident_dense_source<Backend>(
                    eval_, circuit_, trace_, layer_, geometry.source,
                    geometry.pair_count,
                    source_proof_ingress_rns_limbs_);

        // Step 3: Prove the quadratic product sumcheck. Its local identity is
        // claim_j=(1-tau_j)S_j(0)+tau_j*S_j(1); the proof sends the
        // nonsingular Boolean endpoint and S_j(2), binds them, then samples
        // r_j and carries claim_{j+1}=S_j(r_j).
        LanedDenseMultiplicationSumcheck sumcheck(
            eval_, geometry, packed, layer_, claim_, transcript_,
            reserved_transport_depth_, std::move(commitment_function_),
            std::move(progress_));
        return sumcheck.run();
    }

  private:
    /// FHE evaluation context used by packing and encrypted round kernels.
    const typename Backend::EvalContext &eval_;
    /// Layered circuit defining the dense left/right source relation.
    const payload::LayeredCircuit &circuit_;
    /// Resident encrypted trace from which the pair source is derived.
    const payload::EncryptedTrace<Backend> &trace_;
    /// Multiplication output layer whose claim is being reduced.
    std::size_t layer_;
    /// Single output claim that initializes the multiplication sumcheck.
    const SingleClaim &claim_;
    /// Fiat--Shamir transcript mutated only when the sumcheck begins.
    Transcript &transcript_;
    /// Exact source RNS level admitted before any packing operation.
    std::size_t source_proof_ingress_rns_limbs_;
    /// Multiplicative depth reserved when proof messages are compacted.
    std::size_t reserved_transport_depth_;
    /// Optional binding for each packed encrypted proof message.
    PackedMessageCommitmentFunction<Backend> commitment_function_;
    /// Diagnostics wrapped around semantic sumcheck phases.
    RuntimeProgressCallback progress_;
};

/// Prove one Laned dense multiplication layer.
///
/// Preconditions: claim is over the packed output domain and the compiled
/// source consists of equally sized dense left/right halves.
/// Postcondition: the returned geometry contains selector-prefixed left/right
/// points and plaintext placeholder claim values; transcript challenges are
/// fully bound. These placeholders are not FHE ciphertexts.
template <fhe::FheBackend Backend>
LanedMultiplicationLayerReductionResult<Backend>
prove_multiplication_resident_reference(
    const typename Backend::EvalContext &eval,
    const payload::LayeredCircuit &circuit,
    const payload::EncryptedTrace<Backend> &trace, std::size_t layer,
    const SingleClaim &claim, Transcript &transcript,
    std::size_t source_proof_ingress_rns_limbs,
    std::size_t reserved_transport_depth = 0,
    PackedMessageCommitmentFunction<Backend> commitment_function = {},
    RuntimeProgressCallback progress = {}) {
    return LanedResidentMultiplicationLayerReductionProver<Backend>(
               eval, circuit, trace, layer, claim, transcript,
               source_proof_ingress_rns_limbs, reserved_transport_depth,
               std::move(commitment_function), std::move(progress))
        .run();
}

} // namespace laminate::gkr::laned_detail

#endif // LAMINATE_GKR_DETAIL_LANED_MULTIPLICATION_REFERENCE_PROVER_HPP
