#ifndef LAMINATE_GKR_DETAIL_FOLDED_REFERENCE_MULTIPLICATION_PROVER_HPP
#define LAMINATE_GKR_DETAIL_FOLDED_REFERENCE_MULTIPLICATION_PROVER_HPP

/// @file multiplication_prover.hpp
/// @brief Resident Folded multiplication prover for tests and analysis.

#include "laminate/gkr/detail/folded/reference/multiplication_source.hpp"
#include "laminate/gkr/detail/folded/multiplication/types.hpp"
#include "laminate/gkr/detail/shared/dense_multiplication/reference/prover.hpp"
#include "laminate/runtime_progress.hpp"

#include <cstddef>
#include <utility>

namespace laminate::gkr::folded_detail {

/// Folded transcript domain, result spelling, and progress labels consumed by
/// the shared dense multiplication recurrence. This type contains no protocol
/// state or arithmetic.
struct FoldedResidentMultiplicationTraits {
    static constexpr ProtocolVariant variant =
        ProtocolVariant::LaminateFolded;
    static constexpr RuntimeProgressStage checkpoint_stage =
        RuntimeProgressStage::FoldedMultiplicationSlotCheckpoint;
    static constexpr RuntimeProgressStage sumcheck_stage =
        RuntimeProgressStage::FoldedMultiplicationSumcheckRound;
    static constexpr const char *protocol_name = "LaminateFolded";

    template <fhe::FheBackend Backend>
    using Result = FoldedMultiplicationReductionResult<Backend>;
    using Geometry = FoldedMultiplicationReductionGeometry;
};

/// Folded geometry and transcript labels around the explicit recurrence in
/// `detail/shared/dense_multiplication/reference/prover.hpp`. Its product FHE
/// operations are visible in
/// `detail/shared/dense_multiplication/reference/evaluator.hpp` and use the
/// named helpers in `detail/shared/dense_multiplication/accumulation.hpp`;
/// slot-round extension operations live in
/// `detail/shared/dense_multiplication/rounds.hpp`.
template <fhe::FheBackend Backend>
class FoldedResidentMultiplicationLayerReductionProver {
  public:
    using DenseMultiplicationRecurrence = ::laminate::gkr::detail::
        ReferencePackedDenseMultiplicationProver<
            Backend, FoldedResidentMultiplicationTraits,
            FoldedResidentMultiplicationSource<Backend>>;

    FoldedResidentMultiplicationLayerReductionProver(
        const typename Backend::EvalContext &eval,
        const payload::LayeredCircuit &circuit,
        const payload::EncryptedTrace<Backend> &trace, std::size_t layer,
        const SingleClaim &claim, Transcript &transcript,
        std::size_t reserved_transport_depth,
        PackedMessageCommitmentFunction<Backend> commitment_function = {},
        RuntimeProgressCallback progress = {})
        : geometry_(FoldedMultiplicationReductionGeometry::create(
              circuit, layer, claim)),
          source_(make_folded_resident_multiplication_source<Backend>(
              circuit, trace, layer, geometry_.pair_count)),
          recurrence_(eval, geometry_, source_, layer, claim, transcript,
                      reserved_transport_depth,
                      std::move(commitment_function),
                      std::move(progress)) {}

    FoldedMultiplicationReductionResult<Backend> run() {
        // Step 1: Execute Folded's equality-stripped multiplication
        // recurrence. It proves
        //   claim = sum_(i,s) eq(output_point,(i,s)) L(i,s) R(i,s),
        // then interpolates their selector to return one source-layer claim.
        return recurrence_.run();
    }

  private:
    /// Public split between pair-index and packed-slot sumcheck coordinates.
    FoldedMultiplicationReductionGeometry geometry_;
    /// Alias-aware view of the resident left/right source pairs.
    FoldedResidentMultiplicationSource<Backend> source_;
    /// Typed shared recurrence; all Folded-specific inputs are fixed above.
    DenseMultiplicationRecurrence recurrence_;
};

template <fhe::FheBackend Backend>
FoldedMultiplicationReductionResult<Backend>
prove_multiplication_resident_dense(
    const typename Backend::EvalContext &eval,
    const payload::LayeredCircuit &circuit,
    const payload::EncryptedTrace<Backend> &trace, std::size_t layer,
    const SingleClaim &claim, Transcript &transcript,
    std::size_t reserved_transport_depth = 0,
    PackedMessageCommitmentFunction<Backend> commitment_function = {},
    RuntimeProgressCallback progress = {}) {
    return FoldedResidentMultiplicationLayerReductionProver<Backend>(
               eval, circuit, trace, layer, claim, transcript,
               reserved_transport_depth, std::move(commitment_function),
               std::move(progress))
        .run();
}

} // namespace laminate::gkr::folded_detail

#endif // LAMINATE_GKR_DETAIL_FOLDED_REFERENCE_MULTIPLICATION_PROVER_HPP
