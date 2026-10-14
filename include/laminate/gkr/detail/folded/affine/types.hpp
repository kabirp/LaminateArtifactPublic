#ifndef LAMINATE_GKR_DETAIL_FOLDED_AFFINE_TYPES_HPP
#define LAMINATE_GKR_DETAIL_FOLDED_AFFINE_TYPES_HPP

/// @file types.hpp
/// @brief Claims and round values for a Folded affine layer reduction.

#include "laminate/fhe/storage/ciphertext.hpp"
#include "laminate/gkr/folded.hpp"
#include "laminate/gkr/detail/base/geometry/circuit.hpp"
#include "laminate/gkr/detail/shared/reduction/affine_round.hpp"
#include "laminate/payload/setup/encoding.hpp"

#include <cstddef>
#include <stdexcept>
#include <vector>

namespace laminate::gkr::folded_detail {

template <fhe::PersistableFheBackend Backend, typename TraceSource>
class FoldedProver;

/// Evidence that one Folded source was matched to this layered circuit.
///
/// Standalone affine proving obtains this evidence by hashing and validating
/// the circuit once. The top-level GKR prover instead derives it from the
/// public setup's already-certified layered digest, so an affine reduction
/// never rescans the whole circuit merely to check source identity.
class FoldedAffineSourceAdmission {
  public:
    template <typename TraceSource>
    static FoldedAffineSourceAdmission validate(
        const payload::LayeredCircuit &circuit,
        const TraceSource &trace) {
        return from_certified_identity(
            circuit, trace, payload::digest(circuit));
    }

    /// Check that this evidence is being consumed with the same circuit and
    /// with a source carrying the admitted layered-circuit identity.
    template <typename TraceSource>
    void require_matches(
        const payload::LayeredCircuit &circuit,
        const TraceSource &trace) const {
        if (circuit_ != &circuit ||
            trace.layered_circuit_id() != layered_circuit_id_) {
            throw std::invalid_argument(
                "LaminateFolded affine source admission mismatch");
        }
    }

  private:
    FoldedAffineSourceAdmission(
        const payload::LayeredCircuit &circuit,
        Digest layered_circuit_id)
        : circuit_(&circuit),
          layered_circuit_id_(layered_circuit_id) {}

    /// Admit from an identity already certified by top-level setup
    /// validation. This path deliberately performs no circuit traversal.
    template <typename TraceSource>
    static FoldedAffineSourceAdmission from_certified_identity(
        const payload::LayeredCircuit &circuit,
        const TraceSource &trace,
        const Digest &certified_layered_circuit_id) {
        if (trace.layered_circuit_id() !=
            certified_layered_circuit_id) {
            throw std::invalid_argument(
                "LaminateFolded affine trace circuit mismatch");
        }
        return FoldedAffineSourceAdmission(
            circuit, certified_layered_circuit_id);
    }

    template <fhe::PersistableFheBackend Backend, typename TraceSource>
    friend class FoldedProver;

    const payload::LayeredCircuit *circuit_ = nullptr;
    Digest layered_circuit_id_{};
};

/// The two evaluations transmitted for a degree-two affine sumcheck round.
///
/// If `R_j` is the round polynomial, the prover sends `R_j(1)` and `R_j(2)`.
/// The verifier reconstructs `R_j(0) = claim_j - R_j(1)`. Either field may be
/// encrypted or the distinguished public/null zero; a null zero means the
/// corresponding polynomial evaluation requires no FHE operation.
template <fhe::FheBackend Backend>
using FoldedAffineRoundEvaluations =
    ::laminate::gkr::detail::AffineRoundPair<
        fhe::ExtensionValue<Backend>>;

/// Public points evaluated by every Folded affine round.
using FoldedAffineRoundEvaluationPoints =
    ::laminate::gkr::detail::AffineRoundEvaluationPoints;

/// GateMLE suffix tables restricted at X=1 and X=2.
using FoldedAffineGateRestrictions =
    ::laminate::gkr::detail::AffineRoundPair<std::vector<Fpk>>;

/// Public dimensions of one Folded affine reduction.
struct FoldedAffineReductionGeometry {
    /// Source-ciphertext coordinates fixed before constructing a checkpoint.
    std::size_t ciphertext_index_variables = 0;
    /// Packed SIMD-slot coordinates fixed from that checkpoint.
    std::size_t slot_index_variables = 0;
    /// Total number of affine sumcheck rounds.
    std::size_t round_count = 0;

    static FoldedAffineReductionGeometry create(
        const payload::LayeredCircuit &circuit, std::size_t layer) {
        FoldedAffineReductionGeometry result;
        result.ciphertext_index_variables =
            base_detail::ciphertext_index_variables(circuit, layer + 1U);
        result.slot_index_variables =
            base_detail::slot_index_variables(circuit);
        result.round_count = result.ciphertext_index_variables +
                             result.slot_index_variables;
        return result;
    }
};

/// Output of one encrypted Folded affine reduction.
///
/// `proof` contains the encrypted `R_j(1), R_j(2)` messages and terminal
/// source evaluation. The prover knows the next evaluation point but cannot
/// decrypt its value, so `next_claim.value` is a public-zero placeholder.
/// Verification returns the same point with its concrete plaintext value.
template <fhe::FheBackend Backend> struct FoldedAffineReductionResult {
    /// Messages appended to the enclosing Folded GKR proof.
    EncryptedFoldedAffineLayerReduction<Backend> proof;
    /// Source-layer claim carried to the next GKR reduction.
    SingleClaim next_claim;
};

} // namespace laminate::gkr::folded_detail

#endif // LAMINATE_GKR_DETAIL_FOLDED_AFFINE_TYPES_HPP
