#ifndef LAMINATE_GKR_DETAIL_BASE_AFFINE_TYPES_HPP
#define LAMINATE_GKR_DETAIL_BASE_AFFINE_TYPES_HPP

/// @file types.hpp
/// @brief Semantic values and public geometry for Base affine reductions.

#include "laminate/gkr/base.hpp"
#include "laminate/gkr/detail/base/geometry/circuit.hpp"
#include "laminate/gkr/detail/shared/reduction/affine_round.hpp"
#include "laminate/fhe/storage/ciphertext.hpp"
#include "laminate/payload/setup/encoding.hpp"

#include <stdexcept>
#include <vector>

namespace laminate::gkr::base_detail {

template <fhe::PersistableFheBackend Backend, typename TraceSource>
class BaseProver;

/// Evidence that one Base source was matched to this layered circuit.
///
/// A standalone affine reduction obtains this evidence by hashing the circuit.
/// The top-level Base prover instead uses the layered digest already certified
/// by public-setup validation. Its per-layer recurrence therefore checks only
/// object identity and a fixed-size digest; it never rescans the circuit.
class BaseAffineSourceAdmission {
  public:
    template <typename TraceSource>
    static BaseAffineSourceAdmission validate(
        const payload::LayeredCircuit &circuit,
        const TraceSource &trace) {
        return from_certified_identity(circuit, trace,
                                       payload::digest(circuit));
    }

    /// Require the exact circuit object and source identity admitted above.
    template <typename TraceSource>
    void require_matches(
        const payload::LayeredCircuit &circuit,
        const TraceSource &trace) const {
        if (circuit_ != &circuit ||
            trace.layered_circuit_id() != layered_circuit_id_) {
            throw std::invalid_argument(
                "LaminateBase affine source admission mismatch");
        }
    }

  private:
    BaseAffineSourceAdmission(
        const payload::LayeredCircuit &circuit,
        Digest layered_circuit_id)
        : circuit_(&circuit),
          layered_circuit_id_(layered_circuit_id) {}

    /// Admit from the layered digest already certified by top-level setup
    /// validation. This fixed-size comparison performs no circuit traversal.
    template <typename TraceSource>
    static BaseAffineSourceAdmission from_certified_identity(
        const payload::LayeredCircuit &circuit,
        const TraceSource &trace,
        const Digest &certified_layered_circuit_id) {
        if (trace.layered_circuit_id() != certified_layered_circuit_id) {
            throw std::invalid_argument(
                "LaminateBase affine trace circuit mismatch");
        }
        return BaseAffineSourceAdmission(
            circuit, certified_layered_circuit_id);
    }

    template <fhe::PersistableFheBackend Backend, typename TraceSource>
    friend class BaseProver;

    const payload::LayeredCircuit *circuit_ = nullptr;
    Digest layered_circuit_id_{};
};

/// Affine rounds use the shared selected-endpoint/X=2 representation with the
/// selected endpoint fixed to X=1.
using AffineRoundEvaluationPoints =
    ::laminate::gkr::detail::AffineRoundEvaluationPoints;

/// Encrypted values R_j(1) and R_j(2) produced by one affine FHE scan.
template <fhe::FheBackend Backend>
using EncryptedAffineRoundEvaluations =
    ::laminate::gkr::detail::AffineRoundPair<
        fhe::ExtensionValue<Backend>>;

/// Decrypted scalar values R_j(1) and R_j(2) used by the verifier.
using DecodedAffineRoundEvaluations =
    ::laminate::gkr::detail::AffineRoundPair<Fpk>;

/// Mutable verifier state after fixing the first ciphertext-index coordinates.
/// `reduced_claim` is R_j at that fixed prefix.
struct AffineVerificationState {
    Fpk reduced_claim = Fpk::zero();
    std::vector<Fpk> ciphertext_index_challenges;
};

template <fhe::FheBackend Backend> struct ProvedAffine {
    /// Complete reduction message in canonical transcript order.
    EncryptedBaseAffineLayerReduction<Backend> proof;
    /// Source-layer claim consumed by the next GKR reduction.
    SingleClaim next_claim;
};

struct AffineGeometry {
    /// Number of source-ciphertext coordinates reduced under FHE.
    std::size_t ciphertext_index_variables = 0;
    /// SIMD coordinates left packed until the client terminal check.
    std::size_t slot_index_variables = 0;

    static AffineGeometry create(
        const payload::LayeredCircuit &circuit, std::size_t layer) {
        return AffineGeometry{
            ::laminate::gkr::base_detail::ciphertext_index_variables(
                circuit, layer + 1U),
            ::laminate::gkr::base_detail::slot_index_variables(circuit)};
    }
};

} // namespace laminate::gkr::base_detail

#endif // LAMINATE_GKR_DETAIL_BASE_AFFINE_TYPES_HPP
