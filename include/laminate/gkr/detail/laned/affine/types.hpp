#ifndef LAMINATE_GKR_DETAIL_LANED_AFFINE_TYPES_HPP
#define LAMINATE_GKR_DETAIL_LANED_AFFINE_TYPES_HPP

/// @file types.hpp
/// @brief Protocol objects shared by file-backed and reference affine provers.

#include "laminate/gkr/laned.hpp"
#include "laminate/gkr/detail/laned/affine/internal/gate_claim.hpp"
#include "laminate/gkr/detail/laned/affine/internal/gate_table.hpp"
#include "laminate/gkr/detail/laned/geometry/layout.hpp"
#include "laminate/gkr/detail/shared/reduction/affine_round.hpp"
#include "laminate/fhe/storage/ciphertext.hpp"
#include "laminate/payload/setup/encoding.hpp"
#include "laminate/payload/trace/trace_wire_support.hpp"
#include "laminate/poly/eq.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

namespace laminate::gkr::laned_detail {

template <fhe::PersistableFheBackend Backend, typename TraceSource>
class LanedProver;

/// Evidence that one Laned source was matched to this layered circuit.
///
/// Standalone affine proving obtains this evidence by hashing and validating
/// the circuit once. The top-level GKR prover instead derives it from the
/// public setup's already-certified layered digest, so an affine reduction
/// never rescans the whole circuit merely to check source identity.
class LanedAffineSourceAdmission {
  public:
    template <typename TraceSource>
    static LanedAffineSourceAdmission validate(
        const payload::LayeredCircuit &circuit,
        const TraceSource &trace) {
        return from_certified_identity(circuit, trace,
                                       payload::digest(circuit));
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
                "LaminateLaned affine source admission mismatch");
        }
    }

  private:
    LanedAffineSourceAdmission(
        const payload::LayeredCircuit &circuit,
        Digest layered_circuit_id)
        : circuit_(&circuit), layered_circuit_id_(layered_circuit_id) {}

    /// Admit from an identity already certified by top-level setup
    /// validation. This path deliberately performs no circuit traversal.
    template <typename TraceSource>
    static LanedAffineSourceAdmission from_certified_identity(
        const payload::LayeredCircuit &circuit,
        const TraceSource &trace,
        const Digest &certified_layered_circuit_id) {
        if (trace.layered_circuit_id() != certified_layered_circuit_id) {
            throw std::invalid_argument(
                "LaminateLaned affine trace circuit mismatch");
        }
        return LanedAffineSourceAdmission(circuit,
                                          certified_layered_circuit_id);
    }

    template <fhe::PersistableFheBackend Backend, typename TraceSource>
    friend class LanedProver;

    const payload::LayeredCircuit *circuit_ = nullptr;
    Digest layered_circuit_id_{};
};

/// Result of one encrypted Laned affine reduction. `next_claim` carries a
/// plaintext zero placeholder, not an FHE ciphertext; verification returns a
/// separate claim containing the concrete weighted-source evaluation.
template <fhe::FheBackend Backend>
struct LanedAffineLayerReductionResult {
    EncryptedLanedAffineLayerReduction<Backend> proof;
    SingleClaim next_claim;
};

/// The two encrypted evaluations transmitted in one affine sumcheck round.
///
/// `at_one = R_j(1)` and `at_two = R_j(2)`. The omitted value `R_j(0)` is
/// reconstructed by the verifier from `claim_j = R_j(0) + R_j(1)`. Either
/// field may be a known public zero, represented by a null FHE value so the
/// backend performs no encryption or arithmetic for it.
template <fhe::FheBackend Backend>
using LanedAffineRoundEvaluations =
    ::laminate::gkr::detail::AffineRoundPair<
        fhe::ExtensionValue<Backend>>;

/// Public points evaluated in each affine round.
using LanedAffineRoundEvaluationPoints =
    ::laminate::gkr::detail::AffineRoundEvaluationPoints;

/// GateMLE suffix tables restricted at X=1 and X=2.
using LanedAffineGateRestrictions =
    ::laminate::gkr::detail::AffineRoundPair<std::vector<Fpk>>;

/// Public geometry of one Laned affine reduction.
///
/// The sumcheck first fixes ciphertext-index coordinates and then SIMD-slot
/// coordinates. `lane_point` is the output claim restricted to the lane
/// coordinates; its equality weights are fused into the source values before
/// those slot rounds begin.
struct LanedAffineLayerReductionGeometry {
    /// Packing of the layer whose value is currently claimed.
    packing::LanedPackingLayout output;
    /// Packing of the source layer to which this reduction moves the claim.
    packing::LanedPackingLayout source;
    /// Live source wires; omitted padded positions are known public zero.
    payload::LayerWireSupport source_support;
    /// Lane-coordinate suffix shared by every claim entering this layer.
    std::vector<Fpk> lane_point;
    /// Equality-polynomial values eq(lane_point, lane) fused into the source.
    std::vector<Fpk> lane_weights;
    /// Public table A(current_claim, source_wire) folded once per round.
    std::vector<Fpk> gate_table;
    /// Total ciphertext-index and SIMD-slot sumcheck rounds.
    std::size_t round_count = 0;
    /// Prefix rounds that bind packed ciphertext indices.
    std::size_t ciphertext_index_variables = 0;
    /// Suffix rounds that bind SIMD-slot coordinates.
    std::size_t slot_index_variables = 0;
    /// First challenge coordinate transformed by the terminal Hadamard map.
    std::size_t lane_begin = 0;

    static LanedAffineLayerReductionGeometry create(
        const payload::LayeredCircuit &circuit, std::size_t layer,
        const LayerClaim &claim,
        const payload::LayerWireSupport &source_support) {
        LanedAffineLayerReductionGeometry result;
        result.output = laned_layout(circuit, layer);
        result.source = laned_layout(circuit, layer + 1U);
        result.source_support = source_support;
        result.lane_point = common_lane_point(result.output, claim);
        result.lane_weights = poly::eq_evaluations(result.lane_point);
        result.gate_table = affine_active_table(
            circuit, layer, result.output, result.source, claim);
        result.round_count = layout_variables(result.source);
        result.ciphertext_index_variables = log2_exact(
            result.source.padded_ciphertext_count,
            "LaminateLaned affine ciphertext variables");
        result.slot_index_variables = log2_exact(
            result.source.slot_count,
            "LaminateLaned affine slot variables");
        result.lane_begin = result.round_count - result.lane_point.size();
        return result;
    }
};

/// Mutable state fixed by the Fiat--Shamir challenge after each affine round.
///
/// The challenge vector is the point at which the source MLE is progressively
/// evaluated. `gate_table_` is the matching public GateMLE restriction. They
/// must advance together: after `fix_next_variable(r_j)`, both represent the
/// same prefix `(r_0, ..., r_j)` for the following round.
class LanedAffineCoordinateFixingState {
  public:
    LanedAffineCoordinateFixingState(
        std::span<const Fpk> gate_table, std::size_t round_count)
        : gate_table_(gate_table) {
        challenges_.reserve(round_count);
    }

    LanedAffineGateRestrictions evaluate_public_gate(
        const LanedAffineRoundEvaluationPoints &points) {
        return gate_table_.round_evaluations(points);
    }

    void fix_next_variable(const Fpk &challenge) {
        challenges_.push_back(challenge);
        gate_table_.bind(challenge);
    }

    std::span<const Fpk> fixed_point() const { return challenges_; }

    std::span<const Fpk> slot_point(
        std::size_t ciphertext_variable_count) const {
        return fixed_point().subspan(ciphertext_variable_count);
    }

    const std::vector<Fpk> &owned_point() const { return challenges_; }

    std::uint64_t public_gate_entries_processed() const {
        return gate_table_.entries_processed();
    }

  private:
    /// Public GateMLE table restricted at every challenge sampled so far.
    AffineGateTableFoldState gate_table_;
    /// Ordered Fiat--Shamir challenges; this becomes the terminal source point.
    std::vector<Fpk> challenges_;
};

} // namespace laminate::gkr::laned_detail

#endif // LAMINATE_GKR_DETAIL_LANED_AFFINE_TYPES_HPP
