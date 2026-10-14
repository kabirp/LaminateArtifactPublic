#ifndef LAMINATE_GATES_GATE_MLE_HPP
#define LAMINATE_GATES_GATE_MLE_HPP

/// @file gate_mle.hpp
/// @brief Gate-polynomial query boundary and direct verifier implementation.

#include "laminate/payload/ir/layered.hpp"
#include "laminate/setup.hpp"
#include "laminate/transcript/transcript.hpp"

#include <concepts>
#include <cstddef>
#include <memory>
#include <span>
#include <variant>
#include <vector>

namespace laminate::gates {

/// MLE of an affine layer's public linear matrix A(output, source).
struct AffineQuery {
    std::size_t layer_index = 0;
    std::span<const Fpk> output_point;
    std::span<const Fpk> source_point;
};

/// Scalar affine coefficient for a laned layer. Slot equality is deliberately
/// excluded because LaminateLaned fuses it into lazy witness packing.
struct LanedAffineWireQuery {
    std::size_t layer_index = 0;
    std::span<const Fpk> output_wire_point;
    std::span<const Fpk> source_wire_point;
};

/// Multiplication layers use setup-fixed paired halves and therefore have no
/// public gate polynomial to query. GateMLE queries cover affine relations
/// only.
using GateMleQuery = std::variant<AffineQuery, LanedAffineWireQuery>;

class BoundDirectAffineMle;
class RollingDirectAffineMle;

struct AffineSourceStructure {
    struct Term {
        std::size_t source = 0;
        std::size_t basis = 0;
    };
    std::size_t slot_basis_count = 0;
    /// Maximum simultaneously live generic slot vectors during reverse
    /// preparation; computed without allocating their N field entries.
    std::size_t peak_live_slot_basis_count = 0;
    std::vector<Term> terms;
};

/// Direct affine GateMLE evaluation prepared for one public output point.
///
/// `bind_source_wire_prefix` fixes a possibly partial source-wire point once.
/// The resulting sparse view returns
///
///   A(output_point, (bound_prefix, Boolean_suffix, u))
///
/// at every Boolean source-slot address `u`. Wide preparation propagates
/// shared slot bases backward through the local affine DAG; each node retains
/// at most eight basis components before materializing their combined vector.
/// Uniform additions therefore retain shared bases, and arbitrary diagonal
/// multipliers and rotations preserve their original order. Laned preparation
/// keeps its scalar sparse representation.
///
/// Binding scans the resulting source/basis terms into sparse suffix groups.
/// Keys remain in bit-reversed order for allocation-free binary searches;
/// binding never materializes a suffix-by-slot or suffix-by-basis table.
/// Existing rotation-named accessors index generic slot bases for Wide DAGs.
class PreparedDirectAffineMle {
  public:
    struct WeightedTerm {
        std::size_t source = 0;
        /// Generic slot-basis index; retained name for existing consumers.
        std::size_t rotation_index = 0;
        Fpk coefficient = Fpk::zero();
    };

    BoundDirectAffineMle bind_source_ciphertext_index_point(
        std::span<const Fpk> source_wire_prefix) const;
    /// Stateful MSB-first binding for the prover's sequential sumcheck.
    /// Each candidate evaluation and accepted challenge scans sparse affine
    /// terms once; neither operation sorts nor allocates a padded-domain
    /// prefix/suffix table.
    RollingDirectAffineMle rolling_source_wire_binding() const;

    /// Convenience form for a fully bound, possibly non-Boolean source wire.
    std::vector<Fpk> evaluate_boolean_source_slots(
        std::span<const Fpk> source_wire_point) const;
    std::size_t rotation_basis_count() const;
    std::size_t weighted_term_count() const;
    std::span<const WeightedTerm> weighted_terms() const;
    Fpk constant_evaluation() const;
    std::span<const Fpk> rotation_slot_basis(
        std::size_t rotation_index) const;

  private:
    struct SharedData;

    friend class DirectGateMle;
    friend class BoundDirectAffineMle;
    friend class RollingDirectAffineMle;

    std::shared_ptr<const SharedData> data_;
};

/// One sparse binding of a prepared affine GateMLE's source-wire prefix.
///
/// The view owns `O(S)` sparse suffix indexing and coefficients and shares the
/// prepared evaluator's immutable source terms and shared slot bases. Evaluating a
/// suffix always returns exactly N entries, including an all-zero table for a
/// suffix with no contributing public terms. A caller can therefore preserve
/// challenge-independent backend topology by scaling every witness record.
class BoundDirectAffineMle {
  public:
    struct SparseRotationCoefficient {
        std::size_t rotation_index = 0;
        Fpk coefficient = Fpk::zero();
        /// False only when the current fixed evaluation selects a Boolean
        /// branch absent from every combined term. Numerical zero from an
        /// earlier challenge or output claim remains true.
        bool fixed_point_support = true;
    };

    std::size_t boolean_suffix_count() const;
    std::size_t sparse_suffix_count() const;
    std::size_t rotation_basis_count() const;
    std::span<const SparseRotationCoefficient>
    sparse_rotation_coefficients(std::size_t boolean_suffix) const;
    std::vector<Fpk> evaluate_boolean_source_slots(
        std::size_t boolean_suffix) const;

  private:
    friend class PreparedDirectAffineMle;
    friend class RollingDirectAffineMle;

    std::shared_ptr<const PreparedDirectAffineMle::SharedData> data_;
    std::size_t suffix_count_ = 0;
    std::vector<std::size_t> sparse_suffixes_;
    /// `sparse_suffixes_` projected into the order in which the prepared
    /// source terms are stored. These keys are strictly increasing and make
    /// record-loop lookup allocation-free and hash-free.
    std::vector<std::size_t> sparse_suffix_order_keys_;
    std::vector<std::size_t> suffix_offsets_;
    std::vector<SparseRotationCoefficient> coefficients_;
};

/// Rolling source-wire prefix state for one prepared direct affine MLE.
class RollingDirectAffineMle {
  public:
    BoundDirectAffineMle evaluate_next(const Fpk &round_value) const;
    void bind(const Fpk &challenge);
    std::size_t bound_variables() const;
    std::size_t source_variables() const;
    bool complete() const;

  private:
    friend class PreparedDirectAffineMle;

    std::shared_ptr<const PreparedDirectAffineMle::SharedData> data_;
    std::vector<Fpk> prefix_weights_;
    std::size_t bound_variables_ = 0;
};

template <typename Provider>
concept GateMleProvider = requires(const Provider &provider,
                                   const GateMleQuery &query,
                                   std::size_t layer,
                                   std::span<const Fpk> point) {
    { provider.evaluate(query) } -> std::same_as<Fpk>;
    { provider.evaluate_affine_constant(layer, point) } -> std::same_as<Fpk>;
};

/// DirectGateMle evaluates the public sparse layer descriptors locally. It is
/// used by both Direct and DummyCommittedDirect profiles; the dummy digest is
/// transcript binding only and does not authenticate an outsourced result.
class DirectGateMle {
  public:
    explicit DirectGateMle(const payload::LayeredCircuit &circuit)
        : circuit_(&circuit) {}

    Fpk evaluate(const GateMleQuery &query) const;
    /// Evaluate two affine queries with a common source point in one sparse
    /// layer scan. The result is `first + second_weight * second`.
    Fpk evaluate_affine_pair(
        std::size_t layer_index,
        std::span<const Fpk> first_output_point,
        std::span<const Fpk> second_output_point,
        std::span<const Fpk> source_point,
        const Fpk &second_weight) const;
    PreparedDirectAffineMle prepare_affine(
        std::size_t layer_index,
        std::span<const Fpk> output_point) const;
    /// Same structural support and slot-basis grouping as prepare_affine,
    /// computed without materializing slot vectors. Used by cost accounting.
    AffineSourceStructure affine_structure(std::size_t layer_index) const;
    Fpk evaluate_affine_constant(std::size_t layer_index,
                                 std::span<const Fpk> output_point) const;
    /// Evaluate the affine constants at two output points in one layer scan.
    /// The result is `first + second_weight * second`.
    Fpk evaluate_affine_constant_pair(
        std::size_t layer_index,
        std::span<const Fpk> first_output_point,
        std::span<const Fpk> second_output_point,
        const Fpk &second_weight) const;

  private:
    Fpk evaluate(const AffineQuery &query) const;
    Fpk evaluate(const LanedAffineWireQuery &query) const;
    const payload::LayeredCircuit *circuit_;
};

static_assert(GateMleProvider<DirectGateMle>);

/// Bind the gate-verification profile, circuit digest, and every typed dummy
/// commitment before any proof challenge is sampled.
void observe_gate_mle_setup(const PublicSetup &setup, Transcript &transcript);

} // namespace laminate::gates

#endif // LAMINATE_GATES_GATE_MLE_HPP
