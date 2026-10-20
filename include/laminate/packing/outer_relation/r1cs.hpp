#ifndef LAMINATE_PACKING_OUTER_RELATION_R1CS_HPP
#define LAMINATE_PACKING_OUTER_RELATION_R1CS_HPP

/// @file r1cs.hpp
/// @brief Sparse native-Q R1CS rows for transcript packing.

#include "laminate/packing/outer_relation/constraints.hpp"

#include <cstdint>
#include <optional>
#include <vector>

namespace laminate::packing {

class OuterRelationR1csAssignmentView;

enum class OuterRelationR1csVariableKind : std::uint8_t {
    ConstantOne,
    PublicInput,
    Witness,
};

/// One variable in the conventional assignment `[1 | public | witness]`.
struct OuterRelationR1csVariable {
    OuterRelationR1csVariableKind kind =
        OuterRelationR1csVariableKind::ConstantOne;
    std::uint64_t index = 0;

    bool operator==(const OuterRelationR1csVariable &) const = default;
};

struct OuterRelationR1csTerm {
    OuterRelationR1csVariable variable;
    std::uint64_t coefficient = 0;

    bool operator==(const OuterRelationR1csTerm &) const = default;
};

using OuterRelationR1csLinearCombination =
    std::vector<OuterRelationR1csTerm>;

/// One sparse row `(A z) * (B z) = C z` over the final prime field.
struct OuterRelationR1csRow {
    std::uint64_t constraint_index = 0;
    OuterRelationConstraintFamily family =
        OuterRelationConstraintFamily::ChallengeBitBooleanity;
    OuterRelationR1csLinearCombination a;
    OuterRelationR1csLinearCombination b;
    OuterRelationR1csLinearCombination c;
};

/// Flat assignment matching `OuterRelationVariableLayout`.
struct OuterRelationR1csAssignment {
    std::vector<std::uint64_t> public_inputs;
    std::vector<std::uint64_t> witness;
};

/// Sparse matrix-entry ledger for `(A z) * (B z) = C z`.
struct OuterRelationR1csSize {
    std::uint64_t a_nonzero_entries = 0;
    std::uint64_t b_nonzero_entries = 0;
    std::uint64_t c_nonzero_entries = 0;
    std::uint64_t total_nonzero_entries = 0;
    std::uint64_t packing_a_entries = 0;
    bool packing_a_entries_are_exact = false;
};

/// Count sparse entries without streaming the rows. If the exact number of
/// nonzero fixed packing constants is absent, the preprocessed dense upper
/// bound from the relation plan is used and labeled conservative.
OuterRelationR1csSize estimate_outer_relation_r1cs_size(
    const OuterRelationPlan &plan,
    std::optional<std::uint64_t> exact_packing_nonzero_entries = std::nullopt);

/// Exact overload for a materialized, validated native packing operator.
OuterRelationR1csSize estimate_outer_relation_r1cs_size(
    const OuterRelationPlan &plan,
    const NativePackingOperator &packing_operator);

/// Flatten one concrete relation assignment into `[public | witness]` order.
OuterRelationR1csAssignment make_outer_relation_r1cs_assignment(
    const OuterRelationPlan &plan,
    const OuterRelationPublicInputs &public_inputs,
    const OuterRelationWitnessInputs &witness_inputs,
    const OuterRelationAuxiliaryWitness &auxiliary_witness);

/// Validated random-access sparse row builder.
///
/// The referenced plan and optional fixed operator must outlive the builder.
/// When supplied, the operator is validated once in the constructor; `row()`
/// then allocates only the terms of the requested row, at most `O(r)`.
class OuterRelationR1csBuilder {
  public:
    /// Construct a builder for the four rows that do not need fixed packing
    /// constants. Asking this builder for a packing-equality row throws.
    explicit OuterRelationR1csBuilder(const OuterRelationPlan &plan);

    OuterRelationR1csBuilder(const OuterRelationPlan &plan,
                             const NativePackingOperator &packing_operator);

    /// Convenience random access. This allocates fresh term vectors; use
    /// `materialize_into()` or `OuterRelationR1csCursor` for bulk traversal.
    OuterRelationR1csRow row(std::uint64_t constraint_index) const;

    /// Replace `destination` with one row while retaining its vector capacity.
    /// This is the target-scale path: after the largest row has been seen, no
    /// further term-buffer growth is required.
    void materialize_into(std::uint64_t constraint_index,
                          OuterRelationR1csRow &destination) const;

  private:
    const OuterRelationPlan *plan_;
    const NativePackingOperator *packing_operator_ = nullptr;
};

/// Forward cursor whose returned row storage is reused on every call.
///
/// The plan and optional fixed operator must outlive the cursor. The reference
/// returned by `next()` is invalidated by the next call. The default plan-only
/// constructor traverses the dynamic prefix and stops before fixed packing
/// equalities; its ranged overload likewise cannot cross that boundary.
class OuterRelationR1csCursor {
  public:
    explicit OuterRelationR1csCursor(const OuterRelationPlan &plan);
    OuterRelationR1csCursor(const OuterRelationPlan &plan,
                            std::uint64_t begin, std::uint64_t end);
    OuterRelationR1csCursor(
        const OuterRelationPlan &plan,
        const NativePackingOperator &packing_operator);
    OuterRelationR1csCursor(
        const OuterRelationPlan &plan,
        const NativePackingOperator &packing_operator,
        std::uint64_t begin, std::uint64_t end);

    bool empty() const;
    std::uint64_t position() const;
    std::uint64_t remaining() const;

    const OuterRelationR1csRow &next();

  private:
    static void validate_range(const OuterRelationPlan &plan,
                               std::uint64_t begin, std::uint64_t end,
                               bool has_packing_operator);

    OuterRelationR1csBuilder builder_;
    OuterRelationR1csRow storage_;
    std::uint64_t cursor_ = 0;
    std::uint64_t end_ = 0;
};

/// Evaluate one sparse row against a concrete assignment modulo native `Q`.
/// Malformed lengths, variables, coefficients, or residues throw.
bool evaluate_outer_relation_r1cs_row(
    const OuterRelationPlan &plan, const OuterRelationR1csRow &row,
    const OuterRelationR1csAssignment &assignment);

/// Evaluate against the canonical lazy witness without flattening challenge
/// bits or the `2NTf` product auxiliaries. The view must reference `plan`.
bool evaluate_outer_relation_r1cs_row(
    const OuterRelationPlan &plan, const OuterRelationR1csRow &row,
    const OuterRelationR1csAssignmentView &assignment);

} // namespace laminate::packing

#endif // LAMINATE_PACKING_OUTER_RELATION_R1CS_HPP
