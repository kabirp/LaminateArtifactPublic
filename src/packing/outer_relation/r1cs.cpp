/// @file r1cs.cpp
/// @brief Sparse row materialization and native-Q evaluation.

#include "laminate/packing/outer_relation/r1cs.hpp"

#include "laminate/packing/outer_relation/assignment.hpp"

#include <algorithm>
#include <limits>
#include <span>
#include <stdexcept>
#include <string>
#include <type_traits>

namespace laminate::packing {
namespace {

std::size_t as_size(std::uint64_t value, const char *label) {
    if (value > std::numeric_limits<std::size_t>::max()) {
        throw std::overflow_error(std::string(label) + " exceeds size_t");
    }
    return static_cast<std::size_t>(value);
}

std::uint64_t checked_add(std::uint64_t left, std::uint64_t right,
                          const char *label) {
    if (right > std::numeric_limits<std::uint64_t>::max() - left) {
        throw std::overflow_error(std::string(label) + " overflows u64");
    }
    return left + right;
}

std::uint64_t checked_mul(std::uint64_t left, std::uint64_t right,
                          const char *label) {
    if (left != 0 &&
        right > std::numeric_limits<std::uint64_t>::max() / left) {
        throw std::overflow_error(std::string(label) + " overflows u64");
    }
    return left * right;
}

void require_size(std::size_t actual, std::uint64_t expected,
                  const char *label) {
    if (actual != as_size(expected, label)) {
        throw std::invalid_argument(std::string("outer R1CS: wrong ") +
                                    label + " length");
    }
}

void require_residues(std::span<const std::uint64_t> values,
                      std::uint64_t modulus, const char *label) {
    if (std::any_of(values.begin(), values.end(),
                    [=](std::uint64_t value) {
                        return value >= modulus;
                    })) {
        throw std::invalid_argument(std::string("outer R1CS: ") + label +
                                    " contains a noncanonical residue");
    }
}

OuterRelationR1csVariable constant_one() {
    return OuterRelationR1csVariable{
        .kind = OuterRelationR1csVariableKind::ConstantOne,
        .index = 0,
    };
}

OuterRelationR1csVariable public_variable(
    OuterRelationPublicVariable variable) {
    return OuterRelationR1csVariable{
        .kind = OuterRelationR1csVariableKind::PublicInput,
        .index = variable.index,
    };
}

OuterRelationR1csVariable witness_variable(
    OuterRelationWitnessVariable variable) {
    return OuterRelationR1csVariable{
        .kind = OuterRelationR1csVariableKind::Witness,
        .index = variable.index,
    };
}

OuterRelationR1csTerm term(OuterRelationR1csVariable variable,
                           std::uint64_t coefficient = 1) {
    return OuterRelationR1csTerm{variable, coefficient};
}

void reset_row(OuterRelationR1csRow &row,
               const OuterRelationConstraintDescriptor &descriptor) {
    row.constraint_index = descriptor.index;
    row.family = descriptor.family;
    row.a.clear();
    row.b.clear();
    row.c.clear();
}

void append_one(OuterRelationR1csLinearCombination &combination) {
    combination.push_back(term(constant_one()));
}

void materialize_booleanity_row(
    const OuterRelationPlan &plan,
    const ChallengeBitBooleanityConstraint &constraint,
    OuterRelationR1csRow &row) {
    const auto bit = witness_variable(constraint.bit);
    row.a.push_back(term(bit));
    row.b.push_back(term(bit));
    row.b.push_back(term(constant_one(), plan.shape.native_modulus - 1));
}

void materialize_recomposition_row(
    const ChallengeWordRecompositionConstraint &constraint,
    OuterRelationR1csRow &row) {
    row.a.reserve(constraint.bit_count);
    for (std::size_t offset = 0; offset < constraint.bit_count; ++offset) {
        row.a.push_back(term(
            witness_variable(OuterRelationWitnessVariable{
                constraint.first_bit.index + offset}),
            std::uint64_t{1} << offset));
    }
    append_one(row.b);
    row.c.push_back(term(public_variable(constraint.packed_word)));
}

void materialize_product_row(
    const OuterRelationPlan &plan,
    const WellFormednessProductConstraint &constraint,
    OuterRelationR1csRow &row) {
    row.a.push_back(term(witness_variable(constraint.plus_bit)));
    row.a.push_back(term(witness_variable(constraint.minus_bit),
                         plan.shape.native_modulus - 1));
    row.b.push_back(
        term(witness_variable(constraint.aligned_coordinate)));
    row.c.push_back(term(witness_variable(constraint.product)));
}

void materialize_test_equality_row(
    const RevealedTestEqualityConstraint &constraint,
    OuterRelationR1csRow &row) {
    row.a.reserve(constraint.product_count);
    for (std::size_t input = 0; input < constraint.product_count; ++input) {
        row.a.push_back(term(witness_variable(
            OuterRelationWitnessVariable{
                constraint.first_product.index +
                input * constraint.product_stride})));
    }
    append_one(row.b);
    row.c.push_back(term(public_variable(constraint.revealed_coordinate)));
}

const NativePackingRow &native_packing_row(
    const NativePackingOperator &packing_operator,
    const RevealedPackingEqualityConstraint &constraint) {
    return packing_operator.rows.at(
        constraint.logical_output * packing_operator.digit_count +
        constraint.digit);
}

void materialize_packing_equality_row(
    const OuterRelationPlan &plan,
    const NativePackingOperator &packing_operator,
    const RevealedPackingEqualityConstraint &constraint,
    OuterRelationR1csRow &row) {
    const NativePackingRow &packing_row =
        native_packing_row(packing_operator, constraint);
    row.a.reserve(packing_row.contributions.size());
    for (const NativePackingContribution &contribution :
         packing_row.contributions) {
        const std::uint64_t coefficient =
            contribution
                .multiplier_ntt_coordinates[constraint.ntt_coordinate];
        if (coefficient == 0) {
            continue;
        }
        row.a.push_back(term(
            OuterRelationR1csVariable{
                .kind = OuterRelationR1csVariableKind::Witness,
                .index = plan.aligned_coordinate_witness_index(
                    contribution.aligned_ciphertext, constraint.component,
                    constraint.ntt_coordinate),
            },
            coefficient));
    }
    append_one(row.b);
    row.c.push_back(term(public_variable(constraint.revealed_coordinate)));
}

void materialize_row_into(
    const OuterRelationPlan &plan,
    const NativePackingOperator *packing_operator,
    const OuterRelationConstraintDescriptor &descriptor,
    OuterRelationR1csRow &row) {
    reset_row(row, descriptor);
    std::visit(
        [&](const auto &constraint) {
            using Constraint = std::decay_t<decltype(constraint)>;
            if constexpr (std::is_same_v<
                              Constraint,
                              ChallengeBitBooleanityConstraint>) {
                materialize_booleanity_row(plan, constraint, row);
            } else if constexpr (std::is_same_v<
                                     Constraint,
                                     ChallengeWordRecompositionConstraint>) {
                materialize_recomposition_row(constraint, row);
            } else if constexpr (std::is_same_v<
                                     Constraint,
                                     WellFormednessProductConstraint>) {
                materialize_product_row(plan, constraint, row);
            } else if constexpr (std::is_same_v<
                                     Constraint,
                                     RevealedTestEqualityConstraint>) {
                materialize_test_equality_row(constraint, row);
            } else {
                if (packing_operator == nullptr) {
                    throw std::logic_error(
                        "outer R1CS: packing row needs a fixed operator");
                }
                materialize_packing_equality_row(
                    plan, *packing_operator, constraint, row);
            }
        },
        descriptor.equation);
}

std::uint64_t add_mod(std::uint64_t left, std::uint64_t right,
                      std::uint64_t modulus) {
    return static_cast<std::uint64_t>(
        (static_cast<unsigned __int128>(left) + right) % modulus);
}

std::uint64_t mul_mod(std::uint64_t left, std::uint64_t right,
                      std::uint64_t modulus) {
    return static_cast<std::uint64_t>(
        (static_cast<unsigned __int128>(left) * right) % modulus);
}

std::uint64_t variable_value(
    const OuterRelationR1csVariable &variable,
    const OuterRelationR1csAssignment &assignment) {
    switch (variable.kind) {
    case OuterRelationR1csVariableKind::ConstantOne:
        if (variable.index != 0) {
            throw std::invalid_argument(
                "outer R1CS: constant-one index is not zero");
        }
        return 1;
    case OuterRelationR1csVariableKind::PublicInput:
        return assignment.public_inputs.at(as_size(
            variable.index, "public variable index"));
    case OuterRelationR1csVariableKind::Witness:
        return assignment.witness.at(as_size(
            variable.index, "witness variable index"));
    }
    throw std::logic_error("outer R1CS: unknown variable kind");
}

std::uint64_t variable_value(
    const OuterRelationR1csVariable &variable,
    const OuterRelationR1csAssignmentView &assignment) {
    switch (variable.kind) {
    case OuterRelationR1csVariableKind::ConstantOne:
        if (variable.index != 0) {
            throw std::invalid_argument(
                "outer R1CS: constant-one index is not zero");
        }
        return 1;
    case OuterRelationR1csVariableKind::PublicInput:
        return assignment.public_value(variable.index);
    case OuterRelationR1csVariableKind::Witness:
        return assignment.witness_value(variable.index);
    }
    throw std::logic_error("outer R1CS: unknown variable kind");
}

template <typename Assignment>
std::uint64_t evaluate_linear_combination(
    const OuterRelationR1csLinearCombination &combination,
    const Assignment &assignment, std::uint64_t modulus) {
    std::uint64_t result = 0;
    for (const OuterRelationR1csTerm &item : combination) {
        if (item.coefficient >= modulus) {
            throw std::invalid_argument(
                "outer R1CS: term coefficient is not canonical");
        }
        result = add_mod(
            result,
            mul_mod(item.coefficient,
                    variable_value(item.variable, assignment), modulus),
            modulus);
    }
    return result;
}

template <typename Assignment>
bool evaluate_validated_row(
    const OuterRelationPlan &plan, const OuterRelationR1csRow &row,
    const Assignment &assignment) {
    if (row.constraint_index >= plan.constraints.total) {
        throw std::out_of_range("outer R1CS row index is out of range");
    }
    const std::uint64_t left = evaluate_linear_combination(
        row.a, assignment, plan.shape.native_modulus);
    const std::uint64_t right = evaluate_linear_combination(
        row.b, assignment, plan.shape.native_modulus);
    const std::uint64_t output = evaluate_linear_combination(
        row.c, assignment, plan.shape.native_modulus);
    return mul_mod(left, right, plan.shape.native_modulus) == output;
}

} // namespace

OuterRelationR1csSize estimate_outer_relation_r1cs_size(
    const OuterRelationPlan &plan,
    std::optional<std::uint64_t> exact_packing_nonzero_entries) {
    const std::uint64_t bits =
        plan.variables.witness.derived_challenge_bits.count;
    const std::uint64_t words =
        plan.variables.public_inputs.packed_challenge_words.count;
    const std::uint64_t products =
        plan.variables.witness.well_formedness_products.count;
    const std::uint64_t tests =
        plan.variables.public_inputs.revealed_test_coordinates.count;
    const std::uint64_t packing_outputs =
        plan.variables.public_inputs.revealed_packing_coordinates.count;
    const std::uint64_t packing_entries = exact_packing_nonzero_entries.value_or(
        plan.fixed_packing.constant_matrix_terms);

    const std::uint64_t a = checked_add(
        checked_add(bits, bits, "outer R1CS A entries"),
        checked_add(
            checked_mul(2, products, "outer R1CS A entries"),
            checked_add(products, packing_entries,
                        "outer R1CS A entries"),
            "outer R1CS A entries"),
        "outer R1CS A entries");
    const std::uint64_t b = checked_add(
        checked_add(checked_mul(2, bits, "outer R1CS B entries"), words,
                    "outer R1CS B entries"),
        checked_add(products,
                    checked_add(tests, packing_outputs,
                                "outer R1CS B entries"),
                    "outer R1CS B entries"),
        "outer R1CS B entries");
    const std::uint64_t c = checked_add(
        checked_add(words, products, "outer R1CS C entries"),
        checked_add(tests, packing_outputs, "outer R1CS C entries"),
        "outer R1CS C entries");
    return OuterRelationR1csSize{
        .a_nonzero_entries = a,
        .b_nonzero_entries = b,
        .c_nonzero_entries = c,
        .total_nonzero_entries = checked_add(
            checked_add(a, b, "outer R1CS total entries"), c,
            "outer R1CS total entries"),
        .packing_a_entries = packing_entries,
        .packing_a_entries_are_exact =
            exact_packing_nonzero_entries.has_value(),
    };
}

OuterRelationR1csSize estimate_outer_relation_r1cs_size(
    const OuterRelationPlan &plan,
    const NativePackingOperator &packing_operator) {
    packing_operator.validate(plan);
    return estimate_outer_relation_r1cs_size(
        plan, packing_operator.nonzero_constant_matrix_terms(
                  plan.shape.ciphertext_components));
}

OuterRelationR1csAssignment make_outer_relation_r1cs_assignment(
    const OuterRelationPlan &plan,
    const OuterRelationPublicInputs &public_inputs,
    const OuterRelationWitnessInputs &witness_inputs,
    const OuterRelationAuxiliaryWitness &auxiliary_witness) {
    require_size(public_inputs.packed_challenge_words.size(),
                 plan.variables.public_inputs.packed_challenge_words.count,
                 "public challenge word");
    require_size(public_inputs.revealed_test_coordinates.size(),
                 plan.variables.public_inputs.revealed_test_coordinates.count,
                 "public test coordinate");
    require_size(
        public_inputs.revealed_packing_coordinates.size(),
        plan.variables.public_inputs.revealed_packing_coordinates.count,
        "public packing coordinate");
    require_size(
        auxiliary_witness.challenge_bits.size(),
        plan.variables.witness.derived_challenge_bits.count,
        "challenge-bit witness");
    require_size(
        witness_inputs.aligned_ciphertext_coordinates.size(),
        plan.variables.witness.aligned_ciphertext_coordinates.count,
        "aligned-coordinate witness");
    require_size(
        auxiliary_witness.well_formedness_products.size(),
        plan.variables.witness.well_formedness_products.count,
        "product witness");

    OuterRelationR1csAssignment result;
    result.public_inputs.reserve(
        as_size(plan.variables.public_inputs.total, "public assignment"));
    result.public_inputs.insert(
        result.public_inputs.end(),
        public_inputs.packed_challenge_words.begin(),
        public_inputs.packed_challenge_words.end());
    result.public_inputs.insert(
        result.public_inputs.end(),
        public_inputs.revealed_test_coordinates.begin(),
        public_inputs.revealed_test_coordinates.end());
    result.public_inputs.insert(
        result.public_inputs.end(),
        public_inputs.revealed_packing_coordinates.begin(),
        public_inputs.revealed_packing_coordinates.end());

    result.witness.reserve(
        as_size(plan.variables.witness.total, "witness assignment"));
    result.witness.insert(result.witness.end(),
                          auxiliary_witness.challenge_bits.begin(),
                          auxiliary_witness.challenge_bits.end());
    result.witness.insert(
        result.witness.end(),
        witness_inputs.aligned_ciphertext_coordinates.begin(),
        witness_inputs.aligned_ciphertext_coordinates.end());
    result.witness.insert(
        result.witness.end(),
        auxiliary_witness.well_formedness_products.begin(),
        auxiliary_witness.well_formedness_products.end());

    require_residues(result.public_inputs, plan.shape.native_modulus,
                     "public assignment");
    require_residues(result.witness, plan.shape.native_modulus,
                     "witness assignment");
    return result;
}

OuterRelationR1csBuilder::OuterRelationR1csBuilder(
    const OuterRelationPlan &plan)
    : plan_(&plan) {}

OuterRelationR1csBuilder::OuterRelationR1csBuilder(
    const OuterRelationPlan &plan,
    const NativePackingOperator &packing_operator)
    : plan_(&plan), packing_operator_(&packing_operator) {
    packing_operator.validate(plan);
}

OuterRelationR1csRow OuterRelationR1csBuilder::row(
    std::uint64_t constraint_index) const {
    OuterRelationR1csRow result;
    materialize_into(constraint_index, result);
    return result;
}

void OuterRelationR1csBuilder::materialize_into(
    std::uint64_t constraint_index,
    OuterRelationR1csRow &destination) const {
    materialize_row_into(
        *plan_, packing_operator_,
        describe_outer_relation_constraint(*plan_, constraint_index),
        destination);
}

OuterRelationR1csCursor::OuterRelationR1csCursor(
    const OuterRelationPlan &plan)
    : OuterRelationR1csCursor(
          plan, 0, plan.constraints.revealed_packing_equalities.begin) {}

OuterRelationR1csCursor::OuterRelationR1csCursor(
    const OuterRelationPlan &plan, std::uint64_t begin,
    std::uint64_t end)
    : builder_(plan), cursor_(begin), end_(end) {
    validate_range(plan, begin, end, false);
}

OuterRelationR1csCursor::OuterRelationR1csCursor(
    const OuterRelationPlan &plan,
    const NativePackingOperator &packing_operator)
    : OuterRelationR1csCursor(
          plan, packing_operator, 0, plan.constraints.total) {}

OuterRelationR1csCursor::OuterRelationR1csCursor(
    const OuterRelationPlan &plan,
    const NativePackingOperator &packing_operator,
    std::uint64_t begin, std::uint64_t end)
    : builder_(plan, packing_operator), cursor_(begin), end_(end) {
    validate_range(plan, begin, end, true);
}

void OuterRelationR1csCursor::validate_range(
    const OuterRelationPlan &plan, std::uint64_t begin,
    std::uint64_t end, bool has_packing_operator) {
    if (begin > end || end > plan.constraints.total ||
        (!has_packing_operator &&
         end > plan.constraints.revealed_packing_equalities.begin)) {
        throw std::out_of_range("outer R1CS cursor range is invalid");
    }
}

bool OuterRelationR1csCursor::empty() const {
    return cursor_ == end_;
}

std::uint64_t OuterRelationR1csCursor::position() const {
    return cursor_;
}

std::uint64_t OuterRelationR1csCursor::remaining() const {
    return end_ - cursor_;
}

const OuterRelationR1csRow &OuterRelationR1csCursor::next() {
    if (empty()) {
        throw std::out_of_range("outer R1CS cursor is exhausted");
    }
    builder_.materialize_into(cursor_, storage_);
    ++cursor_;
    return storage_;
}

bool evaluate_outer_relation_r1cs_row(
    const OuterRelationPlan &plan, const OuterRelationR1csRow &row,
    const OuterRelationR1csAssignment &assignment) {
    require_size(assignment.public_inputs.size(),
                 plan.variables.public_inputs.total, "public assignment");
    require_size(assignment.witness.size(), plan.variables.witness.total,
                 "witness assignment");
    require_residues(assignment.public_inputs, plan.shape.native_modulus,
                     "public assignment");
    require_residues(assignment.witness, plan.shape.native_modulus,
                     "witness assignment");
    return evaluate_validated_row(plan, row, assignment);
}

bool evaluate_outer_relation_r1cs_row(
    const OuterRelationPlan &plan, const OuterRelationR1csRow &row,
    const OuterRelationR1csAssignmentView &assignment) {
    if (&assignment.plan() != &plan) {
        throw std::invalid_argument(
            "outer R1CS: assignment view references a different plan");
    }
    return evaluate_validated_row(plan, row, assignment);
}

} // namespace laminate::packing
