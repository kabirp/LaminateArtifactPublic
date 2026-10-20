/// @file constraints.cpp
/// @brief Canonical row decoder for the native-Q outer relation.

#include "laminate/packing/outer_relation/constraints.hpp"

#include <algorithm>
#include <limits>
#include <stdexcept>
#include <string>

namespace laminate::packing {
namespace {

std::size_t as_size(std::uint64_t value, const char *label) {
    if (value > std::numeric_limits<std::size_t>::max()) {
        throw std::overflow_error(std::string(label) + " exceeds size_t");
    }
    return static_cast<std::size_t>(value);
}

bool contains(const OuterRelationRange &range, std::uint64_t index) {
    return index >= range.begin && index < range.end();
}

std::uint64_t local_index(const OuterRelationRange &range,
                          std::uint64_t index) {
    if (!contains(range, index)) {
        throw std::logic_error(
            "outer relation constraint escaped its family range");
    }
    return index - range.begin;
}

OuterRelationWitnessVariable witness(std::uint64_t index) {
    return OuterRelationWitnessVariable{index};
}

OuterRelationPublicVariable public_input(std::uint64_t index) {
    return OuterRelationPublicVariable{index};
}

OuterRelationConstraintDescriptor describe_booleanity(
    const OuterRelationPlan &plan, std::uint64_t index) {
    const std::uint64_t local = local_index(
        plan.constraints.challenge_bit_booleanity, index);
    return OuterRelationConstraintDescriptor{
        .index = index,
        .family = OuterRelationConstraintFamily::ChallengeBitBooleanity,
        .equation = ChallengeBitBooleanityConstraint{
            .bit = witness(
                plan.variables.witness.derived_challenge_bits.begin + local),
        },
    };
}

OuterRelationConstraintDescriptor describe_recomposition(
    const OuterRelationPlan &plan, std::uint64_t index) {
    const std::uint64_t word = local_index(
        plan.constraints.challenge_word_recomposition, index);
    const std::uint64_t first_bit =
        word * plan.shape.public_input_capacity_bits;
    const std::uint64_t remaining =
        plan.variables.witness.derived_challenge_bits.count - first_bit;
    const std::uint64_t bit_count = std::min<std::uint64_t>(
        remaining, plan.shape.public_input_capacity_bits);
    return OuterRelationConstraintDescriptor{
        .index = index,
        .family = OuterRelationConstraintFamily::ChallengeWordRecomposition,
        .equation = ChallengeWordRecompositionConstraint{
            .packed_word = public_input(
                plan.variables.public_inputs.packed_challenge_words.begin +
                word),
            .first_bit = witness(
                plan.variables.witness.derived_challenge_bits.begin +
                first_bit),
            .bit_count = as_size(bit_count, "challenge word bit count"),
        },
    };
}

OuterRelationConstraintDescriptor describe_product(
    const OuterRelationPlan &plan, std::uint64_t index) {
    std::uint64_t local = local_index(
        plan.constraints.well_formedness_products, index);
    const std::uint64_t degree = plan.shape.ring_degree;
    const std::uint64_t components = plan.shape.ciphertext_components;
    const std::uint64_t coordinates_per_aligned = degree * components;
    const std::uint64_t coordinates_per_test =
        coordinates_per_aligned * plan.shape.aligned_ciphertexts;

    const std::size_t test = as_size(local / coordinates_per_test,
                                     "product test index");
    local %= coordinates_per_test;
    const std::size_t aligned = as_size(local / coordinates_per_aligned,
                                        "product aligned index");
    local %= coordinates_per_aligned;
    const std::size_t component =
        as_size(local / degree, "product component index");
    const std::size_t coordinate =
        as_size(local % degree, "product NTT coordinate");

    return OuterRelationConstraintDescriptor{
        .index = index,
        .family = OuterRelationConstraintFamily::WellFormednessProduct,
        .equation = WellFormednessProductConstraint{
            .plus_bit = witness(plan.challenge_bit_witness_index(
                test, aligned, OuterRelationPlan::ChallengeBit::Plus)),
            .minus_bit = witness(plan.challenge_bit_witness_index(
                test, aligned, OuterRelationPlan::ChallengeBit::Minus)),
            .aligned_coordinate = witness(
                plan.aligned_coordinate_witness_index(
                    aligned, component, coordinate)),
            .product = witness(plan.product_witness_index(
                test, aligned, component, coordinate)),
        },
    };
}

OuterRelationConstraintDescriptor describe_test_equality(
    const OuterRelationPlan &plan, std::uint64_t index) {
    std::uint64_t local = local_index(
        plan.constraints.revealed_test_equalities, index);
    const std::uint64_t degree = plan.shape.ring_degree;
    const std::uint64_t coordinates_per_test =
        degree * plan.shape.ciphertext_components;
    const std::size_t test = as_size(local / coordinates_per_test,
                                     "revealed test index");
    local %= coordinates_per_test;
    const std::size_t component =
        as_size(local / degree, "revealed test component");
    const std::size_t coordinate =
        as_size(local % degree, "revealed test coordinate");

    return OuterRelationConstraintDescriptor{
        .index = index,
        .family = OuterRelationConstraintFamily::RevealedTestEquality,
        .equation = RevealedTestEqualityConstraint{
            .revealed_coordinate = public_input(
                plan.test_coordinate_public_index(test, component,
                                                  coordinate)),
            .first_product = witness(plan.product_witness_index(
                test, 0, component, coordinate)),
            .product_stride =
                degree * plan.shape.ciphertext_components,
            .product_count = plan.shape.aligned_ciphertexts,
        },
    };
}

OuterRelationConstraintDescriptor describe_packing_equality(
    const OuterRelationPlan &plan, std::uint64_t index) {
    std::uint64_t local = local_index(
        plan.constraints.revealed_packing_equalities, index);
    const std::uint64_t degree = plan.shape.ring_degree;
    const std::uint64_t coordinates_per_ciphertext =
        degree * plan.shape.ciphertext_components;
    const std::size_t physical = as_size(
        local / coordinates_per_ciphertext, "packing physical output");
    local %= coordinates_per_ciphertext;
    const std::size_t component =
        as_size(local / degree, "packing component");
    const std::size_t coordinate =
        as_size(local % degree, "packing NTT coordinate");
    const std::size_t logical =
        physical / plan.shape.packing_digit_count;
    const std::size_t digit =
        physical % plan.shape.packing_digit_count;

    return OuterRelationConstraintDescriptor{
        .index = index,
        .family = OuterRelationConstraintFamily::RevealedPackingEquality,
        .equation = RevealedPackingEqualityConstraint{
            .revealed_coordinate = public_input(
                plan.packing_coordinate_public_index(
                    logical, digit, component, coordinate)),
            .logical_output = logical,
            .digit = digit,
            .component = component,
            .ntt_coordinate = coordinate,
        },
    };
}

} // namespace

OuterRelationConstraintDescriptor describe_outer_relation_constraint(
    const OuterRelationPlan &plan, std::uint64_t constraint_index) {
    if (constraint_index >= plan.constraints.total) {
        throw std::out_of_range(
            "outer relation constraint index is out of range");
    }
    if (contains(plan.constraints.challenge_bit_booleanity,
                 constraint_index)) {
        return describe_booleanity(plan, constraint_index);
    }
    if (contains(plan.constraints.challenge_word_recomposition,
                 constraint_index)) {
        return describe_recomposition(plan, constraint_index);
    }
    if (contains(plan.constraints.well_formedness_products,
                 constraint_index)) {
        return describe_product(plan, constraint_index);
    }
    if (contains(plan.constraints.revealed_test_equalities,
                 constraint_index)) {
        return describe_test_equality(plan, constraint_index);
    }
    return describe_packing_equality(plan, constraint_index);
}

OuterRelationConstraintCursor::OuterRelationConstraintCursor(
    const OuterRelationPlan &plan)
    : OuterRelationConstraintCursor(plan, 0, plan.constraints.total) {}

OuterRelationConstraintCursor::OuterRelationConstraintCursor(
    const OuterRelationPlan &plan, std::uint64_t begin, std::uint64_t end)
    : plan_(plan), cursor_(begin), end_(end) {
    if (begin > end || end > plan.constraints.total) {
        throw std::out_of_range(
            "outer relation constraint cursor range is invalid");
    }
}

bool OuterRelationConstraintCursor::empty() const {
    return cursor_ == end_;
}

std::uint64_t OuterRelationConstraintCursor::position() const {
    return cursor_;
}

std::uint64_t OuterRelationConstraintCursor::remaining() const {
    return end_ - cursor_;
}

OuterRelationConstraintDescriptor OuterRelationConstraintCursor::next() {
    if (empty()) {
        throw std::out_of_range(
            "outer relation constraint cursor is exhausted");
    }
    return describe_outer_relation_constraint(plan_, cursor_++);
}

} // namespace laminate::packing
