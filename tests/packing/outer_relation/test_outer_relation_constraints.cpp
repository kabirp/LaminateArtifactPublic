/// @file test_outer_relation_constraints.cpp
/// @brief Allocation-free outer-relation row decoding tests.

#include "test_helpers.hpp"

#include "laminate/packing/outer_relation/constraints.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <variant>

using namespace laminate;
using namespace laminate::packing;

namespace {

OuterRelationPlan small_plan() {
    return make_outer_relation_plan(OuterRelationShape{
        .native_modulus = 257,
        .ring_degree = 4,
        .aligned_ciphertexts = 3,
        .repetitions = 2,
        .logical_packed_outputs = 2,
        .packing_digit_count = 2,
        .ciphertext_components = 2,
        .public_input_capacity_bits = 8,
    });
}

OuterRelationPlan target_folded_plan() {
    return make_outer_relation_plan(OuterRelationShape{
        .native_modulus = kOuterFieldOrder,
        .ring_degree = 16'384,
        .aligned_ciphertexts = 517,
        .repetitions = kPackingWellFormednessRepetitions,
        .logical_packed_outputs = 1,
        .packing_digit_count = 4,
        .ciphertext_components = 2,
        .public_input_capacity_bits = 59,
    });
}

template <typename Action>
bool rejects_out_of_range(Action action) {
    try {
        action();
    } catch (const std::out_of_range &) {
        return true;
    }
    return false;
}

} // namespace

int main() {
    test::Runner runner("test_outer_relation_constraints");

    runner.run("family boundaries decode canonical typed rows", [] {
        const OuterRelationPlan plan = small_plan();

        const auto first_boolean = describe_outer_relation_constraint(plan, 0);
        CHECK(first_boolean.family ==
              OuterRelationConstraintFamily::ChallengeBitBooleanity);
        CHECK(std::get<ChallengeBitBooleanityConstraint>(
                  first_boolean.equation)
                  .bit.index == 0);

        const auto last_boolean = describe_outer_relation_constraint(plan, 11);
        CHECK(std::get<ChallengeBitBooleanityConstraint>(
                  last_boolean.equation)
                  .bit.index == 11);

        const auto first_word = describe_outer_relation_constraint(plan, 12);
        const auto &word0 = std::get<ChallengeWordRecompositionConstraint>(
            first_word.equation);
        CHECK(word0.packed_word.index == 0);
        CHECK(word0.first_bit.index == 0);
        CHECK(word0.bit_count == 8);

        const auto second_word = describe_outer_relation_constraint(plan, 13);
        const auto &word1 = std::get<ChallengeWordRecompositionConstraint>(
            second_word.equation);
        CHECK(word1.packed_word.index == 1);
        CHECK(word1.first_bit.index == 8);
        CHECK(word1.bit_count == 4);
    });

    runner.run("product rows name all four witness variables", [] {
        const OuterRelationPlan plan = small_plan();
        const auto first = describe_outer_relation_constraint(plan, 14);
        const auto &first_product =
            std::get<WellFormednessProductConstraint>(first.equation);
        CHECK(first_product.plus_bit.index == 0);
        CHECK(first_product.minus_bit.index == 1);
        CHECK(first_product.aligned_coordinate.index == 12);
        CHECK(first_product.product.index == 36);

        const auto last = describe_outer_relation_constraint(plan, 61);
        const auto &last_product =
            std::get<WellFormednessProductConstraint>(last.equation);
        CHECK(last_product.plus_bit.index == 10);
        CHECK(last_product.minus_bit.index == 11);
        CHECK(last_product.aligned_coordinate.index == 35);
        CHECK(last_product.product.index == 83);
    });

    runner.run("linear rows expose strided sums and fixed output identity", [] {
        const OuterRelationPlan plan = small_plan();
        const auto first_test = describe_outer_relation_constraint(plan, 62);
        const auto &test =
            std::get<RevealedTestEqualityConstraint>(first_test.equation);
        CHECK(test.revealed_coordinate.index == 2);
        CHECK(test.first_product.index == 36);
        CHECK(test.product_stride == 8);
        CHECK(test.product_count == 3);

        const auto last_test = describe_outer_relation_constraint(plan, 77);
        const auto &test_last =
            std::get<RevealedTestEqualityConstraint>(last_test.equation);
        CHECK(test_last.revealed_coordinate.index == 17);
        CHECK(test_last.first_product.index == 67);

        const auto first_packing =
            describe_outer_relation_constraint(plan, 78);
        const auto &packing =
            std::get<RevealedPackingEqualityConstraint>(
                first_packing.equation);
        CHECK(packing.revealed_coordinate.index == 18);
        CHECK(packing.logical_output == 0);
        CHECK(packing.digit == 0);
        CHECK(packing.component == 0);
        CHECK(packing.ntt_coordinate == 0);

        const auto last_packing =
            describe_outer_relation_constraint(plan, 109);
        const auto &packing_last =
            std::get<RevealedPackingEqualityConstraint>(
                last_packing.equation);
        CHECK(packing_last.revealed_coordinate.index == 49);
        CHECK(packing_last.logical_output == 1);
        CHECK(packing_last.digit == 1);
        CHECK(packing_last.component == 1);
        CHECK(packing_last.ntt_coordinate == 3);
    });

    runner.run("cursor streams each row once without retaining the circuit", [] {
        const OuterRelationPlan plan = small_plan();
        OuterRelationConstraintCursor cursor(plan);
        std::array<std::uint64_t, 5> family_counts{};
        while (!cursor.empty()) {
            const OuterRelationConstraintDescriptor descriptor = cursor.next();
            ++family_counts[static_cast<std::size_t>(descriptor.family)];
        }
        CHECK(cursor.position() == plan.constraints.total);
        CHECK(cursor.remaining() == 0);
        CHECK(family_counts[0] == 12);
        CHECK(family_counts[1] == 2);
        CHECK(family_counts[2] == 48);
        CHECK(family_counts[3] == 16);
        CHECK(family_counts[4] == 32);
        CHECK(rejects_out_of_range([&] { (void)cursor.next(); }));
    });

    runner.run("target Folded rows remain random-access plan data", [] {
        const OuterRelationPlan plan = target_folded_plan();
        const std::array<OuterRelationRange, 5> ranges{
            plan.constraints.challenge_bit_booleanity,
            plan.constraints.challenge_word_recomposition,
            plan.constraints.well_formedness_products,
            plan.constraints.revealed_test_equalities,
            plan.constraints.revealed_packing_equalities,
        };
        for (std::size_t family = 0; family < ranges.size(); ++family) {
            const auto first = describe_outer_relation_constraint(
                plan, ranges[family].begin);
            const auto last = describe_outer_relation_constraint(
                plan, ranges[family].end() - 1);
            CHECK(static_cast<std::size_t>(first.family) == family);
            CHECK(static_cast<std::size_t>(last.family) == family);
        }

        OuterRelationConstraintCursor tail(
            plan, plan.constraints.total - 2, plan.constraints.total);
        CHECK(tail.remaining() == 2);
        (void)tail.next();
        (void)tail.next();
        CHECK(tail.empty());
        CHECK(rejects_out_of_range([&] {
            OuterRelationConstraintCursor invalid(
                plan, 0, plan.constraints.total + 1);
            (void)invalid;
        }));
    });

    return runner.summary();
}
