/// @file test_outer_relation.cpp
/// @brief Exact native-Q transcript-packing relation tests.

#include "test_helpers.hpp"

#include "laminate/packing/outer_relation/relation.hpp"
#include "laminate/packing/alignment/layout.hpp"

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <utility>
#include <vector>

using namespace laminate;
using namespace laminate::packing;

namespace {

constexpr std::uint64_t kSmallPrime = 257;

NativePackingContribution contribution(std::size_t aligned,
                                       std::uint64_t seed) {
    return NativePackingContribution{
        .aligned_ciphertext = aligned,
        .multiplier_ntt_coordinates = {
            seed % kSmallPrime, (seed + 1) % kSmallPrime,
            (seed + 2) % kSmallPrime, (seed + 3) % kSmallPrime},
    };
}

NativePackingOperator small_operator() {
    return NativePackingOperator{
        .native_modulus = kSmallPrime,
        .ring_degree = 4,
        .aligned_ciphertexts = 3,
        .logical_outputs = 2,
        .digit_count = 2,
        .rows = {
            NativePackingRow{0, 0,
                             {contribution(0, 1), contribution(1, 11)}},
            NativePackingRow{0, 1,
                             {contribution(0, 21), contribution(1, 31)}},
            NativePackingRow{1, 0, {contribution(2, 41)}},
            NativePackingRow{1, 1, {contribution(2, 51)}},
        },
    };
}

LazyTernaryChallengeMatrix small_challenges() {
    return {
        {{false, false}, {true, true}, {true, false}},
        {{false, true}, {true, false}, {true, true}},
    };
}

OuterRelationWitnessInputs small_witness(const OuterRelationPlan &plan) {
    OuterRelationWitnessInputs result;
    result.aligned_ciphertext_coordinates.resize(
        static_cast<std::size_t>(
            plan.variables.witness.aligned_ciphertext_coordinates.count));
    for (std::size_t index = 0;
         index < result.aligned_ciphertext_coordinates.size(); ++index) {
        result.aligned_ciphertext_coordinates[index] = index + 1;
    }
    return result;
}

OuterRelationPublicInputs honest_public_inputs(
    const OuterRelationPlan &plan,
    const OuterRelationWitnessInputs &witness,
    const NativePackingOperator &packing_operator,
    const LazyTernaryChallengeMatrix &challenges) {
    OuterRelationPublicInputs result;
    result.packed_challenge_words =
        pack_outer_relation_challenge_bits(plan, challenges);
    const OuterRelationExpectedOutputs expected =
        compute_outer_relation_expected_outputs(
            plan, result.packed_challenge_words, witness, packing_operator);
    result.revealed_test_coordinates = expected.revealed_test_coordinates;
    result.revealed_packing_coordinates =
        expected.revealed_packing_coordinates;
    return result;
}

template <typename Action>
bool rejects_invalid_argument(Action action) {
    try {
        action();
    } catch (const std::invalid_argument &) {
        return true;
    }
    return false;
}

SignedCoefficientMask identity_coefficients(const fhe::SlotVector &slots) {
    SignedCoefficientMask result;
    result.reserve(slots.size());
    for (const Fp &value : slots) {
        result.push_back(static_cast<std::int64_t>(value.value()));
    }
    return result;
}

std::vector<std::uint64_t> identity_native_ntt(
    std::span<const std::int64_t> coefficients) {
    std::vector<std::uint64_t> result;
    result.reserve(coefficients.size());
    for (const std::int64_t coefficient : coefficients) {
        result.push_back(
            coefficient >= 0
                ? static_cast<std::uint64_t>(coefficient) % kSmallPrime
                : kSmallPrime -
                      (std::uint64_t{0} -
                       static_cast<std::uint64_t>(coefficient)) %
                          kSmallPrime);
    }
    return result;
}

} // namespace

int main() {
    test::Runner runner("test_outer_relation");

    runner.run("plan fixes exact variable and constraint order", [] {
        CHECK(outer_relation_public_input_capacity(257) == 8);
        CHECK(outer_relation_public_input_capacity(97) == 6);
        CHECK(outer_relation_public_input_capacity(
                  1'152'921'422'732'787'713ULL) == 59);
        const NativePackingOperator packing_operator = small_operator();
        const OuterRelationPlan plan = make_outer_relation_plan(
            packing_operator, 2, 2, 8);

        CHECK(plan.well_formedness.challenge_bits == 12);
        CHECK(plan.well_formedness.packed_public_inputs == 2);
        CHECK(plan.well_formedness.coefficient_products == 48);
        CHECK(plan.well_formedness.subtotal_constraints == 78);
        CHECK(plan.fixed_packing.witness_input_coordinates == 24);
        CHECK(plan.fixed_packing.public_output_coordinates == 32);
        CHECK(plan.variables.public_inputs.total == 50);
        CHECK(plan.variables.witness.total == 84);
        CHECK(plan.constraints.total == 110);

        CHECK(plan.challenge_bit_witness_index(
                  1, 2, OuterRelationPlan::ChallengeBit::Minus) == 11);
        CHECK(plan.aligned_coordinate_witness_index(2, 1, 3) == 35);
        CHECK(plan.product_witness_index(1, 2, 1, 3) == 83);
        CHECK(plan.test_coordinate_public_index(1, 1, 3) == 17);
        CHECK(plan.packing_coordinate_public_index(1, 1, 1, 3) == 49);
    });

    runner.run("exact assignment preserves both Fiat-Shamir zero encodings",
               [] {
        const NativePackingOperator packing_operator = small_operator();
        const OuterRelationPlan plan = make_outer_relation_plan(
            packing_operator, 2, 2, 8);
        const LazyTernaryChallengeMatrix challenges = small_challenges();
        const OuterRelationWitnessInputs witness = small_witness(plan);
        const OuterRelationPublicInputs public_inputs = honest_public_inputs(
            plan, witness, packing_operator, challenges);
        const OuterRelationAuxiliaryWitness auxiliary =
            build_outer_relation_auxiliary_witness(
                plan, public_inputs.packed_challenge_words, witness);

        CHECK(auxiliary.challenge_bits[0] == 0);
        CHECK(auxiliary.challenge_bits[1] == 0);
        CHECK(auxiliary.challenge_bits[2] == 1);
        CHECK(auxiliary.challenge_bits[3] == 1);
        for (std::size_t coordinate = 0; coordinate < 16; ++coordinate) {
            CHECK(auxiliary.well_formedness_products[coordinate] == 0);
        }

        const OuterRelationAssessment assessment = assess_outer_relation(
            plan, public_inputs, witness, auxiliary, packing_operator);
        CHECK(assessment.challenge_bits_are_boolean);
        CHECK(assessment.challenge_words_recompose);
        CHECK(assessment.well_formedness_products_match);
        CHECK(assessment.revealed_tests_match);
        CHECK(assessment.revealed_packing_matches);
        CHECK(assessment.assignment_satisfies_relation());
    });

    runner.run("each relation family rejects its own mutation", [] {
        const NativePackingOperator packing_operator = small_operator();
        const OuterRelationPlan plan = make_outer_relation_plan(
            packing_operator, 2, 2, 8);
        const auto challenges = small_challenges();
        const OuterRelationWitnessInputs witness = small_witness(plan);
        const OuterRelationPublicInputs public_inputs = honest_public_inputs(
            plan, witness, packing_operator, challenges);
        const OuterRelationAuxiliaryWitness auxiliary =
            build_outer_relation_auxiliary_witness(
                plan, public_inputs.packed_challenge_words, witness);

        auto nonboolean = auxiliary;
        nonboolean.challenge_bits.front() = 2;
        CHECK(!assess_outer_relation(plan, public_inputs, witness, nonboolean,
                                     packing_operator)
                   .challenge_bits_are_boolean);

        auto wrong_word = public_inputs;
        wrong_word.packed_challenge_words.front() ^= 1;
        CHECK(!assess_outer_relation(plan, wrong_word, witness, auxiliary,
                                     packing_operator)
                   .challenge_words_recompose);

        auto wrong_product = auxiliary;
        wrong_product.well_formedness_products.front() = 1;
        CHECK(!assess_outer_relation(plan, public_inputs, witness,
                                     wrong_product, packing_operator)
                   .well_formedness_products_match);

        auto wrong_test = public_inputs;
        wrong_test.revealed_test_coordinates.front() ^= 1;
        CHECK(!assess_outer_relation(plan, wrong_test, witness, auxiliary,
                                     packing_operator)
                   .revealed_tests_match);

        auto wrong_packing = public_inputs;
        wrong_packing.revealed_packing_coordinates.front() ^= 1;
        CHECK(!assess_outer_relation(plan, wrong_packing, witness, auxiliary,
                                     packing_operator)
                   .revealed_packing_matches);
    });

    runner.run("target Folded plan computes billions without allocation", [] {
        const OuterRelationPlan plan = make_outer_relation_plan(
            OuterRelationShape{
                .native_modulus = kOuterFieldOrder,
                .ring_degree = 16'384,
                .aligned_ciphertexts = 517,
                .repetitions = kPackingWellFormednessRepetitions,
                .logical_packed_outputs = 1,
                .packing_digit_count = 4,
                .ciphertext_components = 2,
                .public_input_capacity_bits = 59,
            });

        CHECK(plan.well_formedness.coefficient_products == 2'032'926'720ULL);
        CHECK(plan.well_formedness.subtotal_constraints == 2'036'985'064ULL);
        CHECK(plan.fixed_packing.output_relation_constraints == 131'072);
        CHECK(plan.constraints.total == 2'037'116'136ULL);
        CHECK(plan.variables.public_inputs.total == 4'065'336);
        CHECK(plan.variables.witness.total == 2'049'991'856ULL);
    });

    runner.run("base-17 builder follows the logical packing rows", [] {
        const PackingLinearOperator logical = make_packing_linear_operator(
            make_prefix_packing_layout(
                16, std::vector<std::size_t>{4, 4, 4}));
        const BalancedRadix radix =
            make_minimal_balanced_radix(kBaseFieldOrder, 17);
        const NativePackingOperator native =
            make_native_signed_digit_packing_operator(
                logical, identity_coefficients, identity_native_ntt,
                kSmallPrime, radix);
        const OuterRelationPlan plan = make_outer_relation_plan(
            native, 2, 2, 8);

        CHECK(native.aligned_ciphertexts ==
              logical.aligned_ciphertext_count);
        CHECK(native.logical_outputs == logical.rows.size());
        CHECK(native.digit_count == 4);
        CHECK(native.rows.size() == 4 * logical.rows.size());
        CHECK(native.nonzero_constant_matrix_terms(2) == 24);
        native.validate(plan);
    });

    runner.run("malformed native matrices fail closed", [] {
        NativePackingOperator malformed = small_operator();
        const OuterRelationPlan plan = make_outer_relation_plan(
            malformed, 2, 2, 8);

        malformed.rows.front().contributions.push_back(
            malformed.rows.front().contributions.front());
        CHECK(rejects_invalid_argument(
            [&] { malformed.validate(plan); }));

        malformed = small_operator();
        malformed.rows.front()
            .contributions.front()
            .multiplier_ntt_coordinates.front() = kSmallPrime;
        CHECK(rejects_invalid_argument(
            [&] { malformed.validate(plan); }));

        malformed = small_operator();
        malformed.rows.front().contributions.clear();
        CHECK(rejects_invalid_argument(
            [&] { malformed.validate(plan); }));

        OuterRelationWitnessInputs witness = small_witness(plan);
        witness.aligned_ciphertext_coordinates.front() = kSmallPrime;
        const auto words = pack_outer_relation_challenge_bits(
            plan, small_challenges());
        CHECK(rejects_invalid_argument([&] {
            (void)build_outer_relation_auxiliary_witness(
                plan, words, witness);
        }));
    });

    return runner.summary();
}
