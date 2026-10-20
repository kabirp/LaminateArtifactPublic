/// @file test_outer_relation_seal.cpp
/// @brief Cross-check the native-Q relation against live SEAL coordinates.

#include "test_helpers.hpp"

#include "laminate/fhe/seal_backend.hpp"
#include "laminate/packing/analysis/unbound_lazy_ternary_diagnostic.hpp"
#include "laminate/packing/evaluation/lazy_ternary.hpp"
#include "laminate/packing/outer_relation/relation.hpp"
#include "laminate/packing/outer_relation/assignment.hpp"
#include "laminate/packing/outer_relation/packing_r1cs.hpp"
#include "laminate/packing/outer_relation/r1cs.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <tuple>
#include <vector>

using namespace laminate;
using namespace laminate::fhe;
using namespace laminate::packing;

namespace {

constexpr std::size_t kSlots = 1024;
constexpr std::size_t kTests = 8;

SealBackend::Contexts make_contexts() {
    return SealBackend::create(SealParameters{
        .poly_modulus_degree = kSlots,
        .fresh_rns_limbs = 4,
        .bits_per_data_prime = 60,
        .special_prime_bits = 60,
        .security_level = seal::sec_level_type::none,
    });
}

SlotVector make_message(std::uint64_t seed) {
    SlotVector result(kSlots);
    for (std::size_t slot = 0; slot < kSlots; ++slot) {
        result[slot] = Fp(seed + 17 * slot + slot * slot);
    }
    return result;
}

std::vector<std::uint64_t> aligned_coordinates(
    const NormalizedAlignedTranscript<SealBackend> &aligned) {
    std::vector<std::uint64_t> result;
    result.reserve(aligned.values.size() * 2 * kSlots);
    for (std::size_t index = 0; index < aligned.values.size(); ++index) {
        const auto coordinates =
            normalized_aligned_coordinates(aligned, index);
        result.insert(result.end(), coordinates.begin(), coordinates.end());
    }
    return result;
}

std::vector<std::uint64_t> test_coordinates(
    const SealBackend::EvalContext &eval,
    const LazyTernaryEvaluation<SealBackend> &evaluation) {
    std::vector<std::uint64_t> result;
    result.reserve(evaluation.test_values.size() * 2 * kSlots);
    for (const auto &value : evaluation.test_values) {
        const auto coordinates =
            normalized_mixed_value_coordinates<SealBackend>(
                eval, value);
        result.insert(result.end(), coordinates.begin(), coordinates.end());
    }
    return result;
}

std::vector<std::uint64_t> packing_coordinates(
    const SealBackend::EvalContext &eval,
    const LazyTernaryEvaluation<SealBackend> &evaluation) {
    std::vector<std::uint64_t> result;
    result.reserve(evaluation.packed_digit_values.size() * 2 * kSlots);
    for (const auto &value : evaluation.packed_digit_values) {
        const auto coordinates =
            normalized_mixed_value_coordinates<SealBackend>(eval, value);
        result.insert(result.end(), coordinates.begin(), coordinates.end());
    }
    return result;
}

NativePackingOperator make_native_operator(
    const SealBackend::EvalContext &eval,
    const PackingLinearOperator &packing_operator,
    const BalancedRadix &radix) {
    return make_native_signed_digit_packing_operator(
        packing_operator,
        [&](const SlotVector &mask) {
            return SealBackend::encode_centered_plaintext_coefficients(
                eval, mask);
        },
        [&](std::span<const std::int64_t> coefficients) {
            return SealBackend::encode_lowest_plaintext_ntt_coordinates(
                eval, coefficients);
        },
        SealBackend::lowest_coefficient_modulus(eval), radix);
}

auto entry_key(const OuterRelationR1csMatrixEntry &entry) {
    return std::tuple{
        static_cast<std::uint8_t>(entry.matrix), entry.constraint_index,
        static_cast<std::uint8_t>(entry.variable.kind),
        entry.variable.index, entry.coefficient};
}

void sort_entries(std::vector<OuterRelationR1csMatrixEntry> &entries) {
    std::sort(entries.begin(), entries.end(), [](const auto &left,
                                                  const auto &right) {
        return entry_key(left) < entry_key(right);
    });
}

std::vector<OuterRelationR1csMatrixEntry> materialized_fixed_entries(
    const OuterRelationPlan &plan,
    const NativePackingOperator &packing_operator) {
    const OuterRelationR1csBuilder builder(plan, packing_operator);
    std::vector<OuterRelationR1csMatrixEntry> result;
    const OuterRelationRange range =
        plan.constraints.revealed_packing_equalities;
    for (std::uint64_t index = range.begin; index < range.end(); ++index) {
        const OuterRelationR1csRow row = builder.row(index);
        for (const OuterRelationR1csTerm &term : row.a) {
            result.push_back({OuterRelationR1csMatrix::A, index,
                              term.variable, term.coefficient});
        }
        for (const OuterRelationR1csTerm &term : row.b) {
            result.push_back({OuterRelationR1csMatrix::B, index,
                              term.variable, term.coefficient});
        }
        for (const OuterRelationR1csTerm &term : row.c) {
            result.push_back({OuterRelationR1csMatrix::C, index,
                              term.variable, term.coefficient});
        }
    }
    return result;
}

std::vector<OuterRelationR1csMatrixEntry> streamed_fixed_entries(
    const SealBackend::EvalContext &eval, const OuterRelationPlan &plan,
    const PackingLinearOperator &packing_operator,
    const BalancedRadix &radix,
    FixedPackingR1csStreamStatistics &statistics) {
    FixedPackingR1csEntryCursor cursor(
        plan, packing_operator,
        {.centered_coefficients =
             [&](const SlotVector &mask) {
                 return SealBackend::encode_centered_plaintext_coefficients(
                     eval, mask);
             },
         .native_ntt =
             [&](std::span<const std::int64_t> coefficients) {
                 return SealBackend::encode_lowest_plaintext_ntt_coordinates(
                     eval, coefficients);
             }},
        radix);
    std::vector<OuterRelationR1csMatrixEntry> result;
    while (!cursor.empty()) {
        result.push_back(cursor.next());
    }
    statistics = cursor.statistics();
    return result;
}

} // namespace

int main() {
    test::Runner runner("test_outer_relation_seal");
    const SealBackend::Contexts contexts = make_contexts();

    std::vector<SealBackend::Ciphertext> round_ciphertexts;
    const std::vector<std::size_t> widths{16, 16, 16, 16};
    for (std::size_t index = 0; index < widths.size(); ++index) {
        round_ciphertexts.push_back(SealBackend::encrypt(
            contexts.client, make_message(101 + 97 * index)));
    }

    runner.run("live test and base-17 outputs satisfy every native-Q row", [&] {
        const auto aligned =
            prepare_normalized_aligned_transcript<SealBackend>(
                contexts.eval, round_ciphertexts, widths);
        const LazyTernaryParameters parameters{
            .repetitions = kTests,
            .honest_error_bound = kSelectedPackingHonestErrorBound,
            .packing_radix =
                make_minimal_balanced_radix(kBaseFieldOrder, 17),
        };
        Transcript transcript("test/outer-relation/seal");
        const auto evaluation =
            run_unbound_lazy_ternary_diagnostic<SealBackend>(
                contexts.eval, aligned, transcript, parameters);
        const PackingLinearOperator logical_operator =
            make_packing_linear_operator(aligned.layout);
        const NativePackingOperator packing_operator = make_native_operator(
            contexts.eval, logical_operator, parameters.packing_radix);
        const OuterRelationPlan plan = make_outer_relation_plan(
            packing_operator, parameters.repetitions);

        const OuterRelationWitnessInputs witness{
            .aligned_ciphertext_coordinates =
                aligned_coordinates(aligned),
        };
        const OuterRelationPublicInputs public_inputs{
            .packed_challenge_words =
                pack_outer_relation_challenge_bits(
                    plan, evaluation.public_challenges),
            .revealed_test_coordinates =
                test_coordinates(contexts.eval, evaluation),
            .revealed_packing_coordinates =
                packing_coordinates(contexts.eval, evaluation),
        };
        const OuterRelationAuxiliaryWitness auxiliary =
            build_outer_relation_auxiliary_witness(
                plan, public_inputs.packed_challenge_words, witness);
        const OuterRelationExpectedOutputs expected =
            compute_outer_relation_expected_outputs(
                plan, public_inputs.packed_challenge_words, witness,
                packing_operator);
        const OuterRelationAssessment assessment = assess_outer_relation(
            plan, public_inputs, witness, auxiliary, packing_operator);

        CHECK(expected.revealed_test_coordinates ==
              public_inputs.revealed_test_coordinates);
        CHECK(expected.revealed_packing_coordinates ==
              public_inputs.revealed_packing_coordinates);
        CHECK(assessment.assignment_satisfies_relation());

        const OuterRelationR1csAssignment r1cs_assignment =
            make_outer_relation_r1cs_assignment(
                plan, public_inputs, witness, auxiliary);
        const OuterRelationR1csAssignmentView assignment_view(
            plan, public_inputs, witness);
        const OuterRelationR1csAssignmentView borrowed_assignment =
            borrow_outer_relation_r1cs_assignment<SealBackend>(
                contexts.eval,
                plan,
                std::span<const std::uint64_t>(
                    public_inputs.packed_challenge_words),
                std::span<const MixedPackingValue<SealBackend>>(
                    evaluation.test_values),
                std::span<const MixedPackingValue<SealBackend>>(
                    evaluation.packed_digit_values),
                aligned,
                [](const SealBackend::Ciphertext &ciphertext)
                    -> std::span<const std::uint64_t> {
                    return SealBackend::
                        coefficient_commitment_ntt_coordinate_view(
                            ciphertext);
                });
        const std::span<const std::uint64_t> first_aligned =
            SealBackend::coefficient_commitment_ntt_coordinate_view(
                aligned.values.front().ciphertext());
        CHECK(first_aligned.data() ==
              aligned.values.front().ciphertext().raw.data());
        CHECK(first_aligned.size() == 2 * kSlots);
        OuterRelationR1csCursor r1cs_cursor(
            plan, packing_operator);
        while (!r1cs_cursor.empty()) {
            const OuterRelationR1csRow &row = r1cs_cursor.next();
            CHECK(evaluate_outer_relation_r1cs_row(
                plan, row, r1cs_assignment));
            CHECK(evaluate_outer_relation_r1cs_row(
                plan, row, assignment_view));
            CHECK(evaluate_outer_relation_r1cs_row(
                plan, row, borrowed_assignment));
        }

        FixedPackingR1csStreamStatistics stream_statistics;
        auto streamed = streamed_fixed_entries(
            contexts.eval, plan, logical_operator,
            parameters.packing_radix, stream_statistics);
        auto materialized = materialized_fixed_entries(
            plan, packing_operator);
        sort_entries(streamed);
        sort_entries(materialized);
        CHECK(streamed == materialized);
        CHECK(stream_statistics.complete);
        CHECK(stream_statistics.aligned_masks_encoded ==
              plan.shape.aligned_ciphertexts);
        CHECK(stream_statistics.native_digit_polynomials_encoded ==
              plan.shape.aligned_ciphertexts *
                  plan.shape.packing_digit_count);
        CHECK(stream_statistics.a_nonzero_entries ==
              packing_operator.nonzero_constant_matrix_terms(
                  plan.shape.ciphertext_components));

        OuterRelationPublicInputs forged = public_inputs;
        forged.revealed_packing_coordinates.front() ^= 1;
        CHECK(!assess_outer_relation(plan, forged, witness, auxiliary,
                                     packing_operator)
                   .assignment_satisfies_relation());
    });

    runner.run("mixed public overlays preserve every native-Q row", [&] {
        const PackingLayout layout =
            make_fixed_message_coset_packing_layout(kSlots, 2, 2);
        const std::vector<FheValue<SealBackend>> mixed_values{
            FheValue<SealBackend>::from_ciphertext(round_ciphertexts[0]),
            FheValue<SealBackend>::public_scalar(Fp(40'000)),
        };
        const auto aligned =
            prepare_normalized_aligned_transcript<SealBackend>(
                contexts.eval, mixed_values, layout);
        const LazyTernaryParameters parameters{
            .repetitions = 1,
            .honest_error_bound = kSelectedPackingHonestErrorBound,
            .packing_radix =
                make_minimal_balanced_radix(kBaseFieldOrder, 17),
        };
        LazyTernaryChallengeMatrix challenges(
            1, std::vector<LazyTernaryChallenge>(aligned.values.size()));
        challenges[0][0].plus_bit = true;
        challenges[0][1].plus_bit = true;
        const auto evaluation =
            evaluate_lazy_ternary<SealBackend>(
                contexts.eval, aligned, challenges, parameters);
        CHECK(evaluation.test_values.front().encrypted_contribution);
        CHECK(!evaluation.test_values.front()
                   .public_c0_coordinates.empty());

        const PackingLinearOperator logical_operator =
            make_packing_linear_operator(layout);
        const NativePackingOperator packing_operator = make_native_operator(
            contexts.eval, logical_operator, parameters.packing_radix);
        const OuterRelationPlan plan = make_outer_relation_plan(
            packing_operator, parameters.repetitions);
        const OuterRelationWitnessInputs witness{
            .aligned_ciphertext_coordinates =
                aligned_coordinates(aligned),
        };
        const OuterRelationPublicInputs public_inputs{
            .packed_challenge_words =
                pack_outer_relation_challenge_bits(plan, challenges),
            .revealed_test_coordinates =
                test_coordinates(contexts.eval, evaluation),
            .revealed_packing_coordinates =
                packing_coordinates(contexts.eval, evaluation),
        };
        const OuterRelationAuxiliaryWitness auxiliary =
            build_outer_relation_auxiliary_witness(
                plan, public_inputs.packed_challenge_words, witness);
        CHECK(assess_outer_relation(plan, public_inputs, witness, auxiliary,
                                    packing_operator)
                  .assignment_satisfies_relation());

        const OuterRelationR1csAssignment owning =
            make_outer_relation_r1cs_assignment(
                plan, public_inputs, witness, auxiliary);
        const OuterRelationR1csAssignmentView borrowed =
            borrow_outer_relation_r1cs_assignment<SealBackend>(
                contexts.eval, plan,
                public_inputs.packed_challenge_words,
                evaluation.test_values,
                evaluation.packed_digit_values, aligned,
                [](const SealBackend::Ciphertext &ciphertext)
                    -> std::span<const std::uint64_t> {
                    return SealBackend::
                        coefficient_commitment_ntt_coordinate_view(
                            ciphertext);
                });
        OuterRelationR1csCursor cursor(plan, packing_operator);
        while (!cursor.empty()) {
            const OuterRelationR1csRow &row = cursor.next();
            CHECK(evaluate_outer_relation_r1cs_row(plan, row, owning));
            CHECK(evaluate_outer_relation_r1cs_row(plan, row, borrowed));
        }
    });

    runner.run("coordinate extractor rejects a noncanonical ciphertext", [&] {
        CHECK(!SealBackend::is_normalized_for_coefficient_commitment(
            round_ciphertexts.front()));
        bool rejected = false;
        try {
            (void)SealBackend::
                coefficient_commitment_ntt_coordinate_view(
                    round_ciphertexts.front());
        } catch (const std::invalid_argument &) {
            rejected = true;
        }
        CHECK(rejected);

        rejected = false;
        try {
            (void)SealBackend::coefficient_commitment_ntt_coordinates(
                round_ciphertexts.front());
        } catch (const std::invalid_argument &) {
            rejected = true;
        }
        CHECK(rejected);
    });

    return runner.summary();
}
