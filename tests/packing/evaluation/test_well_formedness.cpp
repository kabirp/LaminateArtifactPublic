/// @file test_well_formedness.cpp
/// @brief Constraint, Fiat--Shamir, and no-wrap analysis tests.

#include "test_helpers.hpp"

#include "laminate/packing/evaluation/well_formedness.hpp"

#include <cmath>
#include <cstdint>
#include <stdexcept>
#include <vector>

using namespace laminate;
using namespace laminate::packing;

int main() {
    test::Runner runner("test_well_formedness");

    runner.run("online coefficients incur 2NTf products", [] {
        const auto binary = estimate_well_formedness_constraints(
            WellFormednessRelationShape{
                .ring_degree = 1U << 14U,
                .ciphertext_count = 1U << 10U,
                .repetitions = 100,
                .ciphertext_components = 2,
                .distribution = TestCoefficientDistribution::BinarySubset,
                .public_input_capacity_bits = 59,
            });
        CHECK(binary.coefficient_products ==
              2ULL * (1ULL << 14U) * (1ULL << 10U) * 100ULL);
        CHECK(binary.output_relations == 2ULL * (1ULL << 14U) * 100ULL);
        CHECK(binary.challenge_bits == (1ULL << 10U) * 100ULL);
        CHECK(binary.packed_public_inputs ==
              (binary.challenge_bits + 58ULL) / 59ULL);

        auto ternary_shape = WellFormednessRelationShape{
            .ring_degree = 1U << 14U,
            .ciphertext_count = 1U << 10U,
            .repetitions = 100,
            .ciphertext_components = 2,
            .distribution = TestCoefficientDistribution::LazyTernary,
            .public_input_capacity_bits = 59,
        };
        const auto ternary =
            estimate_well_formedness_constraints(ternary_shape);
        CHECK(ternary.coefficient_products == binary.coefficient_products);
        CHECK(ternary.challenge_bits == 2 * binary.challenge_bits);
    });

    runner.run("fixed digit packing records linear matrix density", [] {
        const auto estimate = estimate_fixed_packing_relation(
            FixedPackingRelationShape{
                .ring_degree = 16384,
                .aligned_ciphertexts = 48,
                .packed_digit_ciphertexts = 3,
                .digit_count = 3,
                .ciphertext_components = 2,
            });
        CHECK(estimate.witness_input_coordinates == 1572864);
        CHECK(estimate.public_output_coordinates == 98304);
        CHECK(estimate.output_relation_constraints == 98304);
        CHECK(estimate.constant_matrix_terms == 4718592);
    });

    runner.run("binary test exposes its 2f completeness-soundness slack", [] {
        const BinarySubsetGap gap = analyze_binary_subset_gap(17, 64);
        CHECK(gap.honest_test_bound == 17 * 64);
        CHECK(gap.bad_ciphertext_trigger == 2 * 17 * 64);
        CHECK(gap.per_ciphertext_slack_factor == 128);
    });

    runner.run("canonical error bound derives public P exactly", [] {
        CHECK(canonical_partial_decryption_bound(65537, 5232) ==
              342922352);
        CHECK(canonical_partial_decryption_bound(65537, 0) == 32768);
        CHECK(canonical_error_bound_from_partial_decryption(65537, 32768) ==
              0);
        CHECK(canonical_error_bound_from_partial_decryption(
                  65537, 2 * 21'976'480'658ULL) == 670'659);
        bool rejected_even_plaintext_modulus = false;
        try {
            (void)canonical_partial_decryption_bound(16, 1);
        } catch (const std::invalid_argument &) {
            rejected_even_plaintext_modulus = true;
        }
        CHECK(rejected_even_plaintext_modulus);
    });

    runner.run("well-formedness masks are deterministic FS challenges", [] {
        Transcript first("test/well-formedness");
        Transcript second("test/well-formedness");
        first.observe("commitment", 41);
        second.observe("commitment", 41);
        const auto a = derive_lazy_ternary_challenges(first, 7, 19);
        const auto b = derive_lazy_ternary_challenges(second, 7, 19);
        CHECK(a == b);
        for (const auto &test : a) {
            for (const LazyTernaryChallenge &challenge : test) {
                const std::int8_t coefficient = challenge.coefficient();
                CHECK(coefficient >= -1);
                CHECK(coefficient <= 1);
            }
        }

        Transcript changed("test/well-formedness");
        changed.observe("commitment", 42);
        CHECK(derive_lazy_ternary_challenges(changed, 7, 19) != a);
    });

    runner.run("lazy-ternary threshold uses exact integer arithmetic", [] {
        CHECK(lazy_ternary_test_threshold(10, 64) == 740);
        CHECK(lazy_ternary_test_threshold(1, 2) == 13);
        CHECK(lazy_ternary_test_threshold(481'072, 48) ==
              30'829'922);
    });

    runner.run("row weight uses coefficient lifts rather than slot sparsity", [] {
        const PackingRowWeight scalar = compute_packing_row_weight(
            PackingRowCoefficientLifts{{{1, 0, 0, 0},
                                         {-1, 0, 0, 0},
                                         {1, 0, 0, 0},
                                         {-1, 0, 0, 0}}});
        CHECK(std::abs(scalar.approximate_mixed_norm - 2.0L) < 1e-12L);
        CHECK(scalar.conservative_integer_upper == 2);
        CHECK(scalar.total_absolute_coefficient_weight == 4);
        CHECK(scalar.cauchy_schwarz_upper >=
              scalar.approximate_mixed_norm);
        CHECK(scalar.coefficient_infinity_upper >=
              scalar.approximate_mixed_norm);

        const PackingRowWeight dense = compute_packing_row_weight(
            PackingRowCoefficientLifts{{{1, 1, 1, 1},
                                         {1, -1, 1, -1}}});
        CHECK(dense.approximate_mixed_norm >
              scalar.approximate_mixed_norm);
        CHECK(dense.conservative_integer_upper == 8);
        CHECK(dense.total_absolute_coefficient_weight == 8);
    });

    runner.run("certificate checks both independent packing inequalities", [] {
        const auto passing = assess_lazy_ternary_certificate(
            LazyTernaryCertificateInputs{
                .packing_modulus = 1'000'000'000,
                .plaintext_modulus = 65'537,
                .honest_partial_decryption_bound = 10,
                .ring_degree = 1U << 14U,
                .ciphertext_count = 64,
                .repetitions = kPackingWellFormednessRepetitions,
                .maximum_row_weight_upper = 32,
            });
        CHECK(passing.theorem_shape_supported);
        CHECK(passing.individual_detection_premise);
        CHECK(passing.modular_detection_premise);
        CHECK(passing.packing_no_wrap);
        CHECK(passing.interactive_detection_guarantees_hold);
        CHECK(passing.interactive_certificate_holds);
        CHECK(std::abs(
                  passing.required_aligned_budget_bits -
                  required_lazy_ternary_aligned_budget_bits(64, 32)) <
              1e-12L);
        CHECK(passing.exact_test_threshold == 740);
        CHECK(passing.accepted_input_bounds
                  .individual_partial_decryption_bound == 1480);
        CHECK(passing.accepted_input_bounds
                  .individual_canonical_error_bound == 0);
        CHECK(passing.accepted_input_bounds
                  .aggregate_column_l2_integer_upper == 4440);
        CHECK(passing.interactive_probabilities.soundness_bits ==
              kPackingWellFormednessRepetitions);
        CHECK(passing.interactive_probabilities.soundness_bits >=
              kInteractiveIntegrityTargetBits);
        CHECK(std::abs(
                  std::log2(passing.interactive_probabilities
                                .soundness_error_upper) +
                  static_cast<long double>(
                      kPackingWellFormednessRepetitions)) <
              1e-12L);
        CHECK(passing.interactive_probabilities
                  .conditional_honest_completeness_bits_lower > 101.4L);
        CHECK(passing.interactive_probabilities
                  .conditional_honest_completeness_bits_lower < 101.7L);

        const auto bad_operator = assess_lazy_ternary_certificate(
            LazyTernaryCertificateInputs{
                .packing_modulus = 1'000'000'000,
                .plaintext_modulus = 65'537,
                .honest_partial_decryption_bound = 10,
                .ring_degree = 1U << 14U,
                .ciphertext_count = 64,
                .repetitions = kPackingWellFormednessRepetitions,
                .maximum_row_weight_upper = 1'000'000,
            });
        CHECK(bad_operator.modular_detection_premise);
        CHECK(bad_operator.interactive_detection_guarantees_hold);
        CHECK(!bad_operator.packing_no_wrap);
        CHECK(!bad_operator.interactive_certificate_holds);
    });

    runner.run("individual certificate uses the exact row l1 weight", [] {
        const auto passing = assess_individual_bound_packing(
            1'000'000, 100, 4'999);
        CHECK(passing.maximum_admissible_input_bound == 100);
        CHECK(passing.packing_no_wrap);

        const auto failing = assess_individual_bound_packing(
            1'000'000, 101, 4'999);
        CHECK(!failing.packing_no_wrap);
    });

    runner.run("one-limb capacity exposes the admissible honest error", [] {
        const PackingModulusCapacity capacity =
            compute_packing_modulus_capacity(
                1'150'727'978'909'433'857ULL, 65'537, 48,
                2'139'792'336ULL);
        CHECK(capacity.maximum_safe_aggregate_input_norm ==
              ((1'150'727'978'909'433'857ULL - 1) / 2) /
                  2'139'792'336ULL);
        CHECK(capacity
                  .maximum_honest_partial_decryption_bound_from_detection ==
              143'984'982'346'025ULL);
        CHECK(capacity
                  .maximum_honest_partial_decryption_bound_from_packing ==
              692'117ULL);
        CHECK(capacity.maximum_honest_partial_decryption_bound ==
              692'117ULL);
        CHECK(capacity.admits_even_zero_error);
        CHECK(capacity.maximum_honest_error_bound == 10);
    });

    runner.run("selected Folded capacity supports beta 17781", [] {
        // For the selected aggregate certificate, the final modulus first
        // limits the admissible column l2 norm. That limit then determines
        // the honest partial-decryption bound P and,
        // finally, the canonical BGV error bound beta_e.
        const PackingModulusCapacity capacity =
            compute_packing_modulus_capacity(
                kOuterFieldOrder, 65'537, 517, 114'670);

        CHECK(capacity.maximum_safe_aggregate_input_norm ==
              4'595'179'180'091ULL);
        CHECK(capacity
                  .maximum_honest_partial_decryption_bound_from_detection ==
              12'242'707'618'592ULL);
        CHECK(capacity
                  .maximum_honest_partial_decryption_bound_from_packing ==
              3'599'827'011ULL);
        CHECK(capacity.maximum_honest_partial_decryption_bound ==
              3'599'827'011ULL);
        CHECK(capacity.admits_even_zero_error);
        CHECK(capacity.maximum_honest_error_bound == 54'927);
        CHECK(capacity.maximum_honest_error_bound >=
              kSelectedPackingHonestErrorBound);
        CHECK(kSelectedPackingHonestErrorBound ==
              kPackingFinalRoundingErrorBound +
                  kPackingInheritedErrorAllowance);

        const std::uint64_t honest_p = canonical_partial_decryption_bound(
            65'537, kSelectedPackingHonestErrorBound);
        const LazyTernaryCertificateAssessment theorem =
            assess_lazy_ternary_certificate(
                LazyTernaryCertificateInputs{
                    .packing_modulus = kOuterFieldOrder,
                    .plaintext_modulus = 65'537,
                    .honest_partial_decryption_bound = honest_p,
                    .ring_degree = 1U << 14U,
                    .ciphertext_count = 517,
                    .repetitions = kPackingWellFormednessRepetitions,
                    .maximum_row_weight_upper = 114'670,
                });
        CHECK(honest_p == 1'165'346'165ULL);
        CHECK(theorem.exact_test_threshold == 245'099'234'912ULL);
        CHECK(theorem.accepted_input_bounds
                  .individual_partial_decryption_bound ==
              490'198'469'824ULL);
        CHECK(theorem.accepted_input_bounds
              .individual_canonical_error_bound == 7'479'721ULL);
        CHECK(theorem.accepted_input_bounds
                  .aggregate_column_l2_integer_upper ==
              1'487'564'379'623ULL);
        CHECK(theorem.interactive_certificate_holds);
        CHECK(theorem.interactive_probabilities
                  .conditional_honest_completeness_bits_lower > 101.4L);
    });

    runner.run("paper inequalities retain equality and strict no-wrap boundaries", [] {
        LazyTernaryCertificateInputs inputs{
            .packing_modulus = 333,
            .plaintext_modulus = 3,
            .honest_partial_decryption_bound = 2,
            .ring_degree = 32,
            .ciphertext_count = 1,
            .repetitions = kPackingWellFormednessRepetitions,
            .maximum_row_weight_upper = 1,
        };
        CHECK(assess_lazy_ternary_certificate(inputs).interactive_certificate_holds);
        inputs.packing_modulus = 332;
        CHECK(!assess_lazy_ternary_certificate(inputs).modular_detection_premise);
        inputs.packing_modulus = 444;
        inputs.maximum_row_weight_upper = 2;
        CHECK(!assess_lazy_ternary_certificate(inputs).packing_no_wrap);
        inputs.packing_modulus = 445;
        CHECK(assess_lazy_ternary_certificate(inputs).interactive_certificate_holds);
        // Non-square r uses an upward-rounded square root, not floating point.
        inputs.ciphertext_count = 2;
        inputs.packing_modulus = 888;
        CHECK(!assess_lazy_ternary_certificate(inputs).packing_no_wrap);
        inputs.packing_modulus = 889;
        CHECK(assess_lazy_ternary_certificate(inputs).interactive_certificate_holds);
    });

    runner.run("capacity and admission agree at their last accepted integer", [] {
        constexpr std::uint64_t modulus = 18'446'744'073'709'551'557ULL;
        const auto capacity = compute_packing_modulus_capacity(modulus, 65'537, 7, 97);
        LazyTernaryCertificateInputs inputs{
            .packing_modulus = modulus,
            .plaintext_modulus = 65'537,
            .honest_partial_decryption_bound = capacity.maximum_honest_partial_decryption_bound,
            .ring_degree = 32,
            .ciphertext_count = 7,
            .repetitions = kPackingWellFormednessRepetitions,
            .maximum_row_weight_upper = 97,
        };
        CHECK(assess_lazy_ternary_certificate(inputs).interactive_certificate_holds);
        ++inputs.honest_partial_decryption_bound;
        CHECK(!assess_lazy_ternary_certificate(inputs).interactive_certificate_holds);
    });
    return runner.summary();
}
