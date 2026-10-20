/// @file packing_capacity_report.cpp
/// @brief Exact N=2^14 one-limb transcript-packing parameter audit.

#include "laminate/fhe/seal_backend.hpp"
#include "laminate/packing/analysis/operator.hpp"

#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>

using namespace laminate;
using namespace laminate::fhe;
using namespace laminate::packing;

namespace {

constexpr std::size_t kRingDegree = 1U << 14U;
constexpr std::uint64_t kDefaultHonestErrorBound =
    kSelectedPackingHonestErrorBound;

struct ScheduleCase {
    std::string_view name;
    std::size_t bhip_round_count;
};

constexpr std::array<ScheduleCase, 4> kScheduleCases{{
    {"laned-b1", 287},
    {"laned-b128", 399},
    {"laned-b16384", 517},
    {"folded", 517},
}};

struct SweepInputs {
    std::uint64_t honest_error_bound = kDefaultHonestErrorBound;
};

std::optional<std::uint64_t> parse_error_bound(int argc, char **argv) {
    if (argc == 1) {
        return kDefaultHonestErrorBound;
    }
    if (argc == 2 && (std::string_view(argv[1]) == "--help" ||
                      std::string_view(argv[1]) == "-h")) {
        std::cout
            << "Usage: laminate_packing_capacity_report [--beta-e E]\n";
        return std::nullopt;
    }
    if (argc != 3 || std::string_view(argv[1]) != "--beta-e") {
        throw std::invalid_argument(
            "usage: laminate_packing_capacity_report [--beta-e E]");
    }
    std::size_t consumed = 0;
    const std::uint64_t result = std::stoull(argv[2], &consumed);
    if (consumed != std::string_view(argv[2]).size()) {
        throw std::invalid_argument("--beta-e must be an integer");
    }
    return result;
}

SealBackend::Contexts make_target_contexts() {
    return SealBackend::create(SealParameters{
        .poly_modulus_degree = kRingDegree,
        .fresh_rns_limbs = 1,
        .bits_per_data_prime = 60,
        .special_prime_bits = 60,
        .security_level = seal::sec_level_type::tc128,
    });
}

SignedCoefficientMask encode_mask(
    const SealBackend::EvalContext &eval,
    const fhe::SlotVector &mask) {
    return SealBackend::encode_centered_plaintext_coefficients(eval, mask);
}

long double direct_required_budget_bits(
    std::uint64_t honest_partial_decryption_bound,
    const IndividualBoundPackingAssessment &assessment) {
    const long double amplification =
        static_cast<long double>(assessment.certified_input_bound) *
        static_cast<long double>(assessment.maximum_row_absolute_weight) /
        static_cast<long double>(honest_partial_decryption_bound);
    return std::log2(amplification);
}

void print_header() {
    std::cout
        << "case\tr\toutputs\tQ\tbeta_e\tP\tbase\tprotocol_selected"
           "\tdigits\tphysical_cts"
           "\tW_upper\tA_l1\tB_column_max\tP_max_detection"
           "\tP_max_packing\tP_max\taggregate_max_beta_e\taggregate_pass"
           "\ttau\taccepted_y_bound\taccepted_beta_bad"
           "\taggregate_l2_integer_upper\tinteractive_soundness_bits"
           "\tfiat_shamir_status\tdirect_capacity_y"
           "\tdirect_pass\taggregate_budget_bits\tdirect_budget_bits\n";
}

void print_profile(std::string_view case_name,
                   const PackingLinearOperator &packing_operator,
                   std::uint64_t packing_modulus,
                   const SweepInputs &inputs,
                   std::uint64_t honest_partial_decryption_bound,
                   SignedDigitPackingWeightAnalysis weights) {
    const PackingModulusCapacity aggregate_capacity =
        compute_packing_modulus_capacity(
            packing_modulus, kBaseFieldOrder,
            packing_operator.aligned_ciphertext_count,
            weights.maximum_digit_row_weight_upper);
    const LazyTernaryCertificateAssessment aggregate_certificate =
        assess_lazy_ternary_certificate(LazyTernaryCertificateInputs{
            .packing_modulus = packing_modulus,
            .plaintext_modulus = kBaseFieldOrder,
            .honest_partial_decryption_bound =
                honest_partial_decryption_bound,
            .ring_degree = packing_operator.slot_count,
            .ciphertext_count = packing_operator.aligned_ciphertext_count,
            .repetitions = kPackingWellFormednessRepetitions,
            .maximum_row_weight_upper =
                weights.maximum_digit_row_weight_upper,
        });
    const IndividualBoundPackingAssessment direct =
        assess_individual_bound_packing(
            packing_modulus,
            aggregate_certificate.accepted_input_bounds
                .individual_partial_decryption_bound,
            weights.maximum_digit_row_absolute_weight);

    std::cout << case_name << '\t'
              << packing_operator.aligned_ciphertext_count << '\t'
              << packing_operator.rows.size() << '\t'
              << packing_modulus << '\t'
              << inputs.honest_error_bound << '\t'
              << honest_partial_decryption_bound << '\t'
              << weights.radix.base << '\t'
              << (weights.radix.base == kSelectedPackingRadixBase) << '\t'
              << weights.radix.digit_count << '\t'
              << weights.rows.size() << '\t'
              << weights.maximum_digit_row_weight_upper << '\t'
              << weights.maximum_digit_row_absolute_weight << '\t'
              << aggregate_capacity.maximum_safe_aggregate_input_norm
              << '\t'
              << aggregate_capacity
                     .maximum_honest_partial_decryption_bound_from_detection
              << '\t'
              << aggregate_capacity
                     .maximum_honest_partial_decryption_bound_from_packing
              << '\t'
              << aggregate_capacity.maximum_honest_partial_decryption_bound
              << '\t'
              << aggregate_capacity.maximum_honest_error_bound << '\t'
              << aggregate_certificate.interactive_certificate_holds
              << '\t'
              << aggregate_certificate.exact_test_threshold << '\t'
              << direct.certified_input_bound << '\t'
              << aggregate_certificate.accepted_input_bounds
                     .individual_canonical_error_bound
              << '\t'
              << aggregate_certificate.accepted_input_bounds
                     .aggregate_column_l2_integer_upper.value_or(0)
              << '\t'
              << aggregate_certificate.interactive_probabilities
                     .soundness_bits
              << '\t'
              << "not-established" << '\t'
              << direct.maximum_admissible_input_bound << '\t'
              << direct.packing_no_wrap << '\t'
              << static_cast<double>(
                     aggregate_certificate.required_aligned_budget_bits)
              << '\t'
              << static_cast<double>(direct_required_budget_bits(
                     honest_partial_decryption_bound, direct))
              << '\n';
}

void run_case(const SealBackend::EvalContext &eval,
              const ScheduleCase &schedule,
              const SweepInputs &inputs) {
    const PackingLayout layout =
        make_fixed_message_coset_packing_layout(
            kRingDegree, schedule.bhip_round_count,
            schedule.bhip_round_count);
    const PackingLinearOperator packing_operator =
        make_packing_linear_operator(layout);
    const std::uint64_t packing_modulus =
        SealBackend::lowest_coefficient_modulus(eval);
    const std::uint64_t honest_partial_decryption_bound =
        canonical_partial_decryption_bound(
            kBaseFieldOrder, inputs.honest_error_bound);

    for (const BalancedRadix &radix :
         canonical_balanced_radix_frontier(kBaseFieldOrder)) {
        SignedDigitPackingWeightAnalysis weights =
            analyze_signed_digit_packing_weights(
                packing_operator,
                [&](const fhe::SlotVector &mask) {
                    return encode_mask(eval, mask);
                },
                radix);
        print_profile(schedule.name, packing_operator, packing_modulus,
                      inputs, honest_partial_decryption_bound,
                      std::move(weights));
        std::cout.flush();
    }
}

void run_sweep(const SweepInputs &inputs) {
    const SealBackend::Contexts contexts = make_target_contexts();
    print_header();
    for (const ScheduleCase &schedule : kScheduleCases) {
        run_case(contexts.eval, schedule, inputs);
    }
}

} // namespace

int main(int argc, char **argv) {
    try {
        const std::optional<std::uint64_t> honest_error_bound =
            parse_error_bound(argc, argv);
        if (!honest_error_bound) {
            return 0;
        }
        run_sweep(SweepInputs{.honest_error_bound = *honest_error_bound});
        return 0;
    } catch (const std::exception &error) {
        std::cerr << "packing capacity report failed: " << error.what()
                  << '\n';
        return 1;
    }
}
