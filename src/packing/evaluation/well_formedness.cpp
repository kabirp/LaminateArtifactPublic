/// @file well_formedness.cpp
/// @brief Constraint, challenge, and no-wrap analysis for transcript packing.

#include "laminate/packing/evaluation/well_formedness.hpp"

#include <algorithm>
#include <cmath>
#include <limits>
#include <stdexcept>
#include <string_view>

namespace laminate::packing {
namespace {

constexpr std::string_view kBinaryChallengeDomain =
    "laminate/packing/well-formedness/binary/v1";
constexpr std::string_view kLazyTernaryChallengeDomain =
    "laminate/packing/well-formedness/lazy-ternary/v1";

std::uint64_t checked_size(std::size_t value, const char *operation) {
    if (value > std::numeric_limits<std::uint64_t>::max()) {
        throw std::overflow_error(std::string(operation) +
                                  ": size does not fit u64");
    }
    return static_cast<std::uint64_t>(value);
}

std::uint64_t checked_add(std::uint64_t left, std::uint64_t right,
                          const char *operation) {
    if (right > std::numeric_limits<std::uint64_t>::max() - left) {
        throw std::overflow_error(std::string(operation) +
                                  ": addition overflow");
    }
    return left + right;
}

std::uint64_t checked_mul(std::uint64_t left, std::uint64_t right,
                          const char *operation) {
    if (left != 0 &&
        right > std::numeric_limits<std::uint64_t>::max() / left) {
        throw std::overflow_error(std::string(operation) +
                                  ": multiplication overflow");
    }
    return left * right;
}

std::uint64_t ceil_div(std::uint64_t numerator,
                       std::uint64_t denominator) {
    if (denominator == 0) {
        throw std::invalid_argument("ceil_div: zero denominator");
    }
    return numerator / denominator + (numerator % denominator != 0 ? 1 : 0);
}

void validate_relation_shape(const WellFormednessRelationShape &shape) {
    if (shape.ring_degree == 0 || shape.ciphertext_count == 0 ||
        shape.repetitions == 0 || shape.ciphertext_components == 0 ||
        shape.public_input_capacity_bits == 0) {
        throw std::invalid_argument(
            "well-formedness relation dimensions must be nonzero");
    }
}

void observe_challenge_shape(Transcript &transcript, std::string_view domain,
                             std::size_t repetitions,
                             std::size_t ciphertext_count) {
    if (repetitions == 0 || ciphertext_count == 0) {
        throw std::invalid_argument(
            "well-formedness challenge dimensions must be nonzero");
    }
    transcript.observe(domain, checked_size(repetitions, "challenge shape"));
    transcript.observe(domain,
                       checked_size(ciphertext_count, "challenge shape"));
}

std::uint64_t ceiling_square_root(std::uint64_t value) {
    if (value < 2) {
        return value;
    }
    std::uint64_t low = 1;
    std::uint64_t high = std::uint64_t{1} << 32U;
    while (low < high) {
        const std::uint64_t middle = low + (high - low) / 2;
        if (middle >= ceil_div(value, middle)) {
            high = middle;
        } else {
            low = middle + 1;
        }
    }
    return low;
}

bool product_at_most(std::uint64_t limit,
                     std::initializer_list<std::uint64_t> factors) {
    std::uint64_t product = 1;
    for (const std::uint64_t factor : factors) {
        if (factor != 0 && product > limit / factor) {
            return false;
        }
        product *= factor;
    }
    return product <= limit;
}

std::uint64_t coefficient_magnitude(std::int64_t coefficient) {
    if (coefficient >= 0) {
        return static_cast<std::uint64_t>(coefficient);
    }
    return std::uint64_t{0} - static_cast<std::uint64_t>(coefficient);
}

std::uint64_t floor_square_root(unsigned __int128 value) {
    std::uint64_t low = 0;
    std::uint64_t high = std::numeric_limits<std::uint64_t>::max();
    while (low < high) {
        const std::uint64_t middle =
            low + (high - low) / 2 + ((high - low) % 2);
        const unsigned __int128 square =
            static_cast<unsigned __int128>(middle) * middle;
        if (square <= value) {
            low = middle;
        } else {
            high = middle - 1;
        }
    }
    return low;
}

bool supports_lazy_ternary_theorem_shape(
    const LazyTernaryCertificateInputs &inputs) {
    return inputs.ring_degree <= (std::size_t{1} << 15U) &&
           inputs.ciphertext_count <= (std::size_t{1} << 20U) &&
           inputs.repetitions == kPackingWellFormednessRepetitions;
}

LazyTernaryAcceptedInputBounds derive_accepted_input_bounds(
    const LazyTernaryCertificateInputs &inputs,
    std::uint64_t exact_test_threshold,
    std::uint64_t ceil_sqrt_aligned_count) {
    LazyTernaryAcceptedInputBounds result;
    result.individual_partial_decryption_bound = checked_mul(
        exact_test_threshold, 2, "lazy-ternary individual certificate");
    result.individual_canonical_error_bound =
        canonical_error_bound_from_partial_decryption(
            inputs.plaintext_modulus,
            result.individual_partial_decryption_bound);

    const long double root_aligned_count =
        std::sqrt(static_cast<long double>(inputs.ciphertext_count));
    result.aggregate_column_l2_boundary =
        (111.0L / 2.0L) *
        static_cast<long double>(inputs.honest_partial_decryption_bound) *
        root_aligned_count;
    const unsigned __int128 twice_upper =
        static_cast<unsigned __int128>(111) *
        inputs.honest_partial_decryption_bound * ceil_sqrt_aligned_count;
    const unsigned __int128 upper = (twice_upper + 1U) / 2U;
    if (upper <= std::numeric_limits<std::uint64_t>::max()) {
        result.aggregate_column_l2_integer_upper =
            static_cast<std::uint64_t>(upper);
    }
    return result;
}

LazyTernaryInteractiveProbabilityBounds derive_interactive_probabilities(
    const LazyTernaryCertificateInputs &inputs) {
    LazyTernaryInteractiveProbabilityBounds result;
    result.soundness_bits = inputs.repetitions;
    result.soundness_error_upper =
        std::exp2(-static_cast<long double>(inputs.repetitions));

    // For one honest coefficient, the paper's Centered-ternary sampling
    // lemma gives
    // Pr[|sum_i X_i y_i| >= tau] <= 2 exp(-(37/4)^2).
    const long double single_check_rejection_upper =
        2.0L * std::exp(-std::pow(37.0L / 4.0L, 2));
    result.conditional_honest_rejection_probability_upper = std::min(
        1.0L,
        static_cast<long double>(inputs.repetitions) *
            static_cast<long double>(inputs.ring_degree) *
            single_check_rejection_upper);
    result.conditional_honest_completeness_bits_lower = -std::log2(
        result.conditional_honest_rejection_probability_upper);
    return result;
}

} // namespace

WellFormednessConstraintEstimate estimate_well_formedness_constraints(
    const WellFormednessRelationShape &shape) {
    validate_relation_shape(shape);
    const std::uint64_t n = checked_size(shape.ring_degree, "constraint estimate");
    const std::uint64_t aligned_count =
        checked_size(shape.ciphertext_count, "constraint estimate");
    const std::uint64_t tests =
        checked_size(shape.repetitions, "constraint estimate");
    const std::uint64_t components =
        checked_size(shape.ciphertext_components, "constraint estimate");
    const std::uint64_t bits_per_coefficient =
        shape.distribution == TestCoefficientDistribution::BinarySubset ? 1 : 2;

    WellFormednessConstraintEstimate result;
    result.revealed_ciphertext_coordinates = checked_mul(
        checked_mul(components, n, "revealed coordinates"), tests,
        "revealed coordinates");
    result.coefficient_products = checked_mul(
        result.revealed_ciphertext_coordinates, aligned_count,
        "public coefficient products");
    result.output_relations = result.revealed_ciphertext_coordinates;
    result.challenge_bits = checked_mul(
        checked_mul(aligned_count, tests, "challenge bits"),
        bits_per_coefficient,
        "challenge bits");
    result.booleanity_constraints = result.challenge_bits;
    result.packed_public_inputs = ceil_div(
        result.challenge_bits,
        checked_size(shape.public_input_capacity_bits,
                     "public input capacity"));
    result.public_input_recomposition_constraints =
        result.packed_public_inputs;
    result.subtotal_constraints = checked_add(
        checked_add(result.coefficient_products, result.output_relations,
                    "constraint subtotal"),
        checked_add(result.booleanity_constraints,
                    result.public_input_recomposition_constraints,
                    "constraint subtotal"),
        "constraint subtotal");
    return result;
}

FixedPackingRelationEstimate estimate_fixed_packing_relation(
    const FixedPackingRelationShape &shape) {
    if (shape.ring_degree == 0 || shape.aligned_ciphertexts == 0 ||
        shape.packed_digit_ciphertexts == 0 ||
        shape.digit_count == 0 || shape.ciphertext_components == 0) {
        throw std::invalid_argument(
            "fixed packing relation dimensions must be nonzero");
    }
    const std::uint64_t n =
        checked_size(shape.ring_degree, "fixed packing relation");
    const std::uint64_t aligned_count =
        checked_size(shape.aligned_ciphertexts, "fixed packing relation");
    const std::uint64_t outputs = checked_size(
        shape.packed_digit_ciphertexts, "fixed packing relation");
    const std::uint64_t components = checked_size(
        shape.ciphertext_components, "fixed packing relation");
    const std::uint64_t digits =
        checked_size(shape.digit_count, "fixed packing relation");

    FixedPackingRelationEstimate result;
    result.witness_input_coordinates = checked_mul(
        checked_mul(components, n, "fixed packing input coordinates"),
        aligned_count,
        "fixed packing input coordinates");
    result.public_output_coordinates = checked_mul(
        checked_mul(components, n, "fixed packing output coordinates"),
        outputs, "fixed packing output coordinates");
    result.output_relation_constraints = result.public_output_coordinates;
    result.constant_matrix_terms = checked_mul(
        checked_mul(
            checked_mul(components, n, "fixed packing matrix terms"),
            aligned_count,
            "fixed packing matrix terms"),
        digits, "fixed packing matrix terms");
    return result;
}

BinarySubsetGap analyze_binary_subset_gap(
    std::uint64_t honest_partial_decryption_bound,
    std::size_t ciphertext_count) {
    if (honest_partial_decryption_bound == 0 || ciphertext_count == 0) {
        throw std::invalid_argument(
            "binary subset analysis inputs must be nonzero");
    }
    const std::uint64_t aligned_count =
        checked_size(ciphertext_count, "binary subset analysis");
    const std::uint64_t bound = checked_mul(
        honest_partial_decryption_bound, aligned_count,
        "binary subset test bound");
    return BinarySubsetGap{
        bound, checked_mul(2, bound, "binary subset trigger"),
        checked_mul(2, aligned_count, "binary subset slack")};
}

std::uint64_t canonical_partial_decryption_bound(
    std::uint64_t plaintext_modulus,
    std::uint64_t honest_error_bound) {
    if (plaintext_modulus < 3 || plaintext_modulus % 2 == 0) {
        throw std::invalid_argument(
            "canonical partial-decryption bound requires odd t >= 3");
    }
    return checked_add(
        checked_mul(plaintext_modulus, honest_error_bound,
                    "canonical partial-decryption bound"),
        (plaintext_modulus - 1) / 2,
        "canonical partial-decryption bound");
}

std::uint64_t canonical_error_bound_from_partial_decryption(
    std::uint64_t plaintext_modulus,
    std::uint64_t partial_decryption_bound) {
    if (plaintext_modulus < 3 || plaintext_modulus % 2 == 0) {
        throw std::invalid_argument(
            "canonical error bound requires odd t >= 3");
    }
    const std::uint64_t centered_plaintext_radius =
        (plaintext_modulus - 1) / 2;
    return checked_add(partial_decryption_bound,
                       centered_plaintext_radius,
                       "canonical error bound") /
           plaintext_modulus;
}

std::vector<std::vector<bool>> derive_binary_subset_challenges(
    Transcript &transcript, std::size_t repetitions,
    std::size_t ciphertext_count) {
    observe_challenge_shape(transcript, kBinaryChallengeDomain, repetitions,
                            ciphertext_count);
    const std::size_t total = checked_mul(
        checked_size(repetitions, "binary challenges"),
        checked_size(ciphertext_count, "binary challenges"),
        "binary challenges");
    const std::vector<bool> bits = transcript.challenge_bits(total);
    std::vector<std::vector<bool>> result(
        repetitions, std::vector<bool>(ciphertext_count));
    for (std::size_t test = 0; test < repetitions; ++test) {
        for (std::size_t ciphertext = 0; ciphertext < ciphertext_count;
             ++ciphertext) {
            result[test][ciphertext] =
                bits[test * ciphertext_count + ciphertext];
        }
    }
    return result;
}

std::int8_t LazyTernaryChallenge::coefficient() const {
    return static_cast<std::int8_t>((plus_bit ? 1 : 0) -
                                    (minus_bit ? 1 : 0));
}

LazyTernaryChallengeMatrix derive_lazy_ternary_challenges(
    Transcript &transcript, std::size_t repetitions,
    std::size_t ciphertext_count) {
    observe_challenge_shape(transcript, kLazyTernaryChallengeDomain,
                            repetitions, ciphertext_count);
    const std::size_t coefficients = checked_mul(
        checked_size(repetitions, "lazy-ternary challenges"),
        checked_size(ciphertext_count, "lazy-ternary challenges"),
        "lazy-ternary challenges");
    const std::size_t bit_count =
        checked_mul(coefficients, 2, "lazy-ternary challenge bits");
    const std::vector<bool> bits = transcript.challenge_bits(bit_count);
    LazyTernaryChallengeMatrix result(
        repetitions,
        std::vector<LazyTernaryChallenge>(ciphertext_count));
    for (std::size_t index = 0; index < coefficients; ++index) {
        result[index / ciphertext_count][index % ciphertext_count] =
            LazyTernaryChallenge{
                .plus_bit = bits[2 * index],
                .minus_bit = bits[2 * index + 1],
            };
    }
    return result;
}

std::uint64_t lazy_ternary_test_threshold(
    std::uint64_t honest_partial_decryption_bound,
    std::size_t ciphertext_count) {
    if (honest_partial_decryption_bound == 0 || ciphertext_count == 0) {
        throw std::invalid_argument(
            "lazy-ternary threshold inputs must be nonzero");
    }
    if (honest_partial_decryption_bound >
        std::numeric_limits<std::uint64_t>::max() / 37) {
        throw std::overflow_error(
            "lazy-ternary threshold scale overflows u64");
    }

    // floor((37/4) P sqrt(r)) = floor(sqrt((37P)^2 r) / 4).
    // Taking the integer square root first is exact because division by four
    // and both floors are monotone on nonnegative integers.
    const std::uint64_t scaled = 37 * honest_partial_decryption_bound;
    const unsigned __int128 square =
        static_cast<unsigned __int128>(scaled) * scaled;
    const unsigned __int128 maximum =
        ~static_cast<unsigned __int128>(0);
    const std::uint64_t aligned_count = checked_size(
        ciphertext_count, "lazy-ternary threshold");
    if (square != 0 && aligned_count > maximum / square) {
        throw std::overflow_error(
            "lazy-ternary threshold square exceeds 128 bits");
    }
    return floor_square_root(square * aligned_count) / 4;
}

PackingRowWeight compute_packing_row_weight(
    const PackingRowCoefficientLifts &row) {
    if (row.contributions.empty() || row.contributions.front().empty()) {
        throw std::invalid_argument(
            "packing row must contain nonempty coefficient lifts");
    }
    PackingRowWeightAccumulator accumulator(
        row.contributions.front().size());
    for (const SignedCoefficientMask &mask : row.contributions) {
        accumulator.add(mask);
    }
    return accumulator.finish();
}

PackingRowWeightAccumulator::PackingRowWeightAccumulator(
    std::size_t ring_degree)
    : coefficient_square_sums_(ring_degree, 0) {
    if (ring_degree == 0) {
        throw std::invalid_argument(
            "packing row accumulator requires a nonzero ring degree");
    }
}

void PackingRowWeightAccumulator::add(
    std::span<const std::int64_t> centered_coefficients) {
    if (centered_coefficients.size() != ring_degree()) {
        throw std::invalid_argument(
            "packing row contains ragged coefficient lifts");
    }
    for (std::size_t coefficient = 0; coefficient < ring_degree();
         ++coefficient) {
        const std::uint64_t magnitude =
            coefficient_magnitude(centered_coefficients[coefficient]);
        maximum_coefficient_magnitude_ =
            std::max(maximum_coefficient_magnitude_, magnitude);
        total_absolute_coefficient_weight_ = checked_add(
            total_absolute_coefficient_weight_, magnitude,
            "packing row absolute weight");
        const std::uint64_t square =
            checked_mul(magnitude, magnitude, "packing row square");
        coefficient_square_sums_[coefficient] = checked_add(
            coefficient_square_sums_[coefficient], square,
            "packing row square sum");
        squared_frobenius_ += static_cast<long double>(square);
    }
    ++contribution_count_;
}

PackingRowWeight PackingRowWeightAccumulator::finish() const {
    if (contribution_count_ == 0) {
        throw std::invalid_argument(
            "packing row must contain coefficient lifts");
    }
    PackingRowWeight result;
    result.total_absolute_coefficient_weight =
        total_absolute_coefficient_weight_;
    for (const std::uint64_t square_sum : coefficient_square_sums_) {
        result.approximate_mixed_norm +=
            std::sqrt(static_cast<long double>(square_sum));
        result.conservative_integer_upper = checked_add(
            result.conservative_integer_upper,
            ceiling_square_root(square_sum),
            "packing row integer upper bound");
    }
    result.cauchy_schwarz_upper =
        std::sqrt(static_cast<long double>(ring_degree()) *
                  squared_frobenius_);
    result.coefficient_infinity_upper =
        static_cast<long double>(ring_degree()) *
        static_cast<long double>(maximum_coefficient_magnitude_) *
        std::sqrt(static_cast<long double>(contribution_count_));
    return result;
}

long double required_lazy_ternary_aligned_budget_bits(
    std::size_t aligned_ciphertext_count,
    std::uint64_t maximum_row_weight_upper) {
    if (aligned_ciphertext_count == 0 || maximum_row_weight_upper == 0) {
        throw std::invalid_argument(
            "packing budget inputs must be nonzero");
    }
    const long double aligned_count =
        static_cast<long double>(aligned_ciphertext_count);
    const long double direct = (333.0L / 4.0L) * aligned_count;
    const long double packing =
        (111.0L / 2.0L) * std::sqrt(aligned_count) *
        static_cast<long double>(maximum_row_weight_upper);
    return std::log2(std::max(direct, packing));
}

LazyTernaryCertificateAssessment assess_lazy_ternary_certificate(
    const LazyTernaryCertificateInputs &inputs) {
    if (inputs.packing_modulus < 3 ||
        inputs.plaintext_modulus < 3 ||
        inputs.plaintext_modulus % 2 == 0 ||
        inputs.honest_partial_decryption_bound == 0 ||
        inputs.ring_degree == 0 || inputs.ciphertext_count == 0 ||
        inputs.repetitions == 0 || inputs.maximum_row_weight_upper == 0) {
        throw std::invalid_argument(
            "lazy-ternary certificate inputs must be nonzero");
    }
    const std::uint64_t p = inputs.honest_partial_decryption_bound;
    const std::uint64_t aligned_count =
        checked_size(inputs.ciphertext_count, "lazy-ternary assessment");
    const std::uint64_t ceil_sqrt_aligned_count =
        ceiling_square_root(aligned_count);

    LazyTernaryCertificateAssessment result;

    // Step 1: derive tau and both consequences of accepting every test.
    result.theorem_shape_supported =
        supports_lazy_ternary_theorem_shape(inputs);
    result.exact_test_threshold =
        lazy_ternary_test_threshold(p, aligned_count);
    result.accepted_input_bounds = derive_accepted_input_bounds(
        inputs, result.exact_test_threshold, ceil_sqrt_aligned_count);

    // Step 2: check modular detection and the concrete packing row.
    result.individual_detection_premise = product_at_most(
        (inputs.packing_modulus - 1) / 4,
        {result.exact_test_threshold});
    // c=37/4 gives Q >= (333/2) P r. Divide before multiplying so
    // this exact integer comparison also handles a full-width modulus.
    const std::uint64_t detection_capacity = static_cast<std::uint64_t>(
        (static_cast<unsigned __int128>(inputs.packing_modulus) * 2U) / 333U);
    result.modular_detection_premise =
        product_at_most(detection_capacity, {p, aligned_count});
    // 6c P sqrt(r) W < Q/2 is 111 P sqrt(r) W < Q. Replace sqrt(r)
    // and W by integer upper bounds; Q-1 preserves the strict inequality.
    result.packing_no_wrap = product_at_most(
        inputs.packing_modulus - 1,
        {111, p, ceil_sqrt_aligned_count,
         inputs.maximum_row_weight_upper});
    result.interactive_detection_guarantees_hold =
        result.theorem_shape_supported &&
        result.modular_detection_premise;
    result.interactive_certificate_holds =
        result.interactive_detection_guarantees_hold &&
        result.packing_no_wrap;

    // Step 3: attach the interactive probability and budget ledgers. Neither
    // field performs a Fiat--Shamir compilation.
    const long double root_aligned_count =
        std::sqrt(static_cast<long double>(inputs.ciphertext_count));
    result.approximate_test_radius =
        (37.0L / 4.0L) * static_cast<long double>(p) *
        root_aligned_count;
    result.interactive_probabilities =
        derive_interactive_probabilities(inputs);
    result.required_aligned_budget_bits =
        required_lazy_ternary_aligned_budget_bits(
            inputs.ciphertext_count, inputs.maximum_row_weight_upper);
    return result;
}

IndividualBoundPackingAssessment assess_individual_bound_packing(
    std::uint64_t packing_modulus,
    std::uint64_t certified_input_bound,
    std::uint64_t maximum_row_absolute_weight) {
    if (packing_modulus < 3 || certified_input_bound == 0 ||
        maximum_row_absolute_weight == 0) {
        throw std::invalid_argument(
            "individual packing inputs must be nonzero");
    }

    IndividualBoundPackingAssessment result;
    result.certified_input_bound = certified_input_bound;
    result.maximum_row_absolute_weight = maximum_row_absolute_weight;
    result.maximum_admissible_input_bound =
        ((packing_modulus - 1) / 2) / maximum_row_absolute_weight;
    result.packing_no_wrap = product_at_most(
        (packing_modulus - 1) / 2,
        {certified_input_bound, maximum_row_absolute_weight});
    return result;
}

PackingModulusCapacity compute_packing_modulus_capacity(
    std::uint64_t packing_modulus,
    std::uint64_t plaintext_modulus,
    std::size_t aligned_ciphertext_count,
    std::uint64_t maximum_row_weight_upper) {
    if (packing_modulus < 3 || plaintext_modulus < 3 ||
        plaintext_modulus % 2 == 0 ||
        aligned_ciphertext_count == 0 || maximum_row_weight_upper == 0) {
        throw std::invalid_argument(
            "packing modulus capacity inputs must be nonzero");
    }
    const std::uint64_t aligned_count = checked_size(
        aligned_ciphertext_count, "packing modulus capacity");
    const std::uint64_t ceil_sqrt_aligned_count =
        ceiling_square_root(aligned_count);

    PackingModulusCapacity result;
    result.maximum_safe_aggregate_input_norm =
        ((packing_modulus - 1) / 2) / maximum_row_weight_upper;
    result.maximum_honest_partial_decryption_bound_from_detection =
        static_cast<std::uint64_t>(
            (static_cast<unsigned __int128>(packing_modulus) * 2U) / 333U) /
        aligned_count;
    result.maximum_honest_partial_decryption_bound_from_packing =
        (packing_modulus - 1) / 111 / ceil_sqrt_aligned_count /
        maximum_row_weight_upper;
    result.maximum_honest_partial_decryption_bound = std::min(
        result.maximum_honest_partial_decryption_bound_from_detection,
        result.maximum_honest_partial_decryption_bound_from_packing);

    const std::uint64_t centered_message_radius =
        (plaintext_modulus - 1) / 2;
    result.admits_even_zero_error =
        result.maximum_honest_partial_decryption_bound >=
        centered_message_radius;
    if (result.admits_even_zero_error) {
        result.maximum_honest_error_bound =
            (result.maximum_honest_partial_decryption_bound -
             centered_message_radius) /
            plaintext_modulus;
    }
    return result;
}

} // namespace laminate::packing
