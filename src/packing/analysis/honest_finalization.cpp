/// @file honest_finalization.cpp
/// @brief Exact honest-finalization recurrence and no-wrap checks.

#include "laminate/packing/analysis/honest_finalization.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <limits>
#include <stdexcept>

namespace laminate::packing {
namespace {

using Wide = unsigned __int128;

std::uint64_t checked_add(std::uint64_t left, std::uint64_t right,
                          const char *operation) {
    if (right > std::numeric_limits<std::uint64_t>::max() - left) {
        throw std::overflow_error(operation);
    }
    return left + right;
}

Wide ceil_div(Wide numerator, std::uint64_t denominator) {
    return numerator / denominator +
           (numerator % denominator == 0 ? 0 : 1);
}

bool narrow(Wide value, std::uint64_t &destination) {
    if (value > std::numeric_limits<std::uint64_t>::max()) {
        destination = std::numeric_limits<std::uint64_t>::max();
        return false;
    }
    destination = static_cast<std::uint64_t>(value);
    return true;
}

Wide product(std::span<const std::uint64_t> factors) {
    Wide result = 1;
    for (const std::uint64_t factor : factors) {
        if (factor == 0 || result > ~Wide{0} / factor) {
            throw std::overflow_error(
                "honest finalization: retained modulus product overflows");
        }
        result *= factor;
    }
    return result;
}

std::size_t bit_count(Wide value) {
    const std::uint64_t high = static_cast<std::uint64_t>(value >> 64);
    return high == 0
               ? std::bit_width(static_cast<std::uint64_t>(value))
               : 64 + std::bit_width(high);
}

/// Return the exact bit length of a product of at most three u64 moduli.
std::size_t modulus_product_bit_count(
    std::span<const std::uint64_t> moduli) {
    std::array<std::uint64_t, 3> limbs{1, 0, 0};
    std::size_t used = 1;
    for (const std::uint64_t modulus : moduli) {
        std::uint64_t carry = 0;
        for (std::size_t limb = 0; limb < used; ++limb) {
            const Wide multiplied =
                Wide{limbs[limb]} * modulus + carry;
            limbs[limb] = static_cast<std::uint64_t>(multiplied);
            carry = static_cast<std::uint64_t>(multiplied >> 64);
        }
        if (carry != 0) {
            if (used == limbs.size()) {
                throw std::overflow_error(
                    "honest finalization: input modulus product overflows");
            }
            limbs[used++] = carry;
        }
    }
    return (used - 1) * 64 + std::bit_width(limbs[used - 1]);
}

std::size_t partial_decryption_norm_bit_count(
    std::size_t input_modulus_bit_count,
    const ObservedInvariantNoiseEvidence &evidence) {
    if (input_modulus_bit_count < 2 ||
        evidence.invariant_noise_budget_bits >=
            input_modulus_bit_count) {
        throw std::invalid_argument(
            "honest finalization: invalid invariant-noise evidence");
    }
    return input_modulus_bit_count -
           evidence.invariant_noise_budget_bits - 1;
}

bool power_of_two_upper(std::size_t bit_count, Wide &upper) {
    if (bit_count >= 128) {
        return false;
    }
    upper = bit_count == 0 ? 0 : (Wide{1} << bit_count) - 1;
    return true;
}

struct PowerDivision {
    Wide quotient = 0;
    bool supported = false;
};

/// Divide `2^exponent + offset` without materializing the power of two.
PowerDivision divide_power_plus_offset(std::size_t exponent,
                                       Wide offset,
                                       Wide denominator) {
    if (denominator == 0 || denominator > (~Wide{0}) / 2 ||
        offset >= denominator) {
        return {};
    }

    Wide quotient = 0;
    Wide remainder = 1;
    for (std::size_t bit = 0; bit < exponent; ++bit) {
        if (quotient > (~Wide{0}) / 2) {
            return {};
        }
        quotient *= 2;
        remainder *= 2;
        if (remainder >= denominator) {
            remainder -= denominator;
            ++quotient;
        }
    }

    // `offset < denominator`, so adding it changes the quotient by at most
    // one. Avoid overflowing the remainder while checking that carry.
    if (offset >= denominator - remainder) {
        if (quotient == ~Wide{0}) {
            return {};
        }
        ++quotient;
    }
    return PowerDivision{.quotient = quotient, .supported = true};
}

void validate_inputs(const HonestFinalizationPolicy &policy,
                     std::span<const std::uint64_t> moduli) {
    if (policy.plaintext_modulus < 2 ||
        policy.secret_hamming_weight_upper == 0 ||
        policy.target_error_bound == 0 ||
        policy.final_rounding_reserve == 0) {
        throw std::invalid_argument(
            "honest finalization: policy fields must be nonzero");
    }
    if (moduli.size() < 2 || moduli.size() > 3) {
        throw std::invalid_argument(
            "honest finalization: expected two or three data primes");
    }
    for (const std::uint64_t modulus : moduli) {
        if (modulus < 3 || modulus % 2 == 0) {
            throw std::invalid_argument(
                "honest finalization: coefficient moduli must be odd");
        }
    }
}

std::uint64_t selected_inherited_allowance(
    const HonestFinalizationPolicy &policy) {
    return policy.final_rounding_reserve <= policy.target_error_bound
               ? policy.target_error_bound -
                     policy.final_rounding_reserve
               : 0;
}

bool target_decryption_no_wrap(const HonestFinalizationPolicy &policy,
                               std::uint64_t bottom_modulus) {
    const Wide message_radius = (policy.plaintext_modulus - 1) / 2;
    if (policy.target_error_bound >
        (~Wide{0} - message_radius) / policy.plaintext_modulus) {
        return false;
    }
    const Wide partial_decryption =
        Wide{policy.plaintext_modulus} * policy.target_error_bound +
        message_radius;
    return partial_decryption <= (bottom_modulus - 1) / 2;
}

struct ErrorState {
    Wide partial_decryption_bound = 0;
    Wide canonical_error_bound = 0;
};

struct AssessedSwitch {
    ModulusSwitchBound bound;
    ErrorState output;
};

Wide switch_rounding_phase(const HonestFinalizationPolicy &policy) {
    return Wide{policy.plaintext_modulus} *
           (policy.secret_hamming_weight_upper + 1);
}

bool make_output_state(const HonestFinalizationPolicy &policy,
                       Wide output_error, ErrorState &output) {
    const Wide radius = (policy.plaintext_modulus - 1) / 2;
    if (output_error >
        (~Wide{0} - radius) / policy.plaintext_modulus) {
        return false;
    }
    output.canonical_error_bound = output_error;
    output.partial_decryption_bound =
        Wide{policy.plaintext_modulus} * output_error + radius;
    return true;
}

AssessedSwitch assess_initial_switch(
    const HonestFinalizationPolicy &policy, std::size_t limb_count,
    std::size_t partial_decryption_bits, std::uint64_t dropped_modulus,
    Wide retained_modulus, std::uint64_t rounding_error_bound) {
    AssessedSwitch result;
    auto &stage = result.bound;
    stage.input_limb_count = limb_count;
    stage.dropped_modulus = dropped_modulus;
    stage.input_partial_decryption_norm_bit_count =
        partial_decryption_bits;

    // For reporting only, materialize the initial beta when it fits. The
    // recurrence below does not depend on this optional u128 representation.
    Wide partial_decryption = 0;
    if (power_of_two_upper(partial_decryption_bits,
                           partial_decryption)) {
        const Wide radius = (policy.plaintext_modulus - 1) / 2;
        const Wide input_error =
            (partial_decryption + radius) / policy.plaintext_modulus;
        stage.input_error_bound_fits_u64 = narrow(
            input_error, stage.input_error_bound);
    } else {
        stage.input_error_bound =
            std::numeric_limits<std::uint64_t>::max();
    }

    // ceil((2^p-1)/q) = floor((2^p+q-2)/q).
    const PowerDivision divided_partial_decryption =
        divide_power_plus_offset(
            partial_decryption_bits, dropped_modulus - 2,
            dropped_modulus);

    // beta=floor((2^p-1+r)/t), hence
    // ceil(beta/q)=floor((2^p+r-1+t(q-1))/(tq)).
    const Wide radius = (policy.plaintext_modulus - 1) / 2;
    const Wide denominator =
        Wide{policy.plaintext_modulus} * dropped_modulus;
    const Wide inherited_offset =
        radius +
        Wide{policy.plaintext_modulus} * (dropped_modulus - 1) - 1;
    const PowerDivision inherited = divide_power_plus_offset(
        partial_decryption_bits, inherited_offset, denominator);
    if (!divided_partial_decryption.supported || !inherited.supported) {
        return result;
    }

    stage.scaled_inherited_error_bound_fits_u64 = narrow(
        inherited.quotient, stage.scaled_inherited_error_bound);
    if (inherited.quotient >
        ~Wide{0} - rounding_error_bound) {
        return result;
    }
    const Wide output_error =
        inherited.quotient + rounding_error_bound;
    stage.output_error_bound_fits_u64 = narrow(
        output_error, stage.output_error_bound);
    stage.pre_switch_no_wrap =
        divided_partial_decryption.quotient +
                switch_rounding_phase(policy) <=
            (retained_modulus - 1) / 2;
    stage.arithmetic_supported =
        make_output_state(policy, output_error, result.output);
    return result;
}

AssessedSwitch assess_bounded_switch(
    const HonestFinalizationPolicy &policy, std::size_t limb_count,
    const ErrorState &input, std::uint64_t dropped_modulus,
    Wide retained_modulus, std::uint64_t rounding_error_bound) {
    AssessedSwitch result;
    auto &stage = result.bound;
    stage.input_limb_count = limb_count;
    stage.dropped_modulus = dropped_modulus;
    stage.input_partial_decryption_norm_bit_count =
        bit_count(input.partial_decryption_bound);
    stage.input_error_bound_fits_u64 = narrow(
        input.canonical_error_bound, stage.input_error_bound);

    const Wide inherited = ceil_div(
        input.canonical_error_bound, dropped_modulus);
    stage.scaled_inherited_error_bound_fits_u64 = narrow(
        inherited, stage.scaled_inherited_error_bound);
    if (inherited > ~Wide{0} - rounding_error_bound) {
        return result;
    }
    const Wide output_error = inherited + rounding_error_bound;
    stage.output_error_bound_fits_u64 = narrow(
        output_error, stage.output_error_bound);
    stage.pre_switch_no_wrap =
        ceil_div(input.partial_decryption_bound, dropped_modulus) +
                switch_rounding_phase(policy) <=
            (retained_modulus - 1) / 2;
    stage.arithmetic_supported =
        make_output_state(policy, output_error, result.output);
    return result;
}

ObservedHonestFinalizationAssessment assess_core(
    const HonestFinalizationPolicy &policy,
    std::span<const std::uint64_t> moduli,
    const ObservedInvariantNoiseEvidence &evidence) {
    validate_inputs(policy, moduli);

    ObservedHonestFinalizationAssessment result;
    result.observed_invariant_noise_budget_bits =
        evidence.invariant_noise_budget_bits;
    result.input_modulus_bit_count =
        modulus_product_bit_count(moduli);
    result.proven_per_switch_rounding_bound = checked_add(
        policy.secret_hamming_weight_upper, 1,
        "honest finalization: rounding bound overflows");
    result.selected_final_rounding_reserve =
        policy.final_rounding_reserve;
    result.selected_scaled_inherited_allowance =
        selected_inherited_allowance(policy);
    result.input_noise_budget_positive =
        evidence.invariant_noise_budget_bits != 0;
    result.rounding_reserve_is_sufficient =
        policy.final_rounding_reserve >=
        result.proven_per_switch_rounding_bound;
    result.target_decryption_no_wrap =
        target_decryption_no_wrap(policy, moduli.front());

    const std::size_t initial_norm_bits =
        partial_decryption_norm_bit_count(
            result.input_modulus_bit_count, evidence);
    bool arithmetic_supported = true;
    bool all_switches_no_wrap = true;
    ErrorState state;

    for (std::size_t limb_count = moduli.size(); limb_count > 1;
         --limb_count) {
        const std::uint64_t dropped = moduli[limb_count - 1];
        const Wide retained_modulus =
            product(moduli.first(limb_count - 1));
        const AssessedSwitch assessed =
            limb_count == moduli.size()
                ? assess_initial_switch(
                      policy, limb_count, initial_norm_bits, dropped,
                      retained_modulus,
                      result.proven_per_switch_rounding_bound)
                : assess_bounded_switch(
                      policy, limb_count, state, dropped,
                      retained_modulus,
                      result.proven_per_switch_rounding_bound);
        const ModulusSwitchBound &stage = assessed.bound;
        all_switches_no_wrap =
            all_switches_no_wrap && stage.pre_switch_no_wrap;
        arithmetic_supported = arithmetic_supported &&
                               stage.arithmetic_supported;
        result.switches.push_back(stage);
        if (!stage.arithmetic_supported) {
            break;
        }
        state = assessed.output;
    }

    result.arithmetic_supported = arithmetic_supported;
    result.all_switches_no_wrap =
        all_switches_no_wrap &&
        result.switches.size() == moduli.size() - 1;
    if (result.switches.size() == moduli.size() - 1) {
        const ModulusSwitchBound &last = result.switches.back();
        result.final_scaled_inherited_error_bound =
            last.scaled_inherited_error_bound;
        result.final_error_bound = last.output_error_bound;
    }
    result.inherited_error_fits_selected_allowance =
        result.arithmetic_supported && !result.switches.empty() &&
        result.switches.back()
            .scaled_inherited_error_bound_fits_u64 &&
        result.final_scaled_inherited_error_bound <=
            result.selected_scaled_inherited_allowance;
    result.final_error_fits_target =
        result.arithmetic_supported && !result.switches.empty() &&
        result.switches.back().output_error_bound_fits_u64 &&
        result.final_error_bound <= policy.target_error_bound;
    return result;
}

std::size_t minimum_required_budget(
    const HonestFinalizationPolicy &policy,
    std::span<const std::uint64_t> moduli,
    std::size_t input_modulus_bit_count) {
    for (std::size_t budget = 1; budget < input_modulus_bit_count;
         ++budget) {
        const auto candidate = assess_core(
            policy, moduli,
            ObservedInvariantNoiseEvidence{
                .invariant_noise_budget_bits = budget,
            });
        if (candidate.input_noise_budget_positive &&
            candidate.arithmetic_supported &&
            candidate.rounding_reserve_is_sufficient &&
            candidate.all_switches_no_wrap &&
            candidate.inherited_error_fits_selected_allowance &&
            candidate.final_error_fits_target &&
            candidate.target_decryption_no_wrap) {
            return budget;
        }
    }
    return input_modulus_bit_count;
}

} // namespace

bool ObservedHonestFinalizationAssessment::
    certifies_observed_finalization() const {
    return input_noise_budget_positive && arithmetic_supported &&
           rounding_reserve_is_sufficient && all_switches_no_wrap &&
           inherited_error_fits_selected_allowance &&
           final_error_fits_target && target_decryption_no_wrap;
}

ObservedHonestFinalizationAssessment assess_observed_honest_finalization(
    const HonestFinalizationPolicy &policy,
    std::span<const std::uint64_t> data_moduli_low_to_high,
    const ObservedInvariantNoiseEvidence &evidence) {
    auto result = assess_core(policy, data_moduli_low_to_high,
                              evidence);
    result.minimum_required_invariant_noise_budget_bits =
        minimum_required_budget(policy, data_moduli_low_to_high,
                                result.input_modulus_bit_count);
    return result;
}

ObservedHonestFinalizationBatchAssessment
assess_observed_honest_finalization_batch(
    const HonestFinalizationPolicy &policy,
    std::span<const ObservedHonestFinalizationInput> inputs) {
    if (inputs.empty()) {
        throw std::invalid_argument(
            "honest finalization batch: ciphertext list is empty");
    }

    ObservedHonestFinalizationBatchAssessment result;
    result.ciphertext_count = inputs.size();
    result.minimum_observed_invariant_noise_budget_bits =
        std::numeric_limits<std::size_t>::max();
    result.minimum_budget_slack_bits =
        std::numeric_limits<std::int64_t>::max();
    result.all_ciphertexts_are_size_two = true;
    result.all_correction_factors_are_one = true;
    result.all_observed_finalizations_certified = true;

    for (std::size_t index = 0; index < inputs.size(); ++index) {
        const ObservedHonestFinalizationInput &input = inputs[index];
        const auto assessment = assess_observed_honest_finalization(
            policy, input.data_moduli_low_to_high,
            ObservedInvariantNoiseEvidence{
                .invariant_noise_budget_bits =
                    input.invariant_noise_budget_bits,
            });
        const std::int64_t slack =
            static_cast<std::int64_t>(
                assessment.observed_invariant_noise_budget_bits) -
            static_cast<std::int64_t>(
                assessment.minimum_required_invariant_noise_budget_bits);
        if (slack < result.minimum_budget_slack_bits) {
            result.minimum_budget_slack_bits = slack;
            result.worst_ciphertext_index = index;
        }
        result.minimum_observed_invariant_noise_budget_bits = std::min(
            result.minimum_observed_invariant_noise_budget_bits,
            assessment.observed_invariant_noise_budget_bits);
        result.maximum_required_invariant_noise_budget_bits = std::max(
            result.maximum_required_invariant_noise_budget_bits,
            assessment.minimum_required_invariant_noise_budget_bits);
        result.maximum_final_scaled_inherited_error_bound = std::max(
            result.maximum_final_scaled_inherited_error_bound,
            assessment.final_scaled_inherited_error_bound);
        result.maximum_final_error_bound = std::max(
            result.maximum_final_error_bound,
            assessment.final_error_bound);
        result.all_ciphertexts_are_size_two =
            result.all_ciphertexts_are_size_two &&
            input.ciphertext_is_size_two;
        result.all_correction_factors_are_one =
            result.all_correction_factors_are_one &&
            input.correction_factor_is_one;
        result.all_observed_finalizations_certified =
            result.all_observed_finalizations_certified &&
            assessment.certifies_observed_finalization();
    }
    result.all_observed_finalizations_certified =
        result.all_observed_finalizations_certified &&
        result.all_ciphertexts_are_size_two &&
        result.all_correction_factors_are_one;
    return result;
}

} // namespace laminate::packing
