/// @file modulus_switch_policy.cpp
/// @brief Exact-integer implementation of the BGV switch-tax planner.

#include "laminate/fhe/noise/modulus_switch_policy.hpp"

#include <stdexcept>

namespace laminate::fhe {
namespace {

bool at_most(const NaturalMagnitude &left,
             const NaturalMagnitude &right) {
    return !(right < left);
}

std::size_t ceiling_log2_ratio(const NaturalMagnitude &numerator,
                               const NaturalMagnitude &denominator) {
    if (at_most(numerator, denominator)) {
        return 0;
    }
    std::size_t bits = numerator.bit_count() > denominator.bit_count()
                           ? numerator.bit_count() - denominator.bit_count()
                           : 0;
    if (NaturalMagnitude::shift_left(denominator, bits) < numerator) {
        ++bits;
    }
    return bits;
}

} // namespace

void ModulusSwitchTaxPolicy::validate() const {
    if (maximum_budget_tax_bits > 4096) {
        throw std::invalid_argument(
            "modulus-switch policy: tax target exceeds supported range");
    }
}

ModulusSwitchTaxPlan plan_modulus_switch_to_next(
    const DeterministicNoisePolicy &noise_policy,
    const DeterministicNoiseBound &input,
    std::size_t ciphertext_component_count,
    std::span<const std::uint64_t> active_moduli_low_to_high,
    ModulusSwitchTaxPolicy planning_policy) {
    planning_policy.validate();
    noise_policy.validate();

    DeterministicModulusSwitchTransition transition =
        derive_modulus_switch_transition(
            noise_policy, input, ciphertext_component_count,
            active_moduli_low_to_high);
    NaturalMagnitude numerator = NaturalMagnitude::multiply(
        transition.output_bound.partial_decryption_bound,
        transition.dropped_modulus);
    const NaturalMagnitude denominator = input.partial_decryption_bound;

    ModulusSwitchTaxPlan result{
        .policy = planning_policy,
        .transition = std::move(transition),
        .tax_ratio_numerator = std::move(numerator),
        .tax_ratio_denominator = denominator,
    };
    if (!result.transition.output_bound.certifies_no_wrap()) {
        result.decision =
            ModulusSwitchTaxDecision::RejectUncertifiedTransition;
        return result;
    }
    if (denominator.is_zero()) {
        result.decision = ModulusSwitchTaxDecision::RetainForUndefinedTax;
        return result;
    }

    result.tax_ceiling_bits = ceiling_log2_ratio(
        result.tax_ratio_numerator, result.tax_ratio_denominator);
    const NaturalMagnitude allowed = NaturalMagnitude::shift_left(
        result.tax_ratio_denominator,
        planning_policy.maximum_budget_tax_bits);
    result.tax_within_target =
        at_most(result.tax_ratio_numerator, allowed);

    if (result.tax_within_target) {
        result.decision = ModulusSwitchTaxDecision::SwitchNow;
    } else {
        result.decision = ModulusSwitchTaxDecision::RetainForTax;
    }
    return result;
}

} // namespace laminate::fhe
