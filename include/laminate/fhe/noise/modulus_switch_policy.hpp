#ifndef LAMINATE_FHE_NOISE_MODULUS_SWITCH_POLICY_HPP
#define LAMINATE_FHE_NOISE_MODULUS_SWITCH_POLICY_HPP

/// @file modulus_switch_policy.hpp
/// @brief Optional BGV level-drop planning, separate from correctness.

#include "laminate/fhe/noise/deterministic.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace laminate::fhe {

inline constexpr std::size_t kDefaultMaximumModulusSwitchTaxBits = 10;

/// Tunable performance preference; not a completeness assumption.
struct ModulusSwitchTaxPolicy {
    std::size_t maximum_budget_tax_bits =
        kDefaultMaximumModulusSwitchTaxBits;

    void validate() const;
};

enum class ModulusSwitchTaxDecision : std::uint8_t {
    SwitchNow,
    RetainForTax,
    RejectUncertifiedTransition,
    RetainForUndefinedTax,
};

/// Auditable plan for one optional computational level drop.
///
/// For coefficient-phase bound P, output bound P', and dropped prime q, the
/// continuous budget loss is exactly log2(q*P'/P). The whole-bit decision is
/// made by exact big-integer cross multiplication.
struct ModulusSwitchTaxPlan {
    ModulusSwitchTaxPolicy policy;
    DeterministicModulusSwitchTransition transition;
    NaturalMagnitude tax_ratio_numerator;
    NaturalMagnitude tax_ratio_denominator;
    std::optional<std::size_t> tax_ceiling_bits;
    bool tax_within_target = false;
    ModulusSwitchTaxDecision decision =
        ModulusSwitchTaxDecision::RejectUncertifiedTransition;

    bool should_switch() const {
        return decision == ModulusSwitchTaxDecision::SwitchNow;
    }
};

/// Plan one optional computational drop of the final active data prime.
///
/// Required alignment and protocol-boundary switches must call
/// the exact transition (directly or through `bound_modulus_switch`) and be
/// judged by their downstream completeness obligations. They bypass this
/// tax preference.
ModulusSwitchTaxPlan plan_modulus_switch_to_next(
    const DeterministicNoisePolicy &noise_policy,
    const DeterministicNoiseBound &input,
    std::size_t ciphertext_component_count,
    std::span<const std::uint64_t> active_moduli_low_to_high,
    ModulusSwitchTaxPolicy planning_policy = {});

} // namespace laminate::fhe

#endif // LAMINATE_FHE_NOISE_MODULUS_SWITCH_POLICY_HPP
