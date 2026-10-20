#ifndef LAMINATE_PACKING_ANALYSIS_HONEST_FINALIZATION_HPP
#define LAMINATE_PACKING_ANALYSIS_HONEST_FINALIZATION_HPP

/// @file honest_finalization.hpp
/// @brief Exact modulus-switch bounds for honest packing inputs.
///
/// This module starts from one client-secret invariant-noise measurement and
/// proves the remaining one- or two-prime finalization schedule.  It does not
/// predict the noise created by the encrypted GKR prover.  Consequently an
/// observed assessment is useful completeness evidence for one execution,
/// but is not the missing setup-time operation-by-operation certificate.

#include "laminate/params.hpp"

#include <concepts>
#include <cstddef>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <vector>

namespace laminate::packing {

/// Public policy selected for the one-prime packing boundary.
struct HonestFinalizationPolicy {
    std::uint64_t plaintext_modulus = kBaseFieldOrder;
    /// Public upper bound on the ternary secret's Hamming weight.  The
    /// unconditional target uses `h <= N`, never a sampled secret-key norm.
    std::uint64_t secret_hamming_weight_upper =
        kDefaultPolyModulusDegree;
    std::uint64_t target_error_bound =
        kSelectedPackingHonestErrorBound;
    /// Deliberately reserved from `target_error_bound` before admitting any
    /// inherited error.  At target N this is N+2.
    std::uint64_t final_rounding_reserve =
        kPackingFinalRoundingErrorBound;
};

/// Exact bit-length evidence exposed by SEAL's invariant-noise diagnostic.
///
/// If the input modulus has bit length `q_bits` and SEAL reports budget `b`,
/// its implementation gives
///
///   bit_length(||c(s)||_infinity) = q_bits - b - 1.
///
/// A zero budget is retained as rejecting evidence rather than silently
/// treating the ciphertext as decryptable.
struct ObservedInvariantNoiseEvidence {
    std::size_t invariant_noise_budget_bits = 0;
};

/// One application of SEAL's BGV mod-t-and-divide switch.
struct ModulusSwitchBound {
    std::size_t input_limb_count = 0;
    std::uint64_t dropped_modulus = 0;
    std::size_t input_partial_decryption_norm_bit_count = 0;
    std::uint64_t input_error_bound = 0;
    std::uint64_t scaled_inherited_error_bound = 0;
    std::uint64_t output_error_bound = 0;
    /// Reporting fields above saturate at u64; the recurrence itself continues
    /// in 128-bit arithmetic when one of these flags is false.
    bool input_error_bound_fits_u64 = false;
    bool scaled_inherited_error_bound_fits_u64 = false;
    bool output_error_bound_fits_u64 = false;
    bool arithmetic_supported = false;
    bool pre_switch_no_wrap = false;
};

/// Fail-closed assessment of the complete finalization chain.
struct ObservedHonestFinalizationAssessment {
    std::size_t input_modulus_bit_count = 0;
    std::size_t observed_invariant_noise_budget_bits = 0;
    std::size_t minimum_required_invariant_noise_budget_bits = 0;
    std::uint64_t proven_per_switch_rounding_bound = 0;
    std::uint64_t selected_final_rounding_reserve = 0;
    std::uint64_t selected_scaled_inherited_allowance = 0;
    std::uint64_t final_scaled_inherited_error_bound = 0;
    std::uint64_t final_error_bound = 0;
    std::vector<ModulusSwitchBound> switches;
    bool input_noise_budget_positive = false;
    bool arithmetic_supported = false;
    bool rounding_reserve_is_sufficient = false;
    bool all_switches_no_wrap = false;
    bool inherited_error_fits_selected_allowance = false;
    bool final_error_fits_target = false;
    bool target_decryption_no_wrap = false;

    bool certifies_observed_finalization() const;
};

/// Assess the final one or two modulus switches.
///
/// `data_moduli_low_to_high` is `[q_0,q_1]` or `[q_0,q_1,q_2]`, where q_0 is
/// the retained packing prime and SEAL drops primes from the back.  The
/// assessment uses
///
///   beta' <= ceil(beta/q_l) + h + 1
///
/// and checks `P/q_l + t(1+h) < Q_retained/2` before every switch.  Arithmetic
/// is exact and integer-only; unsupported bounds reject rather than wrapping.
ObservedHonestFinalizationAssessment assess_observed_honest_finalization(
    const HonestFinalizationPolicy &policy,
    std::span<const std::uint64_t> data_moduli_low_to_high,
    const ObservedInvariantNoiseEvidence &evidence);

/// Aggregate of the same client-secret diagnostic over an aligned list.
struct ObservedHonestFinalizationBatchAssessment {
    std::size_t ciphertext_count = 0;
    std::size_t minimum_observed_invariant_noise_budget_bits = 0;
    std::size_t maximum_required_invariant_noise_budget_bits = 0;
    std::int64_t minimum_budget_slack_bits = 0;
    std::size_t worst_ciphertext_index = 0;
    std::uint64_t maximum_final_scaled_inherited_error_bound = 0;
    std::uint64_t maximum_final_error_bound = 0;
    bool all_ciphertexts_are_size_two = false;
    bool all_correction_factors_are_one = false;
    bool all_observed_finalizations_certified = false;
};

/// Backend-neutral observation for one post-alignment ciphertext.
struct ObservedHonestFinalizationInput {
    std::vector<std::uint64_t> data_moduli_low_to_high;
    std::size_t invariant_noise_budget_bits = 0;
    bool ciphertext_is_size_two = false;
    bool correction_factor_is_one = false;
};

ObservedHonestFinalizationBatchAssessment
assess_observed_honest_finalization_batch(
    const HonestFinalizationPolicy &policy,
    std::span<const ObservedHonestFinalizationInput> inputs);

template <typename Backend>
concept ObservedFinalizationBackend =
    requires(const typename Backend::EvalContext &eval,
             const typename Backend::ClientContext &client,
             const typename Backend::Ciphertext &ciphertext) {
        { ciphertext.size() } -> std::convertible_to<std::size_t>;
        { Backend::invariant_noise_budget(client, ciphertext) } ->
            std::convertible_to<int>;
        { Backend::data_coefficient_moduli(eval, ciphertext) } ->
            std::same_as<std::vector<std::uint64_t>>;
        { Backend::correction_factor_is_one(ciphertext) } ->
            std::convertible_to<bool>;
    };

/// Measure the post-alignment, pre-switch list and prove the remaining
/// finalization recurrence for every ciphertext.  The secret-key measurement
/// is deliberately kept outside `EvalContext` and outside server timings.
template <ObservedFinalizationBackend Backend>
ObservedHonestFinalizationBatchAssessment
assess_observed_honest_finalization_batch(
    const typename Backend::EvalContext &eval,
    const typename Backend::ClientContext &client,
    std::span<const typename Backend::Ciphertext> aligned_ciphertexts,
    const HonestFinalizationPolicy &policy) {
    if (aligned_ciphertexts.empty()) {
        throw std::invalid_argument(
            "honest finalization batch: ciphertext list is empty");
    }

    std::vector<ObservedHonestFinalizationInput> inputs;
    inputs.reserve(aligned_ciphertexts.size());
    for (std::size_t index = 0; index < aligned_ciphertexts.size(); ++index) {
        const auto &ciphertext = aligned_ciphertexts[index];
        const int measured_budget =
            Backend::invariant_noise_budget(client, ciphertext);
        if (measured_budget < 0) {
            throw std::logic_error(
                "honest finalization batch: backend returned negative "
                "invariant-noise budget");
        }
        inputs.push_back(ObservedHonestFinalizationInput{
            .data_moduli_low_to_high =
                Backend::data_coefficient_moduli(eval, ciphertext),
            .invariant_noise_budget_bits =
                static_cast<std::size_t>(measured_budget),
            .ciphertext_is_size_two = ciphertext.size() == 2,
            .correction_factor_is_one =
                Backend::correction_factor_is_one(ciphertext),
        });
    }
    return assess_observed_honest_finalization_batch(policy, inputs);
}

} // namespace laminate::packing

#endif // LAMINATE_PACKING_ANALYSIS_HONEST_FINALIZATION_HPP
