#ifndef LAMINATE_PACKING_ANALYSIS_DETERMINISTIC_COMPLETENESS_IMPL_HPP
#define LAMINATE_PACKING_ANALYSIS_DETERMINISTIC_COMPLETENESS_IMPL_HPP

/// @file deterministic_completeness_impl.hpp
/// @brief Small assessment steps for hard transcript-packing completeness.

#include <algorithm>
#include <limits>
#include <stdexcept>
#include <type_traits>
#include <utility>

namespace laminate::packing::deterministic_completeness_detail {

template <typename Ciphertext>
const fhe::DeterministicNoiseBound *bound_of(
    const Ciphertext &ciphertext) {
    if constexpr (requires {
                      ciphertext.deterministic_noise_bound.has_value();
                  }) {
        return ciphertext.deterministic_noise_bound
                   ? &*ciphertext.deterministic_noise_bound
                   : nullptr;
    } else {
        return &ciphertext.deterministic_noise_bound;
    }
}

template <CoefficientWellFormednessBackend Backend>
DeterministicNoiseStageCertificate assess_stage(
    const typename Backend::EvalContext &eval,
    std::span<const typename Backend::Ciphertext> ciphertexts,
    const fhe::DeterministicNoisePolicy &policy) {
    DeterministicNoiseStageCertificate result;
    result.ciphertext_count = ciphertexts.size();
    result.minimum_rns_limbs =
        std::numeric_limits<std::size_t>::max();
    for (std::size_t index = 0; index < ciphertexts.size(); ++index) {
        const std::size_t limbs =
            Backend::rns_limb_count(eval, ciphertexts[index]);
        result.minimum_rns_limbs =
            std::min(result.minimum_rns_limbs, limbs);
        result.maximum_rns_limbs =
            std::max(result.maximum_rns_limbs, limbs);

        const fhe::DeterministicNoiseBound *bound =
            bound_of(ciphertexts[index]);
        if (bound == nullptr) {
            continue;
        }
        ++result.tracked_ciphertexts;
        result.maximum_partial_decryption_bits = std::max(
            result.maximum_partial_decryption_bits,
            bound->partial_decryption_bound.bit_count());
        result.maximum_canonical_error_bits = std::max(
            result.maximum_canonical_error_bits,
            fhe::canonical_error_bound(
                policy, bound->partial_decryption_bound)
                .bit_count());
        result.maximum_operation_count = std::max(
            result.maximum_operation_count, bound->operation_count);
        if (bound->certifies_no_wrap()) {
            ++result.no_wrap_ciphertexts;
            continue;
        }
        if (!result.first_failure) {
            result.first_failure =
                DeterministicNoiseStageCertificate::Failure{
                    .ciphertext_index = index,
                    .operation = bound->first_failure->operation,
                    .reason = bound->first_failure->reason,
                };
        }
    }
    if (ciphertexts.empty()) {
        result.minimum_rns_limbs = 0;
    }
    return result;
}

template <typename Ciphertext>
std::optional<fhe::NaturalMagnitude> maximum_error(
    std::span<const Ciphertext> ciphertexts,
    const fhe::DeterministicNoisePolicy &policy) {
    fhe::NaturalMagnitude result;
    for (const Ciphertext &ciphertext : ciphertexts) {
        const fhe::DeterministicNoiseBound *bound = bound_of(ciphertext);
        if (bound == nullptr) {
            return std::nullopt;
        }
        const fhe::NaturalMagnitude candidate =
            fhe::canonical_error_bound(
                policy, bound->partial_decryption_bound);
        if (result < candidate) {
            result = candidate;
        }
    }
    return result;
}

} // namespace laminate::packing::deterministic_completeness_detail

namespace laminate::packing {

template <CoefficientWellFormednessBackend Backend>
DeterministicNoiseStageCertificate assess_deterministic_noise_stage(
    const typename Backend::EvalContext &eval,
    std::span<const typename Backend::Ciphertext> ciphertexts,
    const fhe::DeterministicNoisePolicy &policy) {
    policy.validate();
    return deterministic_completeness_detail::assess_stage<Backend>(
        eval, ciphertexts, policy);
}

template <CoefficientWellFormednessBackend Backend>
DeterministicPackingCompletenessCertificate
certify_deterministic_packing_completeness(
    const typename Backend::EvalContext &eval,
    std::span<const typename Backend::Ciphertext> round_ciphertexts,
    const PackingLayout &layout,
    const fhe::DeterministicNoisePolicy &policy,
    std::uint64_t selected_final_error_cap,
    DeterministicPackingCertificateScope scope) {
    policy.validate();
    if (round_ciphertexts.empty() || selected_final_error_cap == 0) {
        throw std::invalid_argument(
            "deterministic completeness: empty round ciphertext list or zero cap");
    }
    if (scope == DeterministicPackingCertificateScope::
                     ChallengeIndependentEnvelope &&
        !fhe::forces_challenge_independent_topology<Backend>(eval)) {
        throw std::invalid_argument(
            "deterministic completeness: backend is not a topology envelope");
    }

    DeterministicPackingCompletenessCertificate result;
    result.scope = scope;
    result.selected_final_error_cap = selected_final_error_cap;
    result.round = assess_deterministic_noise_stage<Backend>(
        eval, round_ciphertexts, policy);

    AlignedTranscriptDraft<Backend> draft =
        materialize_aligned_transcript<Backend>(eval, round_ciphertexts,
                                                layout);
    std::vector<typename Backend::Ciphertext> aligned_ciphertexts;
    aligned_ciphertexts.reserve(draft.values.size());
    for (const fhe::FheValue<Backend> &value : draft.values) {
        if (!value.is_encrypted()) {
            throw std::logic_error(
                "deterministic completeness: encrypted input became public");
        }
        aligned_ciphertexts.push_back(value.ciphertext());
    }
    result.aligned = assess_deterministic_noise_stage<Backend>(
        eval, aligned_ciphertexts, policy);

    const NormalizedAlignedTranscript<Backend> final =
        finalize_aligned_transcript<Backend>(eval, std::move(draft));
    std::vector<typename Backend::Ciphertext> final_ciphertexts;
    final_ciphertexts.reserve(final.values.size());
    for (const fhe::FheValue<Backend> &value : final.values) {
        if (!value.is_encrypted()) {
            throw std::logic_error(
                "deterministic completeness: encrypted input became public");
        }
        final_ciphertexts.push_back(value.ciphertext());
    }
    result.final = assess_deterministic_noise_stage<Backend>(
        eval, final_ciphertexts, policy);
    result.maximum_final_error =
        deterministic_completeness_detail::maximum_error(
            std::span<const typename Backend::Ciphertext>(
                final_ciphertexts),
            policy);
    result.final_error_fits_selected_cap =
        result.maximum_final_error.has_value() &&
        !(fhe::NaturalMagnitude(selected_final_error_cap) <
          *result.maximum_final_error);
    return result;
}

template <CoefficientWellFormednessBackend Backend>
DeterministicPackingCompletenessCertificate
certify_deterministic_packing_completeness(
    const typename Backend::EvalContext &eval,
    std::span<const fhe::FheValue<Backend>> round_values,
    const PackingLayout &layout,
    const fhe::DeterministicNoisePolicy &policy,
    std::uint64_t selected_final_error_cap,
    DeterministicPackingCertificateScope scope) {
    policy.validate();
    if (round_values.empty() || selected_final_error_cap == 0) {
        throw std::invalid_argument(
            "deterministic completeness: empty round value list or zero cap");
    }
    if (scope == DeterministicPackingCertificateScope::
                     ChallengeIndependentEnvelope &&
        !fhe::forces_challenge_independent_topology<Backend>(eval)) {
        throw std::invalid_argument(
            "deterministic completeness: backend is not a topology envelope");
    }
    const auto encrypted_values = [](const auto &values) {
        std::vector<typename Backend::Ciphertext> encrypted;
        encrypted.reserve(values.size());
        for (const auto &value : values) {
            if (value.is_encrypted()) {
                encrypted.push_back(value.ciphertext());
            }
        }
        return encrypted;
    };

    const std::vector<typename Backend::Ciphertext> round_ciphertexts =
        encrypted_values(round_values);
    if (round_ciphertexts.empty()) {
        throw std::invalid_argument(
            "deterministic completeness: proof has no encrypted value to "
            "certify");
    }

    DeterministicPackingCompletenessCertificate result;
    result.scope = scope;
    result.selected_final_error_cap = selected_final_error_cap;
    result.round = assess_deterministic_noise_stage<Backend>(
        eval, round_ciphertexts, policy);

    AlignedTranscriptDraft<Backend> draft =
        materialize_aligned_transcript<Backend>(eval, round_values, layout);
    const std::vector<typename Backend::Ciphertext> aligned_ciphertexts =
        encrypted_values(draft.values);
    result.aligned = assess_deterministic_noise_stage<Backend>(
        eval, aligned_ciphertexts, policy);

    const NormalizedAlignedTranscript<Backend> final =
        finalize_aligned_transcript<Backend>(eval, std::move(draft));
    const std::vector<typename Backend::Ciphertext> final_ciphertexts =
        encrypted_values(final.values);
    result.final = assess_deterministic_noise_stage<Backend>(
        eval, final_ciphertexts, policy);
    result.maximum_final_error =
        deterministic_completeness_detail::maximum_error(
            std::span<const typename Backend::Ciphertext>(
                final_ciphertexts),
            policy);
    result.final_error_fits_selected_cap =
        result.maximum_final_error.has_value() &&
        !(fhe::NaturalMagnitude(selected_final_error_cap) <
          *result.maximum_final_error);
    return result;
}

} // namespace laminate::packing

#endif // LAMINATE_PACKING_ANALYSIS_DETERMINISTIC_COMPLETENESS_IMPL_HPP
