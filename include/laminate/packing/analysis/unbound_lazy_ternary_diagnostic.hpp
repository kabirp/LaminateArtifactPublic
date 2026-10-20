#ifndef LAMINATE_PACKING_ANALYSIS_UNBOUND_LAZY_TERNARY_DIAGNOSTIC_HPP
#define LAMINATE_PACKING_ANALYSIS_UNBOUND_LAZY_TERNARY_DIAGNOSTIC_HPP

/// @file unbound_lazy_ternary_diagnostic.hpp
/// @brief Explicitly unbound completeness and noise measurements.
///
/// These helpers exercise the lazy-ternary FHE calculation without the outer
/// linear-relation proof. They are diagnostics, not a sound proof protocol.

#include "laminate/packing/evaluation/lazy_ternary.hpp"

#include <algorithm>

namespace laminate::packing {

inline constexpr const char *kUnboundLazyTernaryDiagnosticSecurity =
    "UNSOUND_NO_OUTER_LINEAR_RELATION_PROOF";

/// Secret-key measurements from one diagnostic execution.
struct ObservedLazyTernaryDiagnostics {
    std::uint64_t configured_input_bound = 0;
    std::uint64_t observed_max_input_norm = 0;
    std::uint64_t configured_test_threshold = 0;
    std::uint64_t observed_max_test_norm = 0;
    std::uint64_t observed_max_packed_norm = 0;
    std::size_t present_test_ciphertexts = 0;
    std::size_t accepted_tests = 0;
    bool observed_inputs_within_configured_bound = false;
    bool all_tests_within_configured_threshold = false;
};

/// Derive challenges from the aligned-coordinate digest and evaluate the
/// unbound relation. Production protocols instead bind ordered GKR
/// commitments and prove the resulting linear relation.
template <SignedDigitPackingBackend Backend>
LazyTernaryEvaluation<Backend> run_unbound_lazy_ternary_diagnostic(
    const typename Backend::EvalContext &eval,
    const NormalizedAlignedTranscript<Backend> &aligned,
    Transcript &transcript,
    LazyTernaryParameters parameters = {}) {
    if (parameters.repetitions == 0) {
        throw std::invalid_argument(
            "run_unbound_lazy_ternary_diagnostic: repetitions must be "
            "nonzero");
    }
    lazy_ternary_detail::validate_aligned_transcript<Backend>(eval, aligned);
    if (!aligned.ciphertext_list_digest) {
        throw std::invalid_argument(
            "run_unbound_lazy_ternary_diagnostic: aligned-list digest is "
            "missing");
    }

    parameters.packing_radix.validate();
    if (parameters.packing_radix.plaintext_modulus != kBaseFieldOrder) {
        throw std::invalid_argument(
            "run_unbound_lazy_ternary_diagnostic: radix modulus differs "
            "from the backend plaintext field");
    }
    (void)parameters.honest_partial_decryption_bound();

    transcript.observe("laminate/packing/aligned-list-digest/v1",
                       *aligned.ciphertext_list_digest);
    lazy_ternary_detail::observe_parameters(transcript, parameters);
    const LazyTernaryChallengeMatrix challenges =
        derive_lazy_ternary_challenges(
            transcript, parameters.repetitions, aligned.values.size());
    return evaluate_lazy_ternary<Backend>(
        eval, aligned, challenges, parameters);
}

namespace lazy_ternary_diagnostic_detail {

template <PublicCoefficientEncodingBackend Backend>
std::uint64_t maximum_aligned_partial_decryption_norm(
    const typename Backend::ClientContext &client,
    const NormalizedAlignedTranscript<Backend> &aligned) {
    std::uint64_t maximum = 0;
    for (std::size_t index = 0; index < aligned.values.size(); ++index) {
        const fhe::FheValue<Backend> &value = aligned.values[index];
        if (value.is_public()) {
            if (value.is_public_zero() || !aligned.public_sources[index]) {
                continue;
            }
            const auto coordinates =
                normalized_aligned_coordinates(aligned, index);
            maximum = std::max(
                maximum,
                Backend::partial_decryption_with_public_ntt_offset_infinity_norm(
                    client, nullptr,
                    coordinates.first(aligned.layout.slot_count)));
            continue;
        }
        maximum = std::max(
            maximum,
            static_cast<std::uint64_t>(
                Backend::partial_decryption_infinity_norm(
                    client, value.ciphertext())));
    }
    return maximum;
}

} // namespace lazy_ternary_diagnostic_detail

/// Apply the exact client partial-decryption predicate to one diagnostic run.
template <PublicCoefficientEncodingBackend Backend>
ObservedLazyTernaryDiagnostics assess_observed_lazy_ternary_diagnostic(
    const typename Backend::ClientContext &client,
    const NormalizedAlignedTranscript<Backend> &aligned,
    const LazyTernaryEvaluation<Backend> &evaluation) {
    evaluation.parameters.packing_radix.validate();
    if (aligned.values.empty() || evaluation.parameters.repetitions == 0 ||
        evaluation.public_challenges.size() !=
            evaluation.parameters.repetitions ||
        evaluation.test_values.size() != evaluation.parameters.repetitions ||
        evaluation.logical_packed_outputs !=
            aligned.layout.packed_ciphertext_count ||
        evaluation.packed_digit_values.size() !=
            evaluation.logical_packed_outputs *
                evaluation.parameters.packing_radix.digit_count) {
        throw std::invalid_argument(
            "assess_observed_lazy_ternary_diagnostic: malformed evaluation");
    }

    ObservedLazyTernaryDiagnostics result;
    result.configured_input_bound =
        evaluation.parameters.honest_partial_decryption_bound();
    result.observed_max_input_norm =
        lazy_ternary_diagnostic_detail::
            maximum_aligned_partial_decryption_norm<Backend>(client,
                                                               aligned);
    result.observed_inputs_within_configured_bound =
        result.observed_max_input_norm <= result.configured_input_bound;
    result.configured_test_threshold = lazy_ternary_test_threshold(
        result.configured_input_bound, aligned.values.size());

    for (const auto &test_value : evaluation.test_values) {
        if (test_value.encrypted_contribution) {
            ++result.present_test_ciphertexts;
        }
        const std::uint64_t norm =
            Backend::partial_decryption_with_public_ntt_offset_infinity_norm(
                client,
                test_value.encrypted_contribution
                    ? &*test_value.encrypted_contribution
                    : nullptr,
                test_value.public_c0_coordinates);
        result.observed_max_test_norm =
            std::max(result.observed_max_test_norm, norm);
        if (norm <= result.configured_test_threshold) {
            ++result.accepted_tests;
        }
    }
    for (const auto &packed_value : evaluation.packed_digit_values) {
        result.observed_max_packed_norm = std::max(
            result.observed_max_packed_norm,
            Backend::partial_decryption_with_public_ntt_offset_infinity_norm(
                client,
                packed_value.encrypted_contribution
                    ? &*packed_value.encrypted_contribution
                    : nullptr,
                packed_value.public_c0_coordinates));
    }
    result.all_tests_within_configured_threshold =
        result.accepted_tests == evaluation.parameters.repetitions;
    return result;
}

} // namespace laminate::packing

#endif // LAMINATE_PACKING_ANALYSIS_UNBOUND_LAZY_TERNARY_DIAGNOSTIC_HPP
