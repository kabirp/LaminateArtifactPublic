#ifndef LAMINATE_PACKING_EVALUATION_PHASES_EVALUATE_HPP
#define LAMINATE_PACKING_EVALUATION_PHASES_EVALUATE_HPP

/// @file evaluate.hpp
/// @brief High-level prover and verifier lazy-ternary evaluation flow.

namespace laminate::packing {

template <SignedDigitPackingBackend Backend>
LazyTernaryEvaluation<Backend> evaluate_lazy_ternary(
    const typename Backend::EvalContext &eval,
    const NormalizedAlignedTranscript<Backend> &aligned,
    const LazyTernaryChallengeMatrix &public_challenges,
    LazyTernaryParameters parameters) {
    if (parameters.repetitions == 0 ||
        public_challenges.size() != parameters.repetitions) {
        throw std::invalid_argument(
            "evaluate_lazy_ternary: invalid repetition count");
    }
    lazy_ternary_detail::validate_aligned_transcript<Backend>(eval, aligned);
    parameters.packing_radix.validate();
    if (parameters.packing_radix.plaintext_modulus != kBaseFieldOrder) {
        throw std::invalid_argument(
            "evaluate_lazy_ternary: radix differs from the backend "
            "plaintext field");
    }
    for (const auto &row : public_challenges) {
        if (row.size() != aligned.values.size()) {
            throw std::invalid_argument(
                "evaluate_lazy_ternary: ragged challenge row");
        }
    }
    (void)parameters.honest_partial_decryption_bound();

    LazyTernaryEvaluation<Backend> result;
    result.parameters = parameters;
    result.public_challenges = public_challenges;
    result.logical_packed_outputs = aligned.layout.packed_ciphertext_count;

    // Phase 1: one revealed ternary linear test per challenge row.
    result.test_values.reserve(parameters.repetitions);
    for (const auto &challenges : result.public_challenges) {
        result.test_values.push_back(
            lazy_ternary_detail::form_test_value<Backend>(
                eval, aligned, challenges));
    }

    // Phase 2: fixed signed-digit linear forms for logical packed outputs.
    result.packed_digit_values =
        lazy_ternary_detail::form_signed_digit_values<Backend>(
            eval, aligned, parameters.packing_radix);
    return result;
}

template <PublicCoefficientEncodingBackend Backend, typename Context>
    requires PublicCoefficientVerifierContext<Backend, Context>
LazyTernaryEvaluation<Backend> evaluate_verifier_lazy_ternary(
    const Context &context,
    const NormalizedAlignedTranscript<Backend> &public_projection,
    const LazyTernaryChallengeMatrix &public_challenges,
    LazyTernaryParameters parameters) {
    if (parameters.repetitions == 0 ||
        public_challenges.size() != parameters.repetitions) {
        throw std::invalid_argument(
            "evaluate_verifier_lazy_ternary: invalid repetition count");
    }
    lazy_ternary_detail::validate_verifier_projection<Backend>(
        context, public_projection);
    parameters.packing_radix.validate();
    if (parameters.packing_radix.plaintext_modulus != kBaseFieldOrder) {
        throw std::invalid_argument(
            "evaluate_verifier_lazy_ternary: radix differs from the "
            "backend plaintext field");
    }
    for (const auto &row : public_challenges) {
        if (row.size() != public_projection.values.size()) {
            throw std::invalid_argument(
                "evaluate_verifier_lazy_ternary: ragged challenge row");
        }
    }
    (void)parameters.honest_partial_decryption_bound();

    LazyTernaryEvaluation<Backend> result;
    result.parameters = parameters;
    result.public_challenges = public_challenges;
    result.logical_packed_outputs =
        public_projection.layout.packed_ciphertext_count;
    result.test_values.reserve(parameters.repetitions);
    for (const auto &row : result.public_challenges) {
        result.test_values.push_back(
            lazy_ternary_detail::form_verifier_test_value<Backend>(
                public_projection, row));
    }
    result.packed_digit_values =
        lazy_ternary_detail::form_verifier_signed_digit_values<Backend>(
            context, public_projection, parameters.packing_radix);
    return result;
}

} // namespace laminate::packing

#endif // LAMINATE_PACKING_EVALUATION_PHASES_EVALUATE_HPP
