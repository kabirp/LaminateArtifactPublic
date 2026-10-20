/// @file packing_prerequisites.cpp
/// @brief Fail-closed composition of transcript-packing prerequisites.

#include "laminate/protocol/analysis/packing_prerequisites.hpp"

#include <algorithm>
#include <limits>
#include <stdexcept>

namespace laminate::protocol {
namespace {

void validate_operator_weights(
    const packing::SignedDigitPackingWeightAnalysis &weights) {
    weights.radix.validate();
    const std::size_t digits = weights.radix.digit_count;
    if (weights.ring_degree == 0 ||
        weights.source_ciphertext_count == 0 ||
        weights.aligned_ciphertext_count == 0 ||
        weights.logical_output_count == 0 ||
        weights.maximum_digit_row_weight_upper == 0 ||
        weights.logical_output_count >
            std::numeric_limits<std::size_t>::max() / digits ||
        weights.rows.size() != weights.logical_output_count * digits) {
        throw std::invalid_argument(
            "packing prerequisites: malformed operator dimensions");
    }

    std::uint64_t maximum_weight = 0;
    for (std::size_t index = 0; index < weights.rows.size(); ++index) {
        const auto &row = weights.rows[index];
        if (row.output_index != index / digits ||
            row.digit_index != index % digits ||
            row.contribution_count == 0) {
            throw std::invalid_argument(
                "packing prerequisites: malformed operator row");
        }
        maximum_weight = std::max(
            maximum_weight, row.weight.conservative_integer_upper);
    }
    if (maximum_weight != weights.maximum_digit_row_weight_upper) {
        throw std::invalid_argument(
            "packing prerequisites: operator maximum is inconsistent");
    }
}

bool envelope_shape_matches(
    const PackingNoiseEnvelopeResult &envelope,
    const packing::SignedDigitPackingWeightAnalysis &weights) {
    return envelope.ring_degree == weights.ring_degree &&
           envelope.plaintext_modulus == weights.radix.plaintext_modulus &&
           envelope.bhip_round_count == weights.source_ciphertext_count &&
           envelope.certificate.round.ciphertext_count ==
               envelope.bhip_round_count &&
           envelope.certificate.aligned.ciphertext_count ==
               weights.aligned_ciphertext_count &&
           envelope.certificate.final.ciphertext_count ==
               weights.aligned_ciphertext_count &&
           envelope.logical_packed_output_count ==
               weights.logical_output_count;
}

} // namespace

bool SelectedPackingPrerequisiteCertificate::
    passes_arithmetic_prerequisites() const {
    return selected_parameters_match && circuit_wide_noise_certificate &&
           noise_certificate_passes && noise_cap_matches_parameters &&
           one_prime_boundary && operator_radix_matches_parameters &&
           envelope_shape_matches_operator &&
           modulus_capacity_admits_selected_error &&
           interactive_theorem.interactive_certificate_holds;
}

SelectedPackingPrerequisiteCertificate
assess_selected_packing_prerequisites(
    const PackingNoiseEnvelopeResult &noise_envelope,
    const packing::SignedDigitPackingWeightAnalysis &operator_weights,
    const packing::LazyTernaryParameters &parameters) {
    validate_operator_weights(operator_weights);
    parameters.packing_radix.validate();
    if (noise_envelope.packing_modulus < 3 ||
        noise_envelope.plaintext_modulus < 3 ||
        noise_envelope.ring_degree == 0 ||
        noise_envelope.bhip_round_count == 0 ||
        noise_envelope.logical_packed_output_count == 0) {
        throw std::invalid_argument(
            "packing prerequisites: malformed noise envelope identity");
    }

    const packing::PackingModulusCapacity capacity =
        packing::compute_packing_modulus_capacity(
            noise_envelope.packing_modulus,
            noise_envelope.plaintext_modulus,
            operator_weights.aligned_ciphertext_count,
            operator_weights.maximum_digit_row_weight_upper);
    const packing::LazyTernaryCertificateAssessment theorem =
        packing::assess_lazy_ternary_certificate(
            packing::LazyTernaryCertificateInputs{
                .packing_modulus = noise_envelope.packing_modulus,
                .plaintext_modulus = noise_envelope.plaintext_modulus,
                .honest_partial_decryption_bound =
                    parameters.honest_partial_decryption_bound(),
                .ring_degree = noise_envelope.ring_degree,
                .ciphertext_count =
                    operator_weights.aligned_ciphertext_count,
                .repetitions = parameters.repetitions,
                .maximum_row_weight_upper =
                    operator_weights.maximum_digit_row_weight_upper,
            });

    const bool selected_parameters =
        parameters == packing::selected_lazy_ternary_parameters();
    const bool cap_matches =
        noise_envelope.certificate.selected_final_error_cap ==
        parameters.honest_error_bound;
    const bool one_prime =
        noise_envelope.certificate.final.minimum_rns_limbs == 1 &&
        noise_envelope.certificate.final.maximum_rns_limbs == 1;
    const bool capacity_admits =
        capacity.admits_even_zero_error &&
        capacity.maximum_honest_error_bound >=
            parameters.honest_error_bound;

    return SelectedPackingPrerequisiteCertificate{
        .parameters = parameters,
        .modulus_capacity = capacity,
        .interactive_theorem = theorem,
        .bhip_round_count = operator_weights.source_ciphertext_count,
        .aligned_ciphertext_count =
            operator_weights.aligned_ciphertext_count,
        .logical_packed_output_count =
            operator_weights.logical_output_count,
        .physical_packed_ciphertext_count = operator_weights.rows.size(),
        .maximum_row_weight_upper =
            operator_weights.maximum_digit_row_weight_upper,
        .selected_parameters_match = selected_parameters,
        .circuit_wide_noise_certificate =
            noise_envelope.certificate.is_circuit_wide(),
        .noise_certificate_passes = noise_envelope.passes(),
        .noise_cap_matches_parameters = cap_matches,
        .one_prime_boundary = one_prime,
        .operator_radix_matches_parameters =
            operator_weights.radix == parameters.packing_radix,
        .envelope_shape_matches_operator =
            envelope_shape_matches(noise_envelope, operator_weights),
        .modulus_capacity_admits_selected_error = capacity_admits,
    };
}

} // namespace laminate::protocol
