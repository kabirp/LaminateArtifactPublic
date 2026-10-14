#ifndef LAMINATE_PROTOCOL_ANALYSIS_PACKING_PREREQUISITES_HPP
#define LAMINATE_PROTOCOL_ANALYSIS_PACKING_PREREQUISITES_HPP

/// @file packing_prerequisites.hpp
/// @brief Join the public noise envelope to the selected packing operator.

#include "laminate/packing/analysis/operator.hpp"
#include "laminate/protocol/analysis/packing_completeness.hpp"

#include <concepts>
#include <cstddef>
#include <cstdint>

namespace laminate::protocol {

inline constexpr const char *kPackingPrerequisiteCertificateScope =
    "ARITHMETIC_PREREQUISITES_ONLY_NO_SUCCINCT_BINDING";

/// Fail-closed setup assessment for the selected base-17 arithmetic.
///
/// This certificate joins facts that must describe the same public setup:
/// the challenge-independent prover noise envelope, the exact encoded-mask
/// weights, the one-prime modulus, and the transcript-bound test parameters.
/// The composed protocol supplies the relation proof and Fiat--Shamir
/// binding in addition to these arithmetic checks.
struct SelectedPackingPrerequisiteCertificate {
    packing::LazyTernaryParameters parameters;
    packing::PackingModulusCapacity modulus_capacity;
    packing::LazyTernaryCertificateAssessment interactive_theorem;

    std::size_t bhip_round_count = 0;
    std::size_t aligned_ciphertext_count = 0;
    std::size_t logical_packed_output_count = 0;
    std::size_t physical_packed_ciphertext_count = 0;
    std::uint64_t maximum_row_weight_upper = 0;

    bool selected_parameters_match = false;
    bool circuit_wide_noise_certificate = false;
    bool noise_certificate_passes = false;
    bool noise_cap_matches_parameters = false;
    bool one_prime_boundary = false;
    bool operator_radix_matches_parameters = false;
    bool envelope_shape_matches_operator = false;
    bool modulus_capacity_admits_selected_error = false;

    bool passes_arithmetic_prerequisites() const;
};

/// Join an already-computed exact operator analysis to a circuit-wide noise
/// envelope. Malformed analyses throw; valid but inadmissible setups return a
/// certificate whose named failed predicates explain the rejection.
SelectedPackingPrerequisiteCertificate
assess_selected_packing_prerequisites(
    const PackingNoiseEnvelopeResult &noise_envelope,
    const packing::SignedDigitPackingWeightAnalysis &operator_weights,
    const packing::LazyTernaryParameters &parameters =
        packing::selected_lazy_ternary_parameters());

template <typename Backend>
concept PackingPrerequisiteBackend =
    packing::SignedDigitPackingBackend<Backend> &&
    requires(const typename Backend::EvalContext &eval) {
        {
            Backend::lowest_coefficient_modulus(eval)
        } -> std::convertible_to<std::uint64_t>;
    };

/// Recompute the canonical full-capacity operator with the live backend's
/// plaintext encoder, then join it to the value-free noise envelope.
template <PackingPrerequisiteBackend Backend>
SelectedPackingPrerequisiteCertificate
certify_selected_packing_prerequisites(
    const typename Backend::EvalContext &eval,
    const PackingNoiseEnvelopeResult &noise_envelope);

} // namespace laminate::protocol

#include "laminate/protocol/analysis/detail/packing_prerequisites_impl.hpp"

#endif // LAMINATE_PROTOCOL_ANALYSIS_PACKING_PREREQUISITES_HPP
