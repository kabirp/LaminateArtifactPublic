#ifndef LAMINATE_PROTOCOL_ANALYSIS_DETAIL_PACKING_PREREQUISITES_IMPL_HPP
#define LAMINATE_PROTOCOL_ANALYSIS_DETAIL_PACKING_PREREQUISITES_IMPL_HPP

/// @file packing_prerequisites_impl.hpp
/// @brief Exact-backend adapter for selected packing setup admission.

#include "laminate/fhe/layout/fixed_message.hpp"

#include <stdexcept>

namespace laminate::protocol {

template <PackingPrerequisiteBackend Backend>
SelectedPackingPrerequisiteCertificate
certify_selected_packing_prerequisites(
    const typename Backend::EvalContext &eval,
    const PackingNoiseEnvelopeResult &noise_envelope) {
    // Step 1: reject a certificate imported from a different live context.
    if (Backend::slot_count(eval) != noise_envelope.ring_degree ||
        Backend::lowest_coefficient_modulus(eval) !=
            noise_envelope.packing_modulus) {
        throw std::invalid_argument(
            "packing prerequisites: live context differs from envelope");
    }

    // Step 2: reconstruct the one-or-few-output two-row placement schedule.
    const packing::PackingLayout layout =
        packing::make_fixed_message_coset_packing_layout(
            Backend::slot_count(eval), noise_envelope.bhip_round_count,
            Backend::slot_count(eval) / fhe::kFixedMessageCellCount);
    const packing::PackingLinearOperator packing_operator =
        packing::make_packing_linear_operator(layout);

    // Step 3: measure the exact base-17 coefficient masks used on this setup.
    const packing::LazyTernaryParameters parameters =
        packing::selected_lazy_ternary_parameters();
    const packing::SignedDigitPackingWeightAnalysis weights =
        packing::analyze_signed_digit_packing_weights(
            packing_operator,
            [&](const fhe::SlotVector &mask) {
                return Backend::encode_centered_plaintext_coefficients(
                    eval, mask);
            },
            parameters.packing_radix);

    // Step 4: join noise, geometry, modulus, and theorem inequalities.
    return assess_selected_packing_prerequisites(
        noise_envelope, weights, parameters);
}

} // namespace laminate::protocol

#endif // LAMINATE_PROTOCOL_ANALYSIS_DETAIL_PACKING_PREREQUISITES_IMPL_HPP
