/// @file honest_base_proof_noise.cpp
/// @brief Pure Base proof-message normalization assessment.

#include "laminate/payload/noise/honest_base_proof_noise.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <utility>
#include <vector>

namespace laminate::payload {
namespace {

using fhe::HonestBaseNormalizationCoefficientRecord;
using fhe::HonestNoiseEnvelopeFailure;
using fhe::HonestNoiseEnvelopeOperation;
using fhe::HonestNoiseEnvelopeParameters;
using fhe::NaturalMagnitude;

struct ExpectedLayout {
    HonestBaseProofMessageTopology messages;
    std::uint64_t switch_events = 0;
};

struct ChainResult {
    std::vector<HonestBaseProofNoiseNormalizationStep> steps;
    NaturalMagnitude final_canonical_error_bound;
    bool all_phases_fit = true;
    std::optional<std::size_t> first_failed_step;
};

struct FamilyAccumulator {
    HonestBaseProofMessageFamilyAssessment assessment;
    HonestBaseProofMessageFamilyTopology expected;
    bool has_coefficient = false;
    bool topology_complete = true;
    bool all_messages_fit = true;
};

std::optional<std::size_t> checked_size_add(std::size_t left,
                                            std::size_t right) {
    if (right > std::numeric_limits<std::size_t>::max() - left) {
        return std::nullopt;
    }
    return left + right;
}

std::optional<std::uint64_t> checked_u64(std::size_t value) {
    if constexpr (sizeof(std::size_t) > sizeof(std::uint64_t)) {
        if (value > std::numeric_limits<std::uint64_t>::max()) {
            return std::nullopt;
        }
    }
    return static_cast<std::uint64_t>(value);
}

std::optional<std::uint64_t> checked_u64_add(std::uint64_t left,
                                             std::uint64_t right) {
    if (right > std::numeric_limits<std::uint64_t>::max() - left) {
        return std::nullopt;
    }
    return left + right;
}

std::optional<std::uint64_t> checked_u64_multiply(std::size_t left,
                                                  std::size_t right) {
    const auto converted_left = checked_u64(left);
    const auto converted_right = checked_u64(right);
    if (!converted_left || !converted_right ||
        (*converted_left != 0 &&
         *converted_right >
             std::numeric_limits<std::uint64_t>::max() / *converted_left)) {
        return std::nullopt;
    }
    return *converted_left * *converted_right;
}

std::optional<ExpectedLayout> make_expected_layout(
    const HonestBaseProofNormalizationLayerPlan &plan,
    std::size_t source_limbs) {
    ExpectedLayout result;
    try {
        result.messages =
            derive_honest_base_proof_message_topology(plan);
    } catch (const std::invalid_argument &) {
        return std::nullopt;
    } catch (const std::overflow_error &) {
        return std::nullopt;
    }
    if (source_limbs == 0) {
        return result;
    }
    const auto switches = checked_u64_multiply(
        result.messages.base_ciphertext_count, source_limbs - 1U);
    if (!switches) {
        return std::nullopt;
    }
    result.switch_events = *switches;
    return result;
}

std::optional<std::size_t> family_index_for_record(
    LayerKind kind, std::size_t record_index,
    const ExpectedLayout &layout) {
    const std::size_t total_extension_messages =
        layout.messages.round_extension_message_count +
        layout.messages.terminal_extension_message_count;
    if (record_index >= total_extension_messages) {
        return std::nullopt;
    }
    if (kind == LayerKind::Affine) {
        if (record_index < layout.messages.round_extension_message_count) {
            return record_index % 2U;
        }
        return 2U;
    }

    if (record_index < layout.messages.round_extension_message_count) {
        return record_index % 2U;
    }
    return 2U + record_index -
        layout.messages.round_extension_message_count;
}

std::uint64_t expected_message_coordinate_mask(
    const HonestBaseProofMessageFamilyTopology &family,
    std::size_t occurrence) {
    if (occurrence >= family.extension_message_count) {
        return 0;
    }
    return family.message_coordinate_masks.at(occurrence);
}

void update_maximum(NaturalMagnitude &maximum,
                    const NaturalMagnitude &candidate) {
    if (maximum < candidate) {
        maximum = candidate;
    }
}

std::span<const std::uint64_t> active_moduli(
    const HonestNoiseEnvelopeParameters &parameters, std::size_t limbs) {
    return std::span<const std::uint64_t>(parameters.data_moduli).first(limbs);
}

bool phase_fits(const HonestNoiseEnvelopeParameters &parameters,
                const NaturalMagnitude &canonical_error_bound,
                std::size_t limbs) {
    return fhe::honest_noise_fits_active_modulus(
        parameters.plaintext_modulus, canonical_error_bound,
        active_moduli(parameters, limbs));
}

ChainResult derive_chain(const HonestNoiseEnvelopeParameters &parameters,
                         const NaturalMagnitude &input,
                         std::size_t source_limbs) {
    ChainResult result;
    result.final_canonical_error_bound = input;
    result.steps.reserve(source_limbs - 1U);
    if (!phase_fits(parameters, input, source_limbs)) {
        result.all_phases_fit = false;
        result.first_failed_step = 0U;
    }

    for (std::size_t input_limbs = source_limbs; input_limbs > 1U;
         --input_limbs) {
        const std::size_t step_index = source_limbs - input_limbs;
        const std::uint64_t dropped =
            parameters.data_moduli[input_limbs - 1U];
        const NaturalMagnitude output = NaturalMagnitude::add(
            NaturalMagnitude::divide_ceil(
                result.final_canonical_error_bound, dropped),
            parameters.switch_rounding_error_bound);
        const NaturalMagnitude input_phase = fhe::honest_noise_phase_bound(
            parameters.plaintext_modulus,
            result.final_canonical_error_bound);
        const NaturalMagnitude output_phase = fhe::honest_noise_phase_bound(
            parameters.plaintext_modulus, output);
        const bool input_fits = phase_fits(
            parameters, result.final_canonical_error_bound, input_limbs);
        const bool output_fits =
            phase_fits(parameters, output, input_limbs - 1U);
        result.steps.push_back(HonestBaseProofNoiseNormalizationStep{
            .input_rns_limb_count = input_limbs,
            .output_rns_limb_count = input_limbs - 1U,
            .dropped_modulus = dropped,
            .input_canonical_error_bound =
                result.final_canonical_error_bound,
            .output_canonical_error_bound = output,
            .input_phase_bound = input_phase,
            .output_phase_bound = output_phase,
            .input_phase_fits = input_fits,
            .output_phase_fits = output_fits,
        });
        if ((!input_fits || !output_fits) &&
            !result.first_failed_step.has_value()) {
            result.first_failed_step = step_index;
        }
        result.all_phases_fit =
            result.all_phases_fit && input_fits && output_fits;
        result.final_canonical_error_bound = output;
    }
    return result;
}

std::optional<HonestNoiseEnvelopeFailure> expected_normalization_failure(
    const HonestNoiseEnvelopeParameters &parameters,
    const ChainResult &chain) {
    for (std::size_t step_index = 0; step_index < chain.steps.size();
         ++step_index) {
        const HonestBaseProofNoiseNormalizationStep &step =
            chain.steps[step_index];
        if (!step.input_phase_fits) {
            // This state was already created before the current switch, so a
            // missing input failure cannot be repaired by normalization.
            return std::nullopt;
        }
        if (!step.output_phase_fits) {
            return HonestNoiseEnvelopeFailure{
                .operation = HonestNoiseEnvelopeOperation::ModulusSwitch,
                .operation_sequence = 0,
                .input_rns_limbs = step.input_rns_limb_count,
                .output_rns_limbs = step.output_rns_limb_count,
                .canonical_error_bound =
                    step.output_canonical_error_bound,
                .active_modulus_product_bits =
                    NaturalMagnitude::product(active_moduli(
                        parameters, step.output_rns_limb_count))
                        .bit_count(),
            };
        }
    }
    return std::nullopt;
}

bool matches_expected_failure(
    const HonestNoiseEnvelopeFailure &observed,
    const HonestNoiseEnvelopeFailure &expected) {
    return observed.operation_sequence != 0 &&
           observed.operation == expected.operation &&
           observed.input_rns_limbs == expected.input_rns_limbs &&
           observed.output_rns_limbs == expected.output_rns_limbs &&
           observed.canonical_error_bound ==
               expected.canonical_error_bound &&
           observed.active_modulus_product_bits ==
               expected.active_modulus_product_bits;
}

struct CoefficientCheck {
    ChainResult chain;
    bool topology_complete = true;
    bool all_phases_fit = true;
    bool has_failure = false;
    bool output_failure_is_normalization_step = false;
    std::size_t first_failed_step = 0;
};

CoefficientCheck check_coefficient(
    const HonestNoiseEnvelopeParameters &parameters,
    const HonestBaseNormalizationCoefficientRecord &coefficient,
    std::size_t source_limbs) {
    CoefficientCheck result{
        .chain = derive_chain(parameters,
                              coefficient.input_canonical_error_bound,
                              source_limbs),
    };
    const bool input_bound_is_live =
        !coefficient.input_canonical_error_bound.is_zero();
    const bool output_bound_is_live =
        !coefficient.output_canonical_error_bound.is_zero();
    const bool levels_match =
        coefficient.input_rns_limbs == source_limbs &&
        coefficient.output_rns_limbs == 1U;
    const bool components_match =
        coefficient.input_component_count == 2U &&
        coefficient.output_component_count == 2U;
    const bool identities_match =
        coefficient.input_identity != 0 &&
        coefficient.output_identity != 0 &&
        (source_limbs == 1U
             ? coefficient.input_identity == coefficient.output_identity
             : coefficient.input_identity != coefficient.output_identity);
    const bool final_bound_matches =
        coefficient.output_canonical_error_bound ==
        result.chain.final_canonical_error_bound;
    result.topology_complete = input_bound_is_live && output_bound_is_live &&
                               levels_match && components_match &&
                               identities_match && final_bound_matches;

    const bool input_fits = phase_fits(
        parameters, coefficient.input_canonical_error_bound, source_limbs);
    const bool output_fits = phase_fits(
        parameters, coefficient.output_canonical_error_bound, 1U);
    result.all_phases_fit =
        input_fits && output_fits && result.chain.all_phases_fit;

    if (coefficient.input_first_failure) {
        result.has_failure = true;
        result.first_failed_step = 0U;
        if (coefficient.input_first_failure->operation_sequence == 0 ||
            !coefficient.output_first_failure ||
            *coefficient.output_first_failure !=
                *coefficient.input_first_failure) {
            result.topology_complete = false;
        }
        return result;
    }

    if (!input_fits) {
        // The input ciphertext was created before normalization. Its first
        // failed phase check must therefore already be sticky in the record.
        result.topology_complete = false;
        result.has_failure = true;
        result.first_failed_step = 0U;
        return result;
    }

    const auto expected_failure =
        expected_normalization_failure(parameters, result.chain);
    if (expected_failure) {
        result.has_failure = true;
        result.first_failed_step =
            result.chain.first_failed_step.value_or(0U);
        if (!coefficient.output_first_failure ||
            !matches_expected_failure(*coefficient.output_first_failure,
                                      *expected_failure)) {
            result.topology_complete = false;
        } else {
            result.output_failure_is_normalization_step = true;
        }
    } else if (coefficient.output_first_failure) {
        result.has_failure = true;
        result.first_failed_step = 0U;
        result.topology_complete = false;
    }
    return result;
}

struct FailureCandidate {
    std::uint64_t operation_sequence = 0;
    HonestBaseProofNoiseFailure location;
};

void consider_failure(
    std::optional<FailureCandidate> &first,
    const HonestNoiseEnvelopeFailure &failure,
    std::size_t reduction_layer, HonestBaseProofMessageFamily family,
    std::size_t message_occurrence, std::size_t coefficient_index,
    HonestBaseProofNoiseFailureStage stage,
    std::optional<std::size_t> normalization_step) {
    if (failure.operation_sequence == 0 ||
        (first && first->operation_sequence <= failure.operation_sequence)) {
        return;
    }
    first = FailureCandidate{
        .operation_sequence = failure.operation_sequence,
        .location = HonestBaseProofNoiseFailure{
            .reduction_layer = reduction_layer,
            .family = family,
            .message_occurrence = message_occurrence,
            .coefficient_index = coefficient_index,
            .stage = stage,
            .normalization_step = normalization_step,
        },
    };
}

} // namespace

HonestBaseProofReductionNoiseAssessment
aggregate_honest_base_proof_normalization_records(
    const HonestBaseProofNormalizationLayerPlan &normalization_plan,
    const HonestNoiseEnvelopeParameters &parameters, LayerKind kind,
    std::span<const fhe::HonestBaseNormalizationRecord> records) {
    parameters.validate();

    HonestBaseProofReductionNoiseAssessment result{
        .reduction_layer = normalization_plan.reduction_layer,
        .kind = kind,
        .natural_source_rns_limb_count =
            normalization_plan.natural_source_rns_limb_count,
        .proof_ingress_rns_limb_count =
            normalization_plan.proof_ingress_rns_limb_count,
        .live_source_ciphertext_count =
            normalization_plan.live_source_ciphertext_count,
        .source_rns_limb_count =
            normalization_plan.proof_ingress_rns_limb_count,
        .wire_variables = normalization_plan.wire_variables,
        .expected_extension_message_count = 0,
        .observed_extension_message_count = records.size(),
        .ingress_switch_events = normalization_plan.ingress_switch_events,
        .expected_proof_message_switch_events =
            normalization_plan.proof_message_switch_events,
        .observed_proof_message_switch_events = 0,
        .expected_switch_events = normalization_plan.switch_events,
        .observed_switch_events = 0,
        .topology_complete = false,
        .all_messages_fit = false,
    };

    const auto expected = make_expected_layout(
        normalization_plan,
        normalization_plan.proof_ingress_rns_limb_count);
    if (!expected) {
        return result;
    }
    result.expected_extension_message_count =
        expected->messages.round_extension_message_count +
        expected->messages.terminal_extension_message_count;

    std::vector<FamilyAccumulator> families;
    families.reserve(expected->messages.families.size());
    for (const HonestBaseProofMessageFamilyTopology &family :
         expected->messages.families) {
        families.push_back(FamilyAccumulator{
            .assessment = HonestBaseProofMessageFamilyAssessment{
                .family = family.family,
                .extension_message_count = 0,
                .base_ciphertext_count = 0,
                .source_rns_limb_count =
                    normalization_plan.proof_ingress_rns_limb_count,
                .all_pre_normalization_phases_fit = true,
                .all_post_normalization_phases_fit = true,
            },
            .expected = family,
        });
    }

    bool topology_complete =
        normalization_plan.kind == kind &&
        normalization_plan.natural_source_rns_limb_count != 0 &&
        normalization_plan.proof_ingress_rns_limb_count != 0 &&
        normalization_plan.proof_ingress_rns_limb_count <=
            normalization_plan.natural_source_rns_limb_count &&
        normalization_plan.natural_source_rns_limb_count <=
            parameters.data_moduli.size() &&
        normalization_plan.round_extension_ciphertext_count ==
            expected->messages.round_extension_message_count &&
        normalization_plan.terminal_extension_ciphertext_count ==
            expected->messages.terminal_extension_message_count &&
        normalization_plan.public_zero_extension_message_count ==
            expected->messages.public_zero_extension_message_count &&
        normalization_plan.base_ciphertext_count ==
            expected->messages.base_ciphertext_count &&
        normalization_plan.proof_message_switch_events ==
            expected->switch_events &&
        normalization_plan.switch_events ==
            normalization_plan.ingress_switch_events +
                normalization_plan.proof_message_switch_events &&
        records.size() == result.expected_extension_message_count;
    bool all_messages_fit = true;
    std::optional<FailureCandidate> first_failure;
    std::optional<std::uint64_t> observed_switch_events = std::uint64_t{0};

    for (std::size_t record_index = 0; record_index < records.size();
         ++record_index) {
        const auto family_index = family_index_for_record(
            kind, record_index, *expected);
        if (!family_index || *family_index >= families.size()) {
            topology_complete = false;
        }

        std::uint64_t observed_coordinate_mask = 0;
        const std::size_t message_occurrence =
            family_index && *family_index < families.size()
                ? families[*family_index]
                      .assessment.extension_message_count
                : 0U;
        for (std::size_t coefficient_index = 0;
             coefficient_index < kExtensionDegree; ++coefficient_index) {
            const HonestBaseNormalizationCoefficientRecord &coefficient =
                records[record_index].coefficients[coefficient_index];
            if (!coefficient.present) {
                if (!(coefficient ==
                      HonestBaseNormalizationCoefficientRecord{})) {
                    topology_complete = false;
                }
                continue;
            }
            observed_coordinate_mask |=
                std::uint64_t{1} << coefficient_index;
            if (coefficient.input_rns_limbs <
                coefficient.output_rns_limbs) {
                topology_complete = false;
                observed_switch_events = std::nullopt;
            } else if (observed_switch_events) {
                const auto delta = checked_u64(
                    coefficient.input_rns_limbs -
                    coefficient.output_rns_limbs);
                if (!delta) {
                    observed_switch_events = std::nullopt;
                } else {
                    observed_switch_events = checked_u64_add(
                        *observed_switch_events, *delta);
                }
            }

            if (!family_index || *family_index >= families.size() ||
                normalization_plan.proof_ingress_rns_limb_count == 0 ||
                normalization_plan.proof_ingress_rns_limb_count >
                    parameters.data_moduli.size()) {
                continue;
            }
            FamilyAccumulator &family = families[*family_index];
            family.has_coefficient = true;
            HonestBaseProofMessageFamilyAssessment &summary =
                family.assessment;
            const auto updated_base_ciphertexts = checked_size_add(
                summary.base_ciphertext_count, 1U);
            if (!updated_base_ciphertexts) {
                family.topology_complete = false;
                summary.base_ciphertext_count =
                    std::numeric_limits<std::size_t>::max();
            } else {
                summary.base_ciphertext_count =
                    *updated_base_ciphertexts;
            }
            update_maximum(
                summary.maximum_pre_normalization_canonical_error_bound,
                coefficient.input_canonical_error_bound);
            update_maximum(
                summary.maximum_pre_normalization_phase_bound,
                fhe::honest_noise_phase_bound(
                    parameters.plaintext_modulus,
                    coefficient.input_canonical_error_bound));
            update_maximum(
                summary.maximum_post_normalization_canonical_error_bound,
                coefficient.output_canonical_error_bound);
            update_maximum(
                summary.maximum_post_normalization_phase_bound,
                fhe::honest_noise_phase_bound(
                    parameters.plaintext_modulus,
                    coefficient.output_canonical_error_bound));

            const CoefficientCheck checked = check_coefficient(
                parameters, coefficient,
                normalization_plan.proof_ingress_rns_limb_count);
            family.topology_complete =
                family.topology_complete && checked.topology_complete;
            family.assessment.all_pre_normalization_phases_fit =
                family.assessment.all_pre_normalization_phases_fit &&
                phase_fits(parameters,
                           coefficient.input_canonical_error_bound,
                           normalization_plan.proof_ingress_rns_limb_count);
            family.assessment.all_post_normalization_phases_fit =
                family.assessment.all_post_normalization_phases_fit &&
                phase_fits(parameters,
                           coefficient.output_canonical_error_bound, 1U);
            family.all_messages_fit =
                family.all_messages_fit && checked.all_phases_fit &&
                !checked.has_failure;
            if (coefficient.input_first_failure) {
                consider_failure(
                    first_failure, *coefficient.input_first_failure,
                    normalization_plan.reduction_layer,
                    family.assessment.family, message_occurrence,
                    coefficient_index,
                    HonestBaseProofNoiseFailureStage::PreNormalization,
                    std::nullopt);
            }
            const bool repeated_sticky_failure =
                coefficient.input_first_failure &&
                coefficient.output_first_failure &&
                *coefficient.input_first_failure ==
                    *coefficient.output_first_failure;
            if (coefficient.output_first_failure &&
                !repeated_sticky_failure) {
                const bool at_normalization_step =
                    checked.output_failure_is_normalization_step;
                consider_failure(
                    first_failure, *coefficient.output_first_failure,
                    normalization_plan.reduction_layer,
                    family.assessment.family, message_occurrence,
                    coefficient_index,
                    at_normalization_step
                        ? HonestBaseProofNoiseFailureStage::NormalizationStep
                        : HonestBaseProofNoiseFailureStage::PostNormalization,
                    at_normalization_step
                        ? std::optional<std::size_t>(
                              checked.first_failed_step)
                        : std::nullopt);
            }
        }
        if (family_index && *family_index < families.size()) {
            FamilyAccumulator &family = families[*family_index];
            const std::uint64_t planned_coordinate_mask =
                expected_message_coordinate_mask(
                    family.expected, message_occurrence);
            if ((observed_coordinate_mask & ~planned_coordinate_mask) != 0) {
                family.topology_complete = false;
            }
            ++family.assessment.extension_message_count;
        }
    }

    result.observed_proof_message_switch_events =
        observed_switch_events.value_or(
            std::numeric_limits<std::uint64_t>::max());
    if (!observed_switch_events ||
        *observed_switch_events >
            normalization_plan.proof_message_switch_events) {
        topology_complete = false;
    }
    if (observed_switch_events) {
        const auto total = checked_u64_add(
            normalization_plan.ingress_switch_events,
            *observed_switch_events);
        result.observed_switch_events = total.value_or(
            std::numeric_limits<std::uint64_t>::max());
        if (!total || *total > normalization_plan.switch_events) {
            topology_complete = false;
        }
    } else {
        result.observed_switch_events =
            std::numeric_limits<std::uint64_t>::max();
    }

    for (FamilyAccumulator &family : families) {
        if (family.assessment.extension_message_count !=
                family.expected.extension_message_count ||
            family.assessment.base_ciphertext_count >
                family.expected.base_ciphertext_count) {
            family.topology_complete = false;
        }

        if (family.has_coefficient) {
            ChainResult maximum_chain = derive_chain(
                parameters,
                family.assessment
                    .maximum_pre_normalization_canonical_error_bound,
                normalization_plan.proof_ingress_rns_limb_count);
            const NaturalMagnitude expected_pre_phase =
                fhe::honest_noise_phase_bound(
                    parameters.plaintext_modulus,
                    family.assessment
                        .maximum_pre_normalization_canonical_error_bound);
            const NaturalMagnitude expected_post_phase =
                fhe::honest_noise_phase_bound(
                    parameters.plaintext_modulus,
                    family.assessment
                        .maximum_post_normalization_canonical_error_bound);
            if (maximum_chain.final_canonical_error_bound !=
                family.assessment
                    .maximum_post_normalization_canonical_error_bound ||
                family.assessment.maximum_pre_normalization_phase_bound !=
                    expected_pre_phase ||
                family.assessment.maximum_post_normalization_phase_bound !=
                    expected_post_phase) {
                family.topology_complete = false;
            }
            family.all_messages_fit =
                family.all_messages_fit && maximum_chain.all_phases_fit;
            family.assessment.normalization_steps =
                std::move(maximum_chain.steps);
        }

        topology_complete =
            topology_complete && family.topology_complete;
        all_messages_fit =
            all_messages_fit && family.all_messages_fit &&
            family.assessment.all_pre_normalization_phases_fit &&
            family.assessment.all_post_normalization_phases_fit;
        result.families.push_back(std::move(family.assessment));
    }

    if (first_failure) {
        result.first_failure = first_failure->location;
    }
    result.topology_complete = topology_complete;
    result.all_messages_fit = topology_complete && all_messages_fit &&
                              !result.first_failure.has_value();
    return result;
}

} // namespace laminate::payload
