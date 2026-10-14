/// @file honest_base_proof_noise_binding.cpp
/// @brief Canonical binding and exact re-validation of Base noise reports.

#include "laminate/payload/noise/honest_base_proof_noise.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace laminate::payload {
namespace {

using Bytes = std::vector<std::uint8_t>;

constexpr std::size_t kMaximumDecodedReductions = 1U << 12U;
constexpr std::size_t kMaximumDecodedFamiliesPerReduction = 64;
constexpr std::size_t kMaximumDecodedNormalizationSteps = 1U << 12U;
constexpr std::size_t kMaximumDecodedMagnitudeBytes = 1U << 20U;

void append_u64(Bytes &output, std::uint64_t value) {
    for (std::size_t byte = 0; byte < 8; ++byte) {
        output.push_back(static_cast<std::uint8_t>(
            (value >> (8U * byte)) & std::uint64_t{0xff}));
    }
}

void append_size(Bytes &output, std::size_t value) {
    if constexpr (sizeof(std::size_t) > sizeof(std::uint64_t)) {
        if (value > std::numeric_limits<std::uint64_t>::max()) {
            throw std::overflow_error(
                "Base proof-noise encoding: size does not fit u64");
        }
    }
    append_u64(output, static_cast<std::uint64_t>(value));
}

void append_bool(Bytes &output, bool value) {
    output.push_back(value ? std::uint8_t{1} : std::uint8_t{0});
}

void append_label(Bytes &output, std::string_view label) {
    append_size(output, label.size());
    output.insert(output.end(), label.begin(), label.end());
}

void append_digest(Bytes &output, const Digest &digest) {
    output.insert(output.end(), digest.begin(), digest.end());
}

class AssessmentReader {
  public:
    explicit AssessmentReader(std::span<const std::uint8_t> input)
        : input_(input) {}

    std::uint8_t byte(const char *description) {
        require(1, description);
        return input_[position_++];
    }

    bool boolean(const char *description) {
        const std::uint8_t value = byte(description);
        if (value > 1) {
            throw std::invalid_argument(std::string(description) +
                                        " is not Boolean");
        }
        return value != 0;
    }

    std::uint64_t u64(const char *description) {
        require(8, description);
        std::uint64_t result = 0;
        for (std::size_t byte_index = 0; byte_index < 8; ++byte_index) {
            result |= static_cast<std::uint64_t>(
                          input_[position_ + byte_index])
                      << (8U * byte_index);
        }
        position_ += 8;
        return result;
    }

    std::size_t size(std::size_t maximum, const char *description) {
        const std::uint64_t value = u64(description);
        if (value > maximum ||
            value > std::numeric_limits<std::size_t>::max()) {
            throw std::invalid_argument(std::string(description) +
                                        " exceeds its decode limit");
        }
        return static_cast<std::size_t>(value);
    }

    Digest digest(const char *description) {
        require(Digest{}.size(), description);
        Digest result{};
        std::copy_n(input_.begin() +
                        static_cast<std::ptrdiff_t>(position_),
                    result.size(), result.begin());
        position_ += result.size();
        return result;
    }

    void label(std::string_view expected, const char *description) {
        const std::size_t count = size(256, description);
        require(count, description);
        const std::span<const std::uint8_t> selected =
            input_.subspan(position_, count);
        if (selected.size() != expected.size() ||
            !std::equal(selected.begin(), selected.end(), expected.begin())) {
            throw std::invalid_argument(std::string(description) +
                                        " is unsupported");
        }
        position_ += count;
    }

    fhe::NaturalMagnitude magnitude(const char *description) {
        const std::size_t count =
            size(kMaximumDecodedMagnitudeBytes, description);
        require(count, description);
        const auto encoded = input_.subspan(position_, count);
        position_ += count;
        return fhe::decode_canonical_natural_magnitude(encoded);
    }

    void finish() const {
        if (position_ != input_.size()) {
            throw std::invalid_argument(
                "Base proof-noise assessment has trailing data");
        }
    }

  private:
    void require(std::size_t count, const char *description) const {
        if (count > input_.size() -
                        std::min(position_, input_.size())) {
            throw std::invalid_argument(std::string(description) +
                                        " is truncated");
        }
    }

    std::span<const std::uint8_t> input_;
    std::size_t position_ = 0;
};

HonestBaseProofNoiseFailure read_failure(AssessmentReader &reader) {
    HonestBaseProofNoiseFailure result;
    result.reduction_layer = reader.size(
        kMaximumDecodedReductions, "proof-noise failure layer");
    const std::uint8_t family = reader.byte("proof-noise failure family");
    if (family > static_cast<std::uint8_t>(
                     HonestBaseProofMessageFamily::
                         MultiplicationRightTerminal)) {
        throw std::invalid_argument(
            "proof-noise failure family is invalid");
    }
    result.family = static_cast<HonestBaseProofMessageFamily>(family);
    result.message_occurrence = reader.size(
        std::numeric_limits<std::size_t>::max(),
        "proof-noise failure occurrence");
    result.coefficient_index = reader.size(
        kExtensionDegree, "proof-noise failure coefficient");
    const std::uint8_t stage = reader.byte("proof-noise failure stage");
    if (stage > static_cast<std::uint8_t>(
                    HonestBaseProofNoiseFailureStage::PostNormalization)) {
        throw std::invalid_argument(
            "proof-noise failure stage is invalid");
    }
    result.stage = static_cast<HonestBaseProofNoiseFailureStage>(stage);
    if (reader.boolean("proof-noise failure step presence")) {
        result.normalization_step = reader.size(
            kMaximumDecodedNormalizationSteps,
            "proof-noise failure normalization step");
    }
    return result;
}

std::optional<HonestBaseProofNoiseFailure>
read_optional_failure(AssessmentReader &reader) {
    if (!reader.boolean("proof-noise failure presence")) {
        return std::nullopt;
    }
    return read_failure(reader);
}

HonestBaseProofNoiseNormalizationStep
read_normalization_step(AssessmentReader &reader) {
    HonestBaseProofNoiseNormalizationStep result;
    result.input_rns_limb_count = reader.size(
        kMaximumDecodedNormalizationSteps, "normalization input limbs");
    result.output_rns_limb_count = reader.size(
        kMaximumDecodedNormalizationSteps, "normalization output limbs");
    result.dropped_modulus = reader.u64("normalization dropped modulus");
    result.input_canonical_error_bound =
        reader.magnitude("normalization input canonical bound");
    result.output_canonical_error_bound =
        reader.magnitude("normalization output canonical bound");
    result.input_phase_bound =
        reader.magnitude("normalization input phase bound");
    result.output_phase_bound =
        reader.magnitude("normalization output phase bound");
    result.input_phase_fits =
        reader.boolean("normalization input fit");
    result.output_phase_fits =
        reader.boolean("normalization output fit");
    return result;
}

HonestBaseProofMessageFamilyAssessment read_family(
    AssessmentReader &reader) {
    HonestBaseProofMessageFamilyAssessment result;
    const std::uint8_t family = reader.byte("proof-noise family");
    if (family > static_cast<std::uint8_t>(
                     HonestBaseProofMessageFamily::
                         MultiplicationRightTerminal)) {
        throw std::invalid_argument("proof-noise family is invalid");
    }
    result.family = static_cast<HonestBaseProofMessageFamily>(family);
    result.extension_message_count = reader.size(
        std::numeric_limits<std::size_t>::max(),
        "proof-noise extension message count");
    result.base_ciphertext_count = reader.size(
        std::numeric_limits<std::size_t>::max(),
        "proof-noise base ciphertext count");
    result.source_rns_limb_count = reader.size(
        kMaximumDecodedNormalizationSteps, "proof-noise source limbs");
    result.maximum_pre_normalization_canonical_error_bound =
        reader.magnitude("proof-noise pre-normalization canonical bound");
    result.maximum_pre_normalization_phase_bound =
        reader.magnitude("proof-noise pre-normalization phase bound");
    result.all_pre_normalization_phases_fit =
        reader.boolean("proof-noise pre-normalization fit");
    const std::size_t step_count = reader.size(
        kMaximumDecodedNormalizationSteps,
        "proof-noise normalization step count");
    result.normalization_steps.reserve(step_count);
    for (std::size_t index = 0; index < step_count; ++index) {
        result.normalization_steps.push_back(
            read_normalization_step(reader));
    }
    result.maximum_post_normalization_canonical_error_bound =
        reader.magnitude("proof-noise post-normalization canonical bound");
    result.maximum_post_normalization_phase_bound =
        reader.magnitude("proof-noise post-normalization phase bound");
    result.all_post_normalization_phases_fit =
        reader.boolean("proof-noise post-normalization fit");
    return result;
}

HonestBaseProofReductionNoiseAssessment read_reduction(
    AssessmentReader &reader) {
    HonestBaseProofReductionNoiseAssessment result;
    result.reduction_layer = reader.size(
        kMaximumDecodedReductions, "proof-noise reduction layer");
    const std::uint8_t kind = reader.byte("proof-noise reduction kind");
    if (kind > static_cast<std::uint8_t>(LayerKind::Multiplication)) {
        throw std::invalid_argument("proof-noise layer kind is invalid");
    }
    result.kind = static_cast<LayerKind>(kind);
    result.natural_source_rns_limb_count = reader.size(
        kMaximumDecodedNormalizationSteps, "proof-noise natural limbs");
    result.proof_ingress_rns_limb_count = reader.size(
        kMaximumDecodedNormalizationSteps, "proof-noise ingress limbs");
    result.live_source_ciphertext_count = reader.size(
        std::numeric_limits<std::size_t>::max(),
        "proof-noise live source count");
    result.natural_source_canonical_error_bound =
        reader.magnitude("proof-noise natural source bound");
    result.proof_ingress_canonical_error_bound =
        reader.magnitude("proof-noise ingress bound");
    result.ingress_input_phase_fits =
        reader.boolean("proof-noise ingress input fit");
    const std::size_t ingress_steps = reader.size(
        kMaximumDecodedNormalizationSteps,
        "proof-noise ingress normalization count");
    result.ingress_normalization_steps.reserve(ingress_steps);
    for (std::size_t index = 0; index < ingress_steps; ++index) {
        result.ingress_normalization_steps.push_back(
            read_normalization_step(reader));
    }
    if (reader.boolean("proof-noise failed ingress step presence")) {
        result.first_failed_ingress_step = reader.size(
            kMaximumDecodedNormalizationSteps,
            "proof-noise failed ingress step");
    }
    result.all_ingress_phases_fit =
        reader.boolean("proof-noise ingress fit");
    result.source_rns_limb_count = reader.size(
        kMaximumDecodedNormalizationSteps, "proof-noise source limbs");
    result.wire_variables = reader.size(
        1U << 20U, "proof-noise wire variables");
    const std::size_t family_count = reader.size(
        kMaximumDecodedFamiliesPerReduction,
        "proof-noise family count");
    result.families.reserve(family_count);
    for (std::size_t index = 0; index < family_count; ++index) {
        result.families.push_back(read_family(reader));
    }
    result.expected_extension_message_count = reader.size(
        std::numeric_limits<std::size_t>::max(),
        "proof-noise expected extension count");
    result.observed_extension_message_count = reader.size(
        std::numeric_limits<std::size_t>::max(),
        "proof-noise observed extension count");
    result.ingress_switch_events =
        reader.u64("proof-noise ingress switch events");
    result.expected_proof_message_switch_events =
        reader.u64("proof-noise expected message switch events");
    result.observed_proof_message_switch_events =
        reader.u64("proof-noise observed message switch events");
    result.expected_switch_events =
        reader.u64("proof-noise expected switch events");
    result.observed_switch_events =
        reader.u64("proof-noise observed switch events");
    result.first_failure = read_optional_failure(reader);
    result.topology_complete =
        reader.boolean("proof-noise topology complete");
    result.all_messages_fit =
        reader.boolean("proof-noise all messages fit");
    return result;
}

void append_magnitude(Bytes &output, const fhe::NaturalMagnitude &value) {
    const Bytes encoded = fhe::encode_canonical(value);
    append_size(output, encoded.size());
    output.insert(output.end(), encoded.begin(), encoded.end());
}

void append_failure(
    Bytes &output,
    const std::optional<HonestBaseProofNoiseFailure> &failure) {
    append_bool(output, failure.has_value());
    if (!failure) {
        return;
    }
    append_size(output, failure->reduction_layer);
    output.push_back(static_cast<std::uint8_t>(failure->family));
    append_size(output, failure->message_occurrence);
    append_size(output, failure->coefficient_index);
    output.push_back(static_cast<std::uint8_t>(failure->stage));
    append_bool(output, failure->normalization_step.has_value());
    if (failure->normalization_step) {
        append_size(output, *failure->normalization_step);
    }
}

void append_normalization_step(
    Bytes &output,
    const HonestBaseProofNoiseNormalizationStep &step) {
    append_size(output, step.input_rns_limb_count);
    append_size(output, step.output_rns_limb_count);
    append_u64(output, step.dropped_modulus);
    append_magnitude(output, step.input_canonical_error_bound);
    append_magnitude(output, step.output_canonical_error_bound);
    append_magnitude(output, step.input_phase_bound);
    append_magnitude(output, step.output_phase_bound);
    append_bool(output, step.input_phase_fits);
    append_bool(output, step.output_phase_fits);
}

void append_family(
    Bytes &output,
    const HonestBaseProofMessageFamilyAssessment &family) {
    output.push_back(static_cast<std::uint8_t>(family.family));
    append_size(output, family.extension_message_count);
    append_size(output, family.base_ciphertext_count);
    append_size(output, family.source_rns_limb_count);
    append_magnitude(
        output, family.maximum_pre_normalization_canonical_error_bound);
    append_magnitude(output,
                     family.maximum_pre_normalization_phase_bound);
    append_bool(output, family.all_pre_normalization_phases_fit);
    append_size(output, family.normalization_steps.size());
    for (const HonestBaseProofNoiseNormalizationStep &step :
         family.normalization_steps) {
        append_normalization_step(output, step);
    }
    append_magnitude(
        output, family.maximum_post_normalization_canonical_error_bound);
    append_magnitude(output,
                     family.maximum_post_normalization_phase_bound);
    append_bool(output, family.all_post_normalization_phases_fit);
}

void append_reduction(
    Bytes &output,
    const HonestBaseProofReductionNoiseAssessment &reduction) {
    append_size(output, reduction.reduction_layer);
    output.push_back(static_cast<std::uint8_t>(reduction.kind));
    append_size(output, reduction.natural_source_rns_limb_count);
    append_size(output, reduction.proof_ingress_rns_limb_count);
    append_size(output, reduction.live_source_ciphertext_count);
    append_magnitude(output,
                     reduction.natural_source_canonical_error_bound);
    append_magnitude(output,
                     reduction.proof_ingress_canonical_error_bound);
    append_bool(output, reduction.ingress_input_phase_fits);
    append_size(output, reduction.ingress_normalization_steps.size());
    for (const HonestBaseProofNoiseNormalizationStep &step :
         reduction.ingress_normalization_steps) {
        append_normalization_step(output, step);
    }
    append_bool(output, reduction.first_failed_ingress_step.has_value());
    if (reduction.first_failed_ingress_step) {
        append_size(output, *reduction.first_failed_ingress_step);
    }
    append_bool(output, reduction.all_ingress_phases_fit);
    append_size(output, reduction.source_rns_limb_count);
    append_size(output, reduction.wire_variables);
    append_size(output, reduction.families.size());
    for (const HonestBaseProofMessageFamilyAssessment &family :
         reduction.families) {
        append_family(output, family);
    }
    append_size(output, reduction.expected_extension_message_count);
    append_size(output, reduction.observed_extension_message_count);
    append_u64(output, reduction.ingress_switch_events);
    append_u64(output, reduction.expected_proof_message_switch_events);
    append_u64(output, reduction.observed_proof_message_switch_events);
    append_u64(output, reduction.expected_switch_events);
    append_u64(output, reduction.observed_switch_events);
    append_failure(output, reduction.first_failure);
    append_bool(output, reduction.topology_complete);
    append_bool(output, reduction.all_messages_fit);
}

bool digest_is_zero(const Digest &digest) {
    return std::all_of(digest.begin(), digest.end(),
                       [](std::uint8_t value) { return value == 0; });
}

std::uint64_t checked_add_u64(std::uint64_t left, std::uint64_t right,
                              const char *description) {
    if (right > std::numeric_limits<std::uint64_t>::max() - left) {
        throw std::overflow_error(description);
    }
    return left + right;
}

std::size_t checked_add_size(std::size_t left, std::size_t right,
                             const char *description) {
    if (right > std::numeric_limits<std::size_t>::max() - left) {
        throw std::overflow_error(description);
    }
    return left + right;
}

std::uint64_t checked_multiply_size(std::size_t left, std::size_t right,
                                    const char *description) {
    if constexpr (sizeof(std::size_t) > sizeof(std::uint64_t)) {
        if (left > std::numeric_limits<std::uint64_t>::max() ||
            right > std::numeric_limits<std::uint64_t>::max()) {
            throw std::overflow_error(description);
        }
    }
    const std::uint64_t converted_left =
        static_cast<std::uint64_t>(left);
    const std::uint64_t converted_right =
        static_cast<std::uint64_t>(right);
    if (converted_left != 0 &&
        converted_right >
            std::numeric_limits<std::uint64_t>::max() / converted_left) {
        throw std::overflow_error(description);
    }
    return converted_left * converted_right;
}

fhe::NaturalMagnitude natural_source_bound(
    const LayeredCircuit &circuit,
    const HonestPayloadNoiseSchedule &schedule,
    std::size_t source_layer) {
    if (source_layer + 1U == circuit.layers.size()) {
        return fhe::NaturalMagnitude(
            schedule.calibration.fresh_canonical_error_bound);
    }
    const auto found = std::find_if(
        schedule.layers_in_evaluation_order.begin(),
        schedule.layers_in_evaluation_order.end(),
        [&](const HonestPayloadLayerSchedule &layer) {
            return layer.layer == source_layer;
        });
    if (found == schedule.layers_in_evaluation_order.end()) {
        throw std::invalid_argument(
            "Base proof-noise natural source envelope is absent");
    }
    return found->output_canonical_error_bound;
}

bool phase_fits(const HonestPayloadNoiseSchedule &schedule,
                const fhe::NaturalMagnitude &bound,
                std::size_t limbs) {
    if (limbs == 0 || limbs > schedule.data_moduli_low_to_high.size()) {
        return false;
    }
    return fhe::honest_noise_fits_active_modulus(
        kBaseFieldOrder, bound,
        std::span<const std::uint64_t>(schedule.data_moduli_low_to_high)
            .first(limbs));
}

void validate_ingress_binding(
    const LayeredCircuit &circuit,
    const HonestPayloadNoiseSchedule &schedule,
    const HonestBaseProofNormalizationLayerPlan &plan,
    const HonestBaseProofReductionNoiseAssessment &reduction) {
    const std::size_t source_layer = plan.reduction_layer + 1U;
    const fhe::NaturalMagnitude natural =
        natural_source_bound(circuit, schedule, source_layer);
    const std::size_t expected_steps =
        plan.natural_source_rns_limb_count -
        plan.proof_ingress_rns_limb_count;
    const std::size_t stored_values =
        canonical_layer_storage_layout(circuit, source_layer)
            .stored_wire_count;
    if (reduction.natural_source_canonical_error_bound != natural ||
        reduction.ingress_normalization_steps.size() != expected_steps ||
        reduction.live_source_ciphertext_count !=
            plan.live_source_ciphertext_count ||
        plan.live_source_ciphertext_count > stored_values) {
        throw std::invalid_argument(
            "Base proof-noise ingress source differs from the plan");
    }

    fhe::NaturalMagnitude current = natural;
    bool input_fits = phase_fits(
        schedule, current, plan.natural_source_rns_limb_count);
    bool all_fits = input_fits;
    std::optional<std::size_t> first_failed;
    for (std::size_t index = 0; index < expected_steps; ++index) {
        const std::size_t input_limbs =
            plan.natural_source_rns_limb_count - index;
        const std::uint64_t dropped =
            schedule.data_moduli_low_to_high[input_limbs - 1U];
        const fhe::NaturalMagnitude output = fhe::NaturalMagnitude::add(
            fhe::NaturalMagnitude::divide_ceil(current, dropped),
            fhe::NaturalMagnitude(
                schedule.calibration.switch_rounding_error_bound));
        const fhe::NaturalMagnitude input_phase =
            fhe::honest_noise_phase_bound(kBaseFieldOrder, current);
        const fhe::NaturalMagnitude output_phase =
            fhe::honest_noise_phase_bound(kBaseFieldOrder, output);
        const bool step_input_fits =
            phase_fits(schedule, current, input_limbs);
        const bool output_fits =
            phase_fits(schedule, output, input_limbs - 1U);
        const HonestBaseProofNoiseNormalizationStep expected{
            .input_rns_limb_count = input_limbs,
            .output_rns_limb_count = input_limbs - 1U,
            .dropped_modulus = dropped,
            .input_canonical_error_bound = current,
            .output_canonical_error_bound = output,
            .input_phase_bound = input_phase,
            .output_phase_bound = output_phase,
            .input_phase_fits = step_input_fits,
            .output_phase_fits = output_fits,
        };
        if (!(reduction.ingress_normalization_steps[index] == expected)) {
            throw std::invalid_argument(
                "Base proof-noise ingress recurrence differs from the "
                "exact chain");
        }
        if ((!step_input_fits || !output_fits) && !first_failed) {
            first_failed = index;
        }
        all_fits = all_fits && step_input_fits && output_fits;
        current = output;
    }
    if (reduction.ingress_input_phase_fits != input_fits ||
        reduction.proof_ingress_canonical_error_bound != current ||
        reduction.first_failed_ingress_step != first_failed ||
        reduction.all_ingress_phases_fit != all_fits) {
        throw std::invalid_argument(
            "Base proof-noise ingress assessment differs from exact "
            "re-derivation");
    }
}

void validate_family_binding(
    const HonestBaseProofMessageFamilyAssessment &family,
    const HonestBaseProofMessageFamilyTopology &expected,
    const HonestBaseProofNormalizationLayerPlan &plan,
    std::span<const std::uint64_t> data_moduli) {
    if (family.family != expected.family ||
        family.extension_message_count != expected.extension_message_count ||
        family.base_ciphertext_count > expected.base_ciphertext_count ||
        family.source_rns_limb_count !=
            plan.proof_ingress_rns_limb_count ||
        plan.proof_ingress_rns_limb_count == 0 ||
        family.normalization_steps.size() !=
            (family.base_ciphertext_count == 0
                 ? 0U
                 : plan.proof_ingress_rns_limb_count - 1U)) {
        throw std::invalid_argument(
            "Base proof-noise family binding differs from the plan");
    }
    if (plan.proof_ingress_rns_limb_count > data_moduli.size()) {
        throw std::invalid_argument(
            "Base proof-noise family source level exceeds the chain");
    }
    for (std::size_t index = 0;
         index < family.normalization_steps.size(); ++index) {
        const std::size_t input_limbs =
            plan.proof_ingress_rns_limb_count - index;
        const HonestBaseProofNoiseNormalizationStep &step =
            family.normalization_steps[index];
        if (step.input_rns_limb_count != input_limbs ||
            step.output_rns_limb_count != input_limbs - 1U ||
            step.dropped_modulus != data_moduli[input_limbs - 1U]) {
            throw std::invalid_argument(
                "Base proof-noise normalization-step topology differs "
                "from the chain");
        }
    }
}

void validate_failure_binding(
    const HonestBaseProofReductionNoiseAssessment &reduction) {
    if (!reduction.first_failure) {
        return;
    }
    const HonestBaseProofNoiseFailure &failure =
        *reduction.first_failure;
    const auto family = std::find_if(
        reduction.families.begin(), reduction.families.end(),
        [&](const HonestBaseProofMessageFamilyAssessment &candidate) {
            return candidate.family == failure.family;
        });
    const bool normalization_failure =
        failure.stage ==
        HonestBaseProofNoiseFailureStage::NormalizationStep;
    const bool known_stage = normalization_failure ||
        failure.stage == HonestBaseProofNoiseFailureStage::PreNormalization ||
        failure.stage == HonestBaseProofNoiseFailureStage::PostNormalization;
    if (failure.reduction_layer != reduction.reduction_layer ||
        family == reduction.families.end() ||
        failure.message_occurrence >= family->extension_message_count ||
        failure.coefficient_index >= kExtensionDegree || !known_stage ||
        normalization_failure != failure.normalization_step.has_value() ||
        (failure.normalization_step &&
         *failure.normalization_step >= family->normalization_steps.size())) {
        throw std::invalid_argument(
            "Base proof-noise failure location is outside its reduction");
    }
}

void validate_reduction_binding(
    const HonestBaseProofNormalizationLayerPlan &plan,
    const HonestBaseProofReductionNoiseAssessment &reduction,
    const LayeredCircuit &circuit,
    const HonestPayloadNoiseSchedule &schedule) {
    const std::span<const std::uint64_t> data_moduli =
        schedule.data_moduli_low_to_high;
    const std::size_t expected_messages = checked_add_size(
        plan.round_extension_ciphertext_count,
        plan.terminal_extension_ciphertext_count,
        "Base proof-noise reduction message count overflows");
    if (reduction.reduction_layer != plan.reduction_layer ||
        reduction.kind != plan.kind ||
        reduction.natural_source_rns_limb_count !=
            plan.natural_source_rns_limb_count ||
        reduction.proof_ingress_rns_limb_count !=
            plan.proof_ingress_rns_limb_count ||
        reduction.live_source_ciphertext_count !=
            plan.live_source_ciphertext_count ||
        reduction.source_rns_limb_count !=
            plan.proof_ingress_rns_limb_count ||
        reduction.wire_variables != plan.wire_variables ||
        reduction.expected_extension_message_count != expected_messages ||
        reduction.observed_extension_message_count != expected_messages ||
        reduction.ingress_switch_events != plan.ingress_switch_events ||
        reduction.expected_proof_message_switch_events !=
            plan.proof_message_switch_events ||
        reduction.observed_proof_message_switch_events >
            plan.proof_message_switch_events ||
        reduction.expected_switch_events != plan.switch_events ||
        reduction.observed_switch_events > plan.switch_events ||
        !reduction.topology_complete) {
        throw std::invalid_argument(
            "Base proof-noise reduction binding differs from the plan");
    }

    std::size_t messages = 0;
    std::size_t ciphertexts = 0;
    const HonestBaseProofMessageTopology topology =
        derive_honest_base_proof_message_topology(plan);
    if (plan.round_extension_ciphertext_count !=
            topology.round_extension_message_count ||
        plan.terminal_extension_ciphertext_count !=
            topology.terminal_extension_message_count ||
        plan.public_zero_extension_message_count !=
            topology.public_zero_extension_message_count ||
        plan.base_ciphertext_count != topology.base_ciphertext_count ||
        reduction.families.size() != topology.families.size()) {
        throw std::invalid_argument(
            "Base proof-noise family topology differs from the plan");
    }
    for (std::size_t index = 0; index < topology.families.size(); ++index) {
        const HonestBaseProofMessageFamilyTopology &expected =
            topology.families[index];
        validate_family_binding(
            reduction.families[index], expected, plan, data_moduli);
        messages = checked_add_size(
            messages, expected.extension_message_count,
            "Base proof-noise message total overflows");
        ciphertexts = checked_add_size(
            ciphertexts,
            reduction.families[index].base_ciphertext_count,
            "Base proof-noise ciphertext total overflows");
    }

    const std::uint64_t observed_proof_switch_events =
        checked_multiply_size(
            ciphertexts, plan.proof_ingress_rns_limb_count - 1U,
            "Base proof-noise observed message switches overflow");
    const std::uint64_t observed_switch_events = checked_add_u64(
        plan.ingress_switch_events, observed_proof_switch_events,
        "Base proof-noise observed switches overflow");
    if (messages != expected_messages ||
        ciphertexts > plan.base_ciphertext_count ||
        reduction.observed_proof_message_switch_events !=
            observed_proof_switch_events ||
        reduction.observed_switch_events != observed_switch_events) {
        throw std::invalid_argument(
            "Base proof-noise family totals differ from the plan");
    }
    validate_ingress_binding(circuit, schedule, plan, reduction);
    validate_failure_binding(reduction);
}

bool exact_report_accepts(
    const HonestPayloadNoiseSchedule &schedule,
    const HonestBaseProofNoiseAssessment &assessment) {
    return schedule.payload_model_accepts() && assessment.report_accepts() &&
           assessment.observed_switch_events <=
               schedule.modeled_base_proof_switch_events;
}

std::optional<HonestPayloadNoiseSchedule> try_derive_reserve_candidate(
    const LayeredCircuit &circuit,
    std::span<const std::uint64_t> data_moduli_low_to_high,
    HonestPayloadNoiseCalibration calibration) {
    try {
        return derive_honest_payload_noise_schedule(
            circuit, data_moduli_low_to_high, calibration);
    } catch (const std::invalid_argument &) {
        // A reserve may be arithmetically invalid or make the payload model
        // fail. Event-cap undercoverage is checked explicitly before search
        // and is therefore never silently classified here.
        return std::nullopt;
    } catch (const std::overflow_error &) {
        // A candidate whose exact public counts cannot be represented is
        // likewise uncertified. Internal invariant failures still propagate.
        return std::nullopt;
    }
}

std::uint64_t search_event_upper_bound(
    const LayeredCircuit &circuit,
    std::span<const std::uint64_t> data_moduli_low_to_high,
    HonestPayloadNoiseCalibration calibration) {
    return honest_base_proof_ingress_search_event_upper_bound(
        circuit, data_moduli_low_to_high, std::move(calibration));
}

void require_search_event_coverage(
    const LayeredCircuit &circuit,
    const HonestPayloadNoiseSchedule &selected) {
    const std::uint64_t required_events = search_event_upper_bound(
        circuit, selected.data_moduli_low_to_high,
        selected.calibration);
    if (selected.calibration.modeled_switch_events_upper_bound <
        required_events) {
        throw std::invalid_argument(
            "Base proof ingress: event calibration does not cover the "
            "global reserve search");
    }
    if (selected.calibration.switch_rounding_error_bound <
        randomized_mod_switch_rounding_heuristic_bound(
            circuit.shape.slot_count,
            required_events,
            selected.calibration.switch_model_failure_budget_bits)) {
        throw std::invalid_argument(
            "Base proof ingress: switch-rounding allowance cannot certify "
            "the reserve search event domain");
    }
}

std::optional<HonestPayloadNoiseSchedule>
select_mixed_ingress_for_natural_schedule(
    const LayeredCircuit &circuit,
    HonestPayloadNoiseSchedule natural,
    const fhe::HonestNoiseEnvelopeParameters &parameters,
    HonestBaseProofNoiseExecutionAudit *execution_audit,
    const HonestBaseProofIngressSelectionProgressCallback
        &progress_callback,
    std::size_t reserve_count) {
    natural.base_proof_noise_assessment.reset();
    std::vector<std::size_t> selected =
        natural.evaluation_plan.trace.required_mult_depth_by_layer;
    for (std::size_t reduction = 0;
         reduction + 1U < circuit.layers.size(); ++reduction) {
        const std::size_t source_layer = reduction + 1U;
        const std::size_t natural_limbs =
            natural.evaluation_plan.trace
                .required_mult_depth_by_layer[source_layer] +
            1U;
        bool found = false;
        // Probe q_0-only ingress as well. Whether a reduction needs a
        // droppable data limb is a property of its exact noise recurrence,
        // not a separate structural restriction.
        for (std::size_t limbs = 1;
             limbs <= natural_limbs; ++limbs) {
            notify_honest_base_proof_ingress_selection_progress(
                progress_callback,
                HonestBaseProofIngressSelectionProgress{
                    .stage =
                        HonestBaseProofIngressSelectionStage::LimbProbe,
                    .reserve = natural.calibration
                                   .proof_suffix_level_reserve,
                    .reserve_count = reserve_count,
                    .reduction = reduction,
                    .reduction_count = circuit.layers.size() - 1U,
                    .candidate_limbs = limbs,
                    .maximum_limbs = natural_limbs,
                });
            std::vector<std::size_t> probe =
                natural.evaluation_plan.trace.required_mult_depth_by_layer;
            probe[source_layer] = limbs - 1U;
            HonestPayloadNoiseSchedule candidate =
                apply_honest_base_proof_ingress_depths(
                    circuit, natural, probe);
            Transcript transcript(
                "LaminateImpl/HonestBaseProofIngressProbe/v1");
            transcript.observe(
                "LaminateImpl/HonestBaseProofIngressProbe/reduction",
                static_cast<std::uint64_t>(reduction));
            transcript.observe(
                "LaminateImpl/HonestBaseProofIngressProbe/limbs",
                static_cast<std::uint64_t>(limbs));
            const HonestBaseProofReductionNoiseAssessment assessment =
                assess_honest_base_proof_reduction_noise(
                    circuit, candidate, reduction, parameters,
                    transcript);
            if (assessment.topology_complete &&
                assessment.all_messages_fit &&
                !assessment.first_failure) {
                selected[source_layer] = limbs - 1U;
                found = true;
                break;
            }
        }
        if (!found) {
            return std::nullopt;
        }
    }

    HonestPayloadNoiseSchedule mixed =
        apply_honest_base_proof_ingress_depths(
            circuit, std::move(natural), selected);
    notify_honest_base_proof_ingress_selection_progress(
        progress_callback, HonestBaseProofIngressSelectionProgress{
            .stage = HonestBaseProofIngressSelectionStage::FinalAssessment,
            .reserve = mixed.calibration.proof_suffix_level_reserve,
            .reserve_count = reserve_count,
            .reduction_count = circuit.layers.size() - 1U,
        });
    HonestBaseProofNoiseExecutionAudit audit;
    HonestBaseProofNoiseAssessment assessment =
        assess_honest_base_proof_noise(
            circuit, mixed, parameters,
            execution_audit == nullptr ? nullptr : &audit);
    if (!exact_report_accepts(mixed, assessment)) {
        return std::nullopt;
    }
    mixed.base_proof_noise_assessment = std::move(assessment);
    if (execution_audit != nullptr) {
        *execution_audit = std::move(audit);
    }
    return mixed;
}

HonestPayloadNoiseSchedule deterministically_select_mixed_ingress(
    const LayeredCircuit &circuit,
    std::span<const std::uint64_t> data_moduli_low_to_high,
    HonestPayloadNoiseCalibration payload_calibration,
    const fhe::HonestNoiseEnvelopeParameters &parameters,
    HonestBaseProofNoiseExecutionAudit *execution_audit,
    const HonestBaseProofIngressSelectionProgressCallback
        &progress_callback) {
    for (std::size_t reserve = 0;
         reserve < data_moduli_low_to_high.size(); ++reserve) {
        notify_honest_base_proof_ingress_selection_progress(
            progress_callback, HonestBaseProofIngressSelectionProgress{
                .stage = HonestBaseProofIngressSelectionStage::
                    ReserveCandidate,
                .reserve = reserve,
                .reserve_count = data_moduli_low_to_high.size(),
                .reduction_count = circuit.layers.size() - 1U,
            });
        payload_calibration.proof_suffix_level_reserve = reserve;
        std::optional<HonestPayloadNoiseSchedule> natural =
            try_derive_reserve_candidate(
                circuit, data_moduli_low_to_high, payload_calibration);
        if (!natural || !natural->payload_model_accepts()) {
            continue;
        }
        std::optional<HonestPayloadNoiseSchedule> selected =
            select_mixed_ingress_for_natural_schedule(
                circuit, std::move(*natural), parameters,
                execution_audit, progress_callback,
                data_moduli_low_to_high.size());
        if (selected) {
            return std::move(*selected);
        }
    }
    throw std::invalid_argument(
        "Base proof ingress: no setup-certified mixed ingress exists");
}

} // namespace

void HonestBaseProofNoiseCalibration::validate() const {
    if (ctct_relinearized_debit_bits >
            fhe::kMaximumHonestNoiseEnvelopeDebitBits ||
        plaintext_multiplication_debit_bits >
            fhe::kMaximumHonestNoiseEnvelopeDebitBits ||
        rotation_debit_bits >
            fhe::kMaximumHonestNoiseEnvelopeDebitBits) {
        throw std::invalid_argument(
            "Base proof-noise calibration debit exceeds the supported "
            "bound");
    }
}

fhe::HonestNoiseEnvelopeParameters
derive_honest_base_proof_noise_parameters(
    const LayeredCircuit &circuit,
    const HonestPayloadNoiseSchedule &payload_core_schedule,
    const HonestBaseProofNoiseCalibration &calibration) {
    validate_honest_payload_noise_schedule_core(
        circuit, payload_core_schedule);
    calibration.validate();

    fhe::HonestNoiseEnvelopeParameters result{
        .ring_degree = circuit.shape.slot_count,
        .plaintext_modulus = kBaseFieldOrder,
        .fresh_canonical_error_bound = fhe::NaturalMagnitude(
            payload_core_schedule.calibration.fresh_canonical_error_bound),
        .ctct_relinearized_debit_bits =
            calibration.ctct_relinearized_debit_bits,
        .plaintext_multiplication_debit_bits =
            calibration.plaintext_multiplication_debit_bits,
        .rotation_debit_bits = calibration.rotation_debit_bits,
        .switch_rounding_error_bound = fhe::NaturalMagnitude(
            payload_core_schedule.calibration.switch_rounding_error_bound),
        .data_moduli = payload_core_schedule.data_moduli_low_to_high,
    };
    result.validate();
    return result;
}

std::vector<std::uint8_t> encode_canonical(
    const HonestBaseProofNoiseAssessment &assessment) {
    Bytes output;
    append_label(output,
                 "LaminateImpl/HonestBaseProofNoiseAssessmentReport/v6");
    append_label(output, assessment.policy);
    append_digest(output, assessment.source_payload_schedule_digest);
    append_digest(output, assessment.proof_noise_parameters_digest);
    append_size(output, assessment.reductions.size());
    for (const HonestBaseProofReductionNoiseAssessment &reduction :
         assessment.reductions) {
        append_reduction(output, reduction);
    }
    append_u64(output, assessment.observed_switch_events);
    append_failure(output, assessment.first_failure);
    append_bool(output, assessment.topology_complete);
    append_bool(output, assessment.all_messages_fit);
    return output;
}

HonestBaseProofNoiseAssessment
decode_canonical_honest_base_proof_noise_assessment(
    std::span<const std::uint8_t> encoded, std::size_t max_bytes) {
    if (encoded.size() > max_bytes) {
        throw std::invalid_argument(
            "Base proof-noise assessment exceeds its decode limit");
    }

    AssessmentReader reader(encoded);
    reader.label(
        "LaminateImpl/HonestBaseProofNoiseAssessmentReport/v6",
        "Base proof-noise assessment format");

    HonestBaseProofNoiseAssessment result;
    reader.label(kHonestBaseProofNoiseAssessmentPolicyV6,
                 "Base proof-noise assessment policy");
    result.policy = kHonestBaseProofNoiseAssessmentPolicyV6;
    result.source_payload_schedule_digest =
        reader.digest("Base proof-noise source schedule digest");
    result.proof_noise_parameters_digest =
        reader.digest("Base proof-noise parameter digest");
    const std::size_t reduction_count = reader.size(
        kMaximumDecodedReductions,
        "Base proof-noise reduction count");
    result.reductions.reserve(reduction_count);
    for (std::size_t index = 0; index < reduction_count; ++index) {
        result.reductions.push_back(read_reduction(reader));
    }
    result.observed_switch_events =
        reader.u64("Base proof-noise observed switch events");
    result.first_failure = read_optional_failure(reader);
    result.topology_complete =
        reader.boolean("Base proof-noise topology complete");
    result.all_messages_fit =
        reader.boolean("Base proof-noise all messages fit");
    reader.finish();

    if (encode_canonical(result) !=
        std::vector<std::uint8_t>(encoded.begin(), encoded.end())) {
        throw std::invalid_argument(
            "Base proof-noise assessment is not canonical");
    }
    return result;
}

Digest honest_base_proof_noise_assessment_digest(
    const HonestBaseProofNoiseAssessment &assessment) {
    const Bytes encoded = encode_canonical(assessment);
    return sha256(encoded);
}

void validate_honest_base_proof_noise_assessment_binding(
    const LayeredCircuit &circuit,
    const HonestPayloadNoiseSchedule &schedule) {
    validate_honest_payload_noise_schedule_core(circuit, schedule);
    if (!schedule.base_proof_noise_assessment) {
        throw std::invalid_argument(
            "Base proof-noise assessment binding is absent");
    }
    const HonestBaseProofNoiseAssessment &assessment =
        *schedule.base_proof_noise_assessment;
    if (assessment.policy != kHonestBaseProofNoiseAssessmentPolicyV6 ||
        assessment.source_payload_schedule_digest !=
            honest_payload_noise_schedule_digest(circuit, schedule) ||
        digest_is_zero(assessment.proof_noise_parameters_digest)) {
        throw std::invalid_argument(
            "Base proof-noise policy or input digest binding is invalid");
    }

    const HonestBaseProofNormalizationPlan &plan =
        schedule.base_proof_normalization_plan;
    if (assessment.reductions.size() != plan.reductions.size()) {
        throw std::invalid_argument(
            "Base proof-noise reduction count differs from the plan");
    }

    std::uint64_t ingress_switch_events = 0;
    std::uint64_t proof_message_switch_events = 0;
    std::uint64_t switch_events = 0;
    bool topology_complete = true;
    bool all_messages_fit = true;
    std::optional<HonestBaseProofNoiseFailure> first_failure;
    for (std::size_t index = 0; index < plan.reductions.size(); ++index) {
        const HonestBaseProofNormalizationLayerPlan &planned =
            plan.reductions[index];
        const HonestBaseProofReductionNoiseAssessment &reduction =
            assessment.reductions[index];
        if (planned.reduction_layer != index) {
            throw std::invalid_argument(
                "Base proof-noise normalization plan is not canonical");
        }
        validate_reduction_binding(
            planned, reduction, circuit, schedule);
        ingress_switch_events = checked_add_u64(
            ingress_switch_events, reduction.ingress_switch_events,
            "Base proof-noise ingress-switch total overflows");
        proof_message_switch_events = checked_add_u64(
            proof_message_switch_events,
            reduction.observed_proof_message_switch_events,
            "Base proof-noise message-switch total overflows");
        switch_events = checked_add_u64(
            switch_events, reduction.observed_switch_events,
            "Base proof-noise switch total overflows");
        topology_complete =
            topology_complete && reduction.topology_complete;
        all_messages_fit =
            all_messages_fit && reduction.all_messages_fit;
        if (!first_failure && reduction.first_failure) {
            first_failure = reduction.first_failure;
        }
    }
    all_messages_fit = topology_complete && all_messages_fit &&
                       !first_failure.has_value();
    if (ingress_switch_events != plan.ingress_switch_events ||
        ingress_switch_events !=
            schedule.modeled_base_proof_ingress_switch_events ||
        proof_message_switch_events >
            plan.proof_message_switch_events ||
        proof_message_switch_events >
            schedule.modeled_base_proof_message_switch_events ||
        switch_events > plan.switch_events ||
        switch_events > schedule.modeled_base_proof_switch_events ||
        assessment.observed_switch_events != switch_events ||
        assessment.first_failure != first_failure ||
        assessment.topology_complete != topology_complete ||
        assessment.all_messages_fit != all_messages_fit) {
        throw std::invalid_argument(
            "Base proof-noise aggregate report differs from the plan");
    }
}

void validate_honest_base_proof_noise_assessment(
    const LayeredCircuit &circuit,
    const HonestPayloadNoiseSchedule &schedule,
    fhe::HonestNoiseEnvelopeParameters parameters) {
    validate_honest_base_proof_noise_assessment_binding(circuit, schedule);
    if (fhe::honest_noise_envelope_parameters_digest(parameters) !=
        schedule.base_proof_noise_assessment
            ->proof_noise_parameters_digest) {
        throw std::invalid_argument(
            "Base proof-noise parameters differ from the assessment "
            "binding");
    }
    HonestPayloadNoiseSchedule detached = schedule;
    detached.base_proof_noise_assessment.reset();
    const HonestBaseProofNoiseAssessment expected =
        assess_honest_base_proof_noise(
            circuit, detached, std::move(parameters));
    if (!(expected == *schedule.base_proof_noise_assessment)) {
        throw std::invalid_argument(
            "Base proof-noise report differs from exact re-derivation");
    }
}

bool honest_base_end_to_end_model_accepts(
    const LayeredCircuit &circuit,
    const HonestPayloadNoiseSchedule &schedule,
    fhe::HonestNoiseEnvelopeParameters parameters) {
    validate_honest_base_proof_noise_assessment(
        circuit, schedule, std::move(parameters));
    return exact_report_accepts(
        schedule, *schedule.base_proof_noise_assessment);
}

bool honest_base_proof_ingress_is_minimal(
    const LayeredCircuit &circuit,
    const HonestPayloadNoiseSchedule &schedule,
    fhe::HonestNoiseEnvelopeParameters parameters) {
    validate_honest_base_proof_noise_assessment(
        circuit, schedule, parameters);
    const HonestBaseProofNoiseAssessment &assessment =
        *schedule.base_proof_noise_assessment;
    if (!exact_report_accepts(schedule, assessment)) {
        return false;
    }
    require_search_event_coverage(circuit, schedule);
    HonestPayloadNoiseCalibration calibration = schedule.calibration;
    const HonestPayloadNoiseSchedule expected =
        deterministically_select_mixed_ingress(
            circuit, schedule.data_moduli_low_to_high, calibration,
            parameters, nullptr, {});
    return expected.evaluation_plan
               .proof_ingress_mult_depth_by_layer ==
               schedule.evaluation_plan
                   .proof_ingress_mult_depth_by_layer &&
           expected.calibration.proof_suffix_level_reserve ==
               schedule.calibration.proof_suffix_level_reserve;
}

CertifiedHonestBaseProofIngressSelection
select_certified_honest_base_proof_ingress(
    const LayeredCircuit &circuit,
    std::span<const std::uint64_t> data_moduli_low_to_high,
    HonestPayloadNoiseCalibration payload_calibration,
    const HonestBaseProofNoiseCalibration &proof_calibration,
    HonestBaseProofNoiseExecutionAudit *execution_audit,
    HonestBaseProofIngressSelectionProgressCallback progress_callback) {
    circuit.validate();
    proof_calibration.validate();
    const std::uint64_t required_events = search_event_upper_bound(
        circuit, data_moduli_low_to_high, payload_calibration);
    if (payload_calibration.modeled_switch_events_upper_bound <
        required_events) {
        throw std::invalid_argument(
            "Base proof ingress: event calibration does not cover the "
            "global reserve search");
    }
    if (payload_calibration.switch_rounding_error_bound <
        randomized_mod_switch_rounding_heuristic_bound(
            circuit.shape.slot_count,
            required_events,
            payload_calibration.switch_model_failure_budget_bits)) {
        throw std::invalid_argument(
            "Base proof ingress: switch-rounding allowance cannot certify "
            "the reserve search event domain");
    }
    HonestPayloadNoiseCalibration seed_calibration = payload_calibration;
    seed_calibration.proof_suffix_level_reserve = 0;
    const HonestPayloadNoiseSchedule seed =
        derive_honest_payload_noise_schedule(
            circuit, data_moduli_low_to_high, seed_calibration);
    const fhe::HonestNoiseEnvelopeParameters parameters =
        derive_honest_base_proof_noise_parameters(
            circuit, seed, proof_calibration);
    HonestPayloadNoiseSchedule selected =
        deterministically_select_mixed_ingress(
            circuit, data_moduli_low_to_high, payload_calibration,
            parameters, execution_audit, progress_callback);
    validate_honest_base_proof_noise_assessment_binding(
        circuit, selected);
    CertifiedHonestBaseProofIngressSelection result;
    result.schedule_ = std::move(selected);
    return result;
}

HonestPayloadNoiseSchedule select_minimal_honest_base_proof_ingress(
    const LayeredCircuit &circuit,
    std::span<const std::uint64_t> data_moduli_low_to_high,
    HonestPayloadNoiseCalibration payload_calibration,
    const HonestBaseProofNoiseCalibration &proof_calibration,
    HonestBaseProofNoiseExecutionAudit *execution_audit) {
    CertifiedHonestBaseProofIngressSelection selected =
        select_certified_honest_base_proof_ingress(
            circuit, data_moduli_low_to_high,
            std::move(payload_calibration), proof_calibration,
            execution_audit, {});
    return std::move(selected).release_schedule();
}

HonestPayloadNoiseSchedule attach_honest_base_proof_noise_assessment(
    const LayeredCircuit &circuit, HonestPayloadNoiseSchedule schedule,
    fhe::HonestNoiseEnvelopeParameters parameters,
    HonestBaseProofNoiseExecutionAudit *execution_audit) {
    validate_honest_payload_noise_schedule_core(circuit, schedule);
    schedule.base_proof_noise_assessment.reset();
    schedule.base_proof_noise_assessment = assess_honest_base_proof_noise(
        circuit, schedule, std::move(parameters), execution_audit);
    validate_honest_base_proof_noise_assessment_binding(circuit, schedule);
    return schedule;
}

} // namespace laminate::payload
