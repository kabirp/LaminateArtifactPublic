/// @file test_honest_base_proof_noise.cpp
/// @brief Pure Base normalization-record aggregation tests.

#include "test_helpers.hpp"

#include "laminate/payload/noise/honest_base_proof_noise.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <stdexcept>
#include <string_view>
#include <utility>
#include <vector>

namespace {

using namespace laminate;
using namespace laminate::fhe;
using namespace laminate::payload;

HonestNoiseEnvelopeParameters fitting_parameters(std::size_t limbs = 3) {
    std::vector<std::uint64_t> moduli{
        1'000'000'000'000'037ULL,
        1'000'000'000'000'099ULL,
        1'000'000'000'000'133ULL,
    };
    moduli.resize(limbs);
    return HonestNoiseEnvelopeParameters{
        .ring_degree = 8,
        .plaintext_modulus = kBaseFieldOrder,
        .fresh_canonical_error_bound = NaturalMagnitude(7),
        .ctct_relinearized_debit_bits = 2,
        .plaintext_multiplication_debit_bits = 1,
        .rotation_debit_bits = 1,
        .switch_rounding_error_bound = NaturalMagnitude(7),
        .data_moduli = std::move(moduli),
    };
}

HonestNoiseEnvelopeParameters failing_bottom_parameters() {
    HonestNoiseEnvelopeParameters result = fitting_parameters(2);
    result.data_moduli = {1'000'003ULL, 2'000'033ULL};
    return result;
}

NaturalMagnitude normalized_bound(
    const HonestNoiseEnvelopeParameters &parameters,
    NaturalMagnitude input, std::size_t source_limbs) {
    for (std::size_t limbs = source_limbs; limbs > 1U; --limbs) {
        input = NaturalMagnitude::add(
            NaturalMagnitude::divide_ceil(
                input, parameters.data_moduli[limbs - 1U]),
            parameters.switch_rounding_error_bound);
    }
    return input;
}

HonestBaseProofNormalizationLayerPlan make_plan(
    LayerKind kind, std::size_t wire_variables, std::size_t source_limbs,
    std::size_t reduction_layer = 4) {
    constexpr HonestBaseProofCoordinateMask full_mask =
        static_cast<HonestBaseProofCoordinateMask>(
            (std::uint16_t{1} << kExtensionDegree) - 1U);
    const std::size_t round_messages =
        wire_variables * 2U;
    const std::size_t terminal_messages =
        kind == LayerKind::Affine ? 1U : 2U;
    std::vector<HonestBaseProofCoordinateMask> masks(
        round_messages + terminal_messages, full_mask);
    if (wire_variables == 0) {
        std::fill(masks.begin(), masks.end(),
                  HonestBaseProofCoordinateMask{1});
    }
    std::size_t base_ciphertexts = 0;
    for (const HonestBaseProofCoordinateMask mask : masks) {
        base_ciphertexts += static_cast<std::size_t>(std::popcount(mask));
    }
    return HonestBaseProofNormalizationLayerPlan{
        .reduction_layer = reduction_layer,
        .kind = kind,
        .natural_source_rns_limb_count = source_limbs,
        .proof_ingress_rns_limb_count = source_limbs,
        .live_source_ciphertext_count = 1,
        .wire_variables = wire_variables,
        .round_extension_ciphertext_count =
            round_messages,
        .terminal_extension_ciphertext_count =
            terminal_messages,
        .public_zero_extension_message_count = 0,
        .message_coordinate_masks = std::move(masks),
        .base_ciphertext_count = base_ciphertexts,
        .ingress_switch_events = 0,
        .proof_message_switch_events = static_cast<std::uint64_t>(
            base_ciphertexts * (source_limbs - 1U)),
        .switch_events = static_cast<std::uint64_t>(
            base_ciphertexts * (source_limbs - 1U)),
    };
}

std::uint64_t input_bound_value(std::size_t record,
                                std::size_t coefficient) {
    return 7U + 10U * record + coefficient;
}

HonestBaseNormalizationRecord make_record(
    const HonestNoiseEnvelopeParameters &parameters,
    std::size_t source_limbs, std::size_t record_index,
    std::uint64_t coordinate_mask,
    bool normalization_failure = false) {
    HonestBaseNormalizationRecord result;
    for (std::size_t coefficient = 0; coefficient < kExtensionDegree;
         ++coefficient) {
        if ((coordinate_mask & (std::uint64_t{1} << coefficient)) == 0) {
            continue;
        }
        const NaturalMagnitude input(
            input_bound_value(record_index, coefficient));
        const NaturalMagnitude output = normalized_bound(
            parameters, input, source_limbs);
        const std::uint64_t input_identity =
            1U + 100U * record_index + coefficient;
        std::optional<HonestNoiseEnvelopeFailure> output_failure;
        if (normalization_failure) {
            output_failure = HonestNoiseEnvelopeFailure{
                .operation = HonestNoiseEnvelopeOperation::ModulusSwitch,
                .operation_sequence =
                    1U + 10U * record_index + coefficient,
                .input_rns_limbs = 2,
                .output_rns_limbs = 1,
                .canonical_error_bound = output,
                .active_modulus_product_bits =
                    NaturalMagnitude::product(
                        std::span<const std::uint64_t>(
                            parameters.data_moduli)
                            .first(1))
                        .bit_count(),
            };
        }
        result.coefficients[coefficient] =
            HonestBaseNormalizationCoefficientRecord{
                .present = true,
                .input_canonical_error_bound = input,
                .output_canonical_error_bound = output,
                .input_rns_limbs = source_limbs,
                .output_rns_limbs = 1,
                .input_component_count = 2,
                .output_component_count = 2,
                .input_identity = input_identity,
                .output_identity = source_limbs == 1U
                                       ? input_identity
                                       : input_identity + 10'000U,
                .input_first_failure = std::nullopt,
                .output_first_failure = std::move(output_failure),
            };
    }
    return result;
}

std::vector<HonestBaseNormalizationRecord> make_records(
    const HonestNoiseEnvelopeParameters &parameters,
    const HonestBaseProofNormalizationLayerPlan &plan,
    bool normalization_failure = false) {
    const std::size_t count =
        plan.round_extension_ciphertext_count +
        plan.terminal_extension_ciphertext_count;
    std::vector<HonestBaseNormalizationRecord> result;
    result.reserve(count);
    for (std::size_t record = 0; record < count; ++record) {
        result.push_back(make_record(
            parameters, plan.proof_ingress_rns_limb_count, record,
            plan.message_coordinate_masks.at(record),
            normalization_failure));
    }
    return result;
}

NaturalMagnitude expected_family_maximum(std::size_t record_index) {
    return NaturalMagnitude(
        input_bound_value(record_index, kExtensionDegree - 1U));
}

void check_family(
    const HonestBaseProofMessageFamilyAssessment &family,
    HonestBaseProofMessageFamily expected_family,
    std::size_t expected_messages, std::size_t expected_base_ciphertexts,
    std::size_t expected_steps,
    const NaturalMagnitude &expected_maximum) {
    CHECK(family.family == expected_family);
    CHECK(family.extension_message_count == expected_messages);
    CHECK(family.base_ciphertext_count == expected_base_ciphertexts);
    CHECK(family.maximum_pre_normalization_canonical_error_bound ==
          expected_maximum);
    CHECK(family.normalization_steps.size() == expected_steps);
    CHECK(family.all_pre_normalization_phases_fit);
    CHECK(family.all_post_normalization_phases_fit);
}

NaturalMagnitude large_magnitude() {
    const NaturalMagnitude maximum(
        std::numeric_limits<std::uint64_t>::max());
    return NaturalMagnitude::multiply(maximum, maximum);
}

HonestBaseProofNoiseNormalizationStep sample_normalization_step() {
    return HonestBaseProofNoiseNormalizationStep{
        .input_rns_limb_count = 3,
        .output_rns_limb_count = 2,
        .dropped_modulus = 1'000'000'000'000'133ULL,
        .input_canonical_error_bound = large_magnitude(),
        .output_canonical_error_bound = NaturalMagnitude(37),
        .input_phase_bound = NaturalMagnitude(41),
        .output_phase_bound = NaturalMagnitude(43),
        .input_phase_fits = true,
        .output_phase_fits = false,
    };
}

HonestBaseProofNoiseFailure sample_failure() {
    return HonestBaseProofNoiseFailure{
        .reduction_layer = 3,
        .family = HonestBaseProofMessageFamily::AffineRoundAtTwo,
        .message_occurrence = 5,
        .coefficient_index = 2,
        .stage = HonestBaseProofNoiseFailureStage::NormalizationStep,
        .normalization_step = 0,
    };
}

HonestBaseProofNoiseAssessment sample_assessment() {
    Digest schedule_digest{};
    Digest parameters_digest{};
    for (std::size_t index = 0; index < schedule_digest.size(); ++index) {
        schedule_digest[index] = static_cast<std::uint8_t>(index + 1U);
        parameters_digest[index] =
            static_cast<std::uint8_t>(0xf0U - index);
    }

    const HonestBaseProofNoiseNormalizationStep step =
        sample_normalization_step();
    const HonestBaseProofNoiseFailure failure = sample_failure();
    HonestBaseProofMessageFamilyAssessment family{
        .family = HonestBaseProofMessageFamily::AffineRoundAtTwo,
        .extension_message_count = 6,
        .base_ciphertext_count = 17,
        .source_rns_limb_count = 3,
        .maximum_pre_normalization_canonical_error_bound =
            large_magnitude(),
        .maximum_pre_normalization_phase_bound = NaturalMagnitude(47),
        .all_pre_normalization_phases_fit = true,
        .normalization_steps = {step},
        .maximum_post_normalization_canonical_error_bound =
            NaturalMagnitude(53),
        .maximum_post_normalization_phase_bound = NaturalMagnitude(59),
        .all_post_normalization_phases_fit = false,
    };
    HonestBaseProofReductionNoiseAssessment reduction{
        .reduction_layer = 3,
        .kind = LayerKind::Affine,
        .natural_source_rns_limb_count = 4,
        .proof_ingress_rns_limb_count = 3,
        .live_source_ciphertext_count = 61,
        .natural_source_canonical_error_bound = NaturalMagnitude(67),
        .proof_ingress_canonical_error_bound = NaturalMagnitude(71),
        .ingress_input_phase_fits = true,
        .ingress_normalization_steps = {step},
        .first_failed_ingress_step = 0,
        .all_ingress_phases_fit = false,
        .source_rns_limb_count = 3,
        .wire_variables = 7,
        .families = {std::move(family)},
        .expected_extension_message_count = 6,
        .observed_extension_message_count = 6,
        .ingress_switch_events = 61,
        .expected_proof_message_switch_events = 34,
        .observed_proof_message_switch_events = 34,
        .expected_switch_events = 95,
        .observed_switch_events = 95,
        .first_failure = failure,
        .topology_complete = true,
        .all_messages_fit = false,
    };
    return HonestBaseProofNoiseAssessment{
        .policy = kHonestBaseProofNoiseAssessmentPolicyV6,
        .source_payload_schedule_digest = schedule_digest,
        .proof_noise_parameters_digest = parameters_digest,
        .reductions = {std::move(reduction)},
        .observed_switch_events = 95,
        .first_failure = failure,
        .topology_complete = true,
        .all_messages_fit = false,
    };
}

bool assessment_decode_rejects(
    const std::vector<std::uint8_t> &encoded,
    std::size_t max_bytes = 64U << 20U) {
    try {
        (void)decode_canonical_honest_base_proof_noise_assessment(
            encoded, max_bytes);
        return false;
    } catch (const std::invalid_argument &) {
        return true;
    }
}

void write_u64(std::vector<std::uint8_t> &encoded, std::size_t offset,
               std::uint64_t value) {
    for (std::size_t byte = 0; byte < 8; ++byte) {
        encoded.at(offset + byte) = static_cast<std::uint8_t>(
            (value >> (8U * byte)) & std::uint64_t{0xff});
    }
}

std::size_t reduction_count_offset() {
    constexpr std::string_view format =
        "LaminateImpl/HonestBaseProofNoiseAssessmentReport/v6";
    return 8U + format.size() + 8U +
           kHonestBaseProofNoiseAssessmentPolicyV6.size() +
           2U * Digest{}.size();
}

} // namespace

int main() {
    test::Runner runner("honest Base proof normalization aggregation");

    runner.run("canonical assessment decoding round trips every field", [] {
        const HonestBaseProofNoiseAssessment assessment =
            sample_assessment();
        const std::vector<std::uint8_t> encoded =
            encode_canonical(assessment);
        const HonestBaseProofNoiseAssessment decoded =
            decode_canonical_honest_base_proof_noise_assessment(encoded);
        CHECK(decoded == assessment);
        CHECK(encode_canonical(decoded) == encoded);
    });

    runner.run("assessment decoder rejects malformed and trailing bytes", [] {
        const std::vector<std::uint8_t> encoded =
            encode_canonical(sample_assessment());
        CHECK(assessment_decode_rejects({}));
        CHECK(assessment_decode_rejects(std::vector<std::uint8_t>(
            encoded.begin(), encoded.end() - 1U)));

        std::vector<std::uint8_t> trailing = encoded;
        trailing.push_back(0);
        CHECK(assessment_decode_rejects(trailing));

        std::vector<std::uint8_t> invalid_label = encoded;
        invalid_label.at(8) ^= 1U;
        CHECK(assessment_decode_rejects(invalid_label));
    });

    runner.run("assessment decoder rejects noncanonical nested values", [] {
        const NaturalMagnitude magnitude = large_magnitude();
        const std::vector<std::uint8_t> magnitude_encoding =
            laminate::fhe::encode_canonical(magnitude);
        std::vector<std::uint8_t> encoded =
            encode_canonical(sample_assessment());
        const auto found = std::search(
            encoded.begin(), encoded.end(), magnitude_encoding.begin(),
            magnitude_encoding.end());
        CHECK(found != encoded.end());
        const std::size_t magnitude_offset = static_cast<std::size_t>(
            std::distance(encoded.begin(), found));
        CHECK(magnitude_encoding.size() == 24U);
        write_u64(encoded, magnitude_offset + 16U, 0);
        CHECK(assessment_decode_rejects(encoded));
    });

    runner.run("assessment decoder enforces byte and collection limits", [] {
        const std::vector<std::uint8_t> canonical =
            encode_canonical(sample_assessment());
        CHECK(assessment_decode_rejects(canonical, canonical.size() - 1U));

        std::vector<std::uint8_t> excessive_reductions = canonical;
        write_u64(excessive_reductions, reduction_count_offset(),
                  (std::uint64_t{1} << 12U) + 1U);
        CHECK(assessment_decode_rejects(excessive_reductions));
    });

    runner.run("affine records map to three families and maximum chains", [] {
        const HonestNoiseEnvelopeParameters parameters = fitting_parameters();
        const HonestBaseProofNormalizationLayerPlan plan =
            make_plan(LayerKind::Affine, 2, 3);
        const std::vector<HonestBaseNormalizationRecord> records =
            make_records(parameters, plan);

        const HonestBaseProofReductionNoiseAssessment assessment =
            aggregate_honest_base_proof_normalization_records(
                plan, parameters, LayerKind::Affine, records);
        CHECK(assessment.reduction_layer == plan.reduction_layer);
        CHECK(assessment.kind == LayerKind::Affine);
        CHECK(assessment.expected_extension_message_count == 5);
        CHECK(assessment.observed_extension_message_count == 5);
        CHECK(assessment.expected_switch_events == plan.switch_events);
        CHECK(assessment.observed_switch_events == plan.switch_events);
        CHECK(assessment.families.size() == 3);
        CHECK(assessment.topology_complete);
        CHECK(assessment.all_messages_fit);
        CHECK(!assessment.first_failure.has_value());

        check_family(
            assessment.families[0],
            HonestBaseProofMessageFamily::AffineRoundAtOne,
            2, 2 * kExtensionDegree, 2, expected_family_maximum(2));
        check_family(
            assessment.families[1],
            HonestBaseProofMessageFamily::AffineRoundAtTwo,
            2, 2 * kExtensionDegree, 2, expected_family_maximum(3));
        check_family(
            assessment.families[2],
            HonestBaseProofMessageFamily::AffineTerminal,
            1, kExtensionDegree, 2, expected_family_maximum(4));
        for (const auto &family : assessment.families) {
            CHECK(family.normalization_steps[0].input_rns_limb_count == 3);
            CHECK(family.normalization_steps[0].output_rns_limb_count == 2);
            CHECK(family.normalization_steps[0].dropped_modulus ==
                  parameters.data_moduli[2]);
            CHECK(family.normalization_steps[1].input_rns_limb_count == 2);
            CHECK(family.normalization_steps[1].output_rns_limb_count == 1);
            CHECK(family.normalization_steps[1].dropped_modulus ==
                  parameters.data_moduli[1]);
            CHECK(family.normalization_steps.back()
                      .output_canonical_error_bound ==
                  family.maximum_post_normalization_canonical_error_bound);
        }
    });

    runner.run("wholly public messages realize an empty planned subset", [] {
        const HonestNoiseEnvelopeParameters parameters = fitting_parameters();
        const HonestBaseProofNormalizationLayerPlan plan =
            make_plan(LayerKind::Affine, 2, 3);
        const std::size_t message_count =
            plan.round_extension_ciphertext_count +
            plan.terminal_extension_ciphertext_count;
        const std::vector<HonestBaseNormalizationRecord> records(
            message_count);

        const HonestBaseProofReductionNoiseAssessment assessment =
            aggregate_honest_base_proof_normalization_records(
                plan, parameters, LayerKind::Affine, records);
        CHECK(assessment.topology_complete);
        CHECK(assessment.all_messages_fit);
        CHECK(!assessment.first_failure.has_value());
        CHECK(assessment.expected_proof_message_switch_events ==
              plan.proof_message_switch_events);
        CHECK(assessment.expected_proof_message_switch_events > 0);
        CHECK(assessment.observed_proof_message_switch_events == 0);
        CHECK(assessment.observed_switch_events ==
              plan.ingress_switch_events);
        for (const auto &family : assessment.families) {
            CHECK(family.base_ciphertext_count == 0);
            CHECK(family.normalization_steps.empty());
            CHECK(family.all_pre_normalization_phases_fit);
            CHECK(family.all_post_normalization_phases_fit);
        }
    });

    runner.run("multiplication records preserve left right and terminal order",
               [] {
        const HonestNoiseEnvelopeParameters parameters =
            fitting_parameters(2);
        const HonestBaseProofNormalizationLayerPlan plan =
            make_plan(LayerKind::Multiplication, 2, 2, 7);
        const std::vector<HonestBaseNormalizationRecord> records =
            make_records(parameters, plan);

        const HonestBaseProofReductionNoiseAssessment assessment =
            aggregate_honest_base_proof_normalization_records(
                plan, parameters, LayerKind::Multiplication, records);
        CHECK(assessment.expected_extension_message_count == 6);
        CHECK(assessment.observed_extension_message_count == 6);
        CHECK(assessment.families.size() == 4);
        CHECK(assessment.topology_complete);
        CHECK(assessment.all_messages_fit);

        const std::array<HonestBaseProofMessageFamily, 4> expected_families{
            HonestBaseProofMessageFamily::MultiplicationRoundPrimary,
            HonestBaseProofMessageFamily::MultiplicationRoundAtTwo,
            HonestBaseProofMessageFamily::MultiplicationLeftTerminal,
            HonestBaseProofMessageFamily::MultiplicationRightTerminal,
        };
        const std::array<std::size_t, 4> maximum_records{2, 3, 4, 5};
        const HonestBaseProofMessageTopology topology =
            derive_honest_base_proof_message_topology(plan);
        for (std::size_t family = 0; family < expected_families.size();
             ++family) {
            check_family(
                assessment.families[family], expected_families[family],
                family < 2 ? 2U : 1U,
                topology.families[family].base_ciphertext_count, 1,
                expected_family_maximum(maximum_records[family]));
        }
    });

    runner.run("one-limb normalization has an empty exact chain", [] {
        const HonestNoiseEnvelopeParameters parameters =
            fitting_parameters(1);
        const HonestBaseProofNormalizationLayerPlan plan =
            make_plan(LayerKind::Affine, 1, 1);
        const std::vector<HonestBaseNormalizationRecord> records =
            make_records(parameters, plan);

        const HonestBaseProofReductionNoiseAssessment assessment =
            aggregate_honest_base_proof_normalization_records(
                plan, parameters, LayerKind::Affine, records);
        CHECK(assessment.topology_complete);
        CHECK(assessment.all_messages_fit);
        CHECK(assessment.expected_switch_events == 0);
        CHECK(assessment.observed_switch_events == 0);
        for (const auto &family : assessment.families) {
            CHECK(family.normalization_steps.empty());
            CHECK(family.maximum_pre_normalization_canonical_error_bound ==
                  family.maximum_post_normalization_canonical_error_bound);
        }
    });

    runner.run("count level component final and plan mismatches fail closed",
               [] {
        const HonestNoiseEnvelopeParameters parameters = fitting_parameters();
        const HonestBaseProofNormalizationLayerPlan plan =
            make_plan(LayerKind::Affine, 1, 3);
        const std::vector<HonestBaseNormalizationRecord> valid =
            make_records(parameters, plan);

        std::vector<HonestBaseNormalizationRecord> altered = valid;
        altered.pop_back();
        auto assessment =
            aggregate_honest_base_proof_normalization_records(
                plan, parameters, LayerKind::Affine, altered);
        CHECK(!assessment.topology_complete);
        CHECK(!assessment.all_messages_fit);
        CHECK(assessment.observed_extension_message_count + 1 ==
              assessment.expected_extension_message_count);

        altered = valid;
        --altered[0].coefficients[0].input_rns_limbs;
        assessment = aggregate_honest_base_proof_normalization_records(
            plan, parameters, LayerKind::Affine, altered);
        CHECK(!assessment.topology_complete);
        CHECK(!assessment.all_messages_fit);

        altered = valid;
        altered[0].coefficients[0].output_component_count = 3;
        assessment = aggregate_honest_base_proof_normalization_records(
            plan, parameters, LayerKind::Affine, altered);
        CHECK(!assessment.topology_complete);
        CHECK(!assessment.all_messages_fit);

        altered = valid;
        altered[0].coefficients[0].output_identity =
            altered[0].coefficients[0].input_identity;
        assessment = aggregate_honest_base_proof_normalization_records(
            plan, parameters, LayerKind::Affine, altered);
        CHECK(!assessment.topology_complete);
        CHECK(!assessment.all_messages_fit);

        altered = valid;
        altered[0].coefficients[0].output_canonical_error_bound =
            NaturalMagnitude(999);
        assessment = aggregate_honest_base_proof_normalization_records(
            plan, parameters, LayerKind::Affine, altered);
        CHECK(!assessment.topology_complete);
        CHECK(!assessment.all_messages_fit);

        HonestBaseProofNormalizationLayerPlan altered_plan = plan;
        ++altered_plan.switch_events;
        assessment = aggregate_honest_base_proof_normalization_records(
            altered_plan, parameters, LayerKind::Affine, valid);
        CHECK(!assessment.topology_complete);
        CHECK(!assessment.all_messages_fit);

        assessment = aggregate_honest_base_proof_normalization_records(
            plan, parameters, LayerKind::Multiplication, valid);
        CHECK(!assessment.topology_complete);
        CHECK(!assessment.all_messages_fit);
    });

    runner.run("consistent sticky and normalization failures remain visible",
               [] {
        const HonestNoiseEnvelopeParameters parameters = fitting_parameters(2);
        const HonestBaseProofNormalizationLayerPlan plan =
            make_plan(LayerKind::Affine, 1, 2);
        std::vector<HonestBaseNormalizationRecord> records =
            make_records(parameters, plan);
        const HonestNoiseEnvelopeFailure sticky{
            .operation = HonestNoiseEnvelopeOperation::Addition,
            .operation_sequence = 17,
            .input_rns_limbs = 2,
            .output_rns_limbs = 2,
            .canonical_error_bound =
                records[0].coefficients[0]
                    .input_canonical_error_bound,
            .active_modulus_product_bits =
                NaturalMagnitude::product(parameters.data_moduli).bit_count(),
        };
        records[0].coefficients[0].input_first_failure = sticky;
        records[0].coefficients[0].output_first_failure = sticky;

        auto assessment =
            aggregate_honest_base_proof_normalization_records(
                plan, parameters, LayerKind::Affine, records);
        CHECK(assessment.topology_complete);
        CHECK(!assessment.all_messages_fit);
        CHECK(assessment.first_failure.has_value());
        CHECK(assessment.first_failure->family ==
              HonestBaseProofMessageFamily::AffineRoundAtOne);
        CHECK(assessment.first_failure->message_occurrence == 0);
        CHECK(assessment.first_failure->coefficient_index == 0);
        CHECK(assessment.first_failure->stage ==
              HonestBaseProofNoiseFailureStage::PreNormalization);
        CHECK(!assessment.first_failure->normalization_step.has_value());

        std::vector<HonestBaseNormalizationRecord> ordered_failures =
            make_records(parameters, plan);
        HonestNoiseEnvelopeFailure later_sequence = sticky;
        later_sequence.operation_sequence = 30;
        ordered_failures[0].coefficients[0].input_first_failure =
            later_sequence;
        ordered_failures[0].coefficients[0].output_first_failure =
            later_sequence;
        HonestNoiseEnvelopeFailure earlier_sequence = sticky;
        earlier_sequence.operation_sequence = 5;
        ordered_failures[1].coefficients[1].input_first_failure =
            earlier_sequence;
        ordered_failures[1].coefficients[1].output_first_failure =
            earlier_sequence;
        assessment = aggregate_honest_base_proof_normalization_records(
            plan, parameters, LayerKind::Affine, ordered_failures);
        CHECK(assessment.topology_complete);
        CHECK(!assessment.all_messages_fit);
        CHECK(assessment.first_failure.has_value());
        CHECK(assessment.first_failure->family ==
              HonestBaseProofMessageFamily::AffineRoundAtTwo);
        CHECK(assessment.first_failure->message_occurrence == 0);
        CHECK(assessment.first_failure->coefficient_index == 1);
        CHECK(assessment.first_failure->stage ==
              HonestBaseProofNoiseFailureStage::PreNormalization);

        std::vector<HonestBaseNormalizationRecord> cross_stage_failures =
            make_records(parameters, plan);
        cross_stage_failures[0].coefficients[0].input_first_failure =
            later_sequence;
        cross_stage_failures[0].coefficients[0].output_first_failure =
            later_sequence;
        HonestNoiseEnvelopeFailure earlier_post_failure = sticky;
        earlier_post_failure.operation_sequence = 5;
        cross_stage_failures[1].coefficients[1].output_first_failure =
            earlier_post_failure;
        assessment = aggregate_honest_base_proof_normalization_records(
            plan, parameters, LayerKind::Affine, cross_stage_failures);
        CHECK(!assessment.topology_complete);
        CHECK(!assessment.all_messages_fit);
        CHECK(assessment.first_failure.has_value());
        CHECK(assessment.first_failure->family ==
              HonestBaseProofMessageFamily::AffineRoundAtTwo);
        CHECK(assessment.first_failure->message_occurrence == 0);
        CHECK(assessment.first_failure->coefficient_index == 1);
        CHECK(assessment.first_failure->stage ==
              HonestBaseProofNoiseFailureStage::PostNormalization);
        CHECK(!assessment.first_failure->normalization_step.has_value());

        records[0].coefficients[0].output_first_failure.reset();
        assessment = aggregate_honest_base_proof_normalization_records(
            plan, parameters, LayerKind::Affine, records);
        CHECK(!assessment.topology_complete);
        CHECK(!assessment.all_messages_fit);

        const HonestNoiseEnvelopeParameters small =
            failing_bottom_parameters();
        const HonestBaseProofNormalizationLayerPlan small_plan =
            make_plan(LayerKind::Affine, 1, 2);
        const std::vector<HonestBaseNormalizationRecord> failing_records =
            make_records(small, small_plan, true);
        assessment = aggregate_honest_base_proof_normalization_records(
            small_plan, small, LayerKind::Affine, failing_records);
        CHECK(assessment.topology_complete);
        CHECK(!assessment.all_messages_fit);
        CHECK(assessment.first_failure.has_value());
        CHECK(assessment.first_failure->stage ==
              HonestBaseProofNoiseFailureStage::NormalizationStep);
        CHECK(assessment.first_failure->normalization_step ==
              std::optional<std::size_t>(0));
        CHECK(!assessment.families[0].normalization_steps[0]
                   .output_phase_fits);
    });

    return runner.summary();
}
