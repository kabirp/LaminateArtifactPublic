/// @file honest_base_proof_noise_assessor.cpp
/// @brief One-reduction operational Base proof-noise assessment.

#include "laminate/payload/noise/honest_base_proof_noise.hpp"

#include "laminate/gates/gate_mle.hpp"
#include "laminate/gkr/detail/base/affine/prover.hpp"
#include "laminate/gkr/detail/base/multiplication/prover.hpp"

#include <bit>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace laminate::payload {
namespace {

using Backend = fhe::HonestNoiseEnvelopeBackend;
using gkr::base_detail::BaseAffineStatistics;
using gkr::base_detail::HonestBaseVirtualSource;
using gkr::base_detail::HonestBaseVirtualSourceAuditCounters;

std::uint64_t checked_u64(std::size_t value, const char *description) {
    if constexpr (sizeof(std::size_t) > sizeof(std::uint64_t)) {
        if (value > std::numeric_limits<std::uint64_t>::max()) {
            throw std::overflow_error(description);
        }
    }
    return static_cast<std::uint64_t>(value);
}

std::uint64_t checked_product(std::uint64_t left, std::size_t right,
                              const char *description) {
    const std::uint64_t converted = checked_u64(right, description);
    if (left != 0 &&
        converted > std::numeric_limits<std::uint64_t>::max() / left) {
        throw std::overflow_error(description);
    }
    return left * converted;
}

std::size_t checked_sum(std::size_t left, std::size_t right,
                        const char *description) {
    if (right > std::numeric_limits<std::size_t>::max() - left) {
        throw std::overflow_error(description);
    }
    return left + right;
}

void checked_accumulate(std::uint64_t &destination, std::uint64_t value,
                        const char *description) {
    if (value > std::numeric_limits<std::uint64_t>::max() - destination) {
        throw std::overflow_error(description);
    }
    destination += value;
}

void checked_accumulate_size(std::uint64_t &destination, std::size_t value,
                             const char *description) {
    checked_accumulate(destination, checked_u64(value, description),
                       description);
}

gkr::SingleClaim deterministic_zero_claim(
    const LayeredCircuit &circuit, std::size_t reduction_layer) {
    return gkr::SingleClaim{
        std::vector<Fpk>(
            gkr::base_detail::layer_vars(circuit, reduction_layer),
            Fpk::zero()),
        Fpk::zero(),
    };
}

const HonestBaseProofNormalizationLayerPlan &normalization_plan_for(
    const LayeredCircuit &circuit,
    const HonestPayloadNoiseSchedule &schedule,
    std::size_t reduction_layer) {
    validate_honest_payload_noise_schedule_core(circuit, schedule);
    validate_honest_base_proof_normalization_plan(
        circuit, schedule.evaluation_plan,
        schedule.base_proof_normalization_plan);
    if (reduction_layer + 1U >= circuit.layers.size() ||
        reduction_layer >=
            schedule.base_proof_normalization_plan.reductions.size()) {
        throw std::out_of_range(
            "honest Base proof-noise reduction layer is out of range");
    }
    const HonestBaseProofNormalizationLayerPlan &plan =
        schedule.base_proof_normalization_plan.reductions.at(
            reduction_layer);
    if (plan.reduction_layer != reduction_layer ||
        plan.kind != layer_kind(circuit.layers.at(reduction_layer))) {
        throw std::logic_error(
            "honest Base proof-noise normalization plan is misordered");
    }
    return plan;
}

void validate_affine_execution_audit(
    const HonestBaseVirtualSource &source,
    const BaseAffineStatistics &statistics,
    const HonestBaseVirtualSourceAuditCounters &virtual_source) {
    const LayerWireSupport &support = source.descriptor().source_support;
    const std::uint64_t expected_source_records = checked_product(
        statistics.source_scans, support.live_wire_count,
        "honest Base affine source-record count overflows");
    const std::uint64_t expected_source_ciphertexts = checked_product(
        statistics.source_scans,
        source.source_ciphertext_objects_per_scan(),
        "honest Base affine source-ciphertext count overflows");
    const std::uint64_t expected_padding = checked_product(
        statistics.source_scans,
        support.padded_wire_count - support.live_wire_count,
        "honest Base affine padding count overflows");
    if (statistics.source_ciphertexts_read != expected_source_ciphertexts ||
        virtual_source.source_objects_returned != expected_source_records ||
        virtual_source.source_ciphertext_objects_returned !=
            expected_source_ciphertexts ||
        virtual_source.contribution_objects_returned != 0 ||
        statistics.public_zero_positions != expected_padding ||
        virtual_source.structural_padding_positions_skipped !=
            expected_padding ||
        virtual_source.padding_objects_returned != 0) {
        throw std::logic_error(
            "honest Base affine virtual-source audit drifted");
    }
}

void validate_multiplication_execution_audit(
    const HonestBaseVirtualSource &source,
    const gkr::detail::FileBackedMultiplicationStatistics &statistics,
    const HonestBaseVirtualSourceAuditCounters &virtual_source) {
    const auto &descriptor = source.descriptor();
    const std::uint64_t expected_pairs = checked_product(
        statistics.artifact_scans, descriptor.live_pair_count,
        "honest Base multiplication pair count overflows");
    const std::uint64_t expected_values = checked_product(
        statistics.artifact_scans, descriptor.stored_value_count,
        "honest Base multiplication value count overflows");
    const std::uint64_t expected_ciphertexts = checked_product(
        statistics.artifact_scans,
        source.source_ciphertext_objects_per_scan(),
        "honest Base multiplication ciphertext count overflows");
    const std::uint64_t expected_padding = checked_product(
        statistics.artifact_scans,
        descriptor.pair_count - descriptor.live_pair_count,
        "honest Base multiplication padding-pair count overflows");
    if (statistics.artifact_pairs_read != expected_pairs ||
        statistics.artifact_values_read != expected_values ||
        virtual_source.source_objects_returned != expected_values ||
        virtual_source.source_ciphertext_objects_returned !=
            expected_ciphertexts ||
        virtual_source.contribution_objects_returned != 0 ||
        virtual_source.structural_padding_positions_skipped !=
            expected_padding ||
        virtual_source.padding_objects_returned != 0) {
        throw std::logic_error(
            "honest Base multiplication virtual-source audit drifted "
            "(scans=" + std::to_string(statistics.artifact_scans) +
            ", pairs=" + std::to_string(statistics.artifact_pairs_read) +
            "/" + std::to_string(expected_pairs) + ", values=" +
            std::to_string(statistics.artifact_values_read) + "/" +
            std::to_string(expected_values) + ", objects=" +
            std::to_string(virtual_source.source_objects_returned) +
            ", skipped=" + std::to_string(
                virtual_source.structural_padding_positions_skipped) +
            "/" + std::to_string(expected_padding) + ")");
    }
}

void validate_family_assessment(
    const HonestBaseProofMessageFamilyAssessment &family,
    const HonestBaseProofMessageFamilyTopology &expected,
    const HonestBaseProofNormalizationLayerPlan &plan) {
    if (family.family != expected.family ||
        family.extension_message_count !=
            expected.extension_message_count ||
        family.base_ciphertext_count > expected.base_ciphertext_count ||
        family.source_rns_limb_count !=
            plan.proof_ingress_rns_limb_count ||
        plan.proof_ingress_rns_limb_count == 0 ||
        family.normalization_steps.size() !=
            (family.base_ciphertext_count == 0
                 ? 0U
                 : plan.proof_ingress_rns_limb_count - 1U)) {
        throw std::logic_error(
            "honest Base proof-noise message-family parity drifted");
    }
}

void validate_reduction_assessment(
    const HonestBaseProofNormalizationLayerPlan &plan,
    const HonestBaseProofReductionNoiseAssessment &assessment) {
    const std::size_t expected_extensions = checked_sum(
        plan.round_extension_ciphertext_count,
        plan.terminal_extension_ciphertext_count,
        "honest Base reduction extension-message count overflows");
    const std::size_t expected_ingress_steps =
        plan.natural_source_rns_limb_count -
        plan.proof_ingress_rns_limb_count;
    const bool ingress_failure_is_valid =
        !assessment.first_failed_ingress_step ||
        *assessment.first_failed_ingress_step <
            assessment.ingress_normalization_steps.size();
    if (!assessment.topology_complete ||
        assessment.reduction_layer != plan.reduction_layer ||
        assessment.kind != plan.kind ||
        assessment.natural_source_rns_limb_count !=
            plan.natural_source_rns_limb_count ||
        assessment.proof_ingress_rns_limb_count !=
            plan.proof_ingress_rns_limb_count ||
        assessment.live_source_ciphertext_count !=
            plan.live_source_ciphertext_count ||
        assessment.source_rns_limb_count !=
            plan.proof_ingress_rns_limb_count ||
        assessment.natural_source_canonical_error_bound.is_zero() ||
        assessment.proof_ingress_canonical_error_bound.is_zero() ||
        assessment.ingress_normalization_steps.size() !=
            expected_ingress_steps ||
        !ingress_failure_is_valid ||
        assessment.all_ingress_phases_fit !=
            (assessment.ingress_input_phase_fits &&
             !assessment.first_failed_ingress_step.has_value()) ||
        assessment.wire_variables != plan.wire_variables ||
        assessment.expected_extension_message_count !=
            expected_extensions ||
        assessment.observed_extension_message_count !=
            expected_extensions ||
        assessment.ingress_switch_events != plan.ingress_switch_events ||
        assessment.expected_proof_message_switch_events !=
            plan.proof_message_switch_events ||
        assessment.observed_proof_message_switch_events >
            plan.proof_message_switch_events ||
        assessment.expected_switch_events != plan.switch_events ||
        assessment.observed_switch_events > plan.switch_events) {
        throw std::logic_error(
            "honest Base proof-noise reduction parity drifted");
    }

    const HonestBaseProofMessageTopology topology =
        derive_honest_base_proof_message_topology(plan);
    if (plan.round_extension_ciphertext_count !=
            topology.round_extension_message_count ||
        plan.terminal_extension_ciphertext_count !=
            topology.terminal_extension_message_count ||
        plan.public_zero_extension_message_count !=
            topology.public_zero_extension_message_count ||
        plan.base_ciphertext_count != topology.base_ciphertext_count ||
        assessment.families.size() != topology.families.size()) {
        throw std::logic_error(
            "honest Base proof-noise family topology differs from plan");
    }

    std::size_t family_extensions = 0;
    std::size_t family_base_ciphertexts = 0;
    for (std::size_t index = 0; index < topology.families.size(); ++index) {
        const HonestBaseProofMessageFamilyTopology &expected =
            topology.families[index];
        validate_family_assessment(
            assessment.families[index], expected, plan);
        family_extensions = checked_sum(
            family_extensions, expected.extension_message_count,
            "honest Base family-message total overflows");
        family_base_ciphertexts = checked_sum(
            family_base_ciphertexts,
            assessment.families[index].base_ciphertext_count,
            "honest Base family-ciphertext total overflows");
    }

    const std::uint64_t observed_proof_switch_events = checked_product(
        checked_u64(family_base_ciphertexts,
                    "honest Base family-ciphertext count"),
        plan.proof_ingress_rns_limb_count - 1U,
        "honest Base observed proof-switch count overflows");
    std::uint64_t observed_switch_events = plan.ingress_switch_events;
    checked_accumulate(
        observed_switch_events, observed_proof_switch_events,
        "honest Base observed switch count overflows");
    if (family_extensions != expected_extensions ||
        family_base_ciphertexts > plan.base_ciphertext_count ||
        assessment.observed_proof_message_switch_events !=
            observed_proof_switch_events ||
        assessment.observed_switch_events != observed_switch_events) {
        throw std::logic_error(
            "honest Base proof-noise family totals differ from plan");
    }
}

void accumulate_execution_audit(
    HonestBaseProofNoiseExecutionAudit &total,
    const HonestBaseProofReductionNoiseAssessment &assessment,
    const HonestBaseProofReductionNoiseExecutionAudit &reduction) {
    checked_accumulate_size(
        total.normalization_records_observed,
        assessment.observed_extension_message_count,
        "honest Base normalization-observation total overflows");
    checked_accumulate(total.backend_operation_count,
                       reduction.backend_operation_count,
                       "honest Base backend-operation total overflows");
    checked_accumulate(
        total.virtual_source.source_objects_returned,
        reduction.virtual_source.source_objects_returned,
        "honest Base source-object total overflows");
    checked_accumulate(
        total.virtual_source.source_ciphertext_objects_returned,
        reduction.virtual_source.source_ciphertext_objects_returned,
        "honest Base source-ciphertext total overflows");
    checked_accumulate(
        total.virtual_source.contribution_objects_returned,
        reduction.virtual_source.contribution_objects_returned,
        "honest Base contribution-object total overflows");
    checked_accumulate(
        total.virtual_source.structural_padding_positions_skipped,
        reduction.virtual_source.structural_padding_positions_skipped,
        "honest Base skipped-padding total overflows");
    checked_accumulate(
        total.virtual_source.padding_objects_returned,
        reduction.virtual_source.padding_objects_returned,
        "honest Base padding-object total overflows");
    total.reductions.push_back(reduction);
}

} // namespace

HonestBaseProofReductionNoiseAssessment
assess_honest_base_proof_reduction_noise(
    const LayeredCircuit &circuit,
    const HonestPayloadNoiseSchedule &schedule,
    std::size_t reduction_layer,
    fhe::HonestNoiseEnvelopeParameters parameters,
    Transcript &transcript,
    HonestBaseProofReductionNoiseExecutionAudit *execution_audit) {
    const HonestBaseProofNormalizationLayerPlan &plan =
        normalization_plan_for(circuit, schedule, reduction_layer);
    parameters.validate();
    auto contexts = Backend::create(std::move(parameters));
    const HonestBaseVirtualSource source(
        circuit, schedule, reduction_layer, contexts.eval);
    if (source.natural_source_rns_limb_count() !=
            plan.natural_source_rns_limb_count ||
        source.source_rns_limb_count() !=
            plan.proof_ingress_rns_limb_count ||
        source.descriptor().source_layer.required_mult_depth + 1U !=
            plan.proof_ingress_rns_limb_count) {
        throw std::logic_error(
            "honest Base proof-noise source boundary differs from plan");
    }

    Backend::clear_base_message_normalization_records(contexts.eval);
    HonestBaseProofReductionNoiseExecutionAudit audit{
        .kind = plan.kind,
    };
    const std::uint64_t first_backend_operation =
        contexts.eval.sequences->next_operation;
    const gkr::SingleClaim claim =
        deterministic_zero_claim(circuit, reduction_layer);
    if (plan.kind == LayerKind::Affine) {
        gates::DirectGateMle gate_mle(circuit);
        const gkr::LayerClaim layer_claim = claim;
        BaseAffineStatistics statistics;
        (void)gkr::base_detail::prove_affine_reduction<Backend>(
            contexts.eval, circuit, source,
            source.layer_support(reduction_layer + 1U), reduction_layer,
            layer_claim, gate_mle, transcript, nullptr, &statistics);
        audit.affine = statistics;
    } else if (plan.kind == LayerKind::Multiplication) {
        gkr::detail::FileBackedMultiplicationStatistics statistics;
        (void)gkr::base_detail::prove_multiplication_reduction<Backend>(
            contexts.eval, circuit, source, reduction_layer, claim,
            transcript, &statistics);
        audit.multiplication = statistics;
    } else {
        throw std::logic_error(
            "honest Base proof-noise reduction has unknown layer kind");
    }
    if (contexts.eval.sequences->next_operation < first_backend_operation) {
        throw std::logic_error(
            "honest Base proof-noise backend operation counter regressed");
    }
    audit.backend_operation_count =
        contexts.eval.sequences->next_operation - first_backend_operation;
    const std::span<const fhe::HonestBaseNormalizationRecord> records =
        Backend::base_message_normalization_records(contexts.eval);
    audit.observed_message_coordinate_masks.reserve(records.size());
    for (const fhe::HonestBaseNormalizationRecord &record : records) {
        HonestBaseProofCoordinateMask mask = 0;
        for (std::size_t coefficient = 0;
             coefficient < kExtensionDegree; ++coefficient) {
            if (record.coefficients[coefficient].present) {
                mask = static_cast<HonestBaseProofCoordinateMask>(
                    mask | (HonestBaseProofCoordinateMask{1}
                            << coefficient));
            }
        }
        audit.observed_message_coordinate_masks.push_back(mask);
    }
    const std::size_t expected_extensions = checked_sum(
        plan.round_extension_ciphertext_count,
        plan.terminal_extension_ciphertext_count,
        "honest Base proof-noise extension-message count overflows");
    if (records.size() != expected_extensions) {
        throw std::logic_error(
            "honest Base proof-noise observer count differs from plan");
    }
    if (audit.observed_message_coordinate_masks.size() !=
        plan.message_coordinate_masks.size()) {
        throw std::logic_error(
            "honest Base proof-noise observer support count differs from "
            "plan");
    }
    for (std::size_t message = 0;
         message < plan.message_coordinate_masks.size(); ++message) {
        const HonestBaseProofCoordinateMask observed =
            audit.observed_message_coordinate_masks[message];
        const HonestBaseProofCoordinateMask planned =
            plan.message_coordinate_masks[message];
        if ((observed & static_cast<HonestBaseProofCoordinateMask>(~planned)) ==
            0) {
            continue;
        }
        throw std::logic_error(
            "honest Base proof-noise observer support exceeds plan at "
            "message " + std::to_string(message) + " (planned " +
            std::to_string(plan.message_coordinate_masks[message]) +
            ", observed " + std::to_string(
                audit.observed_message_coordinate_masks[message]) + ")");
    }
    std::size_t observed_proof_ciphertexts = 0;
    for (const HonestBaseProofCoordinateMask mask :
         audit.observed_message_coordinate_masks) {
        observed_proof_ciphertexts = checked_sum(
            observed_proof_ciphertexts,
            static_cast<std::size_t>(std::popcount(mask)),
            "honest Base observed proof-ciphertext count overflows");
    }
    if (audit.backend_operation_count == 0 &&
        (source.source_ciphertext_objects_per_scan() != 0 ||
         observed_proof_ciphertexts != 0)) {
        throw std::logic_error(
            "honest Base proof-noise reduction omitted backend work");
    }

    source.assert_no_padding_objects();
    audit.virtual_source = source.audit_counters();
    if (audit.affine) {
        validate_affine_execution_audit(
            source, *audit.affine, audit.virtual_source);
    } else if (audit.multiplication) {
        validate_multiplication_execution_audit(
            source, *audit.multiplication,
            audit.virtual_source);
    } else {
        throw std::logic_error(
            "honest Base proof-noise execution produced no stream audit");
    }

    HonestBaseProofReductionNoiseAssessment assessment =
        aggregate_honest_base_proof_normalization_records(
            plan, contexts.eval.parameters, plan.kind, records);
    assessment.natural_source_canonical_error_bound =
        source.natural_source_canonical_error_bound();
    assessment.proof_ingress_canonical_error_bound =
        source.source_canonical_error_bound();
    assessment.ingress_input_phase_fits =
        source.ingress_input_phase_fits();
    assessment.ingress_normalization_steps =
        source.ingress_normalization_steps();
    assessment.first_failed_ingress_step =
        source.first_failed_ingress_step();
    assessment.all_ingress_phases_fit =
        source.all_ingress_phases_fit();
    assessment.all_messages_fit =
        assessment.all_messages_fit && assessment.all_ingress_phases_fit;
    if (assessment.expected_extension_message_count !=
            expected_extensions ||
        assessment.observed_extension_message_count != records.size() ||
        assessment.expected_proof_message_switch_events !=
            plan.proof_message_switch_events ||
        assessment.observed_proof_message_switch_events >
            plan.proof_message_switch_events ||
        assessment.expected_switch_events != plan.switch_events ||
        assessment.observed_switch_events > plan.switch_events) {
        throw std::logic_error(
            "honest Base proof-noise aggregation differs from plan");
    }
    if (execution_audit != nullptr) {
        *execution_audit = std::move(audit);
    }
    return assessment;
}

HonestBaseProofNoiseAssessment assess_honest_base_proof_noise(
    const LayeredCircuit &circuit,
    const HonestPayloadNoiseSchedule &schedule,
    fhe::HonestNoiseEnvelopeParameters parameters,
    HonestBaseProofNoiseExecutionAudit *execution_audit) {
    validate_honest_payload_noise_schedule_core(circuit, schedule);
    parameters.validate();

    const HonestBaseProofNormalizationPlan &normalization =
        schedule.base_proof_normalization_plan;
    if (circuit.layers.empty() ||
        normalization.reductions.size() != circuit.layers.size() - 1U ||
        normalization.ingress_switch_events !=
            schedule.modeled_base_proof_ingress_switch_events ||
        normalization.proof_message_switch_events !=
            schedule.modeled_base_proof_message_switch_events ||
        normalization.switch_events !=
            schedule.modeled_base_proof_switch_events) {
        throw std::logic_error(
            "honest Base proof-noise all-layer plan parity drifted");
    }

    Transcript zero_history(
        "LaminateImpl/HonestBaseProofNoiseAssessment/zero-history/v2");
    zero_history.observe(
        "LaminateImpl/HonestBaseProofNoiseAssessment/history-seed",
        std::uint64_t{0});
    Transcript dense_history(
        "LaminateImpl/HonestBaseProofNoiseAssessment/dense-history/v2");
    dense_history.observe(
        "LaminateImpl/HonestBaseProofNoiseAssessment/history-seed",
        std::uint64_t{0xd6e8feb86659fd93ULL});

    HonestBaseProofNoiseAssessment result{
        .policy = kHonestBaseProofNoiseAssessmentPolicyV6,
        .source_payload_schedule_digest =
            honest_payload_noise_schedule_digest(circuit, schedule),
        .proof_noise_parameters_digest =
            fhe::honest_noise_envelope_parameters_digest(parameters),
        .observed_switch_events = 0,
        .topology_complete = true,
        .all_messages_fit = true,
    };
    HonestBaseProofNoiseExecutionAudit audit;
    result.reductions.reserve(normalization.reductions.size());
    audit.reductions.reserve(normalization.reductions.size());

    std::uint64_t expected_ingress_switch_events = 0;
    std::uint64_t observed_ingress_switch_events = 0;
    std::uint64_t expected_proof_message_switch_events = 0;
    std::uint64_t observed_proof_message_switch_events = 0;
    std::uint64_t expected_switch_events = 0;
    std::uint64_t observed_switch_events = 0;
    std::uint64_t expected_normalization_records = 0;
    for (std::size_t index = 0; index < normalization.reductions.size();
         ++index) {
        const HonestBaseProofNormalizationLayerPlan &plan =
            normalization.reductions[index];
        if (plan.reduction_layer != index) {
            throw std::logic_error(
                "honest Base proof-noise reductions are not canonical");
        }

        HonestBaseProofReductionNoiseExecutionAudit zero_audit;
        HonestBaseProofReductionNoiseExecutionAudit dense_audit;
        HonestBaseProofReductionNoiseAssessment zero_assessment =
            assess_honest_base_proof_reduction_noise(
                circuit, schedule, index, parameters, zero_history,
                &zero_audit);
        const HonestBaseProofReductionNoiseAssessment dense_assessment =
            assess_honest_base_proof_reduction_noise(
                circuit, schedule, index, parameters, dense_history,
                &dense_audit);
        if (zero_assessment != dense_assessment ||
            zero_audit != dense_audit) {
            throw std::logic_error(
                "honest Base proof-noise assessment depends on transcript "
                "history");
        }

        validate_reduction_assessment(plan, zero_assessment);
        checked_accumulate(expected_ingress_switch_events,
                           plan.ingress_switch_events,
                           "honest Base expected-ingress total overflows");
        checked_accumulate(observed_ingress_switch_events,
                           zero_assessment.ingress_switch_events,
                           "honest Base observed-ingress total overflows");
        checked_accumulate(
            expected_proof_message_switch_events,
            plan.proof_message_switch_events,
            "honest Base expected-message-switch total overflows");
        checked_accumulate(
            observed_proof_message_switch_events,
            zero_assessment.observed_proof_message_switch_events,
            "honest Base observed-message-switch total overflows");
        checked_accumulate(expected_switch_events,
                           zero_assessment.expected_switch_events,
                           "honest Base expected-switch total overflows");
        checked_accumulate(observed_switch_events,
                           zero_assessment.observed_switch_events,
                           "honest Base observed-switch total overflows");
        checked_accumulate_size(
            expected_normalization_records,
            zero_assessment.expected_extension_message_count,
            "honest Base expected-observation total overflows");
        accumulate_execution_audit(audit, zero_assessment, zero_audit);

        if (!result.first_failure && zero_assessment.first_failure) {
            result.first_failure = zero_assessment.first_failure;
        }
        result.topology_complete =
            result.topology_complete && zero_assessment.topology_complete;
        result.all_messages_fit =
            result.all_messages_fit && zero_assessment.all_messages_fit;
        result.reductions.push_back(std::move(zero_assessment));
    }

    if (expected_ingress_switch_events !=
            normalization.ingress_switch_events ||
        observed_ingress_switch_events !=
            normalization.ingress_switch_events ||
        expected_proof_message_switch_events !=
            normalization.proof_message_switch_events ||
        observed_proof_message_switch_events >
            normalization.proof_message_switch_events ||
        expected_switch_events != normalization.switch_events ||
        observed_switch_events > normalization.switch_events ||
        audit.normalization_records_observed !=
            expected_normalization_records ||
        audit.reductions.size() != normalization.reductions.size()) {
        throw std::logic_error(
            "honest Base proof-noise all-layer totals differ from plan");
    }
    audit.virtual_source.assert_no_padding_objects();
    result.observed_switch_events = observed_switch_events;
    result.topology_complete =
        result.topology_complete &&
        result.reductions.size() == normalization.reductions.size();
    result.all_messages_fit = result.topology_complete &&
                              result.all_messages_fit &&
                              !result.first_failure.has_value();
    if (execution_audit != nullptr) {
        *execution_audit = std::move(audit);
    }
    return result;
}

} // namespace laminate::payload
