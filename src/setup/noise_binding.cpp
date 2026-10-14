#include "laminate/setup/noise_binding.hpp"

#include "laminate/payload/noise/honest_base_proof_noise.hpp"
#include "laminate/payload/noise/honest_noise_schedule.hpp"

#include <stdexcept>
#include <utility>

namespace laminate {

void PublicSetup::validate_certified_payload_schedule(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &layered,
    const payload::CertifiedHonestPayloadSchedule &certified) const {
    validate(payload, layered);
    certified.validate_circuit_digest(layered_digest);
    const payload::HonestPayloadNoiseSchedule &schedule =
        certified.schedule();
    if (!schedule.payload_model_accepts()) {
        throw std::invalid_argument(
            "PublicSetup: honest payload schedule is not accepted by its "
            "payload operational model");
    }
    if (!honest_payload_noise_schedule_digest ||
        *honest_payload_noise_schedule_digest != certified.digest()) {
        throw std::invalid_argument(
            "PublicSetup: honest payload schedule binding is absent or "
            "does not match");
    }

    if (!schedule.base_proof_noise_assessment) {
        if (honest_base_proof_noise_assessment_digest) {
            throw std::invalid_argument(
                "PublicSetup: Base proof-noise binding is present for a "
                "payload-only schedule");
        }
        return;
    }

    const payload::HonestBaseProofNoiseAssessment &assessment =
        *schedule.base_proof_noise_assessment;
    if (!assessment.report_accepts() ||
        assessment.observed_switch_events >
            schedule.modeled_base_proof_switch_events) {
        throw std::invalid_argument(
            "PublicSetup: Base proof-noise report does not satisfy its "
            "bound predicate state");
    }
    if (!honest_base_proof_noise_assessment_digest ||
        !certified.proof_assessment_digest() ||
        *honest_base_proof_noise_assessment_digest !=
            *certified.proof_assessment_digest()) {
        throw std::invalid_argument(
            "PublicSetup: Base proof-noise assessment binding is absent "
            "or does not match");
    }
}

PublicSetup bind_honest_payload_noise_schedule(
    PublicSetup setup, const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &layered,
    const payload::HonestPayloadNoiseSchedule &schedule) {
    setup.validate(payload, layered);
    if (!schedule.base_proof_ingress_policy.empty() ||
        schedule.base_proof_noise_assessment ||
        setup.honest_base_proof_noise_assessment_digest) {
        throw std::invalid_argument(
            "bind_honest_payload_noise_schedule: payload-only binding "
            "cannot carry a Base proof-noise assessment");
    }
    if (!schedule.payload_model_accepts()) {
        throw std::invalid_argument(
            "bind_honest_payload_noise_schedule: schedule is not accepted "
            "by its payload operational model");
    }
    setup.honest_payload_noise_schedule_digest =
        payload::honest_payload_noise_schedule_digest(layered, schedule);
    return setup;
}

PublicSetup bind_uniform_honest_base_proof_schedule(
    PublicSetup setup, const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &layered,
    const payload::HonestPayloadNoiseSchedule &schedule) {
    return bind_certified_uniform_honest_base_proof_schedule(
        std::move(setup), payload, layered,
        payload::certify_honest_payload_noise_schedule(layered, schedule));
}

PublicSetup bind_certified_uniform_honest_base_proof_schedule(
    PublicSetup setup, const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &layered,
    const payload::CertifiedHonestPayloadSchedule &certified) {
    setup.validate(payload, layered);
    certified.validate_circuit_digest(setup.layered_digest);
    const payload::HonestPayloadNoiseSchedule &schedule =
        certified.schedule();
    if (schedule.base_proof_ingress_policy !=
            payload::kUniformBaseProofIngressPolicyV1 ||
        schedule.base_proof_noise_assessment ||
        setup.honest_base_proof_noise_assessment_digest ||
        !schedule.payload_model_accepts()) {
        throw std::invalid_argument(
            "bind_certified_uniform_honest_base_proof_schedule: schedule is "
            "not an accepted fixed uniform Base proof schedule");
    }
    setup.honest_payload_noise_schedule_digest = certified.digest();
    return setup;
}

PublicSetup bind_honest_base_proof_noise_assessment(
    PublicSetup setup, const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &layered,
    const payload::HonestPayloadNoiseSchedule &schedule,
    fhe::HonestNoiseEnvelopeParameters parameters) {
    setup.validate(payload, layered);
    if (!payload::honest_base_proof_ingress_is_minimal(
            layered, schedule, std::move(parameters))) {
        throw std::invalid_argument(
            "bind_honest_base_proof_noise_assessment: attached report "
            "does not admit the minimal setup-certified Base execution");
    }

    setup.honest_payload_noise_schedule_digest =
        payload::honest_payload_noise_schedule_digest(layered, schedule);
    setup.honest_base_proof_noise_assessment_digest =
        payload::honest_base_proof_noise_assessment_digest(
            *schedule.base_proof_noise_assessment);
    return setup;
}

PublicSetup bind_certified_honest_base_proof_noise_assessment(
    PublicSetup setup, const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &layered,
    const payload::CertifiedHonestBaseProofIngressSelection &selection) {
    setup.validate(payload, layered);
    const payload::HonestPayloadNoiseSchedule &schedule =
        selection.schedule();
    payload::validate_honest_base_proof_noise_assessment_binding(
        layered, schedule);
    if (!schedule.payload_model_accepts() ||
        !schedule.base_proof_noise_assessment->report_accepts() ||
        schedule.base_proof_noise_assessment->observed_switch_events >
            schedule.modeled_base_proof_switch_events) {
        throw std::invalid_argument(
            "bind_certified_honest_base_proof_noise_assessment: certified "
            "selection is not accepted");
    }

    setup.honest_payload_noise_schedule_digest =
        payload::honest_payload_noise_schedule_digest(layered, schedule);
    setup.honest_base_proof_noise_assessment_digest =
        payload::honest_base_proof_noise_assessment_digest(
            *schedule.base_proof_noise_assessment);
    return setup;
}

} // namespace laminate
