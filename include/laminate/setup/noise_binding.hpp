#ifndef LAMINATE_SETUP_NOISE_BINDING_HPP
#define LAMINATE_SETUP_NOISE_BINDING_HPP

/// @file setup/noise_binding.hpp
/// @brief Bind accepted payload and Base proof-noise schedules to setup.

#include "laminate/setup/public.hpp"

namespace laminate {

namespace fhe {
struct HonestNoiseEnvelopeParameters;
}

namespace payload {
class CertifiedHonestBaseProofIngressSelection;
struct HonestPayloadNoiseSchedule;
}

/// Bind one accepted payload-core schedule without a Base proof assessment.
PublicSetup bind_honest_payload_noise_schedule(
    PublicSetup setup, const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &layered,
    const payload::HonestPayloadNoiseSchedule &schedule);

/// Bind the fixed uniform Base proof schedule after exact certification.
PublicSetup bind_uniform_honest_base_proof_schedule(
    PublicSetup setup, const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &layered,
    const payload::HonestPayloadNoiseSchedule &schedule);

PublicSetup bind_certified_uniform_honest_base_proof_schedule(
    PublicSetup setup, const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &layered,
    const payload::CertifiedHonestPayloadSchedule &schedule);

/// Validate and bind an attached Base proof-noise assessment.
PublicSetup bind_honest_base_proof_noise_assessment(
    PublicSetup setup, const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &layered,
    const payload::HonestPayloadNoiseSchedule &schedule,
    fhe::HonestNoiseEnvelopeParameters parameters);

/// Bind the exhaustive selector's already certified minimal schedule.
PublicSetup bind_certified_honest_base_proof_noise_assessment(
    PublicSetup setup, const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &layered,
    const payload::CertifiedHonestBaseProofIngressSelection &selection);

} // namespace laminate

#endif // LAMINATE_SETUP_NOISE_BINDING_HPP
