#ifndef LAMINATE_DELEGATION_BASE_SERVER_REQUEST_VALIDATION_HPP
#define LAMINATE_DELEGATION_BASE_SERVER_REQUEST_VALIDATION_HPP

/// @file server/request_validation.hpp
/// @brief Setup, request, noise-schedule, and fresh-chain admission checks.

#include "laminate/delegation/base/server/state_access.hpp"
#include "laminate/payload/trace/fhe_trace_id.hpp"
#include "laminate/payload/noise/honest_noise_schedule.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace laminate::delegation::base_server_detail {

template <fhe::FheBackend Backend>
void validate_evaluation_request_binding(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const EvaluationSetup<Backend> &server,
    const BaseRequest<Backend> &request) {
    const Digest setup_id = setup_digest(server.public_setup);
    const Digest circuit_id = server.public_setup.circuit_digest;
    if (payload.shape.kind != payload::PayloadKind::Wide ||
        circuit.shape.kind != payload::PayloadKind::Wide ||
        request.setup_id != setup_id || request.session_id == Digest{} ||
        request.circuit_id != circuit_id ||
        request.trace_id !=
            payload::prevalidated_trace_identity::
                validated_fhe_evaluated_trace_id<Backend>(
                    circuit_id, payload.input_count,
                    request.encrypted_inputs)) {
        throw std::invalid_argument(
            "evaluate_base_request: request binding mismatch");
    }
}

/// Authenticate the executable payload schedule and exact fresh chain before
/// any directory is normalized or FHE operation runs.
template <fhe::FheBackend Backend>
void validate_checkpoint_replay_schedule(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const EvaluationSetup<Backend> &server,
    const BaseRequest<Backend> &request,
    const payload::CertifiedHonestPayloadSchedule &certified_schedule) {
    server.public_setup.validate_certified_payload_schedule(
        payload, circuit, certified_schedule);
    const payload::HonestPayloadNoiseSchedule &schedule =
        certified_schedule.schedule();
    const bool fixed_uniform_policy =
        schedule.base_proof_ingress_policy ==
        payload::kUniformBaseProofIngressPolicyV1;
    const bool exact_assessment =
        schedule.base_proof_noise_assessment &&
        schedule.base_proof_noise_assessment->report_accepts() &&
        server.public_setup.honest_base_proof_noise_assessment_digest;
    if (!server.public_setup.honest_payload_noise_schedule_digest ||
        (!fixed_uniform_policy && !exact_assessment)) {
        throw std::invalid_argument(
            "Base checkpoint evaluation requires either the setup-bound "
            "uniform Base proof policy or an exact assessed schedule");
    }
    validate_evaluation_request_binding(payload, circuit, server, request);

    const std::size_t fresh_limbs = schedule.data_moduli_low_to_high.size();
    for (const typename Backend::Ciphertext &ciphertext :
         request.encrypted_inputs) {
        if (Backend::rns_limb_count(server.context, ciphertext) !=
            fresh_limbs) {
            throw std::invalid_argument(
                "Base checkpoint evaluation: encrypted input is not at "
                "the setup-bound fresh RNS level");
        }
    }

    if constexpr (requires(const typename Backend::EvalContext &eval) {
                      {
                          Backend::coefficient_moduli(eval)
                      } -> std::same_as<std::vector<std::uint64_t>>;
                  }) {
        const std::vector<std::uint64_t> coefficient_moduli =
            Backend::coefficient_moduli(server.context);
        if (coefficient_moduli.empty() ||
            coefficient_moduli.size() - 1U != fresh_limbs ||
            !std::equal(schedule.data_moduli_low_to_high.begin(),
                        schedule.data_moduli_low_to_high.end(),
                        coefficient_moduli.begin())) {
            throw std::invalid_argument(
                "Base checkpoint evaluation: backend data-prime chain "
                "differs from the setup-bound honest payload schedule");
        }
    }
}

} // namespace laminate::delegation::base_server_detail

#endif // LAMINATE_DELEGATION_BASE_SERVER_REQUEST_VALIDATION_HPP
