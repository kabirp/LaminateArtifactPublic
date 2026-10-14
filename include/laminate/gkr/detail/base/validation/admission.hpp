#ifndef LAMINATE_GKR_DETAIL_BASE_VALIDATION_ADMISSION_HPP
#define LAMINATE_GKR_DETAIL_BASE_VALIDATION_ADMISSION_HPP

/// @file admission.hpp
/// @brief Read-only admission for one production LaminateBase proof.
///
/// The validator binds the setup, trace identity, claim geometry, replay
/// lifecycle, and multiplication-scratch capacity. It has no transcript and
/// cannot accidentally observe a challenge during preflight.

#include "laminate/gkr/detail/base/proving/types.hpp"
#include "laminate/gkr/detail/base/affine/types.hpp"
#include "laminate/gkr/detail/base/geometry/circuit.hpp"
#include "laminate/gkr/detail/base/multiplication/types.hpp"
#include "laminate/gkr/detail/base/validation/request.hpp"
#include "laminate/gkr/detail/base/validation/scratch.hpp"
#include "laminate/payload/checkpoint/plan.hpp"

#include <stdexcept>
#include <utility>
#include <vector>

namespace laminate::gkr::base_detail::validation {

struct ValidatedBaseRequest {
    std::vector<FileBaseMultiplicationScratch> multiplication_scratch;
    /// Canonical compact support derived once for the whole circuit.
    /// Layer provers consume this admitted metadata directly; they must not
    /// rescan every circuit layer merely to rediscover omitted public zeros.
    std::vector<payload::LayerWireSupport> layer_support;
    /// Static pair geometry and operand aliases for each multiplication
    /// layer, in the same order as `multiplication_scratch`.
    std::vector<detail::DenseMultiplicationSourcePlan>
        multiplication_source_plans;
};

template <fhe::PersistableFheBackend Backend, typename TraceSource>
payload::CanonicalTraceLayout validate_base_request_identity(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit, const TraceSource &trace,
    const EvaluationSetup<Backend> &setup,
    const SingleClaim &output_claim, const ProtocolProfile &profile) {
    setup.public_setup.validate(payload, circuit);
    const auto &bound_schedule =
        setup.public_setup.honest_payload_noise_schedule_digest;
    const auto &bound_assessment = setup.public_setup
                                       .honest_base_proof_noise_assessment_digest;
    if (bound_schedule || bound_assessment) {
        if (!bound_schedule) {
            throw std::invalid_argument(
                "Base proof cannot bind a proof-noise assessment "
                "without its payload schedule");
        }
        if constexpr (requires(const TraceSource &source) {
                          source.authenticated_honest_payload_noise_schedule_digest();
                          source.authenticated_honest_base_proof_noise_assessment_digest();
                      }) {
            if (trace.authenticated_honest_payload_noise_schedule_digest() !=
                    bound_schedule ||
                trace.authenticated_honest_base_proof_noise_assessment_digest() !=
                    bound_assessment) {
                throw std::invalid_argument(
                    "Base trace does not authenticate the "
                    "setup-bound proof schedule");
            }
        } else {
            throw std::invalid_argument(
                "Base source cannot authenticate the setup-bound "
                "proof schedule");
        }
    } else if constexpr (requires(const TraceSource &source) {
                             source.authenticated_honest_payload_noise_schedule_digest();
                             source.authenticated_honest_base_proof_noise_assessment_digest();
                         }) {
        if (trace.authenticated_honest_payload_noise_schedule_digest() ||
            trace.authenticated_honest_base_proof_noise_assessment_digest()) {
            throw std::invalid_argument(
                "Base authenticated trace requires the same setup "
                "schedule binding");
        }
    }

    validate_profile(profile, setup.public_setup, circuit);
    payload::validate_encrypted_trace_descriptor_for_circuit(
        trace.descriptor(), payload, circuit);
    if (trace.descriptor().shape.kind != payload::PayloadKind::Wide ||
        Backend::slot_count(setup.context) !=
            trace.descriptor().shape.slot_count ||
        Backend::storage_context_id(setup.context) !=
            trace.backend_context_id() ||
        trace.layered_circuit_id() != setup.public_setup.layered_digest ||
        trace.descriptor().circuit_id != setup.public_setup.circuit_digest ||
        output_claim.point.size() != layer_vars(circuit, 0)) {
        throw std::invalid_argument(
            "Base proof requires matching Wide trace, setup, and "
            "output geometry");
    }
    // Deriving support walks the layered circuit. Do it once at admission,
    // then hand the result to every reduction that needs it.
    payload::CanonicalTraceLayout canonical_layout =
        payload::canonical_trace_layout(circuit);
    for (std::size_t layer = 0;
         layer < canonical_layout.wire_support.size(); ++layer) {
        if (trace.layer_support(layer) !=
            canonical_layout.wire_support[layer]) {
            throw std::invalid_argument(
                "Base proof source support is noncanonical");
        }
    }
    if constexpr (requires(const TraceSource &source) {
                      source.report().checkpoint_set_published;
                      source.report().all_payload_artifacts_retired;
                      source.proof_attempt_started();
                  }) {
        if (!trace.report().checkpoint_set_published ||
            trace.report().all_payload_artifacts_retired ||
            trace.proof_attempt_started()) {
            throw std::invalid_argument(
                "Base replay source is not a fresh published "
                "session");
        }
    }
    return canonical_layout;
}

inline void validate_base_claim_flow(
    const payload::LayeredCircuit &circuit,
    std::size_t output_point_variables) {
    // Affine reduction and multiplication-selector interpolation both leave
    // a single claim at the next layer's full source point.
    std::size_t point_variables = output_point_variables;
    for (std::size_t layer = 0; layer + 1U < circuit.layers.size(); ++layer) {
        if (point_variables != layer_vars(circuit, layer)) {
            throw std::invalid_argument(
                "Base claim-flow point geometry mismatch");
        }
        if (payload::layer_kind(circuit.layers[layer]) ==
            payload::LayerKind::Multiplication) {
            const auto output =
                payload::layer_dimensions(circuit.layers[layer]);
            const auto source =
                payload::layer_dimensions(circuit.layers[layer + 1U]);
            (void)detail::DenseMultiplicationDimensions::create(
                output.padded_size, source.padded_size,
                circuit.shape.value_width());
        } else {
            (void)AffineGeometry::create(circuit, layer);
        }
        point_variables = layer_vars(circuit, layer + 1U);
    }
}

template <fhe::PersistableFheBackend Backend, typename TraceSource>
ValidatedBaseRequest validate_base_request(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit, const TraceSource &trace,
    const EvaluationSetup<Backend> &setup,
    const SingleClaim &output_claim, const ProtocolProfile &profile,
    const FileEncryptedBaseGkrOptions &options) {
    payload::CanonicalTraceLayout canonical_layout =
        validate_base_request_identity(
        payload, circuit, trace, setup, output_claim, profile);
    validate_base_claim_flow(
        circuit, output_claim.point.size());

    auto normalized = preflight_and_normalize_file_base_gkr_scratch(
        circuit, trace.directory(), options);
    const Digest setup_id = setup_digest(setup.public_setup);
    std::vector<detail::DenseMultiplicationSourcePlan>
        multiplication_source_plans;
    multiplication_source_plans.reserve(
        normalized.multiplication_scratch.size());
    for (const FileBaseMultiplicationScratch &scratch :
         normalized.multiplication_scratch) {
        const std::size_t source_layer = scratch.reduction_layer + 1U;
        const std::size_t source_ingress_limbs =
            trace.descriptor().layers.at(source_layer).required_mult_depth +
            1U;
        detail::DenseMultiplicationSourcePlan source_plan =
            detail::make_dense_multiplication_source_plan(
                circuit, trace.descriptor(), trace.layered_circuit_id(),
                trace.backend_context_id(), scratch.reduction_layer,
                canonical_layout.wire_support.at(source_layer),
                canonical_layout.storage.at(source_layer),
                setup_id, source_ingress_limbs);
        if (scratch.storage_limits.max_total_bytes <
            source_plan.minimum_artifact_framing_bytes) {
            throw std::invalid_argument(
                "Base scratch quota cannot hold artifact framing");
        }
        multiplication_source_plans.push_back(std::move(source_plan));
    }
    return ValidatedBaseRequest{
        std::move(normalized.multiplication_scratch),
        std::move(canonical_layout.wire_support),
        std::move(multiplication_source_plans)};
}

} // namespace laminate::gkr::base_detail::validation

#endif // LAMINATE_GKR_DETAIL_BASE_VALIDATION_ADMISSION_HPP
