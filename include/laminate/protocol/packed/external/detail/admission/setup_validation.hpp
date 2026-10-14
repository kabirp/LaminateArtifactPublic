#ifndef LAMINATE_PROTOCOL_PACKED_EXTERNAL_DETAIL_ADMISSION_SETUP_VALIDATION_HPP
#define LAMINATE_PROTOCOL_PACKED_EXTERNAL_DETAIL_ADMISSION_SETUP_VALIDATION_HPP

/// @file setup_validation.hpp
/// @brief Static certification shared by Folded and Laned packed proving.

#include "laminate/payload/setup/encoding.hpp"

#include <limits>
#include <memory>
#include <ranges>
#include <stdexcept>

namespace laminate::protocol::packed_external_detail {

template <packing::SignedDigitPackingBackend Backend>
void validate_setup(
    PackingGkrVariant expected_variant,
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const EvaluationSetup<Backend> &evaluation,
    const PackedExternalProverSetup &setup) {
    const std::size_t expected_rounds =
        expected_variant == PackingGkrVariant::Folded
            ? folded_bhip_round_count(circuit)
            : laned_bhip_round_count(circuit);
    const auto &packing = setup.transcript_packing();
    validate_conservative_packed_proof_ingress_schedule(
        payload, circuit, evaluation.public_setup,
        setup.proof_ingress_schedule());
    if (setup.variant() != expected_variant ||
        setup.bhip_round_count() != expected_rounds ||
        setup.layered_circuit_digest() != payload::digest(circuit) ||
        setup.proof_ingress_rns_limbs_by_layer().size() !=
            circuit.layers.size() ||
        std::ranges::any_of(
            setup.proof_ingress_rns_limbs_by_layer(),
            [](std::size_t limbs) { return limbs == 0; }) ||
        packing.variant() != expected_variant ||
        packing.bhip_round_count() != expected_rounds ||
        Backend::slot_count(evaluation.context) !=
            circuit.shape.slot_count ||
        Backend::slot_count(evaluation.context) !=
            packing.relation().alignment_layout.slot_count ||
        Backend::lowest_coefficient_modulus(evaluation.context) !=
            kOuterFieldOrder) {
        throw std::invalid_argument(
            "packed external prover setup does not match the live "
            "variant, circuit, ingress schedule, and evaluation context");
    }
}

/// Certify the immutable portion of repeated server requests. In particular,
/// each multiplication layer receives a prevalidated file-source descriptor;
/// request-time admission then needs only to authenticate the fresh trace.
template <packing::SignedDigitPackingBackend Backend>
CertifiedPackedExternalGkrStatic<Backend>
certify_static_gkr(
    PackingGkrVariant expected_variant,
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const EvaluationSetup<Backend> &evaluation,
    const PackedExternalProverSetup &setup,
    payload::EncryptedTraceDescriptor proof_trace_template) {
    validate_setup<Backend>(expected_variant, payload, circuit,
                            evaluation, setup);
    proof_trace_template.trace_id.front() = 1U;
    payload::validate_encrypted_trace_descriptor_for_circuit(
        proof_trace_template, payload, circuit);
    const payload::PayloadKind expected_kind =
        expected_variant == PackingGkrVariant::Folded
            ? payload::PayloadKind::Wide
            : payload::PayloadKind::Laned;
    const payload::TraceLayerLayout expected_layout =
        expected_variant == PackingGkrVariant::Folded
            ? payload::TraceLayerLayout::Wide
            : payload::TraceLayerLayout::BPeriodic;
    if (proof_trace_template.shape.kind != expected_kind ||
        proof_trace_template.layers.size() != circuit.layers.size() ||
        Backend::storage_context_id(evaluation.context) == Digest{}) {
        throw std::invalid_argument(
            "packed external static GKR trace template mismatch");
    }
    for (std::size_t layer = 0; layer < circuit.layers.size(); ++layer) {
        const auto &trace_layer = proof_trace_template.layers[layer];
        if (trace_layer.layout != expected_layout ||
            trace_layer.dimensions !=
                payload::layer_dimensions(circuit.layers[layer]) ||
            (layer != 0 &&
             (trace_layer.required_mult_depth ==
                  std::numeric_limits<std::size_t>::max() ||
              trace_layer.required_mult_depth + 1U !=
                  setup.proof_ingress_rns_limbs_by_layer()[layer]))) {
            throw std::invalid_argument(
                "packed external static GKR layer template mismatch");
        }
    }
    proof_trace_template.trace_id = Digest{};

    using Certificate = CertifiedPackedExternalGkrStatic<Backend>;
    auto state = std::make_shared<typename Certificate::State>();
    state->variant = expected_variant;
    state->payload = &payload;
    state->circuit = &circuit;
    state->evaluation = &evaluation;
    state->setup = &setup;
    const Digest layered_circuit_id = payload::digest(circuit);
    const Digest backend_context_id =
        Backend::storage_context_id(evaluation.context);
    const Digest setup_id = setup_digest(evaluation.public_setup);
    // Canonical support and physical aliases are whole-circuit setup facts.
    // Derive them once, then prepare each multiplication layer from its source
    // entries instead of rescanning the circuit per reduction.
    const payload::CanonicalTraceLayout canonical_trace =
        payload::canonical_trace_layout(circuit);
    for (std::size_t layer = 0; layer + 1U < circuit.layers.size();
         ++layer) {
        if (payload::layer_kind(circuit.layers[layer]) !=
            payload::LayerKind::Multiplication) {
            continue;
        }
        state->multiplication_source_plans.push_back(
            gkr::detail::make_dense_multiplication_source_plan(
                circuit, proof_trace_template, layered_circuit_id,
                backend_context_id, layer,
                canonical_trace.wire_support.at(layer + 1U),
                canonical_trace.storage.at(layer + 1U), setup_id,
                setup.proof_ingress_rns_limbs_by_layer()[layer + 1U]));
    }
    return Certificate(std::move(state));
}

} // namespace laminate::protocol::packed_external_detail

#endif // LAMINATE_PROTOCOL_PACKED_EXTERNAL_DETAIL_ADMISSION_SETUP_VALIDATION_HPP
