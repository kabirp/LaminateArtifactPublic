#ifndef LAMINATE_GKR_DETAIL_BASE_VALIDATION_REQUEST_HPP
#define LAMINATE_GKR_DETAIL_BASE_VALIDATION_REQUEST_HPP

/// @file request.hpp
/// @brief Trace and encrypted-proof structural validation for Base.

#include "laminate/gkr/base.hpp"
#include "laminate/gkr/detail/base/geometry/circuit.hpp"
#include "laminate/payload/trace/trace_wire_support.hpp"

namespace laminate::gkr::base_detail {

template <fhe::FheBackend Backend>
void validate_trace_shape(const payload::LayeredCircuit &circuit,
                          const payload::EncryptedTrace<Backend> &trace) {
    if (!(trace.shape == circuit.shape) ||
        trace.shape.kind != payload::PayloadKind::Wide ||
        trace.layers.size() != circuit.layers.size()) {
        throw std::invalid_argument(
            "LaminateBase: expected a matching wide encrypted trace");
    }
    const std::vector<payload::LayerStorageLayout> storage =
        payload::canonical_trace_storage_layout(circuit);
    for (std::size_t layer = 0; layer < trace.layers.size(); ++layer) {
        if (trace.layers[layer].layout != payload::TraceLayerLayout::Wide ||
            !(trace.layers[layer].dimensions ==
              payload::layer_dimensions(circuit.layers[layer])) ||
            trace.layers[layer].wires.size() !=
                storage[layer].stored_wire_count) {
            throw std::invalid_argument(
                "LaminateBase: resident proving requires a canonical compact "
                "encrypted trace layer");
        }
    }
}

template <fhe::FheBackend Backend>
void validate_trace_shape(const typename Backend::EvalContext &eval,
                          const payload::LayeredCircuit &circuit,
                          const payload::EncryptedTrace<Backend> &trace) {
    validate_trace_shape(circuit, trace);
    for (const payload::EncryptedTraceLayer<Backend> &layer : trace.layers) {
        const std::size_t expected_rns_limbs =
            layer.required_mult_depth + 1U;
        for (const fhe::FheValue<Backend> &wire : layer.wires) {
            if (wire.is_public()) {
                wire.plaintext().validate_slot_count(
                    Backend::slot_count(eval),
                    "LaminateBase resident trace validation");
                continue;
            }
            if (Backend::rns_limb_count(eval, wire.ciphertext()) !=
                expected_rns_limbs) {
                throw std::invalid_argument(
                    "LaminateBase: resident trace ciphertext has the wrong "
                    "proof-ingress level");
            }
        }
    }
}

template <fhe::FheBackend Backend>
bool validate_structure(const EncryptedBaseProof<Backend> &proof,
                        payload::TraceProvenance provenance,
                        const Digest &trace_id, const PublicSetup &setup,
                        const payload::LayeredCircuit &circuit) {
    try {
        const ProtocolProfile expected{ProtocolVariant::LaminateBase,
                                       setup.gate_mle_profile,
                                       CrossRoundPacking::None};
        validate_profile(expected, setup, circuit);
        if (proof.header.version != kEncryptedBaseProofVersion ||
            proof.header.profile != expected ||
            proof.header.provenance != provenance ||
            proof.header.circuit_id != setup.circuit_digest ||
            proof.header.setup_id != setup_digest(setup) ||
            proof.header.trace_id != trace_id ||
            proof.header.layer_count != circuit.layers.size() ||
            proof.reductions.size() + 1 != circuit.layers.size() ||
            proof.gate_mle_opening.has_value() !=
                (setup.gate_mle_profile ==
                 GateMleProfile::OutsourcedBaseFold)) {
            return false;
        }
        for (std::size_t layer = 0; layer < proof.reductions.size(); ++layer) {
            const payload::LayerKind kind =
                payload::layer_kind(circuit.layers[layer]);
            if (kind == payload::LayerKind::Affine) {
                const auto *affine =
                    std::get_if<EncryptedBaseAffineLayerReduction<Backend>>(
                        &proof.reductions[layer]);
                if (affine == nullptr ||
                    affine->rounds.size() !=
                        ciphertext_index_variables(circuit, layer + 1) ||
                    affine->partial_gate_mle.evaluations.size() !=
                        circuit.shape.value_width()) {
                    return false;
                }
            } else {
                const auto *multiplication =
                    std::get_if<EncryptedBaseMultiplicationLayerReduction<Backend>>(
                        &proof.reductions[layer]);
                if (multiplication == nullptr ||
                    multiplication->rounds.size() !=
                        ciphertext_index_variables(circuit, layer)) {
                    return false;
                }
            }
        }
        return true;
    } catch (const std::invalid_argument &) {
        return false;
    } catch (const std::out_of_range &) {
        return false;
    }
}

} // namespace laminate::gkr::base_detail

#endif // LAMINATE_GKR_DETAIL_BASE_VALIDATION_REQUEST_HPP
