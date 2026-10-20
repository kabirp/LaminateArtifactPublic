#ifndef LAMINATE_GKR_DETAIL_LANED_VALIDATION_REQUEST_HPP
#define LAMINATE_GKR_DETAIL_LANED_VALIDATION_REQUEST_HPP

/// @file request.hpp
/// @brief Trace and encrypted-proof shape validation for LaminateLaned.

#include "laminate/gkr/laned.hpp"
#include "laminate/gkr/detail/laned/geometry/layout.hpp"
#include "laminate/setup.hpp"
#include "laminate/payload/trace/trace_wire_support.hpp"

#include <limits>
#include <span>
#include <string>

namespace laminate::gkr::laned_detail {

template <fhe::FheBackend Backend>
void validate_exact_proof_ingress_ciphertext(
    const typename Backend::EvalContext &eval,
    const typename Backend::Ciphertext &ciphertext,
    std::size_t expected_rns_limbs, const char *description) {
    if (expected_rns_limbs == 0) {
        throw std::invalid_argument(std::string(description) +
                                    ": proof-ingress RNS level is zero");
    }
    if (Backend::rns_limb_count(eval, ciphertext) != expected_rns_limbs) {
        throw std::invalid_argument(
            std::string(description) +
            ": ciphertext is not at the setup-selected proof-ingress RNS "
            "level");
    }
}

template <fhe::FheBackend Backend>
void validate_trace_shape(const typename Backend::EvalContext &eval,
                          const payload::LayeredCircuit &circuit,
                          const payload::EncryptedTrace<Backend> &trace,
                          std::span<const std::size_t>
                              proof_ingress_rns_limbs_by_layer) {
    if (!(trace.shape == circuit.shape) ||
        trace.shape.kind != payload::PayloadKind::Laned ||
        trace.layers.size() != circuit.layers.size() ||
        proof_ingress_rns_limbs_by_layer.size() != circuit.layers.size()) {
        throw std::invalid_argument(
            "LaminateLaned: expected a matching laned encrypted trace");
    }
    const std::vector<payload::LayerStorageLayout> storage =
        payload::canonical_trace_storage_layout(circuit);
    for (std::size_t layer = 0; layer < trace.layers.size(); ++layer) {
        if (trace.layers[layer].layout !=
                payload::TraceLayerLayout::BPeriodic ||
            !(trace.layers[layer].dimensions ==
              payload::layer_dimensions(circuit.layers[layer])) ||
            trace.layers[layer].wires.size() !=
                storage[layer].stored_wire_count) {
            throw std::invalid_argument(
                "LaminateLaned: resident trace is not the canonical compact "
                "live-wire representation");
        }
        // Layer zero is the payload output/decryption layer. Reverse GKR
        // consumes layers 1..L-1 as proof sources, so only those layers are
        // normalized at proof ingress and bound to this setup schedule.
        if (layer == 0) {
            continue;
        }
        for (const auto &value : trace.layers[layer].wires) {
            if (value.is_encrypted()) {
                validate_exact_proof_ingress_ciphertext<Backend>(
                    eval, value.ciphertext(),
                    proof_ingress_rns_limbs_by_layer[layer],
                    "LaminateLaned resident source");
            }
        }
    }
}

template <typename Message>
bool validate_structure_against_setup_id(
    const LanedGkrProof<Message> &proof,
    payload::TraceProvenance provenance, const Digest &trace_id,
    const PublicSetup &setup, const payload::LayeredCircuit &circuit,
    const Digest &expected_setup_id) {
    try {
        const ProtocolProfile expected{ProtocolVariant::LaminateLaned,
                                       setup.gate_mle_profile,
                                       CrossRoundPacking::None};
        validate_profile(expected, setup, circuit);
        if (circuit.shape.slot_count < 2 * kExtensionDegree ||
            proof.header.version != kEncryptedLanedProofVersion ||
            proof.header.profile != expected ||
            proof.header.provenance != provenance ||
            proof.header.circuit_id != setup.circuit_digest ||
            proof.header.setup_id != expected_setup_id ||
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
                    std::get_if<LanedAffineLayerReduction<Message>>(
                        &proof.reductions[layer]);
                if (affine == nullptr ||
                    affine->rounds.size() !=
                        laned_layer_variables(circuit, layer + 1)) {
                    return false;
                }
            } else {
                const auto *multiplication = std::get_if<
                    LanedMultiplicationLayerReduction<Message>>(
                    &proof.reductions[layer]);
                const auto output_layout = laned_layout(circuit, layer);
                const auto source_layout = laned_layout(circuit, layer + 1);
                if (multiplication == nullptr ||
                    multiplication->rounds.size() !=
                        layout_variables(output_layout) ||
                    source_layout.padded_ciphertext_count !=
                        2 * output_layout.padded_ciphertext_count) {
                    return false;
                }
            }
        }
        return true;
    } catch (const std::invalid_argument &) {
        return false;
    } catch (const std::out_of_range &) {
        return false;
    } catch (const std::overflow_error &) {
        return false;
    }
}

template <typename Message>
bool validate_structure(const LanedGkrProof<Message> &proof,
                        payload::TraceProvenance provenance,
                        const Digest &trace_id, const PublicSetup &setup,
                        const payload::LayeredCircuit &circuit) {
    try {
        return validate_structure_against_setup_id(
            proof, provenance, trace_id, setup, circuit,
            setup_digest(setup));
    } catch (const std::invalid_argument &) {
        return false;
    } catch (const std::out_of_range &) {
        return false;
    } catch (const std::overflow_error &) {
        return false;
    }
}

} // namespace laminate::gkr::laned_detail

#endif // LAMINATE_GKR_DETAIL_LANED_VALIDATION_REQUEST_HPP
