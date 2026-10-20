#ifndef LAMINATE_GKR_DETAIL_FOLDED_VALIDATION_REQUEST_HPP
#define LAMINATE_GKR_DETAIL_FOLDED_VALIDATION_REQUEST_HPP

/// @file request.hpp
/// @brief Encrypted-proof structural validation for LaminateFolded.

#include "laminate/gkr/folded.hpp"
#include "laminate/gkr/detail/base/geometry/circuit.hpp"

#include <span>
#include <stdexcept>

namespace laminate::gkr::folded_detail {

template <fhe::FheBackend Backend>
void validate_exact_resident_proof_ingress(
    const typename Backend::EvalContext &eval,
    const payload::EncryptedTrace<Backend> &trace,
    std::span<const std::size_t> selected_rns_limbs_by_layer) {
    if (selected_rns_limbs_by_layer.size() != trace.layers.size()) {
        throw std::invalid_argument(
            "LaminateFolded setup has the wrong proof-ingress schedule "
            "length");
    }
    // Layer 0 is the payload output returned for client decryption. Reverse
    // GKR never scans it, so proof ingress starts at source layer 1.
    for (std::size_t layer_index = 1;
         layer_index < trace.layers.size(); ++layer_index) {
        const std::size_t expected_limbs =
            selected_rns_limbs_by_layer[layer_index];
        if (expected_limbs == 0) {
            throw std::invalid_argument(
                "LaminateFolded setup selected zero proof-ingress limbs");
        }
        const auto &layer = trace.layers[layer_index];
        for (const auto &value : layer.wires) {
            if (value.is_public()) {
                continue;
            }
            if (Backend::rns_limb_count(eval, value.ciphertext()) !=
                expected_limbs) {
                throw std::invalid_argument(
                    "LaminateFolded resident ciphertext is not at the "
                    "setup-selected proof-ingress RNS level");
            }
        }
    }
}

template <typename Message>
bool validate_structure_against_setup_id(
    const FoldedGkrProof<Message> &proof,
    payload::TraceProvenance provenance, const Digest &trace_id,
    const PublicSetup &setup, const payload::LayeredCircuit &circuit,
    const Digest &expected_setup_id) {
    try {
        const ProtocolProfile expected{ProtocolVariant::LaminateFolded,
                                       setup.gate_mle_profile,
                                       CrossRoundPacking::None};
        validate_profile(expected, setup, circuit);
        if (circuit.shape.slot_count < 2 * kExtensionDegree ||
            proof.header.version != kEncryptedFoldedProofVersion ||
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
            const std::size_t slot_variables =
                base_detail::slot_index_variables(circuit);
        for (std::size_t layer = 0; layer < proof.reductions.size(); ++layer) {
            const std::size_t ciphertext_index_variables =
                base_detail::ciphertext_index_variables(circuit, layer + 1);
            if (payload::layer_kind(circuit.layers[layer]) ==
                payload::LayerKind::Affine) {
                const auto *affine =
                    std::get_if<FoldedAffineLayerReduction<Message>>(
                        &proof.reductions[layer]);
                if (affine == nullptr ||
                    affine->rounds.size() !=
                        ciphertext_index_variables + slot_variables) {
                    return false;
                }
            } else {
                const auto *multiplication = std::get_if<
                    FoldedMultiplicationLayerReduction<Message>>(
                    &proof.reductions[layer]);
                if (multiplication == nullptr ||
                    multiplication->rounds.size() !=
                        ciphertext_index_variables - 1U + slot_variables) {
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

template <typename Message>
bool validate_structure(const FoldedGkrProof<Message> &proof,
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
    }
}

} // namespace laminate::gkr::folded_detail

#endif // LAMINATE_GKR_DETAIL_FOLDED_VALIDATION_REQUEST_HPP
