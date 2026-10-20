#ifndef LAMINATE_PROTOCOL_DETAIL_FOLDED_SETUP_VALIDATION_HPP
#define LAMINATE_PROTOCOL_DETAIL_FOLDED_SETUP_VALIDATION_HPP

/// @file setup_validation.hpp
/// @brief Folded transcript-packing setup checks at the prover boundary.

#include "laminate/protocol/packed/setup.hpp"

#include <ranges>

namespace laminate::protocol::folded_protocol_detail {

template <packing::SignedDigitPackingBackend Backend>
void validate_packing_setup(
    const payload::LayeredCircuit &circuit,
    const EvaluationSetup<Backend> &setup,
    const FoldedSetup &packing_setup) {
    if (packing_setup.proof_ingress_rns_limbs_by_layer.size() !=
            circuit.layers.size() ||
        std::ranges::any_of(
            packing_setup.proof_ingress_rns_limbs_by_layer,
            [](std::size_t limbs) { return limbs == 0; }) ||
        packing_setup.transcript_packing.variant !=
            PackingGkrVariant::Folded ||
        packing_setup.transcript_packing.bhip_round_count !=
            folded_bhip_round_count(circuit) ||
        Backend::slot_count(setup.context) !=
            packing_setup.transcript_packing.alignment_layout.slot_count) {
        throw std::invalid_argument(
            "prove_folded: packing setup does not match the circuit");
    }
}

} // namespace laminate::protocol::folded_protocol_detail

#endif // LAMINATE_PROTOCOL_DETAIL_FOLDED_SETUP_VALIDATION_HPP
