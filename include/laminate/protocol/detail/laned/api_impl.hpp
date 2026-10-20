#ifndef LAMINATE_PROTOCOL_DETAIL_LANED_API_IMPL_HPP
#define LAMINATE_PROTOCOL_DETAIL_LANED_API_IMPL_HPP

/// @file api_impl.hpp
/// @brief Thin definitions of the public LaminateLaned entry points.

#include "laminate/protocol/detail/laned/setup_validation.hpp"
#include "laminate/protocol/detail/laned/verification.hpp"

namespace laminate::protocol {

template <packing::SignedDigitPackingBackend Backend>
void preflight_laned_packing_setup(
    const payload::LayeredCircuit &circuit,
    const EvaluationSetup<Backend> &setup,
    const LanedSetup &packing_setup) {
    laned_protocol_detail::validate_packing_setup<Backend>(
        circuit, setup, packing_setup);
}

template <packing::SignedDigitPackingBackend Backend,
          typename VerifierContext>
    requires packing::PublicCoefficientVerifierContext<
        Backend, VerifierContext>
bool verify_laned(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    std::span<const fhe::SlotVector> input_layer,
    const VerifierContext &verifier,
    const LanedVerifierSetup &packing_setup,
    const ClientSetup<Backend> &setup,
    payload::TraceProvenance expected_provenance,
    const Digest &expected_trace_id,
    const gkr::SingleClaim &expected_output_claim,
    const LaminateLanedProof<Backend> &proof, Transcript &transcript) {
    return laned_protocol_detail::verify_standard<Backend>(
        payload, circuit, input_layer, verifier, packing_setup, setup,
        expected_provenance, expected_trace_id, expected_output_claim,
        proof, transcript);
}

} // namespace laminate::protocol

#endif // LAMINATE_PROTOCOL_DETAIL_LANED_API_IMPL_HPP
