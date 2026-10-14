#ifndef LAMINATE_PROTOCOL_DETAIL_BASE_REFERENCE_IMPL_HPP
#define LAMINATE_PROTOCOL_DETAIL_BASE_REFERENCE_IMPL_HPP

/// @file reference_impl.hpp
/// @brief Template implementations for the Base resident parity paths.

#include "laminate/gkr/detail/base/reference/prover.hpp"
#include "laminate/gkr/detail/base/verifier.hpp"

namespace laminate::protocol::reference {

template <fhe::FheBackend Backend>
LaminateBaseProof<Backend> prove_base(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const payload::EncryptedTrace<Backend> &trace,
    const EvaluationSetup<Backend> &setup,
    std::span<const Fpk> output_point, Transcript &transcript) {
    return gkr::base_detail::prove_resident_synthetic_reference<Backend>(
        payload, circuit, trace, setup, output_point, transcript);
}

template <fhe::FheBackend Backend>
bool verify_base(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    std::span<const fhe::SlotVector> input_layer,
    const ClientSetup<Backend> &setup,
    payload::TraceProvenance expected_provenance,
    const Digest &expected_trace_id,
    const gkr::SingleClaim &expected_output_claim,
    const LaminateBaseProof<Backend> &proof, Transcript &transcript) {
    return gkr::base_detail::verify_base_gkr_reference<Backend>(
        payload, circuit, input_layer, setup, expected_provenance,
        expected_trace_id, expected_output_claim, proof, transcript);
}

} // namespace laminate::protocol::reference

#endif // LAMINATE_PROTOCOL_DETAIL_BASE_REFERENCE_IMPL_HPP
