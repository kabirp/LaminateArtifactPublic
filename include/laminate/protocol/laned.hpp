#ifndef LAMINATE_PROTOCOL_LANED_HPP
#define LAMINATE_PROTOCOL_LANED_HPP

/// @file laned.hpp
/// @brief Top-level LaminateLaned proof and protocol entry points.

#include "laminate/protocol/packed/proof.hpp"
#include "laminate/protocol/packed/setup.hpp"

namespace laminate::protocol {

/// Validate the complete Laned transcript-packing prover setup against the
/// circuit and evaluation context without observing a transcript or changing
/// proof state. Server orchestration uses this before expensive payload FHE.
template <packing::SignedDigitPackingBackend Backend>
void preflight_laned_packing_setup(
    const payload::LayeredCircuit &circuit,
    const EvaluationSetup<Backend> &setup,
    const LanedSetup &packing_setup);

/// Check transcript packing, decrypt the logical GKR messages, and replay the
/// Laned reductions. Verification accepts only the compact verifier setup;
/// prover matrices and PCS opening state never cross the client boundary.
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
    const LaminateLanedProof<Backend> &proof, Transcript &transcript);

} // namespace laminate::protocol

// Template implementations are kept separate from the public declarations.
#include "laminate/protocol/detail/laned/api_impl.hpp"

#endif // LAMINATE_PROTOCOL_LANED_HPP
