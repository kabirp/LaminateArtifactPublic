#ifndef LAMINATE_PROTOCOL_FOLDED_HPP
#define LAMINATE_PROTOCOL_FOLDED_HPP

/// @file folded.hpp
/// @brief Top-level LaminateFolded proof and protocol entry points.

#include "laminate/gkr/folded.hpp"
#include "laminate/protocol/packed/proof.hpp"
#include "laminate/protocol/packed/setup.hpp"

namespace laminate::protocol {

/// Validate the complete Folded transcript-packing prover setup before
/// expensive payload FHE begins.
template <packing::SignedDigitPackingBackend Backend>
void preflight_folded_packing_setup(
    const payload::LayeredCircuit &circuit,
    const EvaluationSetup<Backend> &setup,
    const FoldedSetup &packing_setup);

/// Check transcript packing, decrypt the logical GKR messages, and replay the
/// Folded reductions. Verification accepts only the compact verifier setup;
/// prover matrices and PCS opening state never cross the client boundary.
template <packing::SignedDigitPackingBackend Backend,
          typename VerifierContext>
    requires packing::PublicCoefficientVerifierContext<
        Backend, VerifierContext>
bool verify_folded(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    std::span<const fhe::SlotVector> input_layer,
    const VerifierContext &verifier,
    const FoldedVerifierSetup &packing_setup,
    const ClientSetup<Backend> &setup,
    payload::TraceProvenance expected_provenance,
    const Digest &expected_trace_id,
    const gkr::SingleClaim &expected_output_claim,
    const LaminateFoldedProof<Backend> &proof, Transcript &transcript);

} // namespace laminate::protocol

// Template implementations are kept separate from the public declarations.
#include "laminate/protocol/detail/folded/api_impl.hpp"

#endif // LAMINATE_PROTOCOL_FOLDED_HPP
