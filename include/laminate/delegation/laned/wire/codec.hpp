#ifndef LAMINATE_DELEGATION_LANED_WIRE_CODEC_HPP
#define LAMINATE_DELEGATION_LANED_WIRE_CODEC_HPP

/// @file wire/codec.hpp
/// @brief Setup-shaped decoding for the sole Laned response.

#include "laminate/delegation/laned/wire/format.hpp"
#include "laminate/protocol/packed/wire/proof.hpp"

#include <span>
#include <utility>

namespace laminate::delegation {

/// Decode the complete one-round response under caller-owned envelope and
/// proof budgets. The opaque framing decoder bounds the encrypted output and
/// proof blob before allocation; the packed-proof decoder then derives every
/// collection length from the trusted circuit and compact verifier setup.
template <protocol::PackedProofDecodeBackend Backend, typename Context>
    requires fhe::CiphertextStorageContext<Backend, Context> &&
             protocol::PackedProofDecodeContext<Backend, Context>
LanedResponse<Backend> decode_laned_response(
    const Context &context,
    std::span<const std::uint8_t> encoded,
    const LanedWireDecodeLimits &wire_limits,
    const protocol::PackedProofDecodeLimits &proof_limits,
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit, const PublicSetup &setup,
    const protocol::LanedVerifierSetup &packing_setup,
    payload::TraceProvenance expected_provenance) {
    constexpr const char *operation = "decode_laned_response";
    setup.validate(payload, circuit);
    BorrowedLanedResponseEnvelope<Backend> opaque =
        decode_borrowed_laned_response_envelope<Backend>(
            context, encoded, wire_limits);
    protocol::LaminateLanedProof<Backend> proof =
        protocol::decode_canonical_laned_proof<Backend>(
            context, opaque.opaque_proof_bytes, circuit, setup,
            packing_setup, proof_limits);
    const payload::LayerDimensions expected_output_dimensions =
        payload::layer_dimensions(circuit.layers.front());
    const payload::LayerWireSupport expected_output_support =
        payload::canonical_layer_wire_support(circuit, 0);
    // The setup-shaped decoder consumes the complete proof span, validates
    // typed components, and bounds each opaque BaseFold frame. The BaseFold
    // verifier parses those bytes once, so no second full serialization is
    // needed here.
    if (opaque.setup_id != setup_digest(setup) ||
        opaque.circuit_id != setup.circuit_digest ||
        opaque.output.dimensions != expected_output_dimensions ||
        opaque.output.values.size() !=
            expected_output_support.live_wire_count ||
        proof.gkr.header.setup_id != opaque.setup_id ||
        proof.gkr.header.circuit_id != opaque.circuit_id ||
        proof.gkr.header.trace_id != opaque.trace_id ||
        proof.gkr.header.provenance != expected_provenance ||
        !gkr::laned_detail::validate_structure(
            proof.gkr, expected_provenance, opaque.trace_id, setup,
            circuit)) {
        wire_detail::reject(
            operation, "proof structure or public bindings mismatch");
    }
    return LanedResponse<Backend>{
        opaque.setup_id, opaque.session_id, opaque.circuit_id,
        opaque.trace_id, std::move(opaque.output), std::move(proof)};
}

} // namespace laminate::delegation

#endif // LAMINATE_DELEGATION_LANED_WIRE_CODEC_HPP
