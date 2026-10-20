#ifndef LAMINATE_PROTOCOL_PACKED_WIRE_PROOF_HPP
#define LAMINATE_PROTOCOL_PACKED_WIRE_PROOF_HPP

/// @file proof.hpp
/// @brief Canonical Folded and Laned proof decoder entry points.
///
/// This facade exposes only the allocation policy and the four supported
/// decode operations. Decoder phases live under `wire/detail/`:
///
/// 1. `committed_gkr.hpp` decodes the setup-shaped encrypted GKR proof;
/// 2. `packing_reveals.hpp` decodes public-zero or normalized ciphertext
///    reveals;
/// 3. `spartan_proof.hpp` and `matrix_evaluation_proofs.hpp` decode the
///    transcript-packing relation proof; and
/// 4. `proof_shape.hpp` enforces their canonical top-level order.
///
/// BaseFold openings remain opaque at this boundary. `basefold_frames.hpp`
/// checks their setup-derived maximum size, then BaseFold's verifier performs
/// the sole semantic and canonical parse.

#include "laminate/protocol/packed/preprocessing/client_static.hpp"
#include "laminate/protocol/packed/wire/detail/decode_policy.hpp"

#include <span>

namespace laminate::protocol {

template <PackedProofDecodeBackend Backend, typename Context>
    requires PackedProofDecodeContext<Backend, Context>
LaminateFoldedProof<Backend> decode_canonical_folded_proof(
    const Context &context, std::span<const std::uint8_t> encoded,
    const payload::LayeredCircuit &circuit, const PublicSetup &setup,
    const FoldedVerifierSetup &packing_setup,
    const PackedProofDecodeLimits &limits);

/// Decode against one immutable static capability. The caller cannot
/// independently supply the workload, verifier setup, or BhIP count used to
/// shape the proof.
template <PackedProofDecodeBackend Backend, typename Context>
    requires PackedProofDecodeContext<Backend, Context> &&
             requires(const Context &context) {
                 { Backend::storage_context_id(context) } ->
                     std::same_as<Digest>;
             }
LaminateFoldedProof<Backend> decode_canonical_certified_folded_proof(
    const Context &context, std::span<const std::uint8_t> encoded,
    const CertifiedPackedClientStatic &certified_static,
    const PackedProofDecodeLimits &limits);

template <PackedProofDecodeBackend Backend, typename Context>
    requires PackedProofDecodeContext<Backend, Context>
LaminateLanedProof<Backend> decode_canonical_laned_proof(
    const Context &context, std::span<const std::uint8_t> encoded,
    const payload::LayeredCircuit &circuit, const PublicSetup &setup,
    const LanedVerifierSetup &packing_setup,
    const PackedProofDecodeLimits &limits);

/// Laned counterpart of `decode_canonical_certified_folded_proof`.
template <PackedProofDecodeBackend Backend, typename Context>
    requires PackedProofDecodeContext<Backend, Context> &&
             requires(const Context &context) {
                 { Backend::storage_context_id(context) } ->
                     std::same_as<Digest>;
             }
LaminateLanedProof<Backend> decode_canonical_certified_laned_proof(
    const Context &context, std::span<const std::uint8_t> encoded,
    const CertifiedPackedClientStatic &certified_static,
    const PackedProofDecodeLimits &limits);

} // namespace laminate::protocol

#include "laminate/protocol/packed/wire/detail/proof_shape.hpp"

#endif // LAMINATE_PROTOCOL_PACKED_WIRE_PROOF_HPP
