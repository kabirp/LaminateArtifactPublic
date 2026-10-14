#ifndef LAMINATE_PROTOCOL_PACKED_WIRE_DETAIL_PROOF_SHAPE_HPP
#define LAMINATE_PROTOCOL_PACKED_WIRE_DETAIL_PROOF_SHAPE_HPP

/// @file proof_shape.hpp
/// @brief Top-level canonical Folded/Laned proof frame decoding.

#include "laminate/protocol/packed/preprocessing/client_static.hpp"
#include "laminate/protocol/packed/wire/detail/committed_gkr.hpp"
#include "laminate/protocol/packed/wire/detail/packing_reveals.hpp"
#include "laminate/protocol/packed/wire/detail/spartan_proof.hpp"

#include <stdexcept>

namespace laminate::protocol::detail::packed_proof_decode_detail {

template <packing::CoefficientWellFormednessBackend Backend,
          typename Context, typename Proof, typename CommittedProof>
    requires PackedProofDecodeContext<Backend, Context>
Proof decode_packed_proof_shape(
    std::span<const std::uint8_t> encoded, char variant,
    PackingGkrVariant expected_packing_variant, const Context &context,
    const payload::LayeredCircuit &circuit, const PublicSetup &setup,
    const Digest &expected_setup_id,
    const TranscriptPackingSpartanVerifierSetup &packing_setup,
    std::size_t expected_bhip_rounds,
    const PackedProofDecodeLimits &limits, const char *operation) {
    if (encoded.size() > limits.max_proof_bytes) {
        reject(operation, "proof exceeds configured byte limit");
    }
    if (circuit.layers.empty()) {
        reject(operation, "packed proof circuit has no layers");
    }
    if (packing_setup.variant != expected_packing_variant ||
        packing_setup.bhip_round_count == 0 ||
        packing_setup.bhip_round_count != expected_bhip_rounds ||
        packing_setup.alignment_layout.slot_count !=
            Backend::slot_count(context)) {
        reject(operation, "packed verifier setup has the wrong profile");
    }

    const auto nested_limits = base_limits(limits);
    DecodeBudget budget(nested_limits, operation);
    Reader reader(encoded, operation);
    require_versioned_tag(reader, kPackedPrefix, variant, '7', operation);

    // Phase 1: committed encrypted GKR. Its own bounded sub-reader must end
    // exactly at the declared frame boundary before reveal allocations begin.
    const std::size_t committed_bytes = reader.read_size();
    if (committed_bytes > limits.max_proof_bytes) {
        reject(operation, "committed GKR proof exceeds byte limit");
    }
    Reader committed(reader.read_bytes(committed_bytes), operation);
    Proof result;
    result.gkr = read_committed_gkr<Backend, Context, CommittedProof>(
        committed, variant, context, circuit, setup, expected_setup_id,
        budget, limits, operation);
    committed.require_end();

    // Phase 2: exactly the setup-selected reveal counts. Each reveal applies
    // the shared ciphertext budget before backend deserialization.
    const std::size_t well_formedness =
        packing_setup.parameters.repetitions;
    require_count(reader.read_size(), well_formedness, limits, operation,
                  "well-formedness reveal count");
    result.transcript_packing.well_formedness_reveals.reserve(
        well_formedness);
    for (std::size_t reveal = 0; reveal < well_formedness; ++reveal) {
        result.transcript_packing.well_formedness_reveals.push_back(
            read_reveal<Backend>(reader, context, budget, limits,
                                 operation));
    }

    const std::size_t packed_digits =
        packing_setup.relation_plan.physical_packed_ciphertexts();
    require_count(reader.read_size(), packed_digits, limits, operation,
                  "packed-digit reveal count");
    result.transcript_packing.digit_decomposed_packed_values.reserve(
        packed_digits);
    for (std::size_t digit = 0; digit < packed_digits; ++digit) {
        result.transcript_packing.digit_decomposed_packed_values.push_back(
            read_reveal<Backend>(reader, context, budget, limits,
                                 operation));
    }

    // Phase 3: the Spartan relation proof. Its nested reader must consume the
    // frame exactly; the outer reader then rejects any trailing proof bytes.
    const std::size_t spartan_bytes = reader.read_size();
    if (spartan_bytes == 0 || spartan_bytes > limits.max_proof_bytes) {
        reject(operation, "missing or oversized Spartan packing proof");
    }
    Reader spartan(reader.read_bytes(spartan_bytes), operation);
    result.transcript_packing.proof_of_packing = read_spartan_proof(
        spartan, packing_setup.spartan,
        packing_setup.basefold_parameters, budget, limits, operation);
    spartan.require_end();
    reader.require_end();
    return result;
}

} // namespace laminate::protocol::detail::packed_proof_decode_detail

namespace laminate::protocol {

template <PackedProofDecodeBackend Backend, typename Context>
    requires PackedProofDecodeContext<Backend, Context>
LaminateFoldedProof<Backend> decode_canonical_folded_proof(
    const Context &context, std::span<const std::uint8_t> encoded,
    const payload::LayeredCircuit &circuit, const PublicSetup &setup,
    const FoldedVerifierSetup &packing_setup,
    const PackedProofDecodeLimits &limits) {
    return detail::packed_proof_decode_detail::decode_packed_proof_shape<
        Backend, Context, LaminateFoldedProof<Backend>,
        gkr::CommittedFoldedGkrProof>(
        encoded, 'F', PackingGkrVariant::Folded, context, circuit, setup,
        setup_digest(setup), packing_setup.transcript_packing,
        folded_bhip_round_count(circuit), limits,
        "decode_canonical_folded_proof");
}

template <PackedProofDecodeBackend Backend, typename Context>
    requires PackedProofDecodeContext<Backend, Context> &&
             requires(const Context &context) {
                 { Backend::storage_context_id(context) } ->
                     std::same_as<Digest>;
             }
LaminateFoldedProof<Backend> decode_canonical_certified_folded_proof(
    const Context &context, std::span<const std::uint8_t> encoded,
    const CertifiedPackedClientStatic &certified_static,
    const PackedProofDecodeLimits &limits) {
    if (Backend::storage_context_id(context) !=
        certified_static.fhe_context_storage_id()) {
        throw std::invalid_argument(
            "decode_canonical_certified_folded_proof: verifier context "
            "does not match the certified static authority");
    }
    const auto &workload = certified_static.workload();
    return detail::packed_proof_decode_detail::decode_packed_proof_shape<
        Backend, Context, LaminateFoldedProof<Backend>,
        gkr::CommittedFoldedGkrProof>(
        encoded, 'F', PackingGkrVariant::Folded, context,
        workload.circuit(), workload.public_setup(), workload.setup_digest(),
        certified_static.folded_verifier_setup().transcript_packing,
        certified_static.bhip_round_count(), limits,
        "decode_canonical_certified_folded_proof");
}

template <PackedProofDecodeBackend Backend, typename Context>
    requires PackedProofDecodeContext<Backend, Context>
LaminateLanedProof<Backend> decode_canonical_laned_proof(
    const Context &context, std::span<const std::uint8_t> encoded,
    const payload::LayeredCircuit &circuit, const PublicSetup &setup,
    const LanedVerifierSetup &packing_setup,
    const PackedProofDecodeLimits &limits) {
    return detail::packed_proof_decode_detail::decode_packed_proof_shape<
        Backend, Context, LaminateLanedProof<Backend>,
        gkr::CommittedLanedGkrProof>(
        encoded, 'L', PackingGkrVariant::Laned, context, circuit, setup,
        setup_digest(setup), packing_setup.transcript_packing,
        laned_bhip_round_count(circuit), limits,
        "decode_canonical_laned_proof");
}

template <PackedProofDecodeBackend Backend, typename Context>
    requires PackedProofDecodeContext<Backend, Context> &&
             requires(const Context &context) {
                 { Backend::storage_context_id(context) } ->
                     std::same_as<Digest>;
             }
LaminateLanedProof<Backend> decode_canonical_certified_laned_proof(
    const Context &context, std::span<const std::uint8_t> encoded,
    const CertifiedPackedClientStatic &certified_static,
    const PackedProofDecodeLimits &limits) {
    if (Backend::storage_context_id(context) !=
        certified_static.fhe_context_storage_id()) {
        throw std::invalid_argument(
            "decode_canonical_certified_laned_proof: verifier context "
            "does not match the certified static authority");
    }
    const auto &workload = certified_static.workload();
    return detail::packed_proof_decode_detail::decode_packed_proof_shape<
        Backend, Context, LaminateLanedProof<Backend>,
        gkr::CommittedLanedGkrProof>(
        encoded, 'L', PackingGkrVariant::Laned, context,
        workload.circuit(), workload.public_setup(), workload.setup_digest(),
        certified_static.laned_verifier_setup().transcript_packing,
        certified_static.bhip_round_count(), limits,
        "decode_canonical_certified_laned_proof");
}

} // namespace laminate::protocol

#endif // LAMINATE_PROTOCOL_PACKED_WIRE_DETAIL_PROOF_SHAPE_HPP
