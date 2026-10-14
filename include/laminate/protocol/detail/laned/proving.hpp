#ifndef LAMINATE_PROTOCOL_DETAIL_LANED_PROVING_HPP
#define LAMINATE_PROTOCOL_DETAIL_LANED_PROVING_HPP

/// @file proving.hpp
/// @brief Bounded resident LaminateLaned reference proving.

#include "laminate/gkr/detail/laned/reference/prover.hpp"
#include "laminate/protocol/detail/laned/setup_validation.hpp"
#include "laminate/protocol/detail/packing/aligned_commitments.hpp"
#include "laminate/protocol/detail/packing/proof_completion.hpp"

#include <algorithm>
#include <utility>

namespace laminate::protocol::laned_protocol_detail {

template <packing::SignedDigitPackingBackend Backend>
LaminateLanedProof<Backend> prove_resident(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const payload::EncryptedTrace<Backend> &trace,
    const EvaluationSetup<Backend> &setup,
    const LanedSetup &packing_setup,
    std::span<const Fpk> output_point, Transcript &transcript,
    gkr::ProofTransportPolicy transport = {}) {
    // Advance the caller's transcript only after the complete proof succeeds.
    Transcript protocol_transcript = transcript;
    observe_packed_fiat_shamir_schedule(protocol_transcript);

    // 1. Run encrypted Laned GKR and commit each normalized aligned message
    // as it leaves the GKR prover.
    transport.reserved_mult_depth = std::max(
        transport.reserved_mult_depth, kPackingReservedMultDepth);
    validate_packing_setup<Backend>(circuit, setup, packing_setup);
    detail::AlignedCommitmentCollector<Backend> collector(
        setup.context,
        packing_setup.transcript_packing.alignment_layout,
        packing_setup.transcript_packing.relation_plan.shape
            .ciphertext_commitment_policy);
    const auto encrypted_gkr =
        gkr::laned_detail::prove_laned_gkr_resident<Backend>(
            payload, circuit, trace, setup,
            packing_setup.proof_ingress_rns_limbs_by_layer,
            output_point, protocol_transcript, transport,
            [&collector](const fhe::FheValue<Backend> &message) {
                return collector.commit(message);
            });

    // 2. Prove that the committed ciphertext messages pack the logical GKR
    // transcript recovered by the client.
    auto result = detail::finish_committed_packing_proof<
        Backend, LaminateLanedProof<Backend>>(
        setup.context, packing_setup, encrypted_gkr,
        std::move(collector).finish(), protocol_transcript);
    transcript = std::move(protocol_transcript);
    return result;
}

} // namespace laminate::protocol::laned_protocol_detail

#endif // LAMINATE_PROTOCOL_DETAIL_LANED_PROVING_HPP
