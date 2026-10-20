#ifndef LAMINATE_PROTOCOL_DETAIL_LANED_REFERENCE_PROVING_HPP
#define LAMINATE_PROTOCOL_DETAIL_LANED_REFERENCE_PROVING_HPP

/// @file reference_proving.hpp
/// @brief File-backed LaminateLaned correctness path.

#include "laminate/gkr/detail/laned/prover.hpp"
#include "laminate/protocol/detail/laned/reference_types.hpp"
#include "laminate/protocol/detail/laned/setup_validation.hpp"
#include "laminate/protocol/detail/packing/aligned_commitments.hpp"
#include "laminate/protocol/detail/packing/proof_completion.hpp"

#include <algorithm>
#include <utility>

namespace laminate::protocol::laned_protocol_detail {

template <packing::SignedDigitPackingBackend Backend>
reference::LanedFileProofResult<Backend> prove_irreversible_file(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    payload::FileEncryptedTraceReclamationSession<Backend> &trace,
    const EvaluationSetup<Backend> &setup,
    const LanedSetup &packing_setup,
    std::span<const Fpk> output_point, Transcript &transcript,
    reference::IrreversibleLanedFileProofOptions options,
    gkr::ProofTransportPolicy transport = {}) {
    if (options.lifecycle !=
        payload::FileTraceSessionLifecycle::IrreversibleNoRetry) {
        throw std::invalid_argument(
            "prove_laned_file_irreversible_reference: explicit "
            "IrreversibleNoRetry lifecycle is required");
    }

    // Advance the caller's transcript only after the complete proof succeeds.
    Transcript protocol_transcript = transcript;
    observe_packed_fiat_shamir_schedule(protocol_transcript);
    transport.reserved_mult_depth = std::max(
        transport.reserved_mult_depth, kPackingReservedMultDepth);
    validate_packing_setup<Backend>(circuit, setup, packing_setup);

    // GKR consumes trace layers and multiplication scratch; aligned messages
    // stay live for the resident transcript-packing suffix.
    detail::AlignedCommitmentCollector<Backend> collector(
        setup.context,
        packing_setup.transcript_packing.alignment_layout,
        packing_setup.transcript_packing.relation_plan.shape
            .ciphertext_commitment_policy);
    const RuntimeProgressCallback packing_progress =
        options.proof.progress;
    auto encrypted_gkr =
        gkr::laned_detail::prove_laned_gkr_irreversible<Backend>(
            payload, circuit, trace, setup,
            packing_setup.proof_ingress_rns_limbs_by_layer,
            output_point, protocol_transcript, std::move(options), transport,
            [&collector](const fhe::FheValue<Backend> &message) {
                return collector.commit(message);
            });

    auto proof = detail::finish_committed_packing_proof<
        Backend, LaminateLanedProof<Backend>>(
        setup.context, packing_setup,
        encrypted_gkr.proof, std::move(collector).finish(), protocol_transcript,
        packing_progress);
    auto result = reference::LanedFileProofResult<Backend>{
        std::move(proof), std::move(encrypted_gkr.report)};
    transcript = std::move(protocol_transcript);
    return result;
}

template <packing::SignedDigitPackingBackend Backend>
void preflight_irreversible_file(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const payload::FileEncryptedTraceStore<Backend> &trace,
    const EvaluationSetup<Backend> &setup,
    const LanedSetup &packing_setup,
    std::span<const Fpk> output_point,
    const reference::IrreversibleLanedFileProofOptions &options) {
    if (options.lifecycle !=
        payload::FileTraceSessionLifecycle::IrreversibleNoRetry) {
        throw std::invalid_argument(
            "preflight_laned_file_irreversible_reference: explicit "
            "IrreversibleNoRetry lifecycle is required");
    }
    validate_packing_setup<Backend>(circuit, setup, packing_setup);
    gkr::laned_detail::validate_laned_gkr_request<Backend>(
        payload, circuit, trace, setup,
        packing_setup.proof_ingress_rns_limbs_by_layer,
        output_point, options.proof);
}

} // namespace laminate::protocol::laned_protocol_detail

#endif // LAMINATE_PROTOCOL_DETAIL_LANED_REFERENCE_PROVING_HPP
