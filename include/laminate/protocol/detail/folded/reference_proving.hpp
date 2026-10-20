#ifndef LAMINATE_PROTOCOL_DETAIL_FOLDED_REFERENCE_PROVING_HPP
#define LAMINATE_PROTOCOL_DETAIL_FOLDED_REFERENCE_PROVING_HPP

/// @file reference_proving.hpp
/// @brief File-backed LaminateFolded correctness paths.

#include "laminate/gkr/detail/folded/prover.hpp"
#include "laminate/protocol/detail/folded/reference_types.hpp"
#include "laminate/protocol/detail/folded/setup_validation.hpp"
#include "laminate/protocol/detail/packing/aligned_commitments.hpp"
#include "laminate/protocol/detail/packing/proof_completion.hpp"

#include <algorithm>
#include <utility>

namespace laminate::protocol::folded_protocol_detail {

template <packing::SignedDigitPackingBackend Backend>
reference::FoldedFileProofResult<Backend> prove_retryable_file(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const payload::FileEncryptedTraceStore<Backend> &trace,
    const EvaluationSetup<Backend> &setup,
    const FoldedSetup &packing_setup,
    std::span<const Fpk> output_point, Transcript &transcript,
    reference::RetryableFoldedFileProofOptions options,
    gkr::ProofTransportPolicy transport = {}) {
    // Advance the caller's transcript only after the complete proof succeeds.
    Transcript protocol_transcript = transcript;
    observe_packed_fiat_shamir_schedule(protocol_transcript);
    transport.reserved_mult_depth = std::max(
        transport.reserved_mult_depth, kPackingReservedMultDepth);
    validate_packing_setup<Backend>(circuit, setup, packing_setup);

    detail::AlignedCommitmentCollector<Backend> collector(
        setup.context,
        packing_setup.transcript_packing.alignment_layout,
        packing_setup.transcript_packing.relation_plan.shape
            .ciphertext_commitment_policy);
    const RuntimeProgressCallback packing_progress = options.progress;
    auto encrypted_gkr =
        gkr::folded_detail::prove_folded_gkr<Backend>(
            payload, circuit, trace, setup, output_point, protocol_transcript,
            std::move(options),
            packing_setup.proof_ingress_rns_limbs_by_layer, transport,
            [&collector](const fhe::FheValue<Backend> &message) {
                return collector.commit(message);
            });

    auto proof = detail::finish_committed_packing_proof<
        Backend, LaminateFoldedProof<Backend>>(
        setup.context, packing_setup,
        encrypted_gkr.proof, std::move(collector).finish(), protocol_transcript,
        packing_progress);
    auto result = reference::FoldedFileProofResult<Backend>{
        std::move(proof), std::move(encrypted_gkr.report)};
    transcript = std::move(protocol_transcript);
    return result;
}

template <packing::SignedDigitPackingBackend Backend>
void preflight_retryable_file(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const payload::FileEncryptedTraceStore<Backend> &trace,
    const EvaluationSetup<Backend> &setup,
    const FoldedSetup &packing_setup,
    std::span<const Fpk> output_point,
    const reference::RetryableFoldedFileProofOptions &options) {
    validate_packing_setup<Backend>(circuit, setup, packing_setup);
    gkr::folded_detail::validate_folded_gkr_request<Backend>(
        payload, circuit, trace, setup, output_point, options,
        packing_setup.proof_ingress_rns_limbs_by_layer);
}

template <packing::SignedDigitPackingBackend Backend>
reference::FoldedFileProofResult<Backend> prove_irreversible_file(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    payload::FileEncryptedTraceReclamationSession<Backend> &trace,
    const EvaluationSetup<Backend> &setup,
    const FoldedSetup &packing_setup,
    std::span<const Fpk> output_point, Transcript &transcript,
    reference::IrreversibleFoldedFileProofOptions options,
    gkr::ProofTransportPolicy transport = {}) {
    if (options.lifecycle !=
            payload::FileTraceSessionLifecycle::IrreversibleNoRetry ||
        !options.reclaim_completed_multiplication_scratch) {
        throw std::invalid_argument(
            "prove_folded_file_irreversible_reference requires explicit "
            "no-retry "
            "lifecycle and immediate scratch reclamation");
    }

    // Advance the caller's transcript only after the complete proof succeeds.
    Transcript protocol_transcript = transcript;
    observe_packed_fiat_shamir_schedule(protocol_transcript);
    transport.reserved_mult_depth = std::max(
        transport.reserved_mult_depth, kPackingReservedMultDepth);
    validate_packing_setup<Backend>(circuit, setup, packing_setup);

    detail::AlignedCommitmentCollector<Backend> collector(
        setup.context,
        packing_setup.transcript_packing.alignment_layout,
        packing_setup.transcript_packing.relation_plan.shape
            .ciphertext_commitment_policy);
    const RuntimeProgressCallback packing_progress =
        options.proof.progress;
    auto encrypted_gkr =
        gkr::folded_detail::prove_folded_gkr_irreversible<Backend>(
            payload, circuit, trace, setup, output_point, protocol_transcript,
            std::move(options),
            packing_setup.proof_ingress_rns_limbs_by_layer, transport,
            [&collector](const fhe::FheValue<Backend> &message) {
                return collector.commit(message);
            });

    auto proof = detail::finish_committed_packing_proof<
        Backend, LaminateFoldedProof<Backend>>(
        setup.context, packing_setup,
        encrypted_gkr.proof, std::move(collector).finish(), protocol_transcript,
        packing_progress);
    auto result = reference::FoldedFileProofResult<Backend>{
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
    const FoldedSetup &packing_setup,
    std::span<const Fpk> output_point,
    const reference::IrreversibleFoldedFileProofOptions &options) {
    if (options.lifecycle !=
            payload::FileTraceSessionLifecycle::IrreversibleNoRetry ||
        !options.reclaim_completed_multiplication_scratch) {
        throw std::invalid_argument(
            "preflight_folded_file_irreversible_reference requires explicit "
            "no-retry lifecycle and immediate scratch reclamation");
    }
    preflight_retryable_file<Backend>(
        payload, circuit, trace, setup, packing_setup, output_point,
        options.proof);
}

} // namespace laminate::protocol::folded_protocol_detail

#endif // LAMINATE_PROTOCOL_DETAIL_FOLDED_REFERENCE_PROVING_HPP
