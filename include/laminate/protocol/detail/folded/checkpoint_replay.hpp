#ifndef LAMINATE_PROTOCOL_DETAIL_FOLDED_CHECKPOINT_REPLAY_HPP
#define LAMINATE_PROTOCOL_DETAIL_FOLDED_CHECKPOINT_REPLAY_HPP

/// @file checkpoint_replay.hpp
/// @brief Folded proving over a destructively consumed checkpoint trace.

#include "laminate/protocol/detail/folded/setup_validation.hpp"
#include "laminate/protocol/detail/folded/reference_types.hpp"
#include "laminate/protocol/detail/packing/aligned_commitments.hpp"
#include "laminate/protocol/detail/packing/checkpoint_replay_lifecycle.hpp"
#include "laminate/protocol/detail/packing/proof_completion.hpp"

#include <algorithm>
#include <utility>

namespace laminate::protocol::folded_protocol_detail {

template <typename Backend>
    requires packing::SignedDigitPackingBackend<Backend> &&
             fhe::PersistableFheBackend<Backend>
void preflight_checkpoint_replay(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const payload::PayloadCheckpointReplayTrace<Backend> &trace,
    const EvaluationSetup<Backend> &setup,
    const FoldedSetup &packing_setup,
    std::span<const Fpk> output_point,
    const reference::IrreversibleFoldedFileProofOptions &options) {
    detail::require_irreversible_checkpoint_options(
        options,
        "preflight_folded_checkpoint_replay_irreversible_reference");
    detail::require_fresh_checkpoint_replay(trace, "Folded");
    validate_packing_setup<Backend>(circuit, setup, packing_setup);

    // Constructing the canonical file-backed prover and validating it exercises every
    // path/geometry check without writing scratch or advancing the caller's
    // Fiat--Shamir transcript.
    Transcript validation_transcript(
        "LaminateImpl/Folded/CheckpointReplayPreflight/v1");
    gkr::folded_detail::FoldedProver<
        Backend,
        const payload::PayloadCheckpointReplayTrace<Backend>> prover(
        payload, circuit, trace, setup, output_point,
        validation_transcript, options.proof,
        packing_setup.proof_ingress_rns_limbs_by_layer);
    prover.validate_before_writes();
}

template <typename Backend>
    requires packing::SignedDigitPackingBackend<Backend> &&
             fhe::PersistableFheBackend<Backend>
reference::FoldedCheckpointReplayProofResult<Backend>
prove_checkpoint_replay(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    payload::PayloadCheckpointReplayTrace<Backend> &trace,
    const EvaluationSetup<Backend> &setup,
    const FoldedSetup &packing_setup,
    std::span<const Fpk> output_point, Transcript &transcript,
    reference::IrreversibleFoldedFileProofOptions options,
    gkr::ProofTransportPolicy transport = {}) {
    preflight_checkpoint_replay<Backend>(
        payload, circuit, trace, setup, packing_setup, output_point,
        options);
    // Advance the caller's transcript only after the complete proof succeeds.
    Transcript protocol_transcript = transcript;
    observe_packed_fiat_shamir_schedule(protocol_transcript);
    transport.reserved_mult_depth = std::max(
        transport.reserved_mult_depth, kPackingReservedMultDepth);

    // Step 1: Replay and retire payload checkpoints while Folded GKR emits and commits
    // its normalized aligned ciphertext messages.
    detail::AlignedCommitmentCollector<Backend> collector(
        setup.context,
        packing_setup.transcript_packing.alignment_layout,
        packing_setup.transcript_packing.relation_plan.shape
            .ciphertext_commitment_policy);
    const RuntimeProgressCallback packing_progress =
        options.proof.progress;
    auto encrypted_gkr =
        gkr::folded_detail::FoldedProver<
            Backend, payload::PayloadCheckpointReplayTrace<Backend>>(
            payload, circuit, trace, setup, output_point, protocol_transcript,
            std::move(options.proof),
            packing_setup.proof_ingress_rns_limbs_by_layer, transport,
            [&collector](const fhe::FheValue<Backend> &message) {
                return collector.commit(message);
            },
            options.reclaim_completed_multiplication_scratch)
            .run();
    detail::require_retired_checkpoint_replay(trace, "Folded");
    const payload::PayloadCheckpointReplayExecutionReport replay_report =
        trace.report();

    // Step 2: The payload trace is gone. Complete the committed transcript-packing
    // proof; any failure in this suffix is therefore terminal by design.
    auto proof = detail::finish_committed_packing_proof<
        Backend, LaminateFoldedProof<Backend>>(
        setup.context, packing_setup,
        encrypted_gkr.proof, std::move(collector).finish(), protocol_transcript,
        packing_progress);
    auto result = reference::FoldedCheckpointReplayProofResult<Backend>{
        std::move(proof), std::move(encrypted_gkr.report), replay_report};
    transcript = std::move(protocol_transcript);
    return result;
}

} // namespace laminate::protocol::folded_protocol_detail

#endif // LAMINATE_PROTOCOL_DETAIL_FOLDED_CHECKPOINT_REPLAY_HPP
