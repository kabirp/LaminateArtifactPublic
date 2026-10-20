#ifndef LAMINATE_PROTOCOL_DETAIL_PACKING_PROOF_COMPLETION_HPP
#define LAMINATE_PROTOCOL_DETAIL_PACKING_PROOF_COMPLETION_HPP

/// @file proof_completion.hpp
/// @brief Common suffix after Folded or Laned encrypted GKR finishes.

#include "laminate/protocol/detail/packing/aligned_commitments.hpp"
#include "laminate/protocol/detail/packing/committed_gkr_encoding.hpp"
#include "laminate/protocol/detail/packing/messages.hpp"
#include "laminate/protocol/detail/packing/resident_transcript_packing.hpp"
#include "laminate/protocol/fiat_shamir.hpp"

namespace laminate::protocol::detail {

/// Replace each encrypted GKR message by its commitment, then prove that the
/// committed ciphertexts encode the logical GKR transcript. Both packed
/// variants use this exact suffix; their only difference is the encrypted GKR
/// proof type produced before this function is called.
template <packing::SignedDigitPackingBackend Backend,
          typename LaminateProof, typename PackingSetup,
          typename EncryptedGkrProof>
LaminateProof finish_committed_packing_proof(
    const typename Backend::EvalContext &eval,
    const PackingSetup &packing_setup,
    const EncryptedGkrProof &encrypted_gkr,
    CollectedAlignedCommitments<Backend> collected,
    Transcript &transcript,
    const RuntimeProgressCallback &progress = {}) {
    LaminateProof proof;
    proof.gkr = commit_gkr_round_messages<Backend>(
        encrypted_gkr, collected.commitments());

    // Continue the completed GKR/gate-opening interaction. Bind the complete
    // proof encoding, including terminal responses, before packing challenges.
    bind_committed_gkr_for_packing(proof.gkr, transcript);
    proof.transcript_packing = prove_transcript_packing<Backend>(
        eval, packing_setup.transcript_packing, collected.aligned(),
        collected.commitments(), transcript, progress);
    return proof;
}

} // namespace laminate::protocol::detail

#endif // LAMINATE_PROTOCOL_DETAIL_PACKING_PROOF_COMPLETION_HPP
