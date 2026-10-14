#ifndef LAMINATE_PROTOCOL_DETAIL_PACKING_PACKED_VERIFICATION_HPP
#define LAMINATE_PROTOCOL_DETAIL_PACKING_PACKED_VERIFICATION_HPP

/// @file packed_verification.hpp
/// @brief Shared transcript-packing verification stage for packed variants.

#include "laminate/protocol/detail/packing/committed_gkr_encoding.hpp"
#include "laminate/protocol/detail/packing/messages.hpp"
#include "laminate/protocol/detail/packing/resident_transcript_packing.hpp"

namespace laminate::protocol::detail {

/// Verify that the committed ciphertexts encode the logical GKR transcript.
/// The caller supplies the transcript after public GKR replay and gate-opening
/// verification. It checks the recovered messages against that replay plan
/// afterwards; this suffix never restarts the Fiat--Shamir challenge stream.
template <packing::SignedDigitPackingBackend Backend,
          typename VerifierContext, typename ClientContext,
          typename PackingSetup, typename PackedProof>
VerifiedPackedTranscript verify_committed_packing_transcript(
    const VerifierContext &verifier,
    const ClientContext &client_context,
    const PackingSetup &packing_setup,
    const PackedProof &proof,
    Transcript &packing_transcript) {
    bind_committed_gkr_for_packing(proof.gkr, packing_transcript);
    const auto messages =
        view_transcript_packing_committed_messages(proof.gkr);
    return verify_transcript_packing<Backend>(
        verifier, client_context, packing_setup.transcript_packing,
        messages, proof.transcript_packing, packing_transcript);
}

} // namespace laminate::protocol::detail

#endif // LAMINATE_PROTOCOL_DETAIL_PACKING_PACKED_VERIFICATION_HPP
