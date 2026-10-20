#ifndef LAMINATE_PROTOCOL_DETAIL_FOLDED_VERIFICATION_HPP
#define LAMINATE_PROTOCOL_DETAIL_FOLDED_VERIFICATION_HPP

/// @file verification.hpp
/// @brief LaminateFolded verification in protocol order.

#include "laminate/gkr/detail/folded/verifier.hpp"
#include "laminate/gkr/detail/base/geometry/circuit.hpp"
#include "laminate/protocol/detail/packing/packed_verification.hpp"
#include "laminate/protocol/detail/packing/gkr_transcript_replay.hpp"
#include "laminate/protocol/detail/packing/transcript_reader.hpp"
#include "laminate/protocol/packed/preprocessing/client_static.hpp"

namespace laminate::protocol::folded_protocol_detail {

template <typename Backend, typename VerifierContext,
          typename PackingSetup>
bool valid_standard_verifier_statement(
    const payload::LayeredCircuit &circuit,
    const VerifierContext &verifier,
    const PackingSetup &packing_setup,
    const gkr::SingleClaim &expected_output_claim) {
    return expected_output_claim.point.size() ==
               gkr::base_detail::layer_vars(circuit, 0) &&
           packing_setup.transcript_packing.variant ==
               PackingGkrVariant::Folded &&
           packing_setup.transcript_packing.bhip_round_count ==
               folded_bhip_round_count(circuit) &&
           Backend::slot_count(verifier) ==
               packing_setup.transcript_packing.alignment_layout.slot_count;
}

template <packing::SignedDigitPackingBackend Backend,
          typename VerifierContext, typename PackingSetup>
    requires packing::PublicCoefficientVerifierContext<
        Backend, VerifierContext>
bool verify_standard(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    std::span<const fhe::SlotVector> input_layer,
    const VerifierContext &verifier,
    const PackingSetup &packing_setup,
    const ClientSetup<Backend> &setup,
    payload::TraceProvenance expected_provenance,
    const Digest &expected_trace_id,
    const gkr::SingleClaim &expected_output_claim,
    const LaminateFoldedProof<Backend> &proof, Transcript &transcript) {
    try {
        setup.public_setup.validate(payload, circuit);
        using Verifier = gkr::folded_detail::FoldedGkrVerifier<
            Backend, detail::PackedTranscriptReader,
            gkr::CommittedPackedMessage>;

        // 1. Authenticate the committed GKR shape before decrypting proof messages.
        const auto validated_structure =
            Verifier::validate_structure_once(
                proof.gkr, expected_provenance, expected_trace_id,
                setup.public_setup, circuit);
        if (!validated_structure ||
            !valid_standard_verifier_statement<Backend>(
                circuit, verifier, packing_setup,
                expected_output_claim)) {
            return false;
        }

        // 2. Replay the public GKR commitments and authenticate its gate
        // openings. Packing continues from this exact state; no plaintext or
        // secret key is needed to reconstruct the challenge sequence.
        Transcript protocol_transcript = transcript;
        auto replay = detail::replay_packed_gkr_transcript<
            gkr::ProtocolVariant::LaminateFolded, Backend>(
                circuit, setup.public_setup, proof.gkr,
                expected_output_claim.point, protocol_transcript);
        if (!replay) {
            return false;
        }

        // 3. Verify the packing argument and thresholds before decrypting its
        // digits. All its challenges extend the completed GKR interaction.
        detail::VerifiedPackedTranscript packed =
            detail::verify_committed_packing_transcript<Backend>(
                verifier, setup.context, packing_setup, proof,
                protocol_transcript);
        if (!packed.accepts()) {
            return false;
        }

        // 4. Check recovered plaintext arithmetic with the recorded public
        // challenges. This consumes no further Fiat--Shamir randomness.
        detail::PackedTranscriptReader reader(packed.logical_messages);
        auto gkr_verifier = replay->make_plaintext_verifier(
            input_layer, expected_output_claim, proof.gkr, reader);
        const bool accepted = gkr_verifier.run();
        if (accepted) {
            transcript = std::move(protocol_transcript);
        }
        return accepted;
    } catch (const std::invalid_argument &) {
        return false;
    } catch (const std::out_of_range &) {
        return false;
    } catch (const std::runtime_error &) {
        return false;
    }
}

/// Certified online counterpart. Static circuit, setup, and layout checks
/// were authenticated when `certified_static` was restored.
template <packing::SignedDigitPackingBackend Backend,
          typename VerifierContext>
    requires packing::PublicCoefficientVerifierContext<
                 Backend, VerifierContext> &&
             requires(const VerifierContext &verifier,
                      const typename Backend::ClientContext &client) {
                 { Backend::storage_context_id(verifier) } ->
                     std::same_as<Digest>;
                 { Backend::storage_context_id(client) } ->
                     std::same_as<Digest>;
             }
bool verify_certified_protocol(
    const CertifiedPackedClientStatic &certified_static,
    std::span<const fhe::SlotVector> input_layer,
    const VerifierContext &verifier,
    const typename Backend::ClientContext &client_context,
    payload::TraceProvenance expected_provenance,
    const Digest &expected_trace_id,
    const gkr::SingleClaim &expected_output_claim,
    const LaminateFoldedProof<Backend> &proof, Transcript &transcript) {
    try {
        const CertifiedPackedWorkloadStatic &workload =
            certified_static.workload();
        const FoldedVerifierSetup &packing_setup =
            certified_static.folded_verifier_setup();
        const payload::LayeredCircuit &circuit = workload.circuit();
        using Verifier = gkr::folded_detail::FoldedGkrVerifier<
            Backend, detail::PackedTranscriptReader,
            gkr::CommittedPackedMessage>;

        // 1. Authenticate the dynamic statement against the certified shape.
        const auto validated_structure =
            Verifier::validate_structure_once(
                workload, proof.gkr, expected_provenance,
                expected_trace_id);
        if (!validated_structure ||
            expected_output_claim.point.size() !=
                gkr::base_detail::layer_vars(circuit, 0) ||
            packing_setup.transcript_packing.variant !=
                PackingGkrVariant::Folded ||
            packing_setup.transcript_packing.bhip_round_count !=
                certified_static.bhip_round_count() ||
            Backend::storage_context_id(verifier) !=
                certified_static.fhe_context_storage_id() ||
            Backend::storage_context_id(client_context) !=
                certified_static.fhe_context_storage_id() ||
            Backend::slot_count(verifier) !=
                packing_setup.transcript_packing.alignment_layout.slot_count) {
            return false;
        }

        // 2. Replay the public GKR commitments and authenticate its gate
        // openings. Packing continues from this exact state; no plaintext or
        // secret key is needed to reconstruct the challenge sequence.
        Transcript protocol_transcript = transcript;
        auto replay = detail::replay_packed_gkr_transcript<
            gkr::ProtocolVariant::LaminateFolded, Backend>(
                circuit, workload.public_setup(), proof.gkr,
                expected_output_claim.point, protocol_transcript);
        if (!replay) {
            return false;
        }

        // 3. Verify the packing argument and thresholds before decrypting its
        // digits. All its challenges extend the completed GKR interaction.
        detail::VerifiedPackedTranscript packed =
            detail::verify_committed_packing_transcript<Backend>(
                verifier, client_context, packing_setup, proof,
                protocol_transcript);
        if (!packed.accepts()) {
            return false;
        }

        // 4. Check recovered plaintext arithmetic with the recorded public
        // challenges. This consumes no further Fiat--Shamir randomness.
        detail::PackedTranscriptReader reader(packed.logical_messages);
        auto gkr_verifier = replay->make_plaintext_verifier(
            input_layer, expected_output_claim, proof.gkr, reader);
        const bool accepted = gkr_verifier.run();
        if (accepted) {
            transcript = std::move(protocol_transcript);
        }
        return accepted;
    } catch (const std::invalid_argument &) {
        return false;
    } catch (const std::out_of_range &) {
        return false;
    } catch (const std::runtime_error &) {
        return false;
    }
}

} // namespace laminate::protocol::folded_protocol_detail

#endif // LAMINATE_PROTOCOL_DETAIL_FOLDED_VERIFICATION_HPP
