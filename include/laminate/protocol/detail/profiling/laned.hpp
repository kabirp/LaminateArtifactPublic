#ifndef LAMINATE_PROTOCOL_DETAIL_PROFILING_LANED_HPP
#define LAMINATE_PROTOCOL_DETAIL_PROFILING_LANED_HPP

/// @file laned.hpp
/// @brief Opt-in timing driver for LaminateLaned.

#include "laminate/protocol/detail/profiling/runner.hpp"
#include "laminate/protocol/detail/profiling/readers.hpp"
#include "laminate/gkr/detail/laned/reference/prover.hpp"
#include "laminate/protocol/detail/packing/aligned_commitments.hpp"
#include "laminate/protocol/detail/packing/gkr_transcript_replay.hpp"
#include "laminate/protocol/fiat_shamir.hpp"
#include "laminate/protocol/laned.hpp"

#include <algorithm>
#include <functional>
#include <utility>

namespace laminate::protocol::profiling_detail {

template <fhe::FheBackend Backend>
gkr::EncryptedLanedProof<Backend> prove_laned_gkr(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const payload::EncryptedTrace<Backend> &trace,
    const EvaluationSetup<Backend> &setup,
    std::span<const Fpk> output_point,
    Transcript &transcript, LanedProverTimings &timings,
    std::span<const std::size_t> proof_ingress_rns_limbs_by_layer,
    gkr::ProofTransportPolicy transport,
    gkr::PackedMessageCommitmentFunction<Backend> commitment_function = {},
    RuntimeProgressCallback progress = {}) {
    gkr::laned_detail::LanedResidentProver<Backend> prover(
        payload, circuit, trace, setup,
        proof_ingress_rns_limbs_by_layer, output_point, transcript,
        transport, std::move(commitment_function), std::move(progress));
    return run_prover(prover, timings);
}

template <packing::SignedDigitPackingBackend Backend>
LaminateLanedProof<Backend> prove_laned_reference(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const payload::EncryptedTrace<Backend> &trace,
    const EvaluationSetup<Backend> &setup,
    const LanedSetup &packing_setup,
    std::span<const Fpk> output_point,
    Transcript &transcript, LanedProverTimings &timings,
    gkr::ProofTransportPolicy transport,
    std::function<void()> gkr_complete,
    RuntimeProgressCallback progress) {
    timings = {};
    // Advance the caller's transcript only after the complete proof succeeds.
    Transcript protocol_transcript = transcript;
    observe_packed_fiat_shamir_schedule(protocol_transcript);
    transport.reserved_mult_depth = std::max(
        transport.reserved_mult_depth, kPackingReservedMultDepth);
    if (packing_setup.proof_ingress_rns_limbs_by_layer.size() !=
            circuit.layers.size() ||
        packing_setup.transcript_packing.variant !=
            PackingGkrVariant::Laned ||
        packing_setup.transcript_packing.bhip_round_count !=
            laned_bhip_round_count(circuit) ||
        Backend::slot_count(setup.context) !=
            packing_setup.transcript_packing.alignment_layout.slot_count) {
        throw std::invalid_argument(
            "prove_laned_reference_profiled: packing setup does not match "
            "the "
            "circuit");
    }

    detail::AlignedCommitmentCollector<Backend> collector(
        setup.context,
        packing_setup.transcript_packing.alignment_layout,
        packing_setup.transcript_packing.relation_plan.shape
            .ciphertext_commitment_policy);
    const RuntimeProgressCallback packing_progress = progress;
    gkr::EncryptedLanedProof<Backend> encrypted =
        prove_laned_gkr<Backend>(
        payload, circuit, trace, setup, output_point, protocol_transcript, timings,
        packing_setup.proof_ingress_rns_limbs_by_layer, transport,
        [&collector](const fhe::FheValue<Backend> &message) {
            return collector.commit(message);
        },
        std::move(progress));
    auto collected = std::move(collector).finish();

    LaminateLanedProof<Backend> proof;
    proof.gkr = commit_gkr_round_messages<Backend>(
        encrypted, collected.commitments());
    if (gkr_complete) {
        gkr_complete();
    }

    detail::bind_committed_gkr_for_packing(proof.gkr, protocol_transcript);
    const Stopwatch packing_timer;
    proof.transcript_packing = detail::prove_transcript_packing<Backend>(
        setup.context, packing_setup.transcript_packing,
        collected.aligned(), collected.commitments(), protocol_transcript,
        packing_progress);
    const Elapsed packing_elapsed = packing_timer.stop();
    timings.transcript_packing_wall_ms = packing_elapsed.wall_ms;
    timings.transcript_packing_cpu_ms = packing_elapsed.cpu_ms;
    transcript = std::move(protocol_transcript);
    return proof;
}

template <packing::SignedDigitPackingBackend Backend,
          typename VerifierContext, typename PackingSetup>
    requires packing::PublicCoefficientVerifierContext<
        Backend, VerifierContext>
bool verify_laned(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    std::span<const fhe::SlotVector> input_layer,
    const VerifierContext &verifier,
    const PackingSetup &packing_setup,
    const ClientSetup<Backend> &setup,
    payload::TraceProvenance expected_provenance,
    const Digest &expected_trace_id,
    const gkr::SingleClaim &expected_output_claim,
    const LaminateLanedProof<Backend> &proof, Transcript &transcript,
    LanedVerifierTimings &timings,
    const RuntimeProgressCallback &progress = {}) {
    timings = {};
    try {
        setup.public_setup.validate(payload, circuit);
        using PackedGkrVerifier = gkr::laned_detail::LanedGkrVerifier<
            Backend, PackedTranscriptReader,
            gkr::CommittedPackedMessage>;
        const auto validated_structure =
            PackedGkrVerifier::validate_structure_once(
                proof.gkr, expected_provenance, expected_trace_id,
                setup.public_setup, circuit);
        if (!validated_structure ||
            expected_output_claim.point.size() !=
                gkr::laned_layer_variables(circuit, 0)) {
            return false;
        }
        if (packing_setup.transcript_packing.variant !=
                PackingGkrVariant::Laned ||
            packing_setup.transcript_packing.bhip_round_count !=
                laned_bhip_round_count(circuit) ||
            Backend::slot_count(verifier) !=
                packing_setup.transcript_packing.alignment_layout.slot_count) {
            return false;
        }

        Transcript protocol_transcript = transcript;
        auto replay = detail::replay_packed_gkr_transcript<
            gkr::ProtocolVariant::LaminateLaned, Backend>(
                circuit, setup.public_setup, proof.gkr,
                expected_output_claim.point, protocol_transcript, &timings);
        if (!replay) {
            return false;
        }
        {
            const verification_profile::ScopedVerificationPhase phase(
                verification_profile::Category::PackingSNARK);
            detail::bind_committed_gkr_for_packing(
                proof.gkr, protocol_transcript);
        }
        const auto messages =
            view_transcript_packing_committed_messages(proof.gkr);

        const Stopwatch recovery_timer;
        detail::VerifiedPackedTranscript packed =
            detail::verify_transcript_packing<Backend>(
                verifier, setup.context, packing_setup.transcript_packing,
                messages, proof.transcript_packing, protocol_transcript,
                progress);
        const Elapsed recovery_elapsed = recovery_timer.stop();
        timings.packed_message_verification_wall_ms =
            recovery_elapsed.wall_ms;
        timings.packed_message_verification_cpu_ms =
            recovery_elapsed.cpu_ms;
        timings.transcript_packing_threshold = packed.threshold_assessment;
        if (!packed.accepts()) {
            return false;
        }

        PackedTranscriptReader reader(packed.logical_messages);
        auto gkr_verifier = replay->make_plaintext_verifier(
            input_layer, expected_output_claim, proof.gkr, reader);
        BaseVerifierTimings plaintext_timings;
        const bool accepted = run_verifier(gkr_verifier, plaintext_timings);
        add_packed_plaintext_timings(timings, plaintext_timings);
        if (accepted) {
            transcript = std::move(protocol_transcript);
        }
        return accepted;
    } catch (const std::invalid_argument &) {
        return false;
    } catch (const std::out_of_range &) {
        return false;
    } catch (const std::overflow_error &) {
        return false;
    } catch (const std::runtime_error &) {
        return false;
    }
}

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
bool verify_certified_laned(
    const CertifiedPackedClientStatic &certified_static,
    std::span<const fhe::SlotVector> input_layer,
    const VerifierContext &verifier,
    const typename Backend::ClientContext &client_context,
    payload::TraceProvenance expected_provenance,
    const Digest &expected_trace_id,
    const gkr::SingleClaim &expected_output_claim,
    const LaminateLanedProof<Backend> &proof, Transcript &transcript,
    LanedVerifierTimings &timings,
    const RuntimeProgressCallback &progress = {}) {
    timings = {};
    try {
        const CertifiedPackedWorkloadStatic &workload =
            certified_static.workload();
        const LanedVerifierSetup &packing_setup =
            certified_static.laned_verifier_setup();
        const payload::LayeredCircuit &circuit = workload.circuit();
        using PackedGkrVerifier = gkr::laned_detail::LanedGkrVerifier<
            Backend, PackedTranscriptReader,
            gkr::CommittedPackedMessage>;
        const auto validated_structure =
            PackedGkrVerifier::validate_structure_once(
                workload, proof.gkr, expected_provenance,
                expected_trace_id);
        if (!validated_structure ||
            expected_output_claim.point.size() !=
                gkr::laned_layer_variables(circuit, 0)) {
            return false;
        }
        if (packing_setup.transcript_packing.variant !=
                PackingGkrVariant::Laned ||
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

        Transcript protocol_transcript = transcript;
        auto replay = detail::replay_packed_gkr_transcript<
            gkr::ProtocolVariant::LaminateLaned, Backend>(
                circuit, workload.public_setup(), proof.gkr,
                expected_output_claim.point, protocol_transcript, &timings);
        if (!replay) {
            return false;
        }
        {
            const verification_profile::ScopedVerificationPhase phase(
                verification_profile::Category::PackingSNARK);
            detail::bind_committed_gkr_for_packing(
                proof.gkr, protocol_transcript);
        }
        const auto messages =
            view_transcript_packing_committed_messages(proof.gkr);

        const Stopwatch recovery_timer;
        detail::VerifiedPackedTranscript packed =
            detail::verify_transcript_packing<Backend>(
                verifier, client_context, packing_setup.transcript_packing,
                messages, proof.transcript_packing, protocol_transcript,
                progress);
        const Elapsed recovery_elapsed = recovery_timer.stop();
        timings.packed_message_verification_wall_ms =
            recovery_elapsed.wall_ms;
        timings.packed_message_verification_cpu_ms =
            recovery_elapsed.cpu_ms;
        timings.transcript_packing_threshold = packed.threshold_assessment;
        if (!packed.accepts()) {
            return false;
        }

        PackedTranscriptReader reader(packed.logical_messages);
        auto gkr_verifier = replay->make_plaintext_verifier(
            input_layer, expected_output_claim, proof.gkr, reader);
        BaseVerifierTimings plaintext_timings;
        const bool accepted = run_verifier(gkr_verifier, plaintext_timings);
        add_packed_plaintext_timings(timings, plaintext_timings);
        if (accepted) {
            transcript = std::move(protocol_transcript);
        }
        return accepted;
    } catch (const std::invalid_argument &) {
        return false;
    } catch (const std::out_of_range &) {
        return false;
    } catch (const std::overflow_error &) {
        return false;
    } catch (const std::runtime_error &) {
        return false;
    }
}

} // namespace laminate::protocol::profiling_detail

#endif // LAMINATE_PROTOCOL_DETAIL_PROFILING_LANED_HPP
