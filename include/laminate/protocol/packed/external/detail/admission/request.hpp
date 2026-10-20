#ifndef LAMINATE_PROTOCOL_PACKED_EXTERNAL_DETAIL_ADMISSION_REQUEST_HPP
#define LAMINATE_PROTOCOL_PACKED_EXTERNAL_DETAIL_ADMISSION_REQUEST_HPP

/// @file request.hpp
/// @brief No-write admission before destructive GKR and Spartan proving.

#include "laminate/protocol/packed/external/detail/admission/artifact_lifecycle.hpp"
#include "laminate/protocol/packed/external/detail/admission/setup_validation.hpp"
#include "laminate/protocol/packed/external/detail/admission/state.hpp"

#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

namespace laminate::protocol::packed_external_detail {

template <typename GkrOptions, typename Trace>
void require_fresh_irreversible_trace(
    const GkrOptions &options,
    const Trace &trace,
    std::string_view variant) {
    if (options.lifecycle !=
            payload::FileTraceSessionLifecycle::IrreversibleNoRetry ||
        !options.reclaim_completed_multiplication_scratch) {
        throw std::invalid_argument(
            "external " + std::string(variant) +
            " checkpoint replay requires explicit no-retry and immediate "
            "GKR scratch reclamation");
    }
    if (!trace.report().checkpoint_set_published ||
        trace.proof_attempt_started() ||
        trace.report().all_payload_artifacts_retired) {
        throw std::invalid_argument(
            "external " + std::string(variant) +
            " checkpoint replay needs a fresh published trace");
    }
}

template <typename Backend>
    requires packing::SignedDigitPackingBackend<Backend> &&
             fhe::PersistableFheBackend<Backend>
FoldedCheckpointReplayExternalAdmission<Backend>
admit_folded_pre_admitted(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    payload::PayloadCheckpointReplayTrace<Backend> &trace,
    const EvaluationSetup<Backend> &evaluation,
    const PackedExternalProverSetup &setup,
    std::span<const Fpk> output_point,
    FoldedExternalGkrProofOptions gkr_options,
    TranscriptPackingExternalAdmission packing) {
    require_fresh_irreversible_trace(gkr_options, trace, "Folded");
    validate_setup<Backend>(
        PackingGkrVariant::Folded, payload, circuit, evaluation, setup);

    // This dry construction checks the exact GKR claim flow and scratch map.
    // No Fiat--Shamir coin is observed and no trace artifact is touched.
    Transcript validation_transcript(
        "LaminateImpl/Folded/PackedExternalPreflight/v1");
    gkr::folded_detail::FoldedProver<
        Backend,
        const payload::PayloadCheckpointReplayTrace<Backend>> prover(
        payload, circuit, trace, evaluation, output_point,
        validation_transcript, gkr_options.proof,
        setup.proof_ingress_rns_limbs_by_layer());
    prover.validate_before_writes();
    return detail::PackedExternalAdmissionAccess::make_folded<Backend>(
        payload, circuit, trace, evaluation, setup, output_point,
        std::move(gkr_options), std::move(packing));
}

template <typename Backend>
    requires packing::SignedDigitPackingBackend<Backend> &&
             fhe::PersistableFheBackend<Backend>
FoldedCheckpointReplayExternalAdmission<Backend>
admit_folded_prepared(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    payload::PayloadCheckpointReplayTrace<Backend> &trace,
    const EvaluationSetup<Backend> &evaluation,
    const PackedExternalProverSetup &setup,
    const CertifiedPackedExternalGkrStatic<Backend> &gkr_static,
    std::span<const Fpk> output_point,
    FoldedExternalGkrProofOptions gkr_options,
    TranscriptPackingExternalAdmission packing) {
    if (gkr_options.lifecycle !=
            payload::FileTraceSessionLifecycle::IrreversibleNoRetry ||
        !gkr_options.reclaim_completed_multiplication_scratch ||
        !trace.report().checkpoint_set_published ||
        trace.proof_attempt_started() ||
        trace.report().all_payload_artifacts_retired ||
        !packing.matches(PackingGkrVariant::Folded,
                         setup.transcript_packing()) ||
        !gkr_static.matches(PackingGkrVariant::Folded, payload, circuit,
                            evaluation, setup)) {
        throw std::invalid_argument(
            "prepared external Folded proof resources are stale or "
            "mismatched");
    }
    return detail::PackedExternalAdmissionAccess::make_folded<Backend>(
        payload, circuit, trace, evaluation, setup, output_point,
        std::move(gkr_options), std::move(packing), &gkr_static);
}

template <typename Backend>
    requires packing::SignedDigitPackingBackend<Backend> &&
             fhe::PersistableFheBackend<Backend>
FoldedCheckpointReplayExternalAdmission<Backend> admit_folded(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    payload::PayloadCheckpointReplayTrace<Backend> &trace,
    const EvaluationSetup<Backend> &evaluation,
    const PackedExternalProverSetup &setup,
    std::span<const Fpk> output_point,
    const FoldedCheckpointReplayExternalOptions &options) {
    reject_cross_root_overlap(
        gkr_roots(trace.directory(), options.gkr.proof),
        packing_mutable_roots(options.transcript_packing));
    TranscriptPackingExternalAdmission packing =
        admit_transcript_packing_external(
            PackingGkrVariant::Folded, setup.transcript_packing(),
            options.transcript_packing);
    return admit_folded_pre_admitted<Backend>(
        payload, circuit, trace, evaluation, setup, output_point,
        options.gkr, std::move(packing));
}

template <typename Backend>
    requires packing::SignedDigitPackingBackend<Backend> &&
             fhe::PersistableFheBackend<Backend>
LanedCheckpointReplayExternalAdmission<Backend>
admit_laned_pre_admitted(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    payload::PayloadCheckpointReplayTrace<Backend> &trace,
    const EvaluationSetup<Backend> &evaluation,
    const PackedExternalProverSetup &setup,
    std::span<const Fpk> output_point,
    LanedExternalGkrProofOptions gkr_options,
    TranscriptPackingExternalAdmission packing) {
    require_fresh_irreversible_trace(gkr_options, trace, "Laned");
    validate_setup<Backend>(
        PackingGkrVariant::Laned, payload, circuit, evaluation, setup);

    Transcript validation_transcript(
        "LaminateImpl/Laned/PackedExternalPreflight/v1");
    gkr::laned_detail::LanedProver<
        Backend,
        const payload::PayloadCheckpointReplayTrace<Backend>> prover(
        payload, circuit, trace, evaluation,
        setup.proof_ingress_rns_limbs_by_layer(), output_point,
        validation_transcript, gkr_options.proof);
    prover.validate_before_writes();
    return detail::PackedExternalAdmissionAccess::make_laned<Backend>(
        payload, circuit, trace, evaluation, setup, output_point,
        std::move(gkr_options), std::move(packing));
}

template <typename Backend>
    requires packing::SignedDigitPackingBackend<Backend> &&
             fhe::PersistableFheBackend<Backend>
LanedCheckpointReplayExternalAdmission<Backend>
admit_laned_prepared(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    payload::PayloadCheckpointReplayTrace<Backend> &trace,
    const EvaluationSetup<Backend> &evaluation,
    const PackedExternalProverSetup &setup,
    const CertifiedPackedExternalGkrStatic<Backend> &gkr_static,
    std::span<const Fpk> output_point,
    LanedExternalGkrProofOptions gkr_options,
    TranscriptPackingExternalAdmission packing) {
    if (gkr_options.lifecycle !=
            payload::FileTraceSessionLifecycle::IrreversibleNoRetry ||
        !gkr_options.reclaim_completed_multiplication_scratch ||
        !trace.report().checkpoint_set_published ||
        trace.proof_attempt_started() ||
        trace.report().all_payload_artifacts_retired ||
        !packing.matches(PackingGkrVariant::Laned,
                         setup.transcript_packing()) ||
        !gkr_static.matches(PackingGkrVariant::Laned, payload, circuit,
                            evaluation, setup)) {
        throw std::invalid_argument(
            "prepared external Laned proof resources are stale or "
            "mismatched");
    }
    return detail::PackedExternalAdmissionAccess::make_laned<Backend>(
        payload, circuit, trace, evaluation, setup, output_point,
        std::move(gkr_options), std::move(packing), &gkr_static);
}

template <typename Backend>
    requires packing::SignedDigitPackingBackend<Backend> &&
             fhe::PersistableFheBackend<Backend>
LanedCheckpointReplayExternalAdmission<Backend> admit_laned(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    payload::PayloadCheckpointReplayTrace<Backend> &trace,
    const EvaluationSetup<Backend> &evaluation,
    const PackedExternalProverSetup &setup,
    std::span<const Fpk> output_point,
    const LanedCheckpointReplayExternalOptions &options) {
    reject_cross_root_overlap(
        gkr_roots(trace.directory(), options.gkr.proof),
        packing_mutable_roots(options.transcript_packing));
    TranscriptPackingExternalAdmission packing =
        admit_transcript_packing_external(
            PackingGkrVariant::Laned, setup.transcript_packing(),
            options.transcript_packing);
    return admit_laned_pre_admitted<Backend>(
        payload, circuit, trace, evaluation, setup, output_point,
        options.gkr, std::move(packing));
}

} // namespace laminate::protocol::packed_external_detail

#endif // LAMINATE_PROTOCOL_PACKED_EXTERNAL_DETAIL_ADMISSION_REQUEST_HPP
