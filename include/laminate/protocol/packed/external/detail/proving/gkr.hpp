#ifndef LAMINATE_PROTOCOL_PACKED_EXTERNAL_DETAIL_PROVING_GKR_HPP
#define LAMINATE_PROTOCOL_PACKED_EXTERNAL_DETAIL_PROVING_GKR_HPP

/// @file gkr.hpp
/// @brief Destructive encrypted-GKR phase and aligned message collection.

#include "laminate/protocol/detail/packing/aligned_commitments.hpp"
#include "laminate/protocol/detail/packing/messages.hpp"
#include "laminate/protocol/packed/external/detail/admission/artifact_lifecycle.hpp"
#include "laminate/protocol/packed/external/detail/admission/state.hpp"

#include <algorithm>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

namespace laminate::protocol::packed_external_detail {

template <packing::SignedDigitPackingBackend Backend>
struct FoldedGkrPhaseResult {
    gkr::CommittedFoldedGkrProof proof;
    gkr::folded_detail::FileFoldedGkrReport report;
    detail::CollectedAlignedCommitments<Backend> packing_sources;
};

template <packing::SignedDigitPackingBackend Backend>
struct LanedGkrPhaseResult {
    gkr::CommittedLanedGkrProof proof;
    gkr::laned_detail::FileLanedGkrReport report;
    detail::CollectedAlignedCommitments<Backend> packing_sources;
};

template <typename Admission>
void require_live_consumed_admission(
    const Admission &admitted,
    std::string_view variant) {
    if (admitted.payload == nullptr || admitted.circuit == nullptr ||
        admitted.trace == nullptr || admitted.evaluation == nullptr ||
        admitted.setup == nullptr) {
        throw std::invalid_argument(
            "external " + std::string(variant) +
            " admission has already been consumed");
    }
    if (admitted.trace->proof_attempt_started() ||
        admitted.trace->report().all_payload_artifacts_retired) {
        throw std::invalid_argument(
            "external " + std::string(variant) +
            " admission no longer names a fresh trace");
    }
}

template <typename Backend>
detail::AlignedCommitmentCollector<Backend> make_message_collector(
    const EvaluationSetup<Backend> &evaluation,
    const PackedExternalProverSetup &setup) {
    const auto &relation = setup.transcript_packing().relation();
    return detail::AlignedCommitmentCollector<Backend>(
        evaluation.context, relation.alignment_layout,
        relation.relation_plan.shape.ciphertext_commitment_policy);
}

template <typename Backend>
std::optional<std::span<
    const gkr::detail::DenseMultiplicationSourcePlan>>
multiplication_source_plans(
    const CertifiedPackedExternalGkrStatic<Backend> *certified) {
    if (certified == nullptr) {
        return std::nullopt;
    }
    return certified->multiplication_source_plans();
}

template <typename Prover>
auto prove_admitted_gkr(Prover &&prover) {
    prover.validate_before_writes();
    return detail::PackedExternalGkrAccess::prove_admitted_request(
        std::move(prover));
}

/// Run encrypted Folded GKR while collecting the exact aligned messages that
/// become the witness of Laminate's transcript-packing relation. The replay
/// trace and every GKR scratch file must be gone before this returns.
template <typename Backend>
    requires packing::SignedDigitPackingBackend<Backend> &&
             fhe::PersistableFheBackend<Backend>
FoldedGkrPhaseResult<Backend> run_folded_gkr_phase(
    detail::ConsumedFoldedCheckpointReplayExternalAdmission<Backend>
        &admitted,
    Transcript &gkr_transcript,
    gkr::ProofTransportPolicy transport) {
    require_live_consumed_admission(admitted, "Folded");
    transport.reserved_mult_depth = std::max(
        transport.reserved_mult_depth, kPackingReservedMultDepth);

    auto collector = make_message_collector<Backend>(
        *admitted.evaluation, *admitted.setup);
    gkr::folded_detail::FoldedProver<
        Backend, payload::PayloadCheckpointReplayTrace<Backend>> prover(
        *admitted.payload, *admitted.circuit, *admitted.trace,
        *admitted.evaluation, admitted.output_point, gkr_transcript,
        admitted.gkr_options.proof,
        admitted.setup->proof_ingress_rns_limbs_by_layer(), transport,
        [&collector](const fhe::FheValue<Backend> &message) {
            return collector.commit(message);
        },
        admitted.gkr_options.reclaim_completed_multiplication_scratch,
        multiplication_source_plans(admitted.gkr_static));
    auto encrypted = prove_admitted_gkr(std::move(prover));
    require_gkr_artifacts_retired(
        *admitted.trace, admitted.gkr_options.proof,
        "external Folded GKR");

    auto collected = std::move(collector).finish();
    auto committed = commit_gkr_round_messages<Backend>(
        encrypted.proof, collected.commitments());
    return {
        .proof = std::move(committed),
        .report = std::move(encrypted.report),
        .packing_sources = std::move(collected),
    };
}

/// Laned has a different GKR constructor and report type, but reaches the
/// same committed-message boundary consumed by transcript packing.
template <typename Backend>
    requires packing::SignedDigitPackingBackend<Backend> &&
             fhe::PersistableFheBackend<Backend>
LanedGkrPhaseResult<Backend> run_laned_gkr_phase(
    detail::ConsumedLanedCheckpointReplayExternalAdmission<Backend>
        &admitted,
    Transcript &gkr_transcript,
    gkr::ProofTransportPolicy transport) {
    require_live_consumed_admission(admitted, "Laned");
    transport.reserved_mult_depth = std::max(
        transport.reserved_mult_depth, kPackingReservedMultDepth);

    auto collector = make_message_collector<Backend>(
        *admitted.evaluation, *admitted.setup);
    gkr::laned_detail::LanedProver<
        Backend, payload::PayloadCheckpointReplayTrace<Backend>> prover(
        *admitted.payload, *admitted.circuit, *admitted.trace,
        *admitted.evaluation,
        admitted.setup->proof_ingress_rns_limbs_by_layer(),
        admitted.output_point, gkr_transcript,
        admitted.gkr_options.proof, transport,
        [&collector](const fhe::FheValue<Backend> &message) {
            return collector.commit(message);
        },
        admitted.gkr_options.reclaim_completed_multiplication_scratch,
        multiplication_source_plans(admitted.gkr_static));
    auto encrypted = prove_admitted_gkr(std::move(prover));
    require_gkr_artifacts_retired(
        *admitted.trace, admitted.gkr_options.proof,
        "external Laned GKR");

    auto collected = std::move(collector).finish();
    auto committed = commit_gkr_round_messages<Backend>(
        encrypted.proof, collected.commitments());
    return {
        .proof = std::move(committed),
        .report = std::move(encrypted.report),
        .packing_sources = std::move(collected),
    };
}

} // namespace laminate::protocol::packed_external_detail

#endif // LAMINATE_PROTOCOL_PACKED_EXTERNAL_DETAIL_PROVING_GKR_HPP
