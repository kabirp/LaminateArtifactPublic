#ifndef LAMINATE_PROTOCOL_PACKED_EXTERNAL_DETAIL_ADMISSION_API_HPP
#define LAMINATE_PROTOCOL_PACKED_EXTERNAL_DETAIL_ADMISSION_API_HPP

/// @file api.hpp
/// @brief Public setup, resource preflight, and one-shot admission definitions.

#include "laminate/protocol/packed/external/detail/admission/request.hpp"

#include <filesystem>
#include <utility>

namespace laminate::protocol {

template <packing::SignedDigitPackingBackend Backend>
CertifiedPackedExternalGkrStatic<Backend>
certify_packed_external_gkr_static(
    PackingGkrVariant expected_variant,
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const EvaluationSetup<Backend> &evaluation,
    const PackedExternalProverSetup &setup,
    payload::EncryptedTraceDescriptor proof_trace_template) {
    return packed_external_detail::certify_static_gkr<Backend>(
        expected_variant, payload, circuit, evaluation, setup,
        std::move(proof_trace_template));
}

template <packing::SignedDigitPackingBackend Backend>
void preflight_packed_external_prover_setup(
    PackingGkrVariant expected_variant,
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const EvaluationSetup<Backend> &evaluation,
    const PackedExternalProverSetup &setup) {
    packed_external_detail::validate_setup<Backend>(
        expected_variant, payload, circuit, evaluation, setup);
}

inline void preflight_folded_packed_external_resource_roots(
    const std::filesystem::path &replay_root,
    const FoldedExternalGkrProofOptions &gkr_options,
    const TranscriptPackingExternalAdmission &packing_admission) {
    packed_external_detail::reject_cross_root_overlap(
        packed_external_detail::gkr_roots(
            replay_root, gkr_options.proof),
        packing_admission.mutable_roots());
}

inline void preflight_laned_packed_external_resource_roots(
    const std::filesystem::path &replay_root,
    const LanedExternalGkrProofOptions &gkr_options,
    const TranscriptPackingExternalAdmission &packing_admission) {
    packed_external_detail::reject_cross_root_overlap(
        packed_external_detail::gkr_roots(
            replay_root, gkr_options.proof),
        packing_admission.mutable_roots());
}

template <typename Backend>
    requires packing::SignedDigitPackingBackend<Backend> &&
             fhe::PersistableFheBackend<Backend>
FoldedCheckpointReplayExternalAdmission<Backend>
admit_folded_checkpoint_replay_external_irreversible(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    payload::PayloadCheckpointReplayTrace<Backend> &trace,
    const EvaluationSetup<Backend> &setup,
    const PackedExternalProverSetup &prover_setup,
    std::span<const Fpk> output_point,
    const FoldedCheckpointReplayExternalOptions &options) {
    return packed_external_detail::admit_folded<Backend>(
        payload, circuit, trace, setup, prover_setup, output_point,
        options);
}

template <typename Backend>
    requires packing::SignedDigitPackingBackend<Backend> &&
             fhe::PersistableFheBackend<Backend>
FoldedCheckpointReplayExternalAdmission<Backend>
admit_folded_checkpoint_replay_with_packing_admission_irreversible(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    payload::PayloadCheckpointReplayTrace<Backend> &trace,
    const EvaluationSetup<Backend> &setup,
    const PackedExternalProverSetup &prover_setup,
    std::span<const Fpk> output_point,
    FoldedExternalGkrProofOptions gkr_options,
    TranscriptPackingExternalAdmission packing_admission) {
    return packed_external_detail::admit_folded_pre_admitted<Backend>(
        payload, circuit, trace, setup, prover_setup, output_point,
        std::move(gkr_options), std::move(packing_admission));
}

template <typename Backend>
    requires packing::SignedDigitPackingBackend<Backend> &&
             fhe::PersistableFheBackend<Backend>
FoldedCheckpointReplayExternalAdmission<Backend>
admit_prepared_folded_checkpoint_replay_external_irreversible(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    payload::PayloadCheckpointReplayTrace<Backend> &trace,
    const EvaluationSetup<Backend> &setup,
    const PackedExternalProverSetup &prover_setup,
    const CertifiedPackedExternalGkrStatic<Backend> &gkr_static,
    std::span<const Fpk> output_point,
    FoldedExternalGkrProofOptions gkr_options,
    TranscriptPackingExternalAdmission packing_admission) {
    return packed_external_detail::admit_folded_prepared<Backend>(
        payload, circuit, trace, setup, prover_setup, gkr_static,
        output_point, std::move(gkr_options),
        std::move(packing_admission));
}

template <typename Backend>
    requires packing::SignedDigitPackingBackend<Backend> &&
             fhe::PersistableFheBackend<Backend>
LanedCheckpointReplayExternalAdmission<Backend>
admit_laned_checkpoint_replay_external_irreversible(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    payload::PayloadCheckpointReplayTrace<Backend> &trace,
    const EvaluationSetup<Backend> &setup,
    const PackedExternalProverSetup &prover_setup,
    std::span<const Fpk> output_point,
    const LanedCheckpointReplayExternalOptions &options) {
    return packed_external_detail::admit_laned<Backend>(
        payload, circuit, trace, setup, prover_setup, output_point,
        options);
}

template <typename Backend>
    requires packing::SignedDigitPackingBackend<Backend> &&
             fhe::PersistableFheBackend<Backend>
LanedCheckpointReplayExternalAdmission<Backend>
admit_laned_checkpoint_replay_with_packing_admission_irreversible(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    payload::PayloadCheckpointReplayTrace<Backend> &trace,
    const EvaluationSetup<Backend> &setup,
    const PackedExternalProverSetup &prover_setup,
    std::span<const Fpk> output_point,
    LanedExternalGkrProofOptions gkr_options,
    TranscriptPackingExternalAdmission packing_admission) {
    return packed_external_detail::admit_laned_pre_admitted<Backend>(
        payload, circuit, trace, setup, prover_setup, output_point,
        std::move(gkr_options), std::move(packing_admission));
}

template <typename Backend>
    requires packing::SignedDigitPackingBackend<Backend> &&
             fhe::PersistableFheBackend<Backend>
LanedCheckpointReplayExternalAdmission<Backend>
admit_prepared_laned_checkpoint_replay_external_irreversible(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    payload::PayloadCheckpointReplayTrace<Backend> &trace,
    const EvaluationSetup<Backend> &setup,
    const PackedExternalProverSetup &prover_setup,
    const CertifiedPackedExternalGkrStatic<Backend> &gkr_static,
    std::span<const Fpk> output_point,
    LanedExternalGkrProofOptions gkr_options,
    TranscriptPackingExternalAdmission packing_admission) {
    return packed_external_detail::admit_laned_prepared<Backend>(
        payload, circuit, trace, setup, prover_setup, gkr_static,
        output_point, std::move(gkr_options),
        std::move(packing_admission));
}

} // namespace laminate::protocol

#endif // LAMINATE_PROTOCOL_PACKED_EXTERNAL_DETAIL_ADMISSION_API_HPP
