#ifndef LAMINATE_PROTOCOL_PACKED_EXTERNAL_DETAIL_ADMISSION_STATE_HPP
#define LAMINATE_PROTOCOL_PACKED_EXTERNAL_DETAIL_ADMISSION_STATE_HPP

/// @file state.hpp
/// @brief One-shot state crossing the packed external proof boundary.

#include <span>
#include <utility>
#include <vector>

namespace laminate::protocol::detail {

/// The packed wrapper enters an already-admitted GKR prover exactly once.
struct PackedExternalGkrAccess {
    template <typename Prover>
    static auto prove_admitted_request(Prover &&prover) {
        return std::forward<Prover>(prover).prove_admitted_request();
    }
};

template <typename Backend>
struct ConsumedFoldedCheckpointReplayExternalAdmission {
    const payload::PayloadCircuit *payload = nullptr;
    const payload::LayeredCircuit *circuit = nullptr;
    payload::PayloadCheckpointReplayTrace<Backend> *trace = nullptr;
    const EvaluationSetup<Backend> *evaluation = nullptr;
    const PackedExternalProverSetup *setup = nullptr;
    std::vector<Fpk> output_point;
    FoldedExternalGkrProofOptions gkr_options;
    TranscriptPackingExternalAdmission packing;
    const CertifiedPackedExternalGkrStatic<Backend> *gkr_static = nullptr;
};

template <typename Backend>
struct ConsumedLanedCheckpointReplayExternalAdmission {
    const payload::PayloadCircuit *payload = nullptr;
    const payload::LayeredCircuit *circuit = nullptr;
    payload::PayloadCheckpointReplayTrace<Backend> *trace = nullptr;
    const EvaluationSetup<Backend> *evaluation = nullptr;
    const PackedExternalProverSetup *setup = nullptr;
    std::vector<Fpk> output_point;
    LanedExternalGkrProofOptions gkr_options;
    TranscriptPackingExternalAdmission packing;
    const CertifiedPackedExternalGkrStatic<Backend> *gkr_static = nullptr;
};

/// The public admission objects hide raw pointers and movable resources. This
/// friend is their only constructor/consumer and makes double use observable.
struct PackedExternalAdmissionAccess {
    template <typename Backend>
    static FoldedCheckpointReplayExternalAdmission<Backend> make_folded(
        const payload::PayloadCircuit &payload,
        const payload::LayeredCircuit &circuit,
        payload::PayloadCheckpointReplayTrace<Backend> &trace,
        const EvaluationSetup<Backend> &evaluation,
        const PackedExternalProverSetup &setup,
        std::span<const Fpk> output_point,
        FoldedExternalGkrProofOptions gkr_options,
        TranscriptPackingExternalAdmission packing,
        const CertifiedPackedExternalGkrStatic<Backend> *gkr_static =
            nullptr) {
        return FoldedCheckpointReplayExternalAdmission<Backend>(
            &payload, &circuit, &trace, &evaluation, &setup,
            std::vector<Fpk>(output_point.begin(), output_point.end()),
            std::move(gkr_options), std::move(packing), gkr_static);
    }

    template <typename Backend>
    static LanedCheckpointReplayExternalAdmission<Backend> make_laned(
        const payload::PayloadCircuit &payload,
        const payload::LayeredCircuit &circuit,
        payload::PayloadCheckpointReplayTrace<Backend> &trace,
        const EvaluationSetup<Backend> &evaluation,
        const PackedExternalProverSetup &setup,
        std::span<const Fpk> output_point,
        LanedExternalGkrProofOptions gkr_options,
        TranscriptPackingExternalAdmission packing,
        const CertifiedPackedExternalGkrStatic<Backend> *gkr_static =
            nullptr) {
        return LanedCheckpointReplayExternalAdmission<Backend>(
            &payload, &circuit, &trace, &evaluation, &setup,
            std::vector<Fpk>(output_point.begin(), output_point.end()),
            std::move(gkr_options), std::move(packing), gkr_static);
    }

    template <typename Backend>
    static ConsumedFoldedCheckpointReplayExternalAdmission<Backend>
    take(FoldedCheckpointReplayExternalAdmission<Backend> admission) {
        return {
            .payload = admission.payload_,
            .circuit = admission.circuit_,
            .trace = admission.trace_,
            .evaluation = admission.evaluation_,
            .setup = admission.setup_,
            .output_point = std::move(admission.output_point_),
            .gkr_options = std::move(admission.gkr_options_),
            .packing = std::move(admission.packing_),
            .gkr_static = admission.gkr_static_,
        };
    }

    template <typename Backend>
    static ConsumedLanedCheckpointReplayExternalAdmission<Backend>
    take(LanedCheckpointReplayExternalAdmission<Backend> admission) {
        return {
            .payload = admission.payload_,
            .circuit = admission.circuit_,
            .trace = admission.trace_,
            .evaluation = admission.evaluation_,
            .setup = admission.setup_,
            .output_point = std::move(admission.output_point_),
            .gkr_options = std::move(admission.gkr_options_),
            .packing = std::move(admission.packing_),
            .gkr_static = admission.gkr_static_,
        };
    }
};

} // namespace laminate::protocol::detail

#endif // LAMINATE_PROTOCOL_PACKED_EXTERNAL_DETAIL_ADMISSION_STATE_HPP
