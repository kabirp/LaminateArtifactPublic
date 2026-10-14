#ifndef LAMINATE_PROTOCOL_DETAIL_FOLDED_REFERENCE_IMPL_HPP
#define LAMINATE_PROTOCOL_DETAIL_FOLDED_REFERENCE_IMPL_HPP

/// @file reference_impl.hpp
/// @brief Definitions of Folded file and checkpoint reference entry points.

#include "laminate/protocol/detail/folded/checkpoint_replay.hpp"
#include "laminate/protocol/detail/folded/proving.hpp"
#include "laminate/protocol/detail/folded/reference_proving.hpp"

#include <utility>

namespace laminate::protocol::reference {

template <packing::SignedDigitPackingBackend Backend>
LaminateFoldedProof<Backend> prove_folded(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const payload::EncryptedTrace<Backend> &trace,
    const EvaluationSetup<Backend> &setup,
    const FoldedSetup &packing_setup,
    std::span<const Fpk> output_point, Transcript &transcript) {
    return folded_protocol_detail::prove_resident<Backend>(
        payload, circuit, trace, setup, packing_setup, output_point,
        transcript);
}

template <packing::SignedDigitPackingBackend Backend>
FoldedFileProofResult<Backend> prove_folded_file_reference(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const payload::FileEncryptedTraceStore<Backend> &trace,
    const EvaluationSetup<Backend> &setup,
    const FoldedSetup &packing_setup,
    std::span<const Fpk> output_point, Transcript &transcript,
    RetryableFoldedFileProofOptions options) {
    return folded_protocol_detail::prove_retryable_file<Backend>(
        payload, circuit, trace, setup, packing_setup, output_point,
        transcript, std::move(options));
}

template <packing::SignedDigitPackingBackend Backend>
void preflight_folded_file_reference(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const payload::FileEncryptedTraceStore<Backend> &trace,
    const EvaluationSetup<Backend> &setup,
    const FoldedSetup &packing_setup,
    std::span<const Fpk> output_point,
    const RetryableFoldedFileProofOptions &options) {
    folded_protocol_detail::preflight_retryable_file<Backend>(
        payload, circuit, trace, setup, packing_setup, output_point,
        options);
}

template <packing::SignedDigitPackingBackend Backend>
FoldedFileProofResult<Backend>
prove_folded_file_irreversible_reference(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    payload::FileEncryptedTraceReclamationSession<Backend> &trace,
    const EvaluationSetup<Backend> &setup,
    const FoldedSetup &packing_setup,
    std::span<const Fpk> output_point, Transcript &transcript,
    IrreversibleFoldedFileProofOptions options) {
    return folded_protocol_detail::prove_irreversible_file<Backend>(
        payload, circuit, trace, setup, packing_setup, output_point,
        transcript, std::move(options));
}

template <packing::SignedDigitPackingBackend Backend>
void preflight_folded_file_irreversible_reference(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const payload::FileEncryptedTraceStore<Backend> &trace,
    const EvaluationSetup<Backend> &setup,
    const FoldedSetup &packing_setup,
    std::span<const Fpk> output_point,
    const IrreversibleFoldedFileProofOptions &options) {
    folded_protocol_detail::preflight_irreversible_file<Backend>(
        payload, circuit, trace, setup, packing_setup, output_point,
        options);
}

template <typename Backend>
    requires packing::SignedDigitPackingBackend<Backend> &&
             fhe::PersistableFheBackend<Backend>
void preflight_folded_checkpoint_replay_irreversible_reference(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const payload::PayloadCheckpointReplayTrace<Backend> &trace,
    const EvaluationSetup<Backend> &setup,
    const FoldedSetup &packing_setup,
    std::span<const Fpk> output_point,
    const IrreversibleFoldedFileProofOptions &options) {
    folded_protocol_detail::preflight_checkpoint_replay<Backend>(
        payload, circuit, trace, setup, packing_setup, output_point,
        options);
}

template <typename Backend>
    requires packing::SignedDigitPackingBackend<Backend> &&
             fhe::PersistableFheBackend<Backend>
FoldedCheckpointReplayProofResult<Backend>
prove_folded_checkpoint_replay_irreversible_reference(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    payload::PayloadCheckpointReplayTrace<Backend> &trace,
    const EvaluationSetup<Backend> &setup,
    const FoldedSetup &packing_setup,
    std::span<const Fpk> output_point, Transcript &transcript,
    IrreversibleFoldedFileProofOptions options) {
    return folded_protocol_detail::prove_checkpoint_replay<Backend>(
        payload, circuit, trace, setup, packing_setup, output_point,
        transcript, std::move(options));
}

} // namespace laminate::protocol::reference

#endif // LAMINATE_PROTOCOL_DETAIL_FOLDED_REFERENCE_IMPL_HPP
