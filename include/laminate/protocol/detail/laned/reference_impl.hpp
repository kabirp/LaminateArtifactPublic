#ifndef LAMINATE_PROTOCOL_DETAIL_LANED_REFERENCE_IMPL_HPP
#define LAMINATE_PROTOCOL_DETAIL_LANED_REFERENCE_IMPL_HPP

/// @file reference_impl.hpp
/// @brief Definitions of Laned file and checkpoint reference entry points.

#include "laminate/protocol/detail/laned/checkpoint_replay.hpp"
#include "laminate/protocol/detail/laned/proving.hpp"
#include "laminate/protocol/detail/laned/reference_proving.hpp"

#include <utility>

namespace laminate::protocol::reference {

template <packing::SignedDigitPackingBackend Backend>
LaminateLanedProof<Backend> prove_laned(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const payload::EncryptedTrace<Backend> &trace,
    const EvaluationSetup<Backend> &setup,
    const LanedSetup &packing_setup,
    std::span<const Fpk> output_point, Transcript &transcript) {
    return laned_protocol_detail::prove_resident<Backend>(
        payload, circuit, trace, setup, packing_setup, output_point,
        transcript);
}

template <packing::SignedDigitPackingBackend Backend>
LanedFileProofResult<Backend>
prove_laned_file_irreversible_reference(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    payload::FileEncryptedTraceReclamationSession<Backend> &trace,
    const EvaluationSetup<Backend> &setup,
    const LanedSetup &packing_setup,
    std::span<const Fpk> output_point, Transcript &transcript,
    IrreversibleLanedFileProofOptions options) {
    return laned_protocol_detail::prove_irreversible_file<Backend>(
        payload, circuit, trace, setup, packing_setup, output_point,
        transcript, std::move(options));
}

template <packing::SignedDigitPackingBackend Backend>
void preflight_laned_file_irreversible_reference(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const payload::FileEncryptedTraceStore<Backend> &trace,
    const EvaluationSetup<Backend> &setup,
    const LanedSetup &packing_setup,
    std::span<const Fpk> output_point,
    const IrreversibleLanedFileProofOptions &options) {
    laned_protocol_detail::preflight_irreversible_file<Backend>(
        payload, circuit, trace, setup, packing_setup, output_point,
        options);
}

template <typename Backend>
    requires packing::SignedDigitPackingBackend<Backend> &&
             fhe::PersistableFheBackend<Backend>
void preflight_laned_checkpoint_replay_irreversible_reference(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const payload::PayloadCheckpointReplayTrace<Backend> &trace,
    const EvaluationSetup<Backend> &setup,
    const LanedSetup &packing_setup,
    std::span<const Fpk> output_point,
    const IrreversibleLanedFileProofOptions &options) {
    laned_protocol_detail::preflight_checkpoint_replay<Backend>(
        payload, circuit, trace, setup, packing_setup, output_point,
        options);
}

template <typename Backend>
    requires packing::SignedDigitPackingBackend<Backend> &&
             fhe::PersistableFheBackend<Backend>
LanedCheckpointReplayProofResult<Backend>
prove_laned_checkpoint_replay_irreversible_reference(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    payload::PayloadCheckpointReplayTrace<Backend> &trace,
    const EvaluationSetup<Backend> &setup,
    const LanedSetup &packing_setup,
    std::span<const Fpk> output_point, Transcript &transcript,
    IrreversibleLanedFileProofOptions options) {
    return laned_protocol_detail::prove_checkpoint_replay<Backend>(
        payload, circuit, trace, setup, packing_setup, output_point,
        transcript, std::move(options));
}

} // namespace laminate::protocol::reference

#endif // LAMINATE_PROTOCOL_DETAIL_LANED_REFERENCE_IMPL_HPP
