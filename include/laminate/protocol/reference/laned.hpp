#ifndef LAMINATE_PROTOCOL_REFERENCE_LANED_HPP
#define LAMINATE_PROTOCOL_REFERENCE_LANED_HPP

/// @file reference/laned.hpp
/// @brief File-backed and checkpoint-replay Laned correctness paths.

#include "laminate/protocol/detail/laned/reference_types.hpp"
#include "laminate/protocol/laned.hpp"

namespace laminate::protocol::reference {

/// Bounded in-memory Laned correctness path. Production servers use the
/// checkpoint-replay/external prover exposed by `delegation/laned/server.hpp`.
template <packing::SignedDigitPackingBackend Backend>
LaminateLanedProof<Backend> prove_laned(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const payload::EncryptedTrace<Backend> &trace,
    const EvaluationSetup<Backend> &setup,
    const LanedSetup &packing_setup,
    std::span<const Fpk> output_point, Transcript &transcript);

template <packing::SignedDigitPackingBackend Backend>
LanedFileProofResult<Backend>
prove_laned_file_irreversible_reference(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    payload::FileEncryptedTraceReclamationSession<Backend> &trace,
    const EvaluationSetup<Backend> &setup,
    const LanedSetup &packing_setup,
    std::span<const Fpk> output_point, Transcript &transcript,
    IrreversibleLanedFileProofOptions options);

template <packing::SignedDigitPackingBackend Backend>
void preflight_laned_file_irreversible_reference(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const payload::FileEncryptedTraceStore<Backend> &trace,
    const EvaluationSetup<Backend> &setup,
    const LanedSetup &packing_setup,
    std::span<const Fpk> output_point,
    const IrreversibleLanedFileProofOptions &options);

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
    const IrreversibleLanedFileProofOptions &options);

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
    IrreversibleLanedFileProofOptions options);

} // namespace laminate::protocol::reference

#include "laminate/protocol/detail/laned/reference_impl.hpp"

#endif // LAMINATE_PROTOCOL_REFERENCE_LANED_HPP
