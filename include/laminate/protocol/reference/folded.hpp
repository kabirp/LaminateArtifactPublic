#ifndef LAMINATE_PROTOCOL_REFERENCE_FOLDED_HPP
#define LAMINATE_PROTOCOL_REFERENCE_FOLDED_HPP

/// @file reference/folded.hpp
/// @brief File-backed and checkpoint-replay Folded correctness paths.

#include "laminate/protocol/detail/folded/reference_types.hpp"
#include "laminate/protocol/folded.hpp"

namespace laminate::protocol::reference {

/// Bounded in-memory Folded correctness path. Production servers use the
/// checkpoint-replay/external prover exposed by `delegation/folded/server.hpp`.
template <packing::SignedDigitPackingBackend Backend>
LaminateFoldedProof<Backend> prove_folded(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const payload::EncryptedTrace<Backend> &trace,
    const EvaluationSetup<Backend> &setup,
    const FoldedSetup &packing_setup,
    std::span<const Fpk> output_point, Transcript &transcript);

template <packing::SignedDigitPackingBackend Backend>
FoldedFileProofResult<Backend> prove_folded_file_reference(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const payload::FileEncryptedTraceStore<Backend> &trace,
    const EvaluationSetup<Backend> &setup,
    const FoldedSetup &packing_setup,
    std::span<const Fpk> output_point, Transcript &transcript,
    RetryableFoldedFileProofOptions options);

template <packing::SignedDigitPackingBackend Backend>
void preflight_folded_file_reference(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const payload::FileEncryptedTraceStore<Backend> &trace,
    const EvaluationSetup<Backend> &setup,
    const FoldedSetup &packing_setup,
    std::span<const Fpk> output_point,
    const RetryableFoldedFileProofOptions &options);

template <packing::SignedDigitPackingBackend Backend>
FoldedFileProofResult<Backend>
prove_folded_file_irreversible_reference(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    payload::FileEncryptedTraceReclamationSession<Backend> &trace,
    const EvaluationSetup<Backend> &setup,
    const FoldedSetup &packing_setup,
    std::span<const Fpk> output_point, Transcript &transcript,
    IrreversibleFoldedFileProofOptions options);

template <packing::SignedDigitPackingBackend Backend>
void preflight_folded_file_irreversible_reference(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const payload::FileEncryptedTraceStore<Backend> &trace,
    const EvaluationSetup<Backend> &setup,
    const FoldedSetup &packing_setup,
    std::span<const Fpk> output_point,
    const IrreversibleFoldedFileProofOptions &options);

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
    const IrreversibleFoldedFileProofOptions &options);

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
    IrreversibleFoldedFileProofOptions options);

} // namespace laminate::protocol::reference

#include "laminate/protocol/detail/folded/reference_impl.hpp"

#endif // LAMINATE_PROTOCOL_REFERENCE_FOLDED_HPP
