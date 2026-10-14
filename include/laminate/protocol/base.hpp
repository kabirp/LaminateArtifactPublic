#ifndef LAMINATE_PROTOCOL_BASE_HPP
#define LAMINATE_PROTOCOL_BASE_HPP

/// @file base.hpp
/// @brief Top-level LaminateBase proof and protocol entry points.

#include "laminate/gkr/base.hpp"
#include "laminate/gkr/detail/base/proving/types.hpp"
#include "laminate/payload/checkpoint/session_engine.hpp"
#include "laminate/protocol/setup/base_client.hpp"

namespace laminate::protocol {

/// LaminateBase transmits its encrypted GKR proof directly.
template <fhe::FheBackend Backend>
using LaminateBaseProof = gkr::EncryptedBaseProof<Backend>;

/// Per-layer scratch and optional progress reporting for the no-retry Base
/// prover. Selecting `prove_base` fixes reclamation semantics; callers cannot
/// accidentally request a retryable lifecycle through this type.
using BaseProverOptions = gkr::base_detail::FileEncryptedBaseGkrOptions;

/// Proof and exact artifact-lifecycle reports returned by the in-process
/// checkpoint-replay Base prover.
template <fhe::PersistableFheBackend Backend>
struct BaseProofResult {
    LaminateBaseProof<Backend> proof;
    gkr::base_detail::FileBaseGkrReport gkr_report;
    payload::PayloadCheckpointReplayExecutionReport payload_replay_report;
};

/// Validate the complete compact replay request, including every disposable
/// multiplication-scratch destination, without changing the trace or proof
/// transcript.
template <fhe::PersistableFheBackend Backend>
void preflight_base(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const payload::PayloadCheckpointReplayTrace<Backend> &trace,
    const EvaluationSetup<Backend> &setup,
    std::span<const Fpk> output_point,
    const BaseProverOptions &options);

/// Prove Base directly from compact Wide checkpoints and retire each payload
/// or multiplication artifact after its last consumer. Any failure after the
/// output-layer retirement is terminal for `trace`.
template <fhe::PersistableFheBackend Backend>
BaseProofResult<Backend> prove_base(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    payload::PayloadCheckpointReplayTrace<Backend> &trace,
    const EvaluationSetup<Backend> &setup,
    std::span<const Fpk> output_point, Transcript &transcript,
    BaseProverOptions options);

/// Decrypt and verify every Base GKR message using metadata certified during
/// client preprocessing, then check the terminal plaintext-input claim.
template <fhe::FheBackend Backend>
bool verify_base(
    const CertifiedBaseClientSetup<Backend> &setup,
    std::span<const fhe::SlotVector> input_layer,
    payload::TraceProvenance expected_provenance,
    const Digest &expected_trace_id,
    const gkr::SingleClaim &expected_output_claim,
    const LaminateBaseProof<Backend> &proof, Transcript &transcript);

} // namespace laminate::protocol

// Template implementations are kept separate from the public declarations.
#include "laminate/protocol/detail/base/api_impl.hpp"

#endif // LAMINATE_PROTOCOL_BASE_HPP
