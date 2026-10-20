#ifndef LAMINATE_GKR_DETAIL_FOLDED_REFERENCE_PROVER_HPP
#define LAMINATE_GKR_DETAIL_FOLDED_REFERENCE_PROVER_HPP

/// @file prover.hpp
/// @brief Resident LaminateFolded GKR parity prover for bounded diagnostics.

#include "laminate/gkr/folded.hpp"
#include "laminate/gkr/detail/base/geometry/circuit.hpp"
#include "laminate/gkr/detail/base/transcript/reduction.hpp"
#include "laminate/gkr/detail/base/validation/request.hpp"
#include "laminate/gkr/detail/folded/reference/affine_prover.hpp"
#include "laminate/gkr/detail/folded/reference/multiplication_prover.hpp"
#include "laminate/gkr/detail/folded/validation/request.hpp"
#include "laminate/runtime_progress.hpp"

#include <cstddef>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

namespace laminate::gkr::folded_detail {

/// Builds the pre-packing encrypted GKR transcript from a bounded resident
/// trace. The affine path adapts resident storage to the canonical Folded
/// recurrence; multiplication uses the explicit resident reference recurrence.
/// This class knows nothing about transcript packing or proof transport.
template <fhe::FheBackend Backend>
class FoldedResidentProver {
  public:
    /// Mutable output-to-input claim state for one Folded GKR proof.
    ///
    /// The profiling runner may advance it one layer at a time. Normal callers
    /// use `run()`, which owns the same canonical proof order.
    struct FoldedResidentProofState {
        /// Proof prefix already transcript-bound and produced by the server.
        EncryptedFoldedProof<Backend> proof;
        /// Claim on `next_layer`, carried from the preceding reduction.
        LayerClaim current_claim;
        /// Circuit layer whose output-to-source reduction runs next.
        std::size_t next_layer = 0;
        /// True only after the terminal GateMLE opening has been published.
        bool proof_complete = false;
    };

    FoldedResidentProver(
        const payload::PayloadCircuit &payload,
        const payload::LayeredCircuit &circuit,
        const payload::EncryptedTrace<Backend> &trace,
        const EvaluationSetup<Backend> &setup,
        std::span<const Fpk> output_point, Transcript &transcript,
        std::span<const std::size_t> proof_ingress_rns_limbs_by_layer,
        ProofTransportPolicy transport,
        PackedMessageCommitmentFunction<Backend>
            commitment_function = {},
        RuntimeProgressCallback progress = {})
        : payload_(payload), circuit_(circuit), trace_(trace), setup_(setup),
          output_claim_{std::vector<Fpk>(output_point.begin(),
                                            output_point.end()),
                           Fpk::zero()},
          transcript_(transcript),
          profile_{ProtocolVariant::LaminateFolded,
                   setup.public_setup.gate_mle_profile,
                   CrossRoundPacking::None},
          gate_claims_(circuit, setup.public_setup, transcript),
          proof_ingress_rns_limbs_by_layer_(
              proof_ingress_rns_limbs_by_layer.begin(),
              proof_ingress_rns_limbs_by_layer.end()),
          transport_(transport),
          commitment_function_(std::move(commitment_function)),
          progress_(std::move(progress)) {}

    EncryptedFoldedProof<Backend> run() {
        // Step 1: Validate the request and bind the proof header/output claim.
        FoldedResidentProofState state = begin();

        // Step 2: Reduce each circuit layer from the claimed output back to
        // the public input layer.
        while (has_next_layer(state)) {
            reduce_next_layer(state);
        }

        // Step 3: Publish the single batched GateMLE opening after every layer
        // claim that contributes to it has been recorded.
        finish(state);
        return std::move(state.proof);
    }

    FoldedResidentProofState begin() {
        validate_request();
        return FoldedResidentProofState{
            bind_proof_header_and_output_claim(), LayerClaim{output_claim_}};
    }

    bool has_next_layer(const FoldedResidentProofState &state) const {
        return !state.proof_complete &&
               state.next_layer + 1U < circuit_.layers.size();
    }

    payload::LayerKind next_layer_kind(
        const FoldedResidentProofState &state) const {
        if (!has_next_layer(state)) {
            throw std::logic_error("LaminateFolded: no layer remains");
        }
        return payload::layer_kind(circuit_.layers[state.next_layer]);
    }

    void reduce_next_layer(FoldedResidentProofState &state) {
        // Step 1: Identify the circuit relation that consumes the current
        // claim. Telemetry wraps the complete semantic layer reduction.
        const std::size_t layer = state.next_layer;
        const payload::LayerKind kind = next_layer_kind(state);
        RuntimeProgressSpan reduction_progress(
            progress_, RuntimeProgressEvent{
                           .stage = RuntimeProgressStage::FoldedReduction,
                           .layer_kind =
                               kind == payload::LayerKind::Affine
                                   ? RuntimeProgressLayerKind::Affine
                                   : RuntimeProgressLayerKind::Multiplication,
                           .reduction_layer = layer,
                           .source_layer = layer + 1U});

        // Step 2: Prove exactly one affine or multiplication sumcheck and
        // replace the current claim with its source-layer claim.
        if (kind == payload::LayerKind::Affine) {
            state.current_claim =
                prove_affine_layer(layer, state.current_claim, state.proof);
        } else {
            state.current_claim = prove_multiplication_layer(
                layer, state.current_claim, state.proof);
        }
        // Step 3: Advance only after the proof message and next claim are both
        // owned by the enclosing proof state.
        ++state.next_layer;
        reduction_progress.finish();
    }

    void finish(FoldedResidentProofState &state) {
        if (state.proof_complete || has_next_layer(state)) {
            throw std::logic_error(
                "LaminateFolded: cannot finish before all layers");
        }
        RuntimeProgressSpan gate_progress(
            progress_, RuntimeProgressEvent{
                           .stage = RuntimeProgressStage::FoldedGateMleFinish});
        state.proof.gate_mle_opening =
            gate_claims_.finish(setup_.gate_mle_prover_key);
        gate_progress.finish();
        state.proof_complete = true;
    }

  private:
    void validate_request() const {
        setup_.public_setup.validate(payload_, circuit_);
        validate_profile(profile_, setup_.public_setup, circuit_);
        base_detail::validate_trace_shape(circuit_, trace_);
        validate_exact_resident_proof_ingress<Backend>(
            setup_.context, trace_, proof_ingress_rns_limbs_by_layer_);
        if (Backend::slot_count(setup_.context) < 2 * kExtensionDegree ||
            trace_.circuit_id != setup_.public_setup.circuit_digest ||
            output_claim_.point.size() !=
                base_detail::layer_vars(circuit_, 0)) {
            throw std::invalid_argument(
                "prove_folded: requires at least 16 slots and matching IDs");
        }
    }

    EncryptedFoldedProof<Backend> bind_proof_header_and_output_claim() {
        EncryptedFoldedProof<Backend> proof;
        proof.header = ProofHeader{
            kEncryptedFoldedProofVersion,
            profile_,
            trace_.provenance,
            trace_.circuit_id,
            setup_digest(setup_.public_setup),
            trace_.trace_id,
            circuit_.layers.size()};
        proof.reductions.reserve(circuit_.layers.size() - 1);
        observe_proof_header(proof.header, transcript_);
        gates::observe_gate_mle_setup(setup_.public_setup, transcript_);
        base_detail::observe_output_point(output_claim_.point,
                                          transcript_);
        return proof;
    }

    LayerClaim prove_affine_layer(
        std::size_t layer, const LayerClaim &current,
        EncryptedFoldedProof<Backend> &proof) {
        FoldedAffineReductionResult<Backend> reduction =
            prove_affine_resident<Backend>(
                setup_.context, circuit_, trace_, layer, current, transcript_,
                transport_.reserved_mult_depth, &gate_claims_,
                commitment_function_, nullptr, progress_);
        LayerClaim next = reduction.next_claim;
        proof.reductions.emplace_back(std::move(reduction.proof));
        return next;
    }

    LayerClaim prove_multiplication_layer(
        std::size_t layer, const LayerClaim &current,
        EncryptedFoldedProof<Backend> &proof) {
        const SingleClaim *single = std::get_if<SingleClaim>(&current);
        if (single == nullptr) {
            throw std::logic_error(
                "prove_folded: multiplication received a batched claim");
        }
        FoldedMultiplicationReductionResult<Backend> reduction =
            prove_multiplication_resident_dense<Backend>(
                setup_.context, circuit_, trace_, layer, *single, transcript_,
                transport_.reserved_mult_depth, commitment_function_,
                progress_);
        LayerClaim next = reduction.next_claim;
        proof.reductions.emplace_back(std::move(reduction.proof));
        return next;
    }

    /// Public payload and its canonical layered arithmetization.
    const payload::PayloadCircuit &payload_;
    const payload::LayeredCircuit &circuit_;
    /// Resident encrypted witness; public padding remains represented as null.
    const payload::EncryptedTrace<Backend> &trace_;
    /// Evaluation context and preprocessed GateMLE prover key.
    const EvaluationSetup<Backend> &setup_;
    /// Initial single claim at layer zero; its value is hidden from the server.
    SingleClaim output_claim_;
    /// Fiat--Shamir state shared by every Folded reduction in proof order.
    Transcript &transcript_;
    /// Fixed Folded protocol domain and GateMLE commitment mode.
    ProtocolProfile profile_;
    /// Batched collection of the public-gate evaluations used by reductions.
    ::laminate::gkr::detail::ProverGateClaims gate_claims_;
    /// Exact modulus level expected for each resident trace layer at ingress.
    std::vector<std::size_t> proof_ingress_rns_limbs_by_layer_;
    /// Message packing and retained-depth policy for the encrypted transcript.
    ProofTransportPolicy transport_;
    PackedMessageCommitmentFunction<Backend> commitment_function_;
    RuntimeProgressCallback progress_;
};

/// Diagnostic entry point for tests and cost/noise analysis that need the
/// round ciphertexts before placement. Whole proofs use
/// `protocol::reference::prove_folded`.
template <fhe::FheBackend Backend>
EncryptedFoldedProof<Backend> prove_folded_gkr_resident(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const payload::EncryptedTrace<Backend> &trace,
    const EvaluationSetup<Backend> &setup, std::span<const Fpk> output_point,
    Transcript &transcript,
    std::span<const std::size_t> proof_ingress_rns_limbs_by_layer,
    ProofTransportPolicy transport = {},
    PackedMessageCommitmentFunction<Backend> commitment_function = {},
    RuntimeProgressCallback progress = {}) {
    return FoldedResidentProver<Backend>(
               payload, circuit, trace, setup, output_point, transcript,
               proof_ingress_rns_limbs_by_layer, transport,
               std::move(commitment_function), std::move(progress))
        .run();
}

} // namespace laminate::gkr::folded_detail

#endif // LAMINATE_GKR_DETAIL_FOLDED_REFERENCE_PROVER_HPP
