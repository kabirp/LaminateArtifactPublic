#ifndef LAMINATE_GKR_DETAIL_LANED_REFERENCE_PROVER_HPP
#define LAMINATE_GKR_DETAIL_LANED_REFERENCE_PROVER_HPP

/// @file prover.hpp
/// @brief Resident LaminateLaned GKR parity prover for bounded diagnostics.

#include "laminate/gkr/laned.hpp"
#include "laminate/gkr/detail/base/transcript/reduction.hpp"
#include "laminate/gkr/detail/laned/affine/reference/prover.hpp"
#include "laminate/gkr/detail/laned/geometry/layers.hpp"
#include "laminate/gkr/detail/laned/multiplication/reference/prover.hpp"
#include "laminate/gkr/detail/laned/validation/request.hpp"
#include "laminate/runtime_progress.hpp"

#include <cstddef>
#include <span>
#include <stdexcept>
#include <utility>
#include <variant>
#include <vector>

namespace laminate::gkr::laned_detail {

/// Mutable output-to-input state of one resident Laned GKR proof.
///
/// `current_claim` is the claim on `next_layer`. Each completed affine or
/// multiplication reduction replaces it with a claim on the following source
/// layer and increments `next_layer`. `proof` owns messages in that same order.
template <fhe::FheBackend Backend>
struct LanedResidentGkrProvingState {
    /// Proof prefix containing exactly the reductions already completed.
    EncryptedLanedProof<Backend> proof;
    /// Claim consumed by the next layer reduction.
    LayerClaim current_claim;
    /// Index of the output-side layer reduced next.
    std::size_t next_layer = 0;
    /// Set only after every reduction and the GateMLE opening are published.
    bool finished = false;
};

/// Builds the pre-packing encrypted GKR transcript from a bounded resident
/// trace. This diagnostic path retains explicit resident layer recurrences;
/// packing, commitments, and proof transport stay outside this class.
template <fhe::FheBackend Backend>
class LanedResidentProver {
  public:
    using ProvingState = LanedResidentGkrProvingState<Backend>;

    LanedResidentProver(
        const payload::PayloadCircuit &payload,
        const payload::LayeredCircuit &circuit,
        const payload::EncryptedTrace<Backend> &trace,
        const EvaluationSetup<Backend> &setup,
        std::span<const std::size_t> proof_ingress_rns_limbs_by_layer,
        std::span<const Fpk> output_point, Transcript &transcript,
        ProofTransportPolicy transport,
        PackedMessageCommitmentFunction<Backend>
            commitment_function = {},
        RuntimeProgressCallback progress = {})
        : payload_(payload), circuit_(circuit), trace_(trace), setup_(setup),
          proof_ingress_rns_limbs_by_layer_(
              proof_ingress_rns_limbs_by_layer.begin(),
              proof_ingress_rns_limbs_by_layer.end()),
          output_claim_{std::vector<Fpk>(output_point.begin(),
                                            output_point.end()),
                           Fpk::zero()},
          transcript_(transcript),
          profile_{ProtocolVariant::LaminateLaned,
                   setup.public_setup.gate_mle_profile,
                   CrossRoundPacking::None},
          gate_claims_(circuit, setup.public_setup, transcript),
          transport_(transport),
          commitment_function_(std::move(commitment_function)),
          progress_(std::move(progress)) {}

    EncryptedLanedProof<Backend> run() {
        // Step 1: Validate the request and bind the proof header, GateMLE
        // setup, and claimed output point to Fiat--Shamir.
        ProvingState state = begin();

        // Step 2: Traverse the circuit from its claimed output to its public
        // input, replacing the current claim after each layer reduction.
        while (has_next_layer(state)) {
            reduce_next_layer(state);
        }

        // Step 3: Publish the one GateMLE opening accumulated by all layers.
        finish(state);
        return std::move(state.proof);
    }

    ProvingState begin() {
        validate_request();
        return ProvingState{begin_proof(), LayerClaim{output_claim_}};
    }

    bool has_next_layer(const ProvingState &state) const {
        return !state.finished &&
               state.next_layer + 1U < circuit_.layers.size();
    }

    payload::LayerKind next_layer_kind(const ProvingState &state) const {
        if (!has_next_layer(state)) {
            throw std::logic_error("LaminateLaned: no layer remains");
        }
        return payload::layer_kind(circuit_.layers[state.next_layer]);
    }

    void reduce_next_layer(ProvingState &state) {
        const std::size_t layer = state.next_layer;
        const payload::LayerKind kind = next_layer_kind(state);
        RuntimeProgressSpan reduction_progress(
            progress_, RuntimeProgressEvent{
                           .stage = RuntimeProgressStage::LanedReduction,
                           .layer_kind =
                               kind == payload::LayerKind::Affine
                                   ? RuntimeProgressLayerKind::Affine
                                   : RuntimeProgressLayerKind::Multiplication,
                           .reduction_layer = layer,
                           .source_layer = layer + 1U});

        if (kind == payload::LayerKind::Affine) {
            // Step 1: Reduce an affine output claim to one transformed source
            // claim using the Laned affine sumcheck.
            state.current_claim =
                prove_affine_layer(layer, state.current_claim, state.proof);
        } else {
            // Step 1: Reduce a multiplication output claim to one source
            // claim by interpolating the left/right selector after sumcheck.
            state.current_claim = prove_multiplication_layer(
                layer, state.current_claim, state.proof);
        }

        // Step 2: Advance only after the next claim and proof message are owned.
        ++state.next_layer;
        reduction_progress.finish();
    }

    void finish(ProvingState &state) {
        if (state.finished || has_next_layer(state)) {
            throw std::logic_error(
                "LaminateLaned: cannot finish before all layers");
        }
        RuntimeProgressSpan gate_progress(
            progress_, RuntimeProgressEvent{
                           .stage = RuntimeProgressStage::LanedGateMleFinish});
        state.proof.gate_mle_opening =
            gate_claims_.finish(setup_.gate_mle_prover_key);
        gate_progress.finish();
        state.finished = true;
    }

  private:
    void validate_request() const {
        setup_.public_setup.validate(payload_, circuit_);
        validate_profile(profile_, setup_.public_setup, circuit_);
        validate_trace_shape(setup_.context, circuit_, trace_,
                             proof_ingress_rns_limbs_by_layer_);
        if (Backend::slot_count(setup_.context) < 2 * kExtensionDegree ||
            trace_.circuit_id != setup_.public_setup.circuit_digest ||
            output_claim_.point.size() !=
                laned_layer_variables(circuit_, 0)) {
            throw std::invalid_argument(
                "prove_laned: requires at least 16 slots and matching IDs");
        }
    }

    EncryptedLanedProof<Backend> begin_proof() {
        EncryptedLanedProof<Backend> proof;
        proof.header = ProofHeader{
            kEncryptedLanedProofVersion,
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
        EncryptedLanedProof<Backend> &proof) {
        LanedAffineLayerReductionResult<Backend> reduction =
            prove_affine_resident_reference<Backend>(
            setup_.context, circuit_, trace_, layer, current, transcript_,
            proof_ingress_rns_limbs_by_layer_.at(layer + 1U),
            transport_.reserved_mult_depth, &gate_claims_,
            commitment_function_, progress_);
        LayerClaim next = reduction.next_claim;
        proof.reductions.emplace_back(std::move(reduction.proof));
        return next;
    }

    LayerClaim prove_multiplication_layer(
        std::size_t layer, const LayerClaim &current,
        EncryptedLanedProof<Backend> &proof) {
        const auto *single = std::get_if<SingleClaim>(&current);
        if (single == nullptr) {
            throw std::logic_error(
                "prove_laned: multiplication received a batched claim");
        }
        LanedMultiplicationLayerReductionResult<Backend> reduction =
            prove_multiplication_resident_reference<Backend>(
            setup_.context, circuit_, trace_, layer, *single, transcript_,
            proof_ingress_rns_limbs_by_layer_.at(layer + 1U),
            transport_.reserved_mult_depth, commitment_function_,
            progress_);
        LayerClaim next = reduction.next_claim;
        proof.reductions.emplace_back(std::move(reduction.proof));
        return next;
    }

    /// Public payload semantics authenticated by setup.
    const payload::PayloadCircuit &payload_;
    /// Layered arithmetization traversed from output to input.
    const payload::LayeredCircuit &circuit_;
    /// Resident encrypted witness trace consumed by layer reductions.
    const payload::EncryptedTrace<Backend> &trace_;
    /// FHE context, public GateMLE setup, and its prover key.
    const EvaluationSetup<Backend> &setup_;
    /// Required source RNS level for each reduction boundary.
    std::vector<std::size_t> proof_ingress_rns_limbs_by_layer_;
    /// Public output point with an encrypted-prover value placeholder.
    SingleClaim output_claim_;
    /// Fiat--Shamir state shared by all reductions in proof order.
    Transcript &transcript_;
    /// Variant and GateMLE mode bound into the proof header.
    ProtocolProfile profile_;
    /// Affine GateMLE claims accumulated into one final opening.
    ::laminate::gkr::detail::ProverGateClaims gate_claims_;
    /// Message-compaction policy for encrypted proof transport.
    ProofTransportPolicy transport_;
    /// Optional binding applied to packed messages in transcript order.
    PackedMessageCommitmentFunction<Backend> commitment_function_;
    /// Diagnostics wrapped around named proving phases.
    RuntimeProgressCallback progress_;
};

/// Diagnostic entry point for tests and analysis of the pre-packing GKR
/// transcript. Bounded whole-proof tests use
/// `protocol::reference::prove_laned`; production servers use checkpoint
/// replay and external transcript packing.
template <fhe::FheBackend Backend>
EncryptedLanedProof<Backend> prove_laned_gkr_resident(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const payload::EncryptedTrace<Backend> &trace,
    const EvaluationSetup<Backend> &setup,
    std::span<const std::size_t> proof_ingress_rns_limbs_by_layer,
    std::span<const Fpk> output_point,
    Transcript &transcript, ProofTransportPolicy transport = {},
    PackedMessageCommitmentFunction<Backend> commitment_function = {},
    RuntimeProgressCallback progress = {}) {
    return LanedResidentProver<Backend>(
               payload, circuit, trace, setup,
               proof_ingress_rns_limbs_by_layer, output_point, transcript,
               transport, std::move(commitment_function),
               std::move(progress))
        .run();
}

} // namespace laminate::gkr::laned_detail

#endif // LAMINATE_GKR_DETAIL_LANED_REFERENCE_PROVER_HPP
