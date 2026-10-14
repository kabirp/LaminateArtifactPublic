#ifndef LAMINATE_GKR_DETAIL_BASE_REFERENCE_PROVER_HPP
#define LAMINATE_GKR_DETAIL_BASE_REFERENCE_PROVER_HPP

/// @file prover.hpp
/// @brief Resident LaminateBase parity prover for bounded tests.

#include "laminate/gkr/detail/base/reference/affine_prover.hpp"
#include "laminate/gkr/detail/base/geometry/circuit.hpp"
#include "laminate/gkr/detail/base/reference/multiplication_prover.hpp"
#include "laminate/gkr/detail/base/transcript/reduction.hpp"
#include "laminate/gkr/detail/base/validation/request.hpp"

#include <cstddef>
#include <span>
#include <stdexcept>
#include <utility>
#include <variant>
#include <vector>

namespace laminate::gkr::base_detail {

/// Builds a LaminateBase proof while carrying one typed claim between layers.
template <fhe::FheBackend Backend>
class ResidentBaseReferenceProver {
  public:
    /// Output-to-input state used by profiling to stop between layer
    /// reductions. This path changes source residency, not Base arithmetic.
    struct BaseResidentProofState {
        EncryptedBaseProof<Backend> proof;
        LayerClaim current_claim;
        std::size_t next_layer = 0;
        bool proof_complete = false;
    };

    enum class TraceAdmission {
        SyntheticOnly,
        TestMayUseFheEvaluated,
    };
    ResidentBaseReferenceProver(
        const payload::PayloadCircuit &payload,
        const payload::LayeredCircuit &circuit,
        const payload::EncryptedTrace<Backend> &trace,
        const EvaluationSetup<Backend> &setup,
        std::span<const Fpk> output_point, Transcript &transcript,
        TraceAdmission admission = TraceAdmission::SyntheticOnly)
        : payload_(payload), circuit_(circuit), trace_(trace), setup_(setup),
          output_claim_{std::vector<Fpk>(output_point.begin(),
                                            output_point.end()),
                           Fpk::zero()},
          transcript_(transcript),
          admission_(admission),
          profile_{ProtocolVariant::LaminateBase,
                   setup.public_setup.gate_mle_profile,
                   CrossRoundPacking::None},
          provider_(circuit),
          gate_claims_(circuit, setup.public_setup, transcript) {}

    EncryptedBaseProof<Backend> run() {
        // Step 1: Validate the bounded resident trace and bind the proof
        // header, GateMLE setup, and output point.
        BaseResidentProofState state = begin();

        // Step 2: Reduce every circuit layer from the claimed output toward
        // the public input layer.
        while (has_next_layer(state)) {
            reduce_next_layer(state);
        }

        // Step 3: Publish the GateMLE opening accumulated by all reductions.
        finish(state);
        return std::move(state.proof);
    }

    BaseResidentProofState begin() {
        validate_request();
        return BaseResidentProofState{begin_proof(), LayerClaim{output_claim_}};
    }

    bool has_next_layer(const BaseResidentProofState &state) const {
        return !state.proof_complete &&
               state.next_layer + 1U < circuit_.layers.size();
    }

    payload::LayerKind next_layer_kind(
        const BaseResidentProofState &state) const {
        if (!has_next_layer(state)) {
            throw std::logic_error("LaminateBase: no layer remains");
        }
        return payload::layer_kind(circuit_.layers[state.next_layer]);
    }

    void reduce_next_layer(BaseResidentProofState &state) {
        // Step 1: Identify the relation that consumes the current claim.
        const std::size_t layer = state.next_layer;
        const payload::LayerKind kind = next_layer_kind(state);

        // Step 2: Prove that affine or multiplication relation and carry its
        // source claim into the next reduction.
        if (kind == payload::LayerKind::Affine) {
            state.current_claim =
                prove_affine_layer(layer, state.current_claim, state.proof);
        } else {
            state.current_claim = prove_multiplication_layer(
                layer, state.current_claim, state.proof);
        }
        // Step 3: Advance only after the proof message and next claim exist.
        ++state.next_layer;
    }

    void finish(BaseResidentProofState &state) {
        if (state.proof_complete || has_next_layer(state)) {
            throw std::logic_error(
                "LaminateBase: cannot finish before all layers");
        }
        state.proof.gate_mle_opening =
            gate_claims_.finish(setup_.gate_mle_prover_key);
        state.proof_complete = true;
    }

  private:
    void validate_request() const {
        setup_.public_setup.validate(payload_, circuit_);
        // A resident trace has no authenticated component-wise ingress
        // certificate. Keep this API as a bounded synthetic parity path only;
        // every FHE-evaluated Base execution must enter through checkpoint
        // replay, whose setup-bound schedule validates each exact source
        // level before proving.
        if (trace_.provenance !=
                payload::TraceProvenance::SyntheticTrace &&
            admission_ != TraceAdmission::TestMayUseFheEvaluated) {
            throw std::invalid_argument(
                "prove_base: resident proving accepts synthetic reference "
                "traces only; use "
                "the checkpoint-replay Base prover");
        }
        if (setup_.public_setup.honest_payload_noise_schedule_digest ||
            setup_.public_setup
                .honest_base_proof_noise_assessment_digest) {
            throw std::invalid_argument(
                "prove_base: setup-bound proof schedules require the "
                "authenticated checkpoint-replay prover");
        }
        validate_profile(profile_, setup_.public_setup, circuit_);
        validate_trace_shape<Backend>(setup_.context, circuit_, trace_);
        if (trace_.circuit_id != setup_.public_setup.circuit_digest ||
            output_claim_.point.size() != layer_vars(circuit_, 0)) {
            throw std::invalid_argument(
                "prove_base: trace ID or output point does not match setup");
        }
    }

    EncryptedBaseProof<Backend> begin_proof() {
        EncryptedBaseProof<Backend> proof;
        proof.header = ProofHeader{
            kEncryptedBaseProofVersion,
            profile_,
            trace_.provenance,
            trace_.circuit_id,
            setup_digest(setup_.public_setup),
            trace_.trace_id,
            circuit_.layers.size()};
        proof.reductions.reserve(circuit_.layers.size() - 1);
        observe_proof_header(proof.header, transcript_);
        gates::observe_gate_mle_setup(setup_.public_setup, transcript_);
        observe_output_point(output_claim_.point, transcript_);
        return proof;
    }

    LayerClaim prove_affine_layer(
        std::size_t layer, const LayerClaim &current,
        EncryptedBaseProof<Backend> &proof) {
        auto reduction = prove_affine_resident<Backend>(
            setup_.context, circuit_, trace_, layer, current, provider_,
            transcript_, &gate_claims_);
        LayerClaim next = reduction.next_claim;
        proof.reductions.emplace_back(std::move(reduction.proof));
        return next;
    }

    LayerClaim prove_multiplication_layer(
        std::size_t layer, const LayerClaim &current,
        EncryptedBaseProof<Backend> &proof) {
        const auto *single = std::get_if<SingleClaim>(&current);
        if (single == nullptr) {
            throw std::logic_error(
                "prove_base: multiplication received a batched claim");
        }
        auto reduction = prove_multiplication_resident<Backend>(
            setup_.context, circuit_, trace_, layer, *single, transcript_);
        LayerClaim next = reduction.next_claim;
        proof.reductions.emplace_back(std::move(reduction.proof));
        return next;
    }

    const payload::PayloadCircuit &payload_;
    const payload::LayeredCircuit &circuit_;
    const payload::EncryptedTrace<Backend> &trace_;
    const EvaluationSetup<Backend> &setup_;
    SingleClaim output_claim_;
    Transcript &transcript_;
    TraceAdmission admission_ = TraceAdmission::SyntheticOnly;
    ProtocolProfile profile_;
    gates::DirectGateMle provider_;
    ::laminate::gkr::detail::ProverGateClaims gate_claims_;
};

template <fhe::FheBackend Backend>
EncryptedBaseProof<Backend> prove_resident_synthetic_reference(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const payload::EncryptedTrace<Backend> &trace,
    const EvaluationSetup<Backend> &setup, std::span<const Fpk> output_point,
    Transcript &transcript) {
    return ResidentBaseReferenceProver<Backend>(
               payload, circuit, trace, setup, output_point, transcript)
        .run();
}

/// Test-only resident parity entry point. It bypasses only the resident
/// provenance quarantine; shape, setup, context, trace-level, and transcript
/// validation remain identical. Production code must use the checkpoint-
/// replay prover.
template <fhe::FheBackend Backend>
EncryptedBaseProof<Backend> prove_resident_test_reference(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const payload::EncryptedTrace<Backend> &trace,
    const EvaluationSetup<Backend> &setup,
    std::span<const Fpk> output_point, Transcript &transcript) {
    return ResidentBaseReferenceProver<Backend>(
               payload, circuit, trace, setup, output_point, transcript,
               ResidentBaseReferenceProver<Backend>::TraceAdmission::
                   TestMayUseFheEvaluated)
        .run();
}

} // namespace laminate::gkr::base_detail

#endif // LAMINATE_GKR_DETAIL_BASE_REFERENCE_PROVER_HPP
