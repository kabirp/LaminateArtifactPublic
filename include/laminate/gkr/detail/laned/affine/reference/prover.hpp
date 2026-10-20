#ifndef LAMINATE_GKR_DETAIL_LANED_AFFINE_REFERENCE_PROVER_HPP
#define LAMINATE_GKR_DETAIL_LANED_AFFINE_REFERENCE_PROVER_HPP

/// @file prover.hpp
/// @brief Resident reference affine-layer proving for LaminateLaned.

#include "laminate/gkr/detail/laned/affine/internal/gate_claim.hpp"
#include "laminate/gkr/detail/laned/affine/internal/hadamard.hpp"
#include "laminate/gkr/detail/laned/affine/arithmetic/lane_placement.hpp"
#include "laminate/gkr/detail/laned/affine/reference/ciphertext_round.hpp"
#include "laminate/gkr/detail/laned/affine/arithmetic/slot_round.hpp"
#include "laminate/gkr/detail/laned/affine/types.hpp"
#include "laminate/gkr/detail/laned/proof/message.hpp"
#include "laminate/gkr/detail/laned/validation/request.hpp"
#include "laminate/gkr/detail/shared/packed/transcript.hpp"
#include "laminate/gkr/detail/shared/reduction/gate_claims.hpp"
#include "laminate/runtime_progress.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <span>
#include <utility>
#include <vector>

namespace laminate::gkr::laned_detail {

/// Stateful affine prover with one method per mathematical phase.
///
/// The reduction proves the multilinear identity
///
///   claim - constant = sum_x A(current, x) W(x).
///
/// Lane equality is fused into H(x,b)=eq(z,b)W(x,b). Ciphertext-index rounds
/// scan the base trace using scalar plaintext weights, then slot rounds share
/// one lane-weighted extension checkpoint. The Hadamard transform converts
/// the terminal H evaluation back into a claim on W. The exact FHE calls are
/// in `affine_ciphertext_round_evaluations` under
/// `reference/ciphertext_round.hpp` and `affine_slot_round_evaluations` under
/// `slot_round.hpp`.
template <fhe::FheBackend Backend>
class LanedResidentAffineLayerReductionProver {
  public:
    LanedResidentAffineLayerReductionProver(
        const typename Backend::EvalContext &eval,
        const payload::LayeredCircuit &circuit,
        const payload::EncryptedTrace<Backend> &trace,
        std::size_t layer, const LayerClaim &claim,
        Transcript &transcript,
        std::size_t source_proof_ingress_rns_limbs,
        std::size_t reserved_transport_depth,
        detail::ProverGateClaims *gate_claims = nullptr,
        PackedMessageCommitmentFunction<Backend>
            commitment_function = {},
        RuntimeProgressCallback progress = {})
        : eval_(eval), trace_(trace), layer_(layer),
          claim_(claim), transcript_(transcript),
          geometry_(LanedAffineLayerReductionGeometry::create(
              circuit, layer, claim,
              payload::canonical_layer_wire_support(
                  circuit, layer + 1U))),
          round_state_(geometry_.gate_table, geometry_.round_count),
          reserved_transport_depth_(reserved_transport_depth),
          gate_claims_(gate_claims),
          commitment_function_(std::move(commitment_function)),
          progress_(std::move(progress)) {
        const typename Backend::Ciphertext *level_reference = nullptr;
        for (const auto &value : source().wires) {
            if (value.is_public()) {
                continue;
            }
            validate_exact_proof_ingress_ciphertext<Backend>(
                eval_, value.ciphertext(),
                source_proof_ingress_rns_limbs,
                "LaminateLaned resident affine source");
            if (level_reference == nullptr) {
                level_reference = &value.ciphertext();
            }
        }
        prepared_lane_bases_ = prepare_laned_lane_bases<Backend>(
            eval_, level_reference,
            geometry_.source,
            geometry_.lane_weights);
        result_.proof.rounds.reserve(geometry_.round_count);
    }

    /// Follow the affine reduction in protocol order. The two round families
    /// are separate because ciphertext coordinates require a source scan,
    /// whereas slot coordinates reuse one encrypted checkpoint.
    LanedAffineLayerReductionResult<Backend> run() {
        // Step 1: Bind the optional affine-constant opening and this layer's
        // sumcheck domain before publishing the first round message.
        record_affine_constant_claim();
        detail::observe_packed_reduction_begin<
            ProtocolVariant::LaminateLaned>(
            layer_, payload::LayerKind::Affine, geometry_.round_count,
            transcript_);

        // Step 2: Fix every packed-ciphertext coordinate. Each round scans the
        // resident source and evaluates the encrypted polynomial R_j.
        prove_ciphertext_index_rounds();

        // Step 3: Collapse the fixed ciphertext coordinates into the one
        // encrypted slot table reused by all remaining rounds.
        const fhe::ExtensionValue<Backend> checkpoint =
            build_slot_checkpoint();

        // Step 4: Fix every SIMD-slot coordinate without rescanning the trace.
        prove_slot_index_rounds(checkpoint);

        // Step 5: Publish the terminal weighted-source evaluation and bind the
        // corresponding public GateMLE opening.
        publish_terminal_message(evaluate_affine_checkpoint<Backend>(
            eval_, checkpoint, slot_index_point()));
        record_terminal_gate_claim();

        // Step 6: Apply the Laned Hadamard coordinate transform to obtain the
        // source-layer claim consumed by the next GKR reduction.
        result_.next_claim = transformed_next_claim();
        return std::move(result_);
    }

  private:
    const payload::EncryptedTraceLayer<Backend> &source() const {
        return trace_.layers[layer_ + 1];
    }

    void record_affine_constant_claim() {
        if (gate_claims_ && gate_claims_->requires_opening()) {
            (void)affine_constant_at(
                *gate_claims_, layer_, geometry_.output, claim_);
        }
    }

    Fpk sample_challenge(std::size_t round) {
        if (round < geometry_.lane_begin) {
            return transcript_.challenge_fpk();
        }
        return challenge_hadamard_safe(
            transcript_,
            geometry_.lane_point[round - geometry_.lane_begin]);
    }

    void publish_round(
        std::size_t round,
        LanedAffineRoundEvaluations<Backend> evaluations) {
        std::array<fhe::ExtensionValue<Backend>, 2> transport_order =
            std::move(evaluations).into_transport_order();
        EncryptedLanedLayerReductionSumcheckRound<Backend> message{
            pack_laned_proof_message<Backend>(
                eval_, transport_order, reserved_transport_depth_)};
        detail::observe_packed_round<
            ProtocolVariant::LaminateLaned, Backend>(
                layer_, round, message, transcript_, commitment_function_);
        result_.proof.rounds.push_back(std::move(message));
    }

    LanedAffineRoundEvaluations<Backend>
    ciphertext_round_evaluations() {
        const LanedAffineRoundEvaluationPoints points;
        const LanedAffineGateRestrictions gate_values =
            round_state_.evaluate_public_gate(points);
        return affine_ciphertext_round_evaluations<Backend>(
            eval_, source(), geometry_.source_support, geometry_.source,
            geometry_.lane_weights, gate_values,
            round_state_.fixed_point(), points, prepared_lane_bases_);
    }

    std::span<const Fpk> slot_index_point() const {
        return round_state_.slot_point(
            geometry_.ciphertext_index_variables);
    }

    LanedAffineRoundEvaluations<Backend>
    slot_round_evaluations(
        const fhe::ExtensionValue<Backend> &checkpoint) {
        const std::span<const Fpk> prefix = slot_index_point();
        const LanedAffineRoundEvaluationPoints points;
        const LanedAffineGateRestrictions gate_values =
            round_state_.evaluate_public_gate(points);
        return affine_slot_round_evaluations<Backend>(
            eval_, checkpoint, geometry_.source, gate_values, prefix);
    }

    void prove_ciphertext_index_rounds() {
        for (std::size_t round = 0;
             round < geometry_.ciphertext_index_variables; ++round) {
            RuntimeProgressSpan round_progress(
                progress_, sumcheck_round_event(round));
            // Step 1: Evaluate encrypted R_j(1) and R_j(2). The exact FHE
            // accumulation is in reference/ciphertext_round.hpp.
            LanedAffineRoundEvaluations<Backend> evaluations =
                ciphertext_round_evaluations();

            // Step 2: Publish R_j(1), R_j(2) and bind them to Fiat--Shamir.
            // Since claim_j = R_j(0) + R_j(1), these two transmitted values
            // determine the complete degree-two polynomial R_j.
            publish_round(round, std::move(evaluations));

            // Step 3: Sample r_j only after the message is transcript-bound.
            const Fpk challenge = sample_challenge(round);

            // Step 4: Fix the same coordinate in the encrypted source MLE and
            // public GateMLE state. The verifier carries
            // claim_{j+1}=R_j(r_j) at this point.
            round_state_.fix_next_variable(challenge);
            round_progress.finish();
        }
    }

    fhe::ExtensionValue<Backend> build_slot_checkpoint() {
        RuntimeProgressSpan checkpoint_progress(
            progress_, slot_checkpoint_event());
        fhe::ExtensionValue<Backend> checkpoint =
            affine_slot_checkpoint<Backend>(
            eval_, source(), geometry_.source_support, geometry_.source,
            geometry_.lane_weights, round_state_.fixed_point(),
            prepared_lane_bases_);
        checkpoint_progress.finish();
        return checkpoint;
    }

    void prove_slot_index_rounds(
        const fhe::ExtensionValue<Backend> &checkpoint) {
        for (std::size_t offset = 0;
             offset < geometry_.slot_index_variables;
             ++offset) {
            const std::size_t round =
                geometry_.ciphertext_index_variables + offset;
            RuntimeProgressSpan round_progress(
                progress_, sumcheck_round_event(round));
            // Step 1: Evaluate encrypted R_j(1) and R_j(2) from the retained
            // slot checkpoint; no trace scan occurs in a slot round.
            LanedAffineRoundEvaluations<Backend> evaluations =
                slot_round_evaluations(checkpoint);

            // Step 2: Publish and bind R_j(1), R_j(2). The verifier recovers
            // R_j(0)=claim_j-R_j(1) before interpolating the quadratic.
            publish_round(round, std::move(evaluations));

            // Step 3: Sample the Hadamard-safe slot challenge r_j.
            const Fpk challenge = sample_challenge(round);

            // Step 4: Fix r_j in both the checkpoint point and GateMLE table.
            round_state_.fix_next_variable(challenge);
            round_progress.finish();
        }
    }

    RuntimeProgressEvent sumcheck_round_event(std::size_t round) const {
        return RuntimeProgressEvent{
            .stage = RuntimeProgressStage::LanedAffineSumcheckRound,
            .layer_kind = RuntimeProgressLayerKind::Affine,
            .coordinate_domain =
                round < geometry_.ciphertext_index_variables
                    ? RuntimeProgressCoordinateDomain::CiphertextIndex
                    : RuntimeProgressCoordinateDomain::SlotIndex,
            .reduction_layer = layer_,
            .source_layer = layer_ + 1U,
            .round = round,
            .round_count = geometry_.round_count,
            .work_units =
                round < geometry_.ciphertext_index_variables
                    ? source().wires.size()
                    : 1U,
        };
    }

    RuntimeProgressEvent slot_checkpoint_event() const {
        return RuntimeProgressEvent{
            .stage = RuntimeProgressStage::LanedAffineSlotCheckpoint,
            .layer_kind = RuntimeProgressLayerKind::Affine,
            .coordinate_domain =
                RuntimeProgressCoordinateDomain::SlotIndex,
            .reduction_layer = layer_,
            .source_layer = layer_ + 1U,
            .checkpoint_layer = layer_ + 1U,
            .work_units = source().wires.size(),
        };
    }

    void publish_terminal_message(
        const fhe::ExtensionValue<Backend> &terminal) {
        const std::array<fhe::ExtensionValue<Backend>, 1> values{
            terminal};
        result_.proof.packed_terminal_value =
            pack_laned_proof_message<Backend>(
                eval_, values, reserved_transport_depth_);
        detail::observe_packed_terminal<
            ProtocolVariant::LaminateLaned, Backend>(
                layer_, result_.proof.packed_terminal_value,
                transcript_, commitment_function_);
    }

    void record_terminal_gate_claim() {
        if (gate_claims_ && gate_claims_->requires_opening()) {
            (void)affine_wire_at(
                *gate_claims_, layer_, geometry_.output,
                geometry_.source, claim_, round_state_.fixed_point());
        }
    }

    SingleClaim transformed_next_claim() const {
        const std::vector<Fpk> raw_lane(
            round_state_.owned_point().begin() +
                static_cast<std::ptrdiff_t>(geometry_.lane_begin),
            round_state_.owned_point().end());
        const HadamardTransform transform =
            hadamard_transform(geometry_.lane_point, raw_lane);
        std::vector<Fpk> next_point = round_state_.owned_point();
        std::copy(
            transform.point.begin(), transform.point.end(),
            next_point.begin() +
                static_cast<std::ptrdiff_t>(geometry_.lane_begin));
        return SingleClaim{std::move(next_point), Fpk::zero()};
    }

    /// FHE context used by the encrypted affine kernels and message packing.
    const typename Backend::EvalContext &eval_;
    /// Resident encrypted source values for every circuit layer.
    const payload::EncryptedTrace<Backend> &trace_;
    /// Affine output layer whose claim is being reduced.
    std::size_t layer_;
    /// Single or batched claim on the current affine output layer.
    const LayerClaim &claim_;
    /// Fiat--Shamir state; messages are observed before challenges are drawn.
    Transcript &transcript_;
    /// Public packed-domain geometry fixed for this reduction.
    LanedAffineLayerReductionGeometry geometry_;
    /// Source point and GateMLE restriction advanced by each challenge.
    LanedAffineCoordinateFixingState round_state_;
    /// Depth retained after compacting each encrypted proof message.
    std::size_t reserved_transport_depth_;
    /// Optional collector for the one final outsourced GateMLE opening.
    detail::ProverGateClaims *gate_claims_;
    /// Optional commitment applied without changing transcript order.
    PackedMessageCommitmentFunction<Backend> commitment_function_;
    /// Diagnostics wrapped around named protocol phases.
    RuntimeProgressCallback progress_;
    /// Round messages and the placeholder-valued source claim being built.
    LanedAffineLayerReductionResult<Backend> result_;
    /// Prepared public lane bases reused by every resident source scan.
    std::vector<detail::MixedPreparedFpkSlotBasis<Backend>>
        prepared_lane_bases_;
};

/// Prove one Laned affine layer.
///
/// Preconditions: a batched input claim, when present, shares one lane point.
/// Postcondition: the returned point has the Hadamard lane transform applied;
/// its plaintext claim value remains a placeholder until verification.
template <fhe::FheBackend Backend>
LanedAffineLayerReductionResult<Backend> prove_affine_resident_reference(
    const typename Backend::EvalContext &eval,
    const payload::LayeredCircuit &circuit,
    const payload::EncryptedTrace<Backend> &trace, std::size_t layer,
    const LayerClaim &claim, Transcript &transcript,
    std::size_t source_proof_ingress_rns_limbs,
    std::size_t reserved_transport_depth = 0,
    detail::ProverGateClaims *gate_claims = nullptr,
    PackedMessageCommitmentFunction<Backend> commitment_function = {},
    RuntimeProgressCallback progress = {}) {
    return LanedResidentAffineLayerReductionProver<Backend>(
               eval, circuit, trace, layer, claim, transcript,
               source_proof_ingress_rns_limbs,
               reserved_transport_depth, gate_claims,
               std::move(commitment_function), std::move(progress))
        .run();
}

} // namespace laminate::gkr::laned_detail

#endif // LAMINATE_GKR_DETAIL_LANED_AFFINE_REFERENCE_PROVER_HPP
