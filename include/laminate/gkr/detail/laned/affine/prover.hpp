#ifndef LAMINATE_GKR_DETAIL_LANED_AFFINE_PROVER_HPP
#define LAMINATE_GKR_DETAIL_LANED_AFFINE_PROVER_HPP

/// @file prover.hpp
/// @brief Canonical file-backed affine reduction for LaminateLaned.

#include "laminate/gkr/laned.hpp"
#include "laminate/gkr/detail/laned/affine/evaluator.hpp"
#include "laminate/gkr/detail/laned/affine/internal/gate_claim.hpp"
#include "laminate/gkr/detail/laned/affine/internal/hadamard.hpp"
#include "laminate/gkr/detail/laned/affine/arithmetic/slot_round.hpp"
#include "laminate/gkr/detail/laned/affine/types.hpp"
#include "laminate/gkr/detail/laned/proof/message.hpp"
#include "laminate/gkr/detail/shared/reduction/gate_claims.hpp"
#include "laminate/gkr/detail/shared/packed/transcript.hpp"
#include "laminate/payload/storage/file_trace_store.hpp"
#include "laminate/runtime_progress.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <stdexcept>
#include <utility>
#include <vector>

namespace laminate::gkr::laned_detail {

/// Affine prover whose source layer remains in a `FileEncryptedTraceStore`.
///
/// This class owns transcript order and the complete affine recurrence:
/// compute `R_j(1)` and `R_j(2)`, bind the message, sample `r_j`, then bind the
/// public gate table for the next round. `LanedAffineEvaluator` separately
/// owns the rewindable source reader and concrete FHE scan. For low-width
/// packed domains it also retains at most 64 challenge-independent packed
/// source ciphertexts. Slot rounds use the retained checkpoint and never
/// read the trace.
template <fhe::PersistableFheBackend Backend, typename TraceSource>
class LanedAffineLayerReductionProver {
  public:
    LanedAffineLayerReductionProver(
        const typename Backend::EvalContext &eval,
        const payload::LayeredCircuit &circuit,
        const TraceSource &trace,
        const LanedAffineSourceAdmission &source_admission,
        const payload::LayerWireSupport &source_support,
        std::size_t layer, const LayerClaim &claim, Transcript &transcript,
        std::size_t source_proof_ingress_rns_limbs,
        std::size_t reserved_transport_depth,
        detail::ProverGateClaims *gate_claims = nullptr,
        PackedMessageCommitmentFunction<Backend> commitment_function = {},
        LanedAffineStatistics *statistics = nullptr,
        RuntimeProgressCallback progress = {})
        : eval_(eval), layer_(layer), claim_(claim), transcript_(transcript),
          geometry_(LanedAffineLayerReductionGeometry::create(
              circuit, layer, claim, source_support)),
          round_state_(geometry_.gate_table, geometry_.round_count),
          evaluator_(eval, trace, layer, geometry_,
                     source_proof_ingress_rns_limbs, statistics),
          reserved_transport_depth_(reserved_transport_depth),
          gate_claims_(gate_claims),
          commitment_function_(std::move(commitment_function)),
          statistics_(statistics), progress_(std::move(progress)) {
        source_admission.require_matches(circuit, trace);
        if (statistics_ != nullptr) {
            *statistics_ = LanedAffineStatistics{};
        }
        result_.proof.rounds.reserve(geometry_.round_count);
    }

    LanedAffineLayerReductionResult<Backend> run() {
        // ===== Laminate affine protocol setup =============================
        // Step 1: Bind the optional affine-constant opening and this layer's
        // sumcheck domain before publishing the first round message.
        record_affine_constant_claim();
        detail::observe_packed_reduction_begin<
            ProtocolVariant::LaminateLaned>(
                layer_, payload::LayerKind::Affine, geometry_.round_count,
                transcript_);

        // ===== Challenge-independent low-width source packing ============
        // Step 2: When S/N is small, place the B-periodic source into those
        // packed ciphertexts once. This stage does not observe or advance the
        // transcript; wider domains retain the bounded streaming fallback.
        prepare_materialized_source();

        // ===== Ciphertext-index sumcheck: file scans plus FHE =============
        // Step 3: Fix every packed-ciphertext coordinate. Materialized rounds
        // scan S/N packed values; the fallback scans the original source.
        prove_ciphertext_index_rounds();

        // ===== File-backed source to in-memory checkpoint handoff =========
        // Step 4: Materialize the encrypted slot table. No later affine step
        // reads the trace or packed source.
        const fhe::ExtensionValue<Backend> checkpoint =
            build_slot_checkpoint();

        // ===== Slot-index sumcheck: checkpoint-only FHE ===================
        // Step 5: Fix every SIMD-slot coordinate without reading the trace.
        prove_slot_index_rounds(checkpoint);

        // ===== Laminate affine protocol completion ========================
        // Step 6: Publish the terminal weighted-source evaluation and bind the
        // corresponding public GateMLE opening.
        publish_terminal_message(evaluate_affine_checkpoint<Backend>(
            eval_, checkpoint, slot_index_point()));
        record_terminal_gate_claim();

        // Step 7: Apply the Laned Hadamard coordinate transform to form the
        // source-layer claim point consumed by the next GKR reduction.
        result_.next_claim = transformed_next_claim();
        return std::move(result_);
    }

  private:
    void prepare_materialized_source() {
        if (!evaluator_.uses_materialized_packed_source()) {
            return;
        }
        RuntimeProgressEvent event{
            .stage = RuntimeProgressStage::LanedAffineSourcePacking,
            .layer_kind = RuntimeProgressLayerKind::Affine,
            .coordinate_domain =
                RuntimeProgressCoordinateDomain::CiphertextIndex,
            .reduction_layer = layer_,
            .source_layer = layer_ + 1U,
            .work_units = evaluator_.source_preparation_work_units(),
        };
        RuntimeProgressSpan packing_progress(progress_, event);
        evaluator_.prepare_source(
            [&](std::size_t completed, std::size_t total) {
                event.boundary = RuntimeProgressBoundary::Update;
                event.completed_steps = completed;
                event.total_steps = total;
                event.completed_work_units = completed;
                event.total_work_units = total;
                notify_runtime_progress(progress_, event);
            });
        packing_progress.finish();
    }

    void prove_ciphertext_index_rounds() {
        for (std::size_t round = 0;
             round < geometry_.ciphertext_index_variables; ++round) {
            RuntimeProgressSpan round_progress(
                progress_, sumcheck_round_event(round));
            // Step 1: Ask the canonical evaluator for encrypted R_j(1) and
            // R_j(2). It performs one sequential source scan and the public-
            // scalar FHE accumulation shown in evaluator.hpp.
            LanedAffineRoundEvaluations<Backend> evaluations =
                ciphertext_round_evaluations();

            // Step 2: Publish and bind R_j(1), R_j(2). The verifier recovers
            // R_j(0)=claim_j-R_j(1), completing the quadratic R_j.
            publish_round(round, std::move(evaluations));

            // Step 3: Sample r_j only after the message is transcript-bound.
            const Fpk challenge = sample_challenge(round);

            // Step 4: Fix r_j in both the source-MLE point and public GateMLE
            // table used to construct the next round polynomial.
            round_state_.fix_next_variable(challenge);
            if (statistics_ != nullptr) {
                statistics_->public_gate_table_entries_processed =
                    round_state_.public_gate_entries_processed();
            }
            round_progress.finish();
        }
    }

    fhe::ExtensionValue<Backend> build_slot_checkpoint() {
        RuntimeProgressSpan checkpoint_progress(
            progress_, slot_checkpoint_event());
        fhe::ExtensionValue<Backend> checkpoint =
            evaluator_.build_slot_checkpoint(round_state_.fixed_point());
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
            // slot checkpoint. This round performs no source read.
            LanedAffineRoundEvaluations<Backend> evaluations =
                slot_round_evaluations(checkpoint);

            // Step 2: Publish and bind R_j(1), R_j(2). The identity
            // claim_j=R_j(0)+R_j(1) reconstructs the omitted endpoint.
            publish_round(round, std::move(evaluations));

            // Step 3: Sample the Hadamard-safe slot challenge r_j.
            const Fpk challenge = sample_challenge(round);

            // Step 4: Fix r_j in the checkpoint point and GateMLE table.
            round_state_.fix_next_variable(challenge);
            if (statistics_ != nullptr) {
                statistics_->public_gate_table_entries_processed =
                    round_state_.public_gate_entries_processed();
            }
            round_progress.finish();
        }
    }

    void record_affine_constant_claim() {
        if (gate_claims_ != nullptr && gate_claims_->requires_opening()) {
            (void)affine_constant_at(*gate_claims_, layer_,
                                     geometry_.output, claim_);
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
        return evaluator_.evaluate_ciphertext_index_round(
            gate_values, round_state_.fixed_point(), points);
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
        if (statistics_ != nullptr) {
            affine_detail::checked_accumulate(
                statistics_->slot_checkpoint_prefix_bindings, 1,
                "file-backed affine slot checkpoint prefix bindings");
            affine_detail::checked_accumulate(
                statistics_->slot_public_mask_pairs_constructed, 1,
                "file-backed affine slot public mask pairs");
        }
        return affine_slot_round_evaluations<Backend>(
            eval_, checkpoint, geometry_.source, gate_values, prefix);
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
        if (gate_claims_ != nullptr && gate_claims_->requires_opening()) {
            (void)affine_wire_at(*gate_claims_, layer_, geometry_.output,
                                 geometry_.source, claim_,
                                 round_state_.fixed_point());
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
                    ? evaluator_.ciphertext_index_work_units()
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
            .work_units = evaluator_.ciphertext_index_work_units(),
        };
    }

    SingleClaim transformed_next_claim() const {
        const std::vector<Fpk> raw_lane(
            round_state_.owned_point().begin() +
                static_cast<std::ptrdiff_t>(geometry_.lane_begin),
            round_state_.owned_point().end());
        const HadamardTransform transform =
            hadamard_transform(geometry_.lane_point, raw_lane);
        std::vector<Fpk> next_point = round_state_.owned_point();
        std::copy(transform.point.begin(), transform.point.end(),
                  next_point.begin() + static_cast<std::ptrdiff_t>(
                                           geometry_.lane_begin));
        return SingleClaim{std::move(next_point), Fpk::zero()};
    }

    /// FHE context used by source-scan kernels and message packing.
    const typename Backend::EvalContext &eval_;
    /// Affine output layer whose claim is being reduced.
    std::size_t layer_;
    /// Single or batched claim on that output layer.
    const LayerClaim &claim_;
    /// Fiat--Shamir state, advanced only after each message is published.
    Transcript &transcript_;
    /// Public packed-domain geometry fixed for this reduction.
    LanedAffineLayerReductionGeometry geometry_;
    /// Source point and GateMLE restriction advanced by each challenge.
    LanedAffineCoordinateFixingState round_state_;
    /// File/source access and concrete affine FHE arithmetic.
    LanedAffineEvaluator<Backend, TraceSource> evaluator_;
    /// Depth retained after compacting each encrypted proof message.
    std::size_t reserved_transport_depth_;
    /// Optional collector for the one final outsourced GateMLE opening.
    detail::ProverGateClaims *gate_claims_;
    /// Optional commitment applied without changing transcript order.
    PackedMessageCommitmentFunction<Backend> commitment_function_;
    /// Non-transcript counters for scan and FHE-resource diagnostics.
    LanedAffineStatistics *statistics_;
    /// Diagnostics wrapped around named protocol phases.
    RuntimeProgressCallback progress_;
    /// Round messages and the placeholder-valued source claim being built.
    LanedAffineLayerReductionResult<Backend> result_;
};

/// Prove one affine layer after top-level source/circuit admission.
template <fhe::PersistableFheBackend Backend, typename TraceSource>
LanedAffineLayerReductionResult<Backend> prove_admitted_affine(
    const typename Backend::EvalContext &eval,
    const payload::LayeredCircuit &circuit,
    const TraceSource &trace,
    const LanedAffineSourceAdmission &source_admission,
    const payload::LayerWireSupport &source_support,
    std::size_t layer, const LayerClaim &claim, Transcript &transcript,
    std::size_t source_proof_ingress_rns_limbs,
    std::size_t reserved_transport_depth = 0,
    detail::ProverGateClaims *gate_claims = nullptr,
    PackedMessageCommitmentFunction<Backend> commitment_function = {},
    LanedAffineStatistics *statistics = nullptr,
    RuntimeProgressCallback progress = {}) {
    return LanedAffineLayerReductionProver<Backend, TraceSource>(
               eval, circuit, trace, source_admission, source_support, layer,
               claim, transcript, source_proof_ingress_rns_limbs,
               reserved_transport_depth, gate_claims,
               std::move(commitment_function), statistics,
               std::move(progress))
        .run();
}

/// Standalone entry point. Validate source identity once, then enter exactly
/// the same admitted affine prover used by the top-level Laned protocol.
template <fhe::PersistableFheBackend Backend, typename TraceSource>
LanedAffineLayerReductionResult<Backend> prove_affine(
    const typename Backend::EvalContext &eval,
    const payload::LayeredCircuit &circuit,
    const TraceSource &trace,
    const payload::LayerWireSupport &source_support,
    std::size_t layer, const LayerClaim &claim, Transcript &transcript,
    std::size_t source_proof_ingress_rns_limbs,
    std::size_t reserved_transport_depth = 0,
    detail::ProverGateClaims *gate_claims = nullptr,
    PackedMessageCommitmentFunction<Backend> commitment_function = {},
    LanedAffineStatistics *statistics = nullptr,
    RuntimeProgressCallback progress = {}) {
    const LanedAffineSourceAdmission source_admission =
        LanedAffineSourceAdmission::validate(circuit, trace);
    return prove_admitted_affine<Backend>(
        eval, circuit, trace, source_admission, source_support, layer, claim,
        transcript, source_proof_ingress_rns_limbs,
        reserved_transport_depth, gate_claims,
        std::move(commitment_function), statistics, std::move(progress));
}

} // namespace laminate::gkr::laned_detail

#endif // LAMINATE_GKR_DETAIL_LANED_AFFINE_PROVER_HPP
