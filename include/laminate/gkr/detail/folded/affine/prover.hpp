#ifndef LAMINATE_GKR_DETAIL_FOLDED_AFFINE_PROVER_HPP
#define LAMINATE_GKR_DETAIL_FOLDED_AFFINE_PROVER_HPP

/// @file prover.hpp
/// @brief Canonical file-backed LaminateFolded affine reduction.

#include "laminate/gkr/detail/folded/affine/types.hpp"
#include "laminate/gkr/detail/base/claims/evaluation.hpp"
#include "laminate/gkr/detail/folded/affine/evaluator.hpp"
#include "laminate/gkr/detail/folded/transport/message_packing.hpp"
#include "laminate/gkr/detail/shared/packed/transcript.hpp"
#include "laminate/gkr/detail/shared/reduction/gate_claims.hpp"
#include "laminate/runtime_progress.hpp"

#include <array>
#include <cstddef>
#include <span>
#include <utility>
#include <vector>

namespace laminate::gkr::folded_detail {

/// Stateful Folded affine prover over a compact active-wire source.
///
/// `TraceSource` supplies the same narrow adapter contract used by the Base
/// file prover. `FoldedAffineEvaluator` owns its reader, rewinds, prepared
/// bases, and checkpoint; none of that storage machinery appears in the
/// transcript recurrence below. Public padded zeros have no record and
/// trigger no backend operation.
/// Returns the source-layer claim at the sampled verifier point.
///
/// This class contains the complete affine recurrence: compute `R_j(1)` and
/// `R_j(2)`, publish and transcript-bind them, sample `r_j`, then bind the
/// equality/gate state for the next round. Ciphertext-index FHE work is
/// implemented by `FoldedAffineEvaluator` in `evaluator.hpp`; slot-index
/// rounds reuse one encrypted checkpoint after the ciphertext-index prefix.
template <fhe::FheBackend Backend, typename TraceSource>
class FoldedAffineLayerReductionProver {
  public:
    FoldedAffineLayerReductionProver(
        const typename Backend::EvalContext &eval,
        const payload::LayeredCircuit &circuit, const TraceSource &trace,
        const FoldedAffineSourceAdmission &source_admission,
        const payload::LayerWireSupport &source_support,
        std::size_t layer, const LayerClaim &claim,
        Transcript &transcript, std::size_t reserved_transport_depth,
        detail::ProverGateClaims *gate_claims = nullptr,
        PackedMessageCommitmentFunction<Backend> commitment_function = {},
        FoldedAffineStatistics *statistics = nullptr,
        RuntimeProgressCallback progress = {})
        : eval_(eval), layer_(layer), claim_(claim), transcript_(transcript),
          geometry_(FoldedAffineReductionGeometry::create(circuit, layer)),
          evaluator_(
              eval, circuit, trace, layer, source_support,
              make_affine_sparse_schedule(circuit, layer, claim),
              geometry_.ciphertext_index_variables, statistics),
          reserved_transport_depth_(reserved_transport_depth),
          gate_claims_(gate_claims),
          commitment_function_(std::move(commitment_function)),
          progress_(std::move(progress)) {
        source_admission.require_matches(circuit, trace);
        result_.proof.rounds.reserve(geometry_.round_count);
        challenges_.reserve(geometry_.round_count);
    }

    FoldedAffineReductionResult<Backend> run() {
        // ===== Source opening and RNS-level preparation ==================
        // Step 1: Match immutable public slot bases to the source ciphertext's
        // modulus level. This local preparation may scan as far as the first
        // encrypted source record, but it sends no message and changes no
        // Fiat--Shamir state.
        evaluator_.prepare_source_level_bases();

        // ===== LaminateFolded affine protocol ============================
        // Step 2: Bind the public affine claim and announce the reduction.
        // This is the first protocol-visible work.
        record_affine_constant_claim();
        detail::observe_packed_reduction_begin<
            ProtocolVariant::LaminateFolded>(
            layer_, payload::LayerKind::Affine, geometry_.round_count,
            transcript_);

        // ===== Ciphertext-index sumcheck: source scans plus FHE ===========
        // Step 3: Reduce the source-ciphertext coordinates under FHE.
        prove_ciphertext_index_rounds();

        // ===== File-backed source to encrypted checkpoint ================
        // Step 4: Fix all ciphertext indices in one encrypted slot checkpoint.
        fhe::ExtensionValue<Backend> checkpoint = build_slot_checkpoint();

        // ===== Slot-index sumcheck: checkpoint-only FHE ==================
        // Step 5: Reduce the remaining packed-slot coordinates under FHE.
        prove_slot_index_rounds(checkpoint);

        // ===== LaminateFolded affine completion ==========================
        // Step 6: Publish the terminal source value and carry its evaluation
        // point into the following GKR layer. Its plaintext value is unknown
        // to the encrypted prover and therefore remains public zero here.
        publish_terminal_message(checkpoint);
        record_terminal_gate_claim();
        result_.next_claim =
            SingleClaim{std::move(challenges_), Fpk::zero()};
        return std::move(result_);
    }

  private:
    void record_affine_constant_claim() {
        if (gate_claims_ != nullptr && gate_claims_->requires_opening()) {
            (void)base_detail::affine_constant_at(
                *gate_claims_, layer_, claim_);
        }
    }

    void publish_round(
        std::size_t round,
        FoldedAffineRoundEvaluations<Backend> evaluations) {
        std::array<fhe::ExtensionValue<Backend>, 2> transport_values =
            std::move(evaluations).into_transport_order();
        EncryptedFoldedLayerReductionSumcheckRound<Backend> message{
            pack_reduction_message<Backend>(
                eval_, transport_values, reserved_transport_depth_)};
        detail::observe_packed_round<
            ProtocolVariant::LaminateFolded, Backend>(
            layer_, round, message, transcript_, commitment_function_);
        result_.proof.rounds.push_back(std::move(message));
    }

    void prove_ciphertext_index_rounds() {
        const FoldedAffineRoundEvaluationPoints points;
        for (std::size_t round = 0;
             round < geometry_.ciphertext_index_variables;
             ++round) {
            RuntimeProgressSpan round_progress(
                progress_, sumcheck_round_event(round));

            // Step 1: Evaluate R_j(1) and R_j(2) under FHE. The evaluator
            // owns source scans and their telemetry.
            FoldedAffineRoundEvaluations<Backend> evaluations =
                evaluator_.evaluate_ciphertext_index_round(points);

            // Step 2: Publish and transcript-bind R_j(1), R_j(2). Since
            // R_j(0) + R_j(1) is the current claim, these values determine
            // the degree-two round polynomial seen by the verifier.
            publish_round(round, std::move(evaluations));

            // Step 3: Sample r_j only after the message is bound.
            const Fpk challenge = transcript_.challenge_fpk();

            // Step 4: Fix this ciphertext index in the equality table used to
            // construct R_{j+1}.
            challenges_.push_back(challenge);
            evaluator_.fix_ciphertext_index(challenge);
            round_progress.finish();
        }
    }

    fhe::ExtensionValue<Backend> build_slot_checkpoint() {
        RuntimeProgressSpan checkpoint_progress(
            progress_, slot_checkpoint_event());
        fhe::ExtensionValue<Backend> checkpoint =
            evaluator_.build_slot_checkpoint();
        checkpoint_progress.finish();
        return checkpoint;
    }

    std::span<const Fpk> slot_index_point() const {
        return std::span<const Fpk>(challenges_).subspan(
            geometry_.ciphertext_index_variables);
    }

    void prove_slot_index_rounds(
        const fhe::ExtensionValue<Backend> &checkpoint) {
        PreparedAffineSlotWeights public_weights =
            evaluator_.prepare_slot_index_gate_weights(
                challenges_, geometry_.ciphertext_index_variables);
        for (std::size_t offset = 0;
             offset < geometry_.slot_index_variables;
             ++offset) {
            const std::size_t round =
                geometry_.ciphertext_index_variables + offset;
            RuntimeProgressSpan round_progress(
                progress_, sumcheck_round_event(round));

            // Step 1: Evaluate R_j(1), R_j(2) from the encrypted checkpoint
            // and the public GateMLE slot weights.
            FoldedAffineRoundEvaluations<Backend> evaluations =
                evaluator_.evaluate_slot_index_round(
                    checkpoint, public_weights, slot_index_point(),
                    geometry_.slot_index_variables);

            // Step 2: Publish and bind R_j(1), R_j(2). Slot rounds continue
            // the same affine sumcheck after every ciphertext index is fixed.
            publish_round(round, std::move(evaluations));

            // Step 3: Sample r_j after binding the message.
            const Fpk challenge = transcript_.challenge_fpk();

            // Step 4: Fix r_j in both the
            // checkpoint evaluation and its public sparse-gate weights.
            challenges_.push_back(challenge);
            public_weights.bind(challenge);
            round_progress.finish();
        }
    }

    RuntimeProgressEvent sumcheck_round_event(std::size_t round) const {
        return RuntimeProgressEvent{
            .stage = RuntimeProgressStage::FoldedAffineSumcheckRound,
            .layer_kind = RuntimeProgressLayerKind::Affine,
            .coordinate_domain =
                round < geometry_.ciphertext_index_variables
                    ? RuntimeProgressCoordinateDomain::CiphertextIndex
                    : RuntimeProgressCoordinateDomain::SlotIndex,
            .reduction_layer = layer_,
            .source_layer = layer_ + 1U,
            .round = round,
            .round_count = geometry_.round_count,
        };
    }

    RuntimeProgressEvent slot_checkpoint_event() const {
        return RuntimeProgressEvent{
            .stage = RuntimeProgressStage::FoldedAffineSlotCheckpoint,
            .layer_kind = RuntimeProgressLayerKind::Affine,
            .coordinate_domain =
                RuntimeProgressCoordinateDomain::SlotIndex,
            .reduction_layer = layer_,
            .source_layer = layer_ + 1U,
            .checkpoint_layer = layer_ + 1U,
        };
    }

    void publish_terminal_message(
        const fhe::ExtensionValue<Backend> &checkpoint) {
        const std::array<fhe::ExtensionValue<Backend>, 1> values{
            evaluator_.evaluate_terminal_source(
                checkpoint, slot_index_point())};
        result_.proof.packed_terminal_value = pack_reduction_message<Backend>(
            eval_, values, reserved_transport_depth_);
        detail::observe_packed_terminal<
            ProtocolVariant::LaminateFolded, Backend>(
            layer_, result_.proof.packed_terminal_value, transcript_,
            commitment_function_);
    }

    void record_terminal_gate_claim() {
        if (gate_claims_ && gate_claims_->requires_opening()) {
            (void)base_detail::affine_gate_at(
                *gate_claims_, layer_, claim_, challenges_);
        }
    }

    /// Backend context used by every encrypted round operation.
    const typename Backend::EvalContext &eval_;
    /// Circuit layer whose claim is reduced to `layer_ + 1`.
    std::size_t layer_;
    /// Immutable output-layer claim for the entire affine reduction.
    const LayerClaim &claim_;
    /// Fiat--Shamir state; mutated only by explicit publish/sample steps.
    Transcript &transcript_;
    /// Public round dimensions derived from the source layer and slot count.
    FoldedAffineReductionGeometry geometry_;
    /// Canonical file/source access and all concrete affine FHE arithmetic.
    FoldedAffineEvaluator<Backend, TraceSource> evaluator_;
    std::size_t reserved_transport_depth_;
    detail::ProverGateClaims *gate_claims_;
    PackedMessageCommitmentFunction<Backend> commitment_function_;
    RuntimeProgressCallback progress_;
    /// Proof messages and next source claim accumulated by this reduction.
    FoldedAffineReductionResult<Backend> result_;
    /// Fiat--Shamir coordinates sampled in ciphertext-index-then-slot order.
    std::vector<Fpk> challenges_;
};

template <fhe::FheBackend Backend, typename TraceSource>
FoldedAffineReductionResult<Backend> prove_admitted_affine(
    const typename Backend::EvalContext &eval,
    const payload::LayeredCircuit &circuit, const TraceSource &trace,
    const FoldedAffineSourceAdmission &source_admission,
    const payload::LayerWireSupport &source_support,
    std::size_t layer, const LayerClaim &claim, Transcript &transcript,
    std::size_t reserved_transport_depth = 0,
    detail::ProverGateClaims *gate_claims = nullptr,
    PackedMessageCommitmentFunction<Backend> commitment_function = {},
    FoldedAffineStatistics *statistics = nullptr,
    RuntimeProgressCallback progress = {}) {
    return FoldedAffineLayerReductionProver<Backend, TraceSource>(
               eval, circuit, trace, source_admission, source_support, layer,
               claim, transcript, reserved_transport_depth, gate_claims,
               std::move(commitment_function), statistics,
               std::move(progress))
        .run();
}

/// Standalone entry point. Validate source identity once, then enter exactly
/// the same admitted affine prover used by the top-level Folded protocol.
template <fhe::FheBackend Backend, typename TraceSource>
FoldedAffineReductionResult<Backend> prove_affine(
    const typename Backend::EvalContext &eval,
    const payload::LayeredCircuit &circuit, const TraceSource &trace,
    const payload::LayerWireSupport &source_support,
    std::size_t layer, const LayerClaim &claim, Transcript &transcript,
    std::size_t reserved_transport_depth = 0,
    detail::ProverGateClaims *gate_claims = nullptr,
    PackedMessageCommitmentFunction<Backend> commitment_function = {},
    FoldedAffineStatistics *statistics = nullptr,
    RuntimeProgressCallback progress = {}) {
    const FoldedAffineSourceAdmission source_admission =
        FoldedAffineSourceAdmission::validate(circuit, trace);
    return prove_admitted_affine<Backend>(
        eval, circuit, trace, source_admission, source_support, layer, claim,
        transcript, reserved_transport_depth, gate_claims,
        std::move(commitment_function), statistics, std::move(progress));
}

} // namespace laminate::gkr::folded_detail

#endif // LAMINATE_GKR_DETAIL_FOLDED_AFFINE_PROVER_HPP
