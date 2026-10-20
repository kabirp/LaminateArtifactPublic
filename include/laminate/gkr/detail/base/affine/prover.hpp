#ifndef LAMINATE_GKR_DETAIL_BASE_AFFINE_PROVER_HPP
#define LAMINATE_GKR_DETAIL_BASE_AFFINE_PROVER_HPP

/// @file prover.hpp
/// @brief Proof-order implementation of the production Base affine reduction.

#include "laminate/gkr/detail/base/affine/types.hpp"
#include "laminate/gkr/detail/base/affine/evaluator.hpp"
#include "laminate/gkr/detail/base/affine/internal/partial_gate_mle.hpp"
#include "laminate/gkr/detail/base/claims/evaluation.hpp"
#include "laminate/gkr/detail/base/fhe/message_normalization.hpp"
#include "laminate/gkr/detail/base/transcript/reduction.hpp"
#include "laminate/gkr/detail/shared/reduction/gate_claims.hpp"
#include "laminate/runtime_progress.hpp"

#include <cstddef>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

namespace laminate::gkr::base_detail {

/// Production Base affine prover over a compact file-backed trace source.
///
/// After subtracting the public affine constant, the reduction proves
///
///   claim = sum_u GateMLE(output_claim, u) * W(u).
///
/// At round `j`, earlier source coordinates are fixed to `r[0..j)`. The
/// prover computes the remaining Boolean sum at `X=1` and `X=2`, publishes
/// those values, then samples `r[j]`. The verifier recovers `R_j(0)` from
/// `R_j(0) + R_j(1) = claim_j` and continues with
/// `claim_{j+1} = R_j(r[j])`.
///
/// `BaseAffineEvaluator` owns every source-reader, decoding, batching, and FHE
/// concern. The recurrence below sees only the two mathematical round
/// evaluations and the terminal source MLE. Circuit-certified absent positions
/// remain the public plaintext zero polynomial and make no backend call.
template <fhe::FheBackend Backend, typename TraceSource>
class BaseAffineReductionProver {
  public:
    BaseAffineReductionProver(
        const typename Backend::EvalContext &eval,
        const payload::LayeredCircuit &circuit, const TraceSource &trace,
        const BaseAffineSourceAdmission &source_admission,
        const payload::LayerWireSupport &source_support,
        std::size_t layer, const LayerClaim &claim,
        const gates::DirectGateMle &provider, Transcript &transcript,
        detail::ProverGateClaims *gate_claims = nullptr,
        BaseAffineStatistics *statistics = nullptr,
        RuntimeProgressCallback progress = {})
        : eval_(eval), circuit_(circuit), layer_(layer),
          claim_(claim), transcript_(transcript),
          geometry_(AffineGeometry::create(circuit, layer)),
          evaluator_(eval, circuit, trace, source_admission, source_support,
                     layer, claim, provider, geometry_, statistics),
          gate_claims_(gate_claims), progress_(std::move(progress)) {
        result_.proof.rounds.reserve(
            geometry_.ciphertext_index_variables);
        ciphertext_index_challenges_.reserve(
            geometry_.ciphertext_index_variables);
    }

    ProvedAffine<Backend> run() {
        // Step 1: subtract and bind the public affine constant. This must
        // precede the layer-begin message in the canonical transcript.
        record_affine_constant_claim();

        // Step 2: announce the ciphertext-index sumcheck.
        observe_begin(layer_, payload::LayerKind::Affine,
                      geometry_.ciphertext_index_variables, transcript_);

        // Step 3: reduce every source-ciphertext coordinate under FHE.
        prove_affine_layer_reduction_sumcheck();

        // Step 4: publish W(r_ct, slot), still packed over SIMD slots.
        publish_terminal_message();

        // Step 5: publish and bind GateMLE(output, r_ct, slot).
        publish_partial_gate_mle();

        // Step 6: sample the client's terminal slot point and hand the
        // resulting source claim to the next GKR layer.
        const std::vector<Fpk> slot =
            transcript_.challenge_vector(geometry_.slot_index_variables);
        record_terminal_gate_claims(slot);
        result_.next_claim = SingleClaim{
            concatenate(ciphertext_index_challenges_, slot), Fpk::zero()};
        return std::move(result_);
    }

  private:
    void record_affine_constant_claim() {
        if (gate_claims_ != nullptr && gate_claims_->requires_opening()) {
            (void)affine_constant_at(*gate_claims_, layer_, claim_);
        }
    }

    /// Publish the encrypted ciphertext-index rounds of the Laminate affine
    /// reduction. SIMD slot coordinates remain packed for client completion.
    void prove_affine_layer_reduction_sumcheck() {
        for (std::size_t round = 0;
             round < geometry_.ciphertext_index_variables;
             ++round) {
            prove_one_ciphertext_index_round(round);
        }
    }

    /// One visible affine recurrence step. The named round evaluator below is
    /// the only encrypted-arithmetic boundary; publication and challenge
    /// binding are transcript/public-field operations.
    void prove_one_ciphertext_index_round(std::size_t round) {
        RuntimeProgressSpan round_progress(
            progress_, sumcheck_round_event(round));

        // ===== FHE evaluation over the file-backed source ================
        // Step 1: compute R_j(1) and R_j(2) in one sequential source scan.
        EncryptedAffineRoundEvaluations<Backend> evaluations =
            evaluator_.evaluate_ciphertext_index_round();

        // ===== Fiat--Shamir protocol recurrence ==========================
        // Step 2: publish both encrypted evaluations. Together with
        // R_j(0) = claim_j - R_j(1), they determine the degree-two R_j.
        publish_round(round, std::move(evaluations));

        // Step 3: sample r_j only after the message is bound, then restrict
        // GateMLE and eq(r_ct, source_index) for the next round.
        bind_ciphertext_index_challenge(transcript_.challenge_fpk());
        round_progress.finish();
    }

    void publish_round(
        std::size_t round,
        EncryptedAffineRoundEvaluations<Backend> evaluations) {
        EncryptedBaseLayerReductionSumcheckRound<Backend> message{
            std::move(evaluations).into_transport_order()};
        for (auto &evaluation : message.evaluations) {
            switch_message_to_lowest<Backend>(eval_, evaluation);
        }
        observe_round<Backend>(layer_, round, message, transcript_);
        result_.proof.rounds.push_back(std::move(message));
    }

    void bind_ciphertext_index_challenge(const Fpk &challenge) {
        ciphertext_index_challenges_.push_back(challenge);
        evaluator_.bind_ciphertext_index_challenge(challenge);
    }

    RuntimeProgressEvent sumcheck_round_event(std::size_t round) const {
        return RuntimeProgressEvent{
            .stage = RuntimeProgressStage::BaseAffineSumcheckRound,
            .layer_kind = RuntimeProgressLayerKind::Affine,
            .coordinate_domain =
                RuntimeProgressCoordinateDomain::CiphertextIndex,
            .reduction_layer = layer_,
            .source_layer = layer_ + 1U,
            .round = round,
            .round_count = geometry_.ciphertext_index_variables,
        };
    }

    void publish_terminal_message() {
        RuntimeProgressSpan terminal_progress(
            progress_, RuntimeProgressEvent{
                           .stage = RuntimeProgressStage::
                               BaseAffineTerminalEvaluation,
                           .layer_kind = RuntimeProgressLayerKind::Affine,
                           .reduction_layer = layer_,
                           .source_layer = layer_ + 1U,
                       });

        // ===== FHE evaluation over the file-backed source ================
        result_.proof.source_vector =
            evaluator_.evaluate_terminal_source();
        terminal_progress.finish();

        // ===== Canonical proof and transcript publication ================
        switch_message_to_lowest<Backend>(
            eval_, result_.proof.source_vector);
        observe_terminal<Backend>(
            layer_,
            std::span<const fhe::ExtensionValue<Backend>>(
                &result_.proof.source_vector, 1),
            transcript_);
    }

    void publish_partial_gate_mle() {
        result_.proof.partial_gate_mle = make_affine_partial_gate_mle(
            circuit_, layer_, claim_, ciphertext_index_challenges_);
        observe_partial_gate_mle(
            layer_, PartialGateMleKind::Affine,
            result_.proof.partial_gate_mle, transcript_);
    }

    void record_terminal_gate_claims(std::span<const Fpk> slot) {
        if (gate_claims_ == nullptr ||
            !gate_claims_->requires_opening()) {
            return;
        }
        const std::vector<Fpk> source_point =
            concatenate(ciphertext_index_challenges_, slot);
        (void)affine_gate_at(*gate_claims_, layer_, claim_, source_point);
    }

    const typename Backend::EvalContext &eval_;
    const payload::LayeredCircuit &circuit_;
    std::size_t layer_;
    const LayerClaim &claim_;
    Transcript &transcript_;
    AffineGeometry geometry_;
    /// Sole FHE/storage boundary for ciphertext-index and terminal evaluation.
    BaseAffineEvaluator<Backend, TraceSource> evaluator_;
    detail::ProverGateClaims *gate_claims_;
    RuntimeProgressCallback progress_;
    /// Proof built strictly in transcript order plus its outgoing claim.
    ProvedAffine<Backend> result_;
    /// Fiat--Shamir ciphertext-index point fixed by completed rounds.
    std::vector<Fpk> ciphertext_index_challenges_;
};

/// Prove one LaminateBase affine reduction after top-level source admission.
template <fhe::FheBackend Backend, typename TraceSource>
ProvedAffine<Backend> prove_admitted_affine_reduction(
    const typename Backend::EvalContext &eval,
    const payload::LayeredCircuit &circuit, const TraceSource &trace,
    const BaseAffineSourceAdmission &source_admission,
    const payload::LayerWireSupport &source_support,
    std::size_t layer, const LayerClaim &claim,
    const gates::DirectGateMle &provider, Transcript &transcript,
    detail::ProverGateClaims *gate_claims = nullptr,
    BaseAffineStatistics *statistics = nullptr,
    RuntimeProgressCallback progress = {}) {
    return BaseAffineReductionProver<Backend, TraceSource>(
               eval, circuit, trace, source_admission, source_support, layer,
               claim, provider, transcript, gate_claims, statistics,
               std::move(progress))
        .run();
}

/// Standalone entry point. Validate the circuit/source identity once, then
/// enter the same admitted recurrence used by the complete Base prover.
template <fhe::FheBackend Backend, typename TraceSource>
ProvedAffine<Backend> prove_affine_reduction(
    const typename Backend::EvalContext &eval,
    const payload::LayeredCircuit &circuit, const TraceSource &trace,
    const payload::LayerWireSupport &source_support,
    std::size_t layer, const LayerClaim &claim,
    const gates::DirectGateMle &provider, Transcript &transcript,
    detail::ProverGateClaims *gate_claims = nullptr,
    BaseAffineStatistics *statistics = nullptr,
    RuntimeProgressCallback progress = {}) {
    const BaseAffineSourceAdmission source_admission =
        BaseAffineSourceAdmission::validate(circuit, trace);
    return prove_admitted_affine_reduction<Backend>(
        eval, circuit, trace, source_admission, source_support, layer, claim,
        provider, transcript, gate_claims, statistics, std::move(progress));
}

} // namespace laminate::gkr::base_detail

#endif // LAMINATE_GKR_DETAIL_BASE_AFFINE_PROVER_HPP
