#ifndef LAMINATE_GKR_DETAIL_BASE_MULTIPLICATION_PROVER_HPP
#define LAMINATE_GKR_DETAIL_BASE_MULTIPLICATION_PROVER_HPP

/// @file prover.hpp
/// @brief Proof-order implementation of the production Base multiplication reduction.

#include "laminate/gkr/detail/base/claims/evaluation.hpp"
#include "laminate/gkr/detail/base/fhe/message_normalization.hpp"
#include "laminate/gkr/detail/base/multiplication/evaluator.hpp"
#include "laminate/gkr/detail/base/multiplication/types.hpp"
#include "laminate/gkr/detail/base/transcript/reduction.hpp"
#include "laminate/runtime_progress.hpp"

#include <cstddef>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

namespace laminate::gkr::base_detail {

/// Base prover over the shared alias-aware dense multiplication artifact.
/// Every ciphertext-index round and the checkpoint pass scans bit-reversed
/// logical pairs sequentially. Repeated operands are cached once by the
/// reader and are never duplicated in the artifact.
///
/// The layer relation is `output(i)=left(i)*right(i)`. Equality stripping
/// removes the public output-point factor from the expensive product scan, so
/// round `j` maintains
///
///   claim_j = (1-tau_j) S_j(0) + tau_j S_j(1).
///
/// The loop below publishes the nonsingular Boolean endpoint and `S_j(2)`,
/// then fixes the source coordinate to the Fiat--Shamir challenge. The actual
/// ciphertext products are in `multiplication/evaluator.hpp`, reached through
/// `BaseMultiplicationRoundEvaluator::evaluate_ciphertext_index_round`.
template <fhe::FheBackend Backend, typename Source>
class BaseMultiplicationReductionProver {
  public:
    BaseMultiplicationReductionProver(
        const typename Backend::EvalContext &eval,
        const payload::LayeredCircuit &circuit,
        const Source &source,
        std::size_t layer, const SingleClaim &claim,
        Transcript &transcript,
        detail::FileBackedMultiplicationStatistics *statistics = nullptr,
        RuntimeProgressCallback progress = {})
        : eval_(eval), circuit_(circuit), source_(source), layer_(layer),
          claim_(claim), transcript_(transcript),
          geometry_(MultiplicationGeometry::create(circuit, layer, claim)),
          evaluator_(eval, geometry_.output_ciphertext_index, source,
                     statistics),
          progress_(std::move(progress)) {
        validate_source();
        result_.proof.rounds.reserve(geometry_.round_count);
        ciphertext_index_challenges_.reserve(geometry_.round_count);
    }

    ProvedMultiplication<Backend> run() {
        // Step 1: announce the equality-stripped ciphertext-index sumcheck.
        // Construction validates the artifact but never touches Fiat--Shamir.
        observe_begin(layer_, payload::LayerKind::Multiplication,
                      geometry_.round_count, transcript_);

        // Step 2: reduce every ciphertext-index coordinate under FHE.
        prove_multiplication_layer_reduction_sumcheck();

        // Step 3: evaluate L(r_ct,slot) and R(r_ct,slot) in one final linear
        // source scan. The evaluator owns the disk reader and performs no
        // ciphertext product in this pass.
        RuntimeProgressSpan terminal_evaluation_progress(
            progress_, terminal_source_event());
        EncryptedMultiplicationSourceValues<Backend> source_values =
            evaluator_.evaluate_terminal_source(
                ciphertext_index_challenges_);
        terminal_evaluation_progress.finish();

        // Step 4: publish those packed source vectors.
        publish_slotwise_source_values(std::move(source_values));

        // Step 5: interpolate the selector coordinate for the single source
        // claim consumed by the next GKR layer.
        result_.next_claim = make_next_claim();
        return std::move(result_);
    }

  private:
    void validate_source() const {
        const auto &descriptor = source_.descriptor();
        bool context_matches = false;
        if constexpr (requires { source_.matches_backend_context(eval_); }) {
            context_matches = source_.matches_backend_context(eval_);
        } else if constexpr (requires {
                                 descriptor.backend_context_id;
                                 Backend::storage_context_id(eval_);
                             }) {
            context_matches = descriptor.backend_context_id ==
                Backend::storage_context_id(eval_);
        }
        if (!context_matches || descriptor.shape != circuit_.shape ||
            descriptor.reduction_layer != layer_ ||
            descriptor.output_layout !=
                detail::dense_multiplication_storage_layout(circuit_,
                                                             layer_) ||
            descriptor.source_layout !=
                detail::dense_multiplication_storage_layout(circuit_,
                                                             layer_ + 1U) ||
            descriptor.pair_count != geometry_.pair_count ||
            Backend::slot_count(eval_) != circuit_.shape.slot_count) {
            throw std::invalid_argument(
                "Base dense multiplication artifact mismatch");
        }
    }

    void publish_round(
        std::size_t round,
        EncryptedMultiplicationRoundEvaluations<Backend> evaluations) {
        EncryptedBaseLayerReductionSumcheckRound<Backend> message{
            std::move(evaluations).into_transcript_order()};
        switch_message_to_lowest<Backend>(eval_, message.evaluations[0]);
        switch_message_to_lowest<Backend>(eval_, message.evaluations[1]);
        observe_round<Backend>(layer_, round, message, transcript_);
        result_.proof.rounds.push_back(std::move(message));
    }

    void prove_multiplication_layer_reduction_sumcheck() {
        for (std::size_t round = 0; round < geometry_.ciphertext_index_variables;
             ++round) {
            prove_one_ciphertext_index_round(round);
        }
    }

    /// One visible multiplication recurrence step. The named round evaluator
    /// below is the encrypted L*R boundary; message binding and challenge
    /// fixing remain explicit here.
    void prove_one_ciphertext_index_round(std::size_t round) {
        RuntimeProgressSpan round_progress(
            progress_, sumcheck_round_event(round));

        // Step 1: choose the nonsingular Boolean endpoint derived from tau_j.
        // The verifier reconstructs the other endpoint from
        //   claim_j = (1-tau_j) S_j(0) + tau_j S_j(1).
        const auto points =
            multiplication_round_points(geometry_.output_ciphertext_index[round]);

        // Step 2: compute S_j(endpoint) and S_j(2) in one sequential FHE
        // scan. The called kernel is where ciphertext products occur.
        auto evaluations = evaluator_.evaluate_ciphertext_index_round(
            ciphertext_index_challenges_, points);

        // Step 3: publish and transcript-bind both encrypted evaluations.
        publish_round(round, std::move(evaluations));

        // Step 4: sample r_j only after publication. This fixes one source
        // coordinate for the next scan.
        ciphertext_index_challenges_.push_back(transcript_.challenge_fpk());
        round_progress.finish();
    }

    RuntimeProgressEvent sumcheck_round_event(std::size_t round) const {
        return RuntimeProgressEvent{
            .stage =
                RuntimeProgressStage::BaseMultiplicationSumcheckRound,
            .layer_kind = RuntimeProgressLayerKind::Multiplication,
            .coordinate_domain =
                RuntimeProgressCoordinateDomain::CiphertextIndex,
            .reduction_layer = layer_,
            .source_layer = layer_ + 1U,
            .round = round,
            .round_count = geometry_.round_count,
            .work_units = 2U * evaluator_.live_pair_count(),
        };
    }

    RuntimeProgressEvent terminal_source_event() const {
        return RuntimeProgressEvent{
            .stage = RuntimeProgressStage::
                BaseMultiplicationTerminalSourceEvaluation,
            .layer_kind = RuntimeProgressLayerKind::Multiplication,
            .coordinate_domain =
                RuntimeProgressCoordinateDomain::CiphertextIndex,
            .reduction_layer = layer_,
            .source_layer = layer_ + 1U,
            .work_units = 2U * evaluator_.live_pair_count(),
        };
    }

    void publish_slotwise_source_values(
        EncryptedMultiplicationSourceValues<Backend> source_values) {
        result_.proof.source_vectors = {std::move(source_values.left),
                                        std::move(source_values.right)};
        switch_message_to_lowest<Backend>(
            eval_, result_.proof.source_vectors[0]);
        switch_message_to_lowest<Backend>(
            eval_, result_.proof.source_vectors[1]);
        observe_terminal<Backend>(layer_, result_.proof.source_vectors,
                                  transcript_);
    }

    SingleClaim make_next_claim() {
        const std::vector<Fpk> slot =
            transcript_.challenge_vector(geometry_.slot_index_variables);
        const std::vector<Fpk> shared =
            concatenate(ciphertext_index_challenges_, slot);
        const Fpk selector_challenge = transcript_.challenge_fpk();
        // Terminal ciphertexts are fixed before either challenge. Only the
        // verifier knows their evaluations, so the prover carries a zero
        // value placeholder at the same public source point.
        return ::laminate::gkr::detail::make_dense_multiplication_source_claim(
            shared, Fpk::zero(), Fpk::zero(), selector_challenge);
    }

    const typename Backend::EvalContext &eval_;
    const payload::LayeredCircuit &circuit_;
    const Source &source_;
    std::size_t layer_;
    const SingleClaim &claim_;
    Transcript &transcript_;
    /// Public dimensions and output equality point for this dense layer.
    MultiplicationGeometry geometry_;
    /// Owns the file reader and every source-scan/I/O detail.
    BaseMultiplicationRoundEvaluator<Backend, Source> evaluator_;
    RuntimeProgressCallback progress_;
    /// Proof built strictly in transcript order plus its outgoing claim.
    ProvedMultiplication<Backend> result_;
    /// Fiat--Shamir source-ciphertext-index point fixed by completed rounds.
    std::vector<Fpk> ciphertext_index_challenges_;
};

template <fhe::FheBackend Backend, typename Source>
ProvedMultiplication<Backend> prove_multiplication_reduction(
    const typename Backend::EvalContext &eval,
    const payload::LayeredCircuit &circuit,
    const Source &source,
    std::size_t layer, const SingleClaim &claim, Transcript &transcript,
    detail::FileBackedMultiplicationStatistics *statistics = nullptr,
    RuntimeProgressCallback progress = {}) {
    return BaseMultiplicationReductionProver<Backend, Source>(
               eval, circuit, source, layer, claim, transcript, statistics,
               std::move(progress))
        .run();
}

} // namespace laminate::gkr::base_detail

#endif // LAMINATE_GKR_DETAIL_BASE_MULTIPLICATION_PROVER_HPP
