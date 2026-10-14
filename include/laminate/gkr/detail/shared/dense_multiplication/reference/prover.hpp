#ifndef LAMINATE_GKR_DETAIL_SHARED_DENSE_MULTIPLICATION_REFERENCE_PROVER_HPP
#define LAMINATE_GKR_DETAIL_SHARED_DENSE_MULTIPLICATION_REFERENCE_PROVER_HPP

/// @file prover.hpp
/// @brief Shared Folded/Laned in-memory reference prover.

#include "laminate/gkr/detail/shared/dense_multiplication/geometry.hpp"
#include "laminate/gkr/detail/shared/dense_multiplication/reference/evaluator.hpp"
#include "laminate/gkr/detail/shared/packed/proof.hpp"
#include "laminate/gkr/detail/shared/packed/transcript.hpp"
#include "laminate/runtime_progress.hpp"

#include <array>
#include <cstddef>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

namespace laminate::gkr::detail {

/// Bounded reference multiplication prover shared by Folded and Laned.
///
/// `Source` owns only the variant's compact in-memory view. It exposes the
/// logical left/right pair table, its bit-reversed live order, and the exact
/// first-round scan extent retained by that variant. `VariantPolicy` retains
/// only proof spelling, transcript domain, progress labels, and diagnostics.
/// This class owns the common ciphertext-index/checkpoint/slot-index/terminal
/// phase order and
/// all dense multiplication round algebra.
///
/// Equality stripping makes each round satisfy
/// `claim_j=(1-tau_j)S_j(0)+tau_j*S_j(1)`. The explicit loops below publish
/// the nonsingular Boolean endpoint and `S_j(2)`, transcript-bind the message,
/// and only then sample the coordinate fixed in the following round.
template <fhe::FheBackend Backend, typename VariantPolicy, typename Source>
class ReferencePackedDenseMultiplicationProver {
  public:
    static constexpr ProtocolVariant variant = VariantPolicy::variant;
    static_assert(kIsPackedProofVariant<variant>);

    using Geometry = typename VariantPolicy::Geometry;
    using Result = typename VariantPolicy::template Result<Backend>;
    using Round = PackedRound<fhe::FheValue<Backend>, variant>;
    using RoundEvaluations =
        TransmittedLayerReductionRound<fhe::ExtensionValue<Backend>>;
    using SlotCheckpoints = MultiplicationSlotCheckpoints<Backend>;
    using RoundEvaluator =
        ReferenceDenseMultiplicationRoundEvaluator<Backend, Geometry, Source>;

    ReferencePackedDenseMultiplicationProver(
        const typename Backend::EvalContext &eval,
        const Geometry &geometry, const Source &source,
        std::size_t layer, const SingleClaim &claim,
        Transcript &transcript, std::size_t reserved_transport_depth,
        PackedMessageCommitmentFunction<Backend> commitment_function = {},
        RuntimeProgressCallback progress = {})
        : eval_(eval), geometry_(geometry), source_(source), layer_(layer),
          claim_(claim), transcript_(transcript), evaluator_(eval, geometry,
                                                             source),
          reserved_transport_depth_(reserved_transport_depth),
          commitment_function_(std::move(commitment_function)),
          progress_(std::move(progress)) {
        result_.proof.rounds.reserve(geometry_.round_count);
        challenges_.reserve(geometry_.round_count);
    }

    Result run() {
        // Step 1: Prepare the fixed public slot-equality basis used to fold
        // every ciphertext-index-round result. This performs no protocol observation.
        evaluator_.prepare_output_slot_basis();

        // Step 2: Bind this multiplication reduction to Fiat--Shamir.
        // Construction deliberately leaves the transcript untouched.
        observe_packed_reduction_begin<variant>(
            layer_, payload::LayerKind::Multiplication,
            geometry_.round_count, transcript_);

        // Step 3: Reduce the ciphertext-index variables against the in-memory
        // compact left/right source-pair table.
        prove_ciphertext_index_rounds();

        // Step 4: Fix the full ciphertext-index point and retain the two encrypted,
        // slot-packed source MLEs.
        const SlotCheckpoints checkpoints = make_slot_checkpoints();

        // Step 5: Reduce the remaining SIMD slot variables.
        prove_slot_index_rounds(checkpoints);

        // Step 6: Publish both terminal values, then interpolate their
        // selector at fresh alpha to form one source claim.
        publish_terminal_message(checkpoints);
        result_.next_claim = make_next_claim();
        return std::move(result_);
    }

  private:
    Fpk transmitted_endpoint(std::size_t round) const {
        return dense_multiplication_primary_point(claim_.point[round]);
    }

    fhe::FheValue<Backend> pack(
        std::span<const fhe::ExtensionValue<Backend>> values) const {
        fhe::FheValue<Backend> packed =
            fhe::pack_replicated_extension_values<Backend>(eval_, values);
        fhe::value_compact_for_transport<Backend>(
            eval_, packed, reserved_transport_depth_);
        return packed;
    }

    void publish_round(
        std::size_t round, RoundEvaluations evaluations) {
        const auto ordered = std::move(evaluations).into_transcript_order();
        Round message{pack(ordered)};
        observe_packed_round<variant, Backend>(
            layer_, round, message, transcript_, commitment_function_);
        result_.proof.rounds.push_back(std::move(message));
    }

    void prove_ciphertext_index_rounds() {
        if (!challenges_.empty()) {
            throw std::logic_error(
                "packed multiplication ciphertext-index sumcheck already "
                "started");
        }
        for (std::size_t round = 0; round < geometry_.ciphertext_index_variables;
             ++round) {
            RuntimeProgressSpan progress(progress_,
                                         round_progress_event(round));

            // Step 1: Choose the nonsingular Boolean endpoint and X=2.
            const LayerReductionRoundPoints points{
                .endpoint = transmitted_endpoint(round),
            };

            // Step 2: Evaluate both points under FHE from in-memory source
            // pairs. Later rounds first bind the existing random prefix.
            RoundEvaluations evaluations = evaluator_.evaluate_ciphertext_index_round(
                claim_.point, challenges_, points);

            // Step 3: Publish and transcript-bind the two evaluations.
            publish_round(round, std::move(evaluations));

            // Step 4: Sample r and extend the fixed ciphertext-index prefix.
            const Fpk challenge = transcript_.challenge_fpk();
            challenges_.push_back(challenge);
            progress.finish();
        }
    }

    SlotCheckpoints make_slot_checkpoints() const {
        const RuntimeProgressEvent event{
            .boundary = RuntimeProgressBoundary::Begin,
            .stage = VariantPolicy::checkpoint_stage,
            .layer_kind = RuntimeProgressLayerKind::Multiplication,
            .coordinate_domain =
                RuntimeProgressCoordinateDomain::SlotIndex,
            .reduction_layer = layer_,
            .source_layer = layer_ + 1U,
            .checkpoint_layer = layer_ + 1U,
            .work_units = 2U * source_.live_pair_count(),
        };
        RuntimeProgressSpan progress(progress_, event);
        SlotCheckpoints result =
            evaluator_.evaluate_slot_checkpoints(challenges_);
        progress.finish();
        return result;
    }

    std::span<const Fpk> slot_index_point() const {
        return std::span<const Fpk>(challenges_).subspan(
            geometry_.ciphertext_index_variables);
    }

    void prove_slot_index_rounds(const SlotCheckpoints &checkpoints) {
        if (challenges_.size() != geometry_.ciphertext_index_variables) {
            throw std::logic_error(
                "packed multiplication slot sumcheck has no ciphertext-index prefix");
        }
        for (std::size_t offset = 0;
             offset < geometry_.slot_index_variables;
             ++offset) {
            const std::size_t round = geometry_.ciphertext_index_variables + offset;
            RuntimeProgressSpan progress(progress_,
                                         round_progress_event(round));
            // Step 1: Evaluate the next slot-coordinate polynomial at the
            // nonsingular Boolean endpoint and at X=2.
            RoundEvaluations evaluations = evaluator_.evaluate_slot_index_round(
                checkpoints, geometry_.output_slot, slot_index_point(),
                transmitted_endpoint(round));

            // Step 2: Publish and transcript-bind the two evaluations.
            publish_round(round, std::move(evaluations));

            // Step 3: Sample r and extend the fixed slot prefix.
            const Fpk challenge = transcript_.challenge_fpk();
            challenges_.push_back(challenge);
            progress.finish();
        }
    }

    RuntimeProgressEvent round_progress_event(std::size_t round) const {
        return RuntimeProgressEvent{
            .boundary = RuntimeProgressBoundary::Begin,
            .stage = VariantPolicy::sumcheck_stage,
            .layer_kind = RuntimeProgressLayerKind::Multiplication,
            .coordinate_domain =
                round < geometry_.ciphertext_index_variables
                    ? RuntimeProgressCoordinateDomain::CiphertextIndex
                    : RuntimeProgressCoordinateDomain::SlotIndex,
            .reduction_layer = layer_,
            .source_layer = layer_ + 1U,
            .round = round,
            .round_count = geometry_.round_count,
            .work_units = round < geometry_.ciphertext_index_variables
                              ? 2U * source_.live_pair_count()
                              : 2U,
        };
    }

    void publish_terminal_message(const SlotCheckpoints &checkpoints) {
        auto values =
            evaluator_.evaluate_terminal_source(checkpoints, slot_index_point());
        const std::array ordered{std::move(values.left),
                                 std::move(values.right)};
        result_.proof.packed_source_values = pack(ordered);
        observe_packed_terminal<variant, Backend>(
            layer_, result_.proof.packed_source_values, transcript_,
            commitment_function_);
    }

    SingleClaim make_next_claim() {
        return make_dense_multiplication_source_claim(
            challenges_, Fpk::zero(), Fpk::zero(),
            transcript_.challenge_fpk());
    }

    // Immutable reduction inputs and the variant's compact in-memory source.
    const typename Backend::EvalContext &eval_;
    const Geometry &geometry_;
    const Source &source_;
    std::size_t layer_;
    const SingleClaim &claim_;
    Transcript &transcript_;
    RoundEvaluator evaluator_; ///< Owns reference source traversal and FHE.

    // Message transport and telemetry do not alter the recurrence or
    // challenge order.
    std::size_t reserved_transport_depth_;
    PackedMessageCommitmentFunction<Backend> commitment_function_;
    RuntimeProgressCallback progress_;

    // Mutable protocol state. `challenges_` is the shared source point fixed
    // so far; `result_` accumulates the messages in transcript order.
    Result result_;
    std::vector<Fpk> challenges_;
};

} // namespace laminate::gkr::detail

#endif // LAMINATE_GKR_DETAIL_SHARED_DENSE_MULTIPLICATION_REFERENCE_PROVER_HPP
