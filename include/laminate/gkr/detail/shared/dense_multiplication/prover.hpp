#ifndef LAMINATE_GKR_DETAIL_SHARED_DENSE_MULTIPLICATION_PROVER_HPP
#define LAMINATE_GKR_DETAIL_SHARED_DENSE_MULTIPLICATION_PROVER_HPP

/// @file prover.hpp
/// @brief Shared Folded/Laned file-backed dense multiplication prover.

#include "laminate/gkr/detail/shared/dense_multiplication/geometry.hpp"
#include "laminate/gkr/detail/shared/dense_multiplication/rounds.hpp"
#include "laminate/gkr/detail/shared/dense_multiplication/source/file.hpp"
#include "laminate/gkr/detail/shared/dense_multiplication/evaluator.hpp"
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

/// File-backed dense multiplication prover shared by Folded and Laned.
///
/// The policy is deliberately small. It owns only the variant's geometry and
/// artifact admission, result spelling, transcript domain (through
/// `variant`), progress-stage labels, and overflow diagnostics. This class
/// owns the common phase order, source scans, message packing, Fiat--Shamir
/// sequencing, slot completion, terminal publication, and next-claim shape.
///
/// Equality stripping makes each round satisfy
/// `claim_j=(1-tau_j)S_j(0)+tau_j*S_j(1)`. The explicit loops below publish
/// the nonsingular Boolean endpoint and `S_j(2)`, transcript-bind the message,
/// and only then sample the coordinate fixed in the following scan. The FHE
/// products are immediately below this class boundary in
/// `arithmetic/ciphertext_index_rounds.hpp`.
template <fhe::PersistableFheBackend Backend, typename VariantPolicy>
class PackedDenseMultiplicationProver {
  public:
    static constexpr ProtocolVariant variant = VariantPolicy::variant;
    static_assert(kIsPackedProofVariant<variant>);

    using Source = FileDenseMultiplicationSource<Backend>;
    using Statistics = FileBackedMultiplicationStatistics;
    using Result = typename VariantPolicy::template Result<Backend>;
    using Round = PackedRound<fhe::FheValue<Backend>, variant>;
    using Geometry = typename VariantPolicy::Geometry;
    using RoundEvaluations =
        TransmittedLayerReductionRound<fhe::ExtensionValue<Backend>>;
    using SlotCheckpoints = MultiplicationSlotCheckpoints<Backend>;
    using RoundEvaluator = DenseMultiplicationRoundEvaluator<
        Backend, Geometry, FileDenseMultiplicationSourceReader<Backend>>;

    PackedDenseMultiplicationProver(
        const typename Backend::EvalContext &eval,
        const payload::LayeredCircuit &circuit, const Source &source,
        std::size_t layer, const SingleClaim &claim,
        Transcript &transcript, std::size_t reserved_transport_depth,
        PackedMessageCommitmentFunction<Backend> commitment_function = {},
        Statistics *statistics = nullptr,
        RuntimeProgressCallback progress = {})
        : eval_(eval), layer_(layer),
          claim_(claim), transcript_(transcript),
          geometry_(VariantPolicy::make_geometry(circuit, layer, claim)),
          statistics_(statistics != nullptr ? statistics
                                            : &owned_statistics_),
          evaluator_(eval_, geometry_, source.reader(),
                     source.descriptor().live_pair_count, *statistics_),
          reserved_transport_depth_(reserved_transport_depth),
          commitment_function_(std::move(commitment_function)),
          progress_(std::move(progress)) {
        VariantPolicy::template validate_source<Backend>(
            eval_, circuit, source, layer_, geometry_);
        *statistics_ = Statistics{};
        result_.proof.rounds.reserve(geometry_.round_count);
        challenges_.reserve(geometry_.round_count);
    }

    Result run() {
        // Step 1: Bind the layer, reduction kind, and round count before any
        // prover message. Construction deliberately leaves Fiat--Shamir alone.
        observe_packed_reduction_begin<variant>(
            layer_, payload::LayerKind::Multiplication,
            geometry_.round_count, transcript_);

        // Step 2: Reduce the ciphertext-index variables. Each round performs
        // one sequential scan of the compact left/right source-pair artifact.
        prove_ciphertext_index_rounds();

        // Step 3: Fix the complete ciphertext-index point once. The resulting encrypted
        // left/right MLEs stay slot-packed for the remaining rounds.
        const SlotCheckpoints checkpoints = make_slot_checkpoints();

        // Step 4: Reduce the SIMD slot variables from those two checkpoints.
        prove_slot_index_rounds(checkpoints);

        // Step 5: Publish both source MLEs at the final random point, then
        // interpolate the selector at fresh alpha to form one source claim.
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

            // Step 1: Choose the nonsingular Boolean endpoint and X=2. The
            // output-claim coordinate determines which endpoint is safe.
            const LayerReductionRoundPoints points{
                .endpoint = transmitted_endpoint(round),
            };

            // Step 2: Evaluate S(endpoint) and S(2) under FHE in one scan.
            RoundEvaluations evaluations = evaluator_.evaluate_ciphertext_index_round(
                claim_.point, challenges_, points);

            // Step 3: Publish and transcript-bind the two evaluations.
            publish_round(round, std::move(evaluations));

            // Step 4: Sample r and fix this ciphertext-index coordinate for
            // the next scan.
            const Fpk challenge = transcript_.challenge_fpk();
            challenges_.push_back(challenge);
            progress.finish();
        }
    }

    SlotCheckpoints make_slot_checkpoints() {
        const RuntimeProgressEvent event{
            .boundary = RuntimeProgressBoundary::Begin,
            .stage = VariantPolicy::checkpoint_stage,
            .layer_kind = RuntimeProgressLayerKind::Multiplication,
            .coordinate_domain =
                RuntimeProgressCoordinateDomain::SlotIndex,
            .reduction_layer = layer_,
            .source_layer = layer_ + 1U,
            .checkpoint_layer = layer_ + 1U,
            .work_units = 2U * evaluator_.live_pair_count(),
        };
        RuntimeProgressSpan progress(progress_, event);
        SlotCheckpoints checkpoints =
            evaluator_.evaluate_slot_checkpoints(ciphertext_index_point());
        progress.finish();
        return checkpoints;
    }

    std::span<const Fpk> ciphertext_index_point() const {
        return std::span<const Fpk>(challenges_).first(
            geometry_.ciphertext_index_variables);
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
            // Step 1: Evaluate the next slot-coordinate polynomial at its
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
                              ? 2U * evaluator_.live_pair_count()
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

    // Immutable reduction inputs and admitted external-memory source.
    const typename Backend::EvalContext &eval_;
    std::size_t layer_;
    const SingleClaim &claim_;
    Transcript &transcript_;
    Geometry geometry_;

    // File access, FHE arithmetic, and their diagnostics stay behind one
    // boundary so the protocol loop above is not interleaved with I/O.
    Statistics owned_statistics_;
    Statistics *statistics_;
    RoundEvaluator evaluator_;

    // Message transport and observational progress; neither changes the
    // recurrence or the external-memory access plan.
    std::size_t reserved_transport_depth_;
    PackedMessageCommitmentFunction<Backend> commitment_function_;
    RuntimeProgressCallback progress_;

    // Mutable protocol state. `challenges_` is the shared source point fixed
    // so far.
    Result result_;
    std::vector<Fpk> challenges_;
};

} // namespace laminate::gkr::detail

#endif // LAMINATE_GKR_DETAIL_SHARED_DENSE_MULTIPLICATION_PROVER_HPP
