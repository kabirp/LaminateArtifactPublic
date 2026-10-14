#ifndef LAMINATE_GKR_DETAIL_BASE_REFERENCE_MULTIPLICATION_PROVER_HPP
#define LAMINATE_GKR_DETAIL_BASE_REFERENCE_MULTIPLICATION_PROVER_HPP

/// @file multiplication_prover.hpp
/// @brief Resident Base multiplication oracle for bounded correctness tests.
///
/// Production proving is file-backed. This file intentionally keeps a small
/// in-memory oracle whose proof order mirrors production and whose evaluator
/// exposes the same multiplication equation without file-reader mechanics.

#include "laminate/gkr/detail/base/claims/evaluation.hpp"
#include "laminate/gkr/detail/base/fhe/message_normalization.hpp"
#include "laminate/gkr/detail/base/multiplication/types.hpp"
#include "laminate/gkr/detail/base/transcript/reduction.hpp"
#include "laminate/gkr/detail/shared/dense_multiplication/accumulation.hpp"
#include "laminate/gkr/detail/shared/dense_multiplication/rounds.hpp"
#include "laminate/poly/eq.hpp"

#include <algorithm>
#include <cstddef>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

namespace laminate::gkr::base_detail {

namespace reference_multiplication_detail {

namespace arithmetic = ::laminate::gkr::detail::
    dense_multiplication_accumulation_detail;

inline constexpr char kInvalidRoundPoint[] =
    "LaminateBase multiplication expects the endpoint or X=2";

inline std::size_t bit_reverse(std::size_t value,
                               std::size_t bit_count) {
    std::size_t result = 0;
    for (std::size_t bit = 0; bit < bit_count; ++bit) {
        result = (result << 1U) | (value & std::size_t{1});
        value >>= 1U;
    }
    return result;
}

} // namespace reference_multiplication_detail

/// Arithmetic boundary for the resident Base oracle.
///
/// For fixed ciphertext-index prefix `r`, one round evaluates
///
///   S_j(X;s) = sum_u eq(tau_suffix,u)
///                       L(r,X,u;s)R(r,X,u;s)
///
/// independently in every SIMD slot. The class also computes the terminal
/// L(r;s),R(r;s) terminal values through a linear pass. It never publishes
/// proof messages or samples transcript challenges.
template <fhe::FheBackend Backend>
class ResidentBaseMultiplicationRoundEvaluator {
  public:
    using RoundEvaluations =
        EncryptedMultiplicationRoundEvaluations<Backend>;
    using SourceValues = EncryptedMultiplicationSourceValues<Backend>;

    ResidentBaseMultiplicationRoundEvaluator(
        const typename Backend::EvalContext &eval,
        const payload::LayeredCircuit &circuit,
        const payload::EncryptedTrace<Backend> &trace, std::size_t layer,
        const MultiplicationGeometry &geometry)
        : eval_(eval), circuit_(circuit), trace_(trace), layer_(layer),
          geometry_(geometry),
          storage_(payload::canonical_layer_storage_layout(
              circuit, layer + 1U)),
          metadata_(::laminate::gkr::detail::
                        make_dense_paired_source_metadata(
                            circuit, layer, storage_)) {
        validate_source();
        build_physical_order();
    }

    /// Evaluate S(endpoint;s) and S(2;s). The selected private method contains
    /// the complete source traversal and concrete FHE multiplication.
    RoundEvaluations evaluate_ciphertext_index_round(
        std::span<const Fpk> output_ciphertext_index,
        std::span<const Fpk> ciphertext_index_prefix,
        const ::laminate::gkr::detail::LayerReductionRoundPoints &points)
        const {
        if (ciphertext_index_prefix.empty()) {
            return evaluate_first_ciphertext_index_round(
                output_ciphertext_index, points);
        }
        return evaluate_later_ciphertext_index_round(
            output_ciphertext_index, ciphertext_index_prefix, points);
    }

    /// Bind the complete ciphertext-index point into both source halves:
    ///
    ///   L(r;s)=sum_i eq(r,i)L_i(s),  R(r;s)=sum_i eq(r,i)R_i(s).
    ///
    /// This pass is linear and deliberately performs no L*R product. If the
    /// layer has no ciphertext-index variable, public base-field support is
    /// retained without introducing synthetic extension coordinates.
    SourceValues evaluate_terminal_source_values(
        std::span<const Fpk> ciphertext_index_point) const {
        const std::vector<Fpk> weights = poly::eq_evaluations(
            std::vector<Fpk>(ciphertext_index_point.begin(),
                             ciphertext_index_point.end()));
        reference_multiplication_detail::arithmetic::
            WeightedBaseAccumulator<Backend>
                left;
        reference_multiplication_detail::arithmetic::
            WeightedBaseAccumulator<Backend>
                right;

        // Step 1: visit live source pairs in canonical suffix order.
        for (std::size_t index : physical_order_) {
            if (ciphertext_index_point.empty()) {
                left.add_public_support(eval_, left_value(index),
                                        weights[index]);
                right.add_public_support(eval_, right_value(index),
                                         weights[index]);
            } else {
                left.add(eval_, left_value(index), weights[index]);
                right.add(eval_, right_value(index), weights[index]);
            }
        }

        // Step 2: retain the two slot-packed source MLEs. There is no
        // ciphertext multiplication in this terminal pass.
        return {
            .left = std::move(left).finish(eval_),
            .right = std::move(right).finish(eval_),
        };
    }

  private:
    const payload::EncryptedTraceLayer<Backend> &source_layer() const {
        return trace_.layers.at(layer_ + 1U);
    }

    void validate_source() const {
        if (trace_.shape != circuit_.shape ||
            trace_.layers.size() != circuit_.layers.size() ||
            source_layer().layout != payload::TraceLayerLayout::Wide ||
            source_layer().dimensions !=
                payload::layer_dimensions(circuit_.layers[layer_ + 1U]) ||
            source_layer().wires.size() != storage_.stored_wire_count) {
            throw std::invalid_argument(
                "LaminateBase resident multiplication source is not "
                "canonical compact storage");
        }
    }

    void build_physical_order() {
        physical_order_.reserve(metadata_.counts.active_logical_pairs);
        for (const auto &group : metadata_.groups) {
            physical_order_.insert(physical_order_.end(),
                                   group.logical_indices.begin(),
                                   group.logical_indices.end());
        }
        std::sort(physical_order_.begin(), physical_order_.end(),
                  [&](std::size_t left, std::size_t right) {
                      return reference_multiplication_detail::bit_reverse(
                                 left,
                                 geometry_.ciphertext_index_variables) <
                             reference_multiplication_detail::bit_reverse(
                                 right,
                                 geometry_.ciphertext_index_variables);
                  });
    }

    const fhe::FheValue<Backend> &source_value(
        std::size_t padded_index) const {
        const auto stored = storage_.stored_ordinal_of(padded_index);
        return stored ? source_layer().wires.at(*stored) : public_zero_;
    }

    const fhe::FheValue<Backend> &left_value(std::size_t pair) const {
        return source_value(pair);
    }

    const fhe::FheValue<Backend> &right_value(std::size_t pair) const {
        return source_value(geometry_.pair_count + pair);
    }

    /// First-round equation. Every suffix contributes one base-ciphertext
    /// L(X,u;s)*R(X,u;s) product to each requested evaluation.
    RoundEvaluations evaluate_first_ciphertext_index_round(
        std::span<const Fpk> output_ciphertext_index,
        const ::laminate::gkr::detail::LayerReductionRoundPoints &points)
        const {
        namespace shared = ::laminate::gkr::detail;
        namespace arithmetic = reference_multiplication_detail::arithmetic;

        const shared::DenseMultiplicationRoundValues<
            shared::CiphertextIndexRoundWeights>
            weights{
                .at_endpoint =
                    shared::make_ciphertext_index_round_scalar_weights(
                        output_ciphertext_index,
                        geometry_.ciphertext_index_variables, {},
                        points.endpoint),
                .at_two =
                    shared::make_ciphertext_index_round_scalar_weights(
                        output_ciphertext_index,
                        geometry_.ciphertext_index_variables, {},
                        points.at_two),
            };
        const std::size_t suffix_count = geometry_.pair_count / 2U;
        shared::DenseMultiplicationRoundValues<
            fhe::MixedExtensionAccumulator<Backend>>
            product_sums;
        const auto support = geometry_.ciphertext_index_variables == 1U
                                 ? arithmetic::BaseProductSupport::PublicBase
                                 : arithmetic::BaseProductSupport::
                                       GeneralExtension;

        // Step 1: select the low/high branches at endpoint and X=2.
        for (std::size_t suffix = 0; suffix < suffix_count; ++suffix) {
            const auto endpoint_left =
                arithmetic::select_base_pair_branch<Backend>(
                    eval_, left_value(suffix),
                    left_value(suffix_count + suffix), points.endpoint,
                    reference_multiplication_detail::kInvalidRoundPoint);
            const auto endpoint_right =
                arithmetic::select_base_pair_branch<Backend>(
                    eval_, right_value(suffix),
                    right_value(suffix_count + suffix), points.endpoint,
                    reference_multiplication_detail::kInvalidRoundPoint);
            const auto left_at_two =
                arithmetic::select_base_pair_branch<Backend>(
                    eval_, left_value(suffix),
                    left_value(suffix_count + suffix), points.at_two,
                    reference_multiplication_detail::kInvalidRoundPoint);
            const auto right_at_two =
                arithmetic::select_base_pair_branch<Backend>(
                    eval_, right_value(suffix),
                    right_value(suffix_count + suffix), points.at_two,
                    reference_multiplication_detail::kInvalidRoundPoint);

            // Step 2: concrete FHE boundary. Multiply L and R once at each
            // requested point; public-zero branches remain absent.
            (void)arithmetic::accumulate_base_product<Backend>(
                eval_, product_sums.at_endpoint, endpoint_left,
                endpoint_right, weights.at_endpoint.suffix[suffix], support);
            (void)arithmetic::accumulate_base_product<Backend>(
                eval_, product_sums.at_two, left_at_two, right_at_two,
                weights.at_two.suffix[suffix], support);
        }

        // Step 3: relinearize both slot-packed evaluations.
        return {
            .at_endpoint = arithmetic::finish_product_sum<Backend>(
                eval_, std::move(product_sums.at_endpoint)),
            .at_two = arithmetic::finish_product_sum<Backend>(
                eval_, std::move(product_sums.at_two)),
        };
    }

    /// Later-round equation. Bind the existing prefix linearly within each
    /// suffix group, then perform one extension L*R product per requested
    /// point and suffix.
    RoundEvaluations evaluate_later_ciphertext_index_round(
        std::span<const Fpk> output_ciphertext_index,
        std::span<const Fpk> ciphertext_index_prefix,
        const ::laminate::gkr::detail::LayerReductionRoundPoints &points)
        const {
        namespace shared = ::laminate::gkr::detail;
        namespace arithmetic = reference_multiplication_detail::arithmetic;

        const shared::DenseMultiplicationRoundValues<
            shared::CiphertextIndexRoundWeights>
            weights{
                .at_endpoint =
                    shared::make_ciphertext_index_round_scalar_weights(
                        output_ciphertext_index,
                        geometry_.ciphertext_index_variables,
                        ciphertext_index_prefix, points.endpoint),
                .at_two =
                    shared::make_ciphertext_index_round_scalar_weights(
                        output_ciphertext_index,
                        geometry_.ciphertext_index_variables,
                        ciphertext_index_prefix, points.at_two),
            };
        const shared::DenseMultiplicationRoundValues<std::vector<Fpk>>
            bound_weights{
                .at_endpoint =
                    poly::eq_evaluations(weights.at_endpoint.bound_point),
                .at_two = poly::eq_evaluations(weights.at_two.bound_point),
            };
        const std::size_t group_size = bound_weights.at_endpoint.size();
        const std::size_t suffix_count = geometry_.pair_count / group_size;
        shared::DenseMultiplicationRoundValues<fhe::ExtensionValue<Backend>>
            product_sums;
        std::size_t position = 0;

        // Step 1: bind the prior ciphertext-index prefix within one suffix.
        while (position < physical_order_.size()) {
            const std::size_t suffix =
                physical_order_[position] & (suffix_count - 1U);
            shared::DenseMultiplicationRoundValues<
                arithmetic::WeightedBaseAccumulator<Backend>>
                left;
            shared::DenseMultiplicationRoundValues<
                arithmetic::WeightedBaseAccumulator<Backend>>
                right;
            while (position < physical_order_.size() &&
                   (physical_order_[position] & (suffix_count - 1U)) ==
                       suffix) {
                const std::size_t pair = physical_order_[position++];
                const std::size_t bound = pair / suffix_count;
                if (bound >= group_size) {
                    throw std::logic_error(
                        "reference multiplication group exceeds its bound "
                        "domain");
                }
                left.at_endpoint.add(eval_, left_value(pair),
                                     bound_weights.at_endpoint[bound]);
                right.at_endpoint.add(eval_, right_value(pair),
                                      bound_weights.at_endpoint[bound]);
                left.at_two.add(eval_, left_value(pair),
                                bound_weights.at_two[bound]);
                right.at_two.add(eval_, right_value(pair),
                                 bound_weights.at_two[bound]);
            }

            const shared::DenseMultiplicationRoundValues<
                fhe::ExtensionValue<Backend>>
                left_values{
                    .at_endpoint =
                        std::move(left.at_endpoint).finish(eval_),
                    .at_two = std::move(left.at_two).finish(eval_),
                };
            const shared::DenseMultiplicationRoundValues<
                fhe::ExtensionValue<Backend>>
                right_values{
                    .at_endpoint =
                        std::move(right.at_endpoint).finish(eval_),
                    .at_two = std::move(right.at_two).finish(eval_),
                };

            // Step 2: concrete FHE boundary. Multiply the restricted source
            // MLEs once per point, then apply the suffix equality weight.
            (void)arithmetic::accumulate_extension_product<Backend>(
                eval_, product_sums.at_endpoint, left_values.at_endpoint,
                right_values.at_endpoint,
                weights.at_endpoint.suffix[suffix]);
            (void)arithmetic::accumulate_extension_product<Backend>(
                eval_, product_sums.at_two, left_values.at_two,
                right_values.at_two, weights.at_two.suffix[suffix]);
        }

        // Step 3: relinearize both slot-packed evaluations.
        return {
            .at_endpoint = arithmetic::finish_product_sum<Backend>(
                eval_, std::move(product_sums.at_endpoint)),
            .at_two = arithmetic::finish_product_sum<Backend>(
                eval_, std::move(product_sums.at_two)),
        };
    }

    const typename Backend::EvalContext &eval_;
    const payload::LayeredCircuit &circuit_;
    const payload::EncryptedTrace<Backend> &trace_;
    std::size_t layer_;
    const MultiplicationGeometry &geometry_;

    // Resident source representation. No production code imports this type.
    payload::LayerStorageLayout storage_;
    ::laminate::gkr::detail::DensePairedSourceMetadata metadata_;
    std::vector<std::size_t> physical_order_;
    fhe::FheValue<Backend> public_zero_ =
        fhe::FheValue<Backend>::public_zero();
};

/// Resident correctness prover. Its top-level flow matches production while
/// the evaluator above replaces file-backed source passes with bounded memory.
template <fhe::FheBackend Backend>
class ResidentBaseMultiplicationLayerReductionProver {
  public:
    ResidentBaseMultiplicationLayerReductionProver(
        const typename Backend::EvalContext &eval,
        const payload::LayeredCircuit &circuit,
        const payload::EncryptedTrace<Backend> &trace, std::size_t layer,
        const SingleClaim &claim, Transcript &transcript)
        : eval_(eval), layer_(layer), claim_(claim), transcript_(transcript),
          geometry_(MultiplicationGeometry::create(circuit, layer, claim)),
          evaluator_(eval, circuit, trace, layer, geometry_) {
        result_.proof.rounds.reserve(geometry_.round_count);
        ciphertext_index_challenges_.reserve(geometry_.round_count);
    }

    ProvedMultiplication<Backend> run() {
        // Step 1: announce the equality-stripped ciphertext-index sumcheck.
        observe_begin(layer_, payload::LayerKind::Multiplication,
                      geometry_.round_count, transcript_);

        // Step 2: evaluate, publish, and bind every ciphertext-index round.
        for (std::size_t round = 0;
             round < geometry_.ciphertext_index_variables; ++round) {
            prove_one_ciphertext_index_round(round);
        }

        // Step 3: bind the complete ciphertext-index point into L and R by a
        // linear evaluator pass, then publish those slot-packed values.
        auto source_values = evaluator_.evaluate_terminal_source_values(
            ciphertext_index_challenges_);
        publish_terminal_message(std::move(source_values));

        // Step 4: sample the public slot point and a fresh selector coordinate
        // for the single claim consumed by the next source layer.
        result_.next_claim = make_next_claim();
        return std::move(result_);
    }

  private:
    void prove_one_ciphertext_index_round(std::size_t round) {
        // Step 1: derive the nonsingular Boolean endpoint from tau_j.
        const auto points = multiplication_round_points(
            geometry_.output_ciphertext_index[round]);

        // Step 2: evaluate S_j(endpoint;s) and S_j(2;s) under FHE. One jump
        // reaches the resident source pass and concrete product above.
        auto evaluations = evaluator_.evaluate_ciphertext_index_round(
            geometry_.output_ciphertext_index,
            ciphertext_index_challenges_, points);

        // Step 3: publish and bind the complete encrypted round message.
        publish_round(round, std::move(evaluations));

        // Step 4: sample r_j only after publication, fixing the coordinate
        // used by the next evaluator pass.
        ciphertext_index_challenges_.push_back(transcript_.challenge_fpk());
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

    void publish_terminal_message(
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
        const std::vector<Fpk> slot_index_point =
            transcript_.challenge_vector(geometry_.slot_index_variables);
        const std::vector<Fpk> shared =
            concatenate(ciphertext_index_challenges_, slot_index_point);
        const Fpk selector_challenge = transcript_.challenge_fpk();
        // The encrypted prover carries only the public point; verification
        // supplies the interpolated value from the fixed source vectors.
        return ::laminate::gkr::detail::make_dense_multiplication_source_claim(
            shared, Fpk::zero(), Fpk::zero(), selector_challenge);
    }

    const typename Backend::EvalContext &eval_;
    std::size_t layer_;
    const SingleClaim &claim_;
    Transcript &transcript_;
    MultiplicationGeometry geometry_;
    ResidentBaseMultiplicationRoundEvaluator<Backend> evaluator_;
    ProvedMultiplication<Backend> result_;
    std::vector<Fpk> ciphertext_index_challenges_;
};

template <fhe::FheBackend Backend>
ProvedMultiplication<Backend> prove_multiplication_resident(
    const typename Backend::EvalContext &eval,
    const payload::LayeredCircuit &circuit,
    const payload::EncryptedTrace<Backend> &trace, std::size_t layer,
    const SingleClaim &claim, Transcript &transcript) {
    return ResidentBaseMultiplicationLayerReductionProver<Backend>(
               eval, circuit, trace, layer, claim, transcript)
        .run();
}

} // namespace laminate::gkr::base_detail

#endif // LAMINATE_GKR_DETAIL_BASE_REFERENCE_MULTIPLICATION_PROVER_HPP
