#ifndef LAMINATE_GKR_DETAIL_SHARED_DENSE_MULTIPLICATION_REFERENCE_EVALUATOR_HPP
#define LAMINATE_GKR_DETAIL_SHARED_DENSE_MULTIPLICATION_REFERENCE_EVALUATOR_HPP

/// @file evaluator.hpp
/// @brief In-memory reference evaluator for dense multiplication rounds.
///
/// This is the arithmetic boundary below the bounded Folded/Laned reference
/// prover. The class evaluates round polynomials and the source MLEs retained
/// at the ciphertext-index/slot-index boundary, but never publishes proof
/// messages or samples Fiat--Shamir challenges.

#include "laminate/gkr/detail/shared/dense_multiplication/accumulation.hpp"
#include "laminate/gkr/detail/shared/dense_multiplication/rounds.hpp"
#include "laminate/gkr/detail/shared/packed/prepared_basis.hpp"

#include <cstddef>
#include <optional>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

namespace laminate::gkr::detail {

namespace reference_dense_multiplication_detail {
namespace arithmetic = dense_multiplication_accumulation_detail;
} // namespace reference_dense_multiplication_detail

/// Evaluates
///
///   S_j(X) = sum_u eq(tau_suffix,u)
///                    L(r_prefix,X,u)R(r_prefix,X,u)
///
/// from a compact in-memory source. `Geometry` fixes the ciphertext/slot
/// split and output-slot equality weights. `Source` supplies live left/right
/// pairs in the physical order needed to group an already-bound prefix by
/// canonical suffix.
template <fhe::FheBackend Backend, typename Geometry, typename Source>
class ReferenceDenseMultiplicationRoundEvaluator {
  public:
    using RoundEvaluations =
        TransmittedLayerReductionRound<fhe::ExtensionValue<Backend>>;
    using SlotCheckpoints = MultiplicationSlotCheckpoints<Backend>;
    using SourceValues =
        DenseMultiplicationSourceValues<fhe::ExtensionValue<Backend>>;

    ReferenceDenseMultiplicationRoundEvaluator(
        const typename Backend::EvalContext &eval,
        const Geometry &geometry, const Source &source)
        : eval_(eval), geometry_(geometry), source_(source) {}

    /// Prepare the public eq(tau_slot,s) basis once. This changes no protocol
    /// state and observes nothing in the transcript.
    void prepare_output_slot_basis() {
        if (prepared_output_slots_) {
            throw std::logic_error(
                "reference multiplication evaluator cannot prepare twice");
        }
        prepared_output_slots_.emplace(
            prepare_mixed_fpk_slot_basis<Backend>(
                eval_, source_.level_reference(),
                geometry_.output_slot_weights));
    }

    /// Evaluate S(endpoint) and S(2) for the next ciphertext-index variable.
    /// The private method entered below contains the complete source traversal
    /// and the concrete FHE multiplication for that round family.
    RoundEvaluations evaluate_ciphertext_index_round(
        std::span<const Fpk> output_point,
        std::span<const Fpk> ciphertext_index_prefix,
        const LayerReductionRoundPoints &points) const {
        require_prepared_basis();
        if (ciphertext_index_prefix.empty()) {
            return evaluate_first_ciphertext_index_round(output_point,
                                                          points);
        }
        return evaluate_later_ciphertext_index_round(
            output_point, ciphertext_index_prefix, points);
    }

    /// Fix all ciphertext-index coordinates in L and R separately:
    ///
    ///   L(r;s)=sum_i eq(r,i)L_i(s),  R(r;s)=sum_i eq(r,i)R_i(s).
    ///
    /// This linear FHE pass deliberately performs no L*R product.
    SlotCheckpoints evaluate_slot_checkpoints(
        std::span<const Fpk> ciphertext_index_point) const {
        const std::vector<Fpk> weights = poly::eq_evaluations(
            std::vector<Fpk>(ciphertext_index_point.begin(),
                             ciphertext_index_point.end()));
        reference_dense_multiplication_detail::arithmetic::
            WeightedBaseAccumulator<Backend>
                left;
        reference_dense_multiplication_detail::arithmetic::
            WeightedBaseAccumulator<Backend>
                right;
        for (std::size_t pair = 0; pair < source_.live_pair_count(); ++pair) {
            if (ciphertext_index_point.empty()) {
                left.add_public_support(eval_, source_.left_value(pair),
                                        weights[pair]);
                right.add_public_support(eval_, source_.right_value(pair),
                                         weights[pair]);
            } else {
                left.add(eval_, source_.left_value(pair), weights[pair]);
                right.add(eval_, source_.right_value(pair), weights[pair]);
            }
        }
        return {
            .left = std::move(left).finish(eval_),
            .right = std::move(right).finish(eval_),
        };
    }

    /// Evaluate the next slot-index round from the two retained source MLEs.
    RoundEvaluations evaluate_slot_index_round(
        const SlotCheckpoints &checkpoints,
        std::span<const Fpk> output_slot,
        std::span<const Fpk> slot_index_prefix,
        const Fpk &transmitted_endpoint) const {
        return evaluate_multiplication_slot_round<Backend>(
            eval_, checkpoints.left, checkpoints.right, output_slot,
            slot_index_prefix, transmitted_endpoint);
    }

    /// Finish L and R at the complete shared source point.
    SourceValues evaluate_terminal_source(
        const SlotCheckpoints &checkpoints,
        std::span<const Fpk> slot_index_point) const {
        return {
            .left = fhe::partial_evaluate_slot_index_point<Backend>(
                eval_, checkpoints.left, slot_index_point),
            .right = fhe::partial_evaluate_slot_index_point<Backend>(
                eval_, checkpoints.right, slot_index_point),
        };
    }

  private:
    const fhe::FheValue<Backend> &left_value(std::size_t pair) const {
        return pair < source_.live_pair_count() ? source_.left_value(pair)
                                                : public_zero_;
    }

    const fhe::FheValue<Backend> &right_value(std::size_t pair) const {
        return pair < source_.live_pair_count() ? source_.right_value(pair)
                                                : public_zero_;
    }

    /// First-round equation and FHE source traversal. Each suffix contributes
    /// one base-ciphertext L(X,u)*R(X,u) product to each requested point.
    RoundEvaluations evaluate_first_ciphertext_index_round(
        std::span<const Fpk> output_point,
        const LayerReductionRoundPoints &points) const {
        const DenseMultiplicationRoundValues<CiphertextIndexRoundWeights>
            weights{
                .at_endpoint = make_ciphertext_index_round_scalar_weights(
                    output_point, geometry_.ciphertext_index_variables, {},
                    points.endpoint),
                .at_two = make_ciphertext_index_round_scalar_weights(
                    output_point, geometry_.ciphertext_index_variables, {},
                    points.at_two),
            };
        const std::size_t suffix_count = geometry_.pair_count / 2U;
        const std::size_t scan_count =
            source_.first_round_scan_count(suffix_count);
        DenseMultiplicationRoundValues<
            fhe::MixedExtensionAccumulator<Backend>>
            product_sums;

        // Step 1: select the low/high source branches at endpoint and at X=2.
        for (std::size_t suffix = 0; suffix < scan_count; ++suffix) {
            const auto endpoint_left = reference_dense_multiplication_detail::
                arithmetic::select_base_pair_branch<Backend>(
                    eval_, left_value(suffix),
                         left_value(suffix_count + suffix), points.endpoint,
                         kInvalidRoundPoint);
            const auto endpoint_right = reference_dense_multiplication_detail::
                arithmetic::select_base_pair_branch<Backend>(
                    eval_, right_value(suffix),
                         right_value(suffix_count + suffix), points.endpoint,
                         kInvalidRoundPoint);
            const auto left_at_two = reference_dense_multiplication_detail::
                arithmetic::select_base_pair_branch<Backend>(
                    eval_, left_value(suffix),
                         left_value(suffix_count + suffix), points.at_two,
                         kInvalidRoundPoint);
            const auto right_at_two = reference_dense_multiplication_detail::
                arithmetic::select_base_pair_branch<Backend>(
                    eval_, right_value(suffix),
                         right_value(suffix_count + suffix), points.at_two,
                         kInvalidRoundPoint);

            // Step 2: concrete FHE boundary. Multiply L and R once for each
            // requested point; public-zero operands remain absent.
            (void)reference_dense_multiplication_detail::arithmetic::
                accumulate_base_product<Backend>(
                eval_, product_sums.at_endpoint, endpoint_left,
                endpoint_right, weights.at_endpoint.suffix[suffix]);
            (void)reference_dense_multiplication_detail::arithmetic::
                accumulate_base_product<Backend>(
                eval_, product_sums.at_two, left_at_two, right_at_two,
                weights.at_two.suffix[suffix]);
        }

        // Step 3: apply eq(tau_slot,s), relinearize, and fold the SIMD slots.
        return {
            .at_endpoint = finish_and_fold_slots(
                std::move(product_sums.at_endpoint)),
            .at_two = finish_and_fold_slots(
                std::move(product_sums.at_two)),
        };
    }

    /// Later-round equation and FHE source traversal. The prior challenges
    /// are bound linearly before one extension L*R product per suffix.
    RoundEvaluations evaluate_later_ciphertext_index_round(
        std::span<const Fpk> output_point,
        std::span<const Fpk> ciphertext_index_prefix,
        const LayerReductionRoundPoints &points) const {
        const DenseMultiplicationRoundValues<CiphertextIndexRoundWeights>
            weights{
                .at_endpoint = make_ciphertext_index_round_scalar_weights(
                    output_point, geometry_.ciphertext_index_variables,
                    ciphertext_index_prefix, points.endpoint),
                .at_two = make_ciphertext_index_round_scalar_weights(
                    output_point, geometry_.ciphertext_index_variables,
                    ciphertext_index_prefix, points.at_two),
            };
        const DenseMultiplicationRoundValues<std::vector<Fpk>> bound_weights{
            .at_endpoint =
                poly::eq_evaluations(weights.at_endpoint.bound_point),
            .at_two = poly::eq_evaluations(weights.at_two.bound_point),
        };
        const std::size_t group_size = bound_weights.at_endpoint.size();
        const std::size_t suffix_count = geometry_.pair_count / group_size;
        DenseMultiplicationRoundValues<fhe::ExtensionValue<Backend>>
            product_sums;
        std::size_t position = 0;
        const std::span<const std::size_t> order =
            source_.physical_pair_order();

        // Step 1: bind the prior prefix within one canonical suffix group.
        while (position < order.size()) {
            const std::size_t suffix =
                order[position] & (suffix_count - 1U);
            DenseMultiplicationRoundValues<
                reference_dense_multiplication_detail::arithmetic::
                    WeightedBaseAccumulator<Backend>>
                left;
            DenseMultiplicationRoundValues<
                reference_dense_multiplication_detail::arithmetic::
                    WeightedBaseAccumulator<Backend>>
                right;
            while (position < order.size() &&
                   (order[position] & (suffix_count - 1U)) == suffix) {
                const std::size_t pair = order[position++];
                const std::size_t bound = pair / suffix_count;
                if (bound >= group_size) {
                    throw std::logic_error(
                        "reference multiplication group exceeds its bound "
                        "domain");
                }
                left.at_endpoint.add(eval_, source_.left_value(pair),
                                     bound_weights.at_endpoint[bound]);
                right.at_endpoint.add(eval_, source_.right_value(pair),
                                      bound_weights.at_endpoint[bound]);
                left.at_two.add(eval_, source_.left_value(pair),
                                bound_weights.at_two[bound]);
                right.at_two.add(eval_, source_.right_value(pair),
                                 bound_weights.at_two[bound]);
            }

            const DenseMultiplicationRoundValues<
                fhe::ExtensionValue<Backend>>
                left_values{
                    .at_endpoint =
                        std::move(left.at_endpoint).finish(eval_),
                    .at_two = std::move(left.at_two).finish(eval_),
                };
            const DenseMultiplicationRoundValues<
                fhe::ExtensionValue<Backend>>
                right_values{
                    .at_endpoint =
                        std::move(right.at_endpoint).finish(eval_),
                    .at_two = std::move(right.at_two).finish(eval_),
                };

            // Step 2: concrete FHE boundary. Multiply the two restricted
            // extension MLEs and apply the remaining suffix weight.
            (void)reference_dense_multiplication_detail::arithmetic::
                accumulate_extension_product<Backend>(
                eval_, product_sums.at_endpoint, left_values.at_endpoint,
                right_values.at_endpoint,
                weights.at_endpoint.suffix[suffix]);
            (void)reference_dense_multiplication_detail::arithmetic::
                accumulate_extension_product<Backend>(
                eval_, product_sums.at_two, left_values.at_two,
                right_values.at_two, weights.at_two.suffix[suffix]);
        }

        // Step 3: apply eq(tau_slot,s), relinearize, and fold the SIMD slots.
        return {
            .at_endpoint = finish_and_fold_slots(
                std::move(product_sums.at_endpoint)),
            .at_two = finish_and_fold_slots(
                std::move(product_sums.at_two)),
        };
    }

    template <typename Accumulator>
    fhe::ExtensionValue<Backend> finish_and_fold_slots(
        Accumulator accumulator) const {
        auto result = apply_mixed_prepared_basis<Backend>(
            eval_, std::move(accumulator), prepared_basis());
        fhe::relinearize_extension_value<Backend>(eval_, result);
        return fhe::ext_fold<Backend>(eval_, result);
    }

    const MixedPreparedFpkSlotBasis<Backend> &prepared_basis() const {
        require_prepared_basis();
        return *prepared_output_slots_;
    }

    void require_prepared_basis() const {
        if (!prepared_output_slots_) {
            throw std::logic_error(
                "reference multiplication output basis is not prepared");
        }
    }

    static constexpr char kInvalidRoundPoint[] =
        "reference multiplication expects the endpoint or X=2";

    const typename Backend::EvalContext &eval_; ///< FHE operation context.
    const Geometry &geometry_;                  ///< Fixed reduction geometry.
    const Source &source_;                      ///< Compact resident pair table.
    std::optional<MixedPreparedFpkSlotBasis<Backend>>
        prepared_output_slots_; ///< Reused public slot-equality basis.
    fhe::FheValue<Backend> public_zero_ =
        fhe::FheValue<Backend>::public_zero(); ///< Omitted source entries.
};

} // namespace laminate::gkr::detail

#endif // LAMINATE_GKR_DETAIL_SHARED_DENSE_MULTIPLICATION_REFERENCE_EVALUATOR_HPP
