#ifndef LAMINATE_GKR_DETAIL_BASE_MULTIPLICATION_EVALUATOR_HPP
#define LAMINATE_GKR_DETAIL_BASE_MULTIPLICATION_EVALUATOR_HPP

/// @file evaluator.hpp
/// @brief File-backed FHE evaluator for Base multiplication rounds.
///
/// Base keeps SIMD slots packed and sends the resulting vectors to the
/// client. Consequently this kernel shares the dense multiplication equation
/// and accumulation algebra with Folded/Laned, but does not apply or fold an
/// output-slot equality basis.

#include "laminate/gkr/detail/base/multiplication/types.hpp"
#include "laminate/gkr/detail/shared/dense_multiplication/accumulation.hpp"
#include "laminate/gkr/detail/shared/dense_multiplication/arithmetic/ciphertext_index_rounds.hpp"
#include "laminate/gkr/detail/shared/dense_multiplication/source/scan.hpp"

#include <cstddef>
#include <optional>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

namespace laminate::gkr::base_detail {

namespace base_multiplication_evaluator_detail {

namespace arithmetic = ::laminate::gkr::detail::
    dense_multiplication_accumulation_detail;
namespace shared = ::laminate::gkr::detail;
namespace scan = ::laminate::gkr::detail::multiplication_detail;

inline constexpr char kInvalidRoundPoint[] =
    "Base multiplication expects the endpoint or X=2";

/// First ciphertext-index round:
///
///   S_0(X;s) = sum_u eq(tau_suffix,u) L(X,u;s) R(X,u;s).
///
/// L and R are still base-field ciphertexts, so this pass pairs their low/high
/// branches and performs the concrete base-ciphertext products directly.
template <fhe::FheBackend Backend, typename Reader>
EncryptedMultiplicationRoundEvaluations<Backend>
evaluate_first_ciphertext_index_round(
    const typename Backend::EvalContext &eval, Reader &reader,
    std::size_t ciphertext_index_variables,
    const shared::LayerReductionRoundPoints &round_points,
    const shared::DenseMultiplicationRoundValues<
        shared::CiphertextIndexRoundWeights> &weights,
    shared::FileBackedMultiplicationStatistics &statistics) {
    // Step 1: Start one sequential scan and pair each live low/high branch for
    // the first ciphertext-index coordinate.
    const auto scan_start = scan::begin_scan(reader, statistics);
    const std::size_t suffix_count = reader.domain_size() / 2U;
    shared::DenseMultiplicationRoundValues<
        fhe::MixedExtensionAccumulator<Backend>>
        product_sums;
    std::optional<typename Reader::Pair> pending;
    while (pending || reader.position() < reader.size()) {
        auto low_record =
            pending ? std::move(*pending) : scan::next_pair(reader);
        pending.reset();
        std::optional<typename Reader::Pair> high_record;
        const std::size_t suffix =
            low_record.packed_index & (suffix_count - 1U);
        const bool record_is_high =
            low_record.packed_index >= suffix_count;
        if (!record_is_high && reader.position() < reader.size()) {
            auto candidate = scan::next_pair(reader);
            if (candidate.packed_index == suffix_count + suffix) {
                high_record = std::move(candidate);
            } else {
                pending = std::move(candidate);
            }
        }

        const auto public_zero = fhe::FheValue<Backend>::public_zero();
        const auto &low_left =
            record_is_high ? public_zero : low_record.left();
        const auto &low_right =
            record_is_high ? public_zero : low_record.right();
        const auto &high_left = record_is_high
                                    ? low_record.left()
                                    : high_record ? high_record->left()
                                                  : public_zero;
        const auto &high_right = record_is_high
                                     ? low_record.right()
                                     : high_record ? high_record->right()
                                                   : public_zero;
        const std::size_t buffered_values =
            high_record ? 2U : pending ? 2U : 0U;
        scan::note_source_residency(statistics, 2U + buffered_values);

        // Step 2: Select L(endpoint,u;s) and R(endpoint,u;s), multiply them as
        // base ciphertexts, and add the public suffix-weighted product.
        const auto endpoint_left =
            arithmetic::select_base_pair_branch<Backend>(
                eval, low_left, high_left, round_points.endpoint,
                kInvalidRoundPoint);
        const auto endpoint_right =
            arithmetic::select_base_pair_branch<Backend>(
                eval, low_right, high_right, round_points.endpoint,
                kInvalidRoundPoint);
        const auto support =
            ciphertext_index_variables == 1U
                ? arithmetic::BaseProductSupport::PublicBase
                : arithmetic::BaseProductSupport::GeneralExtension;
        if (arithmetic::accumulate_base_product<Backend>(
                eval, product_sums.at_endpoint, endpoint_left,
                endpoint_right, weights.at_endpoint.suffix[suffix],
                support)) {
            scan::note_base_product(statistics);
        }

        // Step 3: Repeat the same concrete FHE product at X=2.
        const auto left_at_two =
            arithmetic::select_base_pair_branch<Backend>(
                eval, low_left, high_left, round_points.at_two,
                kInvalidRoundPoint);
        const auto right_at_two =
            arithmetic::select_base_pair_branch<Backend>(
                eval, low_right, high_right, round_points.at_two,
                kInvalidRoundPoint);
        if (arithmetic::accumulate_base_product<Backend>(
                eval, product_sums.at_two, left_at_two, right_at_two,
                weights.at_two.suffix[suffix], support)) {
            scan::note_base_product(statistics);
        }
        scan::note_extension_residency(
            statistics,
            shared::dense_multiplication_ciphertext_round_detail::
                present_round_values(product_sums));
    }
    scan::finish_scan(reader, scan_start, statistics);

    // Step 4: Relinearize both slot-packed round values. Base leaves them
    // packed because the client evaluates the SIMD-slot point after decryption.
    return {
        .at_endpoint = arithmetic::finish_product_sum<Backend>(
            eval, std::move(product_sums.at_endpoint)),
        .at_two = arithmetic::finish_product_sum<Backend>(
            eval, std::move(product_sums.at_two)),
    };
}

/// Later ciphertext-index round:
///
///   S_j(X;s) = sum_u eq(tau_suffix,u)
///                    L(r_prefix,X,u;s) R(r_prefix,X,u;s).
///
/// The prior challenges make L and R extension-field values. This pass first
/// binds those challenges within each suffix group, then multiplies the two
/// restricted extension MLEs.
template <fhe::FheBackend Backend, typename Reader>
EncryptedMultiplicationRoundEvaluations<Backend>
evaluate_later_ciphertext_index_round(
    const typename Backend::EvalContext &eval, Reader &reader,
    std::size_t ciphertext_index_variables,
    std::span<const Fpk> ciphertext_index_prefix,
    const shared::DenseMultiplicationRoundValues<
        shared::CiphertextIndexRoundWeights> &weights,
    shared::FileBackedMultiplicationStatistics &statistics) {
    // Step 1: Build equality weights for the prefix already fixed at the
    // transmitted endpoint and at X=2.
    const shared::DenseMultiplicationRoundValues<std::vector<Fpk>>
        bound_weights{
            .at_endpoint =
                poly::eq_evaluations(weights.at_endpoint.bound_point),
            .at_two = poly::eq_evaluations(weights.at_two.bound_point),
        };
    const std::size_t suffix_variables =
        ciphertext_index_variables - ciphertext_index_prefix.size() - 1U;
    const std::size_t suffix_count =
        poly::hypercube_size(suffix_variables);
    shared::DenseMultiplicationRoundValues<fhe::ExtensionValue<Backend>>
        product_sums;
    std::optional<typename Reader::Pair> pending;
    const auto scan_start = scan::begin_scan(reader, statistics);

    // Step 2: Bind L and R to the existing prefix within one canonical suffix
    // group. Reader buffering and its accounting remain local to this scan.
    while (pending || reader.position() < reader.size()) {
        std::optional<std::size_t> suffix;
        shared::DenseMultiplicationRoundValues<
            arithmetic::WeightedBaseAccumulator<Backend>>
            left;
        shared::DenseMultiplicationRoundValues<
            arithmetic::WeightedBaseAccumulator<Backend>>
            right;
        while (pending || reader.position() < reader.size()) {
            auto pair =
                pending ? std::move(*pending) : scan::next_pair(reader);
            pending.reset();
            const std::size_t bound = pair.packed_index / suffix_count;
            const std::size_t pair_suffix =
                pair.packed_index & (suffix_count - 1U);
            if (!suffix) {
                suffix = pair_suffix;
            } else if (*suffix != pair_suffix) {
                pending = std::move(pair);
                break;
            }
            scan::note_source_residency(statistics, 2U);
            left.at_endpoint.add(eval, pair.left(),
                                 bound_weights.at_endpoint[bound]);
            right.at_endpoint.add(eval, pair.right(),
                                  bound_weights.at_endpoint[bound]);
            left.at_two.add(eval, pair.left(), bound_weights.at_two[bound]);
            right.at_two.add(eval, pair.right(), bound_weights.at_two[bound]);
            scan::note_extension_residency(
                statistics,
                4U + shared::dense_multiplication_ciphertext_round_detail::
                         present_round_values(product_sums));
        }
        if (!suffix) {
            throw std::logic_error(
                "Base file-backed multiplication suffix group was empty");
        }

        const shared::DenseMultiplicationRoundValues<
            fhe::ExtensionValue<Backend>>
            left_values{
                .at_endpoint = std::move(left.at_endpoint).finish(eval),
                .at_two = std::move(left.at_two).finish(eval),
            };
        const shared::DenseMultiplicationRoundValues<
            fhe::ExtensionValue<Backend>>
            right_values{
                .at_endpoint = std::move(right.at_endpoint).finish(eval),
                .at_two = std::move(right.at_two).finish(eval),
            };

        // Step 3: Multiply the restricted extension MLEs at both transmitted
        // points and apply the remaining suffix equality weight.
        if (arithmetic::accumulate_extension_product<Backend>(
                eval, product_sums.at_endpoint, left_values.at_endpoint,
                right_values.at_endpoint,
                weights.at_endpoint.suffix[*suffix])) {
            scan::note_extension_product(statistics);
        }
        if (arithmetic::accumulate_extension_product<Backend>(
                eval, product_sums.at_two, left_values.at_two,
                right_values.at_two, weights.at_two.suffix[*suffix])) {
            scan::note_extension_product(statistics);
        }
        scan::note_extension_residency(
            statistics,
            shared::dense_multiplication_ciphertext_round_detail::
                present_round_values(product_sums));
    }
    scan::finish_scan(reader, scan_start, statistics);

    // Step 4: Relinearize both slot-packed evaluations without folding SIMD.
    return {
        .at_endpoint = arithmetic::finish_product_sum<Backend>(
            eval, std::move(product_sums.at_endpoint)),
        .at_two = arithmetic::finish_product_sum<Backend>(
            eval, std::move(product_sums.at_two)),
    };
}

} // namespace base_multiplication_evaluator_detail

/// Arithmetic boundary for the production Base multiplication reduction.
///
/// The visible prover asks this object to evaluate one protocol object at a
/// time. This object alone owns the rewindable file reader and the associated
/// I/O/FHE ledger. It never publishes a proof message or samples a
/// Fiat--Shamir challenge.
///
/// For a fixed ciphertext-index prefix `r`, one sumcheck round evaluates
///
///   S_j(X;s) = sum_u eq(tau_suffix,u)
///                       L(r,X,u;s) R(r,X,u;s)
///
/// independently in every SIMD slot `s`. Unlike Folded and Laned, Base does
/// not fold those slots under FHE. After the last ciphertext-index round,
/// `evaluate_terminal_source` returns the packed vectors L(r;s), R(r;s); the
/// client evaluates their slot coordinates after decryption.
template <fhe::FheBackend Backend, typename Source>
class BaseMultiplicationRoundEvaluator {
  public:
    using RoundEvaluations =
        EncryptedMultiplicationRoundEvaluations<Backend>;
    using SourceValues = EncryptedMultiplicationSourceValues<Backend>;

    BaseMultiplicationRoundEvaluator(
        const typename Backend::EvalContext &eval,
        std::span<const Fpk> output_ciphertext_index, const Source &source,
        ::laminate::gkr::detail::FileBackedMultiplicationStatistics
            *statistics = nullptr)
        : eval_(eval),
          output_ciphertext_index_(output_ciphertext_index),
          reader_(source.reader()),
          live_pair_count_(source.descriptor().live_pair_count),
          statistics_(statistics != nullptr ? *statistics
                                            : owned_statistics_) {
        statistics_ =
            ::laminate::gkr::detail::FileBackedMultiplicationStatistics{};
    }

    /// Evaluate S_j(endpoint;s) and S_j(2;s) in one sequential source pass.
    /// Reader rewinds, decoding, buffering, and accounting remain below this
    /// semantic method.
    RoundEvaluations evaluate_ciphertext_index_round(
        std::span<const Fpk> ciphertext_index_prefix,
        const ::laminate::gkr::detail::LayerReductionRoundPoints
            &round_points) {
        namespace shared = ::laminate::gkr::detail;
        namespace kernel = base_multiplication_evaluator_detail;

        const std::size_t ciphertext_index_variables =
            output_ciphertext_index_.size();
        if (ciphertext_index_variables == 0U ||
            reader_.domain_size() !=
                poly::hypercube_size(ciphertext_index_variables) ||
            ciphertext_index_prefix.size() >= ciphertext_index_variables) {
            throw std::invalid_argument(
                "Base file-backed multiplication round shape mismatch");
        }

        const shared::DenseMultiplicationRoundValues<
            shared::CiphertextIndexRoundWeights>
            weights{
                .at_endpoint =
                    shared::make_ciphertext_index_round_scalar_weights(
                        output_ciphertext_index_,
                        ciphertext_index_variables,
                        ciphertext_index_prefix, round_points.endpoint),
                .at_two =
                    shared::make_ciphertext_index_round_scalar_weights(
                        output_ciphertext_index_,
                        ciphertext_index_variables,
                        ciphertext_index_prefix, round_points.at_two),
            };
        if (ciphertext_index_prefix.empty()) {
            return kernel::evaluate_first_ciphertext_index_round<Backend>(
                eval_, reader_, ciphertext_index_variables,
                round_points, weights, statistics_);
        }
        return kernel::evaluate_later_ciphertext_index_round<Backend>(
            eval_, reader_, ciphertext_index_variables,
            ciphertext_index_prefix, weights, statistics_);
    }

    /// Bind the complete ciphertext-index point into both source halves:
    ///
    ///   L(r;s) = sum_i eq(r,i)L_i(s),
    ///   R(r;s) = sum_i eq(r,i)R_i(s).
    ///
    /// This final source pass is linear: it performs no L*R ciphertext
    /// product and deliberately leaves the SIMD-slot coordinate unresolved.
    SourceValues evaluate_terminal_source(
        std::span<const Fpk> ciphertext_index_point) {
        if (ciphertext_index_point.size() !=
            output_ciphertext_index_.size()) {
            throw std::invalid_argument(
                "Base multiplication terminal point shape mismatch");
        }
        return ::laminate::gkr::detail::
            evaluate_multiplication_slot_checkpoints<Backend>(
                eval_, reader_, ciphertext_index_point, statistics_);
    }

    /// Number of non-padding multiplication pairs visited by each pass.
    std::size_t live_pair_count() const { return live_pair_count_; }

  private:
    using Reader = decltype(std::declval<const Source &>().reader());

    const typename Backend::EvalContext &eval_; ///< Concrete FHE context.
    /// Output equality coordinates reduced under FHE. The remaining slot
    /// coordinates are deliberately deferred to the Base client.
    std::span<const Fpk> output_ciphertext_index_;
    Reader reader_;               ///< Sequential disk reader.
    std::size_t live_pair_count_; ///< Per-pass work units.
    ::laminate::gkr::detail::FileBackedMultiplicationStatistics
        owned_statistics_;
    ::laminate::gkr::detail::FileBackedMultiplicationStatistics
        &statistics_; ///< Source and arithmetic ledger.
};

} // namespace laminate::gkr::base_detail

#endif // LAMINATE_GKR_DETAIL_BASE_MULTIPLICATION_EVALUATOR_HPP
