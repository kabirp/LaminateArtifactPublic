#ifndef LAMINATE_GKR_DETAIL_BASE_AFFINE_INTERNAL_SOURCE_PREFIX_HPP
#define LAMINATE_GKR_DETAIL_BASE_AFFINE_INTERNAL_SOURCE_PREFIX_HPP

/// @file source_prefix.hpp
/// @brief Sparse equality-prefix state for the Base affine reduction.

#include "laminate/field/fpk.hpp"
#include "laminate/gkr/detail/base/affine/internal/accounting.hpp"
#include "laminate/gkr/detail/shared/reduction/affine_round.hpp"
#include "laminate/payload/trace/trace_wire_support.hpp"

#include <bit>
#include <cstddef>
#include <stdexcept>
#include <utility>
#include <vector>

namespace laminate::gkr::base_detail::base_affine_detail {

/// Equality weights for only the live wires of a virtually padded source.
///
/// After challenges `r_0,...,r_{j-1}` have been bound, `weights_[u]` equals
/// `eq(r_<j, u_<j)` for live wire `u`. This keeps the public prefix work
/// proportional to live trace records; structural zero wires are never
/// materialized.
class SparseSourcePrefixWeights {
  public:
    explicit SparseSourcePrefixWeights(payload::LayerWireSupport support)
        : support_(std::move(support)),
          weights_(support_.live_wire_count, Fpk::one()) {
        payload::validate_layer_wire_support(support_);
        variables_ = std::bit_width(support_.padded_wire_count) - 1U;
    }

    /// Return `eq(r_<j || x, u_<j+1>)` for x=1 and x=2.
    ::laminate::gkr::detail::AffineRoundPair<Fpk> evaluate_next(
        std::size_t live_ordinal, std::size_t padded_index,
        const ::laminate::gkr::detail::AffineRoundEvaluationPoints &points,
        BaseAffineStatistics *statistics) const {
        validate_live(live_ordinal, padded_index);
        if (bound_variables_ >= variables_) {
            throw std::logic_error("Base affine source prefix is complete");
        }
        const bool bit =
            ((padded_index >> (variables_ - 1U - bound_variables_)) &
             std::size_t{1}) != 0;
        if (statistics != nullptr) {
            checked_accumulate(
                statistics->public_live_source_candidate_weight_lookups,
                2, "Base affine source candidate weight lookups");
        }
        const auto restrict_at = [&](const Fpk &point) {
            return weights_[live_ordinal] *
                   (bit ? point : Fpk::one() - point);
        };
        return {.at_one = restrict_at(points.at_one),
                .at_two = restrict_at(points.at_two)};
    }

    /// Bind the next Fiat--Shamir challenge into every live prefix weight.
    void bind(const Fpk &challenge,
              BaseAffineStatistics *statistics) {
        if (bound_variables_ >= variables_) {
            throw std::logic_error("Base affine source prefix is complete");
        }
        std::size_t live = 0;
        const std::size_t shift = variables_ - 1U - bound_variables_;
        for (const payload::LiveWireRange &range : support_.live_ranges) {
            for (std::size_t padded = range.padded_begin;
                 padded < range.padded_end(); ++padded) {
                const bool bit =
                    ((padded >> shift) & std::size_t{1}) != 0;
                weights_.at(live++) *=
                    bit ? challenge : Fpk::one() - challenge;
            }
        }
        if (live != weights_.size()) {
            throw std::logic_error(
                "Base affine source prefix support drifted");
        }
        if (statistics != nullptr) {
            checked_accumulate(
                statistics->public_live_source_weight_updates,
                checked_u64(live, "Base affine source weight updates"),
                "Base affine source weight updates");
        }
        ++bound_variables_;
    }

    const Fpk &complete_at(std::size_t live_ordinal,
                           std::size_t padded_index) const {
        if (bound_variables_ != variables_) {
            throw std::logic_error(
                "Base affine source prefix is incomplete");
        }
        validate_live(live_ordinal, padded_index);
        return weights_[live_ordinal];
    }

    std::size_t bound_variables() const { return bound_variables_; }
    std::size_t variables() const { return variables_; }

    bool next_at_one_has_public_support(std::size_t padded_index) const {
        if (bound_variables_ >= variables_ ||
            padded_index >= support_.padded_wire_count) {
            throw std::out_of_range(
                "Base affine source support query is out of range");
        }
        const std::size_t bit = variables_ - 1U - bound_variables_;
        return ((padded_index >> bit) & std::size_t{1}) != 0;
    }

  private:
    void validate_live(std::size_t live_ordinal,
                       std::size_t padded_index) const {
        if (live_ordinal >= weights_.size() ||
            support_.padded_index_of(live_ordinal) != padded_index) {
            throw std::runtime_error(
                "Base affine source prefix live order mismatch");
        }
    }

    payload::LayerWireSupport support_;
    std::vector<Fpk> weights_;
    std::size_t variables_ = 0;
    std::size_t bound_variables_ = 0;
};

} // namespace laminate::gkr::base_detail::base_affine_detail

#endif // LAMINATE_GKR_DETAIL_BASE_AFFINE_INTERNAL_SOURCE_PREFIX_HPP
