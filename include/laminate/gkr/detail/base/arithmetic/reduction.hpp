#ifndef LAMINATE_GKR_DETAIL_BASE_ARITHMETIC_REDUCTION_HPP
#define LAMINATE_GKR_DETAIL_BASE_ARITHMETIC_REDUCTION_HPP

/// @file reduction.hpp
/// @brief Plain extension-field arithmetic used by Base verification.

#include "laminate/gkr/detail/shared/reduction/sumcheck.hpp"

#include <cstddef>
#include <span>
#include <stdexcept>

namespace laminate::gkr::base_detail {

inline Fpk sum_slots(std::span<const Fpk> slots) {
    Fpk result = Fpk::zero();
    for (const Fpk &slot : slots) {
        result += slot;
    }
    return result;
}

inline Fpk inner_product(std::span<const Fpk> left,
                         std::span<const Fpk> right) {
    if (left.size() != right.size()) {
        throw std::invalid_argument(
            "LaminateBase: inner-product dimensions differ");
    }
    Fpk result = Fpk::zero();
    for (std::size_t index = 0; index < left.size(); ++index) {
        result += left[index] * right[index];
    }
    return result;
}

inline Fpk interpolate_layer_reduction_round(
    const Fpk &at_zero, const Fpk &at_one, const Fpk &at_two,
    const Fpk &point) {
    return detail::LayerReductionRoundEvaluations{
        at_zero, at_one, at_two}
        .interpolate_at(point);
}

} // namespace laminate::gkr::base_detail

#endif // LAMINATE_GKR_DETAIL_BASE_ARITHMETIC_REDUCTION_HPP
