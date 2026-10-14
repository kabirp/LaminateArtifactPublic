#ifndef LAMINATE_GKR_DETAIL_LANED_AFFINE_HADAMARD_HPP
#define LAMINATE_GKR_DETAIL_LANED_AFFINE_HADAMARD_HPP

/// @file hadamard.hpp
/// @brief Convert the lane-weighted terminal into a source-layer claim.

#include "laminate/field/fpk.hpp"
#include "laminate/transcript/transcript.hpp"

#include <span>
#include <stdexcept>
#include <vector>

namespace laminate::gkr::laned_detail {

inline Fpk hadamard_factor(const Fpk &left, const Fpk &right) {
    return (Fpk::one() - left) * (Fpk::one() - right) + left * right;
}

/// Sample a lane challenge for which the terminal change of variables is
/// invertible. This rejection sampling is plaintext transcript work.
inline Fpk challenge_hadamard_safe(Transcript &transcript,
                                   const Fpk &lane_coordinate) {
    while (true) {
        const Fpk candidate = transcript.challenge_fpk();
        if (!hadamard_factor(lane_coordinate, candidate).is_zero()) {
            return candidate;
        }
    }
}

struct HadamardTransform {
    Fpk factor = Fpk::one();
    std::vector<Fpk> point;
};

/// Rewrite `eq(left,b) eq(right,b)` as
/// `factor * eq(transformed,b)` coordinate by coordinate.
inline HadamardTransform hadamard_transform(
    std::span<const Fpk> left, std::span<const Fpk> right) {
    if (left.size() != right.size()) {
        throw std::invalid_argument(
            "LaminateLaned Hadamard points have different dimensions");
    }
    HadamardTransform result;
    result.point.reserve(left.size());
    for (std::size_t index = 0; index < left.size(); ++index) {
        const Fpk factor = hadamard_factor(left[index], right[index]);
        if (factor.is_zero()) {
            throw std::invalid_argument(
                "LaminateLaned singular Hadamard terminal transform");
        }
        result.factor *= factor;
        result.point.push_back(left[index] * right[index] * factor.inverse());
    }
    return result;
}

} // namespace laminate::gkr::laned_detail

#endif // LAMINATE_GKR_DETAIL_LANED_AFFINE_HADAMARD_HPP
