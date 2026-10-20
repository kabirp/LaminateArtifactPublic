#ifndef LAMINATE_GKR_DETAIL_SHARED_REDUCTION_AFFINE_ROUND_HPP
#define LAMINATE_GKR_DETAIL_SHARED_REDUCTION_AFFINE_ROUND_HPP

/// @file affine_round.hpp
/// @brief Named values at X=1 and X=2 in an affine sumcheck round.

#include "laminate/field/fp.hpp"
#include "laminate/field/fpk.hpp"

#include <array>
#include <utility>

namespace laminate::gkr::detail {

/// A pair of affine-round objects evaluated at X=1 and X=2.
///
/// Affine layer reductions always transmit these two points. Naming them here
/// keeps arithmetic kernels from using positional array indices for GateMLE
/// restrictions, equality weights, accumulators, or encrypted messages.
template <typename Value> struct AffineRoundPair {
    Value at_one;
    Value at_two;

    /// Release the pair in the stable proof-transport order: X=1, then X=2.
    std::array<Value, 2> into_transport_order() && {
        return {std::move(at_one), std::move(at_two)};
    }
};

/// The two public field points evaluated in every affine sumcheck round.
struct AffineRoundEvaluationPoints {
    Fpk at_one = Fpk::one();
    Fpk at_two = Fpk::from_base(Fp(2));
};

} // namespace laminate::gkr::detail

#endif // LAMINATE_GKR_DETAIL_SHARED_REDUCTION_AFFINE_ROUND_HPP
