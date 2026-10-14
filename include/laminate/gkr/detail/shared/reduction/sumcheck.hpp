#ifndef LAMINATE_GKR_DETAIL_SHARED_REDUCTION_SUMCHECK_HPP
#define LAMINATE_GKR_DETAIL_SHARED_REDUCTION_SUMCHECK_HPP

/// @file sumcheck.hpp
/// @brief Degree-two interpolation for Laminate layer-reduction rounds.

#include "laminate/field/fp.hpp"
#include "laminate/field/fpk.hpp"

#include <array>
#include <utility>

namespace laminate::gkr::detail {

/// The two evaluations sent in one equality-stripped layer-reduction round.
///
/// The first field is the evaluation at the Boolean endpoint selected by the
/// protocol. For an affine round that endpoint is always one. For a
/// multiplication round it is zero unless the corresponding output-claim
/// coordinate is zero, in which case it is one.
/// The verifier derives that endpoint and reconstructs the other Boolean
/// evaluation from the running sumcheck claim.
template <typename Value>
struct TransmittedLayerReductionRound {
    Value at_endpoint;
    Value at_two;

    /// Convert to the stable wire order: selected endpoint, then X=2.
    std::array<Value, 2> into_transcript_order() && {
        return {std::move(at_endpoint), std::move(at_two)};
    }
};

/// Public points evaluated by the prover in one equality-stripped round.
/// `endpoint` is derived from the verifier's existing claim point; `at_two`
/// is fixed by the protocol and retained here to keep array indices out of
/// arithmetic kernels.
struct LayerReductionRoundPoints {
    Fpk endpoint = Fpk::one();
    Fpk at_two = Fpk::from_base(Fp(2));
};

/// The three evaluations that determine one degree-two sumcheck round.
///
/// Protocol control flow deliberately does not live in this type. Each
/// Laminate affine or multiplication prover/verifier keeps its short round
/// recurrence local so readers can see when the message is bound, when the
/// challenge is sampled, and how the running claim changes.
struct LayerReductionRoundEvaluations {
    Fpk at_zero = Fpk::zero();
    Fpk at_one = Fpk::zero();
    Fpk at_two = Fpk::zero();

    /// Evaluate the unique degree-two polynomial through the three points.
    Fpk interpolate_at(const Fpk &point) const {
        const Fpk one = Fpk::one();
        const Fpk two = Fpk::from_base(Fp(2));
        const Fpk half = two.inverse();

        // Lagrange interpolation on {0,1,2}:
        //
        //   S(r) = S(0)(r-1)(r-2)/2
        //        - S(1)r(r-2)
        //        + S(2)r(r-1)/2.
        return at_zero * (point - one) * (point - two) * half -
               at_one * point * (point - two) +
               at_two * point * (point - one) * half;
    }
};

} // namespace laminate::gkr::detail

#endif // LAMINATE_GKR_DETAIL_SHARED_REDUCTION_SUMCHECK_HPP
