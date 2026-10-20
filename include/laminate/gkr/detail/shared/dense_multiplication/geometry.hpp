#ifndef LAMINATE_GKR_DETAIL_SHARED_DENSE_MULTIPLICATION_GEOMETRY_HPP
#define LAMINATE_GKR_DETAIL_SHARED_DENSE_MULTIPLICATION_GEOMETRY_HPP

/// @file geometry.hpp
/// @brief Common algebra for a multiplication layer with dense operand halves.

#include "laminate/field/fpk.hpp"
#include "laminate/gkr/claims.hpp"

#include <bit>
#include <cstddef>
#include <limits>
#include <span>
#include <stdexcept>
#include <vector>

namespace laminate::gkr::detail {

/// Dimensions of the relation
///
///   output(x, s) = source(0, x, s) * source(1, x, s),
///
/// where `x` selects an output index and `s` selects a SIMD slot. The source
/// index domain is exactly twice the output index domain, so its leading bit is
/// the left/right selector.
struct DenseMultiplicationDimensions {
    std::size_t ciphertext_index_variables = 0;
    std::size_t slot_index_variables = 0;

    std::size_t round_count() const {
        return ciphertext_index_variables + slot_index_variables;
    }

    std::size_t source_point_size() const { return round_count() + 1U; }

    static DenseMultiplicationDimensions create(
        std::size_t output_index_count, std::size_t source_index_count,
        std::size_t slot_count) {
        if (output_index_count == 0 ||
            !std::has_single_bit(output_index_count) || slot_count == 0 ||
            !std::has_single_bit(slot_count) ||
            output_index_count >
                std::numeric_limits<std::size_t>::max() / 2U ||
            source_index_count != 2U * output_index_count) {
            throw std::invalid_argument(
                "dense multiplication requires power-of-two output/slot "
                "domains and a source domain twice the output domain");
        }
        const std::size_t ciphertext_index_variables =
            std::bit_width(output_index_count) - 1U;
        const std::size_t slot_index_variables =
            std::bit_width(slot_count) - 1U;
        if (ciphertext_index_variables >
            std::numeric_limits<std::size_t>::max() - slot_index_variables) {
            throw std::overflow_error(
                "dense multiplication round count overflows");
        }
        return DenseMultiplicationDimensions{ciphertext_index_variables,
                                             slot_index_variables};
    }
};

/// The Boolean endpoint values of one equality-stripped degree-two round.
struct DenseMultiplicationEndpoints {
    Fpk zero = Fpk::zero();
    Fpk one = Fpk::zero();
};

/// The left and right source-layer MLE values at one shared random point.
/// The selector bit is not included: zero selects `left` and one selects
/// `right` when the next GKR claim is formed.
template <typename Value>
struct DenseMultiplicationSourceValues {
    Value left;
    Value right;
};

/// The first transmitted point is zero unless `tau=0`, where sending the
/// one endpoint lets the verifier recover the zero endpoint without division.
inline Fpk dense_multiplication_primary_point(const Fpk &tau) {
    return tau.is_zero() ? Fpk::one() : Fpk::zero();
}

/// Recover S(0),S(1) from the running claim and the transmitted primary value.
/// The invariant is `running = (1-tau) S(0) + tau S(1)`.
inline DenseMultiplicationEndpoints recover_dense_multiplication_endpoints(
    const Fpk &running, const Fpk &tau, const Fpk &primary) {
    if (tau.is_zero()) {
        return DenseMultiplicationEndpoints{running, primary};
    }
    return DenseMultiplicationEndpoints{
        primary,
        (running - (Fpk::one() - tau) * primary) * tau.inverse()};
}

/// One coordinate of the multilinear equality polynomial `eq(tau, challenge)`.
inline Fpk dense_multiplication_equality_factor(const Fpk &tau,
                                                const Fpk &challenge) {
    return (Fpk::one() - tau) * (Fpk::one() - challenge) +
           tau * challenge;
}

/// Form `(selector, shared_point)` in the canonical MSB-first source layout.
inline std::vector<Fpk> dense_multiplication_source_point(
    const Fpk &selector, std::span<const Fpk> shared_point) {
    std::vector<Fpk> result;
    result.reserve(shared_point.size() + 1U);
    result.push_back(selector);
    result.insert(result.end(), shared_point.begin(), shared_point.end());
    return result;
}

/// Reduce the two terminal evaluations to one source-layer claim. Their
/// points differ only in the leading selector, so multilinearity gives
/// Src(alpha, rho) = (1-alpha) Src(0, rho) + alpha Src(1, rho).
/// The caller samples alpha only after binding both terminal evaluations.
/// An encrypted prover supplies zero placeholders; verification computes the
/// claim value from the recovered terminal evaluations.
inline SingleClaim make_dense_multiplication_source_claim(
    std::span<const Fpk> shared_point, const Fpk &left_value,
    const Fpk &right_value, const Fpk &selector_challenge) {
    return SingleClaim{
        dense_multiplication_source_point(selector_challenge, shared_point),
        (Fpk::one() - selector_challenge) * left_value +
            selector_challenge * right_value};
}

inline Fpk dense_multiplication_equality(
    std::span<const Fpk> left, std::span<const Fpk> right) {
    if (left.size() != right.size()) {
        throw std::invalid_argument(
            "dense multiplication equality points have different sizes");
    }
    Fpk result = Fpk::one();
    for (std::size_t coordinate = 0; coordinate < left.size(); ++coordinate) {
        result *= dense_multiplication_equality_factor(left[coordinate],
                                                       right[coordinate]);
    }
    return result;
}

/// Every equality factor has already been stripped from the running claim.
/// Compare the terminal product directly: multiplying both sides by the
/// equality prefix would discard the check whenever that prefix is zero.
inline bool dense_multiplication_terminal_is_valid(
    const Fpk &left_value, const Fpk &right_value,
    const Fpk &running_claim) {
    return left_value * right_value == running_claim;
}

} // namespace laminate::gkr::detail

#endif // LAMINATE_GKR_DETAIL_SHARED_DENSE_MULTIPLICATION_GEOMETRY_HPP
