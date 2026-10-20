#ifndef LAMINATE_GKR_DETAIL_SHARED_DENSE_MULTIPLICATION_ROUNDS_HPP
#define LAMINATE_GKR_DETAIL_SHARED_DENSE_MULTIPLICATION_ROUNDS_HPP

/// @file rounds.hpp
/// @brief Shared round equations for dense-halves multiplication.

#include "laminate/fhe/extension.hpp"
#include "laminate/gkr/detail/shared/dense_multiplication/geometry.hpp"
#include "laminate/gkr/detail/shared/reduction/sumcheck.hpp"
#include "laminate/poly/eq.hpp"

#include <array>
#include <cstddef>
#include <span>
#include <stdexcept>
#include <vector>

namespace laminate::gkr::detail {

/// Values associated with the two points evaluated in one dense
/// multiplication round.
///
/// `at_endpoint` is the nonsingular Boolean endpoint selected from the
/// current output-claim coordinate. `at_two` is the degree-two check point.
/// This type is used for public weights and encrypted accumulators so those
/// meanings never disappear behind array indices.
template <typename Value>
struct DenseMultiplicationRoundValues {
    Value at_endpoint;
    Value at_two;
};

/// Public weights for one ciphertext-index round.
///
/// For the current variable X and remaining Boolean suffix u, the dense
/// Folded/Laned reduction proves
///
///   S(X) = sum_u eq(gamma_suffix, u)
///                    L(prefix, X, u) R(prefix, X, u).
///
/// Slot equality is independent of the ciphertext-index variable and is kept
/// as a SIMD mask.
struct CiphertextIndexRoundWeights {
    /// Equality weights for ciphertext indices already fixed by challenges.
    std::vector<Fpk> bound_point;
    /// Equality weights for the Boolean ciphertext-index suffix being summed.
    std::vector<Fpk> suffix;
    /// Equality weights for the output-slot coordinates carried by SIMD.
    std::vector<Fpk> slots;
};

/// Public SIMD masks for the two evaluations sent in one slot-index round.
struct MultiplicationSlotRoundMasks {
    std::vector<Fpk> at_endpoint;
    std::vector<Fpk> at_two;
};

/// Source-layer MLEs after every ciphertext-index coordinate has been fixed.
/// They remain slot-packed while subsequent slot-index rounds bind one SIMD
/// coordinate at a time.
template <fhe::FheBackend Backend>
struct MultiplicationSlotCheckpoints {
    fhe::ExtensionValue<Backend> left;
    fhe::ExtensionValue<Backend> right;
};

inline CiphertextIndexRoundWeights make_ciphertext_index_round_weights(
    std::span<const Fpk> output_point,
    std::size_t ciphertext_index_variables,
    std::span<const Fpk> prefix, const Fpk &round_value) {
    if (output_point.size() < ciphertext_index_variables) {
        throw std::invalid_argument(
            "dense multiplication output point is too short");
    }

    CiphertextIndexRoundWeights result;
    result.bound_point.assign(prefix.begin(), prefix.end());
    result.bound_point.push_back(round_value);
    if (result.bound_point.size() > ciphertext_index_variables) {
        throw std::invalid_argument(
            "dense multiplication ciphertext-index prefix is too long");
    }

    result.suffix = poly::eq_evaluations(std::vector<Fpk>(
        output_point.begin() +
            static_cast<std::ptrdiff_t>(result.bound_point.size()),
        output_point.begin() +
            static_cast<std::ptrdiff_t>(ciphertext_index_variables)));
    result.slots = poly::eq_evaluations(std::vector<Fpk>(
        output_point.begin() +
            static_cast<std::ptrdiff_t>(ciphertext_index_variables),
        output_point.end()));
    return result;
}

/// Ciphertext-index weights without the N-entry output-slot equality vector.
/// Optimized provers prepare that fixed vector once per reduction and reuse
/// it after scalar-weighted products have been accumulated.
inline CiphertextIndexRoundWeights make_ciphertext_index_round_scalar_weights(
    std::span<const Fpk> output_point,
    std::size_t ciphertext_index_variables,
    std::span<const Fpk> prefix, const Fpk &round_value) {
    CiphertextIndexRoundWeights result = make_ciphertext_index_round_weights(
        output_point.first(ciphertext_index_variables),
        ciphertext_index_variables, prefix, round_value);
    result.slots.clear();
    return result;
}

inline MultiplicationSlotRoundMasks multiplication_slot_round_masks(
    std::span<const Fpk> output_slot, std::size_t prefix_size,
    const Fpk &transmitted_endpoint, std::size_t stride,
    std::size_t slot_count) {
    if (transmitted_endpoint != Fpk::zero() &&
        transmitted_endpoint != Fpk::one()) {
        throw std::invalid_argument(
            "dense multiplication primary slot point is not Boolean");
    }
    const std::vector<Fpk> suffix_weights =
        poly::eq_evaluations(std::vector<Fpk>(
            output_slot.begin() +
                static_cast<std::ptrdiff_t>(prefix_size + 1U),
            output_slot.end()));
    if (suffix_weights.size() != stride) {
        throw std::logic_error(
            "dense multiplication slot suffix dimension mismatch");
    }
    MultiplicationSlotRoundMasks result{
        .at_endpoint = std::vector<Fpk>(slot_count, Fpk::zero()),
        .at_two = std::vector<Fpk>(slot_count, Fpk::zero()),
    };
    const std::size_t primary_base =
        transmitted_endpoint == Fpk::one() ? stride : 0U;
    for (std::size_t suffix = 0; suffix < stride; ++suffix) {
        result.at_endpoint[primary_base + suffix] = suffix_weights[suffix];
        result.at_two[suffix] = suffix_weights[suffix];
    }
    return result;
}

/// Evaluate the protocol's Boolean primary point and X=2 together. The two
/// fixed checkpoints are bound to the existing prefix once; the high branch,
/// X=2 extrapolation, and both public suffix masks are then shared by the
/// transmitted pair.
template <fhe::FheBackend Backend>
TransmittedLayerReductionRound<fhe::ExtensionValue<Backend>>
evaluate_multiplication_slot_round(
    const typename Backend::EvalContext &eval,
    const fhe::ExtensionValue<Backend> &left_checkpoint,
    const fhe::ExtensionValue<Backend> &right_checkpoint,
    std::span<const Fpk> output_slot, std::span<const Fpk> prefix,
    const Fpk &transmitted_endpoint) {
    const std::size_t slot_index_variables = output_slot.size();
    if (prefix.size() >= slot_index_variables ||
        (transmitted_endpoint != Fpk::zero() &&
         transmitted_endpoint != Fpk::one())) {
        throw std::invalid_argument(
            "dense multiplication slot pair has invalid shape");
    }
    if (left_checkpoint.is_public_zero() ||
        right_checkpoint.is_public_zero()) {
        return {};
    }
    const std::size_t stride =
        poly::hypercube_size(
            slot_index_variables - prefix.size() - 1U);
    auto bound_pair = fhe::partial_evaluate_slot_index_point_pair<Backend>(
        eval, left_checkpoint, right_checkpoint, prefix);
    DenseMultiplicationSourceValues<fhe::ExtensionValue<Backend>> bound{
        .left = std::move(bound_pair[0]),
        .right = std::move(bound_pair[1]),
    };
    const auto left_high =
        fhe::rotate_extension<Backend>(eval, bound.left, stride);
    const auto right_high =
        fhe::rotate_extension<Backend>(eval, bound.right, stride);
    auto left_at_two = fhe::extrapolate_extension_at_two<Backend>(
        eval, bound.left, left_high);
    auto right_at_two = fhe::extrapolate_extension_at_two<Backend>(
        eval, bound.right, right_high);
    const MultiplicationSlotRoundMasks masks =
        multiplication_slot_round_masks(
        output_slot, prefix.size(), transmitted_endpoint, stride,
        Backend::slot_count(eval));

    // FHE boundary for S(endpoint): multiply the partially bound source MLEs
    // after applying the public suffix-equality mask to L.
    auto weighted_primary = fhe::scale_extension<Backend>(
        eval, bound.left, masks.at_endpoint);
    auto primary = fhe::mixed_extension_mul_no_relin<Backend>(
        eval, weighted_primary, bound.right);
    fhe::relinearize_extension_value<Backend>(eval, primary);

    // FHE boundary for S(2): extrapolate both branches, apply the X=2 mask,
    // and multiply the resulting extension values.
    auto weighted_two =
        fhe::scale_extension<Backend>(eval, left_at_two, masks.at_two);
    auto two = fhe::mixed_extension_mul_no_relin<Backend>(
        eval, weighted_two, right_at_two);
    fhe::relinearize_extension_value<Backend>(eval, two);
    return {
        .at_endpoint = fhe::ext_fold<Backend>(eval, primary),
        .at_two = fhe::ext_fold<Backend>(eval, two),
    };
}

} // namespace laminate::gkr::detail

#endif // LAMINATE_GKR_DETAIL_SHARED_DENSE_MULTIPLICATION_ROUNDS_HPP
