#ifndef LAMINATE_FHE_EXTENSION_FOLDING_HPP
#define LAMINATE_FHE_EXTENSION_FOLDING_HPP

/// @file folding.hpp
/// @brief Slot and wire-table partial evaluation for extension ciphertexts.

#include "laminate/fhe/extension/accumulator.hpp"
#include "laminate/fhe/extension/arithmetic.hpp"
#include "laminate/poly/eq.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <span>
#include <stdexcept>
#include <vector>

namespace laminate::fhe {
namespace detail {

inline std::vector<Fpk> expanded_slot_prefix_weights(
    std::size_t slots, std::span<const Fpk> prefix) {
    const std::size_t slot_variables = std::bit_width(slots) - 1U;
    const std::vector<Fpk> owned_prefix(prefix.begin(), prefix.end());
    const std::vector<Fpk> prefix_weights =
        poly::eq_evaluations(owned_prefix);
    std::vector<Fpk> slot_weights(slots);
    const std::size_t suffix_variables = slot_variables - prefix.size();
    for (std::size_t slot = 0; slot < slots; ++slot) {
        slot_weights[slot] = prefix_weights[slot >> suffix_variables];
    }
    return slot_weights;
}

template <FheBackend Backend>
typename Backend::ExtCiphertext partial_evaluate_slot_index_point_with_weights(
    const typename Backend::EvalContext &eval,
    const typename Backend::ExtCiphertext &checkpoint,
    std::span<const Fpk> prefix, std::span<const Fpk> slot_weights) {
    const std::size_t slots = Backend::slot_count(eval);
    if (prefix.empty()) {
        return checkpoint;
    }
    if (slot_weights.size() != slots) {
        throw std::invalid_argument(
            "partial_evaluate_slot_index_point: shared mask has wrong size");
    }
    typename Backend::ExtCiphertext result =
        scale_extension<Backend>(eval, checkpoint, slot_weights);
    const std::size_t slot_variables = std::bit_width(slots) - 1U;
    for (std::size_t variable = 0; variable < prefix.size(); ++variable) {
        const std::size_t stride =
            std::size_t{1} << (slot_variables - 1U - variable);
        auto rotated = rotate_extension<Backend>(eval, result, stride);
        ext_add_assign<Backend>(eval, result, rotated);
    }
    return result;
}

} // namespace detail

/// Bind an MSB-first prefix of the slot variables from a fixed extension
/// checkpoint. Every nonempty call performs exactly one slot-varying
/// plaintext multiplication, then folds the selected prefix with rotations.
/// Calling this from the original checkpoint for each round keeps
/// multiplicative depth independent of the number of bound slot variables.
template <FheBackend Backend>
typename Backend::ExtCiphertext partial_evaluate_slot_index_point(
    const typename Backend::EvalContext &eval,
    const typename Backend::ExtCiphertext &checkpoint,
    std::span<const Fpk> prefix) {
    const std::size_t slots = Backend::slot_count(eval);
    if (slots == 0 || (slots & (slots - 1)) != 0) {
        throw std::invalid_argument(
            "partial_evaluate_slot_index_point: slot count is not a power of two");
    }
    const std::size_t slot_variables = std::bit_width(slots) - 1U;
    if (prefix.size() > slot_variables) {
        throw std::invalid_argument(
            "partial_evaluate_slot_index_point: prefix is too long");
    }
    if (prefix.empty()) {
        return checkpoint;
    }
    if (std::none_of(checkpoint.begin(), checkpoint.end(),
                     [](const auto &coefficient) {
                         return coefficient.has_value();
                     })) {
        return checkpoint;
    }
    const std::vector<Fpk> slot_weights =
        detail::expanded_slot_prefix_weights(slots, prefix);
    return detail::partial_evaluate_slot_index_point_with_weights<Backend>(
        eval, checkpoint, prefix, slot_weights);
}

/// Bind the same MSB-first slot prefix in two fixed checkpoints. The public
/// N-slot equality mask is constructed once and reused for both encrypted
/// operands; the two CT--PT applications and fold chains remain necessarily
/// distinct.
template <FheBackend Backend>
std::array<typename Backend::ExtCiphertext, 2>
partial_evaluate_slot_index_point_pair(
    const typename Backend::EvalContext &eval,
    const typename Backend::ExtCiphertext &left_checkpoint,
    const typename Backend::ExtCiphertext &right_checkpoint,
    std::span<const Fpk> prefix) {
    const std::size_t slots = Backend::slot_count(eval);
    if (slots == 0 || (slots & (slots - 1)) != 0) {
        throw std::invalid_argument(
            "partial_evaluate_slot_index_point_pair: slot count is not a power of two");
    }
    const std::size_t slot_variables = std::bit_width(slots) - 1U;
    if (prefix.size() > slot_variables) {
        throw std::invalid_argument(
            "partial_evaluate_slot_index_point_pair: prefix is too long");
    }
    if (prefix.empty()) {
        return {left_checkpoint, right_checkpoint};
    }
    const std::vector<Fpk> slot_weights =
        detail::expanded_slot_prefix_weights(slots, prefix);
    return {
        detail::partial_evaluate_slot_index_point_with_weights<Backend>(
            eval, left_checkpoint, prefix, slot_weights),
        detail::partial_evaluate_slot_index_point_with_weights<Backend>(
            eval, right_checkpoint, prefix, slot_weights)};
}

template <FheBackend Backend>
ExtensionValue<Backend> fold_extension_value(
    const typename Backend::EvalContext &eval,
    const ExtensionValue<Backend> &value) {
    ExtensionValue<Backend> result;
    for (std::size_t coefficient = 0;
         coefficient < kExtensionDegree; ++coefficient) {
        result[coefficient] = value_fold<Backend>(
            eval, value[coefficient]);
    }
    return result;
}

template <FheBackend Backend>
ExtensionValue<Backend> ext_fold(
    const typename Backend::EvalContext &eval,
    const ExtensionValue<Backend> &value) {
    return fold_extension_value<Backend>(eval, value);
}

template <FheBackend Backend>
ExtensionValue<Backend> partial_evaluate_slot_index_point(
    const typename Backend::EvalContext &eval,
    const ExtensionValue<Backend> &checkpoint,
    std::span<const Fpk> prefix) {
    const std::size_t slots = Backend::slot_count(eval);
    if (slots == 0 || (slots & (slots - 1U)) != 0U) {
        throw std::invalid_argument(
            "partial_evaluate_slot_index_point: slot count is not a power of two");
    }
    const std::size_t slot_variables = std::bit_width(slots) - 1U;
    if (prefix.size() > slot_variables) {
        throw std::invalid_argument(
            "partial_evaluate_slot_index_point: prefix is too long");
    }
    if (prefix.empty()) {
        return checkpoint;
    }
    if (checkpoint.is_public_zero()) {
        return {};
    }
    const std::vector<Fpk> weights =
        detail::expanded_slot_prefix_weights(slots, prefix);
    ExtensionValue<Backend> result = scale_extension_value<Backend>(
        eval, checkpoint, weights);
    for (std::size_t variable = 0; variable < prefix.size(); ++variable) {
        const std::size_t stride =
            std::size_t{1} << (slot_variables - 1U - variable);
        const ExtensionValue<Backend> rotated =
            rotate_extension_value<Backend>(eval, result, stride);
        extension_add_assign<Backend>(eval, result, rotated);
    }
    return result;
}

template <FheBackend Backend>
std::array<ExtensionValue<Backend>, 2>
partial_evaluate_slot_index_point_pair(
    const typename Backend::EvalContext &eval,
    const ExtensionValue<Backend> &left_checkpoint,
    const ExtensionValue<Backend> &right_checkpoint,
    std::span<const Fpk> prefix) {
    return {
        partial_evaluate_slot_index_point<Backend>(
            eval, left_checkpoint, prefix),
        partial_evaluate_slot_index_point<Backend>(
            eval, right_checkpoint, prefix)};
}

/// Bind an MSB-first prefix of a base-ciphertext wire table directly from the
/// original table. Every call is from scratch, so depth is independent of the
/// prefix length. The result has one extension ciphertext per Boolean suffix.
template <FheBackend Backend>
std::vector<typename Backend::ExtCiphertext> partial_evaluate_ciphertext_index_point(
    const typename Backend::EvalContext &eval,
    std::span<const typename Backend::Ciphertext> wires,
    std::span<const Fpk> prefix) {
    if (wires.empty() || (wires.size() & (wires.size() - 1)) != 0) {
        throw std::invalid_argument(
            "partial_evaluate_ciphertext_index_point: wire count must be a power of two");
    }
    const std::size_t wire_vars = std::bit_width(wires.size()) - 1U;
    if (prefix.size() > wire_vars) {
        throw std::invalid_argument(
            "partial_evaluate_ciphertext_index_point: prefix is too long");
    }
    const std::vector<Fpk> owned_prefix(prefix.begin(), prefix.end());
    const std::vector<Fpk> weights = poly::eq_evaluations(owned_prefix);
    const std::size_t suffix_count = wires.size() / weights.size();
    const bool retain_zero_terms =
        forces_challenge_independent_topology<Backend>(eval);
    std::vector<typename Backend::ExtCiphertext> result(suffix_count);

    for (std::size_t suffix = 0; suffix < suffix_count; ++suffix) {
        std::array<bool, kExtensionDegree> present{};
        for (std::size_t bound = 0; bound < weights.size(); ++bound) {
            const typename Backend::Ciphertext &source =
                wires[bound * suffix_count + suffix];
            for (std::size_t coefficient = 0;
                 coefficient < kExtensionDegree; ++coefficient) {
                const Fp scalar = weights[bound].coefficients()[coefficient];
                if (scalar.is_zero() && !retain_zero_terms) {
                    continue;
                }
                typename Backend::Ciphertext term =
                    scalar == Fp::one() && !retain_zero_terms
                        ? source
                        : Backend::mul_plain_scalar(
                              eval, source,
                              scalar.is_zero() && retain_zero_terms
                                  ? Fp::one()
                                  : scalar);
                if (present[coefficient]) {
                    add_assign<Backend>(
                        eval, *result[suffix][coefficient], term);
                } else {
                    result[suffix][coefficient] = std::move(term);
                    present[coefficient] = true;
                }
            }
        }
    }
    return result;
}

/// Mixed-value counterpart used by compact resident traces. Public wires are
/// evaluated analytically and retained as plaintext extension coefficients;
/// private wires remain ciphertext-backed.
template <FheBackend Backend>
std::vector<ExtensionValue<Backend>> partial_evaluate_ciphertext_index_point(
    const typename Backend::EvalContext &eval,
    std::span<const FheValue<Backend>> wires,
    std::span<const Fpk> prefix) {
    if (wires.empty() || (wires.size() & (wires.size() - 1)) != 0) {
        throw std::invalid_argument(
            "partial_evaluate_ciphertext_index_point: wire count must be a power of two");
    }
    const std::size_t wire_vars = std::bit_width(wires.size()) - 1U;
    if (prefix.size() > wire_vars) {
        throw std::invalid_argument(
            "partial_evaluate_ciphertext_index_point: prefix is too long");
    }
    const std::vector<Fpk> weights = poly::eq_evaluations(
        std::vector<Fpk>(prefix.begin(), prefix.end()));
    const std::size_t suffix_count = wires.size() / weights.size();
    std::vector<ExtensionValue<Backend>> result;
    result.reserve(suffix_count);
    for (std::size_t suffix = 0; suffix < suffix_count; ++suffix) {
        MixedExtensionAccumulator<Backend> accumulator;
        for (std::size_t bound = 0; bound < weights.size(); ++bound) {
            const FheValue<Backend> &wire =
                wires[bound * suffix_count + suffix];
            if (wire.is_public_zero()) {
                continue;
            }
            accumulator.accumulate_scaled_base(
                eval, wire, weights[bound]);
        }
        result.push_back(std::move(accumulator).finish(eval));
    }
    return result;
}

} // namespace laminate::fhe

#endif // LAMINATE_FHE_EXTENSION_FOLDING_HPP
