#ifndef LAMINATE_GKR_DETAIL_LANED_AFFINE_SLOT_ROUND_HPP
#define LAMINATE_GKR_DETAIL_LANED_AFFINE_SLOT_ROUND_HPP

/// @file slot_round.hpp
/// @brief Slot-round evaluations shared by file-backed and reference affine.

#include "laminate/fhe/extension.hpp"
#include "laminate/gkr/detail/laned/affine/types.hpp"
#include "laminate/gkr/detail/laned/geometry/layout.hpp"
#include "laminate/packing/alignment/laned.hpp"
#include "laminate/poly/eq.hpp"

#include <cstddef>
#include <span>
#include <stdexcept>
#include <vector>

namespace laminate::gkr::laned_detail {

/// Evaluate `R_j(1)` and `R_j(2)` after all ciphertext coordinates are fixed.
/// `checkpoint` is the encrypted slot table C. For each endpoint, this kernel
/// computes
///
///   R_j(a) = FoldSlots(gate_a * C(prefix || a, remaining slots)).
///
/// It restricts C at the public prefix, rotates the Boolean halves together,
/// applies the public gate mask, and folds all slots. These are linear FHE
/// operations only; no source scan or ciphertext-ciphertext product occurs.
template <fhe::FheBackend Backend>
LanedAffineRoundEvaluations<Backend>
affine_slot_round_evaluations(
    const typename Backend::EvalContext &eval,
    const fhe::ExtensionValue<Backend> &checkpoint,
    const packing::LanedPackingLayout &layout,
    const LanedAffineGateRestrictions &gate_values,
    std::span<const Fpk> prefix) {
    const std::size_t slot_index_variables = log2_exact(
        layout.slot_count, "LaminateLaned affine slot variables");
    if (prefix.size() >= slot_index_variables) {
        throw std::invalid_argument(
            "LaminateLaned affine slot round shape mismatch");
    }
    const std::size_t lane_variables = log2_exact(
        layout.lane_count, "LaminateLaned affine lane variables");
    const std::size_t stride = poly::hypercube_size(
        slot_index_variables - prefix.size() - 1U);
    const auto validate_gate_suffix = [](const std::vector<Fpk> &values) {
        if (values.empty() ||
            (values.size() & (values.size() - 1U)) != 0U) {
            throw std::invalid_argument(
                "LaminateLaned affine slot gate suffix is malformed");
        }
    };
    validate_gate_suffix(gate_values.at_one);
    validate_gate_suffix(gate_values.at_two);
    // A known zero polynomial needs no prefix masks, rotation, or FHE call.
    if (checkpoint.is_public_zero()) {
        return {};
    }

    const auto partial = fhe::partial_evaluate_slot_index_point<Backend>(
        eval, checkpoint, prefix);
    const auto high = fhe::rotate_extension<Backend>(eval, partial, stride);
    const auto at_two = fhe::extrapolate_extension_at_two<Backend>(
        eval, partial, high);

    LanedAffineGateRestrictions masks{
        .at_one = std::vector<Fpk>(layout.slot_count, Fpk::zero()),
        .at_two = std::vector<Fpk>(layout.slot_count, Fpk::zero())};
    for (std::size_t suffix = 0; suffix < stride; ++suffix) {
        const std::size_t chunk = suffix >> lane_variables;
        masks.at_one[stride + suffix] =
            gate_values.at_one[
                chunk & (gate_values.at_one.size() - 1U)];
        masks.at_two[suffix] =
            gate_values.at_two[
                chunk & (gate_values.at_two.size() - 1U)];
    }
    auto one =
        fhe::scale_extension<Backend>(eval, partial, masks.at_one);
    auto two =
        fhe::scale_extension<Backend>(eval, at_two, masks.at_two);
    return {.at_one = fhe::ext_fold<Backend>(eval, one),
            .at_two = fhe::ext_fold<Backend>(eval, two)};
}

/// Evaluate the slot checkpoint at the final slot point. This performs one
/// public slot-mask multiplication and one linear slot fold.
template <fhe::FheBackend Backend>
fhe::ExtensionValue<Backend> evaluate_affine_checkpoint(
    const typename Backend::EvalContext &eval,
    const fhe::ExtensionValue<Backend> &checkpoint,
    std::span<const Fpk> slot_point) {
    if (slot_point.size() !=
        log2_exact(Backend::slot_count(eval),
                   "LaminateLaned affine terminal slot point")) {
        throw std::invalid_argument(
            "LaminateLaned affine terminal slot point has wrong dimension");
    }
    if (checkpoint.is_public_zero()) {
        return {};
    }
    const std::vector<Fpk> owned_point(slot_point.begin(), slot_point.end());
    const std::vector<Fpk> weights = poly::eq_evaluations(owned_point);
    return fhe::ext_fold<Backend>(
        eval, fhe::scale_extension<Backend>(eval, checkpoint, weights));
}

} // namespace laminate::gkr::laned_detail

#endif // LAMINATE_GKR_DETAIL_LANED_AFFINE_SLOT_ROUND_HPP
