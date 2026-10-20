#ifndef LAMINATE_GKR_DETAIL_FOLDED_AFFINE_SLOT_SUMCHECK_HPP
#define LAMINATE_GKR_DETAIL_FOLDED_AFFINE_SLOT_SUMCHECK_HPP

/// @file slot_round.hpp
/// @brief Slot-round algebra for a Folded affine reduction.

#include "laminate/fhe/extension.hpp"
#include "laminate/gkr/detail/folded/affine/internal/gate_schedule.hpp"
#include "laminate/gkr/detail/folded/affine/types.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <vector>

namespace laminate::gkr::folded_detail {

struct FoldedAffineSlotRoundStatistics {
    /// The fixed checkpoint prefix is bound once for the transmitted pair.
    std::uint64_t checkpoint_prefix_bindings = 0;
    /// Public R(1)/R(2) weights and their two full-slot masks are constructed
    /// together rather than by two independent round evaluators.
    std::uint64_t public_weight_pairs_constructed = 0;
    std::uint64_t full_slot_masks_constructed = 0;
    std::uint64_t full_slot_mask_elements_constructed = 0;

    bool operator==(const FoldedAffineSlotRoundStatistics &) const = default;
};

/// Rolling public GateMLE values for the remaining slot suffix.
///
/// The schedule's rotation bases are combined once into one table G. Each
/// call to `round_weights` returns G(prefix, 1, suffix) and
/// G(prefix, 2, suffix); `bind` then fixes the sampled slot challenge. This
/// is plaintext host-field work and retains O(N) field elements.
class PreparedAffineSlotWeights {
  public:
    static PreparedAffineSlotWeights create(
        const AffineSparseSchedule &schedule,
        std::span<const Fpk> basis_weights) {
        if (schedule.bases.size() != basis_weights.size()) {
            throw std::invalid_argument(
                "LaminateFolded affine basis-weight shape mismatch");
        }
        PreparedAffineSlotWeights result;
        if (schedule.bases.empty()) {
            throw std::invalid_argument(
                "LaminateFolded affine schedule has no slot basis");
        }
        result.remaining_slots_ = affine_slot_count(schedule);
        result.table_.assign(result.remaining_slots_, Fpk::zero());
        for (std::size_t basis = 0; basis < schedule.bases.size(); ++basis) {
            for (std::size_t slot = 0; slot < result.remaining_slots_;
                 ++slot) {
                result.table_[slot] +=
                    basis_weights[basis] *
                    affine_slot_basis_value(schedule, basis, slot);
            }
        }
        return result;
    }

    FoldedAffineGateRestrictions round_weights() const {
        if (remaining_slots_ < 2) {
            throw std::logic_error(
                "LaminateFolded affine slot table is terminal");
        }
        const std::size_t stride = remaining_slots_ / 2U;
        FoldedAffineGateRestrictions result{
            .at_one = std::vector<Fpk>(stride, Fpk::zero()),
            .at_two = std::vector<Fpk>(stride, Fpk::zero())};
        for (std::size_t suffix = 0; suffix < stride; ++suffix) {
            const Fpk low = table_[suffix];
            const Fpk high = table_[stride + suffix];
            result.at_one[suffix] = high;
            result.at_two[suffix] = high + high - low;
        }
        return result;
    }

    void bind(const Fpk &challenge) {
        if (remaining_slots_ < 2) {
            throw std::logic_error(
                "LaminateFolded affine slot table is already terminal");
        }
        const std::size_t stride = remaining_slots_ / 2U;
        for (std::size_t suffix = 0; suffix < stride; ++suffix) {
            table_[suffix] +=
                challenge * (table_[stride + suffix] - table_[suffix]);
        }
        table_.resize(stride);
        remaining_slots_ = stride;
    }

  private:
    /// Current Boolean suffix table of the public affine GateMLE.
    std::vector<Fpk> table_;
    /// Boolean size of `table_`; halved after every sampled slot challenge.
    std::size_t remaining_slots_ = 0;
};

inline std::vector<Fpk> place_slot_suffix(
    std::span<const Fpk> values, std::size_t base,
    std::size_t slot_count) {
    if (base > slot_count || values.size() > slot_count - base) {
        throw std::invalid_argument(
            "LaminateFolded slot suffix exceeds the SIMD grid");
    }
    std::vector<Fpk> result(slot_count, Fpk::zero());
    for (std::size_t index = 0; index < values.size(); ++index) {
        result[base + index] = values[index];
    }
    return result;
}

/// Compute the two encrypted evaluations for one affine slot round.
///
/// With every ciphertext-index variable and the prior slot prefix fixed, let
/// C be the encrypted source MLE after the ciphertext-index coordinates have
/// been fixed and G the public affine GateMLE. This returns
///
///   R_j(x) = sum_b G(prefix, x, b) C(prefix, x, b),  x in {1, 2}.
///
/// `partial_evaluate_slot_index_point`, the rotation/extrapolation, public-mask
/// scaling, and `ext_fold` below are the complete FHE boundary of a slot
/// round. Preparing G and placing its masks are plaintext host work.
template <fhe::FheBackend Backend>
FoldedAffineRoundEvaluations<Backend> affine_sparse_slot_round(
    const typename Backend::EvalContext &eval,
    const fhe::ExtensionValue<Backend> &checkpoint,
    const FoldedAffineGateRestrictions &gate,
    std::span<const Fpk> prefix, std::size_t slot_index_variables,
    FoldedAffineSlotRoundStatistics *statistics = nullptr) {
    const std::size_t slot_count = Backend::slot_count(eval);
    if (prefix.size() >= slot_index_variables) {
        throw std::invalid_argument(
            "LaminateFolded affine slot prefix is too long");
    }
    const std::size_t suffix_variables =
        slot_index_variables - prefix.size() - 1U;
    const std::size_t stride = poly::hypercube_size(suffix_variables);
    if (gate.at_one.size() != stride || gate.at_two.size() != stride) {
        throw std::invalid_argument(
            "LaminateFolded prepared affine slot weights have wrong size");
    }
    if (checkpoint.is_public_zero()) {
        // A structurally zero source contributes no backend work.
        return {};
    }

    // FHE boundary: fix the already sampled slot prefix in C, then rotate its
    // next Boolean branches into aligned SIMD positions. A null C returned
    // above, so neither operation manufactures an encryption of zero.
    const auto partial = fhe::partial_evaluate_slot_index_point<Backend>(
        eval, checkpoint, prefix);
    const auto high = fhe::rotate_extension<Backend>(eval, partial, stride);
    const auto at_two = fhe::extrapolate_extension_at_two<Backend>(
        eval, partial, high);
    if (statistics != nullptr) {
        ++statistics->checkpoint_prefix_bindings;
        ++statistics->public_weight_pairs_constructed;
        statistics->full_slot_masks_constructed += 2U;
        statistics->full_slot_mask_elements_constructed +=
            2U * slot_count;
    }
    // FHE boundary: multiply the aligned branches by the two public GateMLE
    // masks, then fold each SIMD vector to the scalar R_j(1) or R_j(2).
    auto one = fhe::scale_extension<Backend>(
        eval, partial,
        place_slot_suffix(gate.at_one, stride, slot_count));
    auto two = fhe::scale_extension<Backend>(
        eval, at_two, place_slot_suffix(gate.at_two, 0, slot_count));
    return FoldedAffineRoundEvaluations<Backend>{
        fhe::ext_fold<Backend>(eval, one),
        fhe::ext_fold<Backend>(eval, two)};
}

} // namespace laminate::gkr::folded_detail

#endif // LAMINATE_GKR_DETAIL_FOLDED_AFFINE_SLOT_SUMCHECK_HPP
