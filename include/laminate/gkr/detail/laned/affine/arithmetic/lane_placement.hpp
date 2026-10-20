#ifndef LAMINATE_GKR_DETAIL_LANED_AFFINE_LANE_PLACEMENT_HPP
#define LAMINATE_GKR_DETAIL_LANED_AFFINE_LANE_PLACEMENT_HPP

/// @file lane_placement.hpp
/// @brief Put B-lane source wires into their N-slot packed positions.

#include "laminate/fhe/extension.hpp"
#include "laminate/fhe/layout/slot_grid.hpp"
#include "laminate/field/fpk.hpp"
#include "laminate/gkr/detail/shared/packed/prepared_basis.hpp"
#include "laminate/packing/alignment/laned.hpp"

#include <algorithm>
#include <cstddef>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

namespace laminate::gkr::laned_detail {

/// Prepare the lane-equality mask for the first B-slot chunk. Other chunks
/// reuse this basis and differ only by a public rotation, so preparation uses
/// O(N) storage rather than one N-slot basis per chunk.
template <fhe::FheBackend Backend>
std::vector<detail::MixedPreparedFpkSlotBasis<Backend>>
prepare_laned_lane_bases(
    const typename Backend::EvalContext &eval,
    const typename Backend::Ciphertext *level_reference,
    const packing::LanedPackingLayout &layout,
    std::span<const Fpk> lane_weights) {
    if (lane_weights.size() != layout.lane_count ||
        Backend::slot_count(eval) != layout.slot_count) {
        throw std::invalid_argument(
            "LaminateLaned prepared lane basis shape mismatch");
    }
    std::vector<detail::MixedPreparedFpkSlotBasis<Backend>> result;
    result.reserve(1);
    std::vector<Fpk> basis(layout.slot_count, Fpk::zero());
    std::copy(lane_weights.begin(), lane_weights.end(), basis.begin());
    result.push_back(detail::prepare_mixed_fpk_slot_basis<Backend>(
        eval, level_reference, basis));
    return result;
}

/// Add `scalar * source` to an extension-field accumulator. This is the
/// per-source FHE boundary in an affine scan: extension-by-public-scalar
/// multiplication followed by ciphertext addition. No ciphertext-ciphertext
/// product is performed.
template <fhe::FheBackend Backend>
void accumulate_laned_scalar_source(
    const typename Backend::EvalContext &eval,
    fhe::MixedExtensionAccumulator<Backend> &accumulator,
    const typename Backend::Ciphertext &source, const Fpk &scalar) {
    if (scalar.is_zero() &&
        !fhe::forces_challenge_independent_topology<Backend>(eval)) {
        return;
    }
    accumulator.accumulate_scaled_base(eval, source, scalar);
}

template <fhe::FheBackend Backend>
void accumulate_laned_scalar_source(
    const typename Backend::EvalContext &eval,
    fhe::MixedExtensionAccumulator<Backend> &accumulator,
    const fhe::FheValue<Backend> &source, const Fpk &scalar) {
    if (source.is_public_zero()) {
        return;
    }
    if (scalar.is_zero() &&
        !fhe::forces_challenge_independent_topology<Backend>(eval)) {
        return;
    }
    accumulator.accumulate_scaled_base(eval, source, scalar);
}

/// Apply the prepared public lane mask, rotate each nonfirst B-slot chunk to
/// its packed position, and add the chunks. These prepared public products,
/// rotations, and additions are the only FHE work in lane placement.
template <fhe::FheBackend Backend>
fhe::ExtensionValue<Backend> apply_laned_lane_bases(
    const typename Backend::EvalContext &eval,
    std::span<fhe::MixedExtensionAccumulator<Backend>> aggregates,
    std::span<const detail::MixedPreparedFpkSlotBasis<Backend>>
        prepared_bases,
    std::size_t first_chunk = 0,
    std::size_t total_chunks = 0) {
    if (prepared_bases.size() != 1U || aggregates.empty()) {
        throw std::invalid_argument(
            "LaminateLaned lane aggregate count mismatch");
    }
    if (total_chunks == 0) {
        total_chunks = aggregates.size();
    }
    if (total_chunks > Backend::slot_count(eval) ||
        Backend::slot_count(eval) % total_chunks != 0 ||
        first_chunk > total_chunks ||
        aggregates.size() > total_chunks - first_chunk) {
        throw std::invalid_argument(
            "LaminateLaned lane aggregate range mismatch");
    }
    fhe::ExtensionValue<Backend> result;
    for (std::size_t chunk = 0; chunk < aggregates.size(); ++chunk) {
        if (aggregates[chunk].empty()) {
            continue;
        }
        auto placed = detail::apply_mixed_prepared_basis<Backend>(
            eval, std::move(aggregates[chunk]), prepared_bases.front());
        const std::size_t global_chunk = first_chunk + chunk;
        if (global_chunk != 0) {
            placed = fhe::rotate_extension<Backend>(
                eval, placed,
                fhe::grid_inverse(
                    Backend::slot_count(eval),
                    global_chunk *
                        (Backend::slot_count(eval) / total_chunks)));
        }
        fhe::extension_add_assign<Backend>(eval, result,
                                           std::move(placed));
    }
    return result;
}

} // namespace laminate::gkr::laned_detail

#endif // LAMINATE_GKR_DETAIL_LANED_AFFINE_LANE_PLACEMENT_HPP
