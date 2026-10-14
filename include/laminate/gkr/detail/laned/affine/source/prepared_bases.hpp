#ifndef LAMINATE_GKR_DETAIL_LANED_AFFINE_SOURCE_PREPARED_BASES_HPP
#define LAMINATE_GKR_DETAIL_LANED_AFFINE_SOURCE_PREPARED_BASES_HPP

/// @file prepared_bases.hpp
/// @brief Prepared public lane-placement bases for Laned affine evaluation.

#include "laminate/gkr/detail/laned/affine/arithmetic/lane_placement.hpp"
#include "laminate/gkr/detail/laned/affine/diagnostics/statistics.hpp"

#include <cstddef>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

namespace laminate::gkr::laned_detail::affine_detail {

template <fhe::FheBackend Backend>
void ensure_prepared_lane_bases(
    const typename Backend::EvalContext &eval,
    const typename Backend::Ciphertext *level_reference,
    const packing::LanedPackingLayout &layout,
    std::span<const Fpk> lane_weights,
    std::vector<detail::MixedPreparedFpkSlotBasis<Backend>> &prepared_bases,
    LanedAffineStatistics *statistics) {
    if (prepared_bases.empty()) {
        prepared_bases = prepare_laned_lane_bases<Backend>(
            eval, level_reference, layout, lane_weights);
    } else if (prepared_bases.size() != 1U) {
        throw std::logic_error(
            "LaminateLaned affine prepared basis drifted");
    } else if (level_reference != nullptr &&
               !prepared_bases.front().encrypted) {
        prepared_bases = prepare_laned_lane_bases<Backend>(
            eval, level_reference, layout, lane_weights);
    } else {
        return;
    }
    if (statistics == nullptr || !prepared_bases.front().encrypted) {
        return;
    }
    checked_accumulate(
        statistics->prepared_lane_bases,
        checked_u64(prepared_bases.size(),
                    "file-backed affine prepared lane basis count"),
        "file-backed affine prepared lane basis count");
    for (const auto &basis : prepared_bases) {
        const auto &storage = basis.encrypted->storage;
        checked_accumulate(
            statistics->prepared_basis_level_representations,
            checked_u64(storage.level_representations,
                        "file-backed affine prepared level representations"),
            "file-backed affine prepared level representations");
        checked_accumulate(
            statistics->prepared_basis_ntt_bytes,
            checked_u64(storage.ntt_coefficient_bytes,
                        "file-backed affine prepared NTT bytes"),
            "file-backed affine prepared NTT bytes");
        checked_accumulate(
            statistics->prepared_basis_host_bytes,
            checked_u64(storage.host_basis_bytes,
                        "file-backed affine prepared host bytes"),
            "file-backed affine prepared host bytes");
    }
}

template <fhe::FheBackend Backend>
fhe::ExtensionValue<Backend> apply_prepared_lane_bases(
    const typename Backend::EvalContext &eval,
    std::span<fhe::MixedExtensionAccumulator<Backend>> aggregates,
    std::span<const detail::MixedPreparedFpkSlotBasis<Backend>> prepared_bases,
    LanedAffineStatistics *statistics, std::size_t first_chunk = 0,
    std::size_t total_chunks = 0) {
    if (prepared_bases.size() != 1U || aggregates.empty()) {
        throw std::logic_error(
            "LaminateLaned affine aggregate shape drifted");
    }
    if (total_chunks == 0) {
        total_chunks = aggregates.size();
    }
    if (total_chunks > Backend::slot_count(eval) ||
        Backend::slot_count(eval) % total_chunks != 0 ||
        first_chunk > total_chunks ||
        aggregates.size() > total_chunks - first_chunk) {
        throw std::logic_error(
            "LaminateLaned affine aggregate range drifted");
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
            if (statistics != nullptr) {
                checked_accumulate(
                    statistics->lane_placement_extension_rotations, 1,
                    "file-backed affine lane-placement rotations");
            }
        }
        fhe::extension_add_assign<Backend>(eval, result,
                                           std::move(placed));
        if (statistics != nullptr) {
            checked_accumulate(
                statistics->prepared_lane_basis_applications, 1,
                "file-backed affine prepared lane basis applications");
            checked_accumulate(
                statistics->avoided_online_slot_vector_elements,
                checked_u64(Backend::slot_count(eval),
                            "file-backed affine avoided vector elements"),
                "file-backed affine avoided vector elements");
        }
    }
    return result;
}

} // namespace laminate::gkr::laned_detail::affine_detail

#endif // LAMINATE_GKR_DETAIL_LANED_AFFINE_SOURCE_PREPARED_BASES_HPP
