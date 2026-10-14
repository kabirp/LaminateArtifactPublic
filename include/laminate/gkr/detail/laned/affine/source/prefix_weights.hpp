#ifndef LAMINATE_GKR_DETAIL_LANED_AFFINE_SOURCE_PREFIX_WEIGHTS_HPP
#define LAMINATE_GKR_DETAIL_LANED_AFFINE_SOURCE_PREFIX_WEIGHTS_HPP

/// @file prefix_weights.hpp
/// @brief Cached equality-prefix weights for Laned affine source scans.

#include "laminate/gkr/detail/laned/affine/diagnostics/statistics.hpp"
#include "laminate/gkr/detail/laned/geometry/layout.hpp"
#include "laminate/poly/eq.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <vector>

namespace laminate::gkr::laned_detail::affine_detail {

inline Fpk cached_prefix_weight(
    std::span<const Fpk> weights, std::size_t index,
    std::size_t variables, LanedAffineStatistics *statistics) {
    const std::size_t prefix_variables = log2_exact(
        weights.size(), "LaminateLaned cached affine prefix table");
    if (prefix_variables > variables ||
        index >= poly::hypercube_size(variables)) {
        throw std::invalid_argument(
            "LaminateLaned cached affine prefix lookup is out of range");
    }
    if (statistics != nullptr) {
        checked_accumulate(statistics->public_prefix_weight_lookups, 1,
                           "file-backed affine prefix lookup count");
    }
    return weights[index >> (variables - prefix_variables)];
}

inline std::vector<Fpk> cached_prefix_weights(
    std::span<const Fpk> prefix, LanedAffineStatistics *statistics) {
    const std::vector<Fpk> owned(prefix.begin(), prefix.end());
    std::vector<Fpk> result = poly::eq_evaluations(owned);
    if (statistics != nullptr) {
        checked_accumulate(
            statistics->public_prefix_weight_entries_built,
            static_cast<std::uint64_t>(result.size()),
            "file-backed affine prefix table entries");
    }
    return result;
}

} // namespace laminate::gkr::laned_detail::affine_detail

#endif // LAMINATE_GKR_DETAIL_LANED_AFFINE_SOURCE_PREFIX_WEIGHTS_HPP
