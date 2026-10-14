#ifndef LAMINATE_BENCH_PACKED_CHECKPOINT_POLICY_HPP
#define LAMINATE_BENCH_PACKED_CHECKPOINT_POLICY_HPP

/// @file packed_checkpoint_policy.hpp
/// @brief Checked decoder-policy bounds for the packed process benchmark.

#include "laminate/gates/table_types.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <stdexcept>

namespace laminate::bench {

/// Maximum aggregate number of GateMLE target cells in an honest packed
/// proof. Laned reserves two rows per compact table (current GKR needs one).
/// Wide authenticates
/// local constraints at both boundaries and shares a mask dictionary across
/// layers, so its bound includes every layer's local queries. The nested
/// decoder charges cells across all tables.
template <typename GateShape>
inline std::uint64_t packed_gate_mle_target_cell_limit(
    const GateShape &key) {
    if (key.tables.size() != key.layout.tables.size()) {
        throw std::invalid_argument(
            "packed GateMLE verifier-key table count mismatch");
    }

    // Wide local certificates issue several queries per reverse trace, and
    // the mask dictionary is shared by every affine layer. This aggregate
    // bound covers all public table rows without counting composed paths.
    const auto layers = std::max<std::size_t>(1, key.layout.wide_layers.size());
    if (layers > std::numeric_limits<std::uint64_t>::max() / 24U)
        throw std::overflow_error("packed GateMLE layer count overflows");
    const std::uint64_t kMaximumRowsPerTable =
        key.layout.table_set == gates::GateTableSet::Wide ? 24U * layers : 2U;
    std::uint64_t total = 0;
    for (const auto &table : key.tables) {
        if constexpr (std::numeric_limits<std::size_t>::digits >
                      std::numeric_limits<std::uint64_t>::digits) {
            if (table.physical_width >
                static_cast<std::size_t>(
                    std::numeric_limits<std::uint64_t>::max())) {
                throw std::overflow_error(
                    "packed GateMLE physical width exceeds uint64_t");
            }
        }
        const std::uint64_t width =
            static_cast<std::uint64_t>(table.physical_width);
        if (width > std::numeric_limits<std::uint64_t>::max() /
                        kMaximumRowsPerTable) {
            throw std::overflow_error(
                "packed GateMLE target row count overflows");
        }
        const std::uint64_t table_cells =
            kMaximumRowsPerTable * width;
        if (table_cells >
            std::numeric_limits<std::uint64_t>::max() - total) {
            throw std::overflow_error(
                "packed GateMLE aggregate target count overflows");
        }
        total += table_cells;
    }
    return total;
}

} // namespace laminate::bench

#endif // LAMINATE_BENCH_PACKED_CHECKPOINT_POLICY_HPP
