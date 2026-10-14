#ifndef LAMINATE_GKR_DETAIL_SHARED_DENSE_MULTIPLICATION_SOURCE_DISK_BOUNDS_HPP
#define LAMINATE_GKR_DETAIL_SHARED_DENSE_MULTIPLICATION_SOURCE_DISK_BOUNDS_HPP

/// @file disk_bounds.hpp
/// @brief Explicit disk limits for constructing a dense multiplication source.

#include <cstddef>
#include <cstdint>

namespace laminate::gkr::detail {

inline constexpr std::uint64_t
    kDenseMultiplicationSortMaxBufferedPayloadBytes = 4ULL << 30U;
inline constexpr std::size_t kDenseMultiplicationSortMergeFanIn = 64;
inline constexpr std::uint64_t
    kDenseMultiplicationMinimumSortBufferBytes = 64ULL << 20U;

/// Conservative physical-disk bounds for one dense-multiplication source.
/// `completed_artifact_bytes` is the finalized file-trace artifact.
/// `build_peak_bytes` also covers the temporary external-sort runs that
/// coexist while identity, Wide alias, and eager-packed sources are
/// reordered. Other packed aliases can emit one operand at a time directly.
struct FileDenseMultiplicationSourceDiskBounds {
    std::uint64_t completed_artifact_bytes = 0;
    std::uint64_t build_peak_bytes = 0;

    bool operator==(
        const FileDenseMultiplicationSourceDiskBounds &) const = default;
};

/// Bound the disk needed to build one source from `stored_value_count`
/// records whose encoded length is at most `max_record_bytes`.
///
/// The externally sorted paths reserve at least 256 bytes of buffer capacity per
/// record and otherwise stops at `sort_buffer_payload_bytes`, then externally
/// sorts with fan-in 64. The bound follows that exact
/// lifecycle: intermediate replacement runs coexist with the current run
/// generation, while the final artifact instead coexists with the last run
/// generation. These are disjoint phases and are never added together.
FileDenseMultiplicationSourceDiskBounds
file_dense_multiplication_source_disk_bounds(
    std::size_t stored_value_count, std::uint64_t max_record_bytes,
    bool uses_external_sort,
    std::uint64_t sort_buffer_payload_bytes =
        kDenseMultiplicationSortMaxBufferedPayloadBytes);

} // namespace laminate::gkr::detail

#endif // LAMINATE_GKR_DETAIL_SHARED_DENSE_MULTIPLICATION_SOURCE_DISK_BOUNDS_HPP
