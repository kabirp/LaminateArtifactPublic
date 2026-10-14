#ifndef LAMINATE_GKR_DETAIL_SHARED_DENSE_MULTIPLICATION_SOURCE_SCAN_HPP
#define LAMINATE_GKR_DETAIL_SHARED_DENSE_MULTIPLICATION_SOURCE_SCAN_HPP

/// @file scan.hpp
/// @brief Validate and account for each sequential multiplication-source scan.

#include "laminate/gkr/detail/shared/dense_multiplication/statistics.hpp"
#include "laminate/gkr/detail/shared/dense_multiplication/source/file.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>
#include <utility>

namespace laminate::gkr::detail {

namespace multiplication_source_store_detail =
    file_dense_multiplication_source_detail;

namespace multiplication_detail {

struct ScanSnapshot {
    std::uint64_t pairs_read = 0;
    std::uint64_t values_read = 0;
    std::uint64_t distinct_values_read = 0;
    std::uint64_t logical_record_bytes_read = 0;
    std::uint64_t index_bit_flips = 0;
};

/// Start one complete pass over the compact live-pair artifact. Rewinding is
/// explicit because every ciphertext-index round reuses the same source.

inline std::uint64_t checked_delta(std::uint64_t after,
                                   std::uint64_t before,
                                   const char *description) {
    if (after < before) {
        throw std::logic_error(std::string(description) +
                               " counter moved backwards");
    }
    return after - before;
}

inline void note_source_residency(
    FileBackedMultiplicationStatistics &statistics,
    std::size_t values) {
    statistics.peak_live_decoded_source_values = std::max(
        statistics.peak_live_decoded_source_values, values);
}

inline void note_extension_residency(
    FileBackedMultiplicationStatistics &statistics,
    std::size_t accumulators) {
    statistics.peak_retained_extension_accumulators = std::max(
        statistics.peak_retained_extension_accumulators, accumulators);
}

/// Record one nonzero base-ciphertext product and its public Fpk scaling.
/// Call this immediately after the arithmetic routine reports that it did
/// real FHE work; structural public-zero products are deliberately omitted.
inline void note_base_product(
    FileBackedMultiplicationStatistics &statistics) {
    multiplication_source_store_detail::checked_accumulate(
        statistics.base_products, 1,
        "file-backed multiplication base product count");
    multiplication_source_store_detail::checked_accumulate(
        statistics.suffix_scalar_promotions, 1,
        "file-backed multiplication suffix scalar promotion count");
}

/// Record one nonzero extension-field product and its public Fpk scaling.
inline void note_extension_product(
    FileBackedMultiplicationStatistics &statistics) {
    multiplication_source_store_detail::checked_accumulate(
        statistics.extension_products, 1,
        "file-backed multiplication extension product count");
    multiplication_source_store_detail::checked_accumulate(
        statistics.suffix_scalar_promotions, 1,
        "file-backed multiplication suffix scalar promotion count");
}

template <typename Reader>
ScanSnapshot begin_scan(
    Reader &reader,
    FileBackedMultiplicationStatistics &statistics) {
    if (reader.position() != 0) {
        reader.rewind();
        multiplication_source_store_detail::checked_accumulate(
            statistics.artifact_rewinds, 1,
            "file-backed multiplication rewind count");
    }
    multiplication_source_store_detail::checked_accumulate(
        statistics.artifact_scans, 1,
        "file-backed multiplication scan count");
    const auto &current = reader.statistics();
    return ScanSnapshot{current.pairs_read, current.values_read,
                        current.distinct_values_read,
                        current.logical_record_bytes_read,
                        current.bit_reversal_bit_flips};
}

template <typename Reader>
void finish_scan(
    const Reader &reader,
    const ScanSnapshot &before,
    FileBackedMultiplicationStatistics &statistics) {
    // A sumcheck round is valid only after consuming every stored live pair.
    // The deltas below make an accidental partial or duplicated pass visible.
    if (reader.position() != reader.size()) {
        throw std::runtime_error(
            "file-backed multiplication artifact scan ended early");
    }
    const auto &after = reader.statistics();
    statistics.peak_live_decoded_source_values = std::max(
        statistics.peak_live_decoded_source_values,
        after.peak_live_decoded_values);
    const std::uint64_t pairs = checked_delta(
        after.pairs_read, before.pairs_read,
        "file-backed multiplication pair read");
    const std::uint64_t values = checked_delta(
        after.values_read, before.values_read,
        "file-backed multiplication value read");
    const std::uint64_t distinct_values = checked_delta(
        after.distinct_values_read, before.distinct_values_read,
        "file-backed multiplication distinct value read");
    const std::uint64_t bytes = checked_delta(
        after.logical_record_bytes_read,
        before.logical_record_bytes_read,
        "file-backed multiplication record byte read");
    const std::uint64_t bit_flips = checked_delta(
        after.bit_reversal_bit_flips, before.index_bit_flips,
        "file-backed multiplication bit-reversal work");
    const std::uint64_t expected_pairs =
        multiplication_source_store_detail::checked_count(
            reader.size(), "file-backed multiplication live artifact size");
    const std::uint64_t expected_values =
        reader.stored_value_count();
    // Coverage is exact even when the bounded cache rereads evicted aliases.
    // Each pair can decode at most its two operands; I/O totals below retain
    // every physical read rather than silently dropping the reread cost.
    const std::uint64_t maximum_reads =
        dense_resource_multiply(expected_pairs, 2U);
    if (pairs != expected_pairs || distinct_values != expected_values ||
        values < distinct_values || values > maximum_reads) {
        throw std::runtime_error(
            "file-backed multiplication artifact scan ledger drifted: pairs " +
            std::to_string(pairs) + "/" + std::to_string(expected_pairs) +
            ", distinct values " + std::to_string(distinct_values) + "/" +
            std::to_string(expected_values) + ", decoded records " +
            std::to_string(values) + " (expected " +
            std::to_string(expected_values) + ".." +
            std::to_string(maximum_reads) + ")");
    }
    multiplication_source_store_detail::checked_accumulate(
        statistics.artifact_pairs_read, pairs,
        "file-backed multiplication pair read count");
    multiplication_source_store_detail::checked_accumulate(
        statistics.artifact_values_read, values,
        "file-backed multiplication value read count");
    multiplication_source_store_detail::checked_accumulate(
        statistics.artifact_logical_record_bytes_read, bytes,
        "file-backed multiplication record byte read count");
    multiplication_source_store_detail::checked_accumulate(
        statistics.artifact_index_bit_flips, bit_flips,
        "file-backed multiplication bit-reversal work");
    if (values >
        (std::numeric_limits<std::uint64_t>::max() - bytes) /
            sizeof(std::uint64_t)) {
        throw std::overflow_error(
            "file-backed multiplication framed byte count overflows u64");
    }
    const std::uint64_t framed_bytes =
        bytes + values * sizeof(std::uint64_t);
    multiplication_source_store_detail::checked_accumulate(
        statistics.artifact_framed_record_bytes_read, framed_bytes,
        "file-backed multiplication framed byte read count");
}

template <typename Reader>
typename Reader::Pair next_pair(Reader &reader) {
    auto pair = reader.next();
    if (!pair) {
        throw std::runtime_error(
            "file-backed multiplication artifact ended early");
    }
    return std::move(*pair);
}

} // namespace multiplication_detail

} // namespace laminate::gkr::detail

#endif // LAMINATE_GKR_DETAIL_SHARED_DENSE_MULTIPLICATION_SOURCE_SCAN_HPP
