#ifndef LAMINATE_GKR_DETAIL_LANED_AFFINE_SOURCE_SCAN_HPP
#define LAMINATE_GKR_DETAIL_LANED_AFFINE_SOURCE_SCAN_HPP

/// @file scan.hpp
/// @brief Reader normalization and one-pass Laned affine source scans.

#include "laminate/fhe/value.hpp"
#include "laminate/gkr/detail/laned/affine/diagnostics/statistics.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <utility>

namespace laminate::gkr::laned_detail::affine_detail {

struct BatchedSourceScanAccounting {
    std::uint64_t bytes_before = 0;
    std::uint64_t records_before = 0;
    std::uint64_t values_read = 0;
};

template <typename Reader>
std::uint64_t encoded_bytes_read(const Reader &reader) {
    if constexpr (requires { reader.encoded_bytes_read(); }) {
        return reader.encoded_bytes_read();
    }
    return 0;
}

template <typename Reader>
std::uint64_t serialized_records_read(const Reader &reader) {
    if constexpr (requires { reader.serialized_records_read(); }) {
        return reader.serialized_records_read();
    }
    return 0;
}

template <typename Reader>
std::size_t resident_ciphertexts_held(const Reader &reader) {
    if constexpr (requires { reader.resident_ciphertexts_held(); }) {
        return reader.resident_ciphertexts_held();
    }
    return 0;
}

template <typename StoredValue>
const auto &stored_value_ref(const StoredValue &stored) {
    if constexpr (requires { stored.get(); }) {
        return stored.get();
    } else {
        return stored;
    }
}

template <fhe::FheBackend Backend, typename StoredValue>
fhe::FheValue<Backend> as_fhe_value(const StoredValue &stored) {
    const auto &value = stored_value_ref(stored);
    if constexpr (requires {
                      value.is_public();
                      value.is_encrypted();
                  }) {
        return value;
    } else {
        return fhe::FheValue<Backend>::from_ciphertext(value);
    }
}

template <typename Reader>
void record_scan_bytes(const Reader &reader, std::uint64_t bytes_before,
                       std::uint64_t records_before,
                       std::uint64_t fallback_ciphertexts,
                       LanedAffineStatistics *statistics) {
    if (statistics == nullptr) {
        return;
    }
    if constexpr (requires { reader.encoded_bytes_read(); }) {
        const std::uint64_t bytes_after = reader.encoded_bytes_read();
        std::uint64_t physical_records = fallback_ciphertexts;
        if constexpr (requires { reader.serialized_records_read(); }) {
            const std::uint64_t records_after =
                reader.serialized_records_read();
            if (records_after < records_before) {
                throw std::overflow_error(
                    "file-backed affine record accounting underflow");
            }
            physical_records = records_after - records_before;
        }
        if (bytes_after < bytes_before ||
            physical_records >
                (std::numeric_limits<std::uint64_t>::max() -
                 (bytes_after - bytes_before)) /
                    sizeof(std::uint64_t)) {
            throw std::overflow_error(
                "file-backed affine byte accounting overflow");
        }
        const std::uint64_t logical = bytes_after - bytes_before;
        checked_accumulate(statistics->source_logical_bytes_read, logical,
                           "file-backed affine logical bytes");
        checked_accumulate(
            statistics->source_framed_record_bytes_read,
            logical + physical_records * sizeof(std::uint64_t),
            "file-backed affine framed bytes");
    }
}

template <typename Reader>
void validate_full_layer_reader(const Reader &reader,
                                std::size_t reader_value_count) {
    if (reader.begin() != 0 || reader.end() != reader_value_count) {
        throw std::invalid_argument(
            "LaminateLaned affine reader is not the full source layer");
    }
}

/// Start one logical source pass whose physical records will be visited in
/// several indexed, contiguous ranges. Chunk batching uses this instead of
/// rereading the complete layer once per batch.
template <typename Reader>
BatchedSourceScanAccounting begin_batched_source_scan(
    Reader &reader, std::size_t source_live_count,
    LanedAffineStatistics *statistics) {
    validate_full_layer_reader(reader, source_live_count);
    BatchedSourceScanAccounting result{
        .bytes_before = encoded_bytes_read(reader),
        .records_before = serialized_records_read(reader),
    };
    reader.rewind();
    if (statistics != nullptr) {
        checked_accumulate(statistics->source_scans, 1,
                           "file-backed affine scan count");
        checked_accumulate(statistics->source_rewinds, 1,
                           "file-backed affine rewind count");
    }
    return result;
}

/// Visit one half-open range of stored ordinals. The active reader supplies
/// canonical padded indices, so structural zeros remain absent and the
/// caller can map each value to its local chunk accumulator.
template <fhe::FheBackend Backend, typename Reader, typename Visit>
void scan_batched_source_range(
    Reader &reader, std::size_t source_wire_count,
    std::size_t stored_begin, std::size_t stored_end,
    BatchedSourceScanAccounting &accounting,
    LanedAffineStatistics *statistics, Visit &&visit) {
    using OptionalValue = decltype(std::declval<Reader &>().next());
    using Value = typename OptionalValue::value_type;
    static_assert(requires(const Value &value) {
        value.padded_index;
        value.value;
    });
    if (stored_begin > stored_end || stored_begin < reader.begin() ||
        stored_end > reader.end()) {
        throw std::out_of_range(
            "LaminateLaned affine stored range is out of bounds");
    }
    reader.seek_to(stored_begin);
    if (statistics != nullptr) {
        checked_accumulate(statistics->source_range_seeks, 1,
                           "file-backed affine range seek count");
    }
    while (reader.position() < stored_end) {
        auto value = reader.next();
        if (!value || value->padded_index >= source_wire_count) {
            throw std::runtime_error(
                "LaminateLaned affine range reader ended early");
        }
        if (accounting.values_read ==
            std::numeric_limits<std::uint64_t>::max()) {
            throw std::overflow_error(
                "file-backed affine range value count overflows");
        }
        ++accounting.values_read;
        const fhe::FheValue<Backend> logical =
            as_fhe_value<Backend>(value->value);
        if (logical.is_public_zero()) {
            continue;
        }
        if (statistics != nullptr && logical.is_encrypted()) {
            checked_accumulate(statistics->source_ciphertexts_read, 1,
                               "file-backed affine ciphertext read count");
            statistics->peak_live_source_ciphertexts = std::max(
                statistics->peak_live_source_ciphertexts,
                std::size_t{1} + resident_ciphertexts_held(reader));
        }
        visit(value->padded_index, logical);
    }
}

template <typename Reader>
void finish_batched_source_scan(
    const Reader &reader, std::size_t source_live_count,
    const BatchedSourceScanAccounting &accounting,
    LanedAffineStatistics *statistics) {
    if (accounting.values_read != source_live_count) {
        throw std::runtime_error(
            "LaminateLaned affine batched scan omitted source values");
    }
    record_scan_bytes(reader, accounting.bytes_before,
                      accounting.records_before, accounting.values_read,
                      statistics);
}

/// Rewind and visit each nonzero logical source wire exactly once.
///
/// Active readers yield `(padded_index, value)` records and therefore never
/// materialize structural zeros. Dense readers yield values in padded order.
/// Both forms present the same canonical wire indices to the FHE evaluator.
template <fhe::FheBackend Backend, typename Reader, typename Visit>
void scan_source_layer(Reader &reader, std::size_t source_wire_count,
                       std::size_t source_live_count,
                       LanedAffineStatistics *statistics,
                       Visit &&visit) {
    using OptionalValue = decltype(std::declval<Reader &>().next());
    using Value = typename OptionalValue::value_type;
    constexpr bool active_reader = requires(const Value &value) {
        value.padded_index;
        value.value;
    };
    validate_full_layer_reader(
        reader, active_reader ? source_live_count : source_wire_count);
    const std::uint64_t bytes_before = encoded_bytes_read(reader);
    const std::uint64_t records_before = serialized_records_read(reader);
    reader.rewind();
    if (statistics != nullptr) {
        checked_accumulate(statistics->source_scans, 1,
                           "file-backed affine scan count");
        checked_accumulate(statistics->source_rewinds, 1,
                           "file-backed affine rewind count");
    }

    std::size_t position = 0;
    std::size_t live_values = 0;
    while (auto value = reader.next()) {
        if constexpr (active_reader) {
            if (value->padded_index >= source_wire_count) {
                throw std::runtime_error(
                    "LaminateLaned active affine index is out of range");
            }
            const fhe::FheValue<Backend> logical =
                as_fhe_value<Backend>(value->value);
            if (!logical.is_public_zero()) {
                if (statistics != nullptr && logical.is_encrypted()) {
                    checked_accumulate(
                        statistics->source_ciphertexts_read, 1,
                        "file-backed affine ciphertext read count");
                    statistics->peak_live_source_ciphertexts = std::max(
                        statistics->peak_live_source_ciphertexts,
                        std::size_t{1} + resident_ciphertexts_held(reader));
                }
                visit(value->padded_index, logical);
            }
            ++live_values;
        } else {
            if (position >= source_wire_count) {
                throw std::runtime_error(
                    "LaminateLaned affine reader returned too many values");
            }
            const fhe::FheValue<Backend> logical =
                as_fhe_value<Backend>(*value);
            if (!logical.is_public_zero()) {
                if (statistics != nullptr && logical.is_encrypted()) {
                    checked_accumulate(
                        statistics->source_ciphertexts_read, 1,
                        "file-backed affine ciphertext read count");
                    statistics->peak_live_source_ciphertexts = std::max(
                        statistics->peak_live_source_ciphertexts,
                        std::size_t{1} + resident_ciphertexts_held(reader));
                }
                visit(position, logical);
            }
            ++live_values;
        }
        ++position;
    }
    const std::size_t expected_positions =
        active_reader ? source_live_count : source_wire_count;
    if (position != expected_positions ||
        (source_live_count != std::numeric_limits<std::size_t>::max() &&
         live_values != source_live_count) ||
        reader.position() != reader.end()) {
        throw std::runtime_error(
            "LaminateLaned affine reader ended early");
    }
    record_scan_bytes(reader, bytes_before, records_before,
                      static_cast<std::uint64_t>(live_values), statistics);
}

template <fhe::FheBackend Backend, typename Reader, typename Visit>
void scan_source_layer(Reader &reader, std::size_t source_wire_count,
                       LanedAffineStatistics *statistics,
                       Visit &&visit) {
    scan_source_layer<Backend>(
        reader, source_wire_count,
        std::numeric_limits<std::size_t>::max(), statistics,
        std::forward<Visit>(visit));
}

} // namespace laminate::gkr::laned_detail::affine_detail

#endif // LAMINATE_GKR_DETAIL_LANED_AFFINE_SOURCE_SCAN_HPP
