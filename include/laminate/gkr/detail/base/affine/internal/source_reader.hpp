#ifndef LAMINATE_GKR_DETAIL_BASE_AFFINE_INTERNAL_SOURCE_READER_HPP
#define LAMINATE_GKR_DETAIL_BASE_AFFINE_INTERNAL_SOURCE_READER_HPP

/// @file source_reader.hpp
/// @brief Canonical compact-source scans for Base affine rounds.

#include "laminate/fhe/value.hpp"
#include "laminate/gkr/detail/base/affine/internal/accounting.hpp"
#include "laminate/payload/trace/trace_wire_support.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <stdexcept>

namespace laminate::gkr::base_detail::base_affine_detail {

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

template <typename Reader>
void record_scan_bytes(const Reader &reader, std::uint64_t bytes_before,
                       std::uint64_t records_before,
                       std::uint64_t records_read,
                       BaseAffineStatistics *statistics) {
    if (statistics == nullptr) {
        return;
    }
    if constexpr (requires { reader.encoded_bytes_read(); }) {
        const std::uint64_t bytes_after = reader.encoded_bytes_read();
        if (bytes_after < bytes_before) {
            throw std::overflow_error(
                "Base affine byte counter underflows");
        }
        if constexpr (requires { reader.serialized_records_read(); }) {
            const std::uint64_t records_after =
                reader.serialized_records_read();
            if (records_after < records_before ||
                records_after - records_before != records_read) {
                throw std::runtime_error(
                    "Base affine record accounting mismatch");
            }
        }
        const std::uint64_t logical = bytes_after - bytes_before;
        checked_accumulate(statistics->source_logical_bytes_read, logical,
                           "Base affine logical bytes");
        if (records_read >
            (std::numeric_limits<std::uint64_t>::max() - logical) /
                sizeof(std::uint64_t)) {
            throw std::overflow_error(
                "Base affine framed bytes overflow");
        }
        checked_accumulate(
            statistics->source_framed_record_bytes_read,
            logical + records_read * sizeof(std::uint64_t),
            "Base affine framed bytes");
    }
}

/// Rewind and visit every live source record in canonical padded-wire order.
///
/// Structural zero wires are represented by `LayerWireSupport`, not stored
/// records. Readers may return either public-aware values or concrete
/// ciphertexts; the visitor always receives a canonical `FheValue`.
template <fhe::FheBackend Backend, typename Reader, typename Visit>
void scan_active_source(
    Reader &reader, const payload::LayerWireSupport &support,
    BaseAffineStatistics *statistics, Visit &&visit) {
    if (reader.begin() != 0 || reader.end() != support.live_wire_count) {
        throw std::invalid_argument(
            "LaminateBase affine reader is not the complete active "
            "source layer");
    }
    const std::uint64_t bytes_before = encoded_bytes_read(reader);
    const std::uint64_t records_before = serialized_records_read(reader);
    reader.rewind();
    if (statistics != nullptr) {
        checked_accumulate(statistics->source_scans, 1,
                           "Base affine scan count");
        checked_accumulate(statistics->source_rewinds, 1,
                           "Base affine rewind count");
        checked_accumulate(
            statistics->public_zero_positions,
            checked_u64(support.padded_wire_count - support.live_wire_count,
                        "Base affine public-zero count"),
            "Base affine public-zero count");
    }

    std::size_t live_ordinal = 0;
    while (auto record = reader.next()) {
        if (live_ordinal >= support.live_wire_count ||
            record->padded_index != support.padded_index_of(live_ordinal)) {
            throw std::runtime_error(
                "LaminateBase affine active-record order mismatch");
        }
        const auto &stored = [&]() -> const auto & {
            if constexpr (requires { record->value; }) {
                return record->value;
            } else {
                return record->ciphertext;
            }
        }();
        const auto &stored_value = [&]() -> const auto & {
            if constexpr (requires { stored.get(); }) {
                return stored.get();
            } else {
                return stored;
            }
        }();
        const bool is_encrypted = [&]() {
            if constexpr (requires { stored_value.is_encrypted(); }) {
                return stored_value.is_encrypted();
            }
            return true;
        }();
        if (statistics != nullptr && is_encrypted) {
            checked_accumulate(
                statistics->source_ciphertexts_read, 1,
                "Base affine ciphertext read count");
            statistics->peak_live_source_ciphertexts = std::max(
                statistics->peak_live_source_ciphertexts,
                std::size_t{1} + resident_ciphertexts_held(reader));
        }
        if constexpr (requires { stored_value.is_public(); }) {
            visit(live_ordinal, record->padded_index, stored_value);
        } else {
            const fhe::FheValue<Backend> wrapped =
                fhe::FheValue<Backend>::from_ciphertext(stored_value);
            visit(live_ordinal, record->padded_index, wrapped);
        }
        ++live_ordinal;
    }
    if (live_ordinal != support.live_wire_count ||
        reader.position() != reader.end()) {
        throw std::runtime_error(
            "LaminateBase affine active reader ended early");
    }
    const std::uint64_t read =
        checked_u64(live_ordinal, "Base affine records read");
    record_scan_bytes(reader, bytes_before, records_before, read, statistics);
}

} // namespace laminate::gkr::base_detail::base_affine_detail

#endif // LAMINATE_GKR_DETAIL_BASE_AFFINE_INTERNAL_SOURCE_READER_HPP
