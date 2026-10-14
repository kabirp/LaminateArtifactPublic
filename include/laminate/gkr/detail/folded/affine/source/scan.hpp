#ifndef LAMINATE_GKR_DETAIL_FOLDED_AFFINE_SOURCE_SCAN_HPP
#define LAMINATE_GKR_DETAIL_FOLDED_AFFINE_SOURCE_SCAN_HPP

/// @file scan.hpp
/// @brief Compact Folded affine source adaptation and scan accounting.

#include "laminate/gkr/detail/folded/affine/diagnostics/statistics.hpp"
#include "laminate/payload/trace/trace_wire_support.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <stdexcept>

namespace laminate::gkr::folded_detail::folded_affine_detail {

/// Return the stored value behind an optional reference wrapper.
template <typename StoredValue>
const auto &stored_value_ref(const StoredValue &stored) {
    if constexpr (requires { stored.get(); }) {
        return stored.get();
    } else {
        return stored;
    }
}

/// Return the encrypted payload used only as a modulus-level reference.
/// Public values, including known zero, deliberately return null.
template <fhe::FheBackend Backend, typename StoredValue>
const typename Backend::Ciphertext *encrypted_ciphertext_ptr(
    const StoredValue &stored) {
    const auto &value = stored_value_ref(stored);
    if constexpr (requires {
                      value.is_encrypted();
                      value.ciphertext();
                  }) {
        return value.is_encrypted() ? &value.ciphertext() : nullptr;
    } else {
        return &value;
    }
}

template <typename StoredValue>
bool stored_is_encrypted(const StoredValue &stored) {
    const auto &value = stored_value_ref(stored);
    if constexpr (requires { value.is_encrypted(); }) {
        return value.is_encrypted();
    } else {
        return true;
    }
}

template <typename StoredValue>
bool stored_public_zero(const StoredValue &stored) {
    const auto &value = stored_value_ref(stored);
    if constexpr (requires { value.is_public_zero(); }) {
        return value.is_public_zero();
    }
    return false;
}

template <typename Record>
decltype(auto) record_stored_value(const Record &record) {
    if constexpr (requires { record.value; }) {
        return (record.value);
    } else {
        return (record.ciphertext);
    }
}

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

/// Rewind and visit every live source record exactly once.
///
/// The padded suffix is public zero and has no stored record. This adapter
/// validates canonical order and accounts for I/O; it performs no protocol
/// arithmetic itself.
template <typename Reader, typename Visit>
void scan_active_source(
    Reader &reader, const payload::LayerWireSupport &support,
    FoldedAffineStatistics &statistics, Visit &&visit) {
    if (reader.begin() != 0 || reader.end() != support.live_wire_count) {
        throw std::invalid_argument(
            "LaminateFolded affine reader is not the complete active layer");
    }
    const std::uint64_t bytes_before = encoded_bytes_read(reader);
    const std::uint64_t records_before = serialized_records_read(reader);
    reader.rewind();
    checked_accumulate(statistics.source_scans, 1,
                       "Folded affine source scans");
    checked_accumulate(statistics.source_rewinds, 1,
                       "Folded affine source rewinds");
    checked_accumulate(
        statistics.public_zero_positions,
        checked_u64(support.padded_wire_count - support.live_wire_count,
                    "Folded affine public-zero positions"),
        "Folded affine public-zero positions");

    std::size_t live = 0;
    while (auto record = reader.next()) {
        if (live >= support.live_wire_count ||
            record->padded_index != support.padded_index_of(live)) {
            throw std::runtime_error(
                "LaminateFolded affine active-record order mismatch");
        }
        const auto &stored = record_stored_value(*record);
        if (!stored_public_zero(stored)) {
            const bool encrypted = stored_is_encrypted(stored);
            if (encrypted) {
                checked_accumulate(statistics.source_ciphertexts_read, 1,
                                   "Folded affine source reads");
            }
            statistics.peak_live_source_ciphertexts = std::max(
                statistics.peak_live_source_ciphertexts,
                static_cast<std::size_t>(encrypted) +
                    resident_ciphertexts_held(reader));
            visit(record->padded_index, stored_value_ref(stored));
        }
        ++live;
    }
    if (live != support.live_wire_count ||
        reader.position() != reader.end()) {
        throw std::runtime_error(
            "LaminateFolded affine active reader ended early");
    }

    if constexpr (requires { reader.encoded_bytes_read(); }) {
        const std::uint64_t bytes_after = reader.encoded_bytes_read();
        const std::uint64_t records_after =
            serialized_records_read(reader);
        if (bytes_after < bytes_before || records_after < records_before ||
            records_after - records_before != checked_u64(live, "records")) {
            throw std::runtime_error(
                "LaminateFolded affine reader accounting mismatch");
        }
        const std::uint64_t logical = bytes_after - bytes_before;
        checked_accumulate(statistics.source_logical_bytes_read, logical,
                           "Folded affine source bytes");
        const std::uint64_t records = records_after - records_before;
        if (records > (std::numeric_limits<std::uint64_t>::max() - logical) /
                          sizeof(std::uint64_t)) {
            throw std::overflow_error(
                "Folded affine framed-byte accounting overflows");
        }
        checked_accumulate(
            statistics.source_framed_record_bytes_read,
            logical + records * sizeof(std::uint64_t),
            "Folded affine framed source bytes");
    }
}

} // namespace laminate::gkr::folded_detail::folded_affine_detail

#endif // LAMINATE_GKR_DETAIL_FOLDED_AFFINE_SOURCE_SCAN_HPP
