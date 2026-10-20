#ifndef LAMINATE_GKR_DETAIL_LANED_MULTIPLICATION_REFERENCE_SOURCE_HPP
#define LAMINATE_GKR_DETAIL_LANED_MULTIPLICATION_REFERENCE_SOURCE_HPP

/// @file source.hpp
/// @brief Deduplicated packed source owned by resident Laned multiplication.

#include "laminate/fhe/value.hpp"

#include <algorithm>
#include <cstddef>
#include <optional>
#include <span>
#include <stdexcept>
#include <vector>

namespace laminate::gkr::laned_detail::reference_multiplication_detail {

/// Logical left/right pair table over distinct packed source values.
///
/// A one-chunk value borrows its compact trace record. A multi-chunk value
/// owns the single packed result constructed for its public source signature.
/// Repeated operands therefore repeat only small public indices. Structural
/// padding is public zero and never becomes a stored ciphertext.
template <fhe::FheBackend Backend> struct PackedSource {
    struct UniqueValue {
        std::optional<std::size_t> borrowed_stored_ordinal;
        std::optional<fhe::FheValue<Backend>> owned;
    };

    const std::vector<fhe::FheValue<Backend>> *stored_source = nullptr;
    std::vector<UniqueValue> unique;
    std::vector<std::size_t> left;
    std::vector<std::size_t> right;
    /// Canonical live pair indices ordered by bit-reversed physical position.
    std::vector<std::size_t> physical_order;
    std::size_t pair_domain_size = 0;

    const fhe::FheValue<Backend> &value(std::size_t unique_index) const {
        const UniqueValue &entry = unique.at(unique_index);
        if (entry.borrowed_stored_ordinal) {
            return stored_source->at(*entry.borrowed_stored_ordinal);
        }
        if (!entry.owned) {
            throw std::logic_error(
                "LaminateLaned packed source value is empty");
        }
        return *entry.owned;
    }

    std::size_t pair_count() const { return pair_domain_size; }
    std::size_t live_pair_count() const { return left.size(); }
    std::span<const std::size_t> physical_pair_order() const {
        return physical_order;
    }
    std::size_t first_round_scan_count(std::size_t suffix_count) const {
        return std::min(suffix_count, live_pair_count());
    }
    const fhe::FheValue<Backend> &left_value(std::size_t pair) const {
        return value(left.at(pair));
    }
    const fhe::FheValue<Backend> &right_value(std::size_t pair) const {
        return value(right.at(pair));
    }
    const typename Backend::Ciphertext *level_reference() const {
        for (std::size_t unique_index = 0;
             unique_index < unique.size(); ++unique_index) {
            const auto &packed_value = value(unique_index);
            if (packed_value.is_encrypted()) {
                return &packed_value.ciphertext();
            }
        }
        return nullptr;
    }
};

} // namespace laminate::gkr::laned_detail::reference_multiplication_detail

#endif // LAMINATE_GKR_DETAIL_LANED_MULTIPLICATION_REFERENCE_SOURCE_HPP
