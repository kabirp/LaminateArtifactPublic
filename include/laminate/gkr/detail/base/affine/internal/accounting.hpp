#ifndef LAMINATE_GKR_DETAIL_BASE_AFFINE_INTERNAL_ACCOUNTING_HPP
#define LAMINATE_GKR_DETAIL_BASE_AFFINE_INTERNAL_ACCOUNTING_HPP

/// @file accounting.hpp
/// @brief Overflow-checked counters for Base affine scan telemetry.

#include "laminate/gkr/detail/base/affine/diagnostics/statistics.hpp"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>

namespace laminate::gkr::base_detail::base_affine_detail {

inline void checked_accumulate(std::uint64_t &destination,
                               std::uint64_t value,
                               const char *description) {
    if (value > std::numeric_limits<std::uint64_t>::max() - destination) {
        throw std::overflow_error(std::string(description) +
                                  " overflows u64");
    }
    destination += value;
}

inline std::uint64_t checked_u64(std::size_t value,
                                 const char *description) {
    if constexpr (sizeof(std::size_t) > sizeof(std::uint64_t)) {
        if (value > std::numeric_limits<std::uint64_t>::max()) {
            throw std::overflow_error(std::string(description) +
                                      " does not fit u64");
        }
    }
    return static_cast<std::uint64_t>(value);
}

} // namespace laminate::gkr::base_detail::base_affine_detail

#endif // LAMINATE_GKR_DETAIL_BASE_AFFINE_INTERNAL_ACCOUNTING_HPP
