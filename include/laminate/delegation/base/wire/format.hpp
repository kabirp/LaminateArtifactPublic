#ifndef LAMINATE_DELEGATION_BASE_WIRE_FORMAT_HPP
#define LAMINATE_DELEGATION_BASE_WIRE_FORMAT_HPP

/// @file wire/format.hpp
/// @brief Domain labels and fixed framing sizes for Base process messages.

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace laminate::delegation {

inline constexpr std::string_view kBaseDelegationWireDomain =
    "LaminateImpl/BaseDelegationWire";
inline constexpr std::uint8_t kBaseDelegationWireVersion = 4;
inline constexpr std::size_t kBaseDelegationWireHeaderBytes =
    kBaseDelegationWireDomain.size() + 1U + 1U + 2U + 8U;

namespace base_wire_detail {

inline constexpr std::string_view kBaseProofTransportDomain =
    "LaminateImpl/BaseProofTransport/v4";

} // namespace base_wire_detail
} // namespace laminate::delegation

#endif // LAMINATE_DELEGATION_BASE_WIRE_FORMAT_HPP
