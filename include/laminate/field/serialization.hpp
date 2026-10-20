#ifndef LAMINATE_FIELD_SERIALIZATION_HPP
#define LAMINATE_FIELD_SERIALIZATION_HPP

/// @file serialization.hpp
/// @brief Canonical compact encodings for Laminate field elements.
///
/// Fp values are below 2^17 and therefore use exactly three little-endian
/// bytes. Fpk concatenates its eight Fp coefficients in increasing degree
/// order. Fq uses eight little-endian bytes for its ordinary residue (never
/// its internal Montgomery word), and Fq2 concatenates its constant and
/// linear coefficients. Decoding rejects noncanonical values and incorrect
/// lengths rather than reducing them modulo the field order.

#include "laminate/field/fp.hpp"
#include "laminate/field/fpk.hpp"
#include "laminate/field/fq.hpp"
#include "laminate/field/fq2.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace laminate {

inline constexpr std::size_t kSerializedFpBytes = 3;
inline constexpr std::size_t kSerializedFpkBytes =
    kExtensionDegree * kSerializedFpBytes;
inline constexpr std::size_t kSerializedFqBytes = 8;
inline constexpr std::size_t kSerializedFq2Bytes = 2 * kSerializedFqBytes;

using SerializedFp = std::array<std::uint8_t, kSerializedFpBytes>;
using SerializedFpk = std::array<std::uint8_t, kSerializedFpkBytes>;
using SerializedFq = std::array<std::uint8_t, kSerializedFqBytes>;
using SerializedFq2 = std::array<std::uint8_t, kSerializedFq2Bytes>;

SerializedFp serialize(const Fp &value);
SerializedFpk serialize(const Fpk &value);
SerializedFq serialize(const Fq &value);
SerializedFq2 serialize(const Fq2 &value);
Fp deserialize_fp(std::span<const std::uint8_t> bytes);
Fpk deserialize_fpk(std::span<const std::uint8_t> bytes);
Fq deserialize_fq(std::span<const std::uint8_t> bytes);
Fq2 deserialize_fq2(std::span<const std::uint8_t> bytes);

} // namespace laminate

#endif // LAMINATE_FIELD_SERIALIZATION_HPP
