#ifndef LAMINATE_BASEFOLD_COMMON_HPP
#define LAMINATE_BASEFOLD_COMMON_HPP

/// @file common.hpp
/// @brief Field, encoding, and MLE helpers shared by the BaseFold phases.

#include "laminate/field/fp.hpp"
#include "laminate/field/fpk.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace laminate::basefold {

/// Return log2(n), rejecting zero and non-powers of two.
std::size_t log2_exact(std::size_t n);

/// Compute the inverse-rate codeword length without allowing size overflow.
std::size_t codeword_length(std::size_t message_length,
                            std::size_t log_rate);

/// Canonical concatenation used for Merkle leaves and transcript messages.
std::vector<std::uint8_t> serialize_values(std::span<const Fp> values);
std::vector<std::uint8_t> serialize_values(std::span<const Fpk> values);

/// Exponentiation in the base field.
Fp field_power(Fp base, std::size_t exponent);

/// Equality polynomial in BaseFold's LSB-first variable order.
Fpk equality_evaluation(std::size_t Boolean_index,
                        std::span<const Fpk> point);

/// Materialize every equality-polynomial value in one linear pass. The point
/// and resulting Boolean indices use BaseFold's LSB-first variable order.
std::vector<Fpk> equality_evaluations(std::span<const Fpk> point);

/// Evaluate a materialized multilinear table at an LSB-first point.
Fpk evaluate_multilinear(std::span<const Fpk> evaluations,
                         std::span<const Fpk> point);

} // namespace laminate::basefold

#endif // LAMINATE_BASEFOLD_COMMON_HPP
