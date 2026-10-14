#ifndef LAMINATE_PACKING_ALIGNMENT_AFFINE_WEIGHT_HPP
#define LAMINATE_PACKING_ALIGNMENT_AFFINE_WEIGHT_HPP

/// @file affine_weight.hpp
/// @brief Homogeneous bit-weight sums over two affine integer sequences.

#include "laminate/field/fq2.hpp"

#include <array>
#include <cstdint>
#include <span>

namespace laminate::packing {

/// Weights for the zero and one branch of one binary digit, respectively.
using AffineBitWeightPair = std::array<Fq2, 2>;

/// One unsigned affine sequence and the bit weights applied to its values.
///
/// `msb_bit_weights` describes a fixed-width binary domain in most-significant
/// bit order. The value at index `i` is `offset + stride * i`.
struct AffineWeightDomain {
    std::uint64_t offset = 0;
    std::uint64_t stride = 0;
    std::span<const AffineBitWeightPair> msb_bit_weights;
};

/// Sum the homogeneous bit weights of two affine sequences over `[begin,end)`.
///
/// For `h(i) = h.offset + h.stride * i` and
/// `w(i) = w.offset + w.stride * i`, this returns
///
///   sum_i product_b h.msb_bit_weights[b][h(i)_b]
///               * product_b w.msb_bit_weights[b][w(i)_b].
///
/// The supplied branch weights are used verbatim: they need not sum to one,
/// and the implementation performs no normalization or division. It throws
/// `std::invalid_argument` for a reversed interval, `std::overflow_error` if
/// either affine endpoint overflows `uint64_t`, and `std::out_of_range` if an
/// endpoint does not fit its stated binary domain.
Fq2 affine_range_weight_sum(std::uint64_t begin, std::uint64_t end,
                           const AffineWeightDomain &h,
                           const AffineWeightDomain &w);

} // namespace laminate::packing

#endif // LAMINATE_PACKING_ALIGNMENT_AFFINE_WEIGHT_HPP
