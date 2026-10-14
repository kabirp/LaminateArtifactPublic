#ifndef LAMINATE_PACKING_EVALUATION_SIGNED_DIGITS_HPP
#define LAMINATE_PACKING_EVALUATION_SIGNED_DIGITS_HPP

/// @file signed_digits.hpp
/// @brief Exact balanced-radix digits for coefficient-small packing masks.

#include "laminate/packing/evaluation/well_formedness.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace laminate::packing {

/// Public representation used to split one plaintext polynomial into small
/// signed coefficient polynomials.
///
/// `base` is odd, each digit lies in `[-(base-1)/2, (base-1)/2]`, and
/// `base^digit_count >= plaintext_modulus`. The latter condition guarantees
/// that every centered plaintext coefficient has a representation.
struct BalancedRadix {
    std::uint64_t plaintext_modulus = kBaseFieldOrder;
    std::uint64_t base = kSelectedPackingRadixBase;
    std::size_t digit_count = 4;

    std::int64_t maximum_absolute_digit() const;
    void validate() const;

    bool operator==(const BalancedRadix &) const = default;
};

/// Choose the fewest digits for one odd balanced base.
BalancedRadix make_minimal_balanced_radix(std::uint64_t plaintext_modulus,
                                          std::uint64_t base);

/// Return the canonical digit-count frontier, shortest representation first.
///
/// For each attainable digit count, this retains the smallest odd base that
/// covers the plaintext field in that many digits. Larger bases with the same
/// digit count have a weakly larger worst-case digit and are omitted. For
/// `F_65537` the bases are 65537, 257, 41, 17, 11, 7, 5, and 3.
std::vector<BalancedRadix> canonical_balanced_radix_frontier(
    std::uint64_t plaintext_modulus);

/// Decompose one centered representative exactly, least-significant digit
/// first. The value must lie in the centered plaintext interval.
std::vector<std::int64_t> decompose_balanced_coefficient(
    std::int64_t centered_coefficient, const BalancedRadix &radix);

/// Recompose an exact signed integer. This is primarily a validation and
/// client-side reconstruction helper; homomorphic recombination is avoided.
std::int64_t recompose_balanced_coefficient(
    std::span<const std::int64_t> digits, const BalancedRadix &radix);

/// Split one degree-N centered coefficient mask into `digit_count` masks.
std::vector<SignedCoefficientMask> decompose_coefficient_mask(
    std::span<const std::int64_t> centered_coefficients,
    const BalancedRadix &radix);

} // namespace laminate::packing

#endif // LAMINATE_PACKING_EVALUATION_SIGNED_DIGITS_HPP
