/// @file signed_digits.cpp
/// @brief Exact balanced-radix decomposition for packing masks.

#include "laminate/packing/evaluation/signed_digits.hpp"

#include <algorithm>
#include <limits>
#include <optional>
#include <stdexcept>

namespace laminate::packing {
namespace {

std::uint64_t centered_radius(std::uint64_t modulus) {
    return (modulus - 1) / 2;
}

bool radix_covers_modulus(const BalancedRadix &radix) {
    std::uint64_t capacity = 1;
    for (std::size_t digit = 0; digit < radix.digit_count; ++digit) {
        if (capacity >= radix.plaintext_modulus) {
            return true;
        }
        if (capacity >
            (radix.plaintext_modulus - 1) / radix.base) {
            capacity = radix.plaintext_modulus;
        } else {
            capacity *= radix.base;
        }
    }
    return capacity >= radix.plaintext_modulus;
}

std::int64_t checked_centered_value(std::int64_t value,
                                    const BalancedRadix &radix) {
    const std::uint64_t magnitude =
        value >= 0 ? static_cast<std::uint64_t>(value)
                   : std::uint64_t{0} - static_cast<std::uint64_t>(value);
    if (magnitude > centered_radius(radix.plaintext_modulus)) {
        throw std::invalid_argument(
            "balanced radix: coefficient is not a centered representative");
    }
    return value;
}

std::vector<std::int64_t> decompose_validated(
    std::int64_t centered_coefficient, const BalancedRadix &radix) {
    std::int64_t quotient =
        checked_centered_value(centered_coefficient, radix);
    const std::int64_t base = static_cast<std::int64_t>(radix.base);
    const std::int64_t maximum_digit = (base - 1) / 2;

    std::vector<std::int64_t> result(radix.digit_count);
    for (std::size_t digit = 0; digit < radix.digit_count; ++digit) {
        std::int64_t remainder = quotient % base;
        if (remainder > maximum_digit) {
            remainder -= base;
        } else if (remainder < -maximum_digit) {
            remainder += base;
        }
        result[digit] = remainder;
        quotient = (quotient - remainder) / base;
    }
    if (quotient != 0) {
        throw std::logic_error(
            "balanced radix: validated representation did not terminate");
    }
    return result;
}

} // namespace

std::int64_t BalancedRadix::maximum_absolute_digit() const {
    validate();
    return static_cast<std::int64_t>((base - 1) / 2);
}

void BalancedRadix::validate() const {
    if (plaintext_modulus < 3 || plaintext_modulus % 2 == 0 || base < 3 ||
        base % 2 == 0 ||
        base > static_cast<std::uint64_t>(
                   std::numeric_limits<std::int64_t>::max()) ||
        digit_count == 0 || !radix_covers_modulus(*this)) {
        throw std::invalid_argument(
            "balanced radix: invalid modulus, base, or digit count");
    }
}

BalancedRadix make_minimal_balanced_radix(std::uint64_t plaintext_modulus,
                                          std::uint64_t base) {
    if (plaintext_modulus < 3 || plaintext_modulus % 2 == 0 || base < 3 ||
        base % 2 == 0 ||
        base > static_cast<std::uint64_t>(
                   std::numeric_limits<std::int64_t>::max())) {
        throw std::invalid_argument(
            "balanced radix: invalid modulus or base");
    }
    BalancedRadix result{
        .plaintext_modulus = plaintext_modulus,
        .base = base,
        .digit_count = 1,
    };
    while (!radix_covers_modulus(result)) {
        if (result.digit_count ==
            std::numeric_limits<std::size_t>::max()) {
            throw std::overflow_error(
                "balanced radix: digit count overflow");
        }
        ++result.digit_count;
    }
    result.validate();
    return result;
}

std::vector<BalancedRadix> canonical_balanced_radix_frontier(
    std::uint64_t plaintext_modulus) {
    if (plaintext_modulus < 3 || plaintext_modulus % 2 == 0) {
        throw std::invalid_argument(
            "balanced radix frontier requires an odd modulus >= 3");
    }

    // Iterating the at-most-(t-1)/2 odd bases is negligible for the intended
    // small plaintext field and avoids fragile floating-point integer roots.
    std::vector<std::optional<BalancedRadix>> smallest_by_digit_count;
    for (std::uint64_t base = 3; base <= plaintext_modulus; base += 2) {
        const BalancedRadix radix =
            make_minimal_balanced_radix(plaintext_modulus, base);
        if (smallest_by_digit_count.size() <= radix.digit_count) {
            smallest_by_digit_count.resize(radix.digit_count + 1);
        }
        if (!smallest_by_digit_count[radix.digit_count]) {
            smallest_by_digit_count[radix.digit_count] = radix;
        }
    }

    std::vector<BalancedRadix> result;
    for (auto &radix : smallest_by_digit_count) {
        if (radix) {
            result.push_back(*radix);
        }
    }
    std::sort(result.begin(), result.end(),
              [](const BalancedRadix &left, const BalancedRadix &right) {
                  return left.digit_count < right.digit_count;
              });
    return result;
}

std::vector<std::int64_t> decompose_balanced_coefficient(
    std::int64_t centered_coefficient, const BalancedRadix &radix) {
    radix.validate();
    return decompose_validated(centered_coefficient, radix);
}

std::int64_t recompose_balanced_coefficient(
    std::span<const std::int64_t> digits, const BalancedRadix &radix) {
    radix.validate();
    if (digits.size() != radix.digit_count) {
        throw std::invalid_argument(
            "balanced radix: wrong number of digits");
    }

    const std::int64_t maximum_digit =
        static_cast<std::int64_t>((radix.base - 1) / 2);
    __int128 result = 0;
    __int128 place = 1;
    for (const std::int64_t digit : digits) {
        if (digit < -maximum_digit || digit > maximum_digit) {
            throw std::invalid_argument(
                "balanced radix: digit is out of range");
        }
        result += place * digit;
        place *= static_cast<__int128>(radix.base);
    }
    if (result < std::numeric_limits<std::int64_t>::min() ||
        result > std::numeric_limits<std::int64_t>::max()) {
        throw std::overflow_error(
            "balanced radix: recomposed coefficient overflows i64");
    }
    return static_cast<std::int64_t>(result);
}

std::vector<SignedCoefficientMask> decompose_coefficient_mask(
    std::span<const std::int64_t> centered_coefficients,
    const BalancedRadix &radix) {
    radix.validate();
    if (centered_coefficients.empty()) {
        throw std::invalid_argument(
            "balanced radix: coefficient mask is empty");
    }

    std::vector<SignedCoefficientMask> result(
        radix.digit_count,
        SignedCoefficientMask(centered_coefficients.size()));
    for (std::size_t coefficient = 0;
         coefficient < centered_coefficients.size(); ++coefficient) {
        const std::vector<std::int64_t> digits =
            decompose_validated(centered_coefficients[coefficient], radix);
        for (std::size_t digit = 0; digit < radix.digit_count; ++digit) {
            result[digit][coefficient] = digits[digit];
        }
    }
    return result;
}

} // namespace laminate::packing
