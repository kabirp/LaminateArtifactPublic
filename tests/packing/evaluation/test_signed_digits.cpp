/// @file test_signed_digits.cpp
/// @brief Exactness and rejection tests for balanced coefficient digits.

#include "test_helpers.hpp"

#include "laminate/packing/evaluation/signed_digits.hpp"

#include <cstdint>
#include <stdexcept>
#include <vector>

using namespace laminate;
using namespace laminate::packing;

namespace {

template <typename Function> bool rejects_invalid(Function function) {
    try {
        function();
        return false;
    } catch (const std::invalid_argument &) {
        return true;
    }
}

} // namespace

int main() {
    test::Runner runner("signed digits");

    runner.run("selected base 17 covers every centered field coefficient", [] {
        const BalancedRadix radix =
            make_minimal_balanced_radix(kBaseFieldOrder,
                                        kSelectedPackingRadixBase);
        CHECK(radix.digit_count == 4);
        CHECK(radix.maximum_absolute_digit() == 8);

        const std::int64_t radius =
            static_cast<std::int64_t>((kBaseFieldOrder - 1) / 2);
        for (std::int64_t value = -radius; value <= radius; ++value) {
            const auto digits = decompose_balanced_coefficient(value, radix);
            CHECK(digits.size() == 4);
            CHECK(recompose_balanced_coefficient(digits, radix) == value);
            for (const std::int64_t digit : digits) {
                CHECK(digit >= -8);
                CHECK(digit <= 8);
            }
        }
    });

    runner.run("canonical frontier keeps one base per useful digit count", [] {
        const auto frontier =
            canonical_balanced_radix_frontier(kBaseFieldOrder);
        const std::vector<std::uint64_t> expected_bases{
            65537, 257, 41, 17, 11, 7, 5, 3};
        const std::vector<std::size_t> expected_digits{
            1, 2, 3, 4, 5, 6, 7, 11};
        CHECK(frontier.size() == expected_bases.size());
        for (std::size_t index = 0; index < frontier.size(); ++index) {
            CHECK(frontier[index].base == expected_bases[index]);
            CHECK(frontier[index].digit_count == expected_digits[index]);
            frontier[index].validate();
        }
    });

    runner.run("coefficient masks split and recompose independently", [] {
        const BalancedRadix radix{
            .plaintext_modulus = kBaseFieldOrder,
            .base = 17,
            .digit_count = 4,
        };
        const SignedCoefficientMask mask{-32768, -289, -1, 0,
                                          1,      289,  32768};
        const auto digit_masks = decompose_coefficient_mask(mask, radix);
        CHECK(digit_masks.size() == radix.digit_count);
        for (std::size_t coefficient = 0; coefficient < mask.size();
             ++coefficient) {
            std::vector<std::int64_t> digits(radix.digit_count);
            for (std::size_t digit = 0; digit < radix.digit_count; ++digit) {
                digits[digit] = digit_masks[digit][coefficient];
            }
            CHECK(recompose_balanced_coefficient(digits, radix) ==
                  mask[coefficient]);
        }
    });

    runner.run("malformed radices and coefficients fail closed", [] {
        CHECK(rejects_invalid([] {
            (BalancedRadix{.plaintext_modulus = kBaseFieldOrder,
                           .base = 40,
                           .digit_count = 4})
                .validate();
        }));
        CHECK(rejects_invalid([] {
            (BalancedRadix{.plaintext_modulus = kBaseFieldOrder,
                           .base = 41,
                           .digit_count = 2})
                .validate();
        }));
        const BalancedRadix radix =
            make_minimal_balanced_radix(kBaseFieldOrder, 41);
        CHECK(rejects_invalid([&] {
            (void)decompose_balanced_coefficient(32769, radix);
        }));
        CHECK(rejects_invalid([&] {
            (void)recompose_balanced_coefficient(
                std::vector<std::int64_t>{21, 0, 0}, radix);
        }));
    });

    return runner.summary();
}
