/// @file test_affine_weight.cpp
/// @brief Tests for homogeneous affine-range bit-weight sums.

#include "test_helpers.hpp"

#include "laminate/packing/alignment/affine_weight.hpp"

#include <array>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <vector>

using namespace laminate;
using namespace laminate::packing;

namespace {

std::vector<AffineBitWeightPair> weights(std::size_t bits,
                                        std::uint64_t seed) {
    std::vector<AffineBitWeightPair> result;
    result.reserve(bits);
    for (std::size_t bit = 0; bit < bits; ++bit) {
        result.push_back({
            Fq2{{Fq(seed + 7 * bit + 1), Fq(seed + 3 * bit + 2)}},
            Fq2{{Fq(seed + 11 * bit + 4), Fq(seed + 5 * bit + 6)}}});
    }
    return result;
}

Fq2 weight_at(std::uint64_t value,
              const std::vector<AffineBitWeightPair> &bit_weights) {
    Fq2 result = Fq2::one();
    for (std::size_t bit = 0; bit < bit_weights.size(); ++bit) {
        const std::size_t shift = bit_weights.size() - 1U - bit;
        const bool one = shift < 64U && ((value >> shift) & 1U) != 0;
        result *= bit_weights[bit][one ? 1U : 0U];
    }
    return result;
}

Fq2 brute_force(std::uint64_t begin, std::uint64_t end,
                std::uint64_t h_offset, std::uint64_t h_stride,
                const std::vector<AffineBitWeightPair> &h_weights,
                std::uint64_t w_offset, std::uint64_t w_stride,
                const std::vector<AffineBitWeightPair> &w_weights) {
    Fq2 result = Fq2::zero();
    for (std::uint64_t index = begin; index < end; ++index) {
        result += weight_at(h_offset + h_stride * index, h_weights) *
                  weight_at(w_offset + w_stride * index, w_weights);
    }
    return result;
}

void check_case(std::uint64_t begin, std::uint64_t end,
                std::uint64_t h_offset, std::uint64_t h_stride,
                const std::vector<AffineBitWeightPair> &h_weights,
                std::uint64_t w_offset, std::uint64_t w_stride,
                const std::vector<AffineBitWeightPair> &w_weights) {
    const Fq2 expected = brute_force(
        begin, end, h_offset, h_stride, h_weights, w_offset, w_stride,
        w_weights);
    const Fq2 actual = affine_range_weight_sum(
        begin, end,
        AffineWeightDomain{h_offset, h_stride, h_weights},
        AffineWeightDomain{w_offset, w_stride, w_weights});
    CHECK(actual == expected);
}

template <typename Exception, typename Action>
bool throws(Action action) {
    try {
        action();
    } catch (const Exception &) {
        return true;
    }
    return false;
}

} // namespace

int main() {
    test::Runner runner("test_affine_weight");

    runner.run("affine strides and offsets agree with brute force", [] {
        const auto h = weights(13, 19);
        const auto w = weights(12, 71);
        constexpr std::array<std::uint64_t, 6> strides{
            0, 1, 2, 3, 7, 11};
        for (const std::uint64_t h_stride : strides) {
            for (const std::uint64_t w_stride : strides) {
                check_case(4, 49, 5, h_stride, h,
                           11, w_stride, w);
            }
        }
        check_case(0, 37, 3, 1, h, 7, 2, w);
        check_case(13, 58, 101, 6, h, 203, 11, w);
    });

    runner.run("empty and singleton intervals agree with brute force", [] {
        const auto h = weights(9, 101);
        const auto w = weights(10, 211);
        check_case(17, 17, 6, 11, h, 8, 3, w);
        check_case(17, 18, 6, 11, h, 8, 3, w);

        const std::vector<AffineBitWeightPair> empty;
        check_case(0, 1, 0, 0, empty, 0, 0, empty);
    });

    runner.run("high offsets and long bit domains agree with brute force", [] {
        const auto h = weights(72, 307);
        const auto w = weights(69, 401);
        check_case(31, 64, (std::uint64_t{1} << 61U) + 29U, 11,
                   h, (std::uint64_t{1} << 60U) + 17U, 9, w);
    });

    runner.run("alpha and minus-alpha pairs stay homogeneous", [] {
        std::vector<AffineBitWeightPair> h;
        std::vector<AffineBitWeightPair> w;
        const Fq2 x = Fq2::from_base(Fq(2));
        const Fq2 z = Fq2::from_base(Fq(3).inverse());
        const Fq2 h_zero = (Fq2::one() - z) * (Fq2::one() - x);
        const Fq2 h_one = z * x;
        CHECK(!h_one.is_zero());
        CHECK(h_zero == -h_one);
        for (std::size_t bit = 0; bit < 11; ++bit) {
            const Fq2 beta{
                {Fq(31 + 3 * bit), Fq(41 + 11 * bit)}};
            h.push_back({h_zero, h_one});
            w.push_back({beta, -beta});
        }
        check_case(3, 97, 19, 11, h, 7, 9, w);
    });

    runner.run("invalid intervals and affine domains fail explicitly", [] {
        const auto four_bits = weights(4, 503);
        CHECK(throws<std::invalid_argument>([&] {
            (void)affine_range_weight_sum(
                8, 7, AffineWeightDomain{0, 1, four_bits},
                AffineWeightDomain{0, 1, four_bits});
        }));
        CHECK(throws<std::out_of_range>([&] {
            (void)affine_range_weight_sum(
                0, 3, AffineWeightDomain{14, 1, four_bits},
                AffineWeightDomain{0, 1, four_bits});
        }));
        CHECK(throws<std::overflow_error>([&] {
            (void)affine_range_weight_sum(
                0, 2,
                AffineWeightDomain{
                    std::numeric_limits<std::uint64_t>::max() - 1U,
                    2, weights(64, 607)},
                AffineWeightDomain{0, 0, four_bits});
        }));
    });

    return runner.summary();
}
