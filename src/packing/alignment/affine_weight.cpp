/// @file affine_weight.cpp
/// @brief Homogeneous bit-weight sums over two affine integer sequences.

#include "laminate/packing/alignment/affine_weight.hpp"

#include <algorithm>
#include <bit>
#include <compare>
#include <limits>
#include <map>
#include <stdexcept>
#include <utility>

namespace laminate::packing {
namespace {

struct CarryState {
    std::uint64_t h = 0;
    std::uint64_t w = 0;
    bool borrow = false;

    auto operator<=>(const CarryState &) const = default;
};

void validate_endpoint(const AffineWeightDomain &domain,
                       std::uint64_t last_index) {
    const std::uint64_t maximum =
        std::numeric_limits<std::uint64_t>::max();
    if (last_index != 0 &&
        domain.stride > (maximum - domain.offset) / last_index) {
        throw std::overflow_error("affine sequence endpoint overflows u64");
    }
    const std::uint64_t endpoint =
        domain.offset + domain.stride * last_index;
    const std::size_t bits = domain.msb_bit_weights.size();
    if (bits < std::numeric_limits<std::uint64_t>::digits &&
        endpoint >= (std::uint64_t{1} << bits)) {
        throw std::out_of_range(
            "affine sequence endpoint exceeds its bit domain");
    }
}

bool add_stride(std::uint64_t carry, std::uint64_t stride,
                bool input_bit, std::uint64_t &sum) {
    if (!input_bit) {
        sum = carry;
        return true;
    }
    if (carry > std::numeric_limits<std::uint64_t>::max() - stride) {
        return false;
    }
    sum = carry + stride;
    return true;
}

bool apply_output_weight(const AffineWeightDomain &domain,
                         std::size_t lsb, bool output_bit,
                         Fq2 &weight) {
    if (lsb >= domain.msb_bit_weights.size()) {
        return !output_bit;
    }
    const std::size_t msb =
        domain.msb_bit_weights.size() - 1U - lsb;
    weight *= domain.msb_bit_weights[msb][output_bit ? 1U : 0U];
    return true;
}

void accumulate(std::map<CarryState, Fq2> &states,
                const CarryState &key, const Fq2 &value) {
    if (value.is_zero()) {
        return;
    }
    const auto [position, inserted] =
        states.try_emplace(key, Fq2::zero());
    (void)inserted;
    position->second += value;
}

Fq2 affine_prefix_weight_sum(std::uint64_t exclusive_end,
                            const AffineWeightDomain &h,
                            const AffineWeightDomain &w) {
    if (exclusive_end == 0) {
        return Fq2::zero();
    }

    // A subtraction borrow after all input bits is one exactly when
    // `i - exclusive_end` is negative. Carries simultaneously expose the
    // bits of offset + stride*i from least to most significant.
    const std::size_t input_bits = std::bit_width(exclusive_end);
    const std::size_t steps = std::max(
        {input_bits, h.msb_bit_weights.size(),
         w.msb_bit_weights.size()});
    std::map<CarryState, Fq2> states;
    states.emplace(CarryState{h.offset, w.offset, false}, Fq2::one());

    for (std::size_t lsb = 0; lsb < steps; ++lsb) {
        std::map<CarryState, Fq2> next;
        const bool bound_bit =
            lsb < std::numeric_limits<std::uint64_t>::digits &&
            ((exclusive_end >> lsb) & 1U) != 0;
        const unsigned input_choices = lsb < input_bits ? 2U : 1U;

        for (const auto &[state, state_weight] : states) {
            for (unsigned input = 0; input < input_choices; ++input) {
                const bool input_bit = input != 0;
                std::uint64_t h_sum = 0;
                std::uint64_t w_sum = 0;
                if (!add_stride(state.h, h.stride, input_bit, h_sum) ||
                    !add_stride(state.w, w.stride, input_bit, w_sum)) {
                    // Such a path represents an out-of-prefix candidate whose
                    // affine image is larger than uint64_t. Every selected
                    // path was checked by validate_endpoint.
                    continue;
                }

                const bool h_bit = (h_sum & 1U) != 0;
                const bool w_bit = (w_sum & 1U) != 0;
                Fq2 weight = state_weight;
                if (!apply_output_weight(h, lsb, h_bit, weight) ||
                    !apply_output_weight(w, lsb, w_bit, weight)) {
                    continue;
                }

                const unsigned subtrahend =
                    static_cast<unsigned>(bound_bit) +
                    static_cast<unsigned>(state.borrow);
                const bool next_borrow = input < subtrahend;
                accumulate(next,
                           CarryState{h_sum >> 1U, w_sum >> 1U,
                                      next_borrow},
                           weight);
            }
        }
        states = std::move(next);
    }

    const auto selected = states.find(CarryState{0, 0, true});
    return selected == states.end() ? Fq2::zero() : selected->second;
}

} // namespace

Fq2 affine_range_weight_sum(std::uint64_t begin, std::uint64_t end,
                           const AffineWeightDomain &h,
                           const AffineWeightDomain &w) {
    if (begin > end) {
        throw std::invalid_argument("affine weight interval is reversed");
    }
    if (begin == end) {
        return Fq2::zero();
    }
    validate_endpoint(h, end - 1U);
    validate_endpoint(w, end - 1U);
    return affine_prefix_weight_sum(end, h, w) -
           affine_prefix_weight_sum(begin, h, w);
}

} // namespace laminate::packing
