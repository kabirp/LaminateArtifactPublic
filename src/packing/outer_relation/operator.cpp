/// @file operator.cpp
/// @brief Native-Q matrix construction for fixed signed-digit packing.

#include "laminate/packing/outer_relation/relation.hpp"

#include <algorithm>
#include <stdexcept>
#include <utility>

namespace laminate::packing {
namespace {

void validate_native_multiplier(std::span<const std::uint64_t> multiplier,
                                std::size_t ring_degree,
                                std::uint64_t native_modulus) {
    if (multiplier.size() != ring_degree) {
        throw std::invalid_argument(
            "native packing operator: NTT encoder returned the wrong degree");
    }
    if (std::any_of(multiplier.begin(), multiplier.end(),
                    [=](std::uint64_t value) {
                        return value >= native_modulus;
                    })) {
        throw std::invalid_argument(
            "native packing operator: NTT encoder returned a noncanonical "
            "residue");
    }
}

std::vector<SignedCoefficientMask> decompose_position_mask(
    const PackingLinearOperator::AlignedCiphertext &contribution,
    std::size_t slot_count,
    const PlaintextCoefficientEncoder &encode_centered_coefficients,
    const BalancedRadix &radix) {
    SignedCoefficientMask centered = encode_centered_coefficients(
        contribution.position_mask(slot_count));
    if (centered.size() != slot_count) {
        throw std::invalid_argument(
            "native packing operator: coefficient encoder returned the "
            "wrong degree");
    }
    return decompose_coefficient_mask(centered, radix);
}

NativePackingContribution make_native_contribution(
    std::size_t aligned_ciphertext,
    std::span<const std::int64_t> digit_coefficients,
    const NativePlaintextNttEncoder &encode_native_ntt,
    std::size_t ring_degree, std::uint64_t native_modulus) {
    std::vector<std::uint64_t> multiplier =
        encode_native_ntt(digit_coefficients);
    validate_native_multiplier(multiplier, ring_degree, native_modulus);
    return NativePackingContribution{
        .aligned_ciphertext = aligned_ciphertext,
        .multiplier_ntt_coordinates = std::move(multiplier),
    };
}

} // namespace

NativePackingOperator make_native_signed_digit_packing_operator(
    const PackingLinearOperator &packing_operator,
    const PlaintextCoefficientEncoder &encode_centered_coefficients,
    const NativePlaintextNttEncoder &encode_native_ntt,
    std::uint64_t native_modulus, const BalancedRadix &radix) {
    packing_operator.validate();
    radix.validate();
    if (!encode_centered_coefficients || !encode_native_ntt ||
        native_modulus < 3) {
        throw std::invalid_argument(
            "native packing operator: missing encoder or invalid modulus");
    }

    NativePackingOperator result{
        .native_modulus = native_modulus,
        .ring_degree = packing_operator.slot_count,
        .aligned_ciphertexts = packing_operator.aligned_ciphertext_count,
        .logical_outputs = packing_operator.rows.size(),
        .digit_count = radix.digit_count,
    };
    result.rows.resize(result.logical_outputs * result.digit_count);
    for (std::size_t output = 0; output < result.logical_outputs; ++output) {
        for (std::size_t digit = 0; digit < result.digit_count; ++digit) {
            NativePackingRow &row =
                result.rows[output * result.digit_count + digit];
            row.logical_output = output;
            row.digit = digit;
        }
    }

    for (const PackingLinearOperator::OutputRow &logical_row :
         packing_operator.rows) {
        for (const auto &contribution : logical_row.contributions) {
            const std::vector<SignedCoefficientMask> digit_masks =
                decompose_position_mask(
                    contribution, packing_operator.slot_count,
                    encode_centered_coefficients, radix);
            for (std::size_t digit = 0; digit < result.digit_count; ++digit) {
                result.rows[logical_row.output_index * result.digit_count +
                            digit]
                    .contributions.push_back(make_native_contribution(
                        contribution.aligned_index, digit_masks[digit],
                        encode_native_ntt, result.ring_degree,
                        result.native_modulus));
            }
        }
    }
    for (NativePackingRow &row : result.rows) {
        std::sort(row.contributions.begin(), row.contributions.end(),
                  [](const NativePackingContribution &left,
                     const NativePackingContribution &right) {
                      return left.aligned_ciphertext <
                             right.aligned_ciphertext;
                  });
    }
    return result;
}

} // namespace laminate::packing
