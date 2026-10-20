/// @file test_operator_seal.cpp
/// @brief Exact Microsoft SEAL BatchEncoder mask-coefficient audit.

#include "test_helpers.hpp"

#include "laminate/fhe/seal_backend.hpp"
#include "laminate/packing/analysis/operator.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <vector>

using namespace laminate;
using namespace laminate::fhe;
using namespace laminate::packing;

namespace {

constexpr std::size_t kSlots = 1024;

SealBackend::Contexts make_contexts() {
    return SealBackend::create(SealParameters{
        .poly_modulus_degree = kSlots,
        .fresh_rns_limbs = 3,
        .bits_per_data_prime = 40,
        .special_prime_bits = 40,
        .security_level = seal::sec_level_type::none,
    });
}

SignedCoefficientMask encode_mask(const SealBackend::EvalContext &eval,
                                  const SlotVector &mask) {
    return SealBackend::encode_centered_plaintext_coefficients(eval, mask);
}

} // namespace

int main() {
    test::Runner runner("test_packing_operator_seal");
    const SealBackend::Contexts contexts = make_contexts();

    runner.run("centered lift is the exact BatchEncoder polynomial", [&] {
        CHECK(SealBackend::lowest_coefficient_modulus(contexts.eval) >
              kBaseFieldOrder);
        const SignedCoefficientMask zero = encode_mask(
            contexts.eval, SlotVector(kSlots, Fp::zero()));
        CHECK(zero.size() == kSlots);
        CHECK(std::all_of(zero.begin(), zero.end(),
                          [](std::int64_t value) { return value == 0; }));

        const SignedCoefficientMask identity = encode_mask(
            contexts.eval, SlotVector(kSlots, Fp::one()));
        CHECK(identity.front() == 1);
        CHECK(std::all_of(identity.begin() + 1, identity.end(),
                          [](std::int64_t value) { return value == 0; }));

        SlotVector sparse(kSlots, Fp::zero());
        std::fill(sparse.begin(), sparse.begin() + 16, Fp::one());
        const SignedCoefficientMask first = encode_mask(contexts.eval, sparse);
        const SignedCoefficientMask second = encode_mask(contexts.eval, sparse);
        CHECK(first == second);
        CHECK(std::count_if(first.begin(), first.end(), [](std::int64_t value) {
                  return value != 0;
              }) > 16);
        CHECK(std::any_of(first.begin(), first.end(), [](std::int64_t value) {
            return value > 1 || value < -1;
        }));
    });

    runner.run("operator weights use exact SEAL mask coefficients", [&] {
        const PackingLinearOperator packing_operator =
            make_packing_linear_operator(make_prefix_packing_layout(
                kSlots, std::vector<std::size_t>{16, 16, 16, 16}));
        const PackingOperatorWeightAnalysis analysis =
            analyze_packing_operator_weights(
                packing_operator, [&](const SlotVector &mask) {
                    return encode_mask(contexts.eval, mask);
                });

        CHECK(analysis.ring_degree == kSlots);
        CHECK(analysis.source_ciphertext_count == 4);
        CHECK(analysis.aligned_ciphertext_count == 4);
        CHECK(analysis.rows.size() == 1);
        CHECK(analysis.maximum_row_weight_upper > kSlots);
        CHECK(analysis.maximum_row_absolute_weight > 0);
        CHECK(analysis.rows.front().weight.approximate_mixed_norm <=
              static_cast<long double>(
                  analysis.maximum_row_weight_upper));
    });

    runner.run("subgroup-coset rows beat contiguous position masks", [&] {
        const auto contiguous = analyze_packing_operator_weights(
            make_packing_linear_operator(make_prefix_packing_layout(
                kSlots, std::vector<std::size_t>{16, 16, 16, 16})),
            [&](const SlotVector &mask) {
                return encode_mask(contexts.eval, mask);
            });
        const auto cosets = analyze_packing_operator_weights(
            make_packing_linear_operator(
                make_fixed_message_coset_packing_layout(kSlots, 4, 4)),
            [&](const SlotVector &mask) {
                return encode_mask(contexts.eval, mask);
            });

        CHECK(cosets.aligned_ciphertext_count == 4);
        CHECK(cosets.rows.size() == 1);
        CHECK(cosets.maximum_row_weight_upper <
              contiguous.maximum_row_weight_upper);
    });

    runner.run("base-41 digit rows reduce the exact operator weight", [&] {
        const PackingLinearOperator packing_operator =
            make_packing_linear_operator(
                make_fixed_message_coset_packing_layout(kSlots, 8, 8));
        const auto ordinary = analyze_packing_operator_weights(
            packing_operator, [&](const SlotVector &mask) {
                return encode_mask(contexts.eval, mask);
            });
        const BalancedRadix radix =
            make_minimal_balanced_radix(kBaseFieldOrder, 41);
        const auto digits = analyze_signed_digit_packing_weights(
            packing_operator,
            [&](const SlotVector &mask) {
                return encode_mask(contexts.eval, mask);
            },
            radix);

        CHECK(digits.radix == radix);
        CHECK(digits.logical_output_count == 1);
        CHECK(digits.rows.size() == 3);
        CHECK(digits.maximum_digit_row_weight_upper <
              ordinary.maximum_row_weight_upper);
        CHECK(digits.maximum_digit_row_absolute_weight > 0);
        for (const auto &row : digits.rows) {
            CHECK(row.contribution_count == 8);
            CHECK(row.weight.conservative_integer_upper > 0);
        }
    });

    return runner.summary();
}
