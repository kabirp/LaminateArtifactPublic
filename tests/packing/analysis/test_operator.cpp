/// @file test_operator.cpp
/// @brief Grid geometry and exact-mask row-weight tests.

#include "test_helpers.hpp"

#include "laminate/packing/analysis/operator.hpp"

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <vector>

using namespace laminate;
using namespace laminate::packing;

namespace {

SignedCoefficientMask identity_lift(const fhe::SlotVector &mask) {
    SignedCoefficientMask result;
    result.reserve(mask.size());
    for (const Fp &value : mask) {
        result.push_back(static_cast<std::int64_t>(value.value()));
    }
    return result;
}

SignedCoefficientMask scaled_lift(const fhe::SlotVector &mask) {
    SignedCoefficientMask result;
    result.reserve(mask.size());
    for (const Fp &value : mask) {
        result.push_back(value == Fp::zero() ? 0 : 30000);
    }
    return result;
}

} // namespace

int main() {
    test::Runner runner("test_packing_operator");

    runner.run("operator exposes aligned splits as theorem inputs", [] {
        const PackingLayout layout = make_prefix_packing_layout(
            16, std::vector<std::size_t>{12, 12});
        const PackingLinearOperator packing_operator =
            make_packing_linear_operator(layout);

        CHECK(packing_operator.source_ciphertext_count == 2);
        CHECK(packing_operator.aligned_ciphertext_count ==
              layout.placements.size());
        CHECK(packing_operator.aligned_ciphertext_count >
              packing_operator.source_ciphertext_count);
        CHECK(packing_operator.rows.size() == 2);

        std::vector<std::vector<bool>> seen(2, std::vector<bool>(12, false));
        for (const auto &row : packing_operator.rows) {
            std::vector<bool> occupied(16, false);
            for (const auto &input : row.contributions) {
                for (std::size_t offset = 0; offset < input.length; ++offset) {
                    CHECK(!seen[input.source_index]
                               [input.source_begin + offset]);
                    seen[input.source_index]
                        [input.source_begin + offset] = true;
                    CHECK(!occupied[input.destination_begin + offset]);
                    occupied[input.destination_begin + offset] = true;
                }
            }
        }
        for (const auto &message : seen) {
            for (bool coordinate : message) {
                CHECK(coordinate);
            }
        }
    });

    runner.run("row weights encode every actual position mask", [] {
        const PackingLinearOperator packing_operator =
            make_packing_linear_operator(make_prefix_packing_layout(
                64, std::vector<std::size_t>{16, 16, 16, 16}));
        const PackingOperatorWeightAnalysis analysis =
            analyze_packing_operator_weights(packing_operator, identity_lift);

        CHECK(analysis.ring_degree == 64);
        CHECK(analysis.source_ciphertext_count == 4);
        CHECK(analysis.aligned_ciphertext_count == 4);
        CHECK(analysis.rows.size() == 1);
        CHECK(analysis.rows.front().contribution_count == 4);
        CHECK(analysis.rows.front().weight.conservative_integer_upper == 64);
        CHECK(analysis.rows.front().weight
                  .total_absolute_coefficient_weight == 64);
        CHECK(analysis.maximum_row_weight_upper == 64);
        CHECK(analysis.maximum_row_absolute_weight == 64);
    });

    runner.run("frontier selects only the configured admissible radix", [] {
        const PackingLinearOperator packing_operator =
            make_packing_linear_operator(make_prefix_packing_layout(
                64, std::vector<std::size_t>{16, 16, 16, 16}));
        const auto frontier = analyze_signed_digit_packing_frontier(
            packing_operator, scaled_lift,
            SignedDigitFrontierInputs{
                .packing_modulus = 1'000'000'000'000'000ULL,
                .plaintext_modulus = kBaseFieldOrder,
                .honest_error_bound = 100,
                .repetitions = kPackingWellFormednessRepetitions,
                .selected_radix_base = 257,
            });

        CHECK(frontier.profiles.size() == 8);
        CHECK(!frontier.profiles.front()
                   .certificate.interactive_certificate_holds);
        const auto *selected = frontier.selected_profile();
        CHECK(selected != nullptr);
        CHECK(selected->weights.radix.base == 257);
        CHECK(selected->weights.radix.digit_count == 2);
        CHECK(selected->certificate.interactive_certificate_holds);
        CHECK(selected->individual_bound_packing.certified_input_bound ==
              selected->certificate.accepted_input_bounds
                  .individual_partial_decryption_bound);

        const auto rejected_fixed_radix =
            analyze_signed_digit_packing_frontier(
                packing_operator, scaled_lift,
                SignedDigitFrontierInputs{
                    .packing_modulus = 1'000'000'000'000'000ULL,
                    .plaintext_modulus = kBaseFieldOrder,
                    .honest_error_bound = 100,
                    .repetitions = kPackingWellFormednessRepetitions,
                    .selected_radix_base = kBaseFieldOrder,
                });
        CHECK(rejected_fixed_radix.selected_profile() == nullptr);
        CHECK(rejected_fixed_radix.profiles[1]
                  .certificate.interactive_certificate_holds);
    });

    runner.run("analysis rejects an encoder with the wrong ring degree", [] {
        const PackingLinearOperator packing_operator =
            make_packing_linear_operator(make_prefix_packing_layout(
                16, std::vector<std::size_t>{8, 8}));
        bool rejected = false;
        try {
            (void)analyze_packing_operator_weights(
                packing_operator, [](const fhe::SlotVector &) {
                    return SignedCoefficientMask{1, 2, 3};
                });
        } catch (const std::invalid_argument &) {
            rejected = true;
        }
        CHECK(rejected);
    });

    runner.run("compact validation rejects overlapping destinations", [] {
        PackingLinearOperator malformed = make_packing_linear_operator(
            make_prefix_packing_layout(
                64, std::vector<std::size_t>{16, 16}));
        malformed.rows.front().contributions[1].destination_begin = 0;
        bool rejected = false;
        try {
            malformed.validate();
        } catch (const std::invalid_argument &) {
            rejected = true;
        }
        CHECK(rejected);
    });

    return runner.summary();
}
