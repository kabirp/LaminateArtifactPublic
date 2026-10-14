/// @file test_packing_tensor.cpp
/// @brief Natural-coordinate packing tensor compiler tests.

#include "test_helpers.hpp"

#include "laminate/packing/outer_relation/tensor.hpp"

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <utility>
#include <vector>

using namespace laminate;
using namespace laminate::packing;

namespace {

NativePackingOperator make_operator() {
    constexpr std::size_t kDegree = 4;
    constexpr std::size_t kDigits = 2;
    const std::vector<std::vector<std::size_t>> owners{{0, 2, 3}, {1}};
    NativePackingOperator result{
        .native_modulus = kOuterFieldOrder,
        .ring_degree = kDegree,
        .aligned_ciphertexts = 4,
        .logical_outputs = owners.size(),
        .digit_count = kDigits,
    };
    result.rows.resize(result.logical_outputs * result.digit_count);
    for (std::size_t output = 0; output < result.logical_outputs; ++output) {
        for (std::size_t digit = 0; digit < result.digit_count; ++digit) {
            NativePackingRow &row =
                result.rows[output * result.digit_count + digit];
            row.logical_output = output;
            row.digit = digit;
            for (const std::size_t owner : owners[output]) {
                NativePackingContribution contribution;
                contribution.aligned_ciphertext = owner;
                for (std::size_t coordinate = 0; coordinate < kDegree;
                     ++coordinate) {
                    contribution.multiplier_ntt_coordinates.push_back(
                        1'000 * output + 100 * digit + 10 * owner +
                        coordinate + 1);
                }
                row.contributions.push_back(std::move(contribution));
            }
        }
    }
    return result;
}

OuterRelationPlan plan_for(const NativePackingOperator &packing_operator) {
    return make_outer_relation_plan(packing_operator, 2);
}

template <typename Action>
bool rejects_invalid_argument(Action action) {
    try {
        action();
    } catch (const std::invalid_argument &) {
        return true;
    }
    return false;
}

} // namespace

int main() {
    test::Runner runner("test_packing_tensor");

    runner.run("compiler preserves owner coefficient and digit order", [] {
        const NativePackingOperator packing_operator = make_operator();
        const OuterRelationPlan plan = plan_for(packing_operator);
        const std::vector<PackingTensor> tensors =
            compile_packing_tensors(plan, packing_operator);

        CHECK(tensors.size() == 2);
        const PackingTensor &first = tensors[0];
        CHECK(first.global_owners ==
              std::vector<std::size_t>({0, 2, 3}));
        CHECK(first.descriptor.logical_output == 0);
        CHECK(first.descriptor.live_owner_count == 3);
        CHECK(first.descriptor.padded_owner_count == 4);
        CHECK(first.descriptor.ring_degree == 4);
        CHECK(first.descriptor.digit_count == 2);
        CHECK(first.descriptor.live_elements == 24);
        CHECK(first.descriptor.padded_elements == 32);
        CHECK(first.descriptor.field_element_bytes == sizeof(Fq));
        CHECK(first.descriptor.live_bytes == 24 * sizeof(Fq));
        CHECK(first.descriptor.padded_bytes == 32 * sizeof(Fq));
        CHECK(first.digit_columns.size() == 2);
        CHECK(first.digit_columns[0].size() == 16);
        CHECK(first.digit_columns[1].size() == 16);

        for (std::size_t digit = 0; digit < 2; ++digit) {
            for (std::size_t local = 0; local < 3; ++local) {
                const std::size_t owner = first.global_owners[local];
                for (std::size_t coordinate = 0; coordinate < 4;
                     ++coordinate) {
                    CHECK(first.digit_columns[digit][local * 4 + coordinate]
                              .value() ==
                          100 * digit + 10 * owner + coordinate + 1);
                }
            }
            for (std::size_t coordinate = 12; coordinate < 16;
                 ++coordinate) {
                CHECK(first.digit_columns[digit][coordinate].is_zero());
            }
        }

        const PackingTensor &second = tensors[1];
        CHECK(second.global_owners == std::vector<std::size_t>({1}));
        CHECK(second.descriptor.logical_output == 1);
        CHECK(second.descriptor.live_owner_count == 1);
        CHECK(second.descriptor.padded_owner_count == 1);
        CHECK(second.digit_columns[0][0].value() == 1'011);
        CHECK(second.digit_columns[1][3].value() == 1'114);
    });

    runner.run("formula geometry reports the Folded target without allocation",
               [] {
                   const std::vector<std::size_t> owners{517};
                   const PackingTensorGeometry geometry =
                       packing_tensor_geometry(owners, 1U << 14U, 4, 8);
                   CHECK(geometry.outputs.size() == 1);
                   CHECK(geometry.outputs[0].padded_owner_count == 1'024);
                   CHECK(geometry.outputs[0].padded_bytes ==
                         512ULL * 1'024ULL * 1'024ULL);
                   CHECK(geometry.total_live_elements == 33'882'112ULL);
                   CHECK(geometry.total_padded_elements == 67'108'864ULL);
                   CHECK(geometry.total_live_bytes == 271'056'896ULL);
                   CHECK(geometry.total_padded_bytes ==
                         512ULL * 1'024ULL * 1'024ULL);
               });

    runner.run("mismatched digit owner sequence is rejected", [] {
        NativePackingOperator packing_operator = make_operator();
        const OuterRelationPlan plan = plan_for(packing_operator);
        std::swap(packing_operator.rows[1].contributions[0],
                  packing_operator.rows[1].contributions[1]);
        CHECK(rejects_invalid_argument([&] {
            (void)compile_packing_tensors(plan, packing_operator);
        }));
    });

    runner.run("wrong coordinate count is rejected", [] {
        NativePackingOperator packing_operator = make_operator();
        const OuterRelationPlan plan = plan_for(packing_operator);
        packing_operator.rows[1]
            .contributions[0]
            .multiplier_ntt_coordinates.pop_back();
        CHECK(rejects_invalid_argument([&] {
            (void)compile_packing_tensors(plan, packing_operator);
        }));
    });

    runner.run("noncanonical coefficient is rejected", [] {
        NativePackingOperator packing_operator = make_operator();
        const OuterRelationPlan plan = plan_for(packing_operator);
        packing_operator.rows[1]
            .contributions[0]
            .multiplier_ntt_coordinates[0] = kOuterFieldOrder;
        CHECK(rejects_invalid_argument([&] {
            (void)compile_packing_tensors(plan, packing_operator);
        }));
    });

    runner.run("invalid formula geometry is rejected", [] {
        const std::vector<std::size_t> empty_owner{0};
        const std::vector<std::size_t> one_owner{1};
        CHECK(rejects_invalid_argument([&] {
            (void)packing_tensor_geometry(empty_owner, 16, 4, 8);
        }));
        CHECK(rejects_invalid_argument([&] {
            (void)packing_tensor_geometry(one_owner, 12, 4, 8);
        }));
        CHECK(rejects_invalid_argument([&] {
            (void)packing_tensor_geometry(one_owner, 16, 0, 8);
        }));
        CHECK(rejects_invalid_argument([&] {
            (void)packing_tensor_geometry(one_owner, 16, 4, 0);
        }));
    });

    return runner.summary();
}
