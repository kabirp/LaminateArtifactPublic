/// @file test_outer_relation_packing_r1cs.cpp
/// @brief Exact and fail-closed tests for fixed-matrix streaming.

#include "test_helpers.hpp"

#include "laminate/packing/outer_relation/packing_r1cs.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <tuple>
#include <vector>

using namespace laminate;
using namespace laminate::packing;

namespace {

constexpr std::uint64_t kPrime = 257;

SignedCoefficientMask identity_coefficients(
    const fhe::SlotVector &slots) {
    SignedCoefficientMask result;
    result.reserve(slots.size());
    for (const Fp value : slots) {
        result.push_back(static_cast<std::int64_t>(value.value()));
    }
    return result;
}

std::vector<std::uint64_t> identity_native_ntt(
    std::span<const std::int64_t> coefficients) {
    std::vector<std::uint64_t> result;
    result.reserve(coefficients.size());
    for (const std::int64_t coefficient : coefficients) {
        const std::uint64_t magnitude =
            coefficient >= 0
                ? static_cast<std::uint64_t>(coefficient)
                : std::uint64_t{0} -
                      static_cast<std::uint64_t>(coefficient);
        result.push_back(
            coefficient >= 0 || magnitude == 0
                ? magnitude % kPrime
                : (kPrime - magnitude % kPrime) % kPrime);
    }
    return result;
}

struct Fixture {
    BalancedRadix radix =
        make_minimal_balanced_radix(kBaseFieldOrder, 17);
    PackingLinearOperator logical = make_packing_linear_operator(
        make_prefix_packing_layout(
            16, std::vector<std::size_t>{4, 4, 4}));
    NativePackingOperator native;
    OuterRelationPlan plan;

    Fixture() {
        // A valid compact operator need not arrive in aligned-index order.
        // The entry stream canonicalizes it before emitting matrix entries.
        std::reverse(logical.rows.front().contributions.begin(),
                     logical.rows.front().contributions.end());
        native = make_native_signed_digit_packing_operator(
            logical, identity_coefficients, identity_native_ntt,
            kPrime, radix);
        plan = make_outer_relation_plan(native, 2, 2, 8);
    }
};

std::vector<OuterRelationR1csMatrixEntry> materialized_entries(
    const Fixture &fixture) {
    const OuterRelationR1csBuilder builder(
        fixture.plan, fixture.native);
    std::vector<OuterRelationR1csMatrixEntry> result;
    const OuterRelationRange range =
        fixture.plan.constraints.revealed_packing_equalities;
    for (std::uint64_t index = range.begin; index < range.end(); ++index) {
        const OuterRelationR1csRow row = builder.row(index);
        for (const OuterRelationR1csTerm &term : row.a) {
            result.push_back({OuterRelationR1csMatrix::A, index,
                              term.variable, term.coefficient});
        }
        for (const OuterRelationR1csTerm &term : row.b) {
            result.push_back({OuterRelationR1csMatrix::B, index,
                              term.variable, term.coefficient});
        }
        for (const OuterRelationR1csTerm &term : row.c) {
            result.push_back({OuterRelationR1csMatrix::C, index,
                              term.variable, term.coefficient});
        }
    }
    return result;
}

auto entry_key(const OuterRelationR1csMatrixEntry &entry) {
    return std::tuple{
        static_cast<std::uint8_t>(entry.matrix), entry.constraint_index,
        static_cast<std::uint8_t>(entry.variable.kind),
        entry.variable.index, entry.coefficient};
}

void sort_entries(std::vector<OuterRelationR1csMatrixEntry> &entries) {
    std::sort(entries.begin(), entries.end(), [](const auto &left,
                                                  const auto &right) {
        return entry_key(left) < entry_key(right);
    });
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
    test::Runner runner("test_outer_relation_packing_r1cs");

    runner.run("compact stream equals every materialized fixed row", [] {
        const Fixture fixture;
        std::size_t centered_calls = 0;
        std::size_t native_calls = 0;
        FixedPackingR1csEntryCursor cursor(
            fixture.plan, fixture.logical,
            FixedPackingR1csEntryCursor::Encoders{
                .centered_coefficients =
                    [&](const fhe::SlotVector &mask) {
                        ++centered_calls;
                        return identity_coefficients(mask);
                    },
                .native_ntt =
                    [&](std::span<const std::int64_t> coefficients) {
                        ++native_calls;
                        return identity_native_ntt(coefficients);
                    },
            },
            fixture.radix);

        std::vector<OuterRelationR1csMatrixEntry> streamed;
        while (!cursor.empty()) {
            streamed.push_back(cursor.next());
        }
        auto expected = materialized_entries(fixture);
        sort_entries(streamed);
        sort_entries(expected);
        CHECK(streamed == expected);

        const auto &statistics = cursor.statistics();
        CHECK(statistics.complete);
        CHECK(statistics.aligned_masks_encoded == 3);
        CHECK(statistics.native_digit_polynomials_encoded == 12);
        CHECK(centered_calls == 3);
        CHECK(native_calls == 12);
        CHECK(statistics.a_nonzero_entries ==
              fixture.native.nonzero_constant_matrix_terms(2));
        CHECK(statistics.b_nonzero_entries ==
              fixture.plan.constraints.revealed_packing_equalities.count);
        CHECK(statistics.c_nonzero_entries ==
              fixture.plan.constraints.revealed_packing_equalities.count);
        CHECK(statistics.total_nonzero_entries == streamed.size());

        bool exhausted = false;
        try {
            (void)cursor.next();
        } catch (const std::out_of_range &) {
            exhausted = true;
        }
        CHECK(exhausted);
    });

    runner.run("storage ledger removes the r multiplier", [] {
        const Fixture fixture;
        const FixedPackingR1csStorageEstimate storage =
            estimate_fixed_packing_r1cs_storage(fixture.plan);
        CHECK(storage.materialized_multiplier_coordinates == 3 * 4 * 16);
        CHECK(storage.materialized_multiplier_bytes == 3 * 4 * 16 * 8);
        CHECK(storage.streamed_digit_and_ntt_coordinates == 5 * 16);
        CHECK(storage.streamed_digit_and_ntt_bytes == 5 * 16 * 8);

        const OuterRelationPlan target = make_outer_relation_plan(
            OuterRelationShape{
                .native_modulus = kOuterFieldOrder,
                .ring_degree = 16'384,
                .aligned_ciphertexts = 517,
                .repetitions = kPackingWellFormednessRepetitions,
                .logical_packed_outputs = 1,
                .packing_digit_count = 4,
                .ciphertext_components = 2,
                .public_input_capacity_bits = 59,
            });
        const auto target_storage =
            estimate_fixed_packing_r1cs_storage(target);
        CHECK(target_storage.materialized_multiplier_coordinates ==
              33'882'112);
        CHECK(target_storage.materialized_multiplier_bytes ==
              271'056'896);
        CHECK(target_storage.streamed_digit_and_ntt_coordinates == 81'920);
        CHECK(target_storage.streamed_digit_and_ntt_bytes == 655'360);
    });

    runner.run("shape and encoder failures are rejected", [] {
        const Fixture fixture;
        const auto good_encoders = FixedPackingR1csEntryCursor::Encoders{
            .centered_coefficients = identity_coefficients,
            .native_ntt = identity_native_ntt,
        };

        OuterRelationPlan wrong_plan = fixture.plan;
        ++wrong_plan.shape.aligned_ciphertexts;
        CHECK(rejects_invalid_argument([&] {
            FixedPackingR1csEntryCursor cursor(
                wrong_plan, fixture.logical, good_encoders,
                fixture.radix);
            (void)cursor;
        }));

        CHECK(rejects_invalid_argument([&] {
            FixedPackingR1csEntryCursor cursor(
                fixture.plan, fixture.logical, {}, fixture.radix);
            (void)cursor;
        }));

        FixedPackingR1csEntryCursor bad_centered(
            fixture.plan, fixture.logical,
            {.centered_coefficients =
                 [](const fhe::SlotVector &) {
                     return SignedCoefficientMask{1};
                 },
             .native_ntt = identity_native_ntt},
            fixture.radix);
        CHECK(rejects_invalid_argument([&] {
            (void)bad_centered.next();
        }));

        FixedPackingR1csEntryCursor bad_native(
            fixture.plan, fixture.logical,
            {.centered_coefficients = identity_coefficients,
             .native_ntt = [](std::span<const std::int64_t> coefficients) {
                 return std::vector<std::uint64_t>(coefficients.size(),
                                                   kPrime);
             }},
            fixture.radix);
        CHECK(rejects_invalid_argument([&] {
            (void)bad_native.next();
        }));
    });

    return runner.summary();
}
