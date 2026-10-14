/// @file test_outer_relation_r1cs.cpp
/// @brief Sparse R1CS encoding and mutation tests.

#include "test_helpers.hpp"

#include "laminate/packing/outer_relation/r1cs.hpp"

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <vector>

using namespace laminate;
using namespace laminate::packing;

namespace {

constexpr std::uint64_t kPrime = 257;

NativePackingContribution contribution(std::size_t aligned,
                                       std::uint64_t seed) {
    return NativePackingContribution{
        .aligned_ciphertext = aligned,
        .multiplier_ntt_coordinates = {
            seed, seed + 1, seed + 2, seed + 3},
    };
}

NativePackingOperator packing_operator() {
    return NativePackingOperator{
        .native_modulus = kPrime,
        .ring_degree = 4,
        .aligned_ciphertexts = 3,
        .logical_outputs = 2,
        .digit_count = 2,
        .rows = {
            NativePackingRow{0, 0,
                             {contribution(0, 1), contribution(1, 11)}},
            NativePackingRow{0, 1,
                             {contribution(0, 21), contribution(1, 31)}},
            NativePackingRow{1, 0, {contribution(2, 41)}},
            NativePackingRow{1, 1, {contribution(2, 51)}},
        },
    };
}

LazyTernaryChallengeMatrix challenges() {
    return {
        {{false, false}, {true, true}, {true, false}},
        {{false, true}, {true, false}, {true, true}},
    };
}

struct Fixture {
    NativePackingOperator packing = packing_operator();
    OuterRelationPlan plan = make_outer_relation_plan(packing, 2, 2, 8);
    OuterRelationWitnessInputs witness_inputs;
    OuterRelationPublicInputs public_inputs;
    OuterRelationAuxiliaryWitness auxiliary;
    OuterRelationR1csAssignment assignment;

    Fixture() {
        witness_inputs.aligned_ciphertext_coordinates.resize(24);
        for (std::size_t index = 0;
             index < witness_inputs.aligned_ciphertext_coordinates.size();
             ++index) {
            witness_inputs.aligned_ciphertext_coordinates[index] = index + 1;
        }
        public_inputs.packed_challenge_words =
            pack_outer_relation_challenge_bits(plan, challenges());
        const OuterRelationExpectedOutputs expected =
            compute_outer_relation_expected_outputs(
                plan, public_inputs.packed_challenge_words, witness_inputs,
                packing);
        public_inputs.revealed_test_coordinates =
            expected.revealed_test_coordinates;
        public_inputs.revealed_packing_coordinates =
            expected.revealed_packing_coordinates;
        auxiliary = build_outer_relation_auxiliary_witness(
            plan, public_inputs.packed_challenge_words, witness_inputs);
        assignment = make_outer_relation_r1cs_assignment(
            plan, public_inputs, witness_inputs, auxiliary);
    }
};

template <typename Action>
bool rejects_invalid_argument(Action action) {
    try {
        action();
    } catch (const std::invalid_argument &) {
        return true;
    }
    return false;
}

template <typename Exception, typename Action>
bool rejects_as(Action action) {
    try {
        action();
    } catch (const Exception &) {
        return true;
    }
    return false;
}

} // namespace

int main() {
    test::Runner runner("test_outer_relation_r1cs");

    runner.run("every sparse R1CS row accepts the honest assignment", [] {
        const Fixture fixture;
        OuterRelationR1csCursor cursor(
            fixture.plan, fixture.packing);
        std::uint64_t a_entries = 0;
        std::uint64_t b_entries = 0;
        std::uint64_t c_entries = 0;
        while (!cursor.empty()) {
            const std::uint64_t index = cursor.position();
            const OuterRelationR1csRow &row = cursor.next();
            CHECK(row.constraint_index == index);
            CHECK(evaluate_outer_relation_r1cs_row(
                fixture.plan, row, fixture.assignment));
            a_entries += row.a.size();
            b_entries += row.b.size();
            c_entries += row.c.size();
        }
        const OuterRelationR1csSize size =
            estimate_outer_relation_r1cs_size(
                fixture.plan, fixture.packing);
        CHECK(size.packing_a_entries_are_exact);
        CHECK(size.packing_a_entries == 48);
        CHECK(size.a_nonzero_entries == 216);
        CHECK(size.b_nonzero_entries == 122);
        CHECK(size.c_nonzero_entries == 98);
        CHECK(size.total_nonzero_entries == 436);
        CHECK(a_entries == size.a_nonzero_entries);
        CHECK(b_entries == size.b_nonzero_entries);
        CHECK(c_entries == size.c_nonzero_entries);
    });

    runner.run("bulk cursor reuses buffers and enforces operator boundary", [] {
        const Fixture fixture;
        const OuterRelationRange tests =
            fixture.plan.constraints.revealed_test_equalities;
        OuterRelationR1csCursor cursor(
            fixture.plan, fixture.packing, tests.begin, tests.begin + 2);

        const OuterRelationR1csRow &first = cursor.next();
        const OuterRelationR1csTerm *a_storage = first.a.data();
        const std::size_t a_capacity = first.a.capacity();
        CHECK(first.a.size() == 3);

        const OuterRelationR1csRow &second = cursor.next();
        CHECK(&first == &second);
        CHECK(second.a.data() == a_storage);
        CHECK(second.a.capacity() == a_capacity);
        CHECK(second.constraint_index == tests.begin + 1);
        CHECK(cursor.empty());
        CHECK(rejects_as<std::out_of_range>([&] {
            (void)cursor.next();
        }));

        OuterRelationR1csCursor dynamic_prefix(fixture.plan);
        CHECK(dynamic_prefix.remaining() ==
              fixture.plan.constraints.revealed_packing_equalities.begin);
        CHECK(rejects_as<std::out_of_range>([&] {
            OuterRelationR1csCursor invalid(
                fixture.plan, 0, fixture.plan.constraints.total);
            (void)invalid;
        }));

        const OuterRelationR1csBuilder dynamic_builder(fixture.plan);
        CHECK(dynamic_builder.row(0).a.size() == 1);
        CHECK(rejects_as<std::logic_error>([&] {
            (void)dynamic_builder.row(
                fixture.plan.constraints.revealed_packing_equalities.begin);
        }));
    });

    runner.run("row shapes match their five equations", [] {
        const Fixture fixture;
        const OuterRelationR1csBuilder builder(
            fixture.plan, fixture.packing);

        const OuterRelationR1csRow booleanity = builder.row(0);
        CHECK(booleanity.a.size() == 1);
        CHECK(booleanity.b.size() == 2);
        CHECK(booleanity.c.empty());
        CHECK(booleanity.b.back().coefficient == kPrime - 1);

        const OuterRelationR1csRow recomposition = builder.row(12);
        CHECK(recomposition.a.size() == 8);
        CHECK(recomposition.a.back().coefficient == 128);
        CHECK(recomposition.b.size() == 1);
        CHECK(recomposition.c.size() == 1);

        const OuterRelationR1csRow product = builder.row(14);
        CHECK(product.a.size() == 2);
        CHECK(product.b.size() == 1);
        CHECK(product.c.size() == 1);

        const OuterRelationR1csRow test_sum = builder.row(62);
        CHECK(test_sum.a.size() == 3);
        CHECK(test_sum.b.size() == 1);
        CHECK(test_sum.c.size() == 1);

        const OuterRelationR1csRow packing_sum = builder.row(78);
        CHECK(packing_sum.a.size() == 2);
        CHECK(packing_sum.b.size() == 1);
        CHECK(packing_sum.c.size() == 1);
    });

    runner.run("each assignment region is bound by a concrete row", [] {
        const Fixture fixture;
        const OuterRelationR1csBuilder builder(
            fixture.plan, fixture.packing);

        auto changed = fixture.assignment;
        changed.witness[0] = 2;
        CHECK(!evaluate_outer_relation_r1cs_row(
            fixture.plan, builder.row(0), changed));

        changed = fixture.assignment;
        changed.public_inputs[0] ^= 1;
        CHECK(!evaluate_outer_relation_r1cs_row(
            fixture.plan, builder.row(12), changed));

        changed = fixture.assignment;
        changed.witness[28] ^= 1;
        CHECK(!evaluate_outer_relation_r1cs_row(
            fixture.plan, builder.row(30), changed));
        CHECK(!evaluate_outer_relation_r1cs_row(
            fixture.plan, builder.row(94), changed));

        changed = fixture.assignment;
        changed.witness[52] ^= 1;
        CHECK(!evaluate_outer_relation_r1cs_row(
            fixture.plan, builder.row(30), changed));
        CHECK(!evaluate_outer_relation_r1cs_row(
            fixture.plan, builder.row(62), changed));

        changed = fixture.assignment;
        changed.public_inputs[2] ^= 1;
        CHECK(!evaluate_outer_relation_r1cs_row(
            fixture.plan, builder.row(62), changed));

        changed = fixture.assignment;
        changed.public_inputs[18] ^= 1;
        CHECK(!evaluate_outer_relation_r1cs_row(
            fixture.plan, builder.row(78), changed));
    });

    runner.run("malformed assignments and rows fail closed", [] {
        const Fixture fixture;
        const OuterRelationR1csBuilder builder(
            fixture.plan, fixture.packing);

        auto malformed = fixture.assignment;
        malformed.witness.pop_back();
        CHECK(rejects_invalid_argument([&] {
            (void)evaluate_outer_relation_r1cs_row(
                fixture.plan, builder.row(0), malformed);
        }));

        malformed = fixture.assignment;
        malformed.public_inputs.front() = kPrime;
        CHECK(rejects_invalid_argument([&] {
            (void)evaluate_outer_relation_r1cs_row(
                fixture.plan, builder.row(0), malformed);
        }));

        OuterRelationR1csRow malformed_row = builder.row(0);
        malformed_row.a.front().coefficient = kPrime;
        CHECK(rejects_invalid_argument([&] {
            (void)evaluate_outer_relation_r1cs_row(
                fixture.plan, malformed_row, fixture.assignment);
        }));
    });

    runner.run("target Folded sparse-entry ledger stays in uint64", [] {
        const OuterRelationPlan plan = make_outer_relation_plan(
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
        const OuterRelationR1csSize size =
            estimate_outer_relation_r1cs_size(plan);
        CHECK(!size.packing_a_entries_are_exact);
        CHECK(size.packing_a_entries == 67'764'224);
        CHECK(size.a_nonzero_entries == 6'166'792'544ULL);
        CHECK(size.b_nonzero_entries == 2'037'240'216ULL);
        CHECK(size.c_nonzero_entries == 2'036'992'056ULL);
        CHECK(size.total_nonzero_entries == 10'241'024'816ULL);
    });

    return runner.summary();
}
