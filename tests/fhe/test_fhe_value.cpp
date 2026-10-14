#include "test_helpers.hpp"

#include "laminate/fhe/mock_backend.hpp"
#include "laminate/fhe/extension.hpp"
#include "laminate/fhe/value.hpp"

#include <cstddef>
#include <stdexcept>

namespace {

using laminate::Fp;
using laminate::fhe::FheValue;
using laminate::fhe::ExtensionValue;
using laminate::fhe::MockBackend;
using laminate::fhe::MockParameters;
using laminate::fhe::PublicPlaintext;
using laminate::fhe::SlotVector;

using Value = FheValue<MockBackend>;

bool throws_invalid_argument(const auto &body) {
    try {
        body();
    } catch (const std::invalid_argument &) {
        return true;
    }
    return false;
}

bool throws_logic_error(const auto &body) {
    try {
        body();
    } catch (const std::logic_error &) {
        return true;
    }
    return false;
}

SlotVector sequence(std::size_t size, std::uint64_t offset = 0) {
    SlotVector result;
    result.reserve(size);
    for (std::size_t index = 0; index < size; ++index) {
        result.emplace_back(offset + index);
    }
    return result;
}

void expect_public(const Value &value, const SlotVector &expected) {
    CHECK(value.is_public());
    CHECK(value.plaintext().materialize(expected.size()) == expected);
}

void expect_encrypted(const MockBackend::ClientContext &client,
                      const Value &value, const SlotVector &expected) {
    CHECK(value.is_encrypted());
    CHECK(MockBackend::decrypt(client, value.ciphertext()) == expected);
}

void test_canonical_public_representation() {
    const PublicPlaintext scalar =
        PublicPlaintext::from_slots(SlotVector(8, Fp(7)));
    CHECK(scalar.is_scalar());
    CHECK(scalar.scalar() == Fp(7));
    CHECK(scalar.materialize(8) == SlotVector(8, Fp(7)));

    const SlotVector varying = sequence(8, 3);
    const PublicPlaintext slots = PublicPlaintext::from_slots(varying);
    CHECK(slots.is_slots());
    CHECK(slots.slots() == varying);
    CHECK(throws_logic_error([&] { (void)slots.scalar(); }));
    CHECK(throws_logic_error([&] { (void)scalar.slots(); }));
    CHECK(throws_invalid_argument(
        [] { (void)PublicPlaintext::from_slots({}); }));
    CHECK(throws_invalid_argument([&] { (void)slots.materialize(4); }));

    const Value zero;
    CHECK(zero.is_public_zero());
    CHECK(throws_logic_error([&] { (void)zero.ciphertext(); }));
}

void test_public_algebra_never_calls_the_backend() {
    auto contexts = MockBackend::create(MockParameters{.slot_count = 8});
    const Value scalar = Value::public_scalar(Fp(3));
    const Value slots = Value::public_slots(sequence(8, 1));
    MockBackend::reset_counts(contexts.eval);

    expect_public(laminate::fhe::value_add(contexts.eval, scalar, slots),
                  {Fp(4), Fp(5), Fp(6), Fp(7),
                   Fp(8), Fp(9), Fp(10), Fp(11)});
    expect_public(laminate::fhe::value_sub(contexts.eval, slots, scalar),
                  {Fp(65535), Fp(65536), Fp(0), Fp(1),
                   Fp(2), Fp(3), Fp(4), Fp(5)});
    expect_public(laminate::fhe::value_mul(contexts.eval, scalar, slots),
                  {Fp(3), Fp(6), Fp(9), Fp(12),
                   Fp(15), Fp(18), Fp(21), Fp(24)});
    expect_public(laminate::fhe::value_negate(contexts.eval, scalar),
                  SlotVector(8, Fp(65534)));
    expect_public(laminate::fhe::value_rotate(contexts.eval, slots, 3),
                  laminate::fhe::grid_rotate(sequence(8, 1), 3));
    expect_public(laminate::fhe::value_fold(contexts.eval, slots),
                  SlotVector(8, Fp(36)));

    const auto &counts = MockBackend::counts(contexts.eval);
    CHECK(counts.add == 0);
    CHECK(counts.sub == 0);
    CHECK(counts.mul_no_relin == 0);
    CHECK(counts.relinearize == 0);
    CHECK(counts.add_plain == 0);
    CHECK(counts.mul_plain_scalar == 0);
    CHECK(counts.mul_plain_vector == 0);
    CHECK(counts.rotate == 0);
    CHECK(counts.mod_switch == 0);
}

void test_zero_and_one_short_circuits() {
    auto contexts = MockBackend::create(MockParameters{.slot_count = 8});
    const SlotVector clear = sequence(8, 2);
    const Value encrypted = Value::from_ciphertext(
        MockBackend::encrypt(contexts.client, clear));
    const Value zero = Value::public_scalar(Fp::zero());
    const Value one = Value::public_scalar(Fp::one());
    Value accumulator = encrypted;
    MockBackend::reset_counts(contexts.eval);

    expect_encrypted(contexts.client,
                     laminate::fhe::value_add(contexts.eval, encrypted, zero),
                     clear);
    expect_encrypted(contexts.client,
                     laminate::fhe::value_add(contexts.eval, zero, encrypted),
                     clear);
    expect_encrypted(contexts.client,
                     laminate::fhe::value_mul(contexts.eval, encrypted, one),
                     clear);
    expect_public(
        laminate::fhe::value_mul(contexts.eval, encrypted, zero),
        SlotVector(8, Fp::zero()));
    expect_public(
        laminate::fhe::value_sub(contexts.eval, encrypted, encrypted),
        SlotVector(8, Fp::zero()));
    const Value copied = encrypted;
    expect_public(
        laminate::fhe::value_sub(contexts.eval, encrypted, copied),
        SlotVector(8, Fp::zero()));
    laminate::fhe::value_add_assign(contexts.eval, accumulator, zero);
    expect_encrypted(contexts.client, accumulator, clear);

    const auto &counts = MockBackend::counts(contexts.eval);
    CHECK(counts.add == 0);
    CHECK(counts.sub == 0);
    CHECK(counts.mul_no_relin == 0);
    CHECK(counts.relinearize == 0);
    CHECK(counts.add_plain == 0);
    CHECK(counts.mul_plain_scalar == 0);
    CHECK(counts.mul_plain_vector == 0);
}

void test_first_temporary_term_moves_into_accumulator() {
    auto contexts = MockBackend::create(MockParameters{.slot_count = 8});
    const SlotVector clear = sequence(8, 23);
    Value term = Value::from_ciphertext(
        MockBackend::encrypt(contexts.client, clear));
    const Fp *term_storage = term.ciphertext().slots.data();
    Value accumulator = Value::public_zero();
    MockBackend::reset_counts(contexts.eval);

    laminate::fhe::value_add_assign(
        contexts.eval, accumulator, std::move(term));

    expect_encrypted(contexts.client, accumulator, clear);
    CHECK(accumulator.ciphertext().slots.data() == term_storage);
    CHECK(MockBackend::counts(contexts.eval).add == 0);
}

void test_mock_identity_does_not_compare_private_plaintext() {
    auto first = MockBackend::create(MockParameters{.slot_count = 8});
    auto second = MockBackend::create(MockParameters{.slot_count = 8});
    const SlotVector clear = sequence(8, 19);
    const Value left = Value::from_ciphertext(
        MockBackend::encrypt(first.client, clear));
    const Value independently_encrypted = Value::from_ciphertext(
        MockBackend::encrypt(second.client, clear));

    const Value difference = laminate::fhe::value_sub(
        first.eval, left, independently_encrypted);
    CHECK(difference.is_encrypted());
    expect_encrypted(first.client, difference,
                     SlotVector(8, Fp::zero()));
}

void test_mixed_and_encrypted_algebra() {
    auto contexts = MockBackend::create(MockParameters{.slot_count = 8});
    const SlotVector left_clear = sequence(8, 2);
    const SlotVector right_clear = sequence(8, 11);
    const Value left = Value::from_ciphertext(
        MockBackend::encrypt(contexts.client, left_clear));
    const Value right = Value::from_ciphertext(
        MockBackend::encrypt(contexts.client, right_clear));
    const Value scalar = Value::public_scalar(Fp(3));
    const Value slots = Value::public_slots(sequence(8, 1));
    MockBackend::reset_counts(contexts.eval);

    SlotVector expected_add(8);
    SlotVector expected_mul(8);
    SlotVector expected_private_mul(8);
    for (std::size_t index = 0; index < 8; ++index) {
        expected_add[index] = left_clear[index] + Fp(3);
        expected_mul[index] = left_clear[index] * Fp(index + 1);
        expected_private_mul[index] = left_clear[index] * right_clear[index];
    }
    expect_encrypted(contexts.client,
                     laminate::fhe::value_add(contexts.eval, left, scalar),
                     expected_add);
    expect_encrypted(contexts.client,
                     laminate::fhe::value_sub(contexts.eval, scalar, left),
                     SlotVector{Fp(1), Fp(0), Fp(65536), Fp(65535),
                                Fp(65534), Fp(65533), Fp(65532), Fp(65531)});
    expect_encrypted(contexts.client,
                     laminate::fhe::value_mul(contexts.eval, left, slots),
                     expected_mul);
    expect_encrypted(contexts.client,
                     laminate::fhe::value_mul(contexts.eval, left, right),
                     expected_private_mul);

    const auto &counts = MockBackend::counts(contexts.eval);
    CHECK(counts.negate == 1);
    CHECK(counts.add_plain == 2);
    CHECK(counts.add_plain_scalar_api_calls == 2);
    CHECK(counts.mul_plain_vector == 1);
    CHECK(counts.mul_plain_vector_api_calls == 1);
    CHECK(counts.mul_no_relin == 1);
    CHECK(counts.relinearize == 1);
}

void test_rotation_and_mod_switch_dispatch() {
    auto contexts = MockBackend::create(MockParameters{.slot_count = 8});
    const SlotVector clear = sequence(8, 4);
    Value encrypted = Value::from_ciphertext(
        MockBackend::encrypt(contexts.client, clear));
    Value public_slots = Value::public_slots(sequence(8, 1));
    MockBackend::reset_counts(contexts.eval);

    expect_encrypted(contexts.client,
                     laminate::fhe::value_rotate(contexts.eval, encrypted, 2),
                     laminate::fhe::grid_rotate(clear, 2));
    expect_encrypted(contexts.client,
                     laminate::fhe::value_rotate(contexts.eval, encrypted, 8),
                     clear);
    laminate::fhe::value_mod_switch_to_next(contexts.eval, encrypted);
    laminate::fhe::value_mod_switch_to_next(contexts.eval, public_slots);

    const auto &counts = MockBackend::counts(contexts.eval);
    CHECK(counts.rotate == 1);
    CHECK(counts.mod_switch == 1);
    CHECK(encrypted.ciphertext().rns_limbs ==
          contexts.eval.parameters.fresh_rns_limbs - 1);
}

void test_mixed_extension_projection_is_explicit() {
    auto contexts = MockBackend::create(MockParameters{.slot_count = 8});
    const SlotVector clear = sequence(8, 7);
    ExtensionValue<MockBackend> mixed;
    mixed[0] = Value::from_ciphertext(
        MockBackend::encrypt(contexts.client, clear));
    mixed[1] = Value::public_scalar(Fp(13));

    CHECK(mixed.ciphertext_count() == 1);
    CHECK(mixed.has_public_nonzero());
    CHECK(throws_invalid_argument(
        [&] { (void)mixed.encrypted_part(); }));
    const auto projection = mixed.encrypted_projection();
    CHECK(projection[0].has_value());
    CHECK(!projection[1].has_value());

    MockBackend::reset_counts(contexts.eval);
    const auto scaled = laminate::fhe::mixed_scale_extension<MockBackend>(
        contexts.eval, mixed, laminate::Fpk::from_base(Fp(3)));
    const std::vector<laminate::Fpk> opened =
        laminate::fhe::read_extension_value<MockBackend>(
            contexts.client, scaled);
    for (std::size_t slot = 0; slot < opened.size(); ++slot) {
        laminate::Fpk::Coefficients expected{};
        expected[0] = clear[slot] * Fp(3);
        expected[1] = Fp(39);
        CHECK(opened[slot] == laminate::Fpk(expected));
    }
}

} // namespace

int main() {
    laminate::test::Runner runner("fhe value");
    runner.run("canonical public representation",
               test_canonical_public_representation);
    runner.run("public algebra", test_public_algebra_never_calls_the_backend);
    runner.run("zero and one short circuits",
               test_zero_and_one_short_circuits);
    runner.run("first temporary term moves into accumulator",
               test_first_temporary_term_moves_into_accumulator);
    runner.run("Mock ciphertext identity is provenance-only",
               test_mock_identity_does_not_compare_private_plaintext);
    runner.run("mixed and encrypted algebra",
               test_mixed_and_encrypted_algebra);
    runner.run("rotation and modulus switching",
               test_rotation_and_mod_switch_dispatch);
    runner.run("mixed extension projection is explicit",
               test_mixed_extension_projection_is_explicit);
    return runner.summary();
}
