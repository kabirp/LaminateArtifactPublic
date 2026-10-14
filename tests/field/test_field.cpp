#include "test_helpers.hpp"

#include "laminate/field/fp.hpp"
#include "laminate/field/fpk.hpp"
#include "laminate/field/fq.hpp"
#include "laminate/field/fq2.hpp"
#include "laminate/field/serialization.hpp"
#include "laminate/params.hpp"

#include <array>
#include <cstdint>
#include <stdexcept>

namespace {

using laminate::Fp;
using laminate::Fpk;
using laminate::Fq;
using laminate::Fq2;

void test_fp_arithmetic() {
    CHECK(Fp(65536) + Fp(1) == Fp::zero());
    CHECK(Fp::zero() - Fp::one() == Fp(65536));
    CHECK(Fp(65536) * Fp(65536) == Fp::one());
    CHECK(Fp(laminate::kBaseFieldOrder) == Fp::zero());
    CHECK(Fp(laminate::kBaseFieldOrder + 1) == Fp::one());
}

void test_fp_inverse() {
    for (std::uint64_t value : {1ULL, 2ULL, 12345ULL, 65536ULL}) {
        const Fp element(value);
        CHECK(element * element.inverse() == Fp::one());
    }

    bool threw = false;
    try {
        (void)Fp::zero().inverse();
    } catch (const std::domain_error &) {
        threw = true;
    }
    CHECK(threw);
}

void test_fp_roots() {
    for (std::size_t log_order : {1U, 2U, 3U, 8U, 16U}) {
        const Fp root = Fp::two_adic_generator(log_order);
        Fp half_order_power = root;
        for (std::size_t i = 0; i + 1 < log_order; ++i) {
            half_order_power *= half_order_power;
        }
        CHECK(!(half_order_power == Fp::one()));
        CHECK(half_order_power * half_order_power == Fp::one());
    }
}

void test_fpk_reduction() {
    Fpk::Coefficients x4{};
    x4[4] = Fp::one();
    Fpk::Coefficients expected{};
    expected[0] = Fp::zero() - Fp::one();
    expected[3] = Fp::zero() - Fp::one();
    CHECK(Fpk(x4) * Fpk(x4) == Fpk(expected));
}

void test_fpk_axioms() {
    for (int trial = 0; trial < 16; ++trial) {
        const Fpk a = Fpk::random_element();
        const Fpk b = Fpk::random_element();
        const Fpk c = Fpk::random_element();
        CHECK((a * b) * c == a * (b * c));
        CHECK(a * (b + c) == a * b + a * c);
        CHECK((a + b) - b == a);
        CHECK(a * Fpk::one() == a);
        CHECK((a * Fpk::zero()).is_zero());
    }
}

void test_fpk_inverse() {
    for (int trial = 0; trial < 16; ++trial) {
        Fpk value = Fpk::random_element();
        if (value.is_zero()) {
            value = Fpk::one();
        }
        const Fpk inverse = value.inverse();
        CHECK(value * inverse == Fpk::one());
        CHECK(inverse.inverse() == value);
    }

    bool threw = false;
    try {
        (void)Fpk::zero().inverse();
    } catch (const std::domain_error &) {
        threw = true;
    }
    CHECK(threw);
}

void test_mixed_arithmetic() {
    const Fpk value = Fpk::random_element();
    const Fp scalar(4242);
    CHECK(value * scalar == value * Fpk::from_base(scalar));
    CHECK(value + scalar == value + Fpk::from_base(scalar));
}

void test_native_field_and_extension() {
    CHECK((laminate::kOuterFieldOrder >> 59U) == 1);
    CHECK(Fq(laminate::kOuterFieldQuadraticNonResidue)
              .pow((laminate::kOuterFieldOrder - 1) / 2) ==
          Fq(laminate::kOuterFieldOrder - 1));
    CHECK(Fq(laminate::kOuterFieldOrder - 1) + Fq::one() == Fq::zero());
    CHECK(Fq::zero() - Fq::one() ==
          Fq(laminate::kOuterFieldOrder - 1));
    for (const std::uint64_t left : std::array<std::uint64_t, 5>{
             0, 1, 2, laminate::kOuterFieldOrder - 2,
             laminate::kOuterFieldOrder - 1}) {
        CHECK(Fq(left).value() == left);
        for (const std::uint64_t right : std::array<std::uint64_t, 5>{
                 0, 1, 3, laminate::kOuterFieldOrder - 2,
                 laminate::kOuterFieldOrder - 1}) {
            const std::uint64_t expected = static_cast<std::uint64_t>(
                (static_cast<unsigned __int128>(left) * right) %
                laminate::kOuterFieldOrder);
            CHECK((Fq(left) * Fq(right)).value() == expected);
        }
    }
    for (const std::uint64_t word : std::array<std::uint64_t, 4>{
             1, 2, 123456789, laminate::kOuterFieldOrder - 1}) {
        const Fq value(word);
        CHECK(value * value.inverse() == Fq::one());
    }

    for (std::size_t log_order : {1U, 16U, 32U, 37U}) {
        const Fq root = Fq::two_adic_generator(log_order);
        CHECK(root.pow(std::uint64_t{1} << log_order) == Fq::one());
        CHECK(log_order == 0 ||
              !(root.pow(std::uint64_t{1} << (log_order - 1)) ==
                Fq::one()));
    }

    for (int trial = 0; trial < 16; ++trial) {
        Fq2 value = Fq2::random_element();
        if (value.is_zero()) {
            value = Fq2::one();
        }
        CHECK(value * value.inverse() == Fq2::one());
        const Fq scalar = Fq::random_element();
        CHECK(value * scalar == value * Fq2::from_base(scalar));
        const Fq2 left = Fq2::random_element();
        const Fq2 right = Fq2::random_element();
        CHECK((value * left) * right == value * (left * right));
        CHECK(value * (left + right) == value * left + value * right);
    }
}

void test_canonical_serialization() {
    for (std::uint64_t word : {0ULL, 1ULL, 65536ULL}) {
        const Fp value(word);
        const laminate::SerializedFp encoded = laminate::serialize(value);
        CHECK(laminate::deserialize_fp(encoded) == value);
    }

    const Fpk extension = Fpk::random_element();
    const laminate::SerializedFpk encoded_extension =
        laminate::serialize(extension);
    CHECK(laminate::deserialize_fpk(encoded_extension) == extension);

    const Fq native = Fq::random_element();
    CHECK(laminate::deserialize_fq(laminate::serialize(native)) == native);
    const Fq2 native_extension = Fq2::random_element();
    CHECK(laminate::deserialize_fq2(
              laminate::serialize(native_extension)) == native_extension);

    laminate::SerializedFp noncanonical = {1, 0, 1}; // 65537
    bool threw = false;
    try {
        (void)laminate::deserialize_fp(noncanonical);
    } catch (const std::invalid_argument &) {
        threw = true;
    }
    CHECK(threw);
}

} // namespace

int main() {
    laminate::test::Runner runner("test_field");
    runner.run("Fp arithmetic", test_fp_arithmetic);
    runner.run("Fp inversion", test_fp_inverse);
    runner.run("Fp roots of unity", test_fp_roots);
    runner.run("Fpk modulus reduction", test_fpk_reduction);
    runner.run("Fpk ring axioms", test_fpk_axioms);
    runner.run("Fpk inversion", test_fpk_inverse);
    runner.run("Fpk mixed base arithmetic", test_mixed_arithmetic);
    runner.run("native Fq/Fq2 arithmetic", test_native_field_and_extension);
    runner.run("canonical field serialization", test_canonical_serialization);
    return runner.summary();
}
