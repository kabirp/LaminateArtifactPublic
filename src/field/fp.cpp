#include "laminate/field/fp.hpp"

#include <random>
#include <stdexcept>

namespace laminate {

Fp::Fp(std::uint64_t value) : value_(value % kBaseFieldOrder) {}

Fp Fp::operator+(const Fp &other) const {
    const std::uint64_t sum = value_ + other.value_;
    Fp result;
    result.value_ = sum >= kBaseFieldOrder ? sum - kBaseFieldOrder : sum;
    return result;
}

Fp Fp::operator-(const Fp &other) const {
    Fp result;
    result.value_ = value_ >= other.value_
                        ? value_ - other.value_
                        : kBaseFieldOrder + value_ - other.value_;
    return result;
}

Fp Fp::operator*(const Fp &other) const {
    Fp result;
    result.value_ = (value_ * other.value_) % kBaseFieldOrder;
    return result;
}

Fp &Fp::operator+=(const Fp &other) { return *this = *this + other; }
Fp &Fp::operator-=(const Fp &other) { return *this = *this - other; }
Fp &Fp::operator*=(const Fp &other) { return *this = *this * other; }

Fp Fp::inverse() const {
    if (is_zero()) {
        throw std::domain_error("Fp::inverse: zero has no inverse");
    }

    std::uint64_t base = value_;
    std::uint64_t exponent = kBaseFieldOrder - 2;
    std::uint64_t result = 1;
    while (exponent != 0) {
        if ((exponent & 1U) != 0) {
            result = (result * base) % kBaseFieldOrder;
        }
        base = (base * base) % kBaseFieldOrder;
        exponent >>= 1U;
    }
    return Fp(result);
}

Fp Fp::random_element() {
    thread_local std::mt19937_64 generator{std::random_device{}()};
    thread_local std::uniform_int_distribution<std::uint64_t> distribution(
        0, kBaseFieldOrder - 1);
    return Fp(distribution(generator));
}

Fp Fp::two_adic_generator(std::size_t log_order) {
    if (log_order > kBaseFieldTwoAdicity) {
        throw std::domain_error(
            "Fp::two_adic_generator: requested order exceeds two-adicity");
    }

    constexpr std::uint64_t kMultiplicativeGenerator = 3;
    std::uint64_t base = kMultiplicativeGenerator;
    std::uint64_t exponent = (kBaseFieldOrder - 1) >> log_order;
    std::uint64_t result = 1;
    while (exponent != 0) {
        if ((exponent & 1U) != 0) {
            result = (result * base) % kBaseFieldOrder;
        }
        base = (base * base) % kBaseFieldOrder;
        exponent >>= 1U;
    }
    return Fp(result);
}

std::ostream &operator<<(std::ostream &out, const Fp &value) {
    return out << value.value();
}

} // namespace laminate
