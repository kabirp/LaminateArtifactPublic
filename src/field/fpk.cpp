#include "laminate/field/fpk.hpp"

#include <array>
#include <cstddef>
#include <stdexcept>
#include <vector>

namespace laminate {
namespace {

using Polynomial = std::vector<Fp>;

int degree(const Polynomial &polynomial) {
    for (int i = static_cast<int>(polynomial.size()) - 1; i >= 0; --i) {
        if (!polynomial[static_cast<std::size_t>(i)].is_zero()) {
            return i;
        }
    }
    return -1;
}

void subtract_multiple(Polynomial &target, const Fp &coefficient,
                       std::size_t shift, const Polynomial &source,
                       int source_degree) {
    const std::size_t top =
        static_cast<std::size_t>(source_degree) + shift;
    if (target.size() <= top) {
        target.resize(top + 1);
    }
    for (std::size_t i = 0;
         i <= static_cast<std::size_t>(source_degree); ++i) {
        target[i + shift] -= coefficient * source[i];
    }
}

} // namespace

Fpk Fpk::from_base(const Fp &value) {
    Coefficients coefficients{};
    coefficients[0] = value;
    return Fpk(coefficients);
}

Fpk Fpk::operator+(const Fpk &other) const {
    Coefficients result{};
    for (std::size_t i = 0; i < kExtensionDegree; ++i) {
        result[i] = coefficients_[i] + other.coefficients_[i];
    }
    return Fpk(result);
}

Fpk Fpk::operator-(const Fpk &other) const {
    Coefficients result{};
    for (std::size_t i = 0; i < kExtensionDegree; ++i) {
        result[i] = coefficients_[i] - other.coefficients_[i];
    }
    return Fpk(result);
}

Fpk Fpk::operator*(const Fpk &other) const {
    constexpr std::size_t k = kExtensionDegree;
    std::array<Fp, 2 * k - 1> product{};
    for (std::size_t i = 0; i < k; ++i) {
        if (coefficients_[i].is_zero()) {
            continue;
        }
        for (std::size_t j = 0; j < k; ++j) {
            product[i + j] += coefficients_[i] * other.coefficients_[j];
        }
    }

    for (std::size_t i = 2 * k - 2; i >= k; --i) {
        const Fp high = product[i];
        if (high.is_zero()) {
            continue;
        }
        for (std::size_t j = 0; j < k; ++j) {
            if (kExtensionModulusPoly[j] != 0) {
                product[i - k + j] -=
                    high * Fp(kExtensionModulusPoly[j]);
            }
        }
    }

    Coefficients result{};
    for (std::size_t i = 0; i < k; ++i) {
        result[i] = product[i];
    }
    return Fpk(result);
}

Fpk Fpk::operator+(const Fp &value) const {
    Coefficients result = coefficients_;
    result[0] += value;
    return Fpk(result);
}

Fpk Fpk::operator*(const Fp &scalar) const {
    Coefficients result{};
    for (std::size_t i = 0; i < kExtensionDegree; ++i) {
        result[i] = coefficients_[i] * scalar;
    }
    return Fpk(result);
}

Fpk &Fpk::operator+=(const Fpk &other) { return *this = *this + other; }
Fpk &Fpk::operator-=(const Fpk &other) { return *this = *this - other; }
Fpk &Fpk::operator*=(const Fpk &other) { return *this = *this * other; }

Fpk Fpk::inverse() const {
    if (is_zero()) {
        throw std::domain_error("Fpk::inverse: zero has no inverse");
    }

    constexpr std::size_t k = kExtensionDegree;
    Polynomial previous_remainder(k + 1);
    for (std::size_t i = 0; i <= k; ++i) {
        previous_remainder[i] = Fp(kExtensionModulusPoly[i]);
    }
    Polynomial current_remainder(coefficients_.begin(), coefficients_.end());
    current_remainder.resize(k + 1);

    Polynomial previous_coefficient(k + 1);
    Polynomial current_coefficient(k + 1);
    current_coefficient[0] = Fp::one();

    while (degree(current_remainder) > 0) {
        const int divisor_degree = degree(current_remainder);
        const Fp inverse_lead =
            current_remainder[static_cast<std::size_t>(divisor_degree)]
                .inverse();
        Polynomial remainder = previous_remainder;
        Polynomial next_coefficient = previous_coefficient;
        const int coefficient_degree = degree(current_coefficient);

        for (int current_degree = degree(remainder);
             current_degree >= divisor_degree;
             current_degree = degree(remainder)) {
            const Fp quotient =
                remainder[static_cast<std::size_t>(current_degree)] *
                inverse_lead;
            const std::size_t shift = static_cast<std::size_t>(
                current_degree - divisor_degree);
            subtract_multiple(remainder, quotient, shift, current_remainder,
                              divisor_degree);
            if (coefficient_degree >= 0) {
                subtract_multiple(next_coefficient, quotient, shift,
                                  current_coefficient, coefficient_degree);
            }
        }

        previous_remainder = std::move(current_remainder);
        current_remainder = std::move(remainder);
        previous_coefficient = std::move(current_coefficient);
        current_coefficient = std::move(next_coefficient);
    }

    const Fp gcd_inverse = current_remainder[0].inverse();
    Coefficients result{};
    for (std::size_t i = 0; i < k; ++i) {
        result[i] = current_coefficient[i] * gcd_inverse;
    }
    return Fpk(result);
}

Fpk Fpk::random_element() {
    Coefficients coefficients{};
    for (Fp &coefficient : coefficients) {
        coefficient = Fp::random_element();
    }
    return Fpk(coefficients);
}

bool Fpk::is_zero() const {
    for (const Fp &coefficient : coefficients_) {
        if (!coefficient.is_zero()) {
            return false;
        }
    }
    return true;
}

std::ostream &operator<<(std::ostream &out, const Fpk &value) {
    out << '[';
    for (std::size_t i = 0; i < kExtensionDegree; ++i) {
        if (i != 0) {
            out << ", ";
        }
        out << value.coefficients()[i];
    }
    return out << ']';
}

} // namespace laminate
