#ifndef LAMINATE_FIELD_FQ2_HPP
#define LAMINATE_FIELD_FQ2_HPP

/// @file fq2.hpp
/// @brief Quadratic challenge extension of Laminate's native 60-bit field.

#include "laminate/field/fq.hpp"

#include <array>
#include <ostream>

namespace laminate {

/// Element a + b*u with u^2 = 7. Seven is a quadratic non-residue modulo q.
class Fq2 {
  public:
    using Coefficients = std::array<Fq, 2>;

    Fq2() = default;
    explicit Fq2(Coefficients coefficients) : coefficients_(coefficients) {}

    static Fq2 from_base(const Fq &value) {
        return Fq2({value, Fq::zero()});
    }
    static Fq2 zero() { return Fq2(); }
    static Fq2 one() { return from_base(Fq::one()); }
    /// Noncryptographic helper sampling each coefficient with
    /// Fq::random_element(); use the transcript for protocol challenges.
    static Fq2 random_element();

    Fq2 operator+(const Fq2 &other) const {
        return Fq2({coefficients_[0] + other.coefficients_[0],
                    coefficients_[1] + other.coefficients_[1]});
    }
    Fq2 operator-(const Fq2 &other) const {
        return Fq2({coefficients_[0] - other.coefficients_[0],
                    coefficients_[1] - other.coefficients_[1]});
    }
    Fq2 operator-() const { return Fq2::zero() - *this; }
    Fq2 operator*(const Fq2 &other) const {
        const Fq &a = coefficients_[0];
        const Fq &b = coefficients_[1];
        const Fq &c = other.coefficients_[0];
        const Fq &d = other.coefficients_[1];
        const Fq ac = a * c;
        const Fq bd = b * d;
        const Fq cross = (a + b) * (c + d) - ac - bd;
        const Fq seven_bd = (bd + bd + bd + bd) + (bd + bd + bd);
        return Fq2({ac + seven_bd, cross});
    }
    Fq2 operator/(const Fq2 &other) const;
    Fq2 operator*(const Fq &scalar) const {
        return Fq2(
            {coefficients_[0] * scalar, coefficients_[1] * scalar});
    }
    Fq2 operator+(const Fq &value) const {
        return Fq2({coefficients_[0] + value, coefficients_[1]});
    }
    Fq2 &operator+=(const Fq2 &other) { return *this = *this + other; }
    Fq2 &operator-=(const Fq2 &other) { return *this = *this - other; }
    Fq2 &operator*=(const Fq2 &other) { return *this = *this * other; }
    Fq2 &operator/=(const Fq2 &other) { return *this = *this / other; }

    bool operator==(const Fq2 &other) const = default;

    Fq2 inverse() const;
    Fq2 pow(std::uint64_t exponent) const;
    bool is_zero() const {
        return coefficients_[0].is_zero() && coefficients_[1].is_zero();
    }
    const Coefficients &coefficients() const { return coefficients_; }

  private:
    Coefficients coefficients_{};
};

std::ostream &operator<<(std::ostream &out, const Fq2 &value);

} // namespace laminate

#endif // LAMINATE_FIELD_FQ2_HPP
