#include "laminate/field/fq2.hpp"

#include <stdexcept>

namespace laminate {

Fq2 Fq2::operator/(const Fq2 &other) const {
    return *this * other.inverse();
}

Fq2 Fq2::inverse() const {
    if (is_zero()) {
        throw std::domain_error("Fq2::inverse: zero has no inverse");
    }
    const Fq &a = coefficients_[0];
    const Fq &b = coefficients_[1];
    const Fq non_residue(kOuterFieldQuadraticNonResidue);
    const Fq inverse_norm =
        (a * a - non_residue * (b * b)).inverse();
    return Fq2({a * inverse_norm, Fq::zero() - b * inverse_norm});
}

Fq2 Fq2::pow(std::uint64_t exponent) const {
    Fq2 base = *this;
    Fq2 result = Fq2::one();
    while (exponent != 0) {
        if ((exponent & 1U) != 0) {
            result *= base;
        }
        base *= base;
        exponent >>= 1U;
    }
    return result;
}

Fq2 Fq2::random_element() {
    return Fq2({Fq::random_element(), Fq::random_element()});
}

std::ostream &operator<<(std::ostream &out, const Fq2 &value) {
    return out << value.coefficients()[0] << " + "
               << value.coefficients()[1] << "*u";
}

} // namespace laminate
