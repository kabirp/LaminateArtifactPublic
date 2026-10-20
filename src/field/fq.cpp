#include "laminate/field/fq.hpp"

#include <random>
#include <stdexcept>

namespace laminate {
Fq Fq::pow(std::uint64_t exponent) const {
    Fq base = *this;
    Fq result = Fq::one();
    while (exponent != 0) {
        if ((exponent & 1U) != 0) {
            result *= base;
        }
        base *= base;
        exponent >>= 1U;
    }
    return result;
}

Fq Fq::inverse() const {
    if (is_zero()) {
        throw std::domain_error("Fq::inverse: zero has no inverse");
    }
    return pow(kOuterFieldOrder - 2);
}

Fq Fq::random_element() {
    thread_local std::mt19937_64 generator{std::random_device{}()};
    thread_local std::uniform_int_distribution<std::uint64_t> distribution(
        0, kOuterFieldOrder - 1);
    return Fq(distribution(generator));
}

Fq Fq::two_adic_generator(std::size_t log_order) {
    if (log_order > kOuterFieldTwoAdicity) {
        throw std::domain_error(
            "Fq::two_adic_generator: requested order exceeds two-adicity");
    }
    Fq result(kOuterFieldMaxTwoAdicRoot);
    for (std::size_t bit = log_order; bit < kOuterFieldTwoAdicity; ++bit) {
        result *= result;
    }
    return result;
}

std::ostream &operator<<(std::ostream &out, const Fq &value) {
    return out << value.value();
}

} // namespace laminate
