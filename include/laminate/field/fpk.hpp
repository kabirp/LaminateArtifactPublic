#ifndef LAMINATE_FIELD_FPK_HPP
#define LAMINATE_FIELD_FPK_HPP

/// @file fpk.hpp
/// @brief Degree-eight extension field used for GKR challenges.

#include "laminate/field/fp.hpp"
#include "laminate/params.hpp"

#include <array>
#include <ostream>

namespace laminate {

/// Polynomial-basis element of Fp[x]/(x^8 + x^3 + 1). Coefficients are stored
/// from constant term through degree seven, matching extension ciphertexts.
class Fpk {
  public:
    using Coefficients = std::array<Fp, kExtensionDegree>;

    Fpk() = default;
    explicit Fpk(const Coefficients &coefficients)
        : coefficients_(coefficients) {}

    static Fpk from_base(const Fp &value);
    static Fpk zero() { return Fpk(); }
    static Fpk one() { return from_base(Fp::one()); }
    /// Noncryptographic helper sampling each coefficient with
    /// Fp::random_element(); use the transcript for protocol challenges.
    static Fpk random_element();

    Fpk operator+(const Fpk &other) const;
    Fpk operator-(const Fpk &other) const;
    Fpk operator*(const Fpk &other) const;
    Fpk operator+(const Fp &value) const;
    Fpk operator*(const Fp &scalar) const;
    Fpk &operator+=(const Fpk &other);
    Fpk &operator-=(const Fpk &other);
    Fpk &operator*=(const Fpk &other);

    bool operator==(const Fpk &other) const = default;

    Fpk inverse() const;
    bool is_zero() const;
    const Coefficients &coefficients() const { return coefficients_; }

  private:
    Coefficients coefficients_{};
};

std::ostream &operator<<(std::ostream &out, const Fpk &value);

} // namespace laminate

#endif // LAMINATE_FIELD_FPK_HPP
