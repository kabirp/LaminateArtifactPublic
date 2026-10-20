#ifndef LAMINATE_FIELD_FP_HPP
#define LAMINATE_FIELD_FP_HPP

/// @file fp.hpp
/// @brief Prime field F_65537 used by payload wires and BGV plaintext slots.

#include "laminate/params.hpp"

#include <cstddef>
#include <cstdint>
#include <ostream>

namespace laminate {

/// Canonical residue modulo kBaseFieldOrder. The integer constructor reduces
/// its argument; strict wire decoding belongs to deserialize_fp instead.
class Fp {
  public:
    Fp() = default;
    explicit Fp(std::uint64_t value);

    Fp operator+(const Fp &other) const;
    Fp operator-(const Fp &other) const;
    Fp operator*(const Fp &other) const;
    Fp &operator+=(const Fp &other);
    Fp &operator-=(const Fp &other);
    Fp &operator*=(const Fp &other);

    bool operator==(const Fp &other) const = default;

    static Fp zero() { return Fp(); }
    static Fp one() { return Fp(1); }
    /// Noncryptographic test/data helper backed by std::mt19937_64. Protocol
    /// challenges must come from the bound PublicCoin/Transcript interface.
    static Fp random_element();
    static Fp two_adic_generator(std::size_t log_order);

    /// Multiplicative inverse; throws std::domain_error for zero.
    Fp inverse() const;
    bool is_zero() const { return value_ == 0; }
    std::uint64_t value() const { return value_; }

  private:
    std::uint64_t value_ = 0;
};

std::ostream &operator<<(std::ostream &out, const Fp &value);

} // namespace laminate

#endif // LAMINATE_FIELD_FP_HPP
