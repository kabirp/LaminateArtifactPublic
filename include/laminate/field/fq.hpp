#ifndef LAMINATE_FIELD_FQ_HPP
#define LAMINATE_FIELD_FQ_HPP

/// @file fq.hpp
/// @brief Native 60-bit field used by packing, Poseidon, and Spartan.

#include "laminate/params.hpp"

#include <cstddef>
#include <cstdint>
#include <ostream>

namespace laminate {

/// Native-field arithmetic stored in Montgomery form. The constructor accepts
/// an ordinary integer and reduces it modulo q; value() returns the canonical
/// ordinary residue. Persist values through field/serialization.hpp rather
/// than copying the in-memory representation.
class Fq {
  public:
    Fq() = default;
    explicit Fq(std::uint64_t value)
        : value_(to_montgomery(value >= kOuterFieldOrder
                                   ? value % kOuterFieldOrder
                                   : value)) {}

    Fq operator+(const Fq &other) const {
        const std::uint64_t sum = value_ + other.value_;
        return from_montgomery(
            sum >= kOuterFieldOrder ? sum - kOuterFieldOrder : sum);
    }
    Fq operator-(const Fq &other) const {
        return from_montgomery(
            value_ >= other.value_
                ? value_ - other.value_
                : kOuterFieldOrder + value_ - other.value_);
    }
    Fq operator*(const Fq &other) const {
        return from_montgomery(montgomery_reduce(
            static_cast<__uint128_t>(value_) * other.value_));
    }
    Fq &operator+=(const Fq &other) { return *this = *this + other; }
    Fq &operator-=(const Fq &other) { return *this = *this - other; }
    Fq &operator*=(const Fq &other) { return *this = *this * other; }

    bool operator==(const Fq &other) const = default;

    static Fq zero() { return Fq(); }
    static Fq one() { return from_montgomery(kMontgomeryOne); }
    /// Noncryptographic test/data helper backed by std::mt19937_64. Protocol
    /// challenges must come from the bound PublicCoin/Transcript interface.
    static Fq random_element();
    static Fq two_adic_generator(std::size_t log_order);

    Fq pow(std::uint64_t exponent) const;
    /// Multiplicative inverse; throws std::domain_error for zero.
    Fq inverse() const;
    bool is_zero() const { return value_ == 0; }
    std::uint64_t value() const { return montgomery_reduce(value_); }
    static constexpr std::uint64_t modulus() { return kOuterFieldOrder; }

  private:
    /// `R=2^64` Montgomery arithmetic avoids a 128-by-64 division in every
    /// multiplication.  This matters for Spartan: its linear-time kernels
    /// perform billions of native-field products at target scale.
    static constexpr std::uint64_t kMontgomeryNegInverse =
        1'053'858'393'162'252'287ULL;
    static constexpr std::uint64_t kMontgomeryOne =
        531'151'389'951'262'703ULL;
    static constexpr std::uint64_t kMontgomeryR2 =
        741'399'339'714'807'730ULL;

    static std::uint64_t montgomery_reduce(__uint128_t value) {
        const std::uint64_t multiplier =
            static_cast<std::uint64_t>(value) * kMontgomeryNegInverse;
        const __uint128_t quotient =
            (value + static_cast<__uint128_t>(multiplier) *
                         kOuterFieldOrder) >>
            64U;
        const std::uint64_t reduced = static_cast<std::uint64_t>(quotient);
        return reduced >= kOuterFieldOrder ? reduced - kOuterFieldOrder
                                           : reduced;
    }

    static std::uint64_t to_montgomery(std::uint64_t canonical) {
        return montgomery_reduce(
            static_cast<__uint128_t>(canonical) * kMontgomeryR2);
    }

    static Fq from_montgomery(std::uint64_t value) {
        Fq result;
        result.value_ = value;
        return result;
    }

    std::uint64_t value_ = 0;
};

std::ostream &operator<<(std::ostream &out, const Fq &value);

} // namespace laminate

#endif // LAMINATE_FIELD_FQ_HPP
