#ifndef LAMINATE_TRANSCRIPT_PUBLIC_COIN_HPP
#define LAMINATE_TRANSCRIPT_PUBLIC_COIN_HPP

/// @file public_coin.hpp
/// @brief Hash-agnostic public-coin channel for interactive protocol code.

#include "laminate/field/fpk.hpp"
#include "laminate/field/fq2.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

namespace laminate {

/// Message/challenge boundary used by interactive PIOPs and PCS protocols.
///
/// Spartan, its factored matrix argument, and BaseFold depend only on this
/// interface. BCS16 supplies a concrete SHA-256
/// `Transcript` when compiling them non-interactively.
class PublicCoin {
  public:
    virtual ~PublicCoin() = default;

    virtual void observe(std::string_view label,
                         std::span<const std::uint8_t> bytes) = 0;
    virtual void observe(std::string_view label, std::uint64_t value) = 0;

    virtual Fpk challenge_fpk() = 0;
    virtual Fq challenge_fq() = 0;
    virtual Fq2 challenge_fq2() = 0;
    virtual std::vector<Fq2> challenge_fq2_vector(std::size_t count) = 0;
    virtual std::vector<Fpk> challenge_vector(std::size_t count) = 0;
    virtual std::vector<bool> challenge_bits(std::size_t count) = 0;
};

} // namespace laminate

#endif // LAMINATE_TRANSCRIPT_PUBLIC_COIN_HPP
