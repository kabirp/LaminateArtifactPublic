#ifndef LAMINATE_TRANSCRIPT_HASH_HPP
#define LAMINATE_TRANSCRIPT_HASH_HPP

/// @file hash.hpp
/// @brief SHA-256 interface for Fiat--Shamir and conventional digests.

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>

namespace laminate {

using Digest = std::array<std::uint8_t, 32>;

/// Incremental SHA-256 state. `update` retains at most one 64-byte block, so
/// large files can be authenticated without first materializing them.
class Sha256Hasher {
  public:
    Sha256Hasher();
    ~Sha256Hasher();

    Sha256Hasher(const Sha256Hasher &) = delete;
    Sha256Hasher &operator=(const Sha256Hasher &) = delete;
    Sha256Hasher(Sha256Hasher &&) noexcept;
    Sha256Hasher &operator=(Sha256Hasher &&) noexcept;

    void update(std::span<const std::uint8_t> input);
    Digest finish();

  private:
    struct State;
    std::unique_ptr<State> state_;
};

/// Return SHA-256(input), following FIPS 180-4.
Digest sha256(std::span<const std::uint8_t> input);

} // namespace laminate

#endif // LAMINATE_TRANSCRIPT_HASH_HPP
