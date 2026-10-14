#ifndef LAMINATE_BASEFOLD_DIGEST_HPP
#define LAMINATE_BASEFOLD_DIGEST_HPP

/// @file digest.hpp
/// @brief Digest type for BaseFold's out-of-circuit Merkle commitment.

#include <array>
#include <cstdint>

namespace laminate::basefold {

/// BLAKE2b-320 output used only for BaseFold Merkle authentication nodes.
using Digest = std::array<std::uint8_t, 40>;

} // namespace laminate::basefold

#endif // LAMINATE_BASEFOLD_DIGEST_HPP
