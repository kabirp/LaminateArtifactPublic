#ifndef LAMINATE_BASEFOLD_PROOF_IO_HPP
#define LAMINATE_BASEFOLD_PROOF_IO_HPP

/// @file proof_io.hpp
/// @brief Canonical byte encoding for the focused BaseFold argument.

#include "laminate/basefold/basefold.hpp"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace laminate::basefold {

std::vector<std::uint8_t> encode_canonical(const Proof &proof);

inline std::size_t proof_size_bytes(const Proof &proof) {
    return encode_canonical(proof).size();
}

} // namespace laminate::basefold

#endif // LAMINATE_BASEFOLD_PROOF_IO_HPP
