#ifndef LAMINATE_GKR_DETAIL_SHARED_ENCODING_CANONICAL_HPP
#define LAMINATE_GKR_DETAIL_SHARED_ENCODING_CANONICAL_HPP

/// @file canonical.hpp
/// @brief Primitive canonical encodings shared by GKR transcripts and proofs.

#include "laminate/field/serialization.hpp"
#include "laminate/fhe/extension.hpp"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <stdexcept>
#include <vector>

namespace laminate::gkr::detail::canonical_encoding {

inline void append_u64(std::vector<std::uint8_t> &output,
                       std::uint64_t value) {
    for (std::size_t byte = 0; byte < 8; ++byte) {
        output.push_back(static_cast<std::uint8_t>(
            (value >> (8U * byte)) & std::uint64_t{0xff}));
    }
}

inline void append_size(std::vector<std::uint8_t> &output,
                        std::size_t value) {
    if (value > std::numeric_limits<std::uint64_t>::max()) {
        throw std::overflow_error("GKR encoding: size does not fit u64");
    }
    append_u64(output, static_cast<std::uint64_t>(value));
}

inline void append_fpk(std::vector<std::uint8_t> &output,
                       const Fpk &value) {
    const SerializedFpk encoded = serialize(value);
    output.insert(output.end(), encoded.begin(), encoded.end());
}

inline void append_point(std::vector<std::uint8_t> &output,
                         std::span<const Fpk> point) {
    append_size(output, point.size());
    for (const Fpk &coordinate : point) {
        append_fpk(output, coordinate);
    }
}

template <fhe::FheBackend Backend>
void append_extension(
    std::vector<std::uint8_t> &output,
    const fhe::ExtensionValue<Backend> &value) {
    const std::vector<std::uint8_t> encoded =
        fhe::serialize_extension_value<Backend>(value);
    append_size(output, encoded.size());
    output.insert(output.end(), encoded.begin(), encoded.end());
}

} // namespace laminate::gkr::detail::canonical_encoding

#endif // LAMINATE_GKR_DETAIL_SHARED_ENCODING_CANONICAL_HPP
