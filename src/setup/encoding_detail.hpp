#ifndef LAMINATE_SRC_SETUP_ENCODING_DETAIL_HPP
#define LAMINATE_SRC_SETUP_ENCODING_DETAIL_HPP

#include <cstddef>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace laminate::setup_detail {

using Bytes = std::vector<std::uint8_t>;

inline void append_u64(Bytes &output, std::size_t value) {
    if (value > std::numeric_limits<std::uint64_t>::max()) {
        throw std::overflow_error(
            "encode_canonical(PublicSetup): size does not fit u64");
    }
    const std::uint64_t word = static_cast<std::uint64_t>(value);
    for (std::size_t byte = 0; byte < 8; ++byte) {
        output.push_back(
            static_cast<std::uint8_t>((word >> (8U * byte)) & 0xffU));
    }
}

inline void append_label(Bytes &output, std::string_view label) {
    append_u64(output, label.size());
    output.insert(output.end(), label.begin(), label.end());
}

} // namespace laminate::setup_detail

#endif // LAMINATE_SRC_SETUP_ENCODING_DETAIL_HPP
