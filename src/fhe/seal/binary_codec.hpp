#ifndef LAMINATE_SRC_FHE_SEAL_BINARY_CODEC_HPP
#define LAMINATE_SRC_FHE_SEAL_BINARY_CODEC_HPP

/// @file binary_codec.hpp
/// @brief Canonical bounded primitives shared by SEAL persistence formats.

#include "laminate/transcript/hash.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace laminate::fhe::seal_detail {

inline void append_u64(std::vector<std::uint8_t> &output,
                       std::uint64_t value) {
    for (std::size_t byte = 0; byte < 8; ++byte) {
        output.push_back(
            static_cast<std::uint8_t>((value >> (8U * byte)) & 0xffU));
    }
}

inline std::uint64_t checked_u64(std::size_t value,
                                 const char *operation) {
    if constexpr (sizeof(std::size_t) > sizeof(std::uint64_t)) {
        if (value > std::numeric_limits<std::uint64_t>::max()) {
            throw std::invalid_argument(std::string(operation) +
                                        ": size exceeds the bundle format");
        }
    }
    return static_cast<std::uint64_t>(value);
}

inline std::size_t checked_size(std::uint64_t value,
                                const char *operation) {
    if constexpr (sizeof(std::size_t) < sizeof(std::uint64_t)) {
        if (value > std::numeric_limits<std::size_t>::max()) {
            throw std::invalid_argument(std::string(operation) +
                                        ": length exceeds this platform");
        }
    }
    return static_cast<std::size_t>(value);
}

inline void append_bool(std::vector<std::uint8_t> &output, bool value) {
    output.push_back(value ? 1U : 0U);
}

class BinaryReader {
  public:
    BinaryReader(std::span<const std::uint8_t> bytes, const char *operation)
        : bytes_(bytes), operation_(operation) {}

    std::uint8_t read_byte() {
        if (offset_ == bytes_.size()) {
            fail("truncated byte");
        }
        return bytes_[offset_++];
    }

    std::uint64_t read_u64() {
        if (offset_ > bytes_.size() || bytes_.size() - offset_ < 8) {
            fail("truncated integer");
        }
        std::uint64_t result = 0;
        for (std::size_t byte = 0; byte < 8; ++byte) {
            result |= static_cast<std::uint64_t>(bytes_[offset_++])
                      << (8U * byte);
        }
        return result;
    }

    std::size_t read_size() { return checked_size(read_u64(), operation_); }

    bool read_bool() {
        const std::uint8_t value = read_byte();
        if (value > 1) {
            fail("noncanonical Boolean");
        }
        return value != 0;
    }

    std::span<const std::uint8_t> read_bytes(std::size_t count) {
        if (offset_ > bytes_.size() || count > bytes_.size() - offset_) {
            fail("truncated byte string");
        }
        const auto result = bytes_.subspan(offset_, count);
        offset_ += count;
        return result;
    }

    std::span<const std::uint8_t> read_blob() {
        return read_bytes(read_size());
    }

    Digest read_digest() {
        Digest result{};
        const auto bytes = read_bytes(result.size());
        std::copy(bytes.begin(), bytes.end(), result.begin());
        return result;
    }

    bool empty() const { return offset_ == bytes_.size(); }
    std::size_t remaining() const { return bytes_.size() - offset_; }

    [[noreturn]] void fail(const char *reason) const {
        throw std::invalid_argument(std::string(operation_) + ": " + reason);
    }

  private:
    std::span<const std::uint8_t> bytes_;
    const char *operation_;
    std::size_t offset_ = 0;
};

} // namespace laminate::fhe::seal_detail

#endif // LAMINATE_SRC_FHE_SEAL_BINARY_CODEC_HPP
