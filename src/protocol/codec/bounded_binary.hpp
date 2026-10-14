/// @file bounded_binary.hpp
/// @brief Private canonical framing shared by protocol persistence formats.

#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace laminate::protocol::codec {

using Bytes = std::vector<std::uint8_t>;

inline std::uint64_t checked_u64(std::size_t value,
                                 std::string_view description) {
    if constexpr (sizeof(std::size_t) > sizeof(std::uint64_t)) {
        if (value > std::numeric_limits<std::uint64_t>::max()) {
            throw std::overflow_error(std::string(description) +
                                      " does not fit u64");
        }
    }
    return static_cast<std::uint64_t>(value);
}

/// Canonical little-endian writer. Format-specific encoders add their own
/// field, digest, and collection methods instead of growing this core class.
class Writer {
  public:
    void u8(std::uint8_t value) { output_.push_back(value); }

    void u64(std::uint64_t value) {
        for (std::size_t byte = 0; byte < sizeof(value); ++byte) {
            output_.push_back(
                static_cast<std::uint8_t>(value >> (8U * byte)));
        }
    }

    void size(std::size_t value, std::string_view description) {
        u64(checked_u64(value, description));
    }

    void raw(std::span<const std::uint8_t> value) {
        output_.insert(output_.end(), value.begin(), value.end());
    }

    const Bytes &view() const { return output_; }
    Bytes finish() && { return std::move(output_); }

  private:
    Bytes output_;
};

/// Bounds-checking cursor over canonical bytes. The caller supplies semantic
/// descriptions so malformed-input errors still name the owning format.
class Reader {
  public:
    explicit Reader(std::span<const std::uint8_t> input) : input_(input) {}

    std::uint8_t u8(std::string_view description) {
        return take(1, description).front();
    }

    std::uint64_t u64(std::string_view description) {
        const auto encoded = take(sizeof(std::uint64_t), description);
        std::uint64_t result = 0;
        for (std::size_t byte = 0; byte < encoded.size(); ++byte) {
            result |= static_cast<std::uint64_t>(encoded[byte])
                      << (8U * byte);
        }
        return result;
    }

    std::size_t size(std::size_t maximum,
                     std::string_view description) {
        const std::uint64_t value = u64(description);
        if (value > maximum ||
            value > std::numeric_limits<std::size_t>::max()) {
            throw std::invalid_argument(std::string(description) +
                                        " exceeds its decode limit");
        }
        return static_cast<std::size_t>(value);
    }

    std::span<const std::uint8_t> take(
        std::size_t count, std::string_view description) {
        if (position_ > input_.size() ||
            count > input_.size() - position_) {
            throw std::invalid_argument(std::string(description) +
                                        " is truncated");
        }
        const auto result = input_.subspan(position_, count);
        position_ += count;
        return result;
    }

    std::size_t position() const { return position_; }

    void finish(std::string_view trailing_data_error) const {
        if (position_ != input_.size()) {
            throw std::invalid_argument(std::string(trailing_data_error));
        }
    }

  private:
    std::span<const std::uint8_t> input_;
    std::size_t position_ = 0;
};

} // namespace laminate::protocol::codec
