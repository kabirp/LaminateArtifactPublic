/// @file layer_format.cpp
/// @brief Layer-record framing and rolling digests.

#include "layer_format.hpp"

#include "laminate/transcript/hash.hpp"

#include <array>
#include <string_view>
#include <vector>

namespace laminate::payload {
namespace trace_store_format {

Digest initial_layer_digest(std::size_t layer_index,
                            std::size_t record_count) {
    static constexpr std::string_view label =
        "LaminateImpl/FileTraceLayer/v4";
    std::vector<std::uint8_t> bytes(label.begin(), label.end());
    append_u64(bytes, checked_u64(layer_index, "layer index"));
    append_u64(bytes,
               checked_u64(record_count, "record count"));
    return sha256(bytes);
}

Digest extend_layer_digest(const Digest &previous, std::size_t record_index,
                           std::size_t record_length,
                           const Digest &record_digest) {
    std::vector<std::uint8_t> bytes;
    bytes.reserve(previous.size() + 2 * sizeof(std::uint64_t) +
                  record_digest.size());
    append_digest(bytes, previous);
    append_u64(bytes, checked_u64(record_index, "record index"));
    append_u64(bytes,
               checked_u64(record_length, "record length"));
    append_digest(bytes, record_digest);
    return sha256(bytes);
}

void write_exact(ExclusiveOutputFile &output,
                 std::span<const std::uint8_t> bytes,
                 const char *description) {
    output.write(bytes, description);
}

void write_u64(ExclusiveOutputFile &output, std::uint64_t value,
               const char *description) {
    std::array<std::uint8_t, 8> bytes{};
    for (std::size_t byte = 0; byte < bytes.size(); ++byte) {
        bytes[byte] = static_cast<std::uint8_t>(
            (value >> (8U * byte)) & 0xffU);
    }
    write_exact(output, bytes, description);
}

void write_u64_at(ExclusiveOutputFile &output, std::uint64_t offset,
                  std::uint64_t value, const char *description) {
    std::array<std::uint8_t, 8> bytes{};
    for (std::size_t byte = 0; byte < bytes.size(); ++byte) {
        bytes[byte] = static_cast<std::uint8_t>(
            (value >> (8U * byte)) & 0xffU);
    }
    output.write_at(offset, bytes, description);
}

void read_exact(BoundInputFile &input, std::span<std::uint8_t> output,
                const char *description) {
    input.read(output, description);
}

std::uint64_t read_u64(BoundInputFile &input, const char *description) {
    std::array<std::uint8_t, 8> bytes{};
    read_exact(input, bytes, description);
    std::uint64_t result = 0;
    for (std::size_t byte = 0; byte < bytes.size(); ++byte) {
        result |= static_cast<std::uint64_t>(bytes[byte]) << (8U * byte);
    }
    return result;
}

std::uint64_t stream_position(const BoundInputFile &input,
                              const char *description) {
    return input.position(description);
}

std::uint64_t stream_position(const ExclusiveOutputFile &output,
                              const char *description) {
    return output.position(description);
}

} // namespace trace_store_format
} // namespace laminate::payload
