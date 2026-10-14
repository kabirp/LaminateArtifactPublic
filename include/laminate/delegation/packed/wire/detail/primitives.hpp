#ifndef LAMINATE_DELEGATION_PACKED_WIRE_DETAIL_PRIMITIVES_HPP
#define LAMINATE_DELEGATION_PACKED_WIRE_DETAIL_PRIMITIVES_HPP

/// @file packed/wire/detail/primitives.hpp
/// @brief Shared bounded byte, binding, and FHE-value codecs.

#include "laminate/fhe/storage/ciphertext.hpp"
#include "laminate/fhe/storage/value_codec.hpp"
#include "laminate/field/serialization.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace laminate::delegation {

namespace wire_detail {

using Bytes = std::vector<std::uint8_t>;

[[noreturn]] inline void reject(const char *operation,
                                std::string_view reason) {
    throw std::invalid_argument(std::string(operation) + ": " +
                                std::string(reason));
}

inline void append_u16(Bytes &output, std::uint16_t value) {
    output.push_back(static_cast<std::uint8_t>(value & 0xffU));
    output.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xffU));
}

inline void append_u64(Bytes &output, std::uint64_t value) {
    for (std::size_t byte = 0; byte < 8; ++byte) {
        output.push_back(static_cast<std::uint8_t>(
            (value >> (8U * byte)) & std::uint64_t{0xff}));
    }
}

inline void append_size(Bytes &output, std::size_t value,
                        const char *operation) {
    if (value > std::numeric_limits<std::uint64_t>::max()) {
        reject(operation, "size does not fit u64");
    }
    append_u64(output, static_cast<std::uint64_t>(value));
}

inline void patch_size(Bytes &output, std::size_t offset,
                       std::size_t value, const char *operation) {
    if (value > std::numeric_limits<std::uint64_t>::max() ||
        offset > output.size() || output.size() - offset < 8U) {
        reject(operation, "size patch is out of range");
    }
    const std::uint64_t encoded = static_cast<std::uint64_t>(value);
    for (std::size_t byte = 0; byte < 8; ++byte) {
        output[offset + byte] = static_cast<std::uint8_t>(
            (encoded >> (8U * byte)) & std::uint64_t{0xff});
    }
}

inline std::size_t checked_add(std::size_t left, std::size_t right,
                               const char *operation) {
    if (right > std::numeric_limits<std::size_t>::max() - left) {
        reject(operation, "size addition overflows");
    }
    return left + right;
}

inline std::size_t checked_multiply(std::size_t left, std::size_t right,
                                    const char *operation) {
    if (left != 0 && right > std::numeric_limits<std::size_t>::max() / left) {
        reject(operation, "size multiplication overflows");
    }
    return left * right;
}

class Reader {
  public:
    Reader(std::span<const std::uint8_t> input, const char *operation)
        : input_(input), operation_(operation) {}

    std::size_t remaining() const { return input_.size() - offset_; }

    std::span<const std::uint8_t> remaining_bytes() const {
        return input_.subspan(offset_);
    }

    std::uint8_t read_u8() {
        return read_bytes(1).front();
    }

    std::uint16_t read_u16() {
        const auto bytes = read_bytes(2);
        return static_cast<std::uint16_t>(bytes[0]) |
               static_cast<std::uint16_t>(
                   static_cast<std::uint16_t>(bytes[1]) << 8U);
    }

    std::uint64_t read_u64() {
        const auto bytes = read_bytes(8);
        std::uint64_t result = 0;
        for (std::size_t byte = 0; byte < 8; ++byte) {
            result |= static_cast<std::uint64_t>(bytes[byte]) <<
                      (8U * byte);
        }
        return result;
    }

    std::size_t read_size() {
        const std::uint64_t value = read_u64();
        if (value > std::numeric_limits<std::size_t>::max()) {
            reject(operation_, "encoded size does not fit size_t");
        }
        return static_cast<std::size_t>(value);
    }

    std::span<const std::uint8_t> read_bytes(std::size_t count) {
        if (count > remaining()) {
            reject(operation_, "truncated message");
        }
        const auto result = input_.subspan(offset_, count);
        offset_ += count;
        return result;
    }

    void require_end() const {
        if (remaining() != 0) {
            reject(operation_, "trailing payload bytes");
        }
    }

  private:
    std::span<const std::uint8_t> input_;
    std::size_t offset_ = 0;
    const char *operation_;
};

inline void append_digest(Bytes &output, const Digest &digest) {
    output.insert(output.end(), digest.begin(), digest.end());
}

inline Digest read_digest(Reader &reader) {
    Digest digest{};
    const auto bytes = reader.read_bytes(digest.size());
    std::copy(bytes.begin(), bytes.end(), digest.begin());
    return digest;
}

template <typename Message>
void append_bindings(Bytes &output, const Message &message) {
    append_digest(output, message.setup_id);
    append_digest(output, message.session_id);
    append_digest(output, message.circuit_id);
    append_digest(output, message.trace_id);
}

struct Bindings {
    Digest setup_id{};
    Digest session_id{};
    Digest circuit_id{};
    Digest trace_id{};
};

inline Bindings read_bindings(Reader &reader) {
    return Bindings{read_digest(reader), read_digest(reader),
                    read_digest(reader), read_digest(reader)};
}

inline bool all_zero(const Digest &digest) {
    return std::all_of(digest.begin(), digest.end(),
                       [](std::uint8_t byte) { return byte == 0; });
}

inline void validate_bindings(const Bindings &bindings,
                              const char *operation) {
    if (all_zero(bindings.setup_id) || all_zero(bindings.session_id) ||
        all_zero(bindings.circuit_id) || all_zero(bindings.trace_id)) {
        reject(operation, "zero public binding");
    }
}

template <typename Message>
void validate_message_bindings(const Message &message,
                               const char *operation) {
    validate_bindings(
        Bindings{message.setup_id, message.session_id, message.circuit_id,
                 message.trace_id},
        operation);
}

inline void append_dimensions(Bytes &output,
                              const payload::LayerDimensions &dimensions,
                              const char *operation) {
    append_size(output, dimensions.logical_size, operation);
    append_size(output, dimensions.padded_size, operation);
    append_size(output, dimensions.payload_size, operation);
    append_size(output, dimensions.forward_size, operation);
}

inline bool is_power_of_two(std::size_t value) {
    return value != 0 && (value & (value - 1U)) == 0;
}

inline void validate_output_dimensions(
    const payload::LayerDimensions &dimensions, std::size_t value_count,
    const char *operation) {
    if (dimensions.logical_size == 0 ||
        dimensions.logical_size > dimensions.padded_size ||
        !is_power_of_two(dimensions.padded_size) ||
        dimensions.payload_size >
            std::numeric_limits<std::size_t>::max() -
                dimensions.forward_size ||
        dimensions.payload_size + dimensions.forward_size !=
            dimensions.logical_size ||
        value_count != dimensions.logical_size) {
        reject(operation, "invalid output dimensions");
    }
}

inline payload::LayerDimensions read_dimensions(Reader &reader) {
    return payload::LayerDimensions{
        reader.read_size(), reader.read_size(), reader.read_size(),
        reader.read_size()};
}

template <fhe::PersistableFheBackend Backend, typename StorageContext>
    requires fhe::CiphertextStorageContext<Backend, StorageContext>
void append_ciphertexts(
    Bytes &output, const StorageContext &context,
    std::span<const typename Backend::Ciphertext> ciphertexts,
    const char *operation) {
    append_digest(output, Backend::storage_context_id(context));
    append_size(output, ciphertexts.size(), operation);
    for (const auto &ciphertext : ciphertexts) {
        const Bytes encoded =
            Backend::serialize_for_storage(context, ciphertext);
        append_size(output, encoded.size(), operation);
        output.insert(output.end(), encoded.begin(), encoded.end());
    }
}

template <fhe::PersistableFheBackend Backend, typename StorageContext,
          typename Limits>
    requires fhe::CiphertextStorageContext<Backend, StorageContext>
std::vector<typename Backend::Ciphertext> read_ciphertexts(
    Reader &reader, const StorageContext &context,
    const Limits &limits, const char *operation) {
    if (read_digest(reader) != Backend::storage_context_id(context)) {
        reject(operation, "backend storage-context mismatch");
    }
    const std::size_t count = reader.read_size();
    if (count > limits.max_ciphertexts) {
        reject(operation, "ciphertext count exceeds configured limit");
    }
    if (count > reader.remaining() / 8U) {
        reject(operation, "ciphertext count exceeds remaining payload");
    }

    std::vector<typename Backend::Ciphertext> ciphertexts;
    ciphertexts.reserve(count);
    std::size_t total_ciphertext_bytes = 0;
    for (std::size_t index = 0; index < count; ++index) {
        const std::size_t ciphertext_bytes = reader.read_size();
        if (ciphertext_bytes > limits.max_ciphertext_bytes) {
            reject(operation, "ciphertext exceeds configured byte limit");
        }
        total_ciphertext_bytes = checked_add(
            total_ciphertext_bytes, ciphertext_bytes, operation);
        if (total_ciphertext_bytes >
            limits.max_total_ciphertext_bytes) {
            reject(operation,
                   "ciphertext batch exceeds configured byte limit");
        }
        ciphertexts.push_back(Backend::deserialize_from_storage(
            context, reader.read_bytes(ciphertext_bytes)));
    }
    return ciphertexts;
}

template <fhe::PersistableFheBackend Backend, typename StorageContext>
    requires fhe::CiphertextStorageContext<Backend, StorageContext>
void append_fhe_values(
    Bytes &output, const StorageContext &context,
    std::span<const fhe::FheValue<Backend>> values,
    const char *operation) {
    append_digest(output, Backend::storage_context_id(context));
    append_size(output, values.size(), operation);
    for (const fhe::FheValue<Backend> &value : values) {
        fhe::append_self_delimiting_fhe_value<Backend>(
            output, context, value, operation);
    }
}

template <fhe::PersistableFheBackend Backend, typename StorageContext,
          typename Limits>
    requires fhe::CiphertextStorageContext<Backend, StorageContext>
std::vector<fhe::FheValue<Backend>> read_fhe_values(
    Reader &reader, const StorageContext &context,
    const Limits &limits, const char *operation) {
    if (read_digest(reader) != Backend::storage_context_id(context)) {
        reject(operation, "backend storage-context mismatch");
    }
    const std::size_t count = reader.read_size();
    if (count > limits.max_ciphertexts) {
        reject(operation, "FHE-value count exceeds configured limit");
    }
    if (count > reader.remaining()) {
        reject(operation, "FHE-value count exceeds remaining payload");
    }

    std::vector<fhe::FheValue<Backend>> values;
    values.reserve(count);
    std::size_t total_ciphertext_bytes = 0;
    for (std::size_t index = 0; index < count; ++index) {
        auto decoded = fhe::decode_self_delimiting_fhe_value<Backend>(
            context, reader.remaining_bytes(), limits.max_ciphertext_bytes,
            [&](std::span<const std::uint8_t> ciphertext) {
                total_ciphertext_bytes = checked_add(
                    total_ciphertext_bytes, ciphertext.size(), operation);
                if (total_ciphertext_bytes >
                    limits.max_total_ciphertext_bytes) {
                    reject(operation,
                           "ciphertext batch exceeds configured byte limit");
                }
                return Backend::deserialize_from_storage(context,
                                                         ciphertext);
            },
            operation);
        (void)reader.read_bytes(decoded.bytes_consumed);
        values.push_back(std::move(decoded.value));
    }
    return values;
}

} // namespace wire_detail

} // namespace laminate::delegation

#endif // LAMINATE_DELEGATION_PACKED_WIRE_DETAIL_PRIMITIVES_HPP
