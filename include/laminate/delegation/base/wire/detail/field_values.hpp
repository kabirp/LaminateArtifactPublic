#ifndef LAMINATE_DELEGATION_BASE_WIRE_DETAIL_FIELD_VALUES_HPP
#define LAMINATE_DELEGATION_BASE_WIRE_DETAIL_FIELD_VALUES_HPP

/// @file field_values.hpp
/// @brief Bounded field, digest, and public-or-encrypted value codecs.

#include "laminate/basefold/common.hpp"
#include "laminate/delegation/base/wire/detail/envelope.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

namespace laminate::delegation::base_wire_detail {

template <fhe::PersistableFheBackend Backend, typename StorageContext>
    requires fhe::CiphertextStorageContext<Backend, StorageContext>
std::vector<fhe::FheValue<Backend>> read_response_output_values(
    Reader &reader, const StorageContext &context, DecodeBudget &budget,
    const BaseWireDecodeLimits &limits, const char *operation) {
    if (wire_detail::read_digest(reader) !=
        Backend::storage_context_id(context)) {
        wire_detail::reject(operation,
                            "backend storage-context mismatch");
    }
    const std::size_t count = reader.read_size();
    if (count > limits.max_ciphertexts || count > reader.remaining()) {
        wire_detail::reject(
            operation, "response output count exceeds configured limit");
    }

    std::vector<fhe::FheValue<Backend>> values;
    values.reserve(count);
    for (std::size_t index = 0; index < count; ++index) {
        auto decoded = fhe::decode_self_delimiting_fhe_value<Backend>(
            context, reader.remaining_bytes(), limits.max_ciphertext_bytes,
            [&](std::span<const std::uint8_t> ciphertext) {
                budget.add_ciphertext(ciphertext.size());
                return Backend::deserialize_from_storage(context,
                                                         ciphertext);
            },
            operation);
        (void)reader.read_bytes(decoded.bytes_consumed);
        if (decoded.value.is_public()) {
            const fhe::PublicPlaintext &plaintext = decoded.value.plaintext();
            budget.add_fields(plaintext.is_scalar()
                                  ? 1U
                                  : plaintext.slots().size());
        }
        values.push_back(std::move(decoded.value));
    }
    return values;
}

inline void append_label(Bytes &output, std::string_view label,
                         const char *operation) {
    wire_detail::append_size(output, label.size(), operation);
    output.insert(output.end(), label.begin(), label.end());
}

inline void require_label(Reader &reader, std::string_view expected,
                          const char *operation) {
    const std::size_t length = reader.read_size();
    if (length != expected.size()) {
        wire_detail::reject(operation, "wrong canonical encoding tag");
    }
    const auto label = reader.read_bytes(length);
    if (!std::equal(label.begin(), label.end(), expected.begin())) {
        wire_detail::reject(operation, "wrong canonical encoding tag");
    }
}

inline void append_fpk(Bytes &output, const Fpk &value) {
    const SerializedFpk encoded = serialize(value);
    output.insert(output.end(), encoded.begin(), encoded.end());
}

inline Fpk read_fpk(Reader &reader, DecodeBudget &budget) {
    budget.add_fields(1);
    return deserialize_fpk(reader.read_bytes(kSerializedFpkBytes));
}

inline Fp read_fp(Reader &reader, DecodeBudget &budget) {
    budget.add_fields(1);
    return deserialize_fp(reader.read_bytes(kSerializedFpBytes));
}

inline void append_fpk_values(Bytes &output, std::span<const Fpk> values,
                              const char *operation) {
    wire_detail::append_size(output, values.size(), operation);
    for (const Fpk &value : values) {
        append_fpk(output, value);
    }
}

inline std::vector<Fpk> read_fpk_values(
    Reader &reader, std::size_t expected_count, DecodeBudget &budget,
    const char *operation) {
    const std::size_t count = reader.read_size();
    if (count != expected_count) {
        wire_detail::reject(operation, "unexpected field-vector length");
    }
    const std::size_t bytes = wire_detail::checked_multiply(
        count, kSerializedFpkBytes, operation);
    if (bytes > reader.remaining()) {
        wire_detail::reject(operation, "truncated field vector");
    }
    budget.add_fields(count);
    std::vector<Fpk> result;
    result.reserve(count);
    for (std::size_t index = 0; index < count; ++index) {
        result.push_back(
            deserialize_fpk(reader.read_bytes(kSerializedFpkBytes)));
    }
    return result;
}

inline std::vector<Fp> read_fp_values(
    Reader &reader, std::size_t expected_count, DecodeBudget &budget,
    const char *operation) {
    const std::size_t count = reader.read_size();
    if (count != expected_count) {
        wire_detail::reject(operation,
                            "unexpected base-field-vector length");
    }
    const std::size_t bytes = wire_detail::checked_multiply(
        count, kSerializedFpBytes, operation);
    if (bytes > reader.remaining()) {
        wire_detail::reject(operation, "truncated base-field vector");
    }
    budget.add_fields(count);
    std::vector<Fp> result;
    result.reserve(count);
    for (std::size_t index = 0; index < count; ++index) {
        result.push_back(
            deserialize_fp(reader.read_bytes(kSerializedFpBytes)));
    }
    return result;
}

inline void append_digest_path(
    Bytes &output, std::span<const basefold::Digest> path,
    const char *operation) {
    wire_detail::append_size(output, path.size(), operation);
    for (const basefold::Digest &digest : path) {
        output.insert(output.end(), digest.begin(), digest.end());
    }
}

inline std::vector<basefold::Digest> read_digest_path(
    Reader &reader, std::size_t expected_count, DecodeBudget &budget,
    const BaseWireDecodeLimits &limits, const char *operation) {
    const std::size_t count = reader.read_size();
    if (count != expected_count || count > limits.max_merkle_path_digests) {
        wire_detail::reject(operation,
                            "unexpected Merkle authentication path length");
    }
    const std::size_t bytes = wire_detail::checked_multiply(
        count, basefold::Digest{}.size(), operation);
    if (bytes > reader.remaining()) {
        wire_detail::reject(operation, "truncated Merkle path");
    }
    budget.add_digests(count);
    std::vector<basefold::Digest> result;
    result.reserve(count);
    for (std::size_t index = 0; index < count; ++index) {
        basefold::Digest digest{};
        const auto encoded = reader.read_bytes(digest.size());
        std::copy(encoded.begin(), encoded.end(), digest.begin());
        result.push_back(digest);
    }
    return result;
}

} // namespace laminate::delegation::base_wire_detail

#endif // LAMINATE_DELEGATION_BASE_WIRE_DETAIL_FIELD_VALUES_HPP
