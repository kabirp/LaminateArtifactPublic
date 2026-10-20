#ifndef LAMINATE_FHE_STORAGE_VALUE_CODEC_HPP
#define LAMINATE_FHE_STORAGE_VALUE_CODEC_HPP

/// @file value_codec.hpp
/// @brief Canonical storage and process-boundary encodings for `FheValue`.

#include "laminate/fhe/storage/ciphertext.hpp"
#include "laminate/fhe/value.hpp"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace laminate::fhe {

/// Stable tags shared by the encrypted-trace v4 and delegation-wire v4
/// formats. Do not renumber these values without introducing new outer format
/// versions.
enum class FheValueRecordTag : std::uint8_t {
    PublicScalar = 0,
    PublicSlots = 1,
    Ciphertext = 2,
};

namespace value_codec_detail {

[[noreturn]] inline void reject(std::string_view operation,
                                std::string_view reason) {
    throw std::invalid_argument(std::string(operation) + ": " +
                                std::string(reason));
}

inline void append_u64(std::vector<std::uint8_t> &output,
                       std::uint64_t value) {
    for (std::size_t byte = 0; byte < sizeof(value); ++byte) {
        output.push_back(static_cast<std::uint8_t>(
            (value >> (8U * byte)) & std::uint64_t{0xff}));
    }
}

inline std::uint64_t read_u64(std::span<const std::uint8_t> encoded,
                              std::size_t offset,
                              std::string_view operation,
                              std::string_view description) {
    if (offset > encoded.size() ||
        encoded.size() - offset < sizeof(std::uint64_t)) {
        reject(operation, std::string("truncated ") +
                              std::string(description));
    }
    std::uint64_t result = 0;
    for (std::size_t byte = 0; byte < sizeof(result); ++byte) {
        result |= static_cast<std::uint64_t>(encoded[offset + byte])
                  << (8U * byte);
    }
    return result;
}

inline std::size_t checked_size(std::uint64_t value,
                                std::string_view operation,
                                std::string_view description) {
    if (value > std::numeric_limits<std::size_t>::max()) {
        reject(operation, std::string(description) +
                              " does not fit size_t");
    }
    return static_cast<std::size_t>(value);
}

template <PersistableFheBackend Backend, typename StorageContext,
          typename DecodeCiphertext>
    requires CiphertextStorageContext<Backend, StorageContext>
FheValue<Backend> decode_parts(
    const StorageContext &context, FheValueRecordTag tag,
    std::span<const std::uint8_t> body, DecodeCiphertext decode_ciphertext,
    std::string_view operation) {
    switch (tag) {
    case FheValueRecordTag::PublicScalar: {
        if (body.size() != sizeof(std::uint64_t)) {
            reject(operation, "noncanonical public-scalar record length");
        }
        const std::uint64_t scalar =
            read_u64(body, 0, operation, "public-scalar record");
        if (scalar >= kBaseFieldOrder) {
            reject(operation, "public scalar is outside Fp");
        }
        return FheValue<Backend>::public_scalar(Fp(scalar));
    }
    case FheValueRecordTag::PublicSlots: {
        const std::uint64_t encoded_slot_count =
            read_u64(body, 0, operation, "public-slots record");
        const std::size_t expected_slot_count =
            Backend::slot_count(context);
        if (encoded_slot_count != expected_slot_count) {
            reject(operation, "public value has the wrong slot count");
        }
        if (expected_slot_count >
            (std::numeric_limits<std::size_t>::max() -
             sizeof(std::uint64_t)) /
                sizeof(std::uint64_t)) {
            reject(operation, "public-slots record length overflows");
        }
        const std::size_t required =
            sizeof(std::uint64_t) +
            expected_slot_count * sizeof(std::uint64_t);
        if (body.size() != required) {
            reject(operation, "noncanonical public-slots record length");
        }

        SlotVector slots;
        slots.reserve(expected_slot_count);
        for (std::size_t slot = 0; slot < expected_slot_count; ++slot) {
            const std::uint64_t coordinate = read_u64(
                body, sizeof(std::uint64_t) +
                          slot * sizeof(std::uint64_t),
                operation, "public-slots coordinate");
            if (coordinate >= kBaseFieldOrder) {
                reject(operation, "public slot is outside Fp");
            }
            slots.emplace_back(coordinate);
        }
        FheValue<Backend> result =
            FheValue<Backend>::public_slots(std::move(slots));
        if (!result.plaintext().is_slots()) {
            reject(operation,
                   "uniform public-slot value is noncanonical");
        }
        return result;
    }
    case FheValueRecordTag::Ciphertext:
        if (body.empty()) {
            reject(operation, "empty ciphertext record");
        }
        return FheValue<Backend>::from_ciphertext(decode_ciphertext(body));
    }
    reject(operation, "unknown FHE-value record tag");
}

} // namespace value_codec_detail

/// Canonical context-free proof/wire record. Public values use the same tags
/// and field encodings as persisted values; encrypted values use the
/// backend's canonical protocol serialization rather than its private
/// storage encoding. An enclosing format must delimit the returned record.
template <FheBackend Backend>
std::vector<std::uint8_t> encode_canonical_fhe_value(
    const FheValue<Backend> &value,
    std::string_view operation = "encode_canonical_fhe_value") {
    std::vector<std::uint8_t> result;
    if (value.is_public()) {
        const PublicPlaintext &plaintext = value.plaintext();
        if (plaintext.is_scalar()) {
            result.reserve(1U + sizeof(std::uint64_t));
            result.push_back(static_cast<std::uint8_t>(
                FheValueRecordTag::PublicScalar));
            value_codec_detail::append_u64(result,
                                           plaintext.scalar().value());
            return result;
        }

        const std::size_t slot_count = plaintext.slots().size();
        if (slot_count > std::numeric_limits<std::uint64_t>::max() ||
            slot_count >
                (std::numeric_limits<std::size_t>::max() - 1U -
                 sizeof(std::uint64_t)) /
                    sizeof(std::uint64_t)) {
            value_codec_detail::reject(operation,
                                       "public-slots encoding overflows");
        }
        result.reserve(1U + sizeof(std::uint64_t) +
                       slot_count * sizeof(std::uint64_t));
        result.push_back(static_cast<std::uint8_t>(
            FheValueRecordTag::PublicSlots));
        value_codec_detail::append_u64(
            result, static_cast<std::uint64_t>(slot_count));
        for (const Fp &slot : plaintext.slots()) {
            value_codec_detail::append_u64(result, slot.value());
        }
        return result;
    }

    const std::vector<std::uint8_t> ciphertext =
        Backend::serialize(value.ciphertext());
    if (ciphertext.empty()) {
        value_codec_detail::reject(
            operation, "backend produced an empty ciphertext");
    }
    result.reserve(1U + ciphertext.size());
    result.push_back(
        static_cast<std::uint8_t>(FheValueRecordTag::Ciphertext));
    result.insert(result.end(), ciphertext.begin(), ciphertext.end());
    return result;
}

/// Encode one value as an externally delimited record. The trace-store layer
/// supplies the record boundary, so ciphertext bytes follow their tag without
/// an internal length. Public records are self-delimiting.
template <PersistableFheBackend Backend, typename StorageContext>
    requires CiphertextStorageContext<Backend, StorageContext>
std::vector<std::uint8_t> encode_fhe_value_record(
    const StorageContext &context,
    const FheValue<Backend> &value,
    std::string_view operation = "encode_fhe_value_record") {
    std::vector<std::uint8_t> result;
    if (value.is_public()) {
        const PublicPlaintext &plaintext = value.plaintext();
        plaintext.validate_slot_count(Backend::slot_count(context),
                                      operation);
        if (plaintext.is_scalar()) {
            result.reserve(1U + sizeof(std::uint64_t));
            result.push_back(static_cast<std::uint8_t>(
                FheValueRecordTag::PublicScalar));
            value_codec_detail::append_u64(result,
                                           plaintext.scalar().value());
            return result;
        }

        const std::size_t slot_count = plaintext.slots().size();
        if (slot_count > std::numeric_limits<std::uint64_t>::max() ||
            slot_count >
                (std::numeric_limits<std::size_t>::max() - 1U -
                 sizeof(std::uint64_t)) /
                    sizeof(std::uint64_t)) {
            value_codec_detail::reject(operation,
                                       "public-slots encoding overflows");
        }
        result.reserve(1U + sizeof(std::uint64_t) +
                       slot_count * sizeof(std::uint64_t));
        result.push_back(static_cast<std::uint8_t>(
            FheValueRecordTag::PublicSlots));
        value_codec_detail::append_u64(
            result, static_cast<std::uint64_t>(slot_count));
        for (const Fp &slot : plaintext.slots()) {
            value_codec_detail::append_u64(result, slot.value());
        }
        return result;
    }

    const std::vector<std::uint8_t> ciphertext =
        Backend::serialize_for_storage(context, value.ciphertext());
    if (ciphertext.empty()) {
        value_codec_detail::reject(
            operation, "backend produced an empty ciphertext");
    }
    result.reserve(1U + ciphertext.size());
    result.push_back(
        static_cast<std::uint8_t>(FheValueRecordTag::Ciphertext));
    result.insert(result.end(), ciphertext.begin(), ciphertext.end());
    return result;
}

/// Append one canonical FHE-value record to an existing byte vector.
/// Optimized storage sinks use this to serialize directly into their bounded
/// transfer slab without a second whole-record copy.
template <PersistableFheBackend Backend, typename StorageContext>
    requires CiphertextStorageContext<Backend, StorageContext>
void append_fhe_value_record(
    const StorageContext &context, const FheValue<Backend> &value,
    std::vector<std::uint8_t> &result,
    std::string_view operation = "append_fhe_value_record") {
    const std::size_t record_begin = result.size();
    if (value.is_public()) {
        const PublicPlaintext &plaintext = value.plaintext();
        plaintext.validate_slot_count(Backend::slot_count(context),
                                      operation);
        if (plaintext.is_scalar()) {
            result.push_back(static_cast<std::uint8_t>(
                FheValueRecordTag::PublicScalar));
            value_codec_detail::append_u64(result,
                                           plaintext.scalar().value());
            return;
        }
        const std::size_t slot_count = plaintext.slots().size();
        if (slot_count > std::numeric_limits<std::uint64_t>::max() ||
            slot_count >
                (std::numeric_limits<std::size_t>::max() - 1U -
                 sizeof(std::uint64_t)) /
                    sizeof(std::uint64_t)) {
            value_codec_detail::reject(operation,
                                       "public-slots encoding overflows");
        }
        result.reserve(record_begin + 1U + sizeof(std::uint64_t) +
                       slot_count * sizeof(std::uint64_t));
        result.push_back(static_cast<std::uint8_t>(
            FheValueRecordTag::PublicSlots));
        value_codec_detail::append_u64(
            result, static_cast<std::uint64_t>(slot_count));
        for (const Fp &slot : plaintext.slots()) {
            value_codec_detail::append_u64(result, slot.value());
        }
        return;
    }

    result.push_back(
        static_cast<std::uint8_t>(FheValueRecordTag::Ciphertext));
    if constexpr (requires {
                      Backend::append_storage_serialization(
                          context, value.ciphertext(), result);
                  }) {
        Backend::append_storage_serialization(
            context, value.ciphertext(), result);
    } else {
        const std::vector<std::uint8_t> ciphertext =
            Backend::serialize_for_storage(context, value.ciphertext());
        result.insert(result.end(), ciphertext.begin(), ciphertext.end());
    }
    if (result.size() == record_begin + 1U) {
        value_codec_detail::reject(
            operation, "backend produced an empty ciphertext");
    }
}

/// Reusable-buffer form of `encode_fhe_value_record`.
template <PersistableFheBackend Backend, typename StorageContext>
    requires CiphertextStorageContext<Backend, StorageContext>
void encode_fhe_value_record_into(
    const StorageContext &context, const FheValue<Backend> &value,
    std::vector<std::uint8_t> &result,
    std::string_view operation = "encode_fhe_value_record_into") {
    result.clear();
    append_fhe_value_record<Backend>(context, value, result, operation);
}

/// Decode one complete externally delimited record using a caller-selected
/// ciphertext trust boundary.
template <PersistableFheBackend Backend, typename StorageContext,
          typename DecodeCiphertext>
    requires CiphertextStorageContext<Backend, StorageContext>
FheValue<Backend> decode_fhe_value_record(
    const StorageContext &context,
    std::span<const std::uint8_t> encoded,
    DecodeCiphertext decode_ciphertext,
    std::string_view operation = "decode_fhe_value_record") {
    if (encoded.empty()) {
        value_codec_detail::reject(operation, "empty FHE-value record");
    }
    return value_codec_detail::decode_parts<Backend>(
        context, static_cast<FheValueRecordTag>(encoded.front()),
        encoded.subspan(1), std::move(decode_ciphertext), operation);
}

/// Decode a record that was validated when its caller-private artifact was
/// opened.
template <PersistableFheBackend Backend>
FheValue<Backend> decode_validated_private_fhe_value_record(
    const typename Backend::EvalContext &eval,
    std::span<const std::uint8_t> encoded,
    std::string_view operation =
        "decode_validated_private_fhe_value_record") {
    return decode_fhe_value_record<Backend>(
        eval, encoded,
        [&](std::span<const std::uint8_t> ciphertext) {
            return deserialize_validated_private_ciphertext<Backend>(
                eval, ciphertext);
        },
        operation);
}

/// Validate an externally delimited record at a storage trust boundary.
template <PersistableFheBackend Backend>
void validate_fhe_value_record(
    const typename Backend::EvalContext &eval,
    std::span<const std::uint8_t> encoded,
    std::size_t expected_rns_limbs,
    std::uint64_t maximum_ciphertext_bytes,
    std::string_view operation = "validate_fhe_value_record") {
    (void)decode_fhe_value_record<Backend>(
        eval, encoded,
        [&](std::span<const std::uint8_t> ciphertext) {
            if (ciphertext.size() > maximum_ciphertext_bytes) {
                value_codec_detail::reject(
                    operation,
                    "ciphertext trace payload exceeds its backend limit");
            }
            typename Backend::Ciphertext result =
                Backend::deserialize_from_storage(eval, ciphertext);
            if (Backend::rns_limb_count(eval, result) !=
                expected_rns_limbs) {
                value_codec_detail::reject(
                    operation,
                    "ciphertext is not at its exact declared RNS level");
            }
            return result;
        },
        operation);
}

/// Append one self-delimiting value. This is the exact per-value encoding used
/// inside delegation wire v4: public records use their canonical encoding;
/// a ciphertext tag is followed by a u64 byte length and the backend payload.
template <PersistableFheBackend Backend, typename StorageContext>
    requires CiphertextStorageContext<Backend, StorageContext>
void append_self_delimiting_fhe_value(
    std::vector<std::uint8_t> &output,
    const StorageContext &context,
    const FheValue<Backend> &value,
    std::string_view operation = "append_self_delimiting_fhe_value") {
    const std::vector<std::uint8_t> record =
        encode_fhe_value_record<Backend>(context, value, operation);
    const auto tag = static_cast<FheValueRecordTag>(record.front());
    if (tag != FheValueRecordTag::Ciphertext) {
        output.insert(output.end(), record.begin(), record.end());
        return;
    }
    const std::size_t payload_bytes = record.size() - 1U;
    if (payload_bytes > std::numeric_limits<std::uint64_t>::max()) {
        value_codec_detail::reject(operation,
                                   "ciphertext length does not fit u64");
    }
    output.push_back(record.front());
    value_codec_detail::append_u64(
        output, static_cast<std::uint64_t>(payload_bytes));
    output.insert(output.end(), record.begin() + 1, record.end());
}

template <PersistableFheBackend Backend>
struct DecodedSelfDelimitingFheValue {
    FheValue<Backend> value;
    std::size_t bytes_consumed = 0;
    std::size_t ciphertext_payload_bytes = 0;
};

/// Decode one value from the front of a sequence while preserving the caller's
/// per-ciphertext allocation limit. The returned byte count advances the outer
/// message reader; aggregate ciphertext limits remain an outer-message policy.
template <PersistableFheBackend Backend, typename StorageContext,
          typename DecodeCiphertext>
    requires CiphertextStorageContext<Backend, StorageContext>
DecodedSelfDelimitingFheValue<Backend>
decode_self_delimiting_fhe_value(
    const StorageContext &context,
    std::span<const std::uint8_t> encoded,
    std::uint64_t maximum_ciphertext_bytes,
    DecodeCiphertext decode_ciphertext,
    std::string_view operation = "decode_self_delimiting_fhe_value") {
    if (encoded.empty()) {
        value_codec_detail::reject(operation, "truncated FHE-value record");
    }
    const auto tag = static_cast<FheValueRecordTag>(encoded.front());
    switch (tag) {
    case FheValueRecordTag::PublicScalar: {
        constexpr std::size_t bytes = 1U + sizeof(std::uint64_t);
        if (encoded.size() < bytes) {
            value_codec_detail::reject(operation,
                                       "truncated public-scalar record");
        }
        return {value_codec_detail::decode_parts<Backend>(
                    context, tag,
                    encoded.subspan(1, sizeof(std::uint64_t)),
                    std::move(decode_ciphertext), operation),
                bytes, 0};
    }
    case FheValueRecordTag::PublicSlots: {
        if (encoded.size() < 1U + sizeof(std::uint64_t)) {
            value_codec_detail::reject(operation,
                                       "truncated public-slots record");
        }
        const std::uint64_t encoded_slot_count =
            value_codec_detail::read_u64(
                encoded, 1, operation, "public-slots record");
        const std::size_t slot_count =
            value_codec_detail::checked_size(
                encoded_slot_count, operation, "public slot count");
        if (slot_count >
            (std::numeric_limits<std::size_t>::max() - 1U -
             sizeof(std::uint64_t)) /
                sizeof(std::uint64_t)) {
            value_codec_detail::reject(operation,
                                       "public-slots record length overflows");
        }
        const std::size_t bytes =
            1U + sizeof(std::uint64_t) +
            slot_count * sizeof(std::uint64_t);
        if (encoded.size() < bytes) {
            value_codec_detail::reject(operation,
                                       "truncated public-slots record");
        }
        return {value_codec_detail::decode_parts<Backend>(
                    context, tag, encoded.subspan(1, bytes - 1U),
                    std::move(decode_ciphertext), operation),
                bytes, 0};
    }
    case FheValueRecordTag::Ciphertext: {
        if (encoded.size() < 1U + sizeof(std::uint64_t)) {
            value_codec_detail::reject(operation,
                                       "truncated ciphertext record");
        }
        const std::uint64_t encoded_ciphertext_bytes =
            value_codec_detail::read_u64(
                encoded, 1, operation, "ciphertext length");
        if (encoded_ciphertext_bytes == 0 ||
            encoded_ciphertext_bytes > maximum_ciphertext_bytes) {
            value_codec_detail::reject(
                operation, "ciphertext exceeds configured byte limit");
        }
        const std::size_t ciphertext_bytes =
            value_codec_detail::checked_size(
                encoded_ciphertext_bytes, operation, "ciphertext length");
        if (ciphertext_bytes >
            std::numeric_limits<std::size_t>::max() - 1U -
                sizeof(std::uint64_t)) {
            value_codec_detail::reject(operation,
                                       "ciphertext record length overflows");
        }
        const std::size_t bytes =
            1U + sizeof(std::uint64_t) + ciphertext_bytes;
        if (encoded.size() < bytes) {
            value_codec_detail::reject(operation,
                                       "truncated ciphertext record");
        }
        return {value_codec_detail::decode_parts<Backend>(
                    context, tag,
                    encoded.subspan(1U + sizeof(std::uint64_t),
                                    ciphertext_bytes),
                    std::move(decode_ciphertext), operation),
                bytes, ciphertext_bytes};
    }
    }
    value_codec_detail::reject(operation, "unknown FHE-value record tag");
}

} // namespace laminate::fhe

#endif // LAMINATE_FHE_STORAGE_VALUE_CODEC_HPP
