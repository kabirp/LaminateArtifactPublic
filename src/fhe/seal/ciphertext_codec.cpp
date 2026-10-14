/// @file ciphertext_codec.cpp
/// @brief Canonical protocol and trace-storage codecs for SEAL ciphertexts.
///
/// The storage envelope binds a ciphertext to its exact context identity and
/// carries only persistence-safe symbolic metadata. It is separate from
/// context/key bundles in `context_bundle.cpp`.

#include "context_internal.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace laminate::fhe {

namespace {

using Ciphertext = SealBackend::Ciphertext;

constexpr std::array<std::uint8_t, 8> kSealStorageMagic{
    'L', 'M', 'C', 'T', 'S', 'E', 'A', 'L'};
constexpr std::uint8_t kSealStorageVersion = 1;
constexpr std::size_t kSealStorageFixedBytes =
    kSealStorageMagic.size() + 1 + 1 + Digest{}.size() + 8 + 8;

void append_storage_u64(std::vector<std::uint8_t> &output,
                        std::uint64_t value) {
    for (std::size_t byte = 0; byte < 8; ++byte) {
        output.push_back(
            static_cast<std::uint8_t>((value >> (8U * byte)) & 0xffU));
    }
}

void store_storage_u64(std::span<std::uint8_t, 8> output,
                       std::uint64_t value) {
    for (std::size_t byte = 0; byte < output.size(); ++byte) {
        output[byte] = static_cast<std::uint8_t>(
            (value >> (8U * byte)) & 0xffU);
    }
}

std::size_t append_uncompressed_ciphertext(
    std::vector<std::uint8_t> &output,
    const seal::Ciphertext &ciphertext, const char *operation) {
    // SEAL can save directly to caller-owned memory. Using that interface
    // avoids the full-size stream, string, and vector copies on every trace
    // ciphertext while preserving its canonical uncompressed encoding.
    const std::streamoff save_size =
        ciphertext.save_size(seal::compr_mode_type::none);
    if (save_size <= 0 ||
        static_cast<std::uintmax_t>(save_size) >
            std::numeric_limits<std::size_t>::max()) {
        throw std::invalid_argument(std::string(operation) +
                                    ": ciphertext length overflows");
    }
    const std::size_t maximum_bytes =
        static_cast<std::size_t>(save_size);
    if (maximum_bytes >
        std::numeric_limits<std::size_t>::max() - output.size()) {
        throw std::invalid_argument(std::string(operation) +
                                    ": ciphertext length overflows");
    }

    const std::size_t offset = output.size();
    output.resize(offset + maximum_bytes);
    std::streamoff written = 0;
    try {
        written = ciphertext.save(
            reinterpret_cast<seal::seal_byte *>(output.data() + offset),
            maximum_bytes, seal::compr_mode_type::none);
    } catch (const std::exception &error) {
        throw std::invalid_argument(std::string(operation) +
                                    ": SEAL serialization failed: " +
                                    error.what());
    }
    if (written <= 0 || written > save_size) {
        throw std::invalid_argument(std::string(operation) +
                                    ": SEAL serialization returned an "
                                    "invalid length");
    }
    output.resize(offset + static_cast<std::size_t>(written));
    return static_cast<std::size_t>(written);
}

std::uint64_t read_storage_u64(std::span<const std::uint8_t> bytes,
                               std::size_t &offset,
                               const char *operation) {
    if (offset > bytes.size() || bytes.size() - offset < 8) {
        throw std::invalid_argument(std::string(operation) +
                                    ": truncated integer");
    }
    std::uint64_t value = 0;
    for (std::size_t byte = 0; byte < 8; ++byte) {
        value |= static_cast<std::uint64_t>(bytes[offset + byte])
                 << (8U * byte);
    }
    offset += 8;
    return value;
}

std::size_t checked_storage_size(std::uint64_t value,
                                 const char *operation) {
    if (value > std::numeric_limits<std::size_t>::max()) {
        throw std::invalid_argument(std::string(operation) +
                                    ": length exceeds this platform");
    }
    return static_cast<std::size_t>(value);
}

struct ValidatedSealStorageEnvelope {
    std::size_t noise_loss_bits = 0;
    std::span<const std::uint8_t> raw_ciphertext;
};

enum class SealCiphertextLoadTrust {
    Untrusted,
    ValidatedPrivate,
};

template <typename Context>
ValidatedSealStorageEnvelope parse_seal_storage_envelope(
    const Context &context, std::span<const std::uint8_t> bytes,
    const char *operation) {
    if (!context.context) {
        throw std::invalid_argument(std::string(operation) +
                                    ": context is missing");
    }
    if (bytes.size() < kSealStorageFixedBytes ||
        !std::equal(kSealStorageMagic.begin(), kSealStorageMagic.end(),
                    bytes.begin())) {
        throw std::invalid_argument(std::string(operation) +
                                    ": invalid storage header");
    }

    std::size_t offset = kSealStorageMagic.size();
    if (bytes[offset++] != kSealStorageVersion) {
        throw std::invalid_argument(std::string(operation) +
                                    ": unsupported encoding version");
    }
    if (bytes[offset++] != 0) {
        throw std::invalid_argument(std::string(operation) +
                                    ": unsupported storage flags");
    }
    Digest encoded_context_id{};
    std::copy_n(bytes.begin() + static_cast<std::ptrdiff_t>(offset),
                encoded_context_id.size(), encoded_context_id.begin());
    offset += encoded_context_id.size();
    if (encoded_context_id != SealBackend::storage_context_id(context)) {
        throw std::invalid_argument(std::string(operation) +
                                    ": storage context mismatch");
    }

    const std::size_t noise_loss_bits = checked_storage_size(
        read_storage_u64(bytes, offset, operation), operation);
    const std::size_t raw_size = checked_storage_size(
        read_storage_u64(bytes, offset, operation), operation);
    if (raw_size != bytes.size() - offset) {
        throw std::invalid_argument(std::string(operation) +
                                    ": truncated or trailing storage data");
    }
    if (raw_size >
        static_cast<std::size_t>(
            std::numeric_limits<std::streamoff>::max())) {
        throw std::invalid_argument(std::string(operation) +
                                    ": ciphertext length exceeds stream limits");
    }
    return ValidatedSealStorageEnvelope{
        noise_loss_bits, bytes.subspan(offset, raw_size)};
}

template <typename Context>
Ciphertext load_seal_storage_ciphertext(
    const Context &context,
    const ValidatedSealStorageEnvelope &envelope,
    const char *operation,
    SealCiphertextLoadTrust trust =
        SealCiphertextLoadTrust::Untrusted) {
    seal::Ciphertext raw;
    try {
        const auto *encoded =
            reinterpret_cast<const seal::seal_byte *>(
                envelope.raw_ciphertext.data());
        // The validated-private path has already passed SEAL's strict load
        // and Laminate's canonical round-trip at artifact open (or contains
        // bytes emitted by the same-writer handoff). SEAL's unsafe_load still
        // checks serialization framing, context metadata, dimensions, and
        // buffer shape; it skips only the repeated coefficient-by-coefficient
        // range scan.
        const std::streamoff consumed =
            trust == SealCiphertextLoadTrust::ValidatedPrivate
                ? raw.unsafe_load(*context.context, encoded,
                                  envelope.raw_ciphertext.size())
                : raw.load(*context.context, encoded,
                           envelope.raw_ciphertext.size());
        if (consumed != static_cast<std::streamoff>(
                            envelope.raw_ciphertext.size())) {
            throw std::invalid_argument(
                std::string(operation) +
                ": SEAL ciphertext contains trailing data");
        }
    } catch (const std::invalid_argument &) {
        throw;
    } catch (const std::exception &error) {
        throw std::invalid_argument(std::string(operation) +
                                    ": invalid SEAL ciphertext: " +
                                    error.what());
    }
    // Strict admission (or canonical same-writer serialization) has already
    // rejected transparent ciphertexts before a validated-private read. Do
    // not rescan every coefficient on each subsequent payload/GKR pass.
    if (trust == SealCiphertextLoadTrust::Untrusted &&
        raw.is_transparent()) {
        throw std::invalid_argument(
            std::string(operation) +
            ": transparent ciphertexts are public values, not private "
            "storage records");
    }
    return Ciphertext{std::move(raw), envelope.noise_loss_bits,
                      std::nullopt};
}

void require_canonical_seal_storage(
    const Ciphertext &ciphertext,
    const ValidatedSealStorageEnvelope &envelope,
    const char *operation) {
    const std::vector<std::uint8_t> canonical =
        SealBackend::serialize(ciphertext);
    if (!std::equal(canonical.begin(), canonical.end(),
                    envelope.raw_ciphertext.begin(),
                    envelope.raw_ciphertext.end())) {
        throw std::invalid_argument(std::string(operation) +
                                    ": noncanonical SEAL ciphertext encoding");
    }
}

} // namespace

using seal_detail::digest_is_empty;

// Protocol transport uses SEAL's canonical uncompressed ciphertext bytes. The
// decoder round-trips each value so alternate encodings cannot enter a proof.
std::vector<std::uint8_t>
SealBackend::serialize(const Ciphertext &ciphertext) {
    if (ciphertext.raw.is_transparent()) {
        throw std::invalid_argument(
            "SealBackend::serialize: transparent ciphertexts must be "
            "transported as public values");
    }
    std::vector<std::uint8_t> result;
    (void)append_uncompressed_ciphertext(
        result, ciphertext.raw, "SealBackend::serialize");
    return result;
}

SealBackend::Ciphertext SealBackend::deserialize_protocol(
    const EvalContext &context, std::span<const std::uint8_t> bytes) {
    constexpr const char *operation = "SealBackend::deserialize_protocol";
    if (!context.context || bytes.empty()) {
        throw std::invalid_argument(std::string(operation) +
                                    ": missing context or ciphertext bytes");
    }
    const std::string encoded(bytes.begin(), bytes.end());
    std::stringstream stream(encoded,
                             std::ios::binary | std::ios::in);
    Ciphertext result;
    try {
        result.raw.load(*context.context, stream);
    } catch (const std::exception &error) {
        throw std::invalid_argument(std::string(operation) + ": " +
                                    error.what());
    }
    if (result.raw.is_transparent() || serialize(result) !=
                                           std::vector<std::uint8_t>(
                                               bytes.begin(), bytes.end())) {
        throw std::invalid_argument(std::string(operation) +
                                    ": noncanonical ciphertext encoding");
    }
    return result;
}

SealBackend::Ciphertext SealBackend::deserialize_protocol(
    const PublicVerifierContext &context,
    std::span<const std::uint8_t> bytes) {
    constexpr const char *operation =
        "SealBackend::deserialize_protocol(verifier)";
    if (!context.context || bytes.empty()) {
        throw std::invalid_argument(std::string(operation) +
                                    ": missing context or ciphertext bytes");
    }
    const std::string encoded(bytes.begin(), bytes.end());
    std::stringstream stream(encoded, std::ios::binary | std::ios::in);
    Ciphertext result;
    try {
        result.raw.load(*context.context, stream);
    } catch (const std::exception &error) {
        throw std::invalid_argument(std::string(operation) + ": " +
                                    error.what());
    }
    if (result.raw.is_transparent() ||
        serialize(result) !=
            std::vector<std::uint8_t>(bytes.begin(), bytes.end())) {
        throw std::invalid_argument(std::string(operation) +
                                    ": noncanonical ciphertext encoding");
    }
    return result;
}

Digest SealBackend::storage_context_id(const EvalContext &context) {
    if (!context.context || digest_is_empty(context.storage_id)) {
        throw std::invalid_argument(
            "SealBackend::storage_context_id: context identity is missing");
    }
    return context.storage_id;
}

Digest SealBackend::storage_context_id(const ClientContext &context) {
    if (!context.context || digest_is_empty(context.storage_id)) {
        throw std::invalid_argument(
            "SealBackend::storage_context_id: client context identity is "
            "missing");
    }
    return context.storage_id;
}

Digest SealBackend::storage_context_id(
    const PublicVerifierContext &context) {
    if (!context.context || digest_is_empty(context.storage_id)) {
        throw std::invalid_argument(
            "SealBackend::storage_context_id: public verifier context "
            "identity is missing");
    }
    return context.storage_id;
}

std::uint64_t SealBackend::storage_ciphertext_byte_limit(
    const EvalContext &context) {
    constexpr const char *operation =
        "SealBackend::storage_ciphertext_byte_limit";
    if (!context.context) {
        throw std::invalid_argument(std::string(operation) +
                                    ": evaluation context is missing");
    }
    seal::Ciphertext maximum;
    maximum.resize(*context.context, context.context->first_parms_id(),
                   SEAL_CIPHERTEXT_SIZE_MAX);
    const std::streamoff raw =
        maximum.save_size(seal::compr_mode_type::none);
    if (raw <= 0 ||
        static_cast<std::uint64_t>(raw) >
            std::numeric_limits<std::uint64_t>::max() -
                kSealStorageFixedBytes) {
        throw std::invalid_argument(std::string(operation) +
                                    ": byte limit overflows");
    }
    return static_cast<std::uint64_t>(raw) + kSealStorageFixedBytes;
}

// Trace storage adds the context identity and symbolic noise-loss metadata to
// the protocol bytes. Readers reject another setup before asking SEAL to load
// the ciphertext, which makes accidental cross-run trace reuse explicit.
template <typename Context>
void append_storage_serialization_impl(
    const Context &context, const Ciphertext &ciphertext,
    std::vector<std::uint8_t> &output, const char *operation) {
    if (!context.context) {
        throw std::invalid_argument(std::string(operation) +
                                    ": context is missing");
    }
    if (ciphertext.deterministic_noise_bound.has_value()) {
        throw std::invalid_argument(
            std::string(operation) +
            ": deterministic noise bounds are not persistable");
    }
    if (!seal::is_valid_for(ciphertext.raw, *context.context)) {
        throw std::invalid_argument(std::string(operation) +
                                    ": ciphertext does not match context");
    }
    if (ciphertext.raw.is_transparent()) {
        throw std::invalid_argument(
            std::string(operation) +
            ": transparent ciphertexts must be stored as public values");
    }

    output.insert(output.end(), kSealStorageMagic.begin(),
                  kSealStorageMagic.end());
    output.push_back(kSealStorageVersion);
    output.push_back(0); // Reserved flags; nonzero encodings are invalid.
    const Digest context_id = SealBackend::storage_context_id(context);
    output.insert(output.end(), context_id.begin(), context_id.end());
    append_storage_u64(output, ciphertext.noise_loss_bits);
    const std::size_t raw_length_offset = output.size();
    append_storage_u64(output, 0);
    // Append directly after the fixed envelope, then fill the length field.
    // No second raw-ciphertext buffer is materialized.
    const std::size_t raw_size = append_uncompressed_ciphertext(
        output, ciphertext.raw, operation);
    store_storage_u64(
        std::span<std::uint8_t, 8>(output.data() + raw_length_offset, 8),
        static_cast<std::uint64_t>(raw_size));
}

std::vector<std::uint8_t> SealBackend::serialize_for_storage(
    const EvalContext &context, const Ciphertext &ciphertext) {
    std::vector<std::uint8_t> output;
    append_storage_serialization_impl(
        context, ciphertext, output,
        "SealBackend::serialize_for_storage");
    return output;
}

void SealBackend::append_storage_serialization(
    const EvalContext &context, const Ciphertext &ciphertext,
    std::vector<std::uint8_t> &output) {
    append_storage_serialization_impl(
        context, ciphertext, output,
        "SealBackend::append_storage_serialization");
}

std::vector<std::uint8_t> SealBackend::serialize_for_storage(
    const ClientContext &context, const Ciphertext &ciphertext) {
    std::vector<std::uint8_t> output;
    append_storage_serialization_impl(
        context, ciphertext, output,
        "SealBackend::serialize_for_storage(client)");
    return output;
}

std::vector<std::uint8_t> SealBackend::serialize_for_storage(
    const PublicVerifierContext &context,
    const Ciphertext &ciphertext) {
    std::vector<std::uint8_t> output;
    append_storage_serialization_impl(
        context, ciphertext, output,
        "SealBackend::serialize_for_storage(verifier)");
    return output;
}

SealBackend::Ciphertext SealBackend::deserialize_from_storage(
    const EvalContext &context, std::span<const std::uint8_t> bytes) {
    constexpr const char *operation =
        "SealBackend::deserialize_from_storage";
    const ValidatedSealStorageEnvelope envelope =
        parse_seal_storage_envelope(context, bytes, operation);
    Ciphertext result =
        load_seal_storage_ciphertext(context, envelope, operation);
    require_canonical_seal_storage(result, envelope, operation);
    return result;
}

SealBackend::Ciphertext SealBackend::deserialize_from_storage(
    const ClientContext &context, std::span<const std::uint8_t> bytes) {
    constexpr const char *operation =
        "SealBackend::deserialize_from_storage(client)";
    const ValidatedSealStorageEnvelope envelope =
        parse_seal_storage_envelope(context, bytes, operation);
    Ciphertext result =
        load_seal_storage_ciphertext(context, envelope, operation);
    require_canonical_seal_storage(result, envelope, operation);
    return result;
}

SealBackend::Ciphertext SealBackend::deserialize_from_storage(
    const PublicVerifierContext &context,
    std::span<const std::uint8_t> bytes) {
    constexpr const char *operation =
        "SealBackend::deserialize_from_storage(verifier)";
    const ValidatedSealStorageEnvelope envelope =
        parse_seal_storage_envelope(context, bytes, operation);
    Ciphertext result =
        load_seal_storage_ciphertext(context, envelope, operation);
    require_canonical_seal_storage(result, envelope, operation);
    return result;
}

SealBackend::Ciphertext
SealBackend::deserialize_validated_private_storage(
    const EvalContext &context, std::span<const std::uint8_t> bytes) {
    constexpr const char *operation =
        "SealBackend::deserialize_validated_private_storage";
    const ValidatedSealStorageEnvelope envelope =
        parse_seal_storage_envelope(context, bytes, operation);
    return load_seal_storage_ciphertext(
        context, envelope, operation,
        SealCiphertextLoadTrust::ValidatedPrivate);
}


} // namespace laminate::fhe
