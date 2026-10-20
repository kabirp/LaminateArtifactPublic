/// @file context_bundle.cpp
/// @brief Canonical role-separated SEAL context and preprocessing bundles.
///
/// This unit owns persisted evaluation/client/verifier contexts and the
/// fixed-message plaintext basis. Ciphertext trace records use the independent
/// envelope in `ciphertext_codec.cpp`.

#include "arithmetic_internal.hpp"
#include "binary_codec.hpp"
#include "context_internal.hpp"
#include "state.hpp"

#include "seal/util/ntt.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace laminate::fhe {

namespace {

using namespace seal_detail;
using BundleReader = BinaryReader;

constexpr std::array<std::uint8_t, 8> kSealEvaluationBundleMagic{
    'L', 'M', 'S', 'E', 'A', 'L', 'E', 'V'};
constexpr std::array<std::uint8_t, 8> kSealClientBundleMagic{
    'L', 'M', 'S', 'E', 'A', 'L', 'C', 'L'};
constexpr std::array<std::uint8_t, 8> kSealPublicVerifierBundleMagic{
    'L', 'M', 'S', 'E', 'A', 'L', 'P', 'V'};
constexpr std::array<std::uint8_t, 8>
    kSealFixedMessageCellPreprocessingMagic{
        'L', 'M', 'S', 'E', 'A', 'L', 'F', 'M'};
constexpr std::uint8_t kSealContextBundleVersion = 1;
constexpr std::uint8_t kSealFixedMessageCellPreprocessingVersion = 1;
constexpr std::string_view kSealContextBundleChecksumDomain =
    "LaminateImpl/SealContextBundleChecksum/v1";
constexpr std::string_view
    kSealFixedMessageCellPreprocessingChecksumDomain =
        "LaminateImpl/SealFixedMessageCellPreprocessingChecksum/v1";
constexpr std::string_view kSealFixedMessageCellPreprocessingIdDomain =
    "LaminateImpl/SealFixedMessageCellPreprocessingId/v1";

Digest make_bundle_checksum(std::span<const std::uint8_t> bytes) {
    Sha256Hasher hasher;
    hasher.update(std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t *>(
            kSealContextBundleChecksumDomain.data()),
        kSealContextBundleChecksumDomain.size()));
    hasher.update(bytes);
    return hasher.finish();
}

Digest make_fixed_message_cell_preprocessing_checksum(
    std::span<const std::uint8_t> bytes) {
    Sha256Hasher hasher;
    hasher.update(std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t *>(
            kSealFixedMessageCellPreprocessingChecksumDomain.data()),
        kSealFixedMessageCellPreprocessingChecksumDomain.size()));
    hasher.update(bytes);
    return hasher.finish();
}

Digest make_fixed_message_cell_preprocessing_id(
    std::span<const std::uint8_t> bytes) {
    Sha256Hasher hasher;
    hasher.update(std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t *>(
            kSealFixedMessageCellPreprocessingIdDomain.data()),
        kSealFixedMessageCellPreprocessingIdDomain.size()));
    hasher.update(bytes);
    return hasher.finish();
}

void append_blob(std::vector<std::uint8_t> &output,
                 std::span<const std::uint8_t> bytes,
                 const char *operation) {
    append_u64(output, checked_u64(bytes.size(), operation));
    output.insert(output.end(), bytes.begin(), bytes.end());
}

void append_bundle_checksum(std::vector<std::uint8_t> &output) {
    const Digest checksum = make_bundle_checksum(output);
    output.insert(output.end(), checksum.begin(), checksum.end());
}

void append_fixed_message_cell_preprocessing_checksum(
    std::vector<std::uint8_t> &output) {
    const Digest checksum =
        make_fixed_message_cell_preprocessing_checksum(output);
    output.insert(output.end(), checksum.begin(), checksum.end());
}

std::span<const std::uint8_t> verified_bundle_payload(
    std::span<const std::uint8_t> bytes,
    std::span<const std::uint8_t, 8> magic,
    const char *operation) {
    constexpr std::size_t kHeaderBytes = 8 + 1 + 1;
    if (bytes.size() < kHeaderBytes + Digest{}.size() ||
        !std::equal(magic.begin(), magic.end(), bytes.begin())) {
        throw std::invalid_argument(std::string(operation) +
                                    ": invalid bundle header");
    }
    if (bytes[8] != kSealContextBundleVersion) {
        throw std::invalid_argument(std::string(operation) +
                                    ": unsupported bundle version");
    }
    if (bytes[9] != 0) {
        throw std::invalid_argument(std::string(operation) +
                                    ": unsupported bundle flags");
    }
    const auto payload = bytes.first(bytes.size() - Digest{}.size());
    Digest encoded_checksum{};
    std::copy(bytes.end() - static_cast<std::ptrdiff_t>(
                                encoded_checksum.size()),
              bytes.end(), encoded_checksum.begin());
    if (make_bundle_checksum(payload) != encoded_checksum) {
        throw std::invalid_argument(std::string(operation) +
                                    ": bundle checksum mismatch");
    }
    return payload.subspan(kHeaderBytes);
}

std::span<const std::uint8_t>
verified_fixed_message_cell_preprocessing_payload(
    std::span<const std::uint8_t> bytes,
    const char *operation) {
    constexpr std::size_t kHeaderBytes = 8 + 1 + 1;
    if (bytes.size() < kHeaderBytes + Digest{}.size() ||
        !std::equal(kSealFixedMessageCellPreprocessingMagic.begin(),
                    kSealFixedMessageCellPreprocessingMagic.end(),
                    bytes.begin())) {
        throw std::invalid_argument(std::string(operation) +
                                    ": invalid artifact header");
    }
    if (bytes[8] != kSealFixedMessageCellPreprocessingVersion) {
        throw std::invalid_argument(std::string(operation) +
                                    ": unsupported artifact version");
    }
    if (bytes[9] != 0) {
        throw std::invalid_argument(std::string(operation) +
                                    ": unsupported artifact flags");
    }
    const auto payload = bytes.first(bytes.size() - Digest{}.size());
    Digest encoded_checksum{};
    std::copy(bytes.end() - static_cast<std::ptrdiff_t>(
                                encoded_checksum.size()),
              bytes.end(), encoded_checksum.begin());
    if (make_fixed_message_cell_preprocessing_checksum(payload) !=
        encoded_checksum) {
        throw std::invalid_argument(std::string(operation) +
                                    ": artifact checksum mismatch");
    }
    return payload.subspan(kHeaderBytes);
}

std::size_t checked_artifact_add(std::size_t left, std::size_t right,
                                 const char *operation) {
    if (right > std::numeric_limits<std::size_t>::max() - left) {
        throw std::invalid_argument(std::string(operation) +
                                    ": artifact size overflows");
    }
    return left + right;
}

std::size_t checked_artifact_multiply(std::size_t left,
                                      std::size_t right,
                                      const char *operation) {
    if (left != 0 &&
        right > std::numeric_limits<std::size_t>::max() / left) {
        throw std::invalid_argument(std::string(operation) +
                                    ": artifact size overflows");
    }
    return left * right;
}

void append_artifact_u64_words(
    std::vector<std::uint8_t> &output,
    std::span<const std::uint64_t> words,
    const char *operation) {
    const std::size_t byte_count = checked_artifact_multiply(
        words.size(), sizeof(std::uint64_t), operation);
    const std::size_t offset = output.size();
    output.resize(checked_artifact_add(offset, byte_count, operation));
    if constexpr (std::endian::native == std::endian::little) {
        std::memcpy(output.data() + offset, words.data(), byte_count);
    } else {
        for (std::size_t index = 0; index < words.size(); ++index) {
            const std::uint64_t value = words[index];
            for (std::size_t byte = 0; byte < 8; ++byte) {
                output[offset + index * 8 + byte] =
                    static_cast<std::uint8_t>(
                        (value >> (8U * byte)) & UINT64_C(0xff));
            }
        }
    }
}

void read_artifact_u64_words(
    BundleReader &reader, std::span<std::uint64_t> destination,
    const char *operation) {
    const std::size_t byte_count = checked_artifact_multiply(
        destination.size(), sizeof(std::uint64_t), operation);
    const auto encoded = reader.read_bytes(byte_count);
    if constexpr (std::endian::native == std::endian::little) {
        std::memcpy(destination.data(), encoded.data(), byte_count);
    } else {
        for (std::size_t index = 0; index < destination.size(); ++index) {
            std::uint64_t value = 0;
            for (std::size_t byte = 0; byte < 8; ++byte) {
                value |= static_cast<std::uint64_t>(
                             encoded[index * 8 + byte])
                         << (8U * byte);
            }
            destination[index] = value;
        }
    }
}

struct FixedMessageCellPreprocessingShape {
    std::size_t artifact_bytes = 0;
    std::size_t data_levels = 0;
    std::size_t level_representations = 0;
    std::size_t ntt_coefficient_bytes = 0;
};

FixedMessageCellPreprocessingShape
fixed_message_cell_preprocessing_shape(
    const EvalContext &context, const char *operation) {
    if (!context.context) {
        throw std::invalid_argument(std::string(operation) +
                                    ": evaluation context is missing");
    }

    // magic, version, flags, storage identity, slot/cell/level counts, and
    // the trailing checksum.
    std::size_t bytes = 8 + 1 + 1 + Digest{}.size() + 8 + 8 + 8 +
                        Digest{}.size();
    std::size_t one_cell_bytes = 8 + 8 + 8;
    std::size_t one_cell_ntt_bytes = 0;
    std::size_t levels = 0;
    for (auto level = context.context->first_context_data(); level;
         level = level->next_context_data()) {
        const std::size_t modulus_count =
            level->parms().coeff_modulus().size();
        const std::size_t coefficient_count = checked_artifact_multiply(
            level->parms().poly_modulus_degree(), modulus_count,
            operation);
        const std::size_t coefficient_bytes = checked_artifact_multiply(
            coefficient_count, sizeof(std::uint64_t), operation);
        // level index, four-word parms_id, coefficient count, coefficients.
        one_cell_bytes = checked_artifact_add(
            one_cell_bytes, 8 + 4 * 8 + 8, operation);
        one_cell_bytes = checked_artifact_add(
            one_cell_bytes, coefficient_bytes, operation);
        one_cell_ntt_bytes = checked_artifact_add(
            one_cell_ntt_bytes, coefficient_bytes, operation);
        levels = checked_artifact_add(levels, 1, operation);
    }
    if (levels == 0) {
        throw std::invalid_argument(std::string(operation) +
                                    ": evaluation context has no data "
                                    "levels");
    }
    bytes = checked_artifact_add(
        bytes,
        checked_artifact_multiply(kFixedMessageCellCount,
                                  one_cell_bytes, operation),
        operation);
    const std::size_t ntt_bytes = checked_artifact_multiply(
        kFixedMessageCellCount, one_cell_ntt_bytes, operation);
    return FixedMessageCellPreprocessingShape{
        .artifact_bytes = bytes,
        .data_levels = levels,
        .level_representations = checked_artifact_multiply(
            kFixedMessageCellCount, levels, operation),
        .ntt_coefficient_bytes = ntt_bytes,
    };
}


} // namespace

using namespace seal_detail;

// Evaluation bundle: public parameters plus exactly the server's public,
// relinearization, and optional Galois keys. No client secret enters it.
std::vector<std::uint8_t>
SealBackend::serialize_evaluation_context_bundle(
    const EvalContext &context) {
    constexpr const char *operation =
        "SealBackend::serialize_evaluation_context_bundle";
    if (!context.context || !context.public_key || !context.relin_keys ||
        !context.galois_keys) {
        throw std::invalid_argument(std::string(operation) +
                                    ": evaluation context is incomplete");
    }
    const SealParameterDescriptor descriptor = live_parameter_descriptor(
        context.parameters, *context.context, operation);
    validate_evaluation_keys(context.parameters, *context.context,
                             *context.public_key, *context.relin_keys,
                             *context.galois_keys, operation);
    const std::vector<std::uint8_t> descriptor_bytes =
        serialize_parameter_descriptor(descriptor, operation);
    const std::vector<std::uint8_t> public_key_bytes =
        serialize_seal_object(*context.public_key, operation);
    const std::vector<std::uint8_t> relin_key_bytes =
        serialize_seal_object(*context.relin_keys, operation);
    const std::vector<std::uint8_t> galois_key_bytes =
        context.parameters.generate_galois_keys
            ? serialize_seal_object(*context.galois_keys, operation)
            : std::vector<std::uint8_t>{};
    const Digest identity = make_context_identity(
        descriptor_bytes, public_key_bytes, relin_key_bytes,
        galois_key_bytes, operation);
    if (identity != storage_context_id(context)) {
        throw std::invalid_argument(std::string(operation) +
                                    ": evaluation key material changed after "
                                    "context construction");
    }

    std::vector<std::uint8_t> result;
    result.insert(result.end(), kSealEvaluationBundleMagic.begin(),
                  kSealEvaluationBundleMagic.end());
    result.push_back(kSealContextBundleVersion);
    result.push_back(0);
    append_blob(result, descriptor_bytes, operation);
    result.insert(result.end(), identity.begin(), identity.end());
    append_blob(result, public_key_bytes, operation);
    append_blob(result, relin_key_bytes, operation);
    append_blob(result, galois_key_bytes, operation);
    append_bundle_checksum(result);
    return result;
}

SealBackend::EvalContext
SealBackend::deserialize_evaluation_context_bundle(
    std::span<const std::uint8_t> bytes) {
    constexpr const char *operation =
        "SealBackend::deserialize_evaluation_context_bundle";
    const auto payload = verified_bundle_payload(
        bytes, kSealEvaluationBundleMagic, operation);
    BinaryReader reader(payload, operation);
    const auto descriptor_bytes = reader.read_blob();
    const Digest encoded_identity = reader.read_digest();
    const auto public_key_bytes = reader.read_blob();
    const auto relin_key_bytes = reader.read_blob();
    const auto galois_key_bytes = reader.read_blob();
    if (!reader.empty()) {
        reader.fail("trailing bundle data");
    }

    SealParameterDescriptor descriptor =
        deserialize_parameter_descriptor(descriptor_bytes, operation);
    auto seal_context = make_context_from_moduli(
        descriptor.parameters, descriptor.coefficient_moduli, operation);
    auto public_key = std::make_shared<seal::PublicKey>(
        deserialize_seal_key<seal::PublicKey>(
            *seal_context, public_key_bytes, operation));
    auto relin_keys = std::make_shared<seal::RelinKeys>(
        deserialize_seal_key<seal::RelinKeys>(
            *seal_context, relin_key_bytes, operation));
    auto galois_keys = std::make_shared<seal::GaloisKeys>();
    if (descriptor.parameters.generate_galois_keys) {
        *galois_keys = deserialize_seal_key<seal::GaloisKeys>(
            *seal_context, galois_key_bytes, operation);
    } else if (!galois_key_bytes.empty()) {
        throw std::invalid_argument(std::string(operation) +
                                    ": Galois key data is undeclared");
    }
    validate_evaluation_keys(descriptor.parameters, *seal_context,
                             *public_key, *relin_keys, *galois_keys,
                             operation);
    const Digest computed_identity = make_context_identity(
        descriptor_bytes, public_key_bytes, relin_key_bytes,
        galois_key_bytes, operation);
    if (computed_identity != encoded_identity ||
        digest_is_empty(encoded_identity)) {
        throw std::invalid_argument(std::string(operation) +
                                    ": evaluation context identity mismatch");
    }

    auto encoder = std::make_shared<seal::BatchEncoder>(*seal_context);
    auto evaluator = std::make_shared<seal::Evaluator>(*seal_context);
    auto counters = std::make_shared<CounterState>();
    auto prepared_plaintexts =
        std::make_shared<PreparedPlaintextCache>();
    return EvalContext{std::move(descriptor.parameters), encoded_identity,
                       seal_context, encoder, evaluator, relin_keys,
                       galois_keys, counters, prepared_plaintexts, public_key};
}

// Fixed-message preprocessing is stored independently because it can be large
// and is derived entirely during setup. Each cell records every RNS-level NTT
// plaintext needed by the online server.
std::vector<std::uint8_t>
SealBackend::serialize_fixed_message_cell_preprocessing(
    const EvalContext &context) {
    constexpr const char *operation =
        "SealBackend::serialize_fixed_message_cell_preprocessing";
    if (!context.prepared_plaintexts) {
        throw std::invalid_argument(std::string(operation) +
                                    ": plaintext cache is missing");
    }
    const FixedMessageCellPreprocessingShape shape =
        fixed_message_cell_preprocessing_shape(context, operation);
    const std::size_t width = slot_count(context);

    std::array<std::shared_ptr<const PreparedPlaintextCache::Entry>,
               kFixedMessageCellCount>
        cells{};
    {
        std::lock_guard lock(context.prepared_plaintexts->mutex);
        cells = context.prepared_plaintexts->fixed_message_cells;
    }
    if (std::any_of(cells.begin(), cells.end(),
                    [](const auto &entry) { return !entry; })) {
        throw std::invalid_argument(std::string(operation) +
                                    ": fixed message cells are not "
                                    "preprocessed");
    }

    std::vector<std::uint8_t> result;
    result.reserve(shape.artifact_bytes);
    result.insert(result.end(),
                  kSealFixedMessageCellPreprocessingMagic.begin(),
                  kSealFixedMessageCellPreprocessingMagic.end());
    result.push_back(kSealFixedMessageCellPreprocessingVersion);
    result.push_back(0);
    const Digest context_id = storage_context_id(context);
    result.insert(result.end(), context_id.begin(), context_id.end());
    append_u64(result, checked_u64(width, operation));
    append_u64(result,
                       checked_u64(kFixedMessageCellCount, operation));
    append_u64(result,
                       checked_u64(shape.data_levels, operation));

    for (std::size_t cell = 0; cell < cells.size(); ++cell) {
        const auto &entry = cells[cell];
        const std::size_t occupied_slot =
            fixed_message_cell_slot(width, cell);
        if (entry->slots.size() != width ||
            entry->by_level.size() != shape.data_levels) {
            throw std::invalid_argument(std::string(operation) +
                                        ": cached cell shape changed");
        }
        for (std::size_t slot = 0; slot < width; ++slot) {
            const Fp expected =
                slot == occupied_slot ? Fp::one() : Fp::zero();
            if (!(entry->slots[slot] == expected)) {
                throw std::invalid_argument(std::string(operation) +
                                            ": cached cell mask changed");
            }
        }

        append_u64(result, checked_u64(cell, operation));
        append_u64(result,
                           checked_u64(occupied_slot, operation));
        append_u64(
            result, checked_u64(shape.data_levels, operation));
        std::size_t encoded_ntt_bytes = 0;
        std::size_t level_index = 0;
        for (auto level = context.context->first_context_data(); level;
             level = level->next_context_data(), ++level_index) {
            const auto found = entry->by_level.find(level->parms_id());
            if (found == entry->by_level.end()) {
                throw std::invalid_argument(
                    std::string(operation) +
                    ": cached cell is missing a data level");
            }
            const seal::Plaintext &plaintext = found->second;
            const std::size_t coefficient_count =
                checked_artifact_multiply(
                    level->parms().poly_modulus_degree(),
                    level->parms().coeff_modulus().size(), operation);
            if (!plaintext.is_ntt_form() ||
                plaintext.parms_id() != level->parms_id() ||
                plaintext.coeff_count() != coefficient_count ||
                plaintext.scale() != 1.0 ||
                !seal::is_valid_for(plaintext, *context.context)) {
                throw std::invalid_argument(std::string(operation) +
                                            ": cached NTT plaintext is "
                                            "invalid");
            }

            append_u64(result,
                               checked_u64(level_index, operation));
            for (const std::uint64_t word : level->parms_id()) {
                append_u64(result, word);
            }
            append_u64(
                result, checked_u64(coefficient_count, operation));
            append_artifact_u64_words(
                result,
                std::span<const std::uint64_t>(plaintext.data(),
                                               coefficient_count),
                operation);
            encoded_ntt_bytes = checked_artifact_add(
                encoded_ntt_bytes,
                checked_artifact_multiply(coefficient_count,
                                          sizeof(std::uint64_t),
                                          operation),
                operation);
        }
        if (entry->ntt_coefficient_bytes != encoded_ntt_bytes) {
            throw std::invalid_argument(std::string(operation) +
                                        ": cached NTT byte accounting "
                                        "changed");
        }
    }
    append_fixed_message_cell_preprocessing_checksum(result);
    if (result.size() != shape.artifact_bytes) {
        throw std::logic_error(std::string(operation) +
                               ": internal artifact size mismatch");
    }
    return result;
}

Digest SealBackend::fixed_message_cell_preprocessing_artifact_id(
    std::span<const std::uint8_t> bytes) {
    if (bytes.empty()) {
        throw std::invalid_argument(
            "SealBackend::fixed_message_cell_preprocessing_artifact_id: "
            "artifact is empty");
    }
    return make_fixed_message_cell_preprocessing_id(bytes);
}

SealFixedMessageCellPreprocessingMetadata
SealBackend::restore_fixed_message_cell_preprocessing(
    const EvalContext &context, std::span<const std::uint8_t> bytes,
    const Digest &expected_artifact_id,
    const SealFixedMessageCellPreprocessingDecodeLimits &limits) {
    constexpr const char *operation =
        "SealBackend::restore_fixed_message_cell_preprocessing";
    if (!context.context || !context.prepared_plaintexts) {
        throw std::invalid_argument(std::string(operation) +
                                    ": evaluation context is incomplete");
    }
    if (limits.max_artifact_bytes == 0 ||
        limits.max_ntt_coefficient_bytes == 0 || bytes.empty() ||
        bytes.size() > limits.max_artifact_bytes) {
        throw std::invalid_argument(std::string(operation) +
                                    ": invalid or exceeded caller-owned "
                                    "limits");
    }
    if (digest_is_empty(expected_artifact_id)) {
        throw std::invalid_argument(std::string(operation) +
                                    ": expected artifact identity is "
                                    "empty");
    }
    const Digest artifact_id =
        fixed_message_cell_preprocessing_artifact_id(bytes);
    if (artifact_id != expected_artifact_id) {
        throw std::invalid_argument(std::string(operation) +
                                    ": artifact identity mismatch");
    }
    const auto payload =
        verified_fixed_message_cell_preprocessing_payload(bytes,
                                                          operation);
    const FixedMessageCellPreprocessingShape shape =
        fixed_message_cell_preprocessing_shape(context, operation);
    if (bytes.size() != shape.artifact_bytes) {
        throw std::invalid_argument(std::string(operation) +
                                    ": artifact has a noncanonical size");
    }
    if (shape.ntt_coefficient_bytes >
        limits.max_ntt_coefficient_bytes) {
        throw std::invalid_argument(std::string(operation) +
                                    ": NTT coefficient storage exceeds "
                                    "its caller-owned limit");
    }

    auto cache_is_empty = [&context]() {
        return context.prepared_plaintexts->by_hash.empty() &&
               std::all_of(
                   context.prepared_plaintexts->fixed_message_cells.begin(),
                   context.prepared_plaintexts->fixed_message_cells.end(),
                   [](const auto &entry) { return !entry; }) &&
               context.prepared_plaintexts->stats ==
                   PlaintextPreprocessingStats{};
    };
    {
        std::lock_guard lock(context.prepared_plaintexts->mutex);
        if (!cache_is_empty()) {
            throw std::invalid_argument(std::string(operation) +
                                        ": destination cache is not "
                                        "empty");
        }
    }

    BinaryReader reader(payload, operation);
    const Digest encoded_context_id = reader.read_digest();
    const std::size_t encoded_width = reader.read_size();
    const std::size_t encoded_cells = reader.read_size();
    const std::size_t encoded_levels = reader.read_size();
    const std::size_t width = slot_count(context);
    if (encoded_context_id != storage_context_id(context)) {
        throw std::invalid_argument(std::string(operation) +
                                    ": storage context identity "
                                    "mismatch");
    }
    if (encoded_width != width ||
        encoded_cells != kFixedMessageCellCount ||
        encoded_levels != shape.data_levels) {
        throw std::invalid_argument(std::string(operation) +
                                    ": fixed-message-cell shape mismatch");
    }

    std::array<std::shared_ptr<const PreparedPlaintextCache::Entry>,
               kFixedMessageCellCount>
        cells{};
    for (std::size_t cell = 0; cell < cells.size(); ++cell) {
        if (reader.read_size() != cell) {
            reader.fail("duplicate or out-of-order cell index");
        }
        const std::size_t occupied_slot =
            fixed_message_cell_slot(width, cell);
        if (reader.read_size() != occupied_slot) {
            reader.fail("fixed cell occupies a noncanonical slot");
        }
        if (reader.read_size() != shape.data_levels) {
            reader.fail("fixed cell has a noncanonical level count");
        }

        auto entry = std::make_shared<PreparedPlaintextCache::Entry>();
        entry->slots.assign(width, Fp::zero());
        entry->slots[occupied_slot] = Fp::one();
        std::size_t level_index = 0;
        for (auto level = context.context->first_context_data(); level;
             level = level->next_context_data(), ++level_index) {
            if (reader.read_size() != level_index) {
                reader.fail("duplicate or out-of-order level index");
            }
            seal::parms_id_type encoded_parms_id{};
            for (std::uint64_t &word : encoded_parms_id) {
                word = reader.read_u64();
            }
            if (encoded_parms_id != level->parms_id()) {
                reader.fail("data-level identity mismatch");
            }
            const std::size_t coefficient_count =
                checked_artifact_multiply(
                    level->parms().poly_modulus_degree(),
                    level->parms().coeff_modulus().size(), operation);
            if (reader.read_size() != coefficient_count) {
                reader.fail("NTT coefficient count mismatch");
            }

            seal::Plaintext plaintext(coefficient_count);
            plaintext.parms_id() = level->parms_id();
            read_artifact_u64_words(
                reader,
                std::span<std::uint64_t>(plaintext.data(),
                                         coefficient_count),
                operation);
            const auto &moduli = level->parms().coeff_modulus();
            const std::size_t degree =
                level->parms().poly_modulus_degree();
            for (std::size_t modulus_index = 0;
                 modulus_index < moduli.size(); ++modulus_index) {
                const std::uint64_t modulus =
                    moduli[modulus_index].value();
                for (std::size_t coefficient = 0; coefficient < degree;
                     ++coefficient) {
                    const std::uint64_t value =
                        plaintext[modulus_index * degree + coefficient];
                    if (value >= modulus) {
                        reader.fail("noncanonical NTT coefficient");
                    }
                }
            }
            if (!seal::is_valid_for(plaintext, *context.context)) {
                reader.fail("invalid NTT plaintext representation");
            }
            entry->ntt_coefficient_bytes = checked_artifact_add(
                entry->ntt_coefficient_bytes,
                checked_artifact_multiply(coefficient_count,
                                          sizeof(std::uint64_t),
                                          operation),
                operation);
            if (!entry->by_level
                     .emplace(level->parms_id(), std::move(plaintext))
                     .second) {
                reader.fail("duplicate data-level representation");
            }
        }
        cells[cell] = std::move(entry);
    }
    if (!reader.empty()) {
        reader.fail("trailing artifact data");
    }

    decltype(context.prepared_plaintexts->by_hash) by_hash;
    for (const auto &entry : cells) {
        by_hash[plaintext_cache_hash(entry->slots)].push_back(entry);
    }
    const PlaintextPreprocessingStats stats{
        .logical_plaintexts = kFixedMessageCellCount,
        .level_representations = shape.level_representations,
        .ntt_coefficient_bytes = shape.ntt_coefficient_bytes,
    };
    {
        std::lock_guard lock(context.prepared_plaintexts->mutex);
        if (!cache_is_empty()) {
            throw std::invalid_argument(std::string(operation) +
                                        ": destination cache changed "
                                        "during restoration");
        }
        context.prepared_plaintexts->by_hash = std::move(by_hash);
        context.prepared_plaintexts->fixed_message_cells = cells;
        context.prepared_plaintexts->stats = stats;
    }
    return SealFixedMessageCellPreprocessingMetadata{
        .artifact_id = artifact_id,
        .storage_context_id = encoded_context_id,
        .artifact_bytes = shape.artifact_bytes,
        .fixed_message_cells = kFixedMessageCellCount,
        .data_levels = shape.data_levels,
        .level_representations = shape.level_representations,
        .ntt_coefficient_bytes = shape.ntt_coefficient_bytes,
    };
}

// Client bundle: the matching public/secret key pair used to encrypt requests
// and decrypt verified outputs.
std::vector<std::uint8_t>
SealBackend::serialize_client_context_bundle(
    const ClientContext &context) {
    constexpr const char *operation =
        "SealBackend::serialize_client_context_bundle";
    if (!context.context || !context.public_key || !context.secret_key) {
        throw std::invalid_argument(std::string(operation) +
                                    ": client context is incomplete");
    }
    const SealParameterDescriptor descriptor = live_parameter_descriptor(
        context.parameters, *context.context, operation);
    validate_client_key_pair(*context.context, *context.public_key,
                             *context.secret_key, operation);
    const Digest identity = storage_context_id(context);
    const std::vector<std::uint8_t> descriptor_bytes =
        serialize_parameter_descriptor(descriptor, operation);
    const std::vector<std::uint8_t> public_key_bytes =
        serialize_seal_object(*context.public_key, operation);
    const std::vector<std::uint8_t> secret_key_bytes =
        serialize_seal_object(*context.secret_key, operation);

    std::vector<std::uint8_t> result;
    result.insert(result.end(), kSealClientBundleMagic.begin(),
                  kSealClientBundleMagic.end());
    result.push_back(kSealContextBundleVersion);
    result.push_back(0);
    append_blob(result, descriptor_bytes, operation);
    result.insert(result.end(), identity.begin(), identity.end());
    append_blob(result, public_key_bytes, operation);
    append_blob(result, secret_key_bytes, operation);
    append_bundle_checksum(result);
    return result;
}

SealBackend::ClientContext SealBackend::deserialize_client_context_bundle(
    std::span<const std::uint8_t> bytes) {
    constexpr const char *operation =
        "SealBackend::deserialize_client_context_bundle";
    const auto payload = verified_bundle_payload(
        bytes, kSealClientBundleMagic, operation);
    BinaryReader reader(payload, operation);
    const auto descriptor_bytes = reader.read_blob();
    const Digest identity = reader.read_digest();
    const auto public_key_bytes = reader.read_blob();
    const auto secret_key_bytes = reader.read_blob();
    if (!reader.empty()) {
        reader.fail("trailing bundle data");
    }
    if (digest_is_empty(identity)) {
        throw std::invalid_argument(std::string(operation) +
                                    ": client context identity is empty");
    }

    SealParameterDescriptor descriptor =
        deserialize_parameter_descriptor(descriptor_bytes, operation);
    auto seal_context = make_context_from_moduli(
        descriptor.parameters, descriptor.coefficient_moduli, operation);
    auto public_key = std::make_shared<seal::PublicKey>(
        deserialize_seal_key<seal::PublicKey>(
            *seal_context, public_key_bytes, operation));
    auto secret_key = std::make_shared<seal::SecretKey>(
        deserialize_seal_key<seal::SecretKey>(
            *seal_context, secret_key_bytes, operation));
    validate_client_key_pair(*seal_context, *public_key, *secret_key,
                             operation);

    auto encoder = std::make_shared<seal::BatchEncoder>(*seal_context);
    auto encryptor =
        std::make_shared<seal::Encryptor>(*seal_context, *public_key);
    auto decryptor =
        std::make_shared<seal::Decryptor>(*seal_context, *secret_key);
    auto counters = std::make_shared<CounterState>();
    return ClientContext{std::move(descriptor.parameters), seal_context,
                         encoder, encryptor, decryptor, secret_key, counters,
                         identity, public_key};
}

// Public-verifier bundle: exact context parameters and identity only. It is a
// deliberately key-free projection for transcript-packing verification.
std::vector<std::uint8_t>
SealBackend::serialize_public_verifier_context_bundle(
    const PublicVerifierContext &context) {
    constexpr const char *operation =
        "SealBackend::serialize_public_verifier_context_bundle";
    if (!context.context || !context.encoder ||
        digest_is_empty(context.storage_id)) {
        throw std::invalid_argument(std::string(operation) +
                                    ": verifier context is incomplete");
    }
    const SealParameterDescriptor descriptor = live_parameter_descriptor(
        context.parameters, *context.context, operation);
    const std::vector<std::uint8_t> descriptor_bytes =
        serialize_parameter_descriptor(descriptor, operation);

    std::vector<std::uint8_t> result;
    result.insert(result.end(), kSealPublicVerifierBundleMagic.begin(),
                  kSealPublicVerifierBundleMagic.end());
    result.push_back(kSealContextBundleVersion);
    result.push_back(0);
    append_blob(result, descriptor_bytes, operation);
    result.insert(result.end(), context.storage_id.begin(),
                  context.storage_id.end());
    append_bundle_checksum(result);
    return result;
}

SealBackend::PublicVerifierContext
SealBackend::deserialize_public_verifier_context_bundle(
    std::span<const std::uint8_t> bytes,
    const Digest &expected_storage_id,
    const SealPublicVerifierContextDecodeLimits &limits) {
    constexpr const char *operation =
        "SealBackend::deserialize_public_verifier_context_bundle";
    if (limits.max_bundle_bytes == 0 ||
        limits.max_poly_modulus_degree == 0 ||
        limits.max_rns_limbs == 0 ||
        bytes.size() > limits.max_bundle_bytes) {
        throw std::invalid_argument(std::string(operation) +
                                    ": invalid or exceeded caller-owned "
                                    "limits");
    }
    if (digest_is_empty(expected_storage_id)) {
        throw std::invalid_argument(std::string(operation) +
                                    ": expected storage identity is empty");
    }
    const auto payload = verified_bundle_payload(
        bytes, kSealPublicVerifierBundleMagic, operation);
    BinaryReader reader(payload, operation);
    const auto descriptor_bytes = reader.read_blob();
    const Digest encoded_identity = reader.read_digest();
    if (!reader.empty()) {
        reader.fail("trailing bundle data");
    }
    if (encoded_identity != expected_storage_id) {
        throw std::invalid_argument(std::string(operation) +
                                    ": storage identity mismatch");
    }

    SealParameterDescriptor descriptor =
        deserialize_parameter_descriptor(descriptor_bytes, operation);
    if (serialize_parameter_descriptor(descriptor, operation) !=
        std::vector<std::uint8_t>(descriptor_bytes.begin(),
                                  descriptor_bytes.end())) {
        throw std::invalid_argument(std::string(operation) +
                                    ": noncanonical parameter descriptor");
    }
    if (descriptor.parameters.poly_modulus_degree >
            limits.max_poly_modulus_degree ||
        descriptor.parameters.fresh_rns_limbs > limits.max_rns_limbs ||
        descriptor.coefficient_moduli.empty() ||
        descriptor.coefficient_moduli.size() - 1U >
            limits.max_rns_limbs) {
        throw std::invalid_argument(std::string(operation) +
                                    ": parameter descriptor exceeds its "
                                    "caller-owned limits");
    }
    auto seal_context = make_context_from_moduli(
        descriptor.parameters, descriptor.coefficient_moduli, operation);
    const SealParameterDescriptor live = live_parameter_descriptor(
        descriptor.parameters, *seal_context, operation);
    if (serialize_parameter_descriptor(live, operation) !=
        std::vector<std::uint8_t>(descriptor_bytes.begin(),
                                  descriptor_bytes.end())) {
        throw std::invalid_argument(std::string(operation) +
                                    ": restored parameter context changed");
    }
    auto encoder = std::make_shared<seal::BatchEncoder>(*seal_context);
    PublicVerifierContext result{
        std::move(descriptor.parameters), encoded_identity,
        std::move(seal_context), std::move(encoder)};
    if (serialize_public_verifier_context_bundle(result) !=
        std::vector<std::uint8_t>(bytes.begin(), bytes.end())) {
        throw std::invalid_argument(std::string(operation) +
                                    ": noncanonical verifier bundle");
    }
    return result;
}

// Restore matching server/client roles together and reject bundles originating
// from independently generated setups.
SealBackend::Contexts SealBackend::deserialize_context_bundles(
    std::span<const std::uint8_t> evaluation_bundle,
    std::span<const std::uint8_t> client_bundle) {
    constexpr const char *operation =
        "SealBackend::deserialize_context_bundles";
    EvalContext eval =
        deserialize_evaluation_context_bundle(evaluation_bundle);
    ClientContext client = deserialize_client_context_bundle(client_bundle);
    if (storage_context_id(eval) != storage_context_id(client)) {
        throw std::invalid_argument(std::string(operation) +
                                    ": client and server identities differ");
    }
    const SealParameterDescriptor eval_descriptor =
        live_parameter_descriptor(eval.parameters, *eval.context, operation);
    const SealParameterDescriptor client_descriptor =
        live_parameter_descriptor(client.parameters, *client.context,
                                  operation);
    if (serialize_parameter_descriptor(eval_descriptor, operation) !=
            serialize_parameter_descriptor(client_descriptor, operation) ||
        serialize_seal_object(*eval.public_key, operation) !=
            serialize_seal_object(*client.public_key, operation)) {
        throw std::invalid_argument(std::string(operation) +
                                    ": client and server key descriptions "
                                    "differ");
    }
    return Contexts{std::move(eval), std::move(client)};
}

} // namespace laminate::fhe
