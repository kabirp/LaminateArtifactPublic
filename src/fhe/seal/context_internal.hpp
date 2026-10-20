#ifndef LAMINATE_SRC_FHE_SEAL_CONTEXT_INTERNAL_HPP
#define LAMINATE_SRC_FHE_SEAL_CONTEXT_INTERNAL_HPP

/// @file context_internal.hpp
/// @brief Private context identity and key-validation boundary.

#include "laminate/fhe/seal_backend.hpp"

#include <span>
#include <sstream>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

namespace laminate::fhe::seal_detail {

struct SealParameterDescriptor {
    SealParameters parameters;
    std::vector<std::uint64_t> coefficient_moduli;
};

bool digest_is_empty(const Digest &digest);

void validate_parameter_description(const SealParameters &parameters,
                                    const char *operation);
void validate_actual_moduli(const SealParameters &parameters,
                            std::span<const std::uint64_t> moduli,
                            const char *operation);

std::shared_ptr<seal::SEALContext> make_context_from_moduli(
    const SealParameters &parameters,
    std::span<const std::uint64_t> coefficient_moduli,
    const char *operation);

SealParameterDescriptor live_parameter_descriptor(
    const SealParameters &parameters, const seal::SEALContext &context,
    const char *operation);

void validate_client_key_pair(const seal::SEALContext &context,
                              const seal::PublicKey &public_key,
                              const seal::SecretKey &secret_key,
                              const char *operation);
void validate_evaluation_keys(const SealParameters &parameters,
                              const seal::SEALContext &context,
                              const seal::PublicKey &public_key,
                              const seal::RelinKeys &relin_keys,
                              const seal::GaloisKeys &galois_keys,
                              const char *operation);

std::vector<std::uint8_t> serialize_parameter_descriptor(
    const SealParameterDescriptor &descriptor, const char *operation);
SealParameterDescriptor deserialize_parameter_descriptor(
    std::span<const std::uint8_t> bytes, const char *operation);

template <typename SealObject>
std::vector<std::uint8_t> serialize_seal_object(
    const SealObject &object, const char *operation) {
    std::stringstream stream(std::ios::binary | std::ios::in |
                             std::ios::out);
    try {
        object.save(stream, seal::compr_mode_type::none);
    } catch (const std::exception &error) {
        throw std::invalid_argument(std::string(operation) +
                                    ": SEAL serialization failed: " +
                                    error.what());
    }
    if (!stream) {
        throw std::invalid_argument(std::string(operation) +
                                    ": SEAL serialization failed");
    }
    const std::string bytes = stream.str();
    return std::vector<std::uint8_t>(bytes.begin(), bytes.end());
}

template <typename SealObject>
SealObject deserialize_seal_key(const seal::SEALContext &context,
                                std::span<const std::uint8_t> bytes,
                                const char *operation) {
    if (bytes.empty() ||
        bytes.size() > static_cast<std::size_t>(
                           std::numeric_limits<std::streamoff>::max())) {
        throw std::invalid_argument(std::string(operation) +
                                    ": invalid SEAL key length");
    }
    SealObject result;
    try {
        const std::streamoff consumed = result.load(
            context,
            reinterpret_cast<const seal::seal_byte *>(bytes.data()),
            bytes.size());
        if (consumed != static_cast<std::streamoff>(bytes.size())) {
            throw std::invalid_argument(std::string(operation) +
                                        ": trailing SEAL key data");
        }
    } catch (const std::invalid_argument &) {
        throw;
    } catch (const std::exception &error) {
        throw std::invalid_argument(std::string(operation) +
                                    ": invalid SEAL key: " + error.what());
    }
    if (serialize_seal_object(result, operation) !=
        std::vector<std::uint8_t>(bytes.begin(), bytes.end())) {
        throw std::invalid_argument(std::string(operation) +
                                    ": noncanonical SEAL key encoding");
    }
    return result;
}

Digest make_context_identity(
    std::span<const std::uint8_t> descriptor,
    std::span<const std::uint8_t> public_key,
    std::span<const std::uint8_t> relin_keys,
    std::span<const std::uint8_t> galois_keys,
    const char *operation);

} // namespace laminate::fhe::seal_detail

#endif // LAMINATE_SRC_FHE_SEAL_CONTEXT_INTERNAL_HPP
