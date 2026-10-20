/// @file context.cpp
/// @brief SEAL parameter validation, context construction, and key creation.

#include "context_internal.hpp"
#include "binary_codec.hpp"
#include "state.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace laminate::fhe::seal_detail {

constexpr std::string_view kSealContextIdentityDomain =
    "LaminateImpl/SealContextIdentity/v1";

// Canonical parameter descriptors are shared by fresh context construction
// and persisted role bundles. They include exact RNS primes, rather than only
// the requested bit widths, so storage identities bind the actual context.

std::uint64_t security_level_word(seal::sec_level_type security_level,
                                  const char *operation) {
    switch (security_level) {
    case seal::sec_level_type::none:
        return 0;
    case seal::sec_level_type::tc128:
        return 128;
    case seal::sec_level_type::tc192:
        return 192;
    case seal::sec_level_type::tc256:
        return 256;
    }
    throw std::invalid_argument(std::string(operation) +
                                ": unsupported security level");
}

seal::sec_level_type decode_security_level(std::uint64_t value,
                                           BinaryReader &reader) {
    switch (value) {
    case 0:
        return seal::sec_level_type::none;
    case 128:
        return seal::sec_level_type::tc128;
    case 192:
        return seal::sec_level_type::tc192;
    case 256:
        return seal::sec_level_type::tc256;
    default:
        reader.fail("unsupported security level");
    }
}

void append_size_vector(std::vector<std::uint8_t> &output,
                        std::span<const int> values,
                        const char *operation) {
    append_u64(output, checked_u64(values.size(), operation));
    for (const int value : values) {
        if (value < 0) {
            throw std::invalid_argument(std::string(operation) +
                                        ": negative bit width");
        }
        append_u64(output, static_cast<std::uint64_t>(value));
    }
}

void append_u64_vector(std::vector<std::uint8_t> &output,
                       std::span<const std::uint64_t> values,
                       const char *operation) {
    append_u64(output, checked_u64(values.size(), operation));
    for (const std::uint64_t value : values) {
        append_u64(output, value);
    }
}

std::vector<int> read_size_vector(BinaryReader &reader) {
    const std::size_t count = reader.read_size();
    if (count > reader.remaining() / 8) {
        reader.fail("truncated bit-width vector");
    }
    std::vector<int> result;
    result.reserve(count);
    for (std::size_t index = 0; index < count; ++index) {
        const std::uint64_t value = reader.read_u64();
        if (value > static_cast<std::uint64_t>(
                        std::numeric_limits<int>::max())) {
            reader.fail("bit width exceeds int");
        }
        result.push_back(static_cast<int>(value));
    }
    return result;
}

std::vector<std::uint64_t> read_u64_vector(BinaryReader &reader) {
    const std::size_t count = reader.read_size();
    if (count > reader.remaining() / 8) {
        reader.fail("truncated integer vector");
    }
    std::vector<std::uint64_t> result;
    result.reserve(count);
    for (std::size_t index = 0; index < count; ++index) {
        result.push_back(reader.read_u64());
    }
    return result;
}

std::vector<std::uint8_t> serialize_parameter_descriptor(
    const SealParameterDescriptor &descriptor, const char *operation) {
    const SealParameters &parameters = descriptor.parameters;
    std::vector<std::uint8_t> result;
    append_u64(result,
                       checked_u64(parameters.poly_modulus_degree,
                                   operation));
    append_u64(result,
                       checked_u64(parameters.fresh_rns_limbs, operation));
    append_size_vector(result, parameters.data_prime_bit_sizes, operation);
    append_u64_vector(result, parameters.exact_data_primes, operation);
    append_u64(result, parameters.exact_special_prime);
    if (parameters.bits_per_data_prime < 0 ||
        parameters.special_prime_bits < 0) {
        throw std::invalid_argument(std::string(operation) +
                                    ": negative coefficient-modulus width");
    }
    append_u64(
        result, static_cast<std::uint64_t>(parameters.bits_per_data_prime));
    append_u64(
        result, static_cast<std::uint64_t>(parameters.special_prime_bits));
    append_u64(
        result, security_level_word(parameters.security_level, operation));
    append_bool(result, parameters.track_deterministic_noise_bounds);
    append_u64(
        result,
        checked_u64(parameters.max_fresh_ciphertext_modulus_bits,
                    operation));
    append_u64(result,
                       checked_u64(parameters.max_key_modulus_bits,
                                   operation));
    append_bool(result, parameters.generate_galois_keys);
    append_u64_vector(result, descriptor.coefficient_moduli, operation);
    return result;
}

SealParameterDescriptor deserialize_parameter_descriptor(
    std::span<const std::uint8_t> bytes, const char *operation) {
    BinaryReader reader(bytes, operation);
    SealParameters parameters;
    parameters.poly_modulus_degree =
        checked_size(reader.read_u64(), operation);
    parameters.fresh_rns_limbs =
        checked_size(reader.read_u64(), operation);
    parameters.data_prime_bit_sizes = read_size_vector(reader);
    parameters.exact_data_primes = read_u64_vector(reader);
    parameters.exact_special_prime = reader.read_u64();
    const std::uint64_t data_bits = reader.read_u64();
    const std::uint64_t special_bits = reader.read_u64();
    if (data_bits > static_cast<std::uint64_t>(
                        std::numeric_limits<int>::max()) ||
        special_bits > static_cast<std::uint64_t>(
                           std::numeric_limits<int>::max())) {
        reader.fail("coefficient-modulus width exceeds int");
    }
    parameters.bits_per_data_prime = static_cast<int>(data_bits);
    parameters.special_prime_bits = static_cast<int>(special_bits);
    parameters.security_level =
        decode_security_level(reader.read_u64(), reader);
    parameters.track_deterministic_noise_bounds = reader.read_bool();
    parameters.max_fresh_ciphertext_modulus_bits =
        checked_size(reader.read_u64(), operation);
    parameters.max_key_modulus_bits =
        checked_size(reader.read_u64(), operation);
    parameters.generate_galois_keys = reader.read_bool();
    std::vector<std::uint64_t> coefficient_moduli =
        read_u64_vector(reader);
    if (!reader.empty()) {
        reader.fail("trailing parameter data");
    }
    return SealParameterDescriptor{std::move(parameters),
                                   std::move(coefficient_moduli)};
}

std::vector<std::uint64_t> context_coefficient_moduli(
    const seal::SEALContext &context, const char *operation) {
    const auto key_data = context.key_context_data();
    if (!key_data) {
        throw std::invalid_argument(std::string(operation) +
                                    ": key context is missing");
    }
    std::vector<std::uint64_t> result;
    result.reserve(key_data->parms().coeff_modulus().size());
    for (const seal::Modulus &modulus : key_data->parms().coeff_modulus()) {
        result.push_back(modulus.value());
    }
    return result;
}

void hash_length(Sha256Hasher &hasher, std::size_t size,
                 const char *operation) {
    std::array<std::uint8_t, 8> encoded{};
    const std::uint64_t value = checked_u64(size, operation);
    for (std::size_t byte = 0; byte < encoded.size(); ++byte) {
        encoded[byte] =
            static_cast<std::uint8_t>((value >> (8U * byte)) & 0xffU);
    }
    hasher.update(encoded);
}

void hash_blob(Sha256Hasher &hasher, std::span<const std::uint8_t> bytes,
               const char *operation) {
    hash_length(hasher, bytes.size(), operation);
    hasher.update(bytes);
}

Digest make_context_identity(
    std::span<const std::uint8_t> descriptor,
    std::span<const std::uint8_t> public_key,
    std::span<const std::uint8_t> relin_keys,
    std::span<const std::uint8_t> galois_keys,
    const char *operation) {
    Sha256Hasher hasher;
    hasher.update(std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t *>(
            kSealContextIdentityDomain.data()),
        kSealContextIdentityDomain.size()));
    hash_blob(hasher, descriptor, operation);
    hash_blob(hasher, public_key, operation);
    hash_blob(hasher, relin_keys, operation);
    hash_blob(hasher, galois_keys, operation);
    return hasher.finish();
}

bool digest_is_empty(const Digest &digest) {
    return std::all_of(digest.begin(), digest.end(),
                       [](std::uint8_t byte) { return byte == 0; });
}

// Validate the caller's symbolic profile before generating or accepting any
// concrete coefficient moduli.
void validate_parameter_description(const SealParameters &parameters,
                                    const char *operation) {
    if (parameters.poly_modulus_degree < 2 ||
        !std::has_single_bit(parameters.poly_modulus_degree) ||
        parameters.poly_modulus_degree >
            std::numeric_limits<std::size_t>::max() / 2 ||
        kBaseFieldOrder % (2 * parameters.poly_modulus_degree) != 1) {
        throw std::invalid_argument(std::string(operation) +
                                    ": N is not a batching-compatible "
                                    "power of two");
    }
    if (parameters.fresh_rns_limbs == 0 ||
        parameters.bits_per_data_prime < 20 ||
        parameters.bits_per_data_prime > 60 ||
        parameters.special_prime_bits < 20 ||
        parameters.special_prime_bits > 60) {
        throw std::invalid_argument(std::string(operation) +
                                    ": invalid coefficient-modulus shape");
    }
    if (!parameters.data_prime_bit_sizes.empty() &&
        !parameters.exact_data_primes.empty()) {
        throw std::invalid_argument(std::string(operation) +
                                    ": generated widths and exact primes "
                                    "are mutually exclusive");
    }
    if (!parameters.data_prime_bit_sizes.empty()) {
        if (parameters.data_prime_bit_sizes.size() !=
                parameters.fresh_rns_limbs ||
            parameters.data_prime_bit_sizes.front() !=
                static_cast<int>(std::bit_width(kOuterFieldOrder)) ||
            std::any_of(parameters.data_prime_bit_sizes.begin() + 1,
                        parameters.data_prime_bit_sizes.end(),
                        [](int bits) { return bits < 18 || bits > 60; })) {
            throw std::invalid_argument(
                std::string(operation) +
                ": invalid ordered data-prime widths");
        }
    }
    if (!parameters.exact_data_primes.empty()) {
        if (parameters.exact_data_primes.size() !=
                parameters.fresh_rns_limbs ||
            parameters.exact_special_prime == 0 ||
            std::bit_width(parameters.exact_special_prime) !=
                parameters.special_prime_bits) {
            throw std::invalid_argument(std::string(operation) +
                                        ": invalid exact coefficient moduli");
        }
    } else if (parameters.exact_special_prime != 0) {
        throw std::invalid_argument(std::string(operation) +
                                    ": exact special prime has no data "
                                    "profile");
    }
    (void)security_level_word(parameters.security_level, operation);
}

void validate_actual_moduli(const SealParameters &parameters,
                            std::span<const std::uint64_t> moduli,
                            const char *operation) {
    if (parameters.fresh_rns_limbs ==
            std::numeric_limits<std::size_t>::max() ||
        moduli.size() != parameters.fresh_rns_limbs + 1 ||
        moduli.empty() ||
        (parameters.exact_data_primes.empty() &&
         moduli.front() != kOuterFieldOrder)) {
        throw std::invalid_argument(std::string(operation) +
                                    ": coefficient moduli do not match the "
                                    "declared chain shape");
    }
    for (const std::uint64_t modulus : moduli) {
        if (modulus == 0) {
            throw std::invalid_argument(std::string(operation) +
                                        ": zero coefficient modulus");
        }
    }
    if (!parameters.exact_data_primes.empty()) {
        if (!std::equal(parameters.exact_data_primes.begin(),
                        parameters.exact_data_primes.end(), moduli.begin()) ||
            moduli.back() != parameters.exact_special_prime) {
            throw std::invalid_argument(std::string(operation) +
                                        ": exact coefficient moduli changed");
        }
        return;
    }

    if (!parameters.data_prime_bit_sizes.empty()) {
        for (std::size_t index = 0;
             index < parameters.fresh_rns_limbs; ++index) {
            if (std::bit_width(moduli[index]) !=
                parameters.data_prime_bit_sizes[index]) {
                throw std::invalid_argument(
                    std::string(operation) +
                    ": data-prime width does not match the declaration");
            }
        }
    } else {
        for (std::size_t index = 1;
             index < parameters.fresh_rns_limbs; ++index) {
            if (std::bit_width(moduli[index]) !=
                parameters.bits_per_data_prime) {
                throw std::invalid_argument(
                    std::string(operation) +
                    ": uniform data-prime width changed");
            }
        }
    }
    if (std::bit_width(moduli.back()) != parameters.special_prime_bits) {
        throw std::invalid_argument(std::string(operation) +
                                    ": special-prime width changed");
    }
}

std::shared_ptr<seal::SEALContext> make_context_from_moduli(
    const SealParameters &parameters,
    std::span<const std::uint64_t> coefficient_moduli,
    const char *operation) {
    validate_parameter_description(parameters, operation);
    validate_actual_moduli(parameters, coefficient_moduli, operation);

    seal::EncryptionParameters encryption(seal::scheme_type::bgv);
    encryption.set_poly_modulus_degree(parameters.poly_modulus_degree);
    encryption.set_plain_modulus(kBaseFieldOrder);
    std::vector<seal::Modulus> moduli;
    moduli.reserve(coefficient_moduli.size());
    for (const std::uint64_t modulus : coefficient_moduli) {
        moduli.emplace_back(modulus);
    }
    encryption.set_coeff_modulus(std::move(moduli));
    auto context = std::make_shared<seal::SEALContext>(
        encryption, true, parameters.security_level);
    if (!context->parameters_set()) {
        throw std::invalid_argument(
            std::string(operation) + ": invalid BGV parameters: " +
            context->parameter_error_message());
    }
    if (context->first_context_data()
            ->parms()
            .coeff_modulus()
            .size() != parameters.fresh_rns_limbs) {
        throw std::invalid_argument(std::string(operation) +
                                    ": unexpected fresh ciphertext chain "
                                    "shape");
    }
    const std::size_t fresh_bits = static_cast<std::size_t>(
        context->first_context_data()->total_coeff_modulus_bit_count());
    const std::size_t key_bits = static_cast<std::size_t>(
        context->key_context_data()->total_coeff_modulus_bit_count());
    if (parameters.max_fresh_ciphertext_modulus_bits != 0 &&
        fresh_bits > parameters.max_fresh_ciphertext_modulus_bits) {
        throw std::invalid_argument(std::string(operation) +
                                    ": fresh ciphertext modulus exceeds cap");
    }
    if (parameters.max_key_modulus_bits != 0 &&
        key_bits > parameters.max_key_modulus_bits) {
        throw std::invalid_argument(std::string(operation) +
                                    ": key modulus exceeds cap");
    }
    return context;
}

SealParameterDescriptor live_parameter_descriptor(
    const SealParameters &parameters, const seal::SEALContext &context,
    const char *operation) {
    validate_parameter_description(parameters, operation);
    SealParameterDescriptor result{
        parameters, context_coefficient_moduli(context, operation)};
    validate_actual_moduli(parameters, result.coefficient_moduli, operation);
    const auto key_data = context.key_context_data();
    if (!key_data || key_data->qualifiers().sec_level !=
                         parameters.security_level) {
        throw std::invalid_argument(std::string(operation) +
                                    ": live security level changed");
    }
    const std::size_t fresh_bits = static_cast<std::size_t>(
        context.first_context_data()->total_coeff_modulus_bit_count());
    const std::size_t key_bits = static_cast<std::size_t>(
        key_data->total_coeff_modulus_bit_count());
    if ((parameters.max_fresh_ciphertext_modulus_bits != 0 &&
         fresh_bits > parameters.max_fresh_ciphertext_modulus_bits) ||
        (parameters.max_key_modulus_bits != 0 &&
         key_bits > parameters.max_key_modulus_bits)) {
        throw std::invalid_argument(std::string(operation) +
                                    ": live modulus cap is violated");
    }
    return result;
}

// Bundle restoration checks that the serialized public and secret keys are a
// pair by round-tripping one small batched plaintext.
void validate_client_key_pair(const seal::SEALContext &context,
                              const seal::PublicKey &public_key,
                              const seal::SecretKey &secret_key,
                              const char *operation) {
    if (!seal::is_valid_for(public_key, context) ||
        !seal::is_valid_for(secret_key, context)) {
        throw std::invalid_argument(std::string(operation) +
                                    ": invalid client key material");
    }
    try {
        seal::BatchEncoder encoder(context);
        std::vector<std::uint64_t> expected(encoder.slot_count(), 0);
        expected.front() = 1;
        expected.back() = kBaseFieldOrder - 1;
        seal::Plaintext plaintext;
        encoder.encode(expected, plaintext);
        seal::Ciphertext ciphertext;
        seal::Encryptor encryptor(context, public_key);
        encryptor.encrypt(plaintext, ciphertext);
        seal::Decryptor decryptor(context, secret_key);
        seal::Plaintext decrypted;
        decryptor.decrypt(ciphertext, decrypted);
        std::vector<std::uint64_t> observed;
        encoder.decode(decrypted, observed);
        if (observed != expected) {
            throw std::invalid_argument(std::string(operation) +
                                        ": public and secret keys do not "
                                        "match");
        }
    } catch (const std::invalid_argument &) {
        throw;
    } catch (const std::exception &error) {
        throw std::invalid_argument(std::string(operation) +
                                    ": client key-pair check failed: " +
                                    error.what());
    }
}

// Evaluation bundles must contain exactly the public capabilities promised by
// the profile. Galois keys are optional only when rotations were not enabled.
void validate_evaluation_keys(const SealParameters &parameters,
                              const seal::SEALContext &context,
                              const seal::PublicKey &public_key,
                              const seal::RelinKeys &relin_keys,
                              const seal::GaloisKeys &galois_keys,
                              const char *operation) {
    if (!seal::is_valid_for(public_key, context) ||
        !seal::is_valid_for(relin_keys, context) ||
        relin_keys.data().empty()) {
        throw std::invalid_argument(std::string(operation) +
                                    ": invalid public evaluation keys");
    }
    if (parameters.generate_galois_keys) {
        if (!seal::is_valid_for(galois_keys, context) ||
            galois_keys.data().empty()) {
            throw std::invalid_argument(std::string(operation) +
                                        ": Galois keys are missing or "
                                        "invalid");
        }
    } else if (!galois_keys.data().empty()) {
        throw std::invalid_argument(std::string(operation) +
                                    ": undeclared Galois keys are present");
    }
}



} // namespace laminate::fhe::seal_detail

namespace laminate::fhe {

using seal_detail::SealParameterDescriptor;
using seal_detail::digest_is_empty;
using seal_detail::live_parameter_descriptor;
using seal_detail::make_context_identity;
using seal_detail::serialize_parameter_descriptor;
using seal_detail::serialize_seal_object;
using seal_detail::validate_evaluation_keys;

// Explicit depth-eight parameter profile for Base and payload diagnostics.
SealParameters make_depth8_diagnostic_parameters(
    bool generate_galois_keys) {
    // Bottom-to-top data order: q0, two small proof-reserve primes, then
    // seven payload heads. Every data prime is one modulo both t and 2N.
    return SealParameters{
        .poly_modulus_degree = std::size_t{1} << 14,
        .fresh_rns_limbs = 10,
        .data_prime_bit_sizes = {},
        .exact_data_primes =
            {kOuterFieldOrder,
             15'032'614'913ULL,
             53'687'910'401ULL,
             96'638'238'721ULL,
             98'785'755'137ULL,
             118'113'402'881ULL,
             122'408'435'713ULL,
             246'964'387'841ULL,
             272'734'584'833ULL,
             292'062'232'577ULL},
        .exact_special_prime = 8'590'163'969ULL,
        .special_prime_bits = 34,
        .security_level = seal::sec_level_type::none,
        .max_fresh_ciphertext_modulus_bits = 420,
        .generate_galois_keys = generate_galois_keys,
    };
}

SealBackend::Contexts
SealBackend::create(const SealParameters &parameters) {
    // Keep the construction order visible: validate the profile, choose exact
    // primes, create the BGV context, enforce modulus caps, generate role
    // keys, then bind the complete public evaluation material to one identity.
    if (parameters.poly_modulus_degree < 2 ||
        !std::has_single_bit(parameters.poly_modulus_degree) ||
        parameters.poly_modulus_degree >
            std::numeric_limits<std::size_t>::max() / 2 ||
        kBaseFieldOrder % (2 * parameters.poly_modulus_degree) != 1) {
        throw std::invalid_argument(
            "SealBackend::create: N must be a batching-compatible power of two");
    }
    if (parameters.fresh_rns_limbs == 0 ||
        parameters.bits_per_data_prime < 20 ||
        parameters.bits_per_data_prime > 60 ||
        parameters.special_prime_bits < 20 ||
        parameters.special_prime_bits > 60) {
        throw std::invalid_argument(
            "SealBackend::create: invalid coefficient-modulus shape");
    }

    if (!parameters.data_prime_bit_sizes.empty() &&
        !parameters.exact_data_primes.empty()) {
        throw std::invalid_argument(
            "SealBackend::create: choose generated widths or exact primes");
    }
    if (!parameters.data_prime_bit_sizes.empty()) {
        if (parameters.data_prime_bit_sizes.size() !=
                parameters.fresh_rns_limbs ||
            parameters.data_prime_bit_sizes.front() !=
                static_cast<int>(std::bit_width(kOuterFieldOrder)) ||
            std::any_of(parameters.data_prime_bit_sizes.begin() + 1,
                        parameters.data_prime_bit_sizes.end(),
                        [](int bits) { return bits < 18 || bits > 60; })) {
            throw std::invalid_argument(
                "SealBackend::create: invalid ordered data-prime widths");
        }
    }

    if (!parameters.exact_data_primes.empty()) {
        if (parameters.exact_data_primes.size() !=
                parameters.fresh_rns_limbs ||
            parameters.exact_special_prime == 0 ||
            std::bit_width(parameters.exact_special_prime) !=
                parameters.special_prime_bits) {
            throw std::invalid_argument(
                "SealBackend::create: invalid exact coefficient moduli");
        }
    } else if (parameters.exact_special_prime != 0) {
        throw std::invalid_argument(
            "SealBackend::create: exact special prime has no data profile");
    }

    seal::EncryptionParameters encryption(seal::scheme_type::bgv);
    encryption.set_poly_modulus_degree(parameters.poly_modulus_degree);
    encryption.set_plain_modulus(kBaseFieldOrder);
    std::vector<seal::Modulus> coefficient_moduli;
    if (!parameters.exact_data_primes.empty()) {
        coefficient_moduli.reserve(parameters.fresh_rns_limbs + 1);
        for (const std::uint64_t prime : parameters.exact_data_primes) {
            coefficient_moduli.emplace_back(prime);
        }
        coefficient_moduli.emplace_back(parameters.exact_special_prime);
    } else {
        std::vector<int> bit_sizes = parameters.data_prime_bit_sizes.empty()
                                         ? std::vector<int>(
                                               parameters.fresh_rns_limbs,
                                               parameters.bits_per_data_prime)
                                         : parameters.data_prime_bit_sizes;
        // Data primes preserve correction factor one across every switch by
        // using primes modulo lcm(2N,t). The key-switch special prime is not a
        // data-chain drop, so generate it independently with only the NTT
        // congruence. This leaves the smallest correction-preserving prime
        // available for a data head.
        coefficient_moduli = seal::CoeffModulus::Create(
            parameters.poly_modulus_degree,
            seal::Modulus(kBaseFieldOrder), bit_sizes);
        if (parameters.data_prime_bit_sizes.empty()) {
            std::reverse(
                coefficient_moduli.begin(),
                coefficient_moduli.begin() +
                    static_cast<std::ptrdiff_t>(
                        parameters.fresh_rns_limbs));
        }
        // Pin the surviving bottom data prime to the native Poseidon/Spartan
        // field. Coefficient commitments and their R1CS therefore use the
        // exact live BGV modulus rather than an isomorphic-width field.
        coefficient_moduli.front() = seal::Modulus(kOuterFieldOrder);

        const seal::Modulus special = seal::CoeffModulus::Create(
            parameters.poly_modulus_degree,
            {parameters.special_prime_bits}).front();
        if (std::find(coefficient_moduli.begin(),
                      coefficient_moduli.end(), special) !=
            coefficient_moduli.end()) {
            throw std::logic_error(
                "SealBackend::create: generated special prime collides "
                "with the data chain; use exact coefficient moduli");
        }
        coefficient_moduli.push_back(special);
    }
    encryption.set_coeff_modulus(std::move(coefficient_moduli));

    auto context = std::make_shared<seal::SEALContext>(
        encryption, true, parameters.security_level);
    if (!context->parameters_set()) {
        throw std::invalid_argument(
            std::string("SealBackend::create: invalid BGV parameters: ") +
            context->parameter_error_message());
    }
    if (context->first_context_data()
            ->parms()
            .coeff_modulus()
            .size() != parameters.fresh_rns_limbs) {
        throw std::logic_error(
            "SealBackend::create: unexpected fresh ciphertext chain shape");
    }
    const std::size_t fresh_modulus_bits = static_cast<std::size_t>(
        context->first_context_data()->total_coeff_modulus_bit_count());
    const std::size_t key_modulus_bits = static_cast<std::size_t>(
        context->key_context_data()->total_coeff_modulus_bit_count());
    if (parameters.max_fresh_ciphertext_modulus_bits != 0 &&
        fresh_modulus_bits >
            parameters.max_fresh_ciphertext_modulus_bits) {
        throw std::invalid_argument(
            "SealBackend::create: fresh ciphertext modulus exceeds cap");
    }
    if (parameters.max_key_modulus_bits != 0 &&
        key_modulus_bits > parameters.max_key_modulus_bits) {
        throw std::invalid_argument(
            "SealBackend::create: key modulus exceeds cap");
    }

    seal::KeyGenerator key_generator(*context);
    auto public_key = std::make_shared<seal::PublicKey>();
    key_generator.create_public_key(*public_key);
    auto relin_keys = std::make_shared<seal::RelinKeys>();
    key_generator.create_relin_keys(*relin_keys);
    auto galois_keys = std::make_shared<seal::GaloisKeys>();
    if (parameters.generate_galois_keys) {
        key_generator.create_galois_keys(*galois_keys);
    }
    auto encoder = std::make_shared<seal::BatchEncoder>(*context);
    auto evaluator = std::make_shared<seal::Evaluator>(*context);
    auto encryptor =
        std::make_shared<seal::Encryptor>(*context, *public_key);
    auto secret_key =
        std::make_shared<seal::SecretKey>(key_generator.secret_key());
    auto decryptor =
        std::make_shared<seal::Decryptor>(*context, *secret_key);
    auto counters = std::make_shared<CounterState>();
    auto prepared_plaintexts =
        std::make_shared<PreparedPlaintextCache>();

    constexpr const char *identity_operation = "SealBackend::create";
    validate_evaluation_keys(parameters, *context, *public_key, *relin_keys,
                             *galois_keys, identity_operation);
    const SealParameterDescriptor descriptor = live_parameter_descriptor(
        parameters, *context, identity_operation);
    const std::vector<std::uint8_t> descriptor_bytes =
        serialize_parameter_descriptor(descriptor, identity_operation);
    const std::vector<std::uint8_t> public_key_bytes =
        serialize_seal_object(*public_key, identity_operation);
    const std::vector<std::uint8_t> relin_key_bytes =
        serialize_seal_object(*relin_keys, identity_operation);
    const std::vector<std::uint8_t> galois_key_bytes =
        parameters.generate_galois_keys
            ? serialize_seal_object(*galois_keys, identity_operation)
            : std::vector<std::uint8_t>{};
    const Digest storage_id = make_context_identity(
        descriptor_bytes, public_key_bytes, relin_key_bytes,
        galois_key_bytes, identity_operation);
    EvalContext eval{parameters, storage_id, context, encoder, evaluator,
                     relin_keys, galois_keys, counters, prepared_plaintexts,
                     public_key};
    ClientContext client{parameters, context, encoder, encryptor, decryptor,
                         secret_key, counters, storage_id, public_key};
    return Contexts{std::move(eval), std::move(client)};
}

// The verifier projection retains public parameter metadata only. It has no
// evaluation, encryption, or decryption capability.
SealBackend::PublicVerifierContext
SealBackend::make_public_verifier_context(const EvalContext &context) {
    constexpr const char *operation =
        "SealBackend::make_public_verifier_context(eval)";
    if (!context.context || !context.encoder ||
        digest_is_empty(context.storage_id)) {
        throw std::invalid_argument(std::string(operation) +
                                    ": evaluation context is incomplete");
    }
    (void)live_parameter_descriptor(context.parameters, *context.context,
                                    operation);
    return PublicVerifierContext{context.parameters, context.storage_id,
                                 context.context, context.encoder};
}

SealBackend::PublicVerifierContext
SealBackend::make_public_verifier_context(const ClientContext &context) {
    constexpr const char *operation =
        "SealBackend::make_public_verifier_context(client)";
    if (!context.context || !context.encoder ||
        digest_is_empty(context.storage_id)) {
        throw std::invalid_argument(std::string(operation) +
                                    ": client context is incomplete");
    }
    (void)live_parameter_descriptor(context.parameters, *context.context,
                                    operation);
    return PublicVerifierContext{context.parameters, context.storage_id,
                                 context.context, context.encoder};
}


} // namespace laminate::fhe
