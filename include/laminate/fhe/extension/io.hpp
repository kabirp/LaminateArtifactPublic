#ifndef LAMINATE_FHE_EXTENSION_IO_HPP
#define LAMINATE_FHE_EXTENSION_IO_HPP

/// @file io.hpp
/// @brief Decryption, modulus switching, and canonical extension encodings.

#include "laminate/fhe/extension_value.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <vector>

namespace laminate::fhe {
namespace detail {

inline void append_u64(std::vector<std::uint8_t> &output,
                       std::size_t value) {
    if (value > std::numeric_limits<std::uint64_t>::max()) {
        throw std::overflow_error(
            "serialize_extension: size does not fit u64");
    }
    const std::uint64_t word = static_cast<std::uint64_t>(value);
    for (std::size_t byte = 0; byte < 8; ++byte) {
        output.push_back(static_cast<std::uint8_t>(
            (word >> (8U * byte)) & std::uint64_t{0xff}));
    }
}

} // namespace detail

template <FheBackend Backend>
std::vector<Fpk> decrypt_extension(
    const typename Backend::ClientContext &client,
    const typename Backend::ExtCiphertext &ciphertext) {
    std::array<SlotVector, kExtensionDegree> coefficients{};
    const std::size_t expected_slots = Backend::slot_count(client);
    for (std::size_t coefficient = 0; coefficient < kExtensionDegree;
         ++coefficient) {
        if (!ciphertext[coefficient]) {
            coefficients[coefficient].assign(
                expected_slots, Fp::zero());
            continue;
        }
        coefficients[coefficient] = Backend::decrypt(
            client, *ciphertext[coefficient]);
        if (coefficients[coefficient].size() != expected_slots) {
            throw std::invalid_argument(
                "decrypt_extension: backend returned the wrong slot count");
        }
    }
    std::vector<Fpk> result(expected_slots);
    for (std::size_t slot = 0; slot < expected_slots; ++slot) {
        Fpk::Coefficients value{};
        for (std::size_t coefficient = 0; coefficient < kExtensionDegree;
             ++coefficient) {
            value[coefficient] = coefficients[coefficient][slot];
        }
        result[slot] = Fpk(value);
    }
    return result;
}

/// Canonical extension encoding: fixed domain/version, one coordinate bitmap,
/// and a length-prefixed ciphertext only for each live coordinate.
template <FheBackend Backend>
std::vector<std::uint8_t> serialize_extension(
    const typename Backend::ExtCiphertext &ciphertext) {
    std::vector<std::uint8_t> result{'L', 'M', 'E', 'X', 2};
    detail::append_u64(result, kExtensionDegree);
    static_assert(kExtensionDegree <= 8);
    std::uint8_t presence_mask = 0;
    for (std::size_t coefficient = 0;
         coefficient < kExtensionDegree; ++coefficient) {
        if (ciphertext[coefficient]) {
            presence_mask |= static_cast<std::uint8_t>(1U << coefficient);
        }
    }
    result.push_back(presence_mask);
    for (const auto &coefficient : ciphertext) {
        if (!coefficient) {
            continue;
        }
        const std::vector<std::uint8_t> encoded =
            Backend::serialize(*coefficient);
        detail::append_u64(result, encoded.size());
        result.insert(result.end(), encoded.begin(), encoded.end());
    }
    return result;
}

/// Canonical proof/transcript encoding for a public-or-encrypted extension
/// value. Ciphertext/public-zero values use the compact LMEX-v2 encoding. The
/// tagged LMXV-v1 form is used when at least one coefficient is a nonzero
/// public plaintext.
template <FheBackend Backend>
std::vector<std::uint8_t> serialize_extension_value(
    const ExtensionValue<Backend> &value) {
    if (!value.has_public_nonzero()) {
        return serialize_extension<Backend>(value.encrypted_part());
    }

    std::vector<std::uint8_t> result{'L', 'M', 'X', 'V', 1};
    detail::append_u64(result, kExtensionDegree);
    for (const FheValue<Backend> &coefficient : value) {
        if (coefficient.is_public()) {
            const PublicPlaintext &plaintext = coefficient.plaintext();
            if (plaintext.is_scalar()) {
                result.push_back(0);
                detail::append_u64(result, plaintext.scalar().value());
            } else {
                result.push_back(1);
                detail::append_u64(result, plaintext.slots().size());
                for (const Fp &slot : plaintext.slots()) {
                    detail::append_u64(result, slot.value());
                }
            }
            continue;
        }
        result.push_back(2);
        const std::vector<std::uint8_t> encoded =
            Backend::serialize(coefficient.ciphertext());
        detail::append_u64(result, encoded.size());
        result.insert(result.end(), encoded.begin(), encoded.end());
    }
    return result;
}

template <FheBackend Backend>
void mod_switch_extension_value_to_lowest(
    const typename Backend::EvalContext &eval,
    ExtensionValue<Backend> &value) {
    for (FheValue<Backend> &coefficient : value.coefficients()) {
        if (coefficient.is_encrypted()) {
            Backend::mod_switch_to_lowest(eval, coefficient.ciphertext());
        }
    }
}

} // namespace laminate::fhe

#endif // LAMINATE_FHE_EXTENSION_IO_HPP
