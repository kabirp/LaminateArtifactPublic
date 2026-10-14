#ifndef LAMINATE_DELEGATION_BASE_WIRE_DETAIL_EXTENSION_VALUES_HPP
#define LAMINATE_DELEGATION_BASE_WIRE_DETAIL_EXTENSION_VALUES_HPP

/// @file extension_values.hpp
/// @brief Persistent codecs for one F_{65537^8} FHE sumcheck value.

#include "laminate/delegation/base/wire/detail/field_values.hpp"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <utility>

namespace laminate::delegation::base_wire_detail {

template <fhe::PersistableFheBackend Backend, typename StorageContext>
    requires fhe::CiphertextStorageContext<Backend, StorageContext>
void append_persistent_ciphertext(
    Bytes &output, const StorageContext &context,
    const typename Backend::Ciphertext &ciphertext,
    const char *operation) {
    const Bytes encoded = Backend::serialize_for_storage(context, ciphertext);
    wire_detail::append_size(output, encoded.size(), operation);
    output.insert(output.end(), encoded.begin(), encoded.end());
}

template <fhe::PersistableFheBackend Backend, typename StorageContext>
    requires fhe::CiphertextStorageContext<Backend, StorageContext>
typename Backend::Ciphertext read_persistent_ciphertext(
    Reader &reader, const StorageContext &context, DecodeBudget &budget,
    const char *) {
    const std::size_t bytes = reader.read_size();
    budget.add_ciphertext(bytes);
    return Backend::deserialize_from_storage(context,
                                             reader.read_bytes(bytes));
}

/// Public coefficients and encrypted coefficients share one canonical
/// extension-value record. A bitmap is used when every public coefficient is
/// zero; mixed public values use the backend's self-delimiting value codec.
template <fhe::PersistableFheBackend Backend, typename StorageContext>
    requires fhe::CiphertextStorageContext<Backend, StorageContext>
std::size_t append_extension(
    Bytes &output, const StorageContext &context,
    const fhe::ExtensionValue<Backend> &extension,
    const char *operation) {
    if (extension.has_public_nonzero()) {
        wire_detail::append_size(output, kExtensionDegree + 1U, operation);
        std::size_t live = 0;
        for (const fhe::FheValue<Backend> &coefficient : extension) {
            fhe::append_self_delimiting_fhe_value<Backend>(
                output, context, coefficient, operation);
            live += static_cast<std::size_t>(coefficient.is_encrypted());
        }
        return live;
    }

    wire_detail::append_size(output, kExtensionDegree, operation);
    std::uint8_t presence_mask = 0;
    for (std::size_t coefficient = 0;
         coefficient < kExtensionDegree; ++coefficient) {
        if (extension[coefficient].is_encrypted()) {
            presence_mask |= static_cast<std::uint8_t>(1U << coefficient);
        }
    }
    output.push_back(presence_mask);
    std::size_t live = 0;
    for (const auto &coefficient : extension) {
        if (!coefficient.is_encrypted()) {
            continue;
        }
        append_persistent_ciphertext<Backend>(output, context,
                                              coefficient.ciphertext(),
                                              operation);
        ++live;
    }
    return live;
}

template <fhe::FheBackend Backend>
void account_public_extension(
    const fhe::ExtensionValue<Backend> &extension,
    ProofTransportSizeBreakdown &breakdown) {
    if (!extension.has_public_nonzero()) {
        return;
    }
    for (const auto &coefficient : extension) {
        if (!coefficient.is_public()) {
            continue;
        }
        ++breakdown.public_plaintext_coefficients;
        breakdown.public_plaintext_field_elements +=
            coefficient.plaintext().is_scalar()
                ? 1U
                : coefficient.plaintext().slots().size();
    }
}

template <fhe::PersistableFheBackend Backend, typename StorageContext>
    requires fhe::CiphertextStorageContext<Backend, StorageContext>
fhe::ExtensionValue<Backend> read_extension(
    Reader &reader, const StorageContext &context, DecodeBudget &budget,
    const char *operation) {
    const std::size_t encoding = reader.read_size();
    if (encoding == kExtensionDegree + 1U) {
        fhe::ExtensionValue<Backend> mixed;
        for (std::size_t coefficient = 0;
             coefficient < kExtensionDegree; ++coefficient) {
            const auto decoded =
                fhe::decode_self_delimiting_fhe_value<Backend>(
                    context, reader.remaining_bytes(),
                    std::numeric_limits<std::uint64_t>::max(),
                    [&](std::span<const std::uint8_t> ciphertext) {
                        budget.add_ciphertext(ciphertext.size());
                        return Backend::deserialize_from_storage(
                            context, ciphertext);
                    },
                    operation);
            (void)reader.read_bytes(decoded.bytes_consumed);
            if (decoded.value.is_public()) {
                budget.add_fields(
                    decoded.value.plaintext().is_scalar()
                        ? 1U
                        : decoded.value.plaintext().slots().size());
            }
            mixed[coefficient] = std::move(decoded.value);
        }
        if (!mixed.has_public_nonzero()) {
            wire_detail::reject(
                operation, "noncanonical mixed extension encoding");
        }
        return mixed;
    }
    if (encoding != kExtensionDegree) {
        wire_detail::reject(operation, "wrong extension-value degree");
    }

    typename Backend::ExtCiphertext result{};
    const std::uint8_t presence_mask = reader.read_u8();
    for (std::size_t coefficient = 0;
         coefficient < kExtensionDegree; ++coefficient) {
        if ((presence_mask & static_cast<std::uint8_t>(1U << coefficient)) !=
            0U) {
            result[coefficient] = read_persistent_ciphertext<Backend>(
                reader, context, budget, operation);
        }
    }
    return fhe::ExtensionValue<Backend>(std::move(result));
}

} // namespace laminate::delegation::base_wire_detail

#endif // LAMINATE_DELEGATION_BASE_WIRE_DETAIL_EXTENSION_VALUES_HPP
