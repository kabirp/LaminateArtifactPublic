#ifndef LAMINATE_FHE_EXTENSION_PACKING_HPP
#define LAMINATE_FHE_EXTENSION_PACKING_HPP

/// @file packing.hpp
/// @brief Fixed-message packing of one or two replicated extension values.

#include "laminate/fhe/extension_value.hpp"
#include "laminate/fhe/layout/fixed_message.hpp"
#include "laminate/fhe/value.hpp"

#include <cstddef>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

namespace laminate::fhe {

/// Pack one or two extension scalars without manufacturing a ciphertext when
/// the complete fixed message is public. Encrypted coordinates still use the
/// backend's preprocessed fixed-cell multiplication.
template <FheBackend Backend>
FheValue<Backend> pack_replicated_extension_values(
    const typename Backend::EvalContext &eval,
    std::span<const ExtensionValue<Backend>> values) {
    const std::size_t slots = Backend::slot_count(eval);
    if (values.empty() || values.size() > 2 ||
        slots < kFixedMessageCellCount) {
        throw std::invalid_argument(
            "pack_replicated_extension_values: values do not fit in slots");
    }

    FheValue<Backend> result = FheValue<Backend>::public_zero();
    for (std::size_t value = 0; value < values.size(); ++value) {
        for (std::size_t coefficient = 0;
             coefficient < kExtensionDegree; ++coefficient) {
            const FheValue<Backend> &coordinate =
                values[value][coefficient];
            if (coordinate.is_public_zero()) {
                continue;
            }
            const std::size_t cell = value * kExtensionDegree + coefficient;
            FheValue<Backend> term;
            if (coordinate.is_encrypted()) {
                term = FheValue<Backend>::from_ciphertext(
                    Backend::mul_plain_fixed_message_cell(
                        eval, coordinate.ciphertext(), cell));
            } else {
                const std::size_t slot = fixed_message_cell_slot(slots, cell);
                const SlotVector source =
                    coordinate.plaintext().materialize(slots);
                SlotVector placed(slots, Fp::zero());
                placed[slot] = source[slot];
                term = FheValue<Backend>::public_slots(std::move(placed));
            }
            value_add_assign<Backend>(eval, result, std::move(term));
        }
    }
    return result;
}

template <FheBackend Backend>
std::vector<Fpk> unpack_extension_scalars(
    const typename Backend::ClientContext &client,
    const FheValue<Backend> &packed, std::size_t value_count) {
    const std::size_t slots = Backend::slot_count(client);
    if (value_count == 0 || value_count > 2 ||
        slots < kFixedMessageCellCount) {
        throw std::invalid_argument(
            "unpack_extension_scalars: values do not fit in slots");
    }
    const SlotVector plaintext = materialize_or_decrypt<Backend>(
        client, packed);
    std::vector<Fpk> result;
    result.reserve(value_count);
    for (std::size_t value = 0; value < value_count; ++value) {
        Fpk::Coefficients coefficients{};
        for (std::size_t coefficient = 0;
             coefficient < kExtensionDegree; ++coefficient) {
            coefficients[coefficient] = plaintext[fixed_message_cell_slot(
                slots, value * kExtensionDegree + coefficient)];
        }
        result.emplace_back(coefficients);
    }
    return result;
}

} // namespace laminate::fhe

#endif // LAMINATE_FHE_EXTENSION_PACKING_HPP
