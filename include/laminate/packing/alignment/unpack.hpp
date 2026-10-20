#ifndef LAMINATE_PACKING_ALIGNMENT_UNPACK_HPP
#define LAMINATE_PACKING_ALIGNMENT_UNPACK_HPP

/// @file unpack.hpp
/// @brief Recover BhIP-round value vectors from decrypted packed outputs.

#include "laminate/packing/alignment/layout.hpp"

#include <span>
#include <stdexcept>
#include <vector>

namespace laminate::packing {

/// Invert the public placement schedule after packed ciphertext decryption.
/// The result contains one short logical slot vector per BhIP round.
inline std::vector<fhe::SlotVector> unpack_packed_plaintexts(
    const PackingLayout &layout,
    std::span<const fhe::SlotVector> packed_plaintexts) {
    layout.validate();
    if (packed_plaintexts.size() != layout.packed_ciphertext_count) {
        throw std::invalid_argument(
            "unpack_packed_plaintexts: output count does not match layout");
    }
    for (const auto &plaintext : packed_plaintexts) {
        if (plaintext.size() != layout.slot_count) {
            throw std::invalid_argument(
                "unpack_packed_plaintexts: output has wrong slot count");
        }
    }

    std::vector<fhe::SlotVector> messages(
        layout.message_active_slots.size());
    for (const PackingPlacement &placement : layout.placements) {
        fhe::SlotVector &message = messages[placement.message_index];
        if (message.empty()) {
            message.resize(
                layout.message_active_slots[placement.message_index]);
        }
        const fhe::SlotVector &packed =
            packed_plaintexts[placement.packed_index];
        for (std::size_t offset = 0; offset < placement.length; ++offset) {
            message[placement.source_begin + offset] =
                packed[packing_destination_slot(
                    layout, placement, offset)];
        }
    }
    return messages;
}

} // namespace laminate::packing

#endif // LAMINATE_PACKING_ALIGNMENT_UNPACK_HPP
