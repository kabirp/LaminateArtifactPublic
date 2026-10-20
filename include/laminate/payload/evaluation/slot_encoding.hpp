#ifndef LAMINATE_PAYLOAD_EVALUATION_SLOT_ENCODING_HPP
#define LAMINATE_PAYLOAD_EVALUATION_SLOT_ENCODING_HPP

/// @file slot_encoding.hpp
/// @brief Expand logical payload values to the physical SIMD layout.

#include "laminate/payload/circuit.hpp"

#include <algorithm>
#include <cstddef>
#include <span>
#include <stdexcept>

namespace laminate::payload {

inline bool is_zero_slot_vector(std::span<const Fp> values) {
    return std::all_of(values.begin(), values.end(),
                       [](const Fp &value) { return value.is_zero(); });
}

inline fhe::SlotVector expand_for_encryption(const PayloadShape &shape,
                                             const fhe::SlotVector &logical) {
    shape.validate();
    if (logical.size() != shape.value_width()) {
        throw std::invalid_argument(
            "expand_for_encryption: logical wire has the wrong width");
    }
    if (shape.kind == PayloadKind::Wide) {
        return logical;
    }

    // Laned witness packing depends on every physical N/B chunk carrying the
    // same B logical values. A destination-chunk mask can then place a wire
    // directly, with no Galois rotation.
    fhe::SlotVector physical(shape.slot_count);
    for (std::size_t slot = 0; slot < physical.size(); ++slot) {
        physical[slot] = logical[slot % shape.lane_count];
    }
    return physical;
}

} // namespace laminate::payload

#endif // LAMINATE_PAYLOAD_EVALUATION_SLOT_ENCODING_HPP
