#ifndef LAMINATE_PACKING_ALIGNMENT_LANED_HPP
#define LAMINATE_PACKING_ALIGNMENT_LANED_HPP

/// @file laned.hpp
/// @brief Geometry for packing B-periodic Laned wires into N-slot tables.

#include "laminate/payload/circuit.hpp"

#include <cstddef>
#include <limits>
#include <stdexcept>

namespace laminate::packing {

struct LanedPackedAddress {
    std::size_t ciphertext = 0;
    std::size_t slot = 0;

    bool operator==(const LanedPackedAddress &) const = default;
};

/// Maps B-slot logical wires into N-slot packed ciphertexts. Each ciphertext
/// holds N/B consecutive wires; the final physical ciphertext count is padded
/// to a power of two for multilinear evaluation, but that tail remains an
/// implicit public zero and is never stored.
struct LanedPackingLayout {
    std::size_t slot_count = 0;
    std::size_t lane_count = 0;
    std::size_t original_wire_count = 0;
    std::size_t logical_ciphertext_count = 0;
    std::size_t padded_ciphertext_count = 0;

    static LanedPackingLayout create(const payload::PayloadShape &shape,
                                     std::size_t original_wire_count) {
        shape.validate();
        if (shape.kind != payload::PayloadKind::Laned ||
            original_wire_count == 0) {
            throw std::invalid_argument(
                "LanedPackingLayout: expected a nonempty laned layer");
        }
        const std::size_t chunks = shape.slot_count / shape.lane_count;
        const std::size_t logical =
            (original_wire_count + chunks - 1) / chunks;
        std::size_t padded = 1;
        while (padded < logical) {
            if (padded > std::numeric_limits<std::size_t>::max() / 2) {
                throw std::overflow_error(
                    "LanedPackingLayout: packed size overflows");
            }
            padded *= 2;
        }
        return LanedPackingLayout{shape.slot_count, shape.lane_count,
                                  original_wire_count, logical, padded};
    }

    std::size_t chunks_per_ciphertext() const {
        return slot_count / lane_count;
    }

    LanedPackedAddress address(std::size_t original_wire,
                               std::size_t lane) const {
        if (original_wire >= original_wire_count || lane >= lane_count) {
            throw std::invalid_argument(
                "LanedPackingLayout::address: index is out of range");
        }
        const std::size_t chunks = chunks_per_ciphertext();
        return LanedPackedAddress{original_wire / chunks,
                                  (original_wire % chunks) * lane_count + lane};
    }

    bool operator==(const LanedPackingLayout &) const = default;
};

} // namespace laminate::packing

#endif // LAMINATE_PACKING_ALIGNMENT_LANED_HPP
