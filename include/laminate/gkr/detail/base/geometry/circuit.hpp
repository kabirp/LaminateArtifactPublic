#ifndef LAMINATE_GKR_DETAIL_BASE_GEOMETRY_CIRCUIT_HPP
#define LAMINATE_GKR_DETAIL_BASE_GEOMETRY_CIRCUIT_HPP

/// @file circuit.hpp
/// @brief Power-of-two dimensions used by Base layer reductions.

#include "laminate/payload/ir/layered.hpp"

#include <bit>
#include <cstddef>
#include <limits>
#include <stdexcept>
#include <string>

namespace laminate::gkr::base_detail {

inline std::size_t log2_exact(std::size_t value, const char *operation) {
    if (value == 0 || (value & (value - 1)) != 0) {
        throw std::invalid_argument(std::string(operation) +
                                    ": dimension is not a power of two");
    }
    return std::bit_width(value) - 1U;
}

inline std::size_t ciphertext_index_variables(
    const payload::LayeredCircuit &circuit, std::size_t layer) {
    return log2_exact(
        payload::layer_dimensions(circuit.layers.at(layer)).padded_size,
        "LaminateBase ciphertext-index variables");
}

inline std::size_t slot_index_variables(
    const payload::LayeredCircuit &circuit) {
    return log2_exact(circuit.shape.value_width(),
                      "LaminateBase slot-index variables");
}

inline std::size_t layer_vars(const payload::LayeredCircuit &circuit,
                              std::size_t layer) {
    const std::size_t ciphertext_indices =
        ciphertext_index_variables(circuit, layer);
    const std::size_t slots = slot_index_variables(circuit);
    if (ciphertext_indices >
        std::numeric_limits<std::size_t>::max() - slots) {
        throw std::invalid_argument("LaminateBase: variable count overflows");
    }
    return ciphertext_indices + slots;
}

} // namespace laminate::gkr::base_detail

#endif // LAMINATE_GKR_DETAIL_BASE_GEOMETRY_CIRCUIT_HPP
