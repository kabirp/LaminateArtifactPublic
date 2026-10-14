#ifndef LAMINATE_GKR_CHALLENGE_LIMITS_HPP
#define LAMINATE_GKR_CHALLENGE_LIMITS_HPP

/// @file challenge_limits.hpp
/// @brief Dimension admission for the paper's GKR challenge-block bound.

#include "laminate/payload/ir/layered.hpp"

#include <algorithm>
#include <bit>
#include <cstddef>
#include <stdexcept>

namespace laminate::gkr {

/// A block evaluation of a nonzero multilinear discrepancy has error at
/// most this many coordinates divided by the challenge-field order. This
/// dimension limit alone does not certify the composed VCoED protocol.
inline constexpr std::size_t kMaximumChallengeBlockCoordinates = 64;

inline void validate_challenge_block_size(std::size_t coordinates) {
    if (coordinates > kMaximumChallengeBlockCoordinates) {
        throw std::invalid_argument(
            "GKR challenge block exceeds the admitted 64 coordinates");
    }
}

/// Check the points sampled together: the initial output point and Base's
/// terminal slot points. Ciphertext-index sumcheck coordinates and the
/// multiplication selector are separate scalar challenges. Laned output
/// packing rounds its scalar domain up to at least one complete ciphertext.
/// This reads only public dimensions and allocates no wire or slot tables.
inline void validate_challenge_dimensions(
    const payload::LayeredCircuit &circuit) {
    circuit.shape.validate();
    if (circuit.layers.empty()) {
        throw std::invalid_argument("GKR circuit has no output layer");
    }
    const std::size_t output_width =
        payload::layer_dimensions(circuit.layers.front()).padded_size;
    if (!std::has_single_bit(output_width)) {
        throw std::invalid_argument("GKR output width is not a power of two");
    }
    const std::size_t slot_variables =
        std::bit_width(circuit.shape.slot_count) - 1U;
    const std::size_t logical_variables =
        (std::bit_width(output_width) - 1U) +
        (std::bit_width(circuit.shape.value_width()) - 1U);
    validate_challenge_block_size(slot_variables);
    validate_challenge_block_size(
        std::max(logical_variables, slot_variables));
}

} // namespace laminate::gkr

#endif // LAMINATE_GKR_CHALLENGE_LIMITS_HPP
