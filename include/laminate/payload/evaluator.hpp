#ifndef LAMINATE_PAYLOAD_EVALUATOR_HPP
#define LAMINATE_PAYLOAD_EVALUATOR_HPP

/// @file evaluator.hpp
/// @brief Plaintext payload evaluation and unambiguous circuit statistics.

#include "laminate/payload/circuit.hpp"

#include <cstddef>
#include <span>
#include <vector>

namespace laminate::payload {

struct PayloadEvaluation {
    /// `wires[id]` is the complete logical lane/slot vector for wire `id`.
    std::vector<fhe::SlotVector> wires;

    std::vector<fhe::SlotVector>
    output_values(const PayloadCircuit &circuit) const;
};

PayloadEvaluation evaluate(const PayloadCircuit &circuit,
                           std::span<const fhe::SlotVector> inputs);

struct PayloadStats {
    std::size_t add_gates = 0;
    std::size_t add_plain_gates = 0;
    std::size_t mul_gates = 0;
    std::size_t mul_plain_gates = 0;
    std::size_t rotate_gates = 0;

    /// Longest ciphertext-ciphertext multiplication chain, assuming all
    /// payload inputs are encrypted.
    std::size_t ct_ct_multiplicative_depth = 0;
    /// Scheduling proxy: ct-ct and non-uniform ct-plain products cost two
    /// half-levels, while a uniform scalar product costs one.
    std::size_t fhe_half_depth = 0;
    /// Number of strict alternating CT-CT multiplication boundaries.
    /// Every plaintext multiplication remains inside an affine layer.
    std::size_t alternating_multiplicative_depth = 0;
};

PayloadStats analyze(const PayloadCircuit &circuit);

} // namespace laminate::payload

#endif // LAMINATE_PAYLOAD_EVALUATOR_HPP
