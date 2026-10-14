#ifndef LAMINATE_PAYLOAD_SETUP_ENCODING_HPP
#define LAMINATE_PAYLOAD_SETUP_ENCODING_HPP

/// @file encoding.hpp
/// @brief Canonical versioned encodings and digests for circuit setup.

#include "laminate/payload/ir/layered.hpp"
#include "laminate/transcript/hash.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace laminate::payload {

std::vector<std::uint8_t> encode_canonical(const PayloadCircuit &circuit);
std::vector<std::uint8_t> encode_canonical(const LayeredCircuit &circuit);

/// Mandatory bounds for decoding an untrusted canonical circuit. Aggregate
/// affine terms are bounded across the complete layered circuit, not merely
/// one gate or layer.
struct CircuitDecodeLimits {
    std::size_t max_encoded_bytes = 0;
    std::size_t max_slots = 0;
    std::size_t max_plaintexts = 0;
    std::size_t max_payload_inputs = 0;
    std::size_t max_payload_gates = 0;
    std::size_t max_payload_outputs = 0;
    std::size_t max_layers = 0;
    std::size_t max_layer_gates = 0;
    std::size_t max_affine_terms = 0;
};

/// Decode the exact public canonical formats above under caller-supplied
/// allocation/work limits. Both functions reject trailing data and require
/// byte-for-byte canonical re-encoding.
PayloadCircuit decode_canonical_payload(
    std::span<const std::uint8_t> encoded,
    const CircuitDecodeLimits &limits);
LayeredCircuit decode_canonical_layered(
    std::span<const std::uint8_t> encoded,
    const CircuitDecodeLimits &limits);

struct CircuitPairDigests {
    Digest payload{};
    Digest layered{};
    Digest combined{};
};

Digest digest(const PayloadCircuit &circuit);
Digest digest(const LayeredCircuit &circuit);
Digest combined_digest(const PayloadCircuit &payload,
                       const LayeredCircuit &layered);
/// Encode each circuit once and derive all three setup-binding digests.
CircuitPairDigests circuit_pair_digests(const PayloadCircuit &payload,
                                        const LayeredCircuit &layered);

} // namespace laminate::payload

#endif // LAMINATE_PAYLOAD_SETUP_ENCODING_HPP
