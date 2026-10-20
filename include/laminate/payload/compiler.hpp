#ifndef LAMINATE_PAYLOAD_COMPILER_HPP
#define LAMINATE_PAYLOAD_COMPILER_HPP

/// @file compiler.hpp
/// @brief Payload-DAG to strict alternating GKR circuit conversion.

#include "laminate/payload/ir/layered.hpp"

namespace laminate::payload {

/// Validate the payload and derive its canonical alternating proof circuit.
/// Layers are returned in GKR order (output first, input last); forwarding and
/// power-of-two padding are explicit in the IR even when storage omits them.
LayeredCircuit compile(const PayloadCircuit &payload);

/// Reject a layered circuit that is valid in isolation but is not the
/// canonical compilation of `payload`.
void validate_compilation_pair(const PayloadCircuit &payload,
                               const LayeredCircuit &layered);

} // namespace laminate::payload

#endif // LAMINATE_PAYLOAD_COMPILER_HPP
