#ifndef LAMINATE_PAYLOAD_TRACE_HPP
#define LAMINATE_PAYLOAD_TRACE_HPP

/// @file trace.hpp
/// @brief Plain alternating-layer trace synthesis and relation checking.

#include "laminate/payload/evaluator.hpp"
#include "laminate/payload/ir/layered.hpp"
#include "laminate/transcript/hash.hpp"

#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

namespace laminate::payload {

/// Declared trace origin bound into protocol metadata. A tag distinguishes
/// reference fixtures from the FHE execution path; the tag alone is not
/// evidence that any computation was executed or verified.
enum class TraceProvenance : std::uint8_t {
    SyntheticTrace,
    FheEvaluated,
};

std::string_view provenance_name(TraceProvenance provenance);

/// Fast trace construction for role adapters whose circuit was certified
/// during preprocessing.
namespace prevalidated_plain_trace {

/// Construct the input layer after the caller has validated the circuit.
std::vector<fhe::SlotVector> make_plain_input_layer_from_validated_circuit(
    const LayeredCircuit &circuit,
    std::span<const fhe::SlotVector> inputs);

} // namespace prevalidated_plain_trace

struct PlainTrace {
    PayloadShape shape;
    TraceProvenance provenance = TraceProvenance::SyntheticTrace;
    /// Original payload-DAG assignment, before alternating conversion.
    std::vector<fhe::SlotVector> payload_wires;
    std::vector<fhe::SlotVector> payload_outputs;
    /// GKR order, matching LayeredCircuit::layers. Every layer includes its
    /// explicit power-of-two padding wires.
    std::vector<std::vector<fhe::SlotVector>> layers;
};

/// Construct the verifier's padded plaintext input layer without evaluating
/// the payload. This is the only trace layer the Laned verifier needs from the
/// client after a real FHE execution.
std::vector<fhe::SlotVector> make_plain_input_layer(
    const LayeredCircuit &circuit,
    std::span<const fhe::SlotVector> inputs);

/// Evaluate only the alternating circuit, bottom-up from payload inputs.
std::vector<std::vector<fhe::SlotVector>>
evaluate_layers(const LayeredCircuit &circuit,
                std::span<const fhe::SlotVector> inputs);

/// Evaluate the payload normally, derive its alternating trace, and require
/// both computations to agree before returning a synthetic trace.
PlainTrace synthesize_trace(const PayloadCircuit &payload,
                            const LayeredCircuit &layered,
                            std::span<const fhe::SlotVector> inputs);

/// Check shape, all payload wires, every alternating layer relation, and L0
/// against the requested payload outputs. Throws on the first discrepancy.
void validate_trace(const PayloadCircuit &payload,
                    const LayeredCircuit &layered,
                    const PlainTrace &trace);

/// ID of the exact logical proof trace, domain-separated by its circuit ID.
/// This benchmark/oracle ID hashes layer values; it is not a hiding commitment.
Digest digest(const PlainTrace &trace, const Digest &circuit_digest);

} // namespace laminate::payload

#endif // LAMINATE_PAYLOAD_TRACE_HPP
