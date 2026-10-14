/// @file descriptor.cpp
/// @brief Public trace-descriptor and circuit-identity validation.

#include "../format/schema.hpp"

#include <stdexcept>

namespace laminate::payload {
using namespace trace_store_format;

void validate_encrypted_trace_descriptor(
    const EncryptedTraceDescriptor &descriptor) {
    descriptor.shape.validate();
    (void)provenance_code(descriptor.provenance);
    if (descriptor.layers.empty() ||
        descriptor.layers.size() > kMaximumTraceLayers) {
        throw std::invalid_argument(
            "EncryptedTraceDescriptor: invalid v4 layer count");
    }
    const TraceLayerLayout expected_layout =
        descriptor.shape.kind == PayloadKind::Wide
            ? TraceLayerLayout::Wide
            : TraceLayerLayout::BPeriodic;
    for (const EncryptedTraceLayerDescriptor &layer : descriptor.layers) {
        validate_dimensions(layer.dimensions);
        if (layer.layout != expected_layout || layer.record_count == 0 ||
            layer.record_count > layer.dimensions.logical_size ||
            layer.record_count > kMaximumRecordsPerLayer) {
            throw std::invalid_argument(
                "EncryptedTraceDescriptor: layer metadata is inconsistent");
        }
    }
}

void validate_encrypted_trace_descriptor_for_circuit(
    const EncryptedTraceDescriptor &descriptor,
    const PayloadCircuit &payload, const LayeredCircuit &circuit) {
    validate_compilation_pair(payload, circuit);
    validate_encrypted_trace_descriptor(descriptor);
    if (!(descriptor.shape == circuit.shape) ||
        descriptor.circuit_id != combined_digest(payload, circuit) ||
        descriptor.layers.size() != circuit.layers.size()) {
        throw std::invalid_argument(
            "EncryptedTraceDescriptor: circuit identity or shape mismatch");
    }
    const std::vector<LayerStorageLayout> storage =
        canonical_trace_storage_layout(circuit);
    for (std::size_t layer = 0; layer < circuit.layers.size(); ++layer) {
        if (!(descriptor.layers[layer].dimensions ==
              layer_dimensions(circuit.layers[layer])) ||
            descriptor.layers[layer].record_count !=
                storage[layer].stored_wire_count) {
            throw std::invalid_argument(
                "EncryptedTraceDescriptor: circuit layer mismatch");
        }
    }
}

} // namespace laminate::payload
