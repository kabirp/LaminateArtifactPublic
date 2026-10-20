#ifndef LAMINATE_PAYLOAD_TRACE_ENCRYPTED_TRACE_HPP
#define LAMINATE_PAYLOAD_TRACE_ENCRYPTED_TRACE_HPP

/// @file encrypted_trace.hpp
/// @brief Backend-generic public-or-encrypted proof-trace data types.

#include "laminate/fhe/backend.hpp"
#include "laminate/fhe/value.hpp"
#include "laminate/payload/trace.hpp"

#include <cstddef>
#include <optional>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

namespace laminate::payload {

enum class TraceLayerLayout : std::uint8_t { Wide, BPeriodic };

struct TraceEncryptionPlan {
    std::vector<std::size_t> required_mult_depth_by_layer;

    bool operator==(const TraceEncryptionPlan &other) const = default;

    static TraceEncryptionPlan uniform(const LayeredCircuit &circuit,
                                       std::size_t required_mult_depth) {
        return TraceEncryptionPlan{std::vector<std::size_t>(
            circuit.layers.size(), required_mult_depth)};
    }

    void validate(const LayeredCircuit &circuit) const {
        if (required_mult_depth_by_layer.size() != circuit.layers.size()) {
            throw std::invalid_argument(
                "TraceEncryptionPlan: expected one depth per layer");
        }
    }
};

template <fhe::FheBackend Backend> struct EncryptedTraceLayer {
    TraceLayerLayout layout = TraceLayerLayout::Wide;
    LayerDimensions dimensions;
    std::size_t required_mult_depth = 0;
    /// Canonical physical stored-value order. Logical wire positions resolve
    /// through the circuit-derived LayerStorageLayout. Public circuit values
    /// remain plaintext; private values retain their ciphertext even when
    /// their hidden plaintext happens to be zero.
    std::vector<fhe::FheValue<Backend>> wires;
};

/// Non-owning view used by read-only trace helpers. Its lifetime is bounded
/// by the caller-owned layer.
template <fhe::FheBackend Backend> struct EncryptedTraceLayerView {
    TraceLayerLayout layout = TraceLayerLayout::Wide;
    LayerDimensions dimensions;
    std::size_t required_mult_depth = 0;
    std::span<const fhe::FheValue<Backend>> wires;
};

template <fhe::FheBackend Backend>
EncryptedTraceLayerView<Backend>
view_of(const EncryptedTraceLayer<Backend> &layer) {
    return EncryptedTraceLayerView<Backend>{
        layer.layout, layer.dimensions, layer.required_mult_depth,
        layer.wires};
}

template <fhe::FheBackend Backend> struct EncryptedTrace {
    PayloadShape shape;
    TraceProvenance provenance = TraceProvenance::SyntheticTrace;
    Digest circuit_id{};
    Digest trace_id{};
    /// Declared backend context for these ciphertexts when the backend
    /// supports persistent encodings. The producing API stamps this value;
    /// callers must still pair client ciphertexts with their matching
    /// evaluation context. Generic, non-persistable backends leave it unset.
    std::optional<Digest> backend_context_id;
    std::vector<EncryptedTraceLayer<Backend>> layers;
};

} // namespace laminate::payload

#endif // LAMINATE_PAYLOAD_TRACE_ENCRYPTED_TRACE_HPP
