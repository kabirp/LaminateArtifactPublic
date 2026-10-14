#ifndef LAMINATE_PAYLOAD_TRACE_TRACE_SINK_HPP
#define LAMINATE_PAYLOAD_TRACE_TRACE_SINK_HPP

/// @file trace_sink.hpp
/// @brief Incremental destinations for encrypted payload-trace snapshots.

#include "laminate/fhe/storage/ciphertext.hpp"
#include "laminate/payload/trace/encrypted_trace.hpp"

#include <cstddef>
#include <stdexcept>
#include <utility>
#include <vector>

namespace laminate::payload {

/// Resident compact trace sink used as a small-instance oracle and at bounded
/// orchestration boundaries. It uses the same incremental contract as the
/// file-backed store and retains one representative per stored value.
template <fhe::FheBackend Backend> class InMemoryTraceSink {
  public:
    static constexpr bool stores_only_live_wires = true;

    explicit InMemoryTraceSink(
        const typename Backend::EvalContext &eval) {
        if constexpr (fhe::PersistableFheBackend<Backend>) {
            trace_.backend_context_id = Backend::storage_context_id(eval);
        }
    }

    void begin_trace(const PayloadShape &shape, TraceProvenance provenance,
                     const Digest &circuit_id, const Digest &trace_id,
                     std::size_t layer_count) {
        if (started_ || layer_count == 0) {
            throw std::logic_error(
                "InMemoryTraceSink: invalid trace start");
        }
        trace_.shape = shape;
        trace_.provenance = provenance;
        trace_.circuit_id = circuit_id;
        trace_.trace_id = trace_id;
        trace_.layers.resize(layer_count);
        written_.assign(layer_count, false);
        started_ = true;
    }

    void begin_layer(std::size_t layer_index, TraceLayerLayout layout,
                     const LayerDimensions &dimensions,
                     std::size_t required_mult_depth,
                     std::size_t wire_count) {
        if (!started_ || active_ || layer_index >= trace_.layers.size() ||
            written_[layer_index] ||
            wire_count == 0 ||
            wire_count > dimensions.padded_size) {
            throw std::logic_error(
                "InMemoryTraceSink: invalid layer start");
        }
        active_ = true;
        active_layer_ = layer_index;
        auto &layer = trace_.layers[layer_index];
        layer.layout = layout;
        layer.dimensions = dimensions;
        layer.required_mult_depth = required_mult_depth;
        layer.wires.clear();
        layer.wires.reserve(wire_count);
        expected_wires_ = wire_count;
    }

    void append_value(fhe::FheValue<Backend> value) {
        if (!active_) {
            throw std::logic_error(
                "InMemoryTraceSink: no active layer");
        }
        auto &wires = trace_.layers[active_layer_].wires;
        if (wires.size() >= expected_wires_) {
            throw std::logic_error(
                "InMemoryTraceSink: too many wire values");
        }
        wires.push_back(std::move(value));
    }

    void finish_layer() {
        if (!active_ ||
            trace_.layers[active_layer_].wires.size() != expected_wires_) {
            throw std::logic_error(
                "InMemoryTraceSink: incomplete layer");
        }
        written_[active_layer_] = true;
        active_ = false;
    }

    EncryptedTrace<Backend> finish() && {
        if (!started_ || active_) {
            throw std::logic_error(
                "InMemoryTraceSink: incomplete trace");
        }
        for (bool written : written_) {
            if (!written) {
                throw std::logic_error(
                    "InMemoryTraceSink: missing layer");
            }
        }
        started_ = false;
        return std::move(trace_);
    }

  private:
    EncryptedTrace<Backend> trace_;
    std::vector<bool> written_;
    std::size_t active_layer_ = 0;
    std::size_t expected_wires_ = 0;
    bool started_ = false;
    bool active_ = false;
};

} // namespace laminate::payload

#endif // LAMINATE_PAYLOAD_TRACE_TRACE_SINK_HPP
