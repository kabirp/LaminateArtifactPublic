#ifndef LAMINATE_GKR_DETAIL_BASE_REFERENCE_TRACE_SOURCE_HPP
#define LAMINATE_GKR_DETAIL_BASE_REFERENCE_TRACE_SOURCE_HPP

/// @file trace_source.hpp
/// @brief Zero-copy adapter used by bounded resident GKR reference provers.

#include "laminate/fhe/value.hpp"
#include "laminate/payload/setup/encoding.hpp"
#include "laminate/payload/trace/encrypted_trace.hpp"
#include "laminate/payload/trace/trace_wire_support.hpp"

#include <cstddef>
#include <functional>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace laminate::gkr::base_detail {

struct ResidentBaseTraceDescriptor {
    struct Layer {
        payload::TraceLayerLayout layout = payload::TraceLayerLayout::Wide;
        payload::LayerDimensions dimensions;
        std::size_t required_mult_depth = 0;
        std::size_t record_count = 0;
    };

    payload::PayloadShape shape;
    std::vector<Layer> layers;
};

template <fhe::FheBackend Backend>
struct ResidentBaseActiveWire {
    std::size_t padded_index = 0;
    std::reference_wrapper<const fhe::FheValue<Backend>> value;
};

template <fhe::FheBackend Backend>
class ResidentBaseTraceSource;

template <fhe::FheBackend Backend>
class ResidentBaseActiveLayerReader {
  public:
    std::optional<ResidentBaseActiveWire<Backend>> next() {
        if (position_ == end()) {
            return std::nullopt;
        }
        const std::size_t padded = support_->padded_index_of(position_++);
        return ResidentBaseActiveWire<Backend>{
            padded, std::cref(source_->value_at_live(layer_,
                                                     position_ - 1U))};
    }

    void rewind() { position_ = 0; }
    std::size_t begin() const noexcept { return 0; }
    std::size_t end() const noexcept { return support_->live_wire_count; }
    std::size_t position() const noexcept { return position_; }
    std::size_t resident_ciphertexts_held() const noexcept { return 0; }

  private:
    ResidentBaseActiveLayerReader(
        const ResidentBaseTraceSource<Backend> &source, std::size_t layer,
        const payload::LayerWireSupport &support)
        : source_(&source), layer_(layer), support_(&support) {}

    const ResidentBaseTraceSource<Backend> *source_;
    std::size_t layer_ = 0;
    const payload::LayerWireSupport *support_;
    std::size_t position_ = 0;

    friend class ResidentBaseTraceSource<Backend>;
};

/// Present a compact resident trace through the same active-record contract
/// as the file-backed prover. Structural padding remains a virtual public
/// zero: this adapter never constructs or returns a ciphertext for it.
template <fhe::FheBackend Backend>
class ResidentBaseTraceSource {
  public:
    ResidentBaseTraceSource(
        const typename Backend::EvalContext &eval,
        const payload::LayeredCircuit &circuit,
        const payload::EncryptedTrace<Backend> &trace)
        : eval_(&eval), trace_(&trace),
          layered_circuit_id_(payload::digest(circuit)),
          support_(payload::canonical_trace_wire_support(circuit)),
          storage_(payload::canonical_trace_storage_layout(circuit)) {
        if (circuit.shape.kind != payload::PayloadKind::Wide ||
            trace.shape != circuit.shape ||
            trace.layers.size() != circuit.layers.size()) {
            throw std::invalid_argument(
                "resident Base trace source shape mismatch");
        }
        descriptor_.shape = trace.shape;
        descriptor_.layers.reserve(trace.layers.size());
        for (std::size_t layer = 0; layer < trace.layers.size(); ++layer) {
            const auto &source = trace.layers[layer];
            if (source.layout != payload::TraceLayerLayout::Wide ||
                source.dimensions !=
                    payload::layer_dimensions(circuit.layers[layer]) ||
                source.wires.size() != storage_[layer].stored_wire_count) {
                throw std::invalid_argument(
                    "resident Base trace layer is not canonical compact "
                    "storage at layer " + std::to_string(layer) +
                    " (stored " + std::to_string(source.wires.size()) +
                    ", expected " +
                    std::to_string(storage_[layer].stored_wire_count) +
                    ")");
            }
            const std::size_t expected_rns_limbs =
                source.required_mult_depth + 1U;
            for (const fhe::FheValue<Backend> &wire : source.wires) {
                if (wire.is_public()) {
                    wire.plaintext().validate_slot_count(
                        Backend::slot_count(eval),
                        "resident Base trace source");
                    continue;
                }
                if (Backend::rns_limb_count(eval, wire.ciphertext()) !=
                    expected_rns_limbs) {
                    throw std::invalid_argument(
                        "resident Base trace ciphertext has the wrong "
                        "proof-ingress level");
                }
            }
            descriptor_.layers.push_back(ResidentBaseTraceDescriptor::Layer{
                source.layout, source.dimensions,
                source.required_mult_depth,
                support_[layer].live_wire_count});
        }
    }

    const ResidentBaseTraceDescriptor &descriptor() const {
        return descriptor_;
    }

    bool matches_backend_context(
        const typename Backend::EvalContext &eval) const noexcept {
        return eval_ == &eval;
    }

    const Digest &layered_circuit_id() const {
        return layered_circuit_id_;
    }

    const payload::LayerWireSupport &layer_support(
        std::size_t layer) const {
        return support_.at(layer);
    }

    ResidentBaseActiveLayerReader<Backend> active_layer_reader(
        std::size_t layer) const {
        return ResidentBaseActiveLayerReader<Backend>(
            *this, layer, support_.at(layer));
    }

    const fhe::FheValue<Backend> &value_at_live(
        std::size_t layer, std::size_t live) const {
        const std::size_t padded = support_.at(layer).padded_index_of(live);
        const auto stored = storage_.at(layer).stored_ordinal_of(padded);
        if (!stored) {
            throw std::logic_error(
                "resident Base active wire has no stored representative");
        }
        return trace_->layers.at(layer).wires.at(*stored);
    }

  private:
    const typename Backend::EvalContext *eval_;
    const payload::EncryptedTrace<Backend> *trace_;
    Digest layered_circuit_id_{};
    ResidentBaseTraceDescriptor descriptor_;
    std::vector<payload::LayerWireSupport> support_;
    std::vector<payload::LayerStorageLayout> storage_;
};

} // namespace laminate::gkr::base_detail

#endif // LAMINATE_GKR_DETAIL_BASE_REFERENCE_TRACE_SOURCE_HPP
