#ifndef LAMINATE_PAYLOAD_TRACE_TRACE_CRYPTO_HPP
#define LAMINATE_PAYLOAD_TRACE_TRACE_CRYPTO_HPP

/// @file trace_crypto.hpp
/// @brief Client-side trace encryption and decryption helpers.

#include "laminate/fhe/storage/ciphertext.hpp"
#include "laminate/payload/setup/encoding.hpp"
#include "laminate/payload/trace/encrypted_trace.hpp"
#include "laminate/payload/evaluation/slot_encoding.hpp"
#include "laminate/payload/trace/trace_wire_support.hpp"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <utility>
#include <vector>

namespace laminate::payload {

namespace trace_crypto_detail {

inline std::size_t exact_rns_limbs(std::size_t required_mult_depth) {
    if (required_mult_depth == std::numeric_limits<std::size_t>::max()) {
        throw std::invalid_argument(
            "trace encryption depth overflows its RNS limb count");
    }
    return required_mult_depth + 1U;
}

} // namespace trace_crypto_detail

/// Encrypt only the canonical live wires of a synthetic plaintext trace.
/// Structural padding remains the public plaintext zero polynomial and causes
/// no allocation or backend call. This compact reference helper is intended
/// for file-store and streamed-prover tests, not homomorphic payload execution.
template <fhe::FheBackend Backend>
EncryptedTrace<Backend> encrypt_compact_synthetic_trace(
    const typename Backend::EvalContext &eval,
    const typename Backend::ClientContext &client,
    const PayloadCircuit &payload, const LayeredCircuit &layered,
    const PlainTrace &trace, const TraceEncryptionPlan &plan) {
    validate_trace(payload, layered, trace);
    plan.validate(layered);
    if (trace.provenance != TraceProvenance::SyntheticTrace) {
        throw std::invalid_argument(
            "encrypt_compact_synthetic_trace: only synthetic reference "
            "traces are accepted");
    }
    if (Backend::slot_count(eval) != layered.shape.slot_count) {
        throw std::invalid_argument(
            "encrypt_compact_synthetic_trace: backend and payload slot "
            "counts differ");
    }

    const std::vector<LayerStorageLayout> storage =
        canonical_trace_storage_layout(layered);
    EncryptedTrace<Backend> result;
    result.shape = trace.shape;
    result.provenance = trace.provenance;
    result.circuit_id = combined_digest(payload, layered);
    result.trace_id = digest(trace, result.circuit_id);
    if constexpr (fhe::PersistableFheBackend<Backend>) {
        result.backend_context_id = Backend::storage_context_id(eval);
    }
    result.layers.reserve(trace.layers.size());
    for (std::size_t layer_index = 0; layer_index < trace.layers.size();
         ++layer_index) {
        EncryptedTraceLayer<Backend> encrypted_layer;
        encrypted_layer.layout =
            trace.shape.kind == PayloadKind::Wide
                ? TraceLayerLayout::Wide
                : TraceLayerLayout::BPeriodic;
        encrypted_layer.dimensions =
            layer_dimensions(layered.layers[layer_index]);
        encrypted_layer.required_mult_depth =
            plan.required_mult_depth_by_layer[layer_index];
        encrypted_layer.wires.reserve(
            storage[layer_index].stored_wire_count);
        for (std::size_t padded :
             storage[layer_index].representative_padded_indices) {
            encrypted_layer.wires.push_back(
                fhe::FheValue<Backend>::from_ciphertext(
                    Backend::encrypt(
                        client, expand_for_encryption(
                                    trace.shape,
                                    trace.layers[layer_index][padded]))));
        }
        for (fhe::FheValue<Backend> &wire : encrypted_layer.wires) {
            fhe::mod_switch_to_rns_limb_count<Backend>(
                eval, wire.ciphertext(),
                trace_crypto_detail::exact_rns_limbs(
                    encrypted_layer.required_mult_depth));
        }
        result.layers.push_back(std::move(encrypted_layer));
    }
    return result;
}

/// Fast decryption for role adapters carrying immutable setup-certified
/// storage metadata.
namespace prevalidated_trace_crypto {

template <fhe::FheBackend Backend>
std::vector<fhe::SlotVector> decrypt_trace_layer_with_layout(
    const typename Backend::ClientContext &client,
    const LayeredCircuit &layered,
    const PayloadShape &trace_shape,
    const EncryptedTraceLayerView<Backend> &encrypted_layer,
    std::size_t layer_index, const LayerStorageLayout &storage) {
    if (!(trace_shape == layered.shape)) {
        throw std::invalid_argument(
            "decrypt_trace_layer: trace and circuit shapes differ");
    }
    if (layer_index >= layered.layers.size()) {
        throw std::out_of_range(
            "decrypt_trace_layer: layer index is out of range");
    }

    const TraceLayerLayout expected_layout =
        trace_shape.kind == PayloadKind::Wide
            ? TraceLayerLayout::Wide
            : TraceLayerLayout::BPeriodic;
    if (encrypted_layer.layout != expected_layout ||
        !(encrypted_layer.dimensions ==
          layer_dimensions(layered.layers[layer_index])) ||
        encrypted_layer.wires.size() != storage.stored_wire_count) {
        throw std::invalid_argument(
            "decrypt_trace_layer: expected canonical stored trace layer");
    }

    const std::size_t logical_width =
        trace_shape.kind == PayloadKind::Wide
            ? trace_shape.slot_count
            : trace_shape.lane_count;
    std::vector<fhe::SlotVector> result(
        encrypted_layer.dimensions.padded_size,
        fhe::SlotVector(logical_width, Fp::zero()));
    const auto read_wire = [&](const fhe::FheValue<Backend> &wire) {
        const fhe::SlotVector physical = wire.is_public()
            ? wire.plaintext().materialize(trace_shape.slot_count)
            : Backend::decrypt(client, wire.ciphertext());
        if (physical.size() != trace_shape.slot_count) {
            throw std::invalid_argument(
                "decrypt_trace_layer: backend returned wrong slot count");
        }
        if (trace_shape.kind == PayloadKind::Wide) {
            return physical;
        }

        for (std::size_t slot = trace_shape.lane_count;
             slot < physical.size(); ++slot) {
            if (!(physical[slot] ==
                  physical[slot % trace_shape.lane_count])) {
                throw std::invalid_argument(
                    "decrypt_trace_layer: laned wire is not B-periodic");
            }
        }
        return fhe::SlotVector(
            physical.begin(),
            physical.begin() +
                static_cast<std::ptrdiff_t>(trace_shape.lane_count));
    };
    std::vector<fhe::SlotVector> stored;
    stored.reserve(encrypted_layer.wires.size());
    for (const fhe::FheValue<Backend> &wire : encrypted_layer.wires) {
        stored.push_back(read_wire(wire));
    }
    for (std::size_t padded = 0;
         padded < storage.padded_wire_count; ++padded) {
        const std::optional<std::size_t> ordinal =
            storage.stored_ordinal_of(padded);
        if (ordinal) {
            result[padded] = stored[*ordinal];
        }
    }
    return result;
}

} // namespace prevalidated_trace_crypto

template <fhe::FheBackend Backend>
std::vector<fhe::SlotVector> decrypt_trace_layer(
    const typename Backend::ClientContext &client,
    const LayeredCircuit &layered,
    const PayloadShape &trace_shape,
    const EncryptedTraceLayerView<Backend> &encrypted_layer,
    std::size_t layer_index) {
    layered.validate();
    const CanonicalTraceLayout layout = canonical_trace_layout(layered);
    if (layer_index >= layout.wire_support.size()) {
        throw std::out_of_range(
            "decrypt_trace_layer: layer index is out of range");
    }
    return prevalidated_trace_crypto::
        decrypt_trace_layer_with_layout<Backend>(
            client, layered, trace_shape, encrypted_layer, layer_index,
            layout.storage[layer_index]);
}

/// Decrypt one layer against immutable setup-certified support and storage
/// metadata. The certificate was derived from its owned circuit, so this
/// online path performs no circuit-wide validation or layout derivation.
template <fhe::FheBackend Backend>
std::vector<fhe::SlotVector> decrypt_trace_layer(
    const typename Backend::ClientContext &client,
    const CertifiedCanonicalTraceLayout &certified,
    const EncryptedTraceLayerView<Backend> &encrypted_layer,
    std::size_t layer_index) {
    const LayeredCircuit &layered = certified.circuit();
    const CanonicalTraceLayout &layout = certified.layout();
    if (layer_index >= layout.wire_support.size()) {
        throw std::out_of_range(
            "decrypt_trace_layer: layer index is out of range");
    }
    return prevalidated_trace_crypto::
        decrypt_trace_layer_with_layout<Backend>(
            client, layered, layered.shape, encrypted_layer, layer_index,
            layout.storage[layer_index]);
}

template <fhe::FheBackend Backend>
std::vector<fhe::SlotVector> decrypt_trace_layer(
    const typename Backend::ClientContext &client,
    const LayeredCircuit &layered,
    const EncryptedTrace<Backend> &trace, std::size_t layer_index) {
    if (trace.layers.size() != layered.layers.size()) {
        throw std::invalid_argument(
            "decrypt_trace_layer: trace and circuit shapes differ");
    }
    if (layer_index >= trace.layers.size()) {
        throw std::out_of_range(
            "decrypt_trace_layer: layer index is out of range");
    }
    return decrypt_trace_layer<Backend>(
        client, layered, trace.shape, view_of(trace.layers[layer_index]),
        layer_index);
}

template <fhe::FheBackend Backend>
std::vector<std::vector<fhe::SlotVector>> decrypt_trace_layers(
    const typename Backend::ClientContext &client,
    const LayeredCircuit &layered,
    const EncryptedTrace<Backend> &trace) {
    std::vector<std::vector<fhe::SlotVector>> result;
    result.reserve(trace.layers.size());
    for (std::size_t layer = 0; layer < trace.layers.size(); ++layer) {
        result.push_back(decrypt_trace_layer<Backend>(
            client, layered, trace, layer));
    }
    return result;
}

} // namespace laminate::payload

#endif // LAMINATE_PAYLOAD_TRACE_TRACE_CRYPTO_HPP
