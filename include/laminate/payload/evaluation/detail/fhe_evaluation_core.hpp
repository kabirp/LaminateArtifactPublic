#ifndef LAMINATE_PAYLOAD_EVALUATION_DETAIL_FHE_EVALUATION_CORE_HPP
#define LAMINATE_PAYLOAD_EVALUATION_DETAIL_FHE_EVALUATION_CORE_HPP

/// @file fhe_evaluation_core.hpp
/// @brief Shared compact evaluator for Wide and Laned payload layouts.

#include "laminate/payload/compiler.hpp"
#include "laminate/payload/evaluation/affine_program.hpp"
#include "laminate/payload/evaluation/fhe_evaluation_plan.hpp"
#include "laminate/payload/trace/fhe_trace_id.hpp"
#include "laminate/payload/evaluation/proof_ciphertext_normalization.hpp"
#include "laminate/payload/evaluation/slot_encoding.hpp"
#include "laminate/payload/trace/trace_sink.hpp"
#include "laminate/payload/trace/trace_wire_support.hpp"

#include <algorithm>
#include <cstddef>
#include <optional>
#include <span>
#include <stdexcept>
#include <type_traits>
#include <utility>
#include <vector>

namespace laminate::payload::fhe_evaluation_detail {

/// Wide payloads store each logical SIMD wire as one trace value. Their
/// public constants already have the backend's physical slot width.
struct WideLayout {
    static constexpr PayloadKind payload_kind = PayloadKind::Wide;
    static constexpr TraceLayerLayout trace_layout =
        TraceLayerLayout::Wide;

    static fhe::SlotVector public_slots(
        const PayloadShape &, const fhe::SlotVector &values) {
        return values;
    }

    template <fhe::FheBackend Backend>
    static fhe::FheValue<Backend> multiply_by_public_slots(
        const typename Backend::EvalContext &eval,
        const LayeredCircuit &circuit,
        const fhe::FheValue<Backend> &left,
        std::size_t plaintext_index) {
        if (plaintext_index >= circuit.plaintexts.size()) {
            throw std::invalid_argument(
                "payload FHE evaluator: evaluator plaintext is invalid");
        }
        return fhe::value_mul<Backend>(
            eval, left, fhe::FheValue<Backend>::public_slots(
                            circuit.plaintexts[plaintext_index]));
    }
};

/// Laned payloads repeat each B-slot logical wire across the N physical SIMD
/// slots. Their canonical circuit permits only uniform plaintext multipliers.
struct LanedLayout {
    static constexpr PayloadKind payload_kind = PayloadKind::Laned;
    static constexpr TraceLayerLayout trace_layout =
        TraceLayerLayout::BPeriodic;

    static fhe::SlotVector public_slots(
        const PayloadShape &shape, const fhe::SlotVector &values) {
        return expand_for_encryption(shape, values);
    }

    template <fhe::FheBackend Backend>
    static fhe::FheValue<Backend> multiply_by_public_slots(
        const typename Backend::EvalContext &,
        const LayeredCircuit &,
        const fhe::FheValue<Backend> &,
        std::size_t) {
        throw std::logic_error(
            "payload FHE evaluator: Laned multiplication cannot carry a "
            "nonuniform plaintext hint");
    }
};

template <typename Sink> consteval bool stores_only_live_wires() {
    if constexpr (requires { Sink::stores_only_live_wires; }) {
        return Sink::stores_only_live_wires;
    }
    return false;
}

template <fhe::FheBackend Backend>
const fhe::FheValue<Backend> *stored_source(
    std::span<const fhe::FheValue<Backend>> source,
    const LayerStorageLayout &storage, std::size_t padded_index) {
    const std::optional<std::size_t> ordinal =
        storage.stored_ordinal_of(padded_index);
    if (!ordinal) {
        return nullptr;
    }
    if (*ordinal >= source.size()) {
        throw std::logic_error(
            "payload FHE evaluator: compact source is incomplete");
    }
    return &source[*ordinal];
}

template <fhe::FheBackend Backend, typename Layout, typename Resolve>
fhe::FheValue<Backend> evaluate_affine_gate(
    const typename Backend::EvalContext &eval,
    const LayeredCircuit &circuit, const AffineGate &gate,
    Resolve &&resolve) {
    fhe::FheValue<Backend> accumulator;
    for (const AffineTerm &term_description : gate.terms) {
        if (term_description.coefficient.is_zero()) {
            continue;
        }
        fhe::FheValue<Backend> term = resolve(term_description.source);
        if (term_description.rotation != 0) {
            term = fhe::value_rotate<Backend>(
                eval, term, term_description.rotation);
        }
        if (!(term_description.coefficient == Fp::one())) {
            term = fhe::value_mul<Backend>(
                eval, term,
                fhe::FheValue<Backend>::public_scalar(
                    term_description.coefficient));
        }
        if (term_description.plaintext_index) {
            term = Layout::template multiply_by_public_slots<Backend>(
                eval, circuit, term, *term_description.plaintext_index);
        }
        fhe::value_add_assign<Backend>(eval, accumulator,
                                       std::move(term));
    }

    if (const auto *scalar = std::get_if<Fp>(&gate.constant)) {
        if (!scalar->is_zero()) {
            fhe::value_add_assign<Backend>(
                eval, accumulator,
                fhe::FheValue<Backend>::public_scalar(*scalar));
        }
    } else {
        fhe::SlotVector constant = Layout::public_slots(
            circuit.shape, std::get<fhe::SlotVector>(gate.constant));
        if (!is_zero_slot_vector(constant)) {
            fhe::value_add_assign<Backend>(
                eval, accumulator,
                fhe::FheValue<Backend>::public_slots(
                    std::move(constant)));
        }
    }
    return accumulator;
}

template <fhe::FheBackend Backend, typename Layout>
fhe::FheValue<Backend> evaluate_multiplication_gate(
    const typename Backend::EvalContext &eval,
    const LayeredCircuit &, const MultiplicationGate &gate,
    std::size_t gate_index, std::size_t pair_count,
    std::span<const fhe::FheValue<Backend>> source,
    const LayerStorageLayout &source_storage) {
    if (gate.origin == GateOrigin::Padding) {
        throw std::logic_error(
            "payload FHE evaluator: compact evaluation reached a padding "
            "gate");
    }

    const fhe::FheValue<Backend> *left = stored_source<Backend>(
        source, source_storage, gate_index);
    if (left == nullptr) {
        return fhe::FheValue<Backend>::public_zero();
    }
    if (gate.origin == GateOrigin::Forward) {
        return *left;
    }

    const fhe::FheValue<Backend> *right = stored_source<Backend>(
        source, source_storage, pair_count + gate_index);
    if (right == nullptr) {
        return fhe::FheValue<Backend>::public_zero();
    }
    return fhe::value_mul<Backend>(eval, *left, *right);
}

template <fhe::FheBackend Backend, typename Layout>
std::vector<fhe::FheValue<Backend>> evaluate_layer(
    const typename Backend::EvalContext &eval,
    const LayeredCircuit &circuit, std::size_t layer,
    std::span<const fhe::FheValue<Backend>> source,
    const LayerStorageLayout &source_storage,
    const LayerStorageLayout &output_storage) {
    if (source.size() != source_storage.stored_wire_count) {
        throw std::logic_error(
            "payload FHE evaluator: source storage count is inconsistent");
    }

    std::vector<fhe::FheValue<Backend>> result;
    result.reserve(output_storage.stored_wire_count);
    if (const auto *affine =
            std::get_if<AffineLayer>(&circuit.layers.at(layer))) {
        using Value = fhe::FheValue<Backend>;
        auto plan = affine_program_plan(
            *affine, source_storage.padded_wire_count,
            output_storage.representative_padded_indices);
        std::vector<std::optional<Value>> intermediate(
            affine->intermediate_gates.size());
        const auto resolve = [&](std::size_t index) -> Value {
            if (index >= source_storage.padded_wire_count) {
                return intermediate
                    .at(index - source_storage.padded_wire_count)
                    .value();
            }
            const auto *value =
                stored_source<Backend>(source, source_storage, index);
            return value == nullptr ? Value::public_zero() : *value;
        };
        for (const auto &step : plan.steps) {
            const auto &gate = step.output
                                   ? affine->gates[step.index]
                                   : affine->intermediate_gates[step.index];
            Value value = evaluate_affine_gate<Backend, Layout>(
                eval, circuit, gate, resolve);
            for (const auto &term : gate.terms) {
                if (!term.coefficient.is_zero() &&
                    term.source >= source_storage.padded_wire_count) {
                    const auto index =
                        term.source - source_storage.padded_wire_count;
                    if (--plan.remaining_uses[index] == 0) {
                        intermediate[index].reset();
                    }
                }
            }
            if (step.output) {
                result.push_back(std::move(value));
            } else {
                intermediate[step.index] = std::move(value);
            }
        }
    } else if (const auto *multiplication =
                   std::get_if<MultiplicationLayer>(
                       &circuit.layers.at(layer))) {
        for (std::size_t padded :
             output_storage.representative_padded_indices) {
            result.push_back(
                evaluate_multiplication_gate<Backend, Layout>(
                    eval, circuit, multiplication->gates.at(padded),
                    padded, multiplication->dimensions.padded_size,
                    source, source_storage));
        }
    } else {
        throw std::invalid_argument(
            "payload FHE evaluator: input layer has no predecessor "
            "relation");
    }
    if (result.size() != output_storage.stored_wire_count) {
        throw std::logic_error(
            "payload FHE evaluator: output storage count is inconsistent");
    }
    return result;
}

template <fhe::FheBackend Backend, typename Layout, typename Sink>
void emit_trace_snapshot(
    const typename Backend::EvalContext &eval,
    const LayeredCircuit &circuit, std::size_t layer,
    std::span<const fhe::FheValue<Backend>> working,
    const LayerStorageLayout &storage, std::size_t required_proof_depth,
    Sink &sink) {
    if (working.size() != storage.stored_wire_count) {
        throw std::logic_error(
            "payload FHE evaluator: snapshot storage count is "
            "inconsistent");
    }
    sink.begin_layer(layer, Layout::trace_layout,
                     layer_dimensions(circuit.layers.at(layer)),
                     required_proof_depth, storage.stored_wire_count);
    for (const fhe::FheValue<Backend> &wire : working) {
        fhe::FheValue<Backend> snapshot = wire;
        if (snapshot.is_encrypted()) {
            normalize_ciphertext_for_proof<Backend>(
                eval, snapshot.ciphertext(), required_proof_depth);
        }
        sink.append_value(std::move(snapshot));
    }
    sink.finish_layer();
}

template <fhe::FheBackend Backend, typename Layout, typename Sink>
auto evaluate_trace_into(
    const typename Backend::EvalContext &eval,
    const PayloadCircuit &payload, const LayeredCircuit &circuit,
    std::span<const typename Backend::Ciphertext> encrypted_inputs,
    const FheEvaluationPlan &plan, Sink sink)
    -> decltype(std::move(sink).finish()) {
    using SinkType = std::remove_cvref_t<Sink>;
    static_assert(stores_only_live_wires<SinkType>(),
                  "payload FHE evaluation requires a compact live-wire "
                  "sink");

    validate_compilation_pair(payload, circuit);
    plan.validate(circuit);
    if (payload.shape.kind != Layout::payload_kind ||
        circuit.shape.kind != Layout::payload_kind) {
        throw std::invalid_argument(
            "payload FHE evaluator: payload has the wrong layout");
    }
    if (!(payload.shape == circuit.shape) ||
        payload.input_count != circuit.payload_input_count ||
        payload.outputs.size() != circuit.payload_output_count ||
        encrypted_inputs.size() != payload.input_count ||
        Backend::slot_count(eval) != circuit.shape.slot_count) {
        throw std::invalid_argument(
            "payload FHE evaluator: circuit, input, or backend mismatch");
    }
    if constexpr (fhe::PersistableFheBackend<Backend> &&
                  requires(const SinkType &candidate) {
                      candidate.storage_context_id();
                  }) {
        if (sink.storage_context_id() !=
            Backend::storage_context_id(eval)) {
            throw std::invalid_argument(
                "payload FHE evaluator: sink backend context mismatch");
        }
    }

    const Digest circuit_id = combined_digest(payload, circuit);
    const Digest trace_id =
        prevalidated_trace_identity::validated_fhe_evaluated_trace_id<Backend>(
            circuit_id, payload.input_count, encrypted_inputs);
    sink.begin_trace(circuit.shape, TraceProvenance::FheEvaluated,
                     circuit_id, trace_id, circuit.layers.size());

    const std::vector<LayerStorageLayout> storage =
        canonical_trace_storage_layout(circuit);
    const std::size_t input_layer = circuit.layers.size() - 1;
    std::vector<fhe::FheValue<Backend>> working;
    working.reserve(encrypted_inputs.size());
    for (const typename Backend::Ciphertext &input : encrypted_inputs) {
        working.push_back(fhe::FheValue<Backend>::from_ciphertext(input));
    }
    if (working.size() != storage[input_layer].stored_wire_count) {
        throw std::logic_error(
            "payload FHE evaluator: input support is inconsistent");
    }
    emit_trace_snapshot<Backend, Layout>(
        eval, circuit, input_layer, working, storage[input_layer],
        plan.proof_ingress_mult_depth_by_layer[input_layer], sink);

    // Payload layers are stored output-first. Evaluation therefore walks
    // backward from encrypted inputs toward the client-visible outputs.
    for (std::size_t source_layer = input_layer; source_layer > 0;
         --source_layer) {
        const std::size_t output_layer = source_layer - 1;
        working = evaluate_layer<Backend, Layout>(
            eval, circuit, output_layer, working, storage[source_layer],
            storage[output_layer]);

        // Drops occur at public, setup-chosen layer boundaries. The proof
        // snapshot is an independent copy at its configured ingress level.
        for (std::size_t count = 0;
             count < plan.modulus_switches_after_layer[output_layer];
             ++count) {
            for (fhe::FheValue<Backend> &wire : working) {
                fhe::value_mod_switch_to_next<Backend>(eval, wire);
            }
        }
        emit_trace_snapshot<Backend, Layout>(
            eval, circuit, output_layer, working, storage[output_layer],
            plan.proof_ingress_mult_depth_by_layer[output_layer], sink);
    }
    return std::move(sink).finish();
}

} // namespace laminate::payload::fhe_evaluation_detail

#endif // LAMINATE_PAYLOAD_EVALUATION_DETAIL_FHE_EVALUATION_CORE_HPP
