#include "laminate/payload/trace/trace_wire_support.hpp"

#include "laminate/fhe/value.hpp"
#include "laminate/payload/evaluation/slot_encoding.hpp"
#include "laminate/payload/evaluation/affine_program.hpp"

#include <algorithm>
#include <limits>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>

namespace laminate::payload {
namespace {

bool is_power_of_two(std::size_t value) {
    return value != 0 && (value & (value - 1U)) == 0;
}

bool constant_is_zero(const AffineConstant &constant) {
    if (const auto *scalar = std::get_if<Fp>(&constant)) {
        return scalar->is_zero();
    }
    const fhe::SlotVector &slots = std::get<fhe::SlotVector>(constant);
    return std::all_of(slots.begin(), slots.end(),
                       [](const Fp &value) { return value.is_zero(); });
}

template <typename Gate>
LayerWireSupport support_from_gates(const LayerDimensions &dimensions,
                                    std::span<const Gate> gates) {
    LayerWireSupport result{
        dimensions.padded_size, dimensions.logical_size, {}};
    for (std::size_t padded_index = 0; padded_index < gates.size();
         ++padded_index) {
        if (gates[padded_index].origin == GateOrigin::Padding) {
            continue;
        }
        if (!result.live_ranges.empty() &&
            result.live_ranges.back().padded_end() == padded_index) {
            ++result.live_ranges.back().wire_count;
        } else {
            result.live_ranges.push_back(
                LiveWireRange{padded_index, 1});
        }
    }
    validate_layer_wire_support(result);
    return result;
}

LayerWireSupport support_from_layer(const Layer &layer) {
    if (const auto *affine = std::get_if<AffineLayer>(&layer)) {
        return support_from_gates(
            affine->dimensions, std::span<const AffineGate>(affine->gates));
    }
    if (const auto *multiplication =
            std::get_if<MultiplicationLayer>(&layer)) {
        return support_from_gates(
            multiplication->dimensions,
            std::span<const MultiplicationGate>(multiplication->gates));
    }
    const LayerDimensions &dimensions =
        std::get<InputLayer>(layer).dimensions;
    LayerWireSupport result{
        dimensions.padded_size,
        dimensions.logical_size,
        {LiveWireRange{0, dimensions.logical_size}},
    };
    validate_layer_wire_support(result);
    return result;
}

std::vector<LayerWireSupport>
derive_trace_wire_support(const LayeredCircuit &circuit);

std::size_t hash_combine(std::size_t seed, std::size_t value) {
    return seed ^ (value + 0x9e3779b97f4a7c15ULL + (seed << 6U) +
                   (seed >> 2U));
}

std::size_t affine_recipe_hash(const AffineGate &gate) {
    std::size_t result = gate.terms.size();
    for (const AffineTerm &term : gate.terms) {
        result = hash_combine(result, term.source);
        result = hash_combine(result, term.rotation);
        result = hash_combine(result, term.coefficient.value());
        result = hash_combine(result, term.plaintext_index.has_value());
        if (term.plaintext_index) result = hash_combine(result, *term.plaintext_index);
    }
    result = hash_combine(result, gate.constant.index());
    if (const auto *scalar = std::get_if<Fp>(&gate.constant)) {
        return hash_combine(result, scalar->value());
    }
    for (const Fp &value : std::get<fhe::SlotVector>(gate.constant)) {
        result = hash_combine(result, value.value());
    }
    return result;
}

bool same_affine_recipe(const AffineGate &left, const AffineGate &right) {
    return left.terms == right.terms && left.constant == right.constant;
}

LayerStorageLayout identity_storage_layout(
    const LayerWireSupport &support) {
    LayerStorageLayout result;
    result.padded_wire_count = support.padded_wire_count;
    result.padded_to_stored.resize(support.padded_wire_count);
    result.representative_padded_indices.reserve(support.live_wire_count);
    for (std::size_t padded = 0; padded < support.padded_wire_count;
         ++padded) {
        if (!support.is_live(padded)) {
            continue;
        }
        result.padded_to_stored[padded] = result.stored_wire_count++;
        result.representative_padded_indices.push_back(padded);
    }
    validate_layer_storage_layout(result);
    return result;
}

LayerStorageLayout deduplicated_affine_storage_layout(
    const AffineLayer &layer, const LayerWireSupport &support) {
    LayerStorageLayout result;
    result.padded_wire_count = support.padded_wire_count;
    result.padded_to_stored.resize(support.padded_wire_count);

    std::unordered_map<std::size_t, std::vector<std::size_t>> buckets;
    for (std::size_t padded = 0; padded < layer.gates.size(); ++padded) {
        if (!support.is_live(padded)) {
            continue;
        }
        const AffineGate &gate = layer.gates[padded];
        const std::size_t hash = affine_recipe_hash(gate);
        std::optional<std::size_t> ordinal;
        for (std::size_t representative : buckets[hash]) {
            if (same_affine_recipe(gate,
                                   layer.gates[representative])) {
                ordinal = result.padded_to_stored[representative];
                break;
            }
        }
        if (!ordinal) {
            ordinal = result.stored_wire_count++;
            buckets[hash].push_back(padded);
            result.representative_padded_indices.push_back(padded);
        }
        result.padded_to_stored[padded] = *ordinal;
    }
    validate_layer_storage_layout(result);
    return result;
}

std::vector<LayerStorageLayout>
derive_trace_storage_layout(
    const LayeredCircuit &circuit,
    const std::vector<LayerWireSupport> &support) {
    std::vector<LayerStorageLayout> result;
    result.reserve(circuit.layers.size());
    for (std::size_t layer_index = 0;
         layer_index < circuit.layers.size(); ++layer_index) {
        const auto *affine =
            std::get_if<AffineLayer>(&circuit.layers[layer_index]);
        const bool feeds_multiplication =
            affine != nullptr && layer_index > 0 &&
            std::holds_alternative<MultiplicationLayer>(
                circuit.layers[layer_index - 1]);
        result.push_back(
            feeds_multiplication
                ? deduplicated_affine_storage_layout(
                      *affine, support[layer_index])
                : identity_storage_layout(support[layer_index]));
    }
    return result;
}

template <typename Operation>
fhe::PublicPlaintext combine_public_values(
    const fhe::PublicPlaintext &left,
    const fhe::PublicPlaintext &right, std::size_t slot_count,
    Operation operation) {
    if (left.is_scalar() && right.is_scalar()) {
        return fhe::PublicPlaintext::from_scalar(
            operation(left.scalar(), right.scalar()));
    }
    fhe::SlotVector result(slot_count);
    const fhe::SlotVector left_slots = left.materialize(slot_count);
    const fhe::SlotVector right_slots = right.materialize(slot_count);
    for (std::size_t slot = 0; slot < slot_count; ++slot) {
        result[slot] = operation(left_slots[slot], right_slots[slot]);
    }
    return fhe::PublicPlaintext::from_slots(std::move(result));
}

fhe::PublicPlaintext public_affine_constant(
    const LayeredCircuit &circuit, const AffineConstant &constant) {
    if (const auto *scalar = std::get_if<Fp>(&constant)) {
        return fhe::PublicPlaintext::from_scalar(*scalar);
    }
    return fhe::PublicPlaintext::from_slots(expand_for_encryption(
        circuit.shape, std::get<fhe::SlotVector>(constant)));
}

fhe::PublicPlaintext scale_public_value(
    const fhe::PublicPlaintext &value, const Fp &scalar,
    std::size_t slot_count) {
    return combine_public_values(
        value, fhe::PublicPlaintext::from_scalar(scalar), slot_count,
        [](const Fp &left, const Fp &right) { return left * right; });
}

fhe::PublicPlaintext rotate_public_value(
    const fhe::PublicPlaintext &value, std::size_t steps,
    std::size_t slot_count) {
    if (value.is_scalar() || steps % slot_count == 0U) {
        return value;
    }
    return fhe::PublicPlaintext::from_slots(
        fhe::grid_rotate(value.slots(), steps));
}

ClassifiedTraceValue multiply_classified_values(
    const ClassifiedTraceValue &left,
    const ClassifiedTraceValue &right, std::size_t slot_count) {
    if ((left.has_value() && left->is_zero()) ||
        (right.has_value() && right->is_zero())) {
        return fhe::PublicPlaintext::from_scalar(Fp::zero());
    }
    if (!left.has_value() || !right.has_value()) {
        return std::nullopt;
    }
    return combine_public_values(
        *left, *right, slot_count,
        [](const Fp &a, const Fp &b) { return a * b; });
}

template <typename Resolve>
ClassifiedTraceValue classify_affine_value(
    const LayeredCircuit &circuit, const AffineGate &gate,
    Resolve &&resolve) {
    const std::size_t slots = circuit.shape.slot_count;
    fhe::PublicPlaintext accumulator =
        fhe::PublicPlaintext::from_scalar(Fp::zero());
    for (const AffineTerm &term : gate.terms) {
        if (term.coefficient.is_zero()) {
            continue;
        }
        ClassifiedTraceValue source = resolve(term.source);
        if (source) source = rotate_public_value(*source, term.rotation, slots);
        if (term.plaintext_index) {
            source = multiply_classified_values(
                source, fhe::PublicPlaintext::from_slots(expand_for_encryption(
                    circuit.shape, circuit.plaintexts.at(*term.plaintext_index))), slots);
        }
        if (!source.has_value()) return std::nullopt;
        fhe::PublicPlaintext contribution = scale_public_value(
            *source, term.coefficient, slots);
        accumulator = combine_public_values(
            accumulator, contribution, slots,
            [](const Fp &left, const Fp &right) {
                return left + right;
            });
    }
    return combine_public_values(
        accumulator, public_affine_constant(circuit, gate.constant), slots,
        [](const Fp &left, const Fp &right) { return left + right; });
}

ClassifiedTraceValue classify_multiplication_value(
    const LayeredCircuit &circuit, const MultiplicationGate &gate,
    std::size_t gate_index, std::size_t source_layer,
    const std::vector<LayerStorageLayout> &storage,
    const std::vector<std::vector<ClassifiedTraceValue>> &classified) {
    const auto source_value = [&](std::size_t padded) {
        const std::optional<std::size_t> ordinal =
            storage[source_layer].stored_ordinal_of(padded);
        return ordinal.has_value()
                   ? classified[source_layer].at(*ordinal)
                   : ClassifiedTraceValue(
                         fhe::PublicPlaintext::from_scalar(Fp::zero()));
    };
    const ClassifiedTraceValue left = source_value(gate_index);
    if (gate.origin == GateOrigin::Forward) {
        return left;
    }
    const std::size_t pair_count =
        layer_dimensions(circuit.layers[source_layer - 1U]).padded_size;
    return multiply_classified_values(
        left, source_value(pair_count + gate_index),
        circuit.shape.slot_count);
}

std::vector<std::vector<ClassifiedTraceValue>>
derive_trace_value_classifications(
    const LayeredCircuit &circuit,
    const std::vector<LayerStorageLayout> &storage) {
    std::vector<std::vector<ClassifiedTraceValue>> classified(
        circuit.layers.size());
    const std::size_t input_layer = circuit.layers.size() - 1U;
    classified[input_layer].assign(
        storage[input_layer].stored_wire_count, std::nullopt);
    for (std::size_t source_layer = input_layer; source_layer > 0U;
         --source_layer) {
        const std::size_t output_layer = source_layer - 1U;
        classified[output_layer].reserve(
            storage[output_layer].stored_wire_count);
        if (const auto *affine = std::get_if<AffineLayer>(
                &circuit.layers[output_layer])) {
            auto plan = affine_program_plan(*affine,
                storage[source_layer].padded_wire_count,
                storage[output_layer].representative_padded_indices);
            std::vector<ClassifiedTraceValue> intermediate(affine->intermediate_gates.size());
            const auto resolve = [&](std::size_t source) -> ClassifiedTraceValue {
                if (source >= storage[source_layer].padded_wire_count)
                    return intermediate.at(source - storage[source_layer].padded_wire_count);
                const auto ordinal = storage[source_layer].stored_ordinal_of(source);
                return ordinal ? classified[source_layer].at(*ordinal)
                    : ClassifiedTraceValue{fhe::PublicPlaintext::from_scalar(Fp::zero())};
            };
            for (const auto &step : plan.steps) {
                const auto &gate = step.output ? affine->gates[step.index]
                    : affine->intermediate_gates[step.index];
                auto value = classify_affine_value(circuit, gate, resolve);
                for (const auto &term : gate.terms) {
                    if (!term.coefficient.is_zero() && term.source >= storage[source_layer].padded_wire_count) {
                        const auto index = term.source - storage[source_layer].padded_wire_count;
                        if (--plan.remaining_uses[index] == 0) intermediate[index].reset();
                    }
                }
                if (step.output) classified[output_layer].push_back(std::move(value));
                else intermediate[step.index] = std::move(value);
            }
        } else {
            for (const std::size_t padded : storage[output_layer].representative_padded_indices) {
                classified[output_layer].push_back(classify_multiplication_value(
                    circuit, std::get<MultiplicationLayer>(circuit.layers[output_layer]).gates.at(padded),
                    padded, source_layer, storage, classified));
            }
        }
    }
    return classified;
}

std::vector<LayerTraceValueCounts> derive_trace_value_counts(
    const std::vector<LayerWireSupport> &support,
    const std::vector<LayerStorageLayout> &storage,
    const std::vector<std::vector<ClassifiedTraceValue>> &classified) {
    std::vector<LayerTraceValueCounts> result;
    result.reserve(support.size());
    for (std::size_t layer = 0; layer < support.size(); ++layer) {
        const std::size_t encrypted_ciphertexts =
            static_cast<std::size_t>(std::count(
                classified[layer].begin(), classified[layer].end(),
                std::nullopt));
        result.push_back(LayerTraceValueCounts{
            .virtual_wire_positions = support[layer].padded_wire_count,
            .logical_live_wires = support[layer].live_wire_count,
            .stored_values = storage[layer].stored_wire_count,
            .encrypted_ciphertexts = encrypted_ciphertexts,
        });
    }
    return result;
}

void require_padding_outputs_zero(
    const LayeredCircuit &circuit,
    std::span<const LayerWireSupport> support) {
    for (std::size_t layer_index = 0;
         layer_index + 1U < circuit.layers.size(); ++layer_index) {
        const LayerWireSupport &source = support[layer_index + 1U];
        if (const auto *affine =
                std::get_if<AffineLayer>(&circuit.layers[layer_index])) {
            for (const AffineGate &gate : affine->gates) {
                if (gate.origin != GateOrigin::Padding) {
                    continue;
                }
                if (!constant_is_zero(gate.constant)) {
                    throw std::invalid_argument(
                        "trace wire support: affine padding gate has a "
                        "nonzero constant");
                }
                for (const AffineTerm &term : gate.terms) {
                    if (!term.coefficient.is_zero() &&
                        (term.source >= source.padded_wire_count || source.is_live(term.source))) {
                        throw std::invalid_argument(
                            "trace wire support: affine padding gate depends "
                            "on a live source");
                    }
                }
            }
            continue;
        }

        const auto &multiplication =
            std::get<MultiplicationLayer>(circuit.layers[layer_index]);
        const std::size_t pair_count =
            multiplication.dimensions.padded_size;
        for (std::size_t gate_index = 0;
             gate_index < multiplication.gates.size(); ++gate_index) {
            const MultiplicationGate &gate =
                multiplication.gates[gate_index];
            if (gate.origin != GateOrigin::Padding) {
                continue;
            }
            const bool output_is_zero =
                !source.is_live(gate_index) ||
                !source.is_live(pair_count + gate_index);
            if (!output_is_zero) {
                throw std::invalid_argument(
                    "trace wire support: multiplication padding gate is not "
                    "structurally zero");
            }
        }
    }
}

std::vector<LayerWireSupport>
derive_trace_wire_support(const LayeredCircuit &circuit) {
    circuit.validate();
    std::vector<LayerWireSupport> result;
    result.reserve(circuit.layers.size());
    for (const Layer &layer : circuit.layers) {
        result.push_back(support_from_layer(layer));
    }
    require_padding_outputs_zero(circuit, result);
    return result;
}

} // namespace

std::size_t LiveWireRange::padded_end() const {
    if (wire_count >
        std::numeric_limits<std::size_t>::max() - padded_begin) {
        throw std::overflow_error("live wire range end overflows");
    }
    return padded_begin + wire_count;
}

std::optional<std::size_t>
LayerWireSupport::live_index_of(std::size_t padded_index) const {
    if (padded_index >= padded_wire_count) {
        throw std::out_of_range("padded wire index is out of range");
    }
    std::size_t live_begin = 0;
    for (const LiveWireRange &range : live_ranges) {
        if (padded_index < range.padded_begin) {
            return std::nullopt;
        }
        if (padded_index < range.padded_end()) {
            return live_begin + (padded_index - range.padded_begin);
        }
        live_begin += range.wire_count;
    }
    return std::nullopt;
}

std::size_t
LayerWireSupport::padded_index_of(std::size_t live_index) const {
    if (live_index >= live_wire_count) {
        throw std::out_of_range("live wire index is out of range");
    }
    std::size_t live_begin = 0;
    for (const LiveWireRange &range : live_ranges) {
        if (live_index - live_begin < range.wire_count) {
            return range.padded_begin + (live_index - live_begin);
        }
        live_begin += range.wire_count;
    }
    throw std::logic_error("live wire support does not cover its live domain");
}

bool LayerWireSupport::is_live(std::size_t padded_index) const {
    return live_index_of(padded_index).has_value();
}

std::optional<std::size_t>
LayerStorageLayout::stored_ordinal_of(std::size_t padded_index) const {
    if (padded_index >= padded_wire_count) {
        throw std::out_of_range("padded wire index is out of range");
    }
    return padded_to_stored[padded_index];
}

std::size_t LayerStorageLayout::representative_padded_index_of(
    std::size_t stored_ordinal) const {
    if (stored_ordinal >= stored_wire_count) {
        throw std::out_of_range("stored wire ordinal is out of range");
    }
    return representative_padded_indices[stored_ordinal];
}

void validate_layer_wire_support(const LayerWireSupport &support) {
    if (support.padded_wire_count == 0 ||
        !is_power_of_two(support.padded_wire_count) ||
        support.live_wire_count == 0 ||
        support.live_wire_count > support.padded_wire_count ||
        support.live_ranges.empty()) {
        throw std::invalid_argument(
            "trace wire support: invalid wire counts");
    }

    std::size_t counted = 0;
    std::size_t previous_end = 0;
    bool first = true;
    for (const LiveWireRange &range : support.live_ranges) {
        std::size_t end = 0;
        try {
            end = range.padded_end();
        } catch (const std::overflow_error &) {
            throw std::invalid_argument(
                "trace wire support: range end overflows");
        }
        if (range.wire_count == 0 || end > support.padded_wire_count ||
            (!first && range.padded_begin <= previous_end)) {
            throw std::invalid_argument(
                "trace wire support: ranges are not canonical");
        }
        if (range.wire_count > support.live_wire_count - counted) {
            throw std::invalid_argument(
                "trace wire support: live wire count is inconsistent");
        }
        counted += range.wire_count;
        previous_end = end;
        first = false;
    }
    if (counted != support.live_wire_count) {
        throw std::invalid_argument(
            "trace wire support: live wire count is inconsistent");
    }
}

void validate_layer_storage_layout(const LayerStorageLayout &layout) {
    if (layout.padded_wire_count == 0 ||
        !is_power_of_two(layout.padded_wire_count) ||
        layout.stored_wire_count == 0 ||
        layout.stored_wire_count > layout.padded_wire_count ||
        layout.padded_to_stored.size() != layout.padded_wire_count ||
        layout.representative_padded_indices.size() !=
            layout.stored_wire_count) {
        throw std::invalid_argument(
            "trace storage layout: invalid wire counts");
    }

    const std::size_t missing = std::numeric_limits<std::size_t>::max();
    std::vector<std::size_t> first(layout.stored_wire_count, missing);
    for (std::size_t padded = 0; padded < layout.padded_wire_count;
         ++padded) {
        const std::optional<std::size_t> ordinal =
            layout.padded_to_stored[padded];
        if (!ordinal) {
            continue;
        }
        if (*ordinal >= layout.stored_wire_count) {
            throw std::invalid_argument(
                "trace storage layout: stored ordinal is out of range");
        }
        if (first[*ordinal] == missing) {
            first[*ordinal] = padded;
        }
    }
    for (std::size_t ordinal = 0; ordinal < layout.stored_wire_count;
         ++ordinal) {
        if (first[ordinal] == missing ||
            first[ordinal] !=
                layout.representative_padded_indices[ordinal] ||
            (ordinal > 0 &&
             layout.representative_padded_indices[ordinal - 1] >=
                 layout.representative_padded_indices[ordinal])) {
            throw std::invalid_argument(
                "trace storage layout: representatives are not canonical");
        }
    }
}

LayerWireSupport canonical_layer_wire_support(
    const LayeredCircuit &circuit, std::size_t layer_index) {
    const std::vector<LayerWireSupport> support =
        derive_trace_wire_support(circuit);
    if (layer_index >= support.size()) {
        throw std::out_of_range("trace layer index is out of range");
    }
    return support[layer_index];
}

std::vector<LayerWireSupport>
canonical_trace_wire_support(const LayeredCircuit &circuit) {
    return derive_trace_wire_support(circuit);
}

LayerStorageLayout canonical_layer_storage_layout(
    const LayeredCircuit &circuit, std::size_t layer_index) {
    const std::vector<LayerWireSupport> support =
        derive_trace_wire_support(circuit);
    const std::vector<LayerStorageLayout> layouts =
        derive_trace_storage_layout(circuit, support);
    if (layer_index >= layouts.size()) {
        throw std::out_of_range("trace layer index is out of range");
    }
    return layouts[layer_index];
}

std::vector<LayerStorageLayout>
canonical_trace_storage_layout(const LayeredCircuit &circuit) {
    const std::vector<LayerWireSupport> support =
        derive_trace_wire_support(circuit);
    return derive_trace_storage_layout(circuit, support);
}

std::vector<LayerTraceValueCounts>
canonical_trace_value_counts(const LayeredCircuit &circuit) {
    return canonical_trace_layout(circuit).value_counts;
}

CanonicalTraceLayout canonical_trace_layout(
    const LayeredCircuit &circuit) {
    CanonicalTraceLayout result;
    result.wire_support = derive_trace_wire_support(circuit);
    result.storage =
        derive_trace_storage_layout(circuit, result.wire_support);
    result.stored_value_classifications =
        derive_trace_value_classifications(circuit, result.storage);
    result.value_counts = derive_trace_value_counts(
        result.wire_support, result.storage,
        result.stored_value_classifications);
    return result;
}

struct CertifiedCanonicalTraceLayout::State {
    const LayeredCircuit circuit;
    const CanonicalTraceLayout layout;
};

CertifiedCanonicalTraceLayout::CertifiedCanonicalTraceLayout(
    std::shared_ptr<const State> state)
    : state_(std::move(state)) {}

const LayeredCircuit &CertifiedCanonicalTraceLayout::circuit() const {
    if (!state_) {
        throw std::logic_error(
            "certified canonical trace layout is moved from");
    }
    return state_->circuit;
}

const CanonicalTraceLayout &
CertifiedCanonicalTraceLayout::layout() const {
    if (!state_) {
        throw std::logic_error(
            "certified canonical trace layout is moved from");
    }
    return state_->layout;
}

CertifiedCanonicalTraceLayout derive_certified_canonical_trace_layout(
    const LayeredCircuit &circuit) {
    CanonicalTraceLayout layout = canonical_trace_layout(circuit);
    return CertifiedCanonicalTraceLayout(
        std::shared_ptr<const CertifiedCanonicalTraceLayout::State>(
            new CertifiedCanonicalTraceLayout::State{
                circuit, std::move(layout)}));
}

CertifiedCanonicalTraceLayout certify_canonical_trace_layout(
    const LayeredCircuit &circuit, CanonicalTraceLayout candidate) {
    if (candidate != canonical_trace_layout(circuit)) {
        throw std::invalid_argument(
            "canonical trace layout candidate differs from the circuit");
    }
    return CertifiedCanonicalTraceLayout(
        std::shared_ptr<const CertifiedCanonicalTraceLayout::State>(
            new CertifiedCanonicalTraceLayout::State{
                circuit, std::move(candidate)}));
}

void validate_layer_wire_support(const LayeredCircuit &circuit,
                                 std::size_t layer_index,
                                 const LayerWireSupport &support) {
    validate_layer_wire_support(support);
    if (support != canonical_layer_wire_support(circuit, layer_index)) {
        throw std::invalid_argument(
            "trace wire support: layer map disagrees with the circuit");
    }
}

void validate_trace_wire_support(
    const LayeredCircuit &circuit,
    std::span<const LayerWireSupport> support) {
    const std::vector<LayerWireSupport> canonical =
        derive_trace_wire_support(circuit);
    if (support.size() != canonical.size()) {
        throw std::invalid_argument(
            "trace wire support: layer count disagrees with the circuit");
    }
    for (std::size_t layer = 0; layer < support.size(); ++layer) {
        validate_layer_wire_support(support[layer]);
        if (support[layer] != canonical[layer]) {
            throw std::invalid_argument(
                "trace wire support: layer map disagrees with the circuit");
        }
    }
}

void validate_layer_storage_layout(const LayeredCircuit &circuit,
                                   std::size_t layer_index,
                                   const LayerStorageLayout &layout) {
    validate_layer_storage_layout(layout);
    if (layout != canonical_layer_storage_layout(circuit, layer_index)) {
        throw std::invalid_argument(
            "trace storage layout: layer map disagrees with the circuit");
    }
}

void validate_trace_storage_layout(
    const LayeredCircuit &circuit,
    std::span<const LayerStorageLayout> layouts) {
    const std::vector<LayerWireSupport> support =
        derive_trace_wire_support(circuit);
    const std::vector<LayerStorageLayout> canonical =
        derive_trace_storage_layout(circuit, support);
    if (layouts.size() != canonical.size()) {
        throw std::invalid_argument(
            "trace storage layout: layer count disagrees with the circuit");
    }
    for (std::size_t layer = 0; layer < layouts.size(); ++layer) {
        validate_layer_storage_layout(layouts[layer]);
        if (layouts[layer] != canonical[layer]) {
            throw std::invalid_argument(
                "trace storage layout: layer map disagrees with the circuit");
        }
    }
}

} // namespace laminate::payload
