/// @file local_scalar_evaluator.cpp
/// @brief Scalar payload evaluation with indexed cross-slot permutations.

#include "local_scalar_evaluator.hpp"

#include <algorithm>
#include <limits>
#include <stdexcept>
#include <string>

namespace laminate::bench::local_payload {
namespace {

struct IndexedWire {
    const Fp *values = nullptr;
    std::size_t rotation = 0;

    Fp at(std::size_t coordinate, std::size_t half) const {
        // The BGV grid action swaps rows and adds column offsets separately.
        // A cyclic offset across the entire vector would mix the two actions.
        const std::size_t source = ((coordinate ^ rotation) & half) |
            ((coordinate + rotation) & (half - 1U));
        return values[source];
    }
};

std::uint64_t checked_multiply(std::uint64_t left, std::uint64_t right,
                               const char *description) {
    if (left != 0 &&
        right > std::numeric_limits<std::uint64_t>::max() / left) {
        throw std::overflow_error(std::string(description) + " overflows");
    }
    return left * right;
}

void validate_inputs(const payload::PayloadCircuit &circuit,
                     std::span<const fhe::SlotVector> inputs) {
    circuit.validate();
    if (circuit.shape.kind != payload::PayloadKind::Wide) {
        throw std::invalid_argument(
            "local scalar evaluation requires a Wide payload");
    }
    if (inputs.size() != circuit.input_count) {
        throw std::invalid_argument(
            "local scalar evaluation input count differs from the circuit");
    }
    for (const fhe::SlotVector &input : inputs) {
        if (input.size() != circuit.shape.slot_count) {
            throw std::invalid_argument(
                "local scalar evaluation input has the wrong width");
        }
    }
}

std::vector<std::uint8_t> cross_slot_gates(
    const payload::PayloadCircuit &circuit) {
    if (std::none_of(circuit.gates.begin(), circuit.gates.end(),
                    [](const auto &gate) {
                        return gate.op == payload::GateOp::Rotate;
                    })) {
        return {};
    }
    std::vector<std::uint8_t> materialized(circuit.wire_count(), 0);
    for (std::size_t index = 0; index < circuit.gates.size(); ++index) {
        if (circuit.gates[index].op == payload::GateOp::Rotate) {
            materialized[circuit.gate_output(index)] = 1;
        }
    }
    // A reverse topological scan marks exactly the rotation dependency closure.
    for (std::size_t index = circuit.gates.size(); index-- > 0;) {
        if (!materialized[circuit.gate_output(index)]) {
            continue;
        }
        const auto &gate = circuit.gates[index];
        materialized[gate.left] = 1;
        if (gate.op == payload::GateOp::Add ||
            gate.op == payload::GateOp::Mul) {
            materialized[gate.right] = 1;
        }
    }
    return materialized;
}

void checksum_word(std::uint64_t &state, std::uint64_t word) {
    // FNV-1a over an explicit little-endian u64 representation is stable on
    // every host.
    constexpr std::uint64_t kPrime = 1'099'511'628'211ULL;
    for (std::size_t byte = 0; byte < sizeof(word); ++byte) {
        state ^= (word >> (8U * byte)) & 0xffU;
        state *= kPrime;
    }
}

} // namespace

std::uint64_t cross_slot_workspace_bytes(
    const payload::PayloadCircuit &circuit) {
    circuit.validate();
    const auto materialized = cross_slot_gates(circuit);
    if (materialized.empty()) {
        return 0;
    }
    std::size_t arithmetic_gates = 0;
    for (std::size_t index = 0; index < circuit.gates.size(); ++index) {
        if (materialized[circuit.gate_output(index)] &&
            circuit.gates[index].op != payload::GateOp::Rotate) {
            ++arithmetic_gates;
        }
    }
    const std::uint64_t table_bytes = checked_multiply(
        checked_multiply(arithmetic_gates, circuit.shape.slot_count,
                         "cross-slot field elements"),
        sizeof(Fp), "cross-slot field bytes");
    const std::uint64_t index_bytes = checked_multiply(
        circuit.wire_count(), sizeof(fhe::SlotVector) + sizeof(IndexedWire) +
                                  sizeof(std::uint8_t),
        "cross-slot indexing bytes");
    if (table_bytes > std::numeric_limits<std::uint64_t>::max() - index_bytes) {
        throw std::overflow_error("cross-slot workspace bytes overflows");
    }
    return table_bytes + index_bytes;
}

EvaluationResult evaluate_scalar_coordinates(
    const payload::PayloadCircuit &circuit,
    std::span<const fhe::SlotVector> inputs,
    const ProgressCallback &progress) {
    validate_inputs(circuit, inputs);

    const std::size_t coordinates = circuit.shape.slot_count;
    const std::uint64_t operations_per_coordinate = circuit.gates.size();
    const std::uint64_t total_operations = checked_multiply(
        operations_per_coordinate, coordinates,
        "local scalar operation count");

    EvaluationResult result;
    result.outputs.assign(
        circuit.outputs.size(),
        fhe::SlotVector(coordinates, Fp::zero()));
    std::vector<Fp> wires(circuit.wire_count(), Fp::zero());
    const auto materialized = cross_slot_gates(circuit);
    std::vector<fhe::SlotVector> prefix(
        materialized.empty() ? 0 : circuit.wire_count());
    std::vector<IndexedWire> views(prefix.size());
    const std::size_t prefix_gate_count = materialized.empty() ? 0 : std::count(
        materialized.begin() + circuit.input_count, materialized.end(), 1);
    const std::uint64_t prefix_operations = checked_multiply(
        prefix_gate_count, coordinates, "cross-slot scalar operations");

    if (progress) {
        progress(EvaluationProgress{0, coordinates, 0, total_operations});
    }
    const std::size_t half = coordinates / 2U;
    if (!materialized.empty()) {
        for (std::size_t input = 0; input < inputs.size(); ++input) {
            views[input] = IndexedWire{inputs[input].data(), 0};
        }
    }
    const auto source_value = [&](payload::WireId wire,
                                  std::size_t coordinate) {
        return views[wire].at(coordinate, half);
    };
    std::uint64_t completed_prefix = 0;
    for (std::size_t index = 0; index < circuit.gates.size(); ++index) {
        const auto output = circuit.gate_output(index);
        if (materialized.empty() || !materialized[output]) {
            continue;
        }
        const auto &gate = circuit.gates[index];
        if (gate.op == payload::GateOp::Rotate) {
            views[output] = views[gate.left];
            views[output].rotation = fhe::grid_compose(
                coordinates, views[output].rotation, gate.parameter);
            result.scalar_permutation_wires += coordinates;
        } else {
            auto &values = prefix[output];
            values.resize(coordinates);
            for (std::size_t coordinate = 0; coordinate < coordinates; ++coordinate) {
                const Fp left = source_value(gate.left, coordinate);
                switch (gate.op) {
                case payload::GateOp::Add:
                    values[coordinate] = left + source_value(gate.right, coordinate);
                    break;
                case payload::GateOp::Mul:
                    values[coordinate] = left * source_value(gate.right, coordinate);
                    break;
                case payload::GateOp::AddPlain:
                    values[coordinate] = left + circuit.plaintexts[gate.parameter][coordinate];
                    break;
                case payload::GateOp::MulPlain:
                    values[coordinate] = left * circuit.plaintexts[gate.parameter][coordinate];
                    break;
                case payload::GateOp::Rotate:
                    throw std::logic_error("rotation reached arithmetic prefix");
                }
            }
            views[output] = IndexedWire{values.data(), 0};
        }
        completed_prefix += coordinates;
        if (progress && (completed_prefix == prefix_operations ||
                         completed_prefix % (coordinates * 256U) == 0)) {
            progress(EvaluationProgress{0, coordinates, completed_prefix,
                                        total_operations});
        }
    }
    // Specialize the suffix once so circuits without rotations retain their
    // direct scalar-wire loop and allocate no view or prefix tables.
    const auto evaluate_suffix = [&]<bool indexed>() {
        for (std::size_t coordinate = 0; coordinate < coordinates;
             ++coordinate) {
            for (std::size_t input = 0; input < circuit.input_count; ++input) {
                wires[input] = inputs[input][coordinate];
            }
            const auto value_at = [&](payload::WireId wire) {
                return wires[wire];
            };

            for (std::size_t gate_index = 0;
                 gate_index < circuit.gates.size(); ++gate_index) {
                const payload::Gate &gate = circuit.gates[gate_index];
                if constexpr (indexed) {
                    if (materialized[circuit.gate_output(gate_index)]) {
                        // Resolve each indexed wire once for this coordinate;
                        // all later consumers reuse the scalar wire buffer.
                        wires[circuit.gate_output(gate_index)] = source_value(
                            circuit.gate_output(gate_index), coordinate);
                        continue;
                    }
                }
                Fp value;
                switch (gate.op) {
                case payload::GateOp::Add:
                    value = value_at(gate.left) + value_at(gate.right);
                    break;
                case payload::GateOp::AddPlain:
                    value = value_at(gate.left) +
                            circuit.plaintexts[gate.parameter][coordinate];
                    break;
                case payload::GateOp::Mul:
                    value = value_at(gate.left) * value_at(gate.right);
                    break;
                case payload::GateOp::MulPlain:
                    value = value_at(gate.left) *
                            circuit.plaintexts[gate.parameter][coordinate];
                    break;
                case payload::GateOp::Rotate:
                    throw std::logic_error(
                        "rotation was omitted from the cross-slot prefix");
                }
                wires[circuit.input_count + gate_index] = value;
            }

            for (std::size_t output = 0; output < circuit.outputs.size();
                 ++output) {
                result.outputs[output][coordinate] =
                    value_at(circuit.outputs[output]);
            }
            if (progress) {
                const std::uint64_t completed = prefix_operations + checked_multiply(
                    operations_per_coordinate - prefix_gate_count, coordinate + 1U,
                    "completed local scalar operation count");
                progress(EvaluationProgress{coordinate + 1U, coordinates,
                                            completed, total_operations});
            }
        }
    };
    if (materialized.empty()) {
        evaluate_suffix.template operator()<false>();
    } else {
        evaluate_suffix.template operator()<true>();
    }
    return result;
}

std::uint64_t output_checksum(
    std::span<const fhe::SlotVector> outputs) {
    std::uint64_t state = 14'695'981'039'346'656'037ULL;
    checksum_word(state, outputs.size());
    for (const fhe::SlotVector &output : outputs) {
        checksum_word(state, output.size());
        for (const Fp &value : output) {
            checksum_word(state, value.value());
        }
    }
    return state;
}

} // namespace laminate::bench::local_payload
