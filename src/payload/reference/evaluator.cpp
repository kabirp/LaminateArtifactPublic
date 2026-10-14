#include "laminate/payload/evaluator.hpp"

#include <algorithm>
#include <stdexcept>
#include <string>
#include <utility>

namespace laminate::payload {
namespace {

fhe::SlotVector add_vectors(const fhe::SlotVector &left,
                            const fhe::SlotVector &right) {
    fhe::SlotVector result(left.size());
    for (std::size_t index = 0; index < result.size(); ++index) {
        result[index] = left[index] + right[index];
    }
    return result;
}

fhe::SlotVector mul_vectors(const fhe::SlotVector &left,
                            const fhe::SlotVector &right) {
    fhe::SlotVector result(left.size());
    for (std::size_t index = 0; index < result.size(); ++index) {
        result[index] = left[index] * right[index];
    }
    return result;
}

bool is_uniform(const fhe::SlotVector &values) {
    return std::all_of(values.begin() + 1, values.end(),
                       [&](const Fp &value) { return value == values.front(); });
}

} // namespace

std::vector<fhe::SlotVector>
PayloadEvaluation::output_values(const PayloadCircuit &circuit) const {
    circuit.validate();
    if (wires.size() != circuit.wire_count()) {
        throw std::invalid_argument(
            "PayloadEvaluation::output_values: trace has the wrong size");
    }
    std::vector<fhe::SlotVector> result;
    result.reserve(circuit.outputs.size());
    for (WireId output : circuit.outputs) {
        result.push_back(wires[output]);
    }
    return result;
}

PayloadEvaluation evaluate(const PayloadCircuit &circuit,
                           std::span<const fhe::SlotVector> inputs) {
    circuit.validate();
    if (inputs.size() != circuit.input_count) {
        throw std::invalid_argument(
            "payload::evaluate: input vector count does not match circuit");
    }
    for (const fhe::SlotVector &input : inputs) {
        if (input.size() != circuit.shape.value_width()) {
            throw std::invalid_argument(
                "payload::evaluate: input has the wrong logical width");
        }
    }

    PayloadEvaluation result;
    result.wires.reserve(circuit.wire_count());
    result.wires.insert(result.wires.end(), inputs.begin(), inputs.end());
    for (const Gate &gate : circuit.gates) {
        const fhe::SlotVector &left = result.wires[gate.left];
        switch (gate.op) {
        case GateOp::Add:
            result.wires.push_back(
                add_vectors(left, result.wires[gate.right]));
            break;
        case GateOp::AddPlain:
            result.wires.push_back(
                add_vectors(left, circuit.plaintexts[gate.parameter]));
            break;
        case GateOp::Mul:
            result.wires.push_back(
                mul_vectors(left, result.wires[gate.right]));
            break;
        case GateOp::MulPlain:
            result.wires.push_back(
                mul_vectors(left, circuit.plaintexts[gate.parameter]));
            break;
        case GateOp::Rotate:
            result.wires.push_back(fhe::grid_rotate(left, gate.parameter));
            break;
        }
    }
    return result;
}

PayloadStats analyze(const PayloadCircuit &circuit) {
    circuit.validate();
    PayloadStats result;
    std::vector<std::size_t> ct_depth(circuit.input_count, 0);
    std::vector<std::size_t> half_depth(circuit.input_count, 0);
    std::vector<std::size_t> alternating_depth(circuit.input_count, 0);
    ct_depth.reserve(circuit.wire_count());
    half_depth.reserve(circuit.wire_count());
    alternating_depth.reserve(circuit.wire_count());

    for (const Gate &gate : circuit.gates) {
        const std::size_t left_ct = ct_depth[gate.left];
        const std::size_t left_half = half_depth[gate.left];
        const std::size_t left_alternating = alternating_depth[gate.left];
        std::size_t output_ct = left_ct;
        std::size_t output_half = left_half;
        std::size_t output_alternating = left_alternating;
        switch (gate.op) {
        case GateOp::Add:
            ++result.add_gates;
            output_ct = std::max(left_ct, ct_depth[gate.right]);
            output_half = std::max(left_half, half_depth[gate.right]);
            output_alternating =
                std::max(left_alternating, alternating_depth[gate.right]);
            break;
        case GateOp::AddPlain:
            ++result.add_plain_gates;
            break;
        case GateOp::Mul:
            ++result.mul_gates;
            output_ct = std::max(left_ct, ct_depth[gate.right]) + 1;
            output_half = std::max(left_half, half_depth[gate.right]) + 2;
            output_alternating =
                std::max(left_alternating, alternating_depth[gate.right]) + 1;
            break;
        case GateOp::MulPlain:
            ++result.mul_plain_gates;
            if (is_uniform(circuit.plaintexts[gate.parameter])) {
                ++output_half;
            } else {
                output_half += 2;
            }
            break;
        case GateOp::Rotate:
            ++result.rotate_gates;
            break;
        }
        ct_depth.push_back(output_ct);
        half_depth.push_back(output_half);
        alternating_depth.push_back(output_alternating);
        result.ct_ct_multiplicative_depth =
            std::max(result.ct_ct_multiplicative_depth, output_ct);
        result.fhe_half_depth = std::max(result.fhe_half_depth, output_half);
        result.alternating_multiplicative_depth =
            std::max(result.alternating_multiplicative_depth,
                     output_alternating);
    }
    return result;
}

} // namespace laminate::payload
