#include "laminate/payload/circuit.hpp"

#include <algorithm>
#include <stdexcept>
#include <string>
#include <utility>

namespace laminate::payload {
namespace {

bool is_power_of_two(std::size_t value) {
    return value != 0 && (value & (value - 1)) == 0;
}

const char *gate_name(GateOp operation) {
    switch (operation) {
    case GateOp::Add:
        return "Add";
    case GateOp::AddPlain:
        return "AddPlain";
    case GateOp::Mul:
        return "Mul";
    case GateOp::MulPlain:
        return "MulPlain";
    case GateOp::Rotate:
        return "Rotate";
    }
    return "unknown";
}

bool is_uniform(const fhe::SlotVector &plaintext) {
    return !plaintext.empty() &&
           std::all_of(plaintext.begin() + 1, plaintext.end(),
                       [&](const Fp &value) {
                           return value == plaintext.front();
                       });
}

} // namespace

PayloadShape PayloadShape::laned(std::size_t lanes, std::size_t slots) {
    PayloadShape result{PayloadKind::Laned, slots, lanes};
    result.validate();
    return result;
}

PayloadShape PayloadShape::wide(std::size_t slots) {
    PayloadShape result{PayloadKind::Wide, slots, 0};
    result.validate();
    return result;
}

std::size_t PayloadShape::value_width() const {
    return kind == PayloadKind::Laned ? lane_count : slot_count;
}

void PayloadShape::validate() const {
    if (kind != PayloadKind::Laned && kind != PayloadKind::Wide) {
        throw std::invalid_argument("PayloadShape: unsupported payload kind");
    }
    if (slot_count < 2 || !is_power_of_two(slot_count)) {
        throw std::invalid_argument(
            "PayloadShape: slot count must be a power of two >= 2");
    }
    if (kind == PayloadKind::Laned) {
        if (!is_power_of_two(lane_count) || lane_count > slot_count) {
            throw std::invalid_argument(
                "PayloadShape: lane count must be a power of two in [1, N]");
        }
    } else if (lane_count != 0) {
        throw std::invalid_argument(
            "PayloadShape: wide payloads must have lane count zero");
    }
}

WireId PayloadCircuit::gate_output(std::size_t gate_index) const {
    if (gate_index >= gates.size()) {
        throw std::out_of_range("PayloadCircuit::gate_output: bad gate index");
    }
    return input_count + gate_index;
}

void PayloadCircuit::validate() const {
    shape.validate();
    if (input_count == 0) {
        throw std::invalid_argument(
            "PayloadCircuit: at least one input wire is required");
    }
    const std::size_t width = shape.value_width();
    for (std::size_t index = 0; index < plaintexts.size(); ++index) {
        if (plaintexts[index].size() != width) {
            throw std::invalid_argument(
                "PayloadCircuit: plaintext " + std::to_string(index) +
                " has the wrong logical width");
        }
    }

    for (std::size_t index = 0; index < gates.size(); ++index) {
        const Gate &gate = gates[index];
        const WireId output = input_count + index;
        const auto require_input = [&](WireId wire, const char *side) {
            if (wire >= output) {
                throw std::invalid_argument(
                    "PayloadCircuit: gate " + std::to_string(index) + " " +
                    gate_name(gate.op) + " has invalid " + side +
                    " wire " + std::to_string(wire));
            }
        };

        require_input(gate.left, "left");
        switch (gate.op) {
        case GateOp::Add:
        case GateOp::Mul:
            require_input(gate.right, "right");
            if (gate.parameter != 0) {
                throw std::invalid_argument(
                    "PayloadCircuit: binary gate parameter must be zero");
            }
            break;
        case GateOp::AddPlain:
            if (gate.right != kNoWire) {
                throw std::invalid_argument(
                    "PayloadCircuit: unary plaintext gate has a right wire");
            }
            if (gate.parameter >= plaintexts.size()) {
                throw std::invalid_argument(
                    "PayloadCircuit: plaintext gate index is out of range");
            }
            break;
        case GateOp::MulPlain:
            if (gate.right != kNoWire) {
                throw std::invalid_argument(
                    "PayloadCircuit: unary plaintext gate has a right wire");
            }
            if (gate.parameter >= plaintexts.size()) {
                throw std::invalid_argument(
                    "PayloadCircuit: plaintext gate index is out of range");
            }
            if (shape.kind == PayloadKind::Laned &&
                !is_uniform(plaintexts[gate.parameter])) {
                throw std::invalid_argument(
                    "PayloadCircuit: Laned MulPlain requires a uniform "
                    "plaintext");
            }
            break;
        case GateOp::Rotate:
            if (shape.kind != PayloadKind::Wide) {
                throw std::invalid_argument(
                    "PayloadCircuit: Rotate is not valid in laned mode");
            }
            if (gate.right != kNoWire) {
                throw std::invalid_argument(
                    "PayloadCircuit: Rotate has a right wire");
            }
            if (gate.parameter >= shape.slot_count) {
                throw std::invalid_argument(
                    "PayloadCircuit: rotation step is out of range");
            }
            break;
        default:
            throw std::invalid_argument(
                "PayloadCircuit: gate " + std::to_string(index) +
                " has an unsupported operation");
        }
    }

    if (outputs.empty()) {
        throw std::invalid_argument(
            "PayloadCircuit: at least one output wire is required");
    }
    std::vector<bool> seen(wire_count(), false);
    for (WireId output : outputs) {
        if (output >= wire_count()) {
            throw std::invalid_argument(
                "PayloadCircuit: output wire is out of range");
        }
        if (seen[output]) {
            throw std::invalid_argument(
                "PayloadCircuit: output wires must be distinct");
        }
        seen[output] = true;
    }
}

PayloadBuilder::PayloadBuilder(PayloadShape shape, std::size_t input_count) {
    circuit_.shape = shape;
    circuit_.input_count = input_count;
    circuit_.shape.validate();
    if (input_count == 0) {
        throw std::invalid_argument(
            "PayloadBuilder: at least one input wire is required");
    }
}

std::size_t PayloadBuilder::add_plaintext(fhe::SlotVector plaintext) {
    if (plaintext.size() != circuit_.shape.value_width()) {
        throw std::invalid_argument(
            "PayloadBuilder::add_plaintext: wrong logical width");
    }
    circuit_.plaintexts.push_back(std::move(plaintext));
    return circuit_.plaintexts.size() - 1;
}

std::size_t PayloadBuilder::add_scalar_plaintext(const Fp &scalar) {
    return add_plaintext(
        fhe::SlotVector(circuit_.shape.value_width(), scalar));
}

WireId PayloadBuilder::add(WireId left, WireId right) {
    return append(Gate{GateOp::Add, left, right, 0});
}

WireId PayloadBuilder::add_plain(WireId input, std::size_t plaintext) {
    return append(Gate{GateOp::AddPlain, input, kNoWire, plaintext});
}

WireId PayloadBuilder::mul(WireId left, WireId right) {
    return append(Gate{GateOp::Mul, left, right, 0});
}

WireId PayloadBuilder::mul_plain(WireId input, std::size_t plaintext) {
    return append(Gate{GateOp::MulPlain, input, kNoWire, plaintext});
}

WireId PayloadBuilder::rotate(WireId input, std::size_t steps) {
    if (circuit_.shape.kind != PayloadKind::Wide) {
        throw std::invalid_argument(
            "PayloadBuilder::rotate: rotations require a wide payload");
    }
    if (steps >= circuit_.shape.slot_count) {
        throw std::invalid_argument(
            "PayloadBuilder::rotate: rotation step is out of range");
    }
    return append(Gate{GateOp::Rotate, input, kNoWire, steps});
}

void PayloadBuilder::set_outputs(std::vector<WireId> outputs) {
    circuit_.outputs = std::move(outputs);
}

PayloadCircuit PayloadBuilder::finish() {
    circuit_.validate();
    return std::move(circuit_);
}

WireId PayloadBuilder::append(Gate gate) {
    require_existing(gate.left, gate_name(gate.op));
    if (gate.op == GateOp::Add || gate.op == GateOp::Mul) {
        require_existing(gate.right, gate_name(gate.op));
    }
    if ((gate.op == GateOp::AddPlain || gate.op == GateOp::MulPlain) &&
        gate.parameter >= circuit_.plaintexts.size()) {
        throw std::invalid_argument(
            "PayloadBuilder: plaintext index is out of range");
    }
    if (gate.op == GateOp::MulPlain &&
        circuit_.shape.kind == PayloadKind::Laned &&
        !is_uniform(circuit_.plaintexts[gate.parameter])) {
        throw std::invalid_argument(
            "PayloadBuilder::MulPlain: Laned payloads require a uniform "
            "plaintext");
    }
    circuit_.gates.push_back(gate);
    return circuit_.wire_count() - 1;
}

void PayloadBuilder::require_existing(WireId wire,
                                      const char *operation) const {
    if (wire >= circuit_.wire_count()) {
        throw std::invalid_argument(std::string("PayloadBuilder::") +
                                    operation +
                                    ": input wire does not exist yet");
    }
}

} // namespace laminate::payload
