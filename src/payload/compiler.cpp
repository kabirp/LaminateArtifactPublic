#include "laminate/payload/compiler.hpp"

#include "laminate/payload/setup/encoding.hpp"
#include "laminate/payload/evaluator.hpp"

#include <algorithm>
#include <limits>
#include <map>
#include <optional>
#include <span>
#include <stdexcept>
#include <utility>

namespace laminate::payload {
namespace {

using AtomId = std::size_t;
inline constexpr AtomId kNoAtom = std::numeric_limits<AtomId>::max();

struct SymbolicTerm {
    AtomId atom = kNoAtom;
    std::size_t rotation = 0;
    Fp coefficient = Fp::zero();
};

struct SymbolicExpression {
    std::vector<SymbolicTerm> terms;
    AffineConstant constant = Fp::zero();
};

struct Atom {
    std::size_t depth = 0;
    std::size_t last_needed = 0;
};

struct MultiplicationNode {
    std::size_t depth = 0;
    AtomId output = kNoAtom;
    SymbolicExpression left;
    SymbolicExpression right;
};

struct DenseAlternatingStage {
    AffineLayer affine_operands;
    MultiplicationLayer multiplication_outputs;
};

/// Symbolic payload wires between nonlinear gates. Affine operations are
/// absorbed into expressions; each ciphertext multiplication creates one
/// new atom at its multiplicative depth. This path is used only by Laned.
struct SymbolicPayload {
    std::vector<AffineConstant> compact_plaintexts;
    std::vector<Atom> atoms;
    std::vector<SymbolicExpression> wires;
    std::vector<MultiplicationNode> multiplication_nodes;
    std::size_t multiplication_depth = 0;
};

/// Dense alternating stages plus the final location of every live atom.
/// Stages are stored from input to output; final circuit assembly reverses
/// them because `LayeredCircuit` lists output first.
struct DenseAlternatingPlan {
    std::vector<DenseAlternatingStage> stages;
    std::vector<std::size_t> output_state_index;
};

std::size_t next_power_of_two(std::size_t value) {
    if (value == 0) {
        return 1;
    }
    std::size_t result = 1;
    while (result < value) {
        if (result > std::numeric_limits<std::size_t>::max() / 2) {
            throw std::overflow_error("compile: layer size overflows");
        }
        result *= 2;
    }
    return result;
}

bool is_uniform(const fhe::SlotVector &values) {
    return !values.empty() &&
           std::all_of(values.begin() + 1, values.end(),
                       [&](const Fp &value) { return value == values.front(); });
}

AffineConstant compact_constant(const fhe::SlotVector &values) {
    if (is_uniform(values)) {
        return values.front();
    }
    return values;
}

AffineConstant add_constants(const AffineConstant &left,
                             const AffineConstant &right,
                             std::size_t width) {
    if (const auto *left_scalar = std::get_if<Fp>(&left)) {
        if (const auto *right_scalar = std::get_if<Fp>(&right)) {
            return *left_scalar + *right_scalar;
        }
    }
    fhe::SlotVector result = materialize(left, width);
    const fhe::SlotVector right_slots = materialize(right, width);
    for (std::size_t slot = 0; slot < width; ++slot) {
        result[slot] += right_slots[slot];
    }
    return compact_constant(result);
}

AffineConstant scale_constant(const AffineConstant &constant,
                              const Fp &scalar) {
    if (const auto *uniform = std::get_if<Fp>(&constant)) {
        return *uniform * scalar;
    }
    fhe::SlotVector result = std::get<fhe::SlotVector>(constant);
    for (Fp &value : result) {
        value *= scalar;
    }
    return compact_constant(result);
}

AffineConstant rotate_constant(const AffineConstant &constant,
                               std::size_t width, std::size_t steps) {
    if (std::holds_alternative<Fp>(constant)) {
        return constant;
    }
    return compact_constant(
        fhe::grid_rotate(materialize(constant, width), steps));
}

void normalize(SymbolicExpression &expression) {
    std::map<std::pair<AtomId, std::size_t>, Fp> combined;
    for (const SymbolicTerm &term : expression.terms) {
        combined[{term.atom, term.rotation}] += term.coefficient;
    }
    expression.terms.clear();
    expression.terms.reserve(combined.size());
    for (const auto &[key, coefficient] : combined) {
        if (!coefficient.is_zero()) {
            expression.terms.push_back(
                SymbolicTerm{key.first, key.second, coefficient});
        }
    }
}

SymbolicExpression add_expressions(SymbolicExpression left,
                                   const SymbolicExpression &right,
                                   std::size_t width) {
    left.terms.insert(left.terms.end(), right.terms.begin(), right.terms.end());
    left.constant = add_constants(left.constant, right.constant, width);
    normalize(left);
    return left;
}

SymbolicExpression scale_expression(SymbolicExpression expression,
                                    const Fp &scalar) {
    for (SymbolicTerm &term : expression.terms) {
        term.coefficient *= scalar;
    }
    expression.constant = scale_constant(expression.constant, scalar);
    normalize(expression);
    return expression;
}

SymbolicExpression rotate_expression(SymbolicExpression expression,
                                     std::size_t slot_count,
                                     std::size_t steps) {
    for (SymbolicTerm &term : expression.terms) {
        term.rotation = fhe::grid_compose(slot_count, term.rotation, steps);
    }
    expression.constant =
        rotate_constant(expression.constant, slot_count, steps);
    normalize(expression);
    return expression;
}

std::size_t expression_depth(const SymbolicExpression &expression,
                             const std::vector<Atom> &atoms) {
    std::size_t depth = 0;
    for (const SymbolicTerm &term : expression.terms) {
        depth = std::max(depth, atoms[term.atom].depth);
    }
    return depth;
}

void mark_needed(const SymbolicExpression &expression, std::size_t stage,
                 std::vector<Atom> &atoms) {
    for (const SymbolicTerm &term : expression.terms) {
        atoms[term.atom].last_needed =
            std::max(atoms[term.atom].last_needed, stage);
    }
}

SymbolicExpression atom_expression(AtomId atom) {
    SymbolicExpression result;
    result.terms.push_back(SymbolicTerm{atom, 0, Fp::one()});
    return result;
}

bool is_zero_constant(const AffineConstant &constant) {
    if (const auto *scalar = std::get_if<Fp>(&constant)) {
        return scalar->is_zero();
    }
    const fhe::SlotVector &slots = std::get<fhe::SlotVector>(constant);
    return std::all_of(slots.begin(), slots.end(),
                       [](const Fp &value) { return value.is_zero(); });
}

std::optional<AtomId>
identity_operand_atom(const SymbolicExpression &expression) {
    if (expression.terms.size() != 1U ||
        expression.terms.front().rotation != 0U ||
        !(expression.terms.front().coefficient == Fp::one()) ||
        !is_zero_constant(expression.constant)) {
        return std::nullopt;
    }
    return expression.terms.front().atom;
}

bool has_carry_into_stage(const SymbolicPayload &symbolic,
                          std::size_t depth) {
    return std::any_of(
        symbolic.atoms.begin(), symbolic.atoms.end(),
        [depth](const Atom &atom) {
            return atom.depth < depth && atom.last_needed > depth;
        });
}

/// If the next depth is an exact contraction of this depth's products, order
/// those independent products exactly as the next affine layer consumes them:
/// all left operands, followed by all right operands. This turns a shuffled
/// permutation into the identity on dense live-wire ordinals without changing
/// a gate recipe or any layer dimensions.
void reorder_if_identity_contraction(
    std::vector<const MultiplicationNode *> &current,
    const std::vector<const MultiplicationNode *> &next,
    const SymbolicPayload &symbolic, std::size_t current_depth) {
    if (current.empty() || current.size() % 2U != 0U ||
        current.size() / 2U != next.size() ||
        has_carry_into_stage(symbolic, current_depth)) {
        return;
    }

    std::vector<const MultiplicationNode *> node_for_atom(
        symbolic.atoms.size(), nullptr);
    for (const MultiplicationNode *node : current) {
        if (node->output >= node_for_atom.size() ||
            node_for_atom[node->output] != nullptr ||
            symbolic.atoms[node->output].last_needed != current_depth + 1U) {
            return;
        }
        node_for_atom[node->output] = node;
    }

    std::vector<bool> used(symbolic.atoms.size(), false);
    std::vector<const MultiplicationNode *> reordered;
    reordered.reserve(current.size());
    const auto append_operand = [&](const SymbolicExpression &operand) {
        const std::optional<AtomId> atom = identity_operand_atom(operand);
        if (!atom || *atom >= node_for_atom.size() ||
            node_for_atom[*atom] == nullptr || used[*atom]) {
            return false;
        }
        used[*atom] = true;
        reordered.push_back(node_for_atom[*atom]);
        return true;
    };

    for (const MultiplicationNode *node : next) {
        if (!append_operand(node->left)) {
            return;
        }
    }
    for (const MultiplicationNode *node : next) {
        if (!append_operand(node->right)) {
            return;
        }
    }
    if (reordered.size() != current.size()) {
        return;
    }
    current = std::move(reordered);
}

std::vector<std::vector<const MultiplicationNode *>>
canonical_multiplication_order(const SymbolicPayload &symbolic) {
    std::vector<std::vector<const MultiplicationNode *>> result(
        symbolic.multiplication_depth + 1U);
    for (const MultiplicationNode &node : symbolic.multiplication_nodes) {
        result[node.depth].push_back(&node);
    }

    // Work backward: a depth's order must follow the already-final order of
    // its consumers, including through a run of consecutive contractions.
    for (std::size_t next_depth = symbolic.multiplication_depth;
         next_depth > 1U; --next_depth) {
        reorder_if_identity_contraction(
            result[next_depth - 1U], result[next_depth], symbolic,
            next_depth - 1U);
    }
    return result;
}

AffineGate compile_expression(const SymbolicExpression &expression,
                              std::span<const std::size_t> state_index,
                              GateOrigin origin) {
    AffineGate result;
    result.constant = expression.constant;
    result.origin = origin;
    result.terms.reserve(expression.terms.size());
    for (const SymbolicTerm &term : expression.terms) {
        if (term.atom >= state_index.size() ||
            state_index[term.atom] == kNoAtom) {
            throw std::logic_error(
                "compile: affine expression references an unavailable atom");
        }
        result.terms.push_back(AffineTerm{state_index[term.atom],
                                          term.rotation, term.coefficient});
    }
    return result;
}

AffineGate zero_affine_gate() {
    return AffineGate{{}, Fp::zero(), GateOrigin::Padding};
}

DenseAlternatingStage build_dense_stage(
    const std::vector<const MultiplicationNode *> &nodes,
    const std::vector<AtomId> &carry_atoms,
    const std::vector<std::size_t> &state_index,
    std::size_t minimum_padded_products) {
    const std::size_t logical_products = nodes.size() + carry_atoms.size();
    const std::size_t padded_products = std::max(
        next_power_of_two(logical_products), minimum_padded_products);

    DenseAlternatingStage stage;
    stage.affine_operands.gates.reserve(2 * padded_products);
    for (const MultiplicationNode *node : nodes) {
        stage.affine_operands.gates.push_back(compile_expression(
            node->left, state_index, GateOrigin::Payload));
    }
    for (AtomId atom : carry_atoms) {
        stage.affine_operands.gates.push_back(compile_expression(
            atom_expression(atom), state_index, GateOrigin::Forward));
    }
    while (stage.affine_operands.gates.size() < padded_products) {
        stage.affine_operands.gates.push_back(zero_affine_gate());
    }
    for (const MultiplicationNode *node : nodes) {
        stage.affine_operands.gates.push_back(compile_expression(
            node->right, state_index, GateOrigin::Payload));
    }
    stage.affine_operands.gates.insert(
        stage.affine_operands.gates.end(), carry_atoms.size(),
        AffineGate{{}, Fp::one(), GateOrigin::Forward});
    while (stage.affine_operands.gates.size() < 2 * padded_products) {
        stage.affine_operands.gates.push_back(zero_affine_gate());
    }
    stage.affine_operands.dimensions =
        LayerDimensions{2 * logical_products, 2 * padded_products,
                        2 * nodes.size(), 2 * carry_atoms.size()};

    stage.multiplication_outputs.gates.reserve(padded_products);
    for (std::size_t gate = 0; gate < logical_products; ++gate) {
        stage.multiplication_outputs.gates.push_back(MultiplicationGate{
            gate < nodes.size() ? GateOrigin::Payload : GateOrigin::Forward});
    }
    while (stage.multiplication_outputs.gates.size() < padded_products) {
        stage.multiplication_outputs.gates.push_back(
            MultiplicationGate{GateOrigin::Padding});
    }
    stage.multiplication_outputs.dimensions =
        LayerDimensions{logical_products, padded_products, nodes.size(),
                        carry_atoms.size()};
    return stage;
}

std::vector<AffineConstant>
compact_payload_plaintexts(const PayloadCircuit &payload) {
    std::vector<AffineConstant> result;
    result.reserve(payload.plaintexts.size());
    for (const fhe::SlotVector &plaintext : payload.plaintexts) {
        result.push_back(compact_constant(plaintext));
    }
    return result;
}

/// Collapse every affine-only payload path into a symbolic expression and
/// retain only multiplication outputs as atoms. This is the algebraic
/// linearization phase; it does not yet choose padded layer widths.
SymbolicPayload linearize_payload(const PayloadCircuit &payload) {
    SymbolicPayload result;
    result.compact_plaintexts = compact_payload_plaintexts(payload);
    result.atoms.reserve(payload.input_count + payload.gates.size());
    result.wires.resize(payload.wire_count());
    result.multiplication_nodes.reserve(payload.gates.size());

    for (std::size_t input = 0; input < payload.input_count; ++input) {
        result.atoms.push_back(Atom{});
        result.wires[input] = atom_expression(input);
    }

    const std::size_t width = payload.shape.value_width();
    for (std::size_t gate_index = 0; gate_index < payload.gates.size();
         ++gate_index) {
        const Gate &gate = payload.gates[gate_index];
        const WireId output = payload.input_count + gate_index;
        switch (gate.op) {
        case GateOp::Add:
            result.wires[output] = add_expressions(
                result.wires[gate.left], result.wires[gate.right], width);
            break;
        case GateOp::AddPlain:
            result.wires[output] = result.wires[gate.left];
            result.wires[output].constant = add_constants(
                result.wires[output].constant,
                result.compact_plaintexts[gate.parameter], width);
            break;
        case GateOp::Rotate:
            result.wires[output] = rotate_expression(
                result.wires[gate.left], payload.shape.slot_count,
                gate.parameter);
            break;
        case GateOp::MulPlain:
            result.wires[output] = scale_expression(
                result.wires[gate.left],
                std::get<Fp>(result.compact_plaintexts[gate.parameter]));
            break;
        case GateOp::Mul: {
            MultiplicationNode node;
            node.left = result.wires[gate.left];
            node.right = result.wires[gate.right];
            node.depth =
                std::max(expression_depth(node.left, result.atoms),
                         expression_depth(node.right, result.atoms)) + 1;
            node.output = result.atoms.size();
            result.atoms.push_back(Atom{node.depth, node.depth});
            mark_needed(node.left, node.depth, result.atoms);
            mark_needed(node.right, node.depth, result.atoms);
            result.wires[output] = atom_expression(node.output);
            result.multiplication_depth =
                std::max(result.multiplication_depth, node.depth);
            result.multiplication_nodes.push_back(std::move(node));
            break;
        }
        }
    }

    for (WireId output : payload.outputs) {
        mark_needed(result.wires[output], result.multiplication_depth + 1,
                    result.atoms);
    }
    return result;
}

/// At each multiplicative depth, emit one affine operand layer followed by
/// the fixed dense multiplication relation
/// `product[i] = left_half[i] * right_half[i]`. Live atoms needed by a later
/// stage are forwarded as multiplication by public one.
DenseAlternatingPlan plan_dense_alternating_stages(
    const PayloadCircuit &payload, const SymbolicPayload &symbolic) {
    DenseAlternatingPlan result;
    result.stages.resize(symbolic.multiplication_depth);
    const std::vector<std::vector<const MultiplicationNode *>> nodes_by_depth =
        canonical_multiplication_order(symbolic);

    std::vector<std::size_t> state_index(symbolic.atoms.size(), kNoAtom);
    std::vector<AtomId> current_atoms;
    current_atoms.reserve(symbolic.atoms.size());
    for (AtomId input = 0; input < payload.input_count; ++input) {
        state_index[input] = current_atoms.size();
        current_atoms.push_back(input);
    }

    for (std::size_t depth = 1; depth <= symbolic.multiplication_depth;
         ++depth) {
        const std::vector<const MultiplicationNode *> &nodes =
            nodes_by_depth[depth];
        if (nodes.empty()) {
            throw std::logic_error("compile: nonlinear depth has no gates");
        }

        std::vector<AtomId> carry_atoms;
        for (AtomId atom : current_atoms) {
            if (symbolic.atoms[atom].last_needed > depth) {
                carry_atoms.push_back(atom);
            }
        }

        const std::size_t minimum_padded_products =
            payload.shape.kind == PayloadKind::Laned
                ? payload.shape.slot_count / payload.shape.lane_count
                : 1;
        result.stages[depth - 1] = build_dense_stage(
            nodes, carry_atoms, state_index,
            minimum_padded_products);

        std::fill(state_index.begin(), state_index.end(), kNoAtom);
        current_atoms.clear();
        for (const MultiplicationNode *node : nodes) {
            state_index[node->output] = current_atoms.size();
            current_atoms.push_back(node->output);
        }
        for (AtomId atom : carry_atoms) {
            state_index[atom] = current_atoms.size();
            current_atoms.push_back(atom);
        }
    }

    result.output_state_index = std::move(state_index);
    return result;
}

AffineLayer build_output_layer(
    const PayloadCircuit &payload, const SymbolicPayload &symbolic,
    std::span<const std::size_t> output_state_index) {
    AffineLayer result;
    const std::size_t padded_outputs =
        next_power_of_two(payload.outputs.size());
    result.gates.reserve(padded_outputs);
    for (WireId output : payload.outputs) {
        result.gates.push_back(compile_expression(
            symbolic.wires[output], output_state_index, GateOrigin::Payload));
    }
    while (result.gates.size() < padded_outputs) {
        result.gates.push_back(zero_affine_gate());
    }
    result.dimensions = LayerDimensions{payload.outputs.size(),
                                        padded_outputs,
                                        payload.outputs.size(), 0};
    return result;
}

LayeredCircuit assemble_layered_circuit(
    const PayloadCircuit &payload, const SymbolicPayload &symbolic,
    DenseAlternatingPlan plan) {
    LayeredCircuit result;
    result.shape = payload.shape;
    result.payload_input_count = payload.input_count;
    result.payload_output_count = payload.outputs.size();
    result.proof_multiplication_depth = symbolic.multiplication_depth;
    result.plaintexts = payload.plaintexts;

    result.layers.reserve(2 * symbolic.multiplication_depth + 2);
    result.layers.emplace_back(build_output_layer(
        payload, symbolic, plan.output_state_index));
    for (std::size_t depth = symbolic.multiplication_depth; depth > 0;
         --depth) {
        result.layers.emplace_back(
            std::move(plan.stages[depth - 1].multiplication_outputs));
        result.layers.emplace_back(
            std::move(plan.stages[depth - 1].affine_operands));
    }
    const std::size_t padded_inputs =
        next_power_of_two(payload.input_count);
    result.layers.emplace_back(InputLayer{LayerDimensions{
        payload.input_count, padded_inputs, payload.input_count, 0}});
    return result;
}

/// A Wide affine layer retains the original shared DAG. Composing its paths
/// would turn a linear-size prefix-sum circuit into a quadratic coefficient
/// table, and diagonal plaintext multipliers do not commute with rotations.
class WideAffineProgramBuilder {
  public:
    WideAffineProgramBuilder(const PayloadCircuit &payload,
                             std::span<const std::size_t> state,
                             std::size_t source_size)
        : payload_(payload), state_(state), source_size_(source_size),
          references_(payload.wire_count(), kNoAtom) {}

    AffineGate output(WireId wire, GateOrigin origin) {
        prepare(wire);
        return AffineGate{{AffineTerm{references_[wire], 0, Fp::one()}},
                          Fp::zero(), origin};
    }

    std::vector<AffineGate> finish() { return std::move(nodes_); }

  private:
    void prepare(WireId requested) {
        // Explicit traversal avoids a call-stack bound on long affine paths.
        std::vector<WireId> pending{requested};
        while (!pending.empty()) {
            const WireId wire = pending.back();
            if (references_[wire] != kNoAtom) {
                pending.pop_back();
                continue;
            }
            if (state_[wire] != kNoAtom) {
                references_[wire] = state_[wire];
                pending.pop_back();
                continue;
            }
            if (wire < payload_.input_count) {
                throw std::logic_error("compile: unavailable Wide input");
            }
            const Gate &gate = payload_.gates[wire - payload_.input_count];
            if (gate.op == GateOp::Mul) {
                throw std::logic_error("compile: unavailable Wide product");
            }
            if (references_[gate.left] == kNoAtom) {
                pending.push_back(gate.left);
                continue;
            }
            if (gate.op == GateOp::Add &&
                references_[gate.right] == kNoAtom) {
                pending.push_back(gate.right);
                continue;
            }
            AffineGate node;
            node.origin = GateOrigin::Payload;
            node.terms.push_back(
                AffineTerm{references_[gate.left], 0, Fp::one()});
            switch (gate.op) {
            case GateOp::Add:
                node.terms.push_back(
                    AffineTerm{references_[gate.right], 0, Fp::one()});
                break;
            case GateOp::AddPlain:
                node.constant = compact_constant(
                    payload_.plaintexts[gate.parameter]);
                break;
            case GateOp::MulPlain: {
                const auto &plaintext = payload_.plaintexts[gate.parameter];
                if (is_uniform(plaintext)) {
                    node.terms.front().coefficient = plaintext.front();
                } else {
                    node.terms.front().plaintext_index = gate.parameter;
                }
                break;
            }
            case GateOp::Rotate:
                node.terms.front().rotation = gate.parameter;
                break;
            case GateOp::Mul:
                throw std::logic_error("compile: nonlinear affine node");
            }
            references_[wire] = source_size_ + nodes_.size();
            nodes_.push_back(std::move(node));
            pending.pop_back();
        }
    }

    const PayloadCircuit &payload_;
    std::span<const std::size_t> state_;
    std::size_t source_size_;
    std::vector<std::size_t> references_;
    std::vector<AffineGate> nodes_;
};

LayeredCircuit compile_wide(const PayloadCircuit &payload) {
    const std::size_t wire_count = payload.wire_count();
    std::vector<std::size_t> depth(wire_count, 0);
    std::vector<std::size_t> last_needed(wire_count, 0);
    std::size_t maximum_depth = 0;
    for (std::size_t index = 0; index < payload.gates.size(); ++index) {
        const auto &gate = payload.gates[index];
        std::size_t value = depth[gate.left];
        if (gate.op == GateOp::Add || gate.op == GateOp::Mul) {
            value = std::max(value, depth[gate.right]);
        }
        value += gate.op == GateOp::Mul;
        depth[payload.input_count + index] = value;
        maximum_depth = std::max(maximum_depth, value);
    }
    std::vector<std::vector<WireId>> products(maximum_depth + 1U);
    for (std::size_t index = 0; index < payload.gates.size(); ++index) {
        if (payload.gates[index].op == GateOp::Mul) {
            const WireId wire = payload.input_count + index;
            products[depth[wire]].push_back(wire);
        }
    }

    std::vector<std::size_t> visited(wire_count, 0);
    const auto mark_needed = [&](WireId requested, std::size_t stage) {
        std::vector<WireId> pending{requested};
        while (!pending.empty()) {
            const WireId wire = pending.back();
            pending.pop_back();
            if (visited[wire] == stage) {
                continue;
            }
            visited[wire] = stage;
            if (wire < payload.input_count ||
                payload.gates[wire - payload.input_count].op == GateOp::Mul) {
                last_needed[wire] = std::max(last_needed[wire], stage);
                continue;
            }
            const auto &gate = payload.gates[wire - payload.input_count];
            pending.push_back(gate.left);
            if (gate.op == GateOp::Add) {
                pending.push_back(gate.right);
            }
        }
    };
    for (std::size_t stage = 1; stage <= maximum_depth; ++stage) {
        for (WireId wire : products[stage]) {
            const auto &gate = payload.gates[wire - payload.input_count];
            mark_needed(gate.left, stage);
            mark_needed(gate.right, stage);
        }
    }
    for (WireId wire : payload.outputs) {
        mark_needed(wire, maximum_depth + 1U);
    }

    // Preserve the identity contraction layout without composing affine DAGs.
    for (std::size_t next = maximum_depth; next > 1; --next) {
        auto &current = products[next - 1U];
        if (current.size() != 2U * products[next].size()) {
            continue;
        }
        bool eligible = true;
        for (WireId wire = 0; wire < wire_count; ++wire) {
            const bool atom = wire < payload.input_count ||
                payload.gates[wire - payload.input_count].op == GateOp::Mul;
            if (atom && depth[wire] < next - 1U && last_needed[wire] >= next) {
                eligible = false;
                break;
            }
        }
        std::vector<WireId> ordered;
        std::vector<bool> used(wire_count, false);
        for (bool right : {false, true}) {
            for (WireId product : products[next]) {
                const auto &gate = payload.gates[product - payload.input_count];
                const WireId operand = right ? gate.right : gate.left;
                if (operand < payload.input_count ||
                    payload.gates[operand - payload.input_count].op != GateOp::Mul ||
                    depth[operand] != next - 1U || last_needed[operand] != next ||
                    used[operand]) {
                    eligible = false;
                    break;
                }
                used[operand] = true;
                ordered.push_back(operand);
            }
        }
        if (eligible && ordered.size() == current.size()) {
            current = std::move(ordered);
        }
    }

    std::vector<std::size_t> state(wire_count, kNoAtom);
    std::vector<WireId> current_atoms;
    for (WireId input = 0; input < payload.input_count; ++input) {
        state[input] = input;
        current_atoms.push_back(input);
    }
    std::size_t source_size = next_power_of_two(payload.input_count);
    std::vector<DenseAlternatingStage> stages;
    stages.reserve(maximum_depth);
    for (std::size_t stage = 1; stage <= maximum_depth; ++stage) {
        std::vector<WireId> carry;
        for (WireId atom : current_atoms) {
            if (last_needed[atom] > stage) {
                carry.push_back(atom);
            }
        }
        const std::size_t logical = products[stage].size() + carry.size();
        const std::size_t padded = next_power_of_two(logical);
        WideAffineProgramBuilder program(payload, state, source_size);
        DenseAlternatingStage compiled;
        auto &operands = compiled.affine_operands;
        for (bool right : {false, true}) {
            for (WireId wire : products[stage]) {
                const auto &gate = payload.gates[wire - payload.input_count];
                operands.gates.push_back(program.output(
                    right ? gate.right : gate.left, GateOrigin::Payload));
            }
            for (WireId wire : carry) {
                operands.gates.push_back(right
                    ? AffineGate{{}, Fp::one(), GateOrigin::Forward}
                    : program.output(wire, GateOrigin::Forward));
            }
            while (operands.gates.size() < (right ? 2U : 1U) * padded) {
                operands.gates.push_back(zero_affine_gate());
            }
        }
        operands.intermediate_gates = program.finish();
        operands.dimensions = {2U * logical, 2U * padded,
                               2U * products[stage].size(), 2U * carry.size()};
        auto &outputs = compiled.multiplication_outputs;
        for (std::size_t index = 0; index < padded; ++index) {
            outputs.gates.push_back(MultiplicationGate{
                index < products[stage].size() ? GateOrigin::Payload
                : index < logical ? GateOrigin::Forward : GateOrigin::Padding});
        }
        outputs.dimensions = {logical, padded, products[stage].size(), carry.size()};
        stages.push_back(std::move(compiled));
        std::fill(state.begin(), state.end(), kNoAtom);
        current_atoms = products[stage];
        current_atoms.insert(current_atoms.end(), carry.begin(), carry.end());
        for (std::size_t index = 0; index < current_atoms.size(); ++index) {
            state[current_atoms[index]] = index;
        }
        source_size = padded;
    }

    LayeredCircuit result;
    result.shape = payload.shape;
    result.payload_input_count = payload.input_count;
    result.payload_output_count = payload.outputs.size();
    result.proof_multiplication_depth = maximum_depth;
    result.plaintexts = payload.plaintexts;
    WideAffineProgramBuilder program(payload, state, source_size);
    AffineLayer output;
    for (WireId wire : payload.outputs) {
        output.gates.push_back(program.output(wire, GateOrigin::Payload));
    }
    const std::size_t padded = next_power_of_two(payload.outputs.size());
    while (output.gates.size() < padded) {
        output.gates.push_back(zero_affine_gate());
    }
    output.dimensions = {payload.outputs.size(), padded, payload.outputs.size(), 0};
    output.intermediate_gates = program.finish();
    result.layers.emplace_back(std::move(output));
    for (std::size_t stage = stages.size(); stage > 0; --stage) {
        result.layers.emplace_back(std::move(stages[stage - 1U].multiplication_outputs));
        result.layers.emplace_back(std::move(stages[stage - 1U].affine_operands));
    }
    result.layers.emplace_back(InputLayer{LayerDimensions{
        payload.input_count, next_power_of_two(payload.input_count),
        payload.input_count, 0}});
    result.validate();
    return result;
}

} // namespace

LayeredCircuit compile(const PayloadCircuit &payload) {
    payload.validate();
    if (payload.shape.kind == PayloadKind::Wide) {
        return compile_wide(payload);
    }
    const SymbolicPayload symbolic = linearize_payload(payload);
    DenseAlternatingPlan plan =
        plan_dense_alternating_stages(payload, symbolic);
    LayeredCircuit result =
        assemble_layered_circuit(payload, symbolic, std::move(plan));

    const PayloadStats stats = analyze(payload);
    if (stats.alternating_multiplicative_depth !=
        symbolic.multiplication_depth) {
        throw std::logic_error(
            "compile: analyzer and compiler depth calculations disagree");
    }
    result.validate();
    return result;
}

void validate_compilation_pair(const PayloadCircuit &payload,
                               const LayeredCircuit &layered) {
    payload.validate();
    layered.validate();
    const LayeredCircuit expected = compile(payload);
    if (encode_canonical(expected) != encode_canonical(layered)) {
        throw std::invalid_argument(
            "layered circuit is not the canonical payload compilation");
    }
}

} // namespace laminate::payload
