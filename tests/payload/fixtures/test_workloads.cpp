#include "test_helpers.hpp"

#include "laminate/fhe/mock_backend.hpp"
#include "laminate/payload/compiler.hpp"
#include "laminate/payload/input_encryption.hpp"
#include "laminate/payload/laned_fhe_evaluator.hpp"
#include "laminate/payload/wide_fhe_evaluator.hpp"
#include "laminate/payload/trace/trace_crypto.hpp"
#include "laminate/payload/setup/encoding.hpp"
#include "laminate/payload/evaluator.hpp"
#include "laminate/payload/trace.hpp"
#include "laminate/payload/fixtures/workloads.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <map>
#include <numeric>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

namespace {

using laminate::payload::PayloadShape;
using laminate::payload::Workload;
using laminate::payload::WorkloadKind;
using laminate::payload::WorkloadSpec;

bool throws_invalid_argument(const auto &body) {
    try {
        body();
    } catch (const std::invalid_argument &) {
        return true;
    }
    return false;
}

// This check follows expression identity rather than gate indices: equal
// constants, commutative operand swaps, and composed rotations cannot hide
// repeated work behind a different plaintext entry or intermediate wire.
struct ExpressionKey {
    laminate::payload::GateOp op;
    std::size_t left;
    std::size_t right;
    std::size_t parameter;
    bool operator==(const ExpressionKey &) const = default;
};

struct ExpressionKeyHash {
    std::size_t operator()(const ExpressionKey &key) const {
        std::size_t result = static_cast<std::size_t>(key.op);
        for (const auto item : {key.left, key.right, key.parameter}) {
            result ^= item + 0x9e3779b97f4a7c15ULL + (result << 6U) +
                      (result >> 2U);
        }
        return result;
    }
};

void check_no_repeated_expressions(
    const laminate::payload::PayloadCircuit &circuit) {
    using laminate::payload::GateOp;
    std::map<std::vector<std::uint64_t>, std::size_t> constants;
    std::vector<std::size_t> plaintext_ids;
    for (const auto &plaintext : circuit.plaintexts) {
        std::vector<std::uint64_t> values;
        for (const auto value : plaintext) {
            values.push_back(value.value());
        }
        plaintext_ids.push_back(
            constants.emplace(std::move(values), constants.size())
                .first->second);
    }
    std::unordered_map<ExpressionKey, std::size_t, ExpressionKeyHash> seen;
    seen.reserve(circuit.gates.size());
    std::vector<std::size_t> rotation_bases(circuit.wire_count());
    std::iota(rotation_bases.begin(), rotation_bases.end(), 0U);
    std::vector<std::size_t> rotation_steps(circuit.wire_count(), 0U);
    for (std::size_t index = 0; index < circuit.gates.size(); ++index) {
        const auto &gate = circuit.gates[index];
        ExpressionKey key{gate.op, gate.left, gate.right, gate.parameter};
        if (gate.op == GateOp::Add || gate.op == GateOp::Mul) {
            if (key.right < key.left) {
                std::swap(key.left, key.right);
            }
        } else if (gate.op == GateOp::AddPlain ||
                   gate.op == GateOp::MulPlain) {
            key.parameter = plaintext_ids[gate.parameter];
            const auto &plaintext = circuit.plaintexts[gate.parameter];
            const bool uniform = std::all_of(
                plaintext.begin(), plaintext.end(), [&](const auto value) {
                    return value == plaintext.front();
                });
            CHECK(!uniform || !plaintext.front().is_zero());
            CHECK(gate.op != GateOp::MulPlain || !uniform ||
                  plaintext.front() != laminate::Fp::one());
        } else if (gate.op == GateOp::Rotate) {
            key.left = rotation_bases[gate.left];
            key.parameter = laminate::fhe::grid_compose(
                circuit.shape.slot_count, rotation_steps[gate.left],
                gate.parameter);
            CHECK(key.parameter != 0);
            rotation_bases[circuit.gate_output(index)] = key.left;
            rotation_steps[circuit.gate_output(index)] = key.parameter;
        }
        const auto [previous, inserted] = seen.emplace(key, index);
        if (!inserted) {
            throw laminate::test::CheckFailure(
                "Repeated expression at gates " +
                std::to_string(previous->second) + " and " +
                std::to_string(index));
        }
    }
}

// Normalize the affine front end independently of the generator. Different
// addition trees and rotations of sums must not duplicate the same linear
// form over input coordinates. This catches repeated-input expansions and
// associative duplicates that a gate-key check cannot see.
void check_unique_input_affine_forms(
    const laminate::payload::PayloadCircuit &circuit) {
    using laminate::Fp;
    using laminate::payload::GateOp;
    using Term = std::pair<std::size_t, std::size_t>;
    using Form = std::map<Term, std::uint64_t>;
    std::unordered_map<std::size_t, Form> forms;
    std::map<Form, std::size_t> seen;
    for (std::size_t input = 0; input < circuit.input_count; ++input) {
        Form form{{Term{input, 0U}, 1U}};
        forms.emplace(input, form);
        seen.emplace(std::move(form), input);
    }
    const Term constant{circuit.input_count, 0U};
    const auto add_coefficient = [](Form &form, Term term, Fp value) {
        const Fp sum = Fp(form[term]) + value;
        if (sum.is_zero()) {
            form.erase(term);
        } else {
            form[term] = sum.value();
        }
    };
    for (std::size_t index = 0; index < circuit.gates.size(); ++index) {
        const auto &gate = circuit.gates[index];
        if (gate.op == GateOp::Mul || !forms.contains(gate.left) ||
            (gate.op == GateOp::Add && !forms.contains(gate.right))) {
            continue;
        }
        Form form = forms.at(gate.left);
        if (gate.op == GateOp::Add) {
            for (const auto &[term, value] : forms.at(gate.right)) {
                add_coefficient(form, term, Fp(value));
            }
        } else if (gate.op == GateOp::Rotate) {
            Form rotated;
            for (const auto &[term, value] : form) {
                const Term moved{
                    term.first,
                    term.first == circuit.input_count
                        ? 0U
                        : laminate::fhe::grid_compose(
                              circuit.shape.slot_count, term.second,
                              gate.parameter)};
                add_coefficient(rotated, moved, Fp(value));
            }
            form = std::move(rotated);
        } else {
            const auto &plaintext = circuit.plaintexts[gate.parameter];
            if (!std::all_of(plaintext.begin(), plaintext.end(),
                             [&](const auto value) {
                                 return value == plaintext.front();
                             })) {
                // Slot-varying coefficients are covered by the structural
                // and bounded semantic checks, not this scalar normal form.
                continue;
            }
            if (gate.op == GateOp::AddPlain) {
                add_coefficient(form, constant, plaintext.front());
            } else {
                for (auto &[term, value] : form) {
                    (void)term;
                    value = (Fp(value) * plaintext.front()).value();
                }
            }
        }
        const auto output = circuit.gate_output(index);
        const auto [previous, inserted] = seen.emplace(form, output);
        if (!inserted) {
            throw laminate::test::CheckFailure(
                "Repeated input affine form at wires " +
                std::to_string(previous->second) + " and " +
                std::to_string(output));
        }
        forms.emplace(output, std::move(form));
    }
}

void check_all_wires_live(const laminate::payload::PayloadCircuit &circuit) {
    using laminate::payload::GateOp;
    std::vector<bool> live(circuit.wire_count(), false);
    for (const auto output : circuit.outputs) {
        live[output] = true;
    }
    for (std::size_t index = circuit.gates.size(); index > 0; --index) {
        if (!live[circuit.gate_output(index - 1U)]) {
            continue;
        }
        const auto &gate = circuit.gates[index - 1U];
        live[gate.left] = true;
        if (gate.op == GateOp::Add || gate.op == GateOp::Mul) {
            live[gate.right] = true;
        }
    }
    CHECK(std::all_of(live.begin(), live.end(), [](bool value) {
        return value;
    }));
}

std::vector<std::size_t> multiplication_widths(
    const laminate::payload::PayloadCircuit &circuit) {
    using laminate::payload::GateOp;
    std::vector<std::size_t> depths(circuit.wire_count(), 0U);
    std::vector<std::size_t> widths;
    for (std::size_t index = 0; index < circuit.gates.size(); ++index) {
        const auto &gate = circuit.gates[index];
        std::size_t depth = depths[gate.left];
        if (gate.op == GateOp::Add || gate.op == GateOp::Mul) {
            depth = std::max(depth, depths[gate.right]);
        }
        if (gate.op == GateOp::Mul) {
            ++depth;
            widths.resize(std::max(widths.size(), depth), 0U);
            ++widths[depth - 1U];
        }
        depths[circuit.gate_output(index)] = depth;
    }
    return widths;
}

void check_mock_evaluation(const Workload &workload) {
    using laminate::fhe::MockBackend;
    const auto layered = laminate::payload::compile(workload.circuit);
    const auto plain = laminate::payload::synthesize_trace(
        workload.circuit, layered, workload.inputs);
    const auto direct = laminate::payload::evaluate(
        workload.circuit, workload.inputs);
    CHECK(plain.payload_outputs ==
          direct.output_values(workload.circuit));
    auto contexts = MockBackend::create(laminate::fhe::MockParameters{
        .slot_count = workload.circuit.shape.slot_count,
        .fresh_rns_limbs = layered.proof_multiplication_depth + 4U,
        .bits_per_limb = 256,
    });
    const auto plan = laminate::payload::FheEvaluationPlan::
        switch_after_multiplication_layers(layered, 1);
    if (workload.circuit.shape.kind ==
        laminate::payload::PayloadKind::Laned) {
        const auto encrypted_inputs =
            laminate::payload::encrypt_laned_payload_inputs<MockBackend>(
                contexts.client, workload.circuit, workload.inputs);
        const auto encrypted = laminate::payload::evaluate_laned_fhe_trace<
            MockBackend>(contexts.eval, workload.circuit, layered,
                         encrypted_inputs, plan);
        CHECK(laminate::payload::decrypt_trace_layers<MockBackend>(
                  contexts.client, layered, encrypted) == plain.layers);
    } else {
        const auto encrypted_inputs =
            laminate::payload::encrypt_wide_payload_inputs<MockBackend>(
                contexts.client, workload.circuit, workload.inputs);
        const auto encrypted =
            laminate::payload::evaluate_wide_fhe_trace_into<MockBackend>(
                contexts.eval, workload.circuit, layered, encrypted_inputs,
                plan, laminate::payload::InMemoryTraceSink<MockBackend>{
                          contexts.eval});
        CHECK(laminate::payload::decrypt_trace_layers<MockBackend>(
                  contexts.client, layered, encrypted) == plain.layers);
    }
}

void test_determinism_and_seed_sensitivity() {
    const WorkloadSpec spec{WorkloadKind::Diamond, PayloadShape::wide(8), 3,
                            4, 12345};
    const Workload first = laminate::payload::make_workload(spec);
    const Workload same = laminate::payload::make_workload(spec);
    const auto circuit_only = laminate::payload::make_payload_circuit(spec);
    WorkloadSpec changed = spec;
    ++changed.seed;
    const Workload different = laminate::payload::make_workload(changed);

    CHECK(laminate::payload::encode_canonical(first.circuit) ==
          laminate::payload::encode_canonical(same.circuit));
    CHECK(laminate::payload::encode_canonical(first.circuit) ==
          laminate::payload::encode_canonical(circuit_only));
    CHECK(first.inputs == same.inputs);
    CHECK(laminate::payload::encode_canonical(first.circuit) !=
              laminate::payload::encode_canonical(different.circuit) ||
          first.inputs != different.inputs);
}

void test_input_only_generation_matches_full_workload() {
    std::array<WorkloadSpec, 4> specs = {
        WorkloadSpec{WorkloadKind::Diamond, PayloadShape::wide(16), 3, 4,
                     12345},
        WorkloadSpec{WorkloadKind::DeepSnake, PayloadShape::wide(16), 3, 4,
                     54321},
        WorkloadSpec{WorkloadKind::FanoutHeavy, PayloadShape::laned(4, 16),
                     3, 4, 999},
        WorkloadSpec{WorkloadKind::RotationHeavy, PayloadShape::wide(16), 3,
                     4, 777},
    };
    specs.front().input_count = 3;
    for (const WorkloadSpec &spec : specs) {
        CHECK(laminate::payload::make_workload_inputs(spec) ==
              laminate::payload::make_workload(spec).inputs);
    }
}

void test_all_families_compile_and_trace() {
    const std::array<WorkloadKind, 4> kinds = {
        WorkloadKind::Diamond, WorkloadKind::DeepSnake,
        WorkloadKind::FanoutHeavy, WorkloadKind::RotationHeavy};
    for (WorkloadKind kind : kinds) {
        const Workload workload = laminate::payload::make_workload(
            WorkloadSpec{kind, PayloadShape::wide(16), 3, 4, 99});
        const auto stats = laminate::payload::analyze(workload.circuit);
        CHECK(stats.ct_ct_multiplicative_depth == 3);
        CHECK(stats.alternating_multiplicative_depth == 3);
        const auto layered = laminate::payload::compile(workload.circuit);
        const auto trace = laminate::payload::synthesize_trace(
            workload.circuit, layered, workload.inputs);
        laminate::payload::validate_trace(workload.circuit, layered, trace);
        CHECK(!laminate::payload::workload_name(kind).empty());
    }
}

void test_laned_partial_and_full_utilization() {
    for (std::size_t lanes : {1U, 4U, 16U}) {
        for (WorkloadKind kind : {WorkloadKind::Diamond,
                                  WorkloadKind::DeepSnake,
                                  WorkloadKind::FanoutHeavy}) {
            const Workload workload = laminate::payload::make_workload(
                WorkloadSpec{kind, PayloadShape::laned(lanes, 16), 2, 3,
                             777});
            const auto layered = laminate::payload::compile(workload.circuit);
            (void)laminate::payload::synthesize_trace(
                workload.circuit, layered, workload.inputs);
            CHECK(workload.circuit.shape.lane_count == lanes);
        }
    }
}

void test_family_structure() {
    const Workload diamond = laminate::payload::make_workload(
        WorkloadSpec{WorkloadKind::Diamond, PayloadShape::wide(16), 2, 5,
                     1});
    const Workload fanout = laminate::payload::make_workload(
        WorkloadSpec{WorkloadKind::FanoutHeavy, PayloadShape::wide(16), 2, 5,
                     1});
    const Workload rotations = laminate::payload::make_workload(
        WorkloadSpec{WorkloadKind::RotationHeavy, PayloadShape::wide(16), 2,
                     5, 1});
    const auto diamond_stats = laminate::payload::analyze(diamond.circuit);
    const auto fanout_stats = laminate::payload::analyze(fanout.circuit);
    const auto rotation_stats = laminate::payload::analyze(rotations.circuit);
    CHECK(diamond_stats.mul_gates == 10);
    CHECK(fanout_stats.mul_gates == 10);
    CHECK(fanout_stats.add_gates > diamond_stats.add_gates);
    CHECK(rotation_stats.rotate_gates == 10);
    CHECK(rotation_stats.mul_gates == 2);
    CHECK(diamond.circuit.input_count == 5);
    CHECK(diamond.circuit.outputs.size() ==
          laminate::kBenchmarkDiamondOutputCiphertexts);
    const auto diamond_layers =
        laminate::payload::compile(diamond.circuit);
    CHECK(laminate::payload::layer_dimensions(
              diamond_layers.layers.back()).padded_size == 8);
}

void test_diamond_boundary() {
    constexpr std::size_t width =
        laminate::kBenchmarkDiamondInputCiphertexts + 1;
    const Workload wide = laminate::payload::make_workload(WorkloadSpec{
        WorkloadKind::Diamond, PayloadShape::wide(16), 8, width, 9});
    CHECK(wide.circuit.input_count ==
          laminate::kBenchmarkDiamondInputCiphertexts);
    CHECK(wide.circuit.input_count * wide.circuit.shape.value_width() ==
          laminate::kBenchmarkDiamondInputCiphertexts * 16);
    CHECK(wide.circuit.outputs.size() ==
          laminate::kBenchmarkDiamondOutputCiphertexts);
    const auto stats = laminate::payload::analyze(wide.circuit);
    CHECK(stats.ct_ct_multiplicative_depth ==
          laminate::kMaximumPayloadMultiplicativeDepth);
    CHECK(stats.mul_gates == 8 * width);
    CHECK(stats.add_plain_gates == 8 * width);
    CHECK(stats.add_gates ==
          width - laminate::kBenchmarkDiamondOutputCiphertexts);

    const auto layered = laminate::payload::compile(wide.circuit);
    CHECK(laminate::payload::layer_dimensions(layered.layers.front())
              .payload_size ==
          laminate::kBenchmarkDiamondOutputCiphertexts);
    CHECK(laminate::payload::layer_dimensions(layered.layers.back())
              .payload_size ==
          laminate::kBenchmarkDiamondInputCiphertexts);

    const Workload laned = laminate::payload::make_workload(WorkloadSpec{
        WorkloadKind::Diamond, PayloadShape::laned(4, 16), 8, width, 9});
    CHECK(laned.circuit.input_count * laned.circuit.shape.value_width() ==
          laminate::kBenchmarkDiamondInputCiphertexts * 4);

    WorkloadSpec nonuniform_spec{
        WorkloadKind::Diamond, PayloadShape::wide(16), 8, width, 9};
    nonuniform_spec.terminal_nonuniform_plaintext_multiplication = true;
    const auto nonuniform_stats = laminate::payload::analyze(
        laminate::payload::make_workload(nonuniform_spec).circuit);
    CHECK(nonuniform_stats.ct_ct_multiplicative_depth == 7);
    CHECK(nonuniform_stats.alternating_multiplicative_depth == 7);
    CHECK(nonuniform_stats.mul_gates == 7 * width);
    CHECK(nonuniform_stats.mul_plain_gates == width);
}

void test_explicit_diamond_input_count() {
    WorkloadSpec default_spec{WorkloadKind::Diamond, PayloadShape::wide(16),
                              2, 7, 31};
    const Workload implicit =
        laminate::payload::make_workload(default_spec);
    default_spec.input_count = 7;
    const Workload explicit_default =
        laminate::payload::make_workload(default_spec);
    CHECK(laminate::payload::encode_canonical(implicit.circuit) ==
          laminate::payload::encode_canonical(explicit_default.circuit));
    CHECK(implicit.inputs == explicit_default.inputs);

    for (const PayloadShape shape : {PayloadShape::wide(16),
                                     PayloadShape::laned(4, 16)}) {
        WorkloadSpec spec{WorkloadKind::Diamond, shape, 2, 7, 41};
        spec.input_count = 3;
        const Workload workload = laminate::payload::make_workload(spec);
        CHECK(workload.circuit.input_count == 3);
        CHECK(workload.inputs.size() == 3);
        for (const auto &input : workload.inputs) {
            CHECK(input.size() == shape.value_width());
        }
        const auto layered = laminate::payload::compile(workload.circuit);
        (void)laminate::payload::synthesize_trace(
            workload.circuit, layered, workload.inputs);
    }

    constexpr std::size_t above_benchmark_policy =
        laminate::kBenchmarkDiamondInputCiphertexts + 1;
    WorkloadSpec unrestricted{WorkloadKind::Diamond, PayloadShape::wide(2), 1,
                              above_benchmark_policy, 53};
    unrestricted.input_count = above_benchmark_policy;
    const Workload larger = laminate::payload::make_workload(unrestricted);
    CHECK(larger.circuit.input_count == above_benchmark_policy);
    CHECK(larger.inputs.size() == above_benchmark_policy);
}

WorkloadSpec bounded_balanced(PayloadShape shape) {
    WorkloadSpec spec{WorkloadKind::BalancedLaned, shape, 2, 64, 73};
    spec.input_count = 8;
    spec.operation_count = 256;
    spec.multiplication_widths = {64, 64};
    return spec;
}

WorkloadSpec bounded_mulheavy(PayloadShape shape) {
    WorkloadSpec spec{WorkloadKind::MulHeavyPyramid, shape, 4, 110, 73};
    spec.input_count = 8;
    spec.operation_count = 256;
    spec.multiplication_widths = {110, 58, 29, 21};
    return spec;
}

void check_fixture_structure(const WorkloadSpec &spec) {
    const auto payload = laminate::payload::make_payload_circuit(spec);
    CHECK(payload.gates.size() == *spec.operation_count);
    CHECK(payload.input_count == *spec.input_count);
    CHECK(payload.outputs.size() == 1);
    const auto stats = laminate::payload::analyze(payload);
    CHECK(stats.ct_ct_multiplicative_depth == spec.multiplicative_depth);
    CHECK(stats.alternating_multiplicative_depth ==
          spec.multiplicative_depth);
    CHECK(std::accumulate(spec.multiplication_widths.begin(),
                          spec.multiplication_widths.end(), std::size_t{0}) ==
          stats.mul_gates);
    const auto widths = multiplication_widths(payload);
    const auto layered = laminate::payload::compile(payload);
    std::vector<std::size_t> compiled_widths;
    for (std::size_t layer = layered.layers.size(); layer-- > 0;) {
        if (laminate::payload::layer_kind(layered.layers[layer]) ==
            laminate::payload::LayerKind::Multiplication) {
            compiled_widths.push_back(
                laminate::payload::layer_dimensions(layered.layers[layer])
                    .payload_size);
        }
    }
    CHECK(widths == compiled_widths);
    if (spec.kind == WorkloadKind::BalancedLaned) {
        CHECK(widths == spec.multiplication_widths);
    }
    check_all_wires_live(payload);
    check_no_repeated_expressions(payload);
    check_unique_input_affine_forms(payload);
}

void test_selected_benchmark_geometry() {
    CHECK(laminate::kBenchmarkDiamondInputCiphertexts == 64);
    CHECK(laminate::kBenchmarkPayloadOperationCount == 1'048'576);
    CHECK(laminate::benchmark_width_sum(
              laminate::kBenchmarkMulHeavyMultiplicationWidths) ==
          laminate::kBenchmarkMulHeavyMultiplicationGateCount);
    CHECK(laminate::kBenchmarkMulHeavyMultiplicationGateCount == 891'290);
    CHECK(laminate::kBenchmarkMulHeavyAdditionGateCount == 104'858);
    CHECK(laminate::kBenchmarkMulHeavyMultiplicationWidths.front() ==
          434'176);
    CHECK(laminate::kBenchmarkMulHeavyMultiplicationWidths.back() == 3'766);
}

void test_bounded_benchmark_fixtures() {
    for (const WorkloadSpec &spec : {
             bounded_balanced(PayloadShape::laned(4, 16)),
             bounded_mulheavy(PayloadShape::wide(16))}) {
        check_fixture_structure(spec);
        const Workload first = laminate::payload::make_workload(spec);
        const Workload same = laminate::payload::make_workload(spec);
        WorkloadSpec changed = spec;
        ++changed.seed;
        const Workload different = laminate::payload::make_workload(changed);
        CHECK(laminate::payload::encode_canonical(first.circuit) ==
              laminate::payload::encode_canonical(same.circuit));
        CHECK(laminate::payload::encode_canonical(first.circuit) !=
              laminate::payload::encode_canonical(different.circuit));
        CHECK(first.inputs == same.inputs);
        CHECK(first.inputs == laminate::payload::make_workload_inputs(spec));
        const auto stats = laminate::payload::analyze(first.circuit);
        if (spec.kind == WorkloadKind::BalancedLaned) {
            CHECK(stats.mul_gates == 128);
            CHECK(stats.add_gates == 115);
            CHECK(stats.add_plain_gates + stats.mul_plain_gates == 13);
            CHECK(stats.rotate_gates == 0);
        } else {
            CHECK(stats.mul_gates == 218);
            CHECK(stats.add_gates == 26);
            CHECK(stats.add_plain_gates == 0);
            CHECK(stats.mul_plain_gates == 6);
            CHECK(stats.rotate_gates == 6);
        }
        check_mock_evaluation(first);
    }
}

void test_bounded_benchmark_algebraic_distinctness() {
    for (const WorkloadSpec &spec : {
             bounded_balanced(PayloadShape::laned(4, 16)),
             bounded_mulheavy(PayloadShape::wide(16))}) {
        const Workload workload = laminate::payload::make_workload(spec);
        const auto evaluated = laminate::payload::evaluate(
            workload.circuit, workload.inputs);
        // Four or more independent seeded coordinates also expose equal
        // expressions produced by reassociation beyond the affine front end.
        // This is a regression check, not a circuit-minimality proof.
        std::map<std::vector<std::uint64_t>, std::size_t> seen;
        for (std::size_t wire = 0; wire < evaluated.wires.size(); ++wire) {
            std::vector<std::uint64_t> values;
            for (const auto value : evaluated.wires[wire]) {
                values.push_back(value.value());
            }
            const auto [previous, inserted] = seen.emplace(values, wire);
            if (!inserted) {
                throw laminate::test::CheckFailure(
                    "Equal seeded values at wires " +
                    std::to_string(previous->second) + " and " +
                    std::to_string(wire));
            }
        }
    }
}

void test_benchmark_slot_behavior() {
    for (const std::size_t lanes : {1U, 4U, 16U}) {
        const Workload workload = laminate::payload::make_workload(
            bounded_balanced(PayloadShape::laned(lanes, 16)));
        check_mock_evaluation(workload);
        for (const auto &plaintext : workload.circuit.plaintexts) {
            CHECK(std::all_of(plaintext.begin(), plaintext.end(),
                              [&](const auto value) {
                                  return value == plaintext.front();
                              }));
        }
        const auto original = laminate::payload::evaluate(
            workload.circuit, workload.inputs).output_values(workload.circuit);
        auto inputs = workload.inputs;
        inputs.front().front() += laminate::Fp::one();
        const auto changed = laminate::payload::evaluate(
            workload.circuit, inputs).output_values(workload.circuit);
        CHECK(original.front().front() != changed.front().front());
        for (std::size_t slot = 1; slot < lanes; ++slot) {
            CHECK(original.front()[slot] == changed.front()[slot]);
        }
    }

    const Workload workload = laminate::payload::make_workload(
        bounded_mulheavy(PayloadShape::wide(16)));
    for (const auto &gate : workload.circuit.gates) {
        if (gate.op == laminate::payload::GateOp::MulPlain) {
            const auto &plaintext = workload.circuit.plaintexts[gate.parameter];
            CHECK(std::any_of(plaintext.begin(), plaintext.end(),
                              [&](const auto value) {
                                  return value != plaintext.front();
                              }));
        }
    }
    const auto original = laminate::payload::evaluate(
        workload.circuit, workload.inputs).output_values(workload.circuit);
    auto inputs = workload.inputs;
    for (auto &input : inputs) {
        input.front() += laminate::Fp::one();
    }
    const auto changed = laminate::payload::evaluate(
        workload.circuit, inputs).output_values(workload.circuit);
    bool crosses_slots = false;
    for (std::size_t slot = 1; slot < 16; ++slot) {
        crosses_slots |= original.front()[slot] != changed.front()[slot];
    }
    CHECK(crosses_slots);
}

void test_selected_balanced_target() {
    WorkloadSpec spec{
        WorkloadKind::BalancedLaned, PayloadShape::laned(1, 16'384), 8,
        65'536, 1};
    spec.input_count = 64;
    spec.operation_count = 1'048'576;
    spec.multiplication_widths.assign(8, 65'536);
    check_fixture_structure(spec);
    const auto payload = laminate::payload::make_payload_circuit(spec);
    const auto stats = laminate::payload::analyze(payload);
    CHECK(stats.mul_gates == 524'288);
    CHECK(stats.add_gates == 471'859);
    CHECK(stats.add_plain_gates + stats.mul_plain_gates == 52'429);
    CHECK(stats.rotate_gates == 0);
    for (const auto &plaintext : payload.plaintexts) {
        CHECK(std::all_of(plaintext.begin(), plaintext.end(),
                          [&](const auto value) {
                              return value == plaintext.front();
                          }));
    }
    const auto layered = laminate::payload::compile(payload);
    CHECK(layered.proof_multiplication_depth == 8);
    CHECK(layered.layers.size() == 18);
}

void test_selected_mulheavy_target() {
    WorkloadSpec spec{
        WorkloadKind::MulHeavyPyramid, PayloadShape::wide(16'384), 8,
        laminate::kBenchmarkMulHeavyMultiplicationWidths.front(), 1};
    spec.input_count = 64;
    spec.operation_count = 1'048'576;
    spec.multiplication_widths = {
        laminate::kBenchmarkMulHeavyMultiplicationWidths.begin(),
        laminate::kBenchmarkMulHeavyMultiplicationWidths.end()};
    check_fixture_structure(spec);
    const auto payload = laminate::payload::make_payload_circuit(spec);
    const auto stats = laminate::payload::analyze(payload);
    CHECK(stats.mul_gates == 891'290);
    CHECK(stats.add_gates == 104'858);
    CHECK(stats.add_plain_gates == 0);
    CHECK(stats.mul_plain_gates == 26'214);
    CHECK(stats.rotate_gates == 26'214);
    const auto widths = multiplication_widths(payload);
    // Masked input pairs can move from generation stage two to CT-CT depth
    // one. Pin the compiled geometry independently of the stage quotas.
    CHECK(widths == std::vector<std::size_t>({
        434'950, 229'500, 115'134, 57'568,
        28'784, 14'392, 7'196, 3'766}));
    CHECK(std::is_sorted(widths.rbegin(), widths.rend()));
    CHECK(widths[0] + widths[1] > 2U * stats.mul_gates / 3U);
    const auto layered = laminate::payload::compile(payload);
    CHECK(layered.proof_multiplication_depth == 8);
    CHECK(layered.layers.size() == 18);
}

void test_invalid_specs_reject() {
    CHECK(throws_invalid_argument([] {
        auto spec = bounded_balanced(PayloadShape::laned(4, 16));
        spec.operation_count.reset();
        (void)laminate::payload::make_payload_circuit(spec);
    }));
    CHECK(throws_invalid_argument([] {
        auto spec = bounded_balanced(PayloadShape::laned(4, 16));
        --spec.multiplication_widths.back();
        (void)laminate::payload::make_payload_circuit(spec);
    }));
    CHECK(throws_invalid_argument([] {
        const auto spec = bounded_mulheavy(PayloadShape::laned(4, 16));
        (void)laminate::payload::make_payload_circuit(spec);
    }));
    CHECK(throws_invalid_argument([] {
        (void)laminate::payload::make_workload(WorkloadSpec{
            WorkloadKind::Diamond, PayloadShape::wide(8), 2, 0, 1});
    }));
    CHECK(throws_invalid_argument([] {
        (void)laminate::payload::make_workload(WorkloadSpec{
            WorkloadKind::RotationHeavy, PayloadShape::laned(4, 8), 2, 2,
            1});
    }));
    CHECK(throws_invalid_argument([] {
        (void)laminate::payload::make_workload(WorkloadSpec{
            WorkloadKind::Diamond, PayloadShape::wide(8), 9, 2, 1});
    }));
    CHECK(throws_invalid_argument([] {
        WorkloadSpec spec{WorkloadKind::Diamond, PayloadShape::wide(8), 2, 4,
                          1};
        spec.input_count = 0;
        (void)laminate::payload::make_workload(spec);
    }));
    CHECK(throws_invalid_argument([] {
        WorkloadSpec spec{WorkloadKind::MulHeavyPyramid,
                          PayloadShape::wide(8), 4, 120, 1};
        spec.input_count = 8;
        (void)laminate::payload::make_workload(spec);
    }));
    CHECK(throws_invalid_argument([] {
        WorkloadSpec spec{WorkloadKind::MulHeavyPyramid,
                          PayloadShape::wide(8), 4, 105, 1};
        spec.input_count = 8;
        spec.operation_count = 256;
        spec.multiplication_widths = {106, 63, 38, 23};
        (void)laminate::payload::make_workload(spec);
    }));
    CHECK(throws_invalid_argument([] {
        WorkloadSpec spec{WorkloadKind::MulHeavyPyramid,
                          PayloadShape::wide(8), 4, 106, 1};
        spec.input_count = 8;
        spec.operation_count = 256;
        spec.multiplication_widths = {106, 63, 38, 22};
        (void)laminate::payload::make_workload(spec);
    }));
    CHECK(throws_invalid_argument([] {
        WorkloadSpec spec{WorkloadKind::MulHeavyPyramid,
                          PayloadShape::wide(8), 4, 110, 1};
        spec.input_count = 8;
        spec.operation_count = 256;
        spec.multiplication_widths = {110, 50, 40, 30};
        (void)laminate::payload::make_workload(spec);
    }));
    CHECK(throws_invalid_argument([] {
        WorkloadSpec spec{WorkloadKind::Diamond,
                          PayloadShape::wide(8), 2, 4, 1};
        spec.operation_count = 32;
        (void)laminate::payload::make_workload(spec);
    }));
    CHECK(throws_invalid_argument([] {
        WorkloadSpec spec{WorkloadKind::Diamond, PayloadShape::wide(8), 2, 4,
                          1};
        spec.input_count = 5;
        (void)laminate::payload::make_workload(spec);
    }));
    CHECK(throws_invalid_argument([] {
        WorkloadSpec spec{WorkloadKind::DeepSnake, PayloadShape::wide(8), 2, 4,
                          1};
        spec.input_count = 2;
        (void)laminate::payload::make_workload(spec);
    }));
    CHECK(throws_invalid_argument([] {
        WorkloadSpec spec{WorkloadKind::Diamond,
                          PayloadShape::laned(4, 8), 2, 4, 1};
        spec.terminal_nonuniform_plaintext_multiplication = true;
        (void)laminate::payload::make_workload(spec);
    }));
}

} // namespace

int main() {
    laminate::test::Runner runner("test_workloads");
    runner.run("workload determinism and seed sensitivity",
               test_determinism_and_seed_sensitivity);
    runner.run("input-only generation matches the full workload",
               test_input_only_generation_matches_full_workload);
    runner.run("all workload families compile and trace",
               test_all_families_compile_and_trace);
    runner.run("laned partial and full utilization",
               test_laned_partial_and_full_utilization);
    runner.run("workload family structure", test_family_structure);
    runner.run("diamond input, middle, and output boundary",
               test_diamond_boundary);
    runner.run("explicit Diamond input count",
               test_explicit_diamond_input_count);
    runner.run("selected benchmark geometry is exact",
               test_selected_benchmark_geometry);
    runner.run("bounded benchmark fixtures are exact, live, and deterministic",
               test_bounded_benchmark_fixtures);
    runner.run("bounded benchmark algebraic expressions are distinct",
               test_bounded_benchmark_algebraic_distinctness);
    runner.run("balancedLaned independent lanes and mulHeavyPyramid "
               "cross-slot behavior",
               test_benchmark_slot_behavior);
    runner.run("selected balancedLaned target has no repeated expressions",
               test_selected_balanced_target);
    runner.run("selected mulHeavyPyramid target has no repeated expressions",
               test_selected_mulheavy_target);
    runner.run("invalid workload specs reject", test_invalid_specs_reject);
    return runner.summary();
}
