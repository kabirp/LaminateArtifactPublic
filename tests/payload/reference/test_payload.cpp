#include "test_helpers.hpp"

#include "laminate/payload/circuit.hpp"
#include "laminate/payload/compiler.hpp"
#include "laminate/payload/evaluator.hpp"

#include <cstddef>
#include <stdexcept>
#include <vector>

namespace {

using laminate::Fp;
using laminate::fhe::SlotVector;
using laminate::payload::Gate;
using laminate::payload::GateOp;
using laminate::payload::PayloadBuilder;
using laminate::payload::PayloadCircuit;
using laminate::payload::PayloadKind;
using laminate::payload::PayloadShape;

bool throws_invalid_argument(const auto &body) {
    try {
        body();
    } catch (const std::invalid_argument &) {
        return true;
    }
    return false;
}

SlotVector sequence(std::size_t size, std::size_t offset = 0) {
    SlotVector result;
    result.reserve(size);
    for (std::size_t index = 0; index < size; ++index) {
        result.emplace_back(offset + index);
    }
    return result;
}

void test_shape_validation() {
    CHECK(PayloadShape::laned(1, 16).value_width() == 1);
    CHECK(PayloadShape::laned(4, 16).value_width() == 4);
    CHECK(PayloadShape::wide(16).value_width() == 16);
    CHECK(throws_invalid_argument([] { (void)PayloadShape::laned(3, 16); }));
    CHECK(throws_invalid_argument([] { (void)PayloadShape::laned(32, 16); }));
    CHECK(throws_invalid_argument([] { (void)PayloadShape::wide(12); }));
}

void test_unknown_payload_kind_rejects() {
    const PayloadShape shape{static_cast<PayloadKind>(255), 8, 0};
    CHECK(throws_invalid_argument([&] { shape.validate(); }));
    CHECK(throws_invalid_argument([&] { PayloadBuilder builder(shape, 1); }));

    PayloadCircuit circuit;
    circuit.shape = shape;
    circuit.input_count = 1;
    circuit.gates = {Gate{GateOp::Add, 0, 0, 0}};
    circuit.outputs = {1};
    const std::vector<SlotVector> inputs{sequence(8, 1)};
    CHECK(throws_invalid_argument([&] { circuit.validate(); }));
    CHECK(throws_invalid_argument(
        [&] { (void)laminate::payload::evaluate(circuit, inputs); }));
    CHECK(throws_invalid_argument(
        [&] { (void)laminate::payload::analyze(circuit); }));
    CHECK(throws_invalid_argument(
        [&] { (void)laminate::payload::compile(circuit); }));
}

void test_unknown_gate_operation_rejects() {
    for (const PayloadShape shape :
         {PayloadShape::wide(8), PayloadShape::laned(4, 8)}) {
        PayloadBuilder builder(shape, 1);
        builder.set_outputs({builder.add(0, 0)});
        PayloadCircuit circuit = builder.finish();
        circuit.gates.front().op = static_cast<GateOp>(255);
        const std::vector<SlotVector> inputs{sequence(shape.value_width(), 1)};

        CHECK(throws_invalid_argument([&] { circuit.validate(); }));
        CHECK(throws_invalid_argument(
            [&] { (void)laminate::payload::evaluate(circuit, inputs); }));
        CHECK(throws_invalid_argument(
            [&] { (void)laminate::payload::analyze(circuit); }));
        CHECK(throws_invalid_argument(
            [&] { (void)laminate::payload::compile(circuit); }));
    }
}

void test_laned_builder_and_evaluation() {
    PayloadBuilder builder(PayloadShape::laned(4, 16), 2);
    const std::size_t three = builder.add_scalar_plaintext(Fp(3));
    const std::size_t two = builder.add_scalar_plaintext(Fp(2));
    const auto product = builder.mul(0, 1);
    const auto translated = builder.add_plain(product, three);
    const auto output = builder.mul_plain(translated, two);
    builder.set_outputs({output, product});
    const PayloadCircuit circuit = builder.finish();

    const std::vector<SlotVector> inputs{sequence(4, 1), sequence(4, 5)};
    const auto evaluation = laminate::payload::evaluate(circuit, inputs);
    CHECK(evaluation.wires.size() == circuit.wire_count());
    const auto outputs = evaluation.output_values(circuit);
    CHECK(outputs.size() == 2);
    for (std::size_t lane = 0; lane < 4; ++lane) {
        const Fp expected_product = inputs[0][lane] * inputs[1][lane];
        CHECK(outputs[0][lane] == (expected_product + Fp(3)) * Fp(2));
        CHECK(outputs[1][lane] == expected_product);
    }

    const auto stats = laminate::payload::analyze(circuit);
    CHECK(stats.mul_gates == 1);
    CHECK(stats.add_plain_gates == 1);
    CHECK(stats.mul_plain_gates == 1);
    CHECK(stats.ct_ct_multiplicative_depth == 1);
    CHECK(stats.fhe_half_depth == 3);
    CHECK(stats.alternating_multiplicative_depth == 1);
}

void test_laned_plaintext_and_rotation_boundary() {
    PayloadBuilder builder(PayloadShape::laned(4, 16), 1);
    const SlotVector mask{Fp(2), Fp(3), Fp(5), Fp(7)};
    const std::size_t mask_id = builder.add_plaintext(mask);
    CHECK(throws_invalid_argument(
        [&] { (void)builder.mul_plain(0, mask_id); }));

    // Lane-varying public constants remain valid for addition.
    const auto shifted = builder.add_plain(0, mask_id);
    builder.set_outputs({shifted});
    const PayloadCircuit circuit = builder.finish();
    const SlotVector input = sequence(4, 2);
    const auto output = laminate::payload::evaluate(
                            circuit, std::vector<SlotVector>{input})
                            .output_values(circuit)
                            .front();
    for (std::size_t lane = 0; lane < input.size(); ++lane) {
        CHECK(output[lane] == input[lane] + mask[lane]);
    }

    // Validation is a second, durable boundary for circuits not produced by
    // the builder. Compilation revalidates the same payload language.
    PayloadBuilder scalar_builder(PayloadShape::laned(4, 16), 1);
    const std::size_t scalar =
        scalar_builder.add_scalar_plaintext(Fp(2));
    scalar_builder.set_outputs({scalar_builder.mul_plain(0, scalar)});
    PayloadCircuit malformed_plaintext = scalar_builder.finish();
    malformed_plaintext.plaintexts[scalar] = mask;
    CHECK(throws_invalid_argument(
        [&] { malformed_plaintext.validate(); }));
    CHECK(throws_invalid_argument(
        [&] { (void)laminate::payload::compile(malformed_plaintext); }));

    PayloadBuilder rotation_builder(PayloadShape::laned(4, 16), 1);
    CHECK(throws_invalid_argument(
        [&] { (void)rotation_builder.rotate(0, 1); }));

    PayloadCircuit malformed_rotation;
    malformed_rotation.shape = PayloadShape::laned(4, 16);
    malformed_rotation.input_count = 1;
    malformed_rotation.gates = {Gate{
        GateOp::Rotate, 0, laminate::payload::kNoWire, 1}};
    malformed_rotation.outputs = {1};
    CHECK(throws_invalid_argument(
        [&] { malformed_rotation.validate(); }));
    CHECK(throws_invalid_argument(
        [&] { (void)laminate::payload::compile(malformed_rotation); }));
}

void test_wide_grid_evaluation() {
    PayloadBuilder builder(PayloadShape::wide(8), 1);
    const SlotVector mask{Fp(1), Fp(2), Fp(3), Fp(4),
                          Fp(5), Fp(6), Fp(7), Fp(8)};
    const std::size_t mask_id = builder.add_plaintext(mask);
    const auto masked = builder.mul_plain(0, mask_id);
    const auto rotated = builder.rotate(masked, 3);
    const auto output = builder.mul(0, rotated);
    builder.set_outputs({output});
    const PayloadCircuit circuit = builder.finish();

    const SlotVector input = sequence(8, 2);
    const auto evaluation =
        laminate::payload::evaluate(circuit,
                                    std::vector<SlotVector>{input});
    SlotVector masked_plain(8);
    for (std::size_t slot = 0; slot < 8; ++slot) {
        masked_plain[slot] = input[slot] * mask[slot];
    }
    const SlotVector rotated_plain =
        laminate::fhe::grid_rotate(masked_plain, 3);
    const SlotVector output_value = evaluation.output_values(circuit).front();
    for (std::size_t slot = 0; slot < 8; ++slot) {
        CHECK(output_value[slot] == input[slot] * rotated_plain[slot]);
    }

    const auto stats = laminate::payload::analyze(circuit);
    CHECK(stats.mul_plain_gates == 1);
    CHECK(stats.rotate_gates == 1);
    CHECK(stats.mul_gates == 1);
    CHECK(stats.ct_ct_multiplicative_depth == 1);
    CHECK(stats.fhe_half_depth == 4);
    CHECK(stats.alternating_multiplicative_depth == 1);
}

void test_bad_topology_and_inputs_reject() {
    PayloadCircuit bad;
    bad.shape = PayloadShape::wide(8);
    bad.input_count = 1;
    bad.gates = {Gate{GateOp::Add, 0, 2, 0}};
    bad.outputs = {1};
    CHECK(throws_invalid_argument([&] { bad.validate(); }));

    PayloadBuilder builder(PayloadShape::wide(8), 1);
    const auto output = builder.add(0, 0);
    builder.set_outputs({output});
    const PayloadCircuit good = builder.finish();
    CHECK(throws_invalid_argument([&] {
        (void)laminate::payload::evaluate(good, std::vector<SlotVector>{});
    }));
    CHECK(throws_invalid_argument([&] {
        (void)laminate::payload::evaluate(
            good, std::vector<SlotVector>{SlotVector(4, Fp::one())});
    }));
}

void test_builder_rejects_future_wires_and_duplicate_outputs() {
    PayloadBuilder builder(PayloadShape::wide(8), 1);
    CHECK(throws_invalid_argument([&] { (void)builder.add(0, 1); }));
    const auto output = builder.add(0, 0);
    builder.set_outputs({output, output});
    CHECK(throws_invalid_argument([&] { (void)builder.finish(); }));
}

} // namespace

int main() {
    laminate::test::Runner runner("test_payload");
    runner.run("shape validation", test_shape_validation);
    runner.run("unknown payload kind rejects",
               test_unknown_payload_kind_rejects);
    runner.run("unknown gate operation rejects",
               test_unknown_gate_operation_rejects);
    runner.run("laned builder and evaluation",
               test_laned_builder_and_evaluation);
    runner.run("laned plaintext and rotation boundary",
               test_laned_plaintext_and_rotation_boundary);
    runner.run("wide evaluation uses grid rotations",
               test_wide_grid_evaluation);
    runner.run("bad topology and inputs reject",
               test_bad_topology_and_inputs_reject);
    runner.run("builder reference and output checks",
               test_builder_rejects_future_wires_and_duplicate_outputs);
    return runner.summary();
}
