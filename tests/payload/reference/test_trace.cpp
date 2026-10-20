#include "test_helpers.hpp"

#include "laminate/payload/compiler.hpp"
#include "laminate/payload/trace.hpp"

#include <cstddef>
#include <stdexcept>
#include <vector>

namespace {

using laminate::Fp;
using laminate::fhe::SlotVector;
using laminate::payload::LayeredCircuit;
using laminate::payload::PayloadBuilder;
using laminate::payload::PayloadCircuit;
using laminate::payload::PayloadShape;
using laminate::payload::PlainTrace;

bool throws_invalid_argument(const auto &body) {
    try {
        body();
    } catch (const std::invalid_argument &) {
        return true;
    }
    return false;
}

SlotVector sequence(std::size_t size, std::size_t offset) {
    SlotVector result;
    result.reserve(size);
    for (std::size_t index = 0; index < size; ++index) {
        result.emplace_back(offset + index);
    }
    return result;
}

PayloadCircuit make_wide_payload() {
    PayloadBuilder builder(PayloadShape::wide(8), 2);
    const std::size_t mask = builder.add_plaintext(
        {Fp(2), Fp(3), Fp(5), Fp(7), Fp(11), Fp(13), Fp(17), Fp(19)});
    const std::size_t bias = builder.add_plaintext(
        {Fp(1), Fp(4), Fp(9), Fp(16), Fp(25), Fp(36), Fp(49), Fp(64)});
    const auto sum = builder.add(0, 1);
    const auto masked = builder.mul_plain(sum, mask);
    const auto rotated = builder.rotate(masked, 3);
    const auto product = builder.mul(rotated, 0);
    const auto output = builder.add_plain(product, bias);
    builder.set_outputs({output, masked});
    return builder.finish();
}

PayloadCircuit make_laned_payload() {
    PayloadBuilder builder(PayloadShape::laned(4, 16), 2);
    const std::size_t three = builder.add_scalar_plaintext(Fp(3));
    const auto first = builder.mul(0, 1);
    const auto mixed = builder.add(first, 0);
    const auto second = builder.mul(mixed, first);
    const auto output = builder.add_plain(second, three);
    builder.set_outputs({output});
    return builder.finish();
}

void test_wide_synthetic_trace() {
    const PayloadCircuit payload = make_wide_payload();
    const LayeredCircuit layered = laminate::payload::compile(payload);
    const std::vector<SlotVector> inputs{sequence(8, 1), sequence(8, 21)};
    const PlainTrace trace =
        laminate::payload::synthesize_trace(payload, layered, inputs);

    CHECK(laminate::payload::provenance_name(trace.provenance) ==
          "synthetic-trace");
    CHECK(trace.layers.size() == layered.layers.size());
    CHECK(trace.layers.front()[0] == trace.payload_outputs[0]);
    CHECK(trace.layers.front()[1] == trace.payload_outputs[1]);
    laminate::payload::validate_trace(payload, layered, trace);
}

void test_laned_dense_trace() {
    const PayloadCircuit payload = make_laned_payload();
    const LayeredCircuit layered = laminate::payload::compile(payload);
    const std::vector<SlotVector> inputs{sequence(4, 2), sequence(4, 10)};
    const PlainTrace trace =
        laminate::payload::synthesize_trace(payload, layered, inputs);
    CHECK(trace.shape.value_width() == 4);
    CHECK(trace.layers.size() == 6);
    laminate::payload::validate_trace(payload, layered, trace);
}

void test_single_lane_does_not_invent_a_rotation() {
    PayloadBuilder builder(PayloadShape::laned(1, 8), 1);
    const std::size_t five = builder.add_scalar_plaintext(Fp(5));
    const auto output = builder.mul_plain(0, five);
    builder.set_outputs({output});
    const PayloadCircuit payload = builder.finish();
    const LayeredCircuit layered = laminate::payload::compile(payload);
    const PlainTrace trace = laminate::payload::synthesize_trace(
        payload, layered, std::vector<SlotVector>{{Fp(9)}});
    CHECK(trace.payload_outputs[0] == SlotVector{Fp(45)});
}

void test_tampered_layer_rejects() {
    const PayloadCircuit payload = make_wide_payload();
    const LayeredCircuit layered = laminate::payload::compile(payload);
    const std::vector<SlotVector> inputs{sequence(8, 1), sequence(8, 21)};
    PlainTrace trace =
        laminate::payload::synthesize_trace(payload, layered, inputs);
    trace.layers[2][0][3] += Fp::one();
    CHECK(throws_invalid_argument(
        [&] { laminate::payload::validate_trace(payload, layered, trace); }));
}

void test_tampered_payload_or_input_rejects() {
    const PayloadCircuit payload = make_laned_payload();
    const LayeredCircuit layered = laminate::payload::compile(payload);
    const std::vector<SlotVector> inputs{sequence(4, 2), sequence(4, 10)};
    PlainTrace trace =
        laminate::payload::synthesize_trace(payload, layered, inputs);
    trace.payload_outputs[0][0] += Fp::one();
    CHECK(throws_invalid_argument(
        [&] { laminate::payload::validate_trace(payload, layered, trace); }));

    trace = laminate::payload::synthesize_trace(payload, layered, inputs);
    trace.layers.back()[0][0] += Fp::one();
    CHECK(throws_invalid_argument(
        [&] { laminate::payload::validate_trace(payload, layered, trace); }));
}

void test_wrong_width_rejects() {
    const PayloadCircuit payload = make_wide_payload();
    const LayeredCircuit layered = laminate::payload::compile(payload);
    CHECK(throws_invalid_argument([&] {
        (void)laminate::payload::synthesize_trace(
            payload, layered,
            std::vector<SlotVector>{SlotVector(8, Fp::one()),
                                    SlotVector(4, Fp::one())});
    }));
}

} // namespace

int main() {
    laminate::test::Runner runner("test_trace");
    runner.run("wide synthetic trace", test_wide_synthetic_trace);
    runner.run("laned dense trace", test_laned_dense_trace);
    runner.run("single-lane affine trace",
               test_single_lane_does_not_invent_a_rotation);
    runner.run("tampered alternating layer rejects",
               test_tampered_layer_rejects);
    runner.run("tampered payload output or input rejects",
               test_tampered_payload_or_input_rejects);
    runner.run("wrong input width rejects", test_wrong_width_rejects);
    return runner.summary();
}
