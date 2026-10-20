#include "test_helpers.hpp"

#include "laminate/payload/compiler.hpp"
#include "laminate/payload/evaluator.hpp"
#include "laminate/payload/setup/encoding.hpp"
#include "laminate/payload/trace.hpp"

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace {

using laminate::Fp;
using laminate::fhe::SlotVector;
using laminate::payload::AffineLayer;
using laminate::payload::GateOrigin;
using laminate::payload::InputLayer;
using laminate::payload::LayerKind;
using laminate::payload::LayeredCircuit;
using laminate::payload::MultiplicationLayer;
using laminate::payload::PayloadBuilder;
using laminate::payload::PayloadShape;

bool throws_invalid_argument(const auto &body) {
    try {
        body();
    } catch (const std::invalid_argument &) {
        return true;
    }
    return false;
}

void test_affine_only_circuit() {
    PayloadBuilder builder(PayloadShape::wide(8), 2);
    const std::size_t seven = builder.add_scalar_plaintext(Fp(7));
    const auto sum = builder.add(0, 1);
    const auto scaled = builder.mul_plain(sum, seven);
    const auto output = builder.rotate(scaled, 5);
    builder.set_outputs({output});

    const LayeredCircuit layered = laminate::payload::compile(builder.finish());
    CHECK(layered.proof_multiplication_depth == 0);
    CHECK(layered.layers.size() == 2);
    CHECK(laminate::payload::layer_kind(layered.layers[0]) ==
          LayerKind::Affine);
    CHECK(laminate::payload::layer_kind(layered.layers[1]) ==
          LayerKind::Input);
    const auto &output_layer = std::get<AffineLayer>(layered.layers[0]);
    CHECK(output_layer.dimensions.logical_size == 1);
    CHECK(output_layer.intermediate_gates.size() == 3);
    CHECK(output_layer.intermediate_gates[0].terms.size() == 2);
    CHECK(output_layer.intermediate_gates[1].terms[0].coefficient == Fp(7));
    CHECK(output_layer.intermediate_gates[2].terms[0].rotation == 5);
    CHECK(output_layer.gates[0].terms.size() == 1);
}

void test_wide_dense_halves_and_plain_multiplication() {
    PayloadBuilder builder(PayloadShape::wide(8), 2);
    const SlotVector mask_values{
        Fp(1), Fp(2), Fp(3), Fp(4), Fp(5), Fp(6), Fp(7), Fp(8)};
    const std::size_t mask = builder.add_plaintext(mask_values);
    const auto sum = builder.add(0, 1);
    const auto masked = builder.mul_plain(sum, mask);
    const auto squared = builder.mul(sum, sum);
    builder.set_outputs({masked, squared});

    const LayeredCircuit layered = laminate::payload::compile(builder.finish());
    CHECK(layered.proof_multiplication_depth == 1);
    CHECK(layered.layers.size() == 4);
    const auto &products = std::get<MultiplicationLayer>(layered.layers[1]);
    const auto &operands = std::get<AffineLayer>(layered.layers[2]);
    CHECK(products.dimensions.logical_size == 3);
    CHECK(products.dimensions.payload_size == 1);
    CHECK(products.dimensions.forward_size == 2);
    CHECK(operands.dimensions.logical_size == 6);
    CHECK(operands.dimensions.padded_size == 8);
    CHECK(operands.intermediate_gates.size() == 1);
    CHECK(operands.intermediate_gates[0].terms.size() == 2);
    CHECK(operands.gates[0].terms == operands.gates[4].terms);
    const auto &output = std::get<AffineLayer>(layered.layers.front());
    CHECK(output.intermediate_gates.size() == 2);
    CHECK(output.intermediate_gates[1].terms[0].plaintext_index == mask);
}

void test_rotation_composes_in_grid_group() {
    PayloadBuilder builder(PayloadShape::wide(8), 1);
    const auto first = builder.rotate(0, 3);
    const auto second = builder.rotate(first, 3);
    const auto output = builder.mul(second, 0);
    builder.set_outputs({output});

    const auto payload = builder.finish();
    const LayeredCircuit layered = laminate::payload::compile(payload);
    const auto &operands = std::get<AffineLayer>(layered.layers[2]);
    CHECK(operands.intermediate_gates.size() == 2);
    CHECK(operands.intermediate_gates[0].terms[0].rotation == 3);
    CHECK(operands.intermediate_gates[1].terms[0].rotation == 3);
    const SlotVector input{Fp(1), Fp(2), Fp(3), Fp(4),
                           Fp(5), Fp(6), Fp(7), Fp(8)};
    const auto rotated = laminate::fhe::grid_rotate(input, 2);
    const auto trace = laminate::payload::synthesize_trace(
        payload, layered, std::vector<SlotVector>{input});
    for (std::size_t slot = 0; slot < input.size(); ++slot) {
        CHECK(trace.payload_outputs[0][slot] == input[slot] * rotated[slot]);
    }
}

void test_laned_dense_forwarding() {
    PayloadBuilder builder(PayloadShape::laned(4, 16), 2);
    const auto first_product = builder.mul(0, 1);
    const auto sum = builder.add(first_product, 0);
    const auto second_product = builder.mul(sum, first_product);
    builder.set_outputs({second_product});

    const LayeredCircuit layered = laminate::payload::compile(builder.finish());
    CHECK(layered.proof_multiplication_depth == 2);
    CHECK(layered.layers.size() == 6);

    const auto &top_products =
        std::get<MultiplicationLayer>(layered.layers[1]);
    CHECK(top_products.dimensions.logical_size == 1);
    CHECK(top_products.dimensions.payload_size == 1);
    CHECK(top_products.dimensions.forward_size == 0);

    const auto &bottom_products =
        std::get<MultiplicationLayer>(layered.layers[3]);
    const auto &bottom_operands = std::get<AffineLayer>(layered.layers[4]);
    CHECK(bottom_products.dimensions.logical_size == 2);
    CHECK(bottom_products.dimensions.payload_size == 1);
    CHECK(bottom_products.dimensions.forward_size == 1);
    CHECK(bottom_operands.dimensions.logical_size == 4);
    CHECK(bottom_operands.dimensions.payload_size == 2);
    CHECK(bottom_operands.dimensions.forward_size == 2);

    CHECK(bottom_products.gates[0].origin == GateOrigin::Payload);
    CHECK(bottom_products.gates[1].origin == GateOrigin::Forward);
}

void test_laned_plain_multiplier_is_uniform_and_affine() {
    PayloadBuilder builder(PayloadShape::laned(4, 16), 1);
    const std::size_t plaintext =
        builder.add_scalar_plaintext(Fp(7));
    builder.set_outputs({builder.mul_plain(0, plaintext)});

    const LayeredCircuit layered = laminate::payload::compile(builder.finish());
    CHECK(layered.proof_multiplication_depth == 0);
    const auto &output = std::get<AffineLayer>(layered.layers.front());
    CHECK(output.gates.front().terms.size() == 1);
    CHECK(output.gates.front().terms.front().coefficient == Fp(7));

    // Restored layered artifacts are validated independently of the source
    // DAG, so they must not bypass the Laned payload-language restriction.
    PayloadBuilder product_builder(PayloadShape::laned(4, 16), 1);
    product_builder.set_outputs({product_builder.mul(0, 0)});
    LayeredCircuit malformed =
        laminate::payload::compile(product_builder.finish());
    const SlotVector mask{Fp(2), Fp(3), Fp(5), Fp(7)};
    malformed.plaintexts.push_back(mask);
    auto &operands = std::get<AffineLayer>(malformed.layers[2]);
    operands.gates[0].terms[0].plaintext_index = 0;
    CHECK(throws_invalid_argument([&] { malformed.validate(); }));
}

void test_wide_forwarding_and_padding_are_separate() {
    PayloadBuilder builder(PayloadShape::wide(8), 1);
    const auto first = builder.mul(0, 0);
    const auto second = builder.mul(first, first);
    const auto output = builder.add(second, 0);
    builder.set_outputs({output});

    const LayeredCircuit layered = laminate::payload::compile(builder.finish());
    const auto &top_products =
        std::get<MultiplicationLayer>(layered.layers[1]);
    const auto &bottom_products =
        std::get<MultiplicationLayer>(layered.layers[3]);
    CHECK(top_products.dimensions.payload_size == 1);
    CHECK(top_products.dimensions.forward_size == 1);
    CHECK(top_products.dimensions.padding_size() == 0);
    CHECK(bottom_products.dimensions.payload_size == 1);
    CHECK(bottom_products.dimensions.forward_size == 1);
    CHECK(bottom_products.gates[1].origin == GateOrigin::Forward);
    const auto &bottom_operands =
        std::get<AffineLayer>(layered.layers[4]);
    const std::size_t forwarded_right =
        bottom_products.dimensions.padded_size + 1U;
    CHECK(bottom_operands.gates[forwarded_right].terms.empty());
    CHECK(laminate::payload::materialize(
              bottom_operands.gates[forwarded_right].constant, 8) ==
          laminate::fhe::SlotVector(8, Fp::one()));
}

void test_power_of_two_padding_and_validation() {
    PayloadBuilder builder(PayloadShape::wide(8), 1);
    const auto a = builder.mul(0, 0);
    const auto b = builder.mul(0, 0);
    const auto c = builder.mul(0, 0);
    builder.set_outputs({a, b, c});
    LayeredCircuit layered = laminate::payload::compile(builder.finish());

    const auto &products = std::get<MultiplicationLayer>(layered.layers[1]);
    CHECK(products.dimensions.logical_size == 3);
    CHECK(products.dimensions.padded_size == 4);
    CHECK(products.dimensions.padding_size() == 1);
    CHECK(products.gates.back().origin == GateOrigin::Padding);
    CHECK(std::get<AffineLayer>(layered.layers[0]).dimensions.padded_size == 4);
    CHECK(std::get<InputLayer>(layered.layers.back())
              .dimensions.padded_size == 1);

    std::get<MultiplicationLayer>(layered.layers[1]).gates[0].origin =
        GateOrigin::Padding;
    CHECK(throws_invalid_argument([&] { layered.validate(); }));
}

void test_exact_contraction_reorders_independent_products() {
    PayloadBuilder builder(PayloadShape::wide(8), 8);
    const auto a = builder.mul(0, 1);
    const auto b = builder.mul(2, 3);
    const auto c = builder.mul(4, 5);
    const auto d = builder.mul(6, 7);
    const auto x = builder.mul(d, a);
    const auto y = builder.mul(b, c);
    builder.set_outputs({x, y});
    const auto payload = builder.finish();

    const LayeredCircuit first = laminate::payload::compile(payload);
    const LayeredCircuit same = laminate::payload::compile(payload);
    CHECK(laminate::payload::encode_canonical(first) ==
          laminate::payload::encode_canonical(same));
    laminate::payload::validate_compilation_pair(payload, first);

    std::vector<SlotVector> inputs(8, SlotVector(8));
    for (std::size_t input = 0; input < inputs.size(); ++input) {
        for (std::size_t slot = 0; slot < inputs[input].size(); ++slot) {
            inputs[input][slot] = Fp(1U + input * inputs[input].size() + slot);
        }
    }
    const auto direct = laminate::payload::evaluate(payload, inputs);
    const auto trace = laminate::payload::synthesize_trace(
        payload, first, inputs);
    CHECK(trace.payload_outputs == direct.output_values(payload));
    CHECK(trace.layers.front() == trace.payload_outputs);

    const auto &contraction = std::get<AffineLayer>(first.layers[2]);
    CHECK(contraction.dimensions.logical_size == 4);
    for (std::size_t gate = 0; gate < 4; ++gate) {
        CHECK(contraction.gates[gate].terms.size() == 1);
        CHECK(contraction.gates[gate].terms.front().source == gate);
        CHECK(contraction.gates[gate].terms.front().rotation == 0);
        CHECK(contraction.gates[gate].terms.front().coefficient == Fp::one());
        CHECK(contraction.gates[gate].constant ==
              laminate::payload::AffineConstant(Fp::zero()));
    }

    // The prior products have been relabeled from payload order a,b,c,d to
    // the contraction's dense left-then-right use order d,b,a,c.
    const auto &first_operands = std::get<AffineLayer>(first.layers[4]);
    const std::vector<std::size_t> expected_left{6, 2, 0, 4};
    const std::vector<std::size_t> expected_right{7, 3, 1, 5};
    for (std::size_t gate = 0; gate < expected_left.size(); ++gate) {
        CHECK(first_operands.gates[gate].terms.front().source ==
              expected_left[gate]);
        CHECK(first_operands.gates[4 + gate].terms.front().source ==
              expected_right[gate]);
    }
}

void test_ineligible_contraction_keeps_payload_order() {
    PayloadBuilder builder(PayloadShape::wide(8), 8);
    const auto a = builder.mul(0, 1);
    const auto b = builder.mul(2, 3);
    (void)builder.mul(4, 5);
    const auto d = builder.mul(6, 7);
    const auto x = builder.mul(d, a);
    const auto y = builder.mul(b, b);
    builder.set_outputs({x, y});

    const LayeredCircuit layered = laminate::payload::compile(builder.finish());
    const auto &contraction = std::get<AffineLayer>(layered.layers[2]);
    const std::vector<std::size_t> expected_sources{3, 1, 0, 1};
    for (std::size_t gate = 0; gate < expected_sources.size(); ++gate) {
        CHECK(contraction.gates[gate].terms.size() == 1);
        CHECK(contraction.gates[gate].terms.front().source ==
              expected_sources[gate]);
    }

    const auto &first_operands = std::get<AffineLayer>(layered.layers[4]);
    const std::vector<std::size_t> expected_left{0, 2, 4, 6};
    const std::vector<std::size_t> expected_right{1, 3, 5, 7};
    for (std::size_t gate = 0; gate < expected_left.size(); ++gate) {
        CHECK(first_operands.gates[gate].terms.front().source ==
              expected_left[gate]);
        CHECK(first_operands.gates[4 + gate].terms.front().source ==
              expected_right[gate]);
    }
}

void test_wide_plaintext_rotation_dag_and_encoding() {
    PayloadBuilder builder(PayloadShape::wide(8), 1);
    const std::size_t mask = builder.add_plaintext(
        {Fp(2), Fp(3), Fp(5), Fp(7), Fp(11), Fp(13), Fp(17), Fp(19)});
    const auto multiplied = builder.mul_plain(0, mask);
    const auto rotated_product = builder.rotate(multiplied, 5);
    const auto rotated_input = builder.rotate(0, 5);
    const auto product_of_rotation = builder.mul_plain(rotated_input, mask);
    const auto with_bias = builder.add_plain(rotated_product, mask);
    builder.set_outputs({rotated_product, product_of_rotation, with_bias});
    const auto payload = builder.finish();
    const auto layered = laminate::payload::compile(payload);
    CHECK(layered.proof_multiplication_depth == 0);
    const auto &affine = std::get<AffineLayer>(layered.layers[0]);
    CHECK(affine.intermediate_gates.size() == 5);
    const std::vector<SlotVector> inputs{
        {Fp(1), Fp(2), Fp(3), Fp(4), Fp(5), Fp(6), Fp(7), Fp(8)}};
    const auto trace = laminate::payload::synthesize_trace(payload, layered, inputs);
    const auto expected = laminate::payload::evaluate(payload, inputs).output_values(payload);
    CHECK(trace.payload_outputs == expected);
    CHECK(expected[0] != expected[1]);
    const auto encoded = laminate::payload::encode_canonical(layered);
    const laminate::payload::CircuitDecodeLimits limits{
        .max_encoded_bytes = encoded.size(), .max_slots = 8,
        .max_plaintexts = 1, .max_payload_inputs = 1,
        .max_payload_gates = payload.gates.size(), .max_payload_outputs = 3,
        .max_layers = 2, .max_layer_gates = 8, .max_affine_terms = 16};
    const auto decoded = laminate::payload::decode_canonical_layered(encoded, limits);
    CHECK(laminate::payload::encode_canonical(decoded) == encoded);
    CHECK(laminate::payload::synthesize_trace(payload, decoded, inputs).payload_outputs == expected);

    auto malformed = layered;
    auto &bad = std::get<AffineLayer>(malformed.layers[0]);
    bad.intermediate_gates[0].terms[0].source = 1; // Self-reference.
    CHECK(throws_invalid_argument([&] { malformed.validate(); }));
    malformed = layered;
    std::get<AffineLayer>(malformed.layers[0]).intermediate_gates[0]
        .terms[0].plaintext_index = 1;
    CHECK(throws_invalid_argument([&] { malformed.validate(); }));
    malformed = layered;
    std::get<AffineLayer>(malformed.layers[0]).intermediate_gates[0]
        .terms[0].plaintext_index.reset();
    CHECK(laminate::payload::digest(malformed) != laminate::payload::digest(layered));
    CHECK(throws_invalid_argument([&] {
        laminate::payload::validate_compilation_pair(payload, malformed);
    }));
}

void test_wide_shared_prefixes_remain_linear() {
    constexpr std::size_t inputs = 128;
    PayloadBuilder builder(PayloadShape::wide(8), inputs);
    std::vector<laminate::payload::WireId> outputs{0};
    for (std::size_t input = 1; input < inputs; ++input) {
        outputs.push_back(builder.add(outputs.back(), input));
    }
    builder.set_outputs(outputs);
    const auto payload = builder.finish();
    const auto layered = laminate::payload::compile(payload);
    const auto &affine = std::get<AffineLayer>(layered.layers[0]);
    CHECK(affine.intermediate_gates.size() == inputs - 1);
    std::size_t terms = 0;
    for (const auto &gate : affine.intermediate_gates) {
        terms += gate.terms.size();
    }
    for (const auto &gate : affine.gates) {
        terms += gate.terms.size();
    }
    CHECK(terms == 2 * (inputs - 1) + inputs);
    std::vector<SlotVector> values(inputs, SlotVector(8, Fp::one()));
    const auto trace = laminate::payload::synthesize_trace(payload, layered, values);
    for (std::size_t output = 0; output < inputs; ++output) {
        CHECK(trace.payload_outputs[output] == SlotVector(8, Fp(output + 1)));
    }
}

void test_wide_mixed_dags_match_payload_evaluation() {
    for (std::uint64_t seed = 1; seed <= 16; ++seed) {
        PayloadBuilder builder(PayloadShape::wide(8), 3);
        const std::size_t mask = builder.add_plaintext(
            {Fp(0), Fp(1), Fp(3), Fp(7), Fp(11), Fp(13), Fp(17), Fp(19)});
        const std::size_t scalar = builder.add_scalar_plaintext(Fp(5));
        std::uint64_t state = seed;
        const auto random = [&] {
            state = state * 6364136223846793005ULL + 1442695040888963407ULL;
            return state;
        };
        for (std::size_t gate = 0; gate < 64; ++gate) {
            const auto left = random() % (3U + gate);
            const auto right = random() % (3U + gate);
            switch (random() % 5U) {
            case 0: builder.add(left, right); break;
            case 1: builder.add_plain(left, mask); break;
            case 2: builder.mul(left, right); break;
            case 3: builder.mul_plain(left, random() % 2U ? mask : scalar); break;
            case 4: builder.rotate(left, random() % 8U); break;
            }
        }
        builder.set_outputs({65, 66});
        const auto payload = builder.finish();
        const auto layered = laminate::payload::compile(payload);
        CHECK(layered.proof_multiplication_depth ==
              laminate::payload::analyze(payload).ct_ct_multiplicative_depth);
        const std::vector<SlotVector> values{
            SlotVector(8, Fp(seed)), SlotVector(8, Fp(seed + 1)),
            {Fp(1), Fp(2), Fp(3), Fp(4), Fp(5), Fp(6), Fp(7), Fp(8)}};
        const auto expected =
            laminate::payload::evaluate(payload, values).output_values(payload);
        CHECK(laminate::payload::synthesize_trace(payload, layered, values)
                  .payload_outputs == expected);
    }
}

} // namespace

int main() {
    laminate::test::Runner runner("test_layering");
    runner.run("affine-only circuit", test_affine_only_circuit);
    runner.run("Wide plaintext products remain affine",
               test_wide_dense_halves_and_plain_multiplication);
    runner.run("wide rotations compose in the grid group",
               test_rotation_composes_in_grid_group);
    runner.run("laned multiplication layout is dense",
               test_laned_dense_forwarding);
    runner.run("laned plaintext multiplication is uniform and affine",
               test_laned_plain_multiplier_is_uniform_and_affine);
    runner.run("wide forwarding is counted separately",
               test_wide_forwarding_and_padding_are_separate);
    runner.run("power-of-two padding and validation",
               test_power_of_two_padding_and_validation);
    runner.run("exact contraction reorders independent products",
               test_exact_contraction_reorders_independent_products);
    runner.run("ineligible contraction keeps payload order",
               test_ineligible_contraction_keeps_payload_order);
    runner.run("Wide diagonal rotations preserve order and bind encoding",
               test_wide_plaintext_rotation_dag_and_encoding);
    runner.run("Wide shared prefix sums retain a linear-size DAG",
               test_wide_shared_prefixes_remain_linear);
    runner.run("Mixed Wide DAGs match independent payload evaluation",
               test_wide_mixed_dags_match_payload_evaluation);
    return runner.summary();
}
