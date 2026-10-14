#include "test_helpers.hpp"

#include "laminate/payload/compiler.hpp"
#include "laminate/payload/trace/trace_wire_support.hpp"

#include <cstddef>
#include <limits>
#include <stdexcept>
#include <vector>

namespace {

using laminate::Fp;
using laminate::payload::AffineLayer;
using laminate::payload::InputLayer;
using laminate::payload::LayerWireSupport;
using laminate::payload::LayerStorageLayout;
using laminate::payload::LiveWireRange;
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

bool throws_out_of_range(const auto &body) {
    try {
        body();
    } catch (const std::out_of_range &) {
        return true;
    }
    return false;
}

LayerWireSupport prefix(std::size_t live, std::size_t padded) {
    return LayerWireSupport{padded, live, {LiveWireRange{0, live}}};
}

laminate::payload::LayeredCircuit make_three_product_circuit(
    const PayloadShape &shape) {
    PayloadBuilder builder(shape, 3);
    const auto first = builder.mul(0, 1);
    const auto second = builder.mul(1, 2);
    const auto third = builder.mul(2, 0);
    builder.set_outputs({first, second, third});
    return laminate::payload::compile(builder.finish());
}

void test_laned_split_operand_support() {
    const auto circuit =
        make_three_product_circuit(PayloadShape::laned(4, 16));
    const std::vector<LayerWireSupport> support =
        laminate::payload::canonical_trace_wire_support(circuit);
    CHECK(support.size() == 4);

    CHECK(support[0] == prefix(3, 4));
    CHECK(support[1] == prefix(3, 4));
    CHECK(support[2] ==
          (LayerWireSupport{8,
                            6,
                            {LiveWireRange{0, 3},
                             LiveWireRange{4, 3}}}));
    CHECK(support[3] == prefix(3, 4));

    const LayerWireSupport &operands = support[2];
    CHECK(operands.live_index_of(0) == 0);
    CHECK(operands.live_index_of(2) == 2);
    CHECK(!operands.live_index_of(3).has_value());
    CHECK(operands.live_index_of(4) == 3);
    CHECK(operands.live_index_of(6) == 5);
    CHECK(!operands.live_index_of(7).has_value());
    CHECK(operands.padded_index_of(0) == 0);
    CHECK(operands.padded_index_of(2) == 2);
    CHECK(operands.padded_index_of(3) == 4);
    CHECK(operands.padded_index_of(5) == 6);
    CHECK(throws_out_of_range([&] { (void)operands.live_index_of(8); }));
    CHECK(throws_out_of_range([&] { (void)operands.padded_index_of(6); }));

    laminate::payload::validate_trace_wire_support(circuit, support);
}

void test_wide_uses_the_same_split_operand_support() {
    const auto circuit = make_three_product_circuit(PayloadShape::wide(8));
    const std::vector<LayerWireSupport> support =
        laminate::payload::canonical_trace_wire_support(circuit);
    CHECK(support.size() == circuit.layers.size());
    CHECK(support[0] == prefix(3, 4));
    CHECK(support[1] == prefix(3, 4));
    CHECK(support[2] ==
          (LayerWireSupport{8,
                            6,
                            {LiveWireRange{0, 3},
                             LiveWireRange{4, 3}}}));
    CHECK(support[3] == prefix(3, 4));
    laminate::payload::validate_trace_wire_support(circuit, support);

    CHECK(std::get<AffineLayer>(circuit.layers.front())
              .dimensions.padding_size() == 1);
    CHECK(std::get<MultiplicationLayer>(circuit.layers[1])
              .dimensions.padding_size() == 1);
    CHECK(std::holds_alternative<InputLayer>(circuit.layers.back()));
}

void test_multiplication_source_recipes_share_physical_storage() {
    for (const PayloadShape &shape :
         {PayloadShape::wide(8), PayloadShape::laned(4, 16)}) {
        const auto circuit = make_three_product_circuit(shape);
        const std::vector<LayerStorageLayout> layouts =
            laminate::payload::canonical_trace_storage_layout(circuit);
        CHECK(layouts.size() == circuit.layers.size());

        const LayerStorageLayout &operands = layouts[2];
        CHECK(operands.padded_wire_count == 8);
        CHECK(operands.stored_wire_count == 3);
        CHECK(operands.stored_ordinal_of(0) == 0);
        CHECK(operands.stored_ordinal_of(1) == 1);
        CHECK(operands.stored_ordinal_of(2) == 2);
        CHECK(!operands.stored_ordinal_of(3).has_value());
        CHECK(operands.stored_ordinal_of(4) == 1);
        CHECK(operands.stored_ordinal_of(5) == 2);
        CHECK(operands.stored_ordinal_of(6) == 0);
        CHECK(!operands.stored_ordinal_of(7).has_value());
        CHECK(operands.representative_padded_index_of(0) == 0);
        CHECK(operands.representative_padded_index_of(1) == 1);
        CHECK(operands.representative_padded_index_of(2) == 2);

        CHECK(layouts[1].stored_wire_count == 3);
        CHECK(layouts[1].stored_ordinal_of(0) == 0);
        CHECK(layouts[1].stored_ordinal_of(1) == 1);
        CHECK(layouts[1].stored_ordinal_of(2) == 2);
        CHECK(!layouts[1].stored_ordinal_of(3).has_value());
        laminate::payload::validate_trace_storage_layout(circuit, layouts);
    }
}

void test_forwarding_wires_remain_live() {
    PayloadBuilder builder(PayloadShape::laned(4, 16), 2);
    const auto first = builder.mul(0, 1);
    const auto sum = builder.add(first, 0);
    const auto second = builder.mul(sum, first);
    builder.set_outputs({second});
    const auto circuit = laminate::payload::compile(builder.finish());
    const std::vector<LayerWireSupport> support =
        laminate::payload::canonical_trace_wire_support(circuit);

    const auto &bottom_products =
        std::get<MultiplicationLayer>(circuit.layers[3]);
    CHECK(bottom_products.dimensions.payload_size == 1);
    CHECK(bottom_products.dimensions.forward_size == 1);
    CHECK(support[3].live_wire_count == 2);
    CHECK(support[3].is_live(0));
    CHECK(support[3].is_live(1));

    const auto &bottom_operands =
        std::get<AffineLayer>(circuit.layers[4]);
    const std::size_t half = bottom_operands.dimensions.padded_size / 2;
    CHECK(support[4] ==
          (LayerWireSupport{bottom_operands.dimensions.padded_size,
                            bottom_operands.dimensions.logical_size,
                            {LiveWireRange{0, 2},
                             LiveWireRange{half, 2}}}));
}

void test_supplied_maps_fail_closed() {
    const auto circuit =
        make_three_product_circuit(PayloadShape::laned(4, 16));
    std::vector<LayerWireSupport> support =
        laminate::payload::canonical_trace_wire_support(circuit);

    LayerWireSupport adjacent{8,
                              6,
                              {LiveWireRange{0, 3},
                               LiveWireRange{3, 3}}};
    CHECK(throws_invalid_argument([&] {
        laminate::payload::validate_layer_wire_support(adjacent);
    }));

    LayerWireSupport overlapping{8,
                                 6,
                                 {LiveWireRange{0, 4},
                                  LiveWireRange{3, 2}}};
    CHECK(throws_invalid_argument([&] {
        laminate::payload::validate_layer_wire_support(overlapping);
    }));

    LayerWireSupport overflow{
        8,
        1,
        {LiveWireRange{std::numeric_limits<std::size_t>::max(), 2}}};
    CHECK(throws_invalid_argument([&] {
        laminate::payload::validate_layer_wire_support(overflow);
    }));

    support[2] = prefix(6, 8);
    CHECK(throws_invalid_argument([&] {
        laminate::payload::validate_trace_wire_support(circuit, support);
    }));
    CHECK(throws_invalid_argument([&] {
        laminate::payload::validate_layer_wire_support(circuit, 2,
                                                       support[2]);
    }));

    support.pop_back();
    CHECK(throws_invalid_argument([&] {
        laminate::payload::validate_trace_wire_support(circuit, support);
    }));
}

void test_supplied_storage_layouts_fail_closed() {
    const auto circuit =
        make_three_product_circuit(PayloadShape::wide(8));
    std::vector<LayerStorageLayout> layouts =
        laminate::payload::canonical_trace_storage_layout(circuit);

    LayerStorageLayout malformed = layouts[2];
    malformed.padded_to_stored[0] = malformed.stored_wire_count;
    CHECK(throws_invalid_argument([&] {
        laminate::payload::validate_layer_storage_layout(malformed);
    }));

    malformed = layouts[2];
    malformed.representative_padded_indices[0] = 4;
    CHECK(throws_invalid_argument([&] {
        laminate::payload::validate_layer_storage_layout(malformed);
    }));

    layouts[2].padded_to_stored[4] = 0;
    CHECK(throws_invalid_argument([&] {
        laminate::payload::validate_trace_storage_layout(circuit, layouts);
    }));
    CHECK(throws_invalid_argument([&] {
        laminate::payload::validate_layer_storage_layout(
            circuit, 2, layouts[2]);
    }));

    layouts.pop_back();
    CHECK(throws_invalid_argument([&] {
        laminate::payload::validate_trace_storage_layout(circuit, layouts);
    }));
}

void test_padding_gates_must_be_structural_zeroes() {
    auto circuit = make_three_product_circuit(PayloadShape::wide(8));
    auto &output = std::get<AffineLayer>(circuit.layers[0]);
    output.gates.back().constant = Fp::one();
    circuit.validate();
    CHECK(throws_invalid_argument([&] {
        (void)laminate::payload::canonical_trace_wire_support(circuit);
    }));

    circuit = make_three_product_circuit(PayloadShape::wide(8));
    auto &operands = std::get<AffineLayer>(circuit.layers[2]);
    operands.gates[3].constant = Fp::one();
    CHECK(throws_invalid_argument([&] {
        circuit.validate();
    }));
}

} // namespace

int main() {
    laminate::test::Runner runner("trace wire support");
    runner.run("Laned operand support preserves its padded split",
               test_laned_split_operand_support);
    runner.run("Wide dense operands preserve split logical support",
               test_wide_uses_the_same_split_operand_support);
    runner.run("dense operand aliases are setup-derived physical storage",
               test_multiplication_source_recipes_share_physical_storage);
    runner.run("payload and forwarding origins both remain live",
               test_forwarding_wires_remain_live);
    runner.run("noncanonical supplied maps fail closed",
               test_supplied_maps_fail_closed);
    runner.run("noncanonical physical layouts fail closed",
               test_supplied_storage_layouts_fail_closed);
    runner.run("padding origins must denote structural zeroes",
               test_padding_gates_must_be_structural_zeroes);
    return runner.summary();
}
