/// @file test_gate_mle.cpp
/// @brief Direct gate-polynomial evaluation against explicit tensors.

#include "test_helpers.hpp"

#include "laminate/gates/gate_mle.hpp"
#include "laminate/payload/compiler.hpp"
#include "laminate/poly/eq.hpp"
#include "laminate/setup/gate_mle.hpp"

#include <bit>
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <set>
#include <stdexcept>
#include <vector>

using namespace laminate;
using namespace laminate::gates;
using namespace laminate::payload;

namespace {

Fpk value(std::uint64_t seed) {
    Fpk::Coefficients coefficients{};
    for (std::size_t index = 0; index < coefficients.size(); ++index) {
        coefficients[index] = Fp(seed + 17 * index + 3 * index * index);
    }
    return Fpk(coefficients);
}

std::vector<Fpk> point(std::size_t size, std::uint64_t seed) {
    std::vector<Fpk> result;
    result.reserve(size);
    for (std::size_t index = 0; index < size; ++index) {
        result.push_back(value(seed + 29 * index));
    }
    return result;
}

std::size_t variables(std::size_t wires, std::size_t width) {
    return (std::bit_width(wires) - 1U) + (std::bit_width(width) - 1U);
}

PayloadCircuit wide_payload() {
    PayloadBuilder builder(PayloadShape::wide(8), 2);
    const std::size_t diagonal = builder.add_plaintext(
        {Fp(2), Fp(3), Fp(5), Fp(7), Fp(11), Fp(13), Fp(17), Fp(19)});
    const auto rotated = builder.rotate(0, 5);
    const auto ctct = builder.mul(rotated, 1);
    const auto plainct = builder.mul_plain(0, diagonal);
    const auto output = builder.add(ctct, plainct);
    builder.set_outputs({output});
    return builder.finish();
}

PayloadCircuit rotated_padded_affine_payload() {
    PayloadBuilder builder(PayloadShape::wide(8), 3);
    const auto first = builder.rotate(0, 1);
    const auto second = builder.rotate(1, 5);
    const auto third = builder.rotate(2, 3);
    builder.set_outputs({first, second, builder.add(first, third)});
    return builder.finish();
}

std::vector<Fpk> boolean_point(std::size_t index,
                               std::size_t variable_count) {
    std::vector<Fpk> result;
    result.reserve(variable_count);
    for (std::size_t variable = 0; variable < variable_count; ++variable) {
        const std::size_t shift = variable_count - 1U - variable;
        result.push_back(((index >> shift) & std::size_t{1}) != 0
                             ? Fpk::one()
                             : Fpk::zero());
    }
    return result;
}

struct PointWeights {
    std::vector<Fpk> wire;
    std::vector<Fpk> slot;
};

PointWeights weights(const std::vector<Fpk> &evaluation_point,
                     std::size_t wires, std::size_t width) {
    const std::size_t wire_variables = std::bit_width(wires) - 1U;
    const std::size_t slot_variables = std::bit_width(width) - 1U;
    if (evaluation_point.size() != wire_variables + slot_variables) {
        throw std::invalid_argument("weights: point dimension mismatch");
    }
    const std::vector<Fpk> wire_point(
        evaluation_point.begin(),
        evaluation_point.begin() +
            static_cast<std::ptrdiff_t>(wire_variables));
    const std::vector<Fpk> slot_point(
        evaluation_point.begin() +
            static_cast<std::ptrdiff_t>(wire_variables),
        evaluation_point.end());
    return PointWeights{poly::eq_evaluations(wire_point),
                        poly::eq_evaluations(slot_point)};
}

std::vector<std::vector<Fpk>> forward_affine_program(
    const LayeredCircuit &circuit, std::size_t layer_index,
    std::vector<std::vector<Fpk>> values, bool include_constant) {
    const auto &layer = std::get<AffineLayer>(circuit.layers[layer_index]);
    const std::size_t width = circuit.shape.value_width();
    const auto evaluate = [&](const AffineGate &gate) {
        std::vector<Fpk> result(width, Fpk::zero());
        if (include_constant) {
            const auto constants = materialize(gate.constant, width);
            for (std::size_t slot = 0; slot < width; ++slot) {
                result[slot] = Fpk::from_base(constants[slot]);
            }
        }
        for (const auto &term : gate.terms) {
            for (std::size_t slot = 0; slot < width; ++slot) {
                const std::size_t source_slot = width == 1 ? 0
                    : fhe::grid_source(width, term.rotation, slot);
                result[slot] += values.at(term.source)[source_slot] *
                    Fpk::from_base(term.coefficient) *
                    (term.plaintext_index
                        ? Fpk::from_base(circuit.plaintexts[*term.plaintext_index][slot])
                        : Fpk::one());
            }
        }
        return result;
    };
    for (const auto &gate : layer.intermediate_gates) {
        values.push_back(evaluate(gate));
    }
    std::vector<std::vector<Fpk>> result;
    for (const auto &gate : layer.gates) {
        result.push_back(evaluate(gate));
    }
    return result;
}

Fpk naive_affine(const LayeredCircuit &circuit, std::size_t layer_index,
                 const std::vector<Fpk> &output_point,
                 const std::vector<Fpk> &source_point) {
    const auto &layer = std::get<AffineLayer>(circuit.layers[layer_index]);
    const std::size_t width = circuit.shape.value_width();
    const std::size_t sources =
        layer_dimensions(circuit.layers[layer_index + 1]).padded_size;
    const auto output = weights(output_point, layer.dimensions.padded_size, width);
    const auto source = weights(source_point, sources, width);
    std::vector<std::vector<Fpk>> inputs(sources, std::vector<Fpk>(width));
    for (std::size_t wire = 0; wire < sources; ++wire) {
        for (std::size_t slot = 0; slot < width; ++slot) {
            inputs[wire][slot] = source.wire[wire] * source.slot[slot];
        }
    }
    const auto outputs = forward_affine_program(circuit, layer_index,
                                                std::move(inputs), false);
    Fpk result = Fpk::zero();
    for (std::size_t wire = 0; wire < outputs.size(); ++wire) {
        for (std::size_t slot = 0; slot < width; ++slot) {
            result += output.wire[wire] * output.slot[slot] * outputs[wire][slot];
        }
    }
    return result;
}

Fpk naive_laned_affine_wire(
    const LayeredCircuit &circuit, std::size_t layer_index,
    const std::vector<Fpk> &output_point,
    const std::vector<Fpk> &source_point) {
    const auto &layer = std::get<AffineLayer>(circuit.layers[layer_index]);
    const std::size_t sources =
        layer_dimensions(circuit.layers[layer_index + 1]).padded_size;
    const std::vector<Fpk> output = poly::eq_evaluations(output_point);
    const std::vector<Fpk> source = poly::eq_evaluations(source_point);
    CHECK(output.size() == layer.dimensions.padded_size);
    CHECK(source.size() == sources);
    Fpk result = Fpk::zero();
    for (std::size_t gate = 0; gate < layer.gates.size(); ++gate) {
        for (const AffineTerm &term : layer.gates[gate].terms) {
            result += output[gate] * source[term.source] *
                      Fpk::from_base(term.coefficient);
        }
    }
    return result;
}

Fpk naive_constant(const LayeredCircuit &circuit, std::size_t layer_index,
                   const std::vector<Fpk> &output_point) {
    const auto &layer = std::get<AffineLayer>(circuit.layers[layer_index]);
    const std::size_t width = circuit.shape.value_width();
    const auto output =
        weights(output_point, layer.dimensions.padded_size, width);
    const std::size_t sources =
        layer_dimensions(circuit.layers[layer_index + 1]).padded_size;
    const auto values = forward_affine_program(circuit, layer_index,
        std::vector<std::vector<Fpk>>(sources, std::vector<Fpk>(width, Fpk::zero())), true);
    Fpk result = Fpk::zero();
    for (std::size_t gate = 0; gate < layer.gates.size(); ++gate) {
        for (std::size_t slot = 0; slot < width; ++slot) {
            result += output.wire[gate] * output.slot[slot] * values[gate][slot];
        }
    }
    return result;
}

void check_structural_schedule(const DirectGateMle &provider, std::size_t layer,
                               const PreparedDirectAffineMle &prepared) {
    const auto structure = provider.affine_structure(layer);
    CHECK(structure.slot_basis_count == prepared.rotation_basis_count());
    std::vector<std::pair<std::size_t, std::size_t>> expected, actual;
    for (const auto &term : structure.terms) {
        expected.emplace_back(term.source, term.basis);
    }
    for (const auto &term : prepared.weighted_terms()) {
        actual.emplace_back(term.source, term.rotation_index);
    }
    std::sort(expected.begin(), expected.end());
    std::sort(actual.begin(), actual.end());
    CHECK(actual == expected);
}

} // namespace

int main() {
    test::Runner runner("test_gate_mle");

    runner.run("direct affine queries match independent forward evaluation", [] {
        const LayeredCircuit circuit = compile(wide_payload());
        const DirectGateMle provider(circuit);
        for (std::size_t layer_index = 0;
             layer_index + 1 < circuit.layers.size(); ++layer_index) {
            if (layer_kind(circuit.layers[layer_index]) != LayerKind::Affine) {
                continue;
            }
            const std::size_t output_wires =
                layer_dimensions(circuit.layers[layer_index]).padded_size;
            const std::size_t source_wires =
                layer_dimensions(circuit.layers[layer_index + 1]).padded_size;
            const auto output = point(
                variables(output_wires, circuit.shape.value_width()),
                11 + layer_index);
            const auto source = point(
                variables(source_wires, circuit.shape.value_width()),
                47 + layer_index);
            const GateMleQuery query =
                AffineQuery{layer_index, output, source};
            CHECK(provider.evaluate(query) ==
                  naive_affine(circuit, layer_index, output, source));
            CHECK(provider.evaluate_affine_constant(layer_index, output) ==
                  naive_constant(circuit, layer_index, output));
        }
    });

    runner.run("paired direct affine queries match two independent scans", [] {
        const LayeredCircuit circuit = compile(wide_payload());
        const DirectGateMle provider(circuit);
        const Fpk second_weight = value(991);
        for (std::size_t layer_index = 0;
             layer_index + 1 < circuit.layers.size(); ++layer_index) {
            if (layer_kind(circuit.layers[layer_index]) != LayerKind::Affine) {
                continue;
            }
            const std::size_t output_wires =
                layer_dimensions(circuit.layers[layer_index]).padded_size;
            const std::size_t source_wires =
                layer_dimensions(circuit.layers[layer_index + 1]).padded_size;
            const auto first_output = point(
                variables(output_wires, circuit.shape.value_width()),
                601 + layer_index);
            const auto second_output = point(
                variables(output_wires, circuit.shape.value_width()),
                701 + layer_index);
            const auto source = point(
                variables(source_wires, circuit.shape.value_width()),
                801 + layer_index);
            const Fpk first = provider.evaluate(
                GateMleQuery{AffineQuery{
                    layer_index, first_output, source}});
            const Fpk second = provider.evaluate(
                GateMleQuery{AffineQuery{
                    layer_index, second_output, source}});
            CHECK(provider.evaluate_affine_pair(
                      layer_index, first_output, second_output, source,
                      second_weight) ==
                  first + second_weight * second);

            const Fpk first_constant =
                provider.evaluate_affine_constant(
                    layer_index, first_output);
            const Fpk second_constant =
                provider.evaluate_affine_constant(
                    layer_index, second_output);
            CHECK(provider.evaluate_affine_constant_pair(
                      layer_index, first_output, second_output,
                      second_weight) ==
                  first_constant + second_weight * second_constant);
        }
    });

    runner.run(
        "prepared affine slot tables match direct rotations and padding", [] {
        const LayeredCircuit circuit =
            compile(rotated_padded_affine_payload());
        CHECK(circuit.layers.size() == 2);
        const auto &layer = std::get<AffineLayer>(circuit.layers[0]);
        const LayerDimensions source = layer_dimensions(circuit.layers[1]);
        CHECK(layer.dimensions.logical_size == 3);
        CHECK(layer.dimensions.padded_size == 4);
        CHECK(source.logical_size == 3);
        CHECK(source.padded_size == 4);

        const DirectGateMle provider(circuit);
        const std::size_t slot_variables =
            std::bit_width(circuit.shape.value_width()) - 1U;
        const std::size_t source_wire_variables =
            std::bit_width(source.padded_size) - 1U;
        for (std::size_t sample = 0; sample < 7; ++sample) {
            const std::vector<Fpk> output = point(
                variables(layer.dimensions.padded_size,
                          circuit.shape.value_width()),
                401 + 31 * sample);
            const std::vector<Fpk> source_wire =
                point(source_wire_variables, 701 + 43 * sample);
            const PreparedDirectAffineMle prepared =
                provider.prepare_affine(0, output);
            check_structural_schedule(provider, 0, prepared);
            const std::vector<Fpk> table =
                prepared.evaluate_boolean_source_slots(source_wire);
            CHECK(table.size() == circuit.shape.value_width());

            for (std::size_t slot = 0; slot < table.size(); ++slot) {
                std::vector<Fpk> source_point = source_wire;
                const std::vector<Fpk> source_slot =
                    boolean_point(slot, slot_variables);
                source_point.insert(source_point.end(), source_slot.begin(),
                                    source_slot.end());
                CHECK(table[slot] ==
                      provider.evaluate(GateMleQuery{AffineQuery{
                          0, output, source_point}}));
            }

            for (std::size_t prefix_size = 0;
                 prefix_size <= source_wire_variables; ++prefix_size) {
                const std::vector<Fpk> prefix(
                    source_wire.begin(),
                    source_wire.begin() +
                        static_cast<std::ptrdiff_t>(prefix_size));
                const BoundDirectAffineMle bound =
                    prepared.bind_source_ciphertext_index_point(prefix);
                const std::size_t suffix_variables =
                    source_wire_variables - prefix_size;
                const std::size_t suffix_count =
                    std::size_t{1} << suffix_variables;
                CHECK(bound.boolean_suffix_count() == suffix_count);
                for (std::size_t suffix = 0; suffix < suffix_count;
                     ++suffix) {
                    const std::vector<Fpk> suffix_table =
                        bound.evaluate_boolean_source_slots(suffix);
                    CHECK(suffix_table.size() ==
                          circuit.shape.value_width());
                    std::vector<Fpk> bound_source = prefix;
                    const std::vector<Fpk> suffix_point =
                        boolean_point(suffix, suffix_variables);
                    bound_source.insert(bound_source.end(),
                                        suffix_point.begin(),
                                        suffix_point.end());
                    for (std::size_t slot = 0;
                         slot < suffix_table.size(); ++slot) {
                        std::vector<Fpk> source_point = bound_source;
                        const std::vector<Fpk> source_slot =
                            boolean_point(slot, slot_variables);
                        source_point.insert(source_point.end(),
                                            source_slot.begin(),
                                            source_slot.end());
                        CHECK(suffix_table[slot] ==
                              provider.evaluate(GateMleQuery{AffineQuery{
                                  0, output, source_point}}));
                    }
                }
            }
        }

        const std::vector<Fpk> output = point(
            variables(layer.dimensions.padded_size,
                      circuit.shape.value_width()),
            997);
        const PreparedDirectAffineMle prepared =
            provider.prepare_affine(0, output);
        const BoundDirectAffineMle unbound =
            prepared.bind_source_ciphertext_index_point({});
        const std::vector<Fpk> padded_source =
            unbound.evaluate_boolean_source_slots(3);
        for (const Fpk &entry : padded_source) {
            CHECK(entry.is_zero());
        }
    });

    runner.run("single-lane affine predicates have an empty slot point", [] {
        PayloadBuilder builder(PayloadShape::laned(1, 8), 2);
        const auto product = builder.mul(0, 1);
        builder.set_outputs({product});
        const LayeredCircuit circuit = compile(builder.finish());
        const DirectGateMle provider(circuit);
        for (std::size_t layer_index = 0;
             layer_index + 1 < circuit.layers.size(); ++layer_index) {
            if (layer_kind(circuit.layers[layer_index]) != LayerKind::Affine) {
                continue;
            }
            const std::size_t output_wires =
                layer_dimensions(circuit.layers[layer_index]).padded_size;
            const std::size_t source_wires =
                layer_dimensions(circuit.layers[layer_index + 1]).padded_size;
            const auto output = point(variables(output_wires, 1),
                                      181 + layer_index);
            const auto source = point(variables(source_wires, 1),
                                      193 + layer_index);
            CHECK(provider.evaluate(GateMleQuery{AffineQuery{
                      layer_index, output, source}}) ==
                  naive_affine(circuit, layer_index, output, source));
        }
    });

    runner.run("Wide reverse weights preserve shared prefix sums", [] {
        constexpr std::size_t count = 64;
        PayloadBuilder builder(PayloadShape::wide(8), count);
        std::vector<WireId> outputs{0};
        for (std::size_t input = 1; input < count; ++input) {
            outputs.push_back(builder.add(outputs.back(), input));
        }
        builder.set_outputs(outputs);
        const auto circuit = compile(builder.finish());
        const DirectGateMle provider(circuit);
        for (bool boolean : {false, true}) {
            const auto output = boolean ? std::vector<Fpk>(9, Fpk::zero())
                                        : point(9, 710);
            const auto prepared = provider.prepare_affine(0, output);
            check_structural_schedule(provider, 0, prepared);
            CHECK(prepared.rotation_basis_count() == 1);
            CHECK(provider.affine_structure(0).peak_live_slot_basis_count == 1);
            CHECK(prepared.weighted_term_count() == count);
            const auto source = point(9, 812);
            CHECK(provider.evaluate(GateMleQuery{AffineQuery{0, output, source}}) ==
                  naive_affine(circuit, 0, output, source));
            auto rolling = prepared.rolling_source_wire_binding();
            std::vector<Fpk> prefix;
            for (std::size_t variable = 0; variable < 6; ++variable) {
                for (const Fpk &candidate : {Fpk::zero(), Fpk::one(), value(77)}) {
                    auto candidate_prefix = prefix;
                    candidate_prefix.push_back(candidate);
                    const auto expected = prepared.bind_source_ciphertext_index_point(candidate_prefix);
                    const auto actual = rolling.evaluate_next(candidate);
                    for (std::size_t suffix = 0;
                         suffix < actual.boolean_suffix_count(); ++suffix) {
                        CHECK(actual.evaluate_boolean_source_slots(suffix) ==
                              expected.evaluate_boolean_source_slots(suffix));
                    }
                }
                prefix.push_back(source[variable]);
                rolling.bind(source[variable]);
            }
            CHECK(rolling.complete());
        }
    });

    runner.run("Wide reverse constants preserve diagonal and rotation order", [] {
        PayloadBuilder builder(PayloadShape::wide(8), 2);
        const auto mask = builder.add_plaintext(
            {Fp(2), Fp(3), Fp(5), Fp(7), Fp(11), Fp(13), Fp(17), Fp(19)});
        const auto biased = builder.add_plain(0, mask);
        const auto multiplied = builder.mul_plain(biased, mask);
        const auto first = builder.rotate(multiplied, 5);
        const auto second = builder.mul_plain(builder.rotate(biased, 5), mask);
        builder.set_outputs({first, second, builder.add(first, 1)});
        const auto circuit = compile(builder.finish());
        const DirectGateMle provider(circuit);
        const auto output = point(5, 927);
        const auto source = point(4, 961);
        CHECK(provider.evaluate(GateMleQuery{AffineQuery{0, output, source}}) ==
              naive_affine(circuit, 0, output, source));
        CHECK(provider.evaluate_affine_constant(0, output) ==
              naive_constant(circuit, 0, output));
        CHECK(!provider.evaluate_affine_constant(0, output).is_zero());
    });

    runner.run("Wide basis collapse bounds highly varied fanout", [] {
        PayloadBuilder builder(PayloadShape::wide(8), 1);
        std::vector<WireId> outputs;
        for (std::size_t diagonal = 0; diagonal < 25; ++diagonal) {
            fhe::SlotVector slots;
            for (std::size_t slot = 0; slot < 8; ++slot) {
                slots.push_back(Fp(3 + diagonal + slot * (diagonal + 1)));
            }
            const auto plaintext = builder.add_plaintext(std::move(slots));
            outputs.push_back(builder.mul_plain(0, plaintext));
        }
        builder.set_outputs(outputs);
        const auto circuit = compile(builder.finish());
        const DirectGateMle provider(circuit);
        const auto output = point(8, 1101);
        const auto source = point(3, 1201);
        const auto prepared = provider.prepare_affine(0, output);
        check_structural_schedule(provider, 0, prepared);
        CHECK(prepared.weighted_term_count() <= 8);
        CHECK(prepared.rotation_basis_count() <= 8);
        const auto structure = provider.affine_structure(0);
        CHECK(structure.peak_live_slot_basis_count > structure.slot_basis_count);
        CHECK(affine_gate_preparation_workspace_bytes(circuit) >=
              (structure.peak_live_slot_basis_count + structure.slot_basis_count) *
                  circuit.shape.value_width() * sizeof(Fpk));
        CHECK(provider.evaluate(GateMleQuery{AffineQuery{0, output, source}}) ==
              naive_affine(circuit, 0, output, source));
    });

    runner.run("laned affine wire predicate excludes slot equality", [] {
        PayloadBuilder builder(PayloadShape::laned(4, 16), 2);
        const auto product = builder.mul(0, 1);
        builder.set_outputs({builder.add(product, 0)});
        const LayeredCircuit circuit = compile(builder.finish());
        const DirectGateMle provider(circuit);
        for (std::size_t layer_index = 0;
             layer_index + 1 < circuit.layers.size(); ++layer_index) {
            if (layer_kind(circuit.layers[layer_index]) != LayerKind::Affine) {
                continue;
            }
            const std::size_t output_wires =
                layer_dimensions(circuit.layers[layer_index]).padded_size;
            const std::size_t source_wires =
                layer_dimensions(circuit.layers[layer_index + 1]).padded_size;
            const auto output_wire =
                point(std::bit_width(output_wires) - 1U, 307 + layer_index);
            const auto source_wire =
                point(std::bit_width(source_wires) - 1U, 331 + layer_index);
            const Fpk scalar = provider.evaluate(GateMleQuery{
                LanedAffineWireQuery{layer_index, output_wire, source_wire}});
            CHECK(scalar == naive_laned_affine_wire(
                                circuit, layer_index, output_wire,
                                source_wire));

            const auto output_lane = point(2, 353 + layer_index);
            const auto source_lane = point(2, 379 + layer_index);
            std::vector<Fpk> output = output_wire;
            output.insert(output.end(), output_lane.begin(),
                          output_lane.end());
            std::vector<Fpk> source = source_wire;
            source.insert(source.end(), source_lane.begin(),
                          source_lane.end());
            CHECK(provider.evaluate(GateMleQuery{AffineQuery{
                      layer_index, output, source}}) ==
                  scalar * poly::eq_eval(output_lane, source_lane));
        }
    });

    runner.run("dummy commitments change the bound transcript", [] {
        const PayloadCircuit payload = wide_payload();
        const LayeredCircuit circuit = compile(payload);
        const PublicSetup direct = make_direct_setup(payload, circuit);
        const PublicSetup dummy = make_dummy_committed_setup(payload, circuit);

        Transcript direct_transcript("test/gates/setup");
        observe_gate_mle_setup(direct, direct_transcript);
        const Fpk direct_challenge = direct_transcript.challenge_fpk();
        Transcript dummy_transcript("test/gates/setup");
        observe_gate_mle_setup(dummy, dummy_transcript);
        const Fpk dummy_challenge = dummy_transcript.challenge_fpk();
        Transcript replay_transcript("test/gates/setup");
        observe_gate_mle_setup(dummy, replay_transcript);

        CHECK(direct_challenge != dummy_challenge);
        CHECK(dummy_challenge == replay_transcript.challenge_fpk());
        CHECK(!dummy.dummy_gate_commitments.empty());
    });

    runner.run("query dimensions are enforced", [] {
        const LayeredCircuit circuit = compile(wide_payload());
        const DirectGateMle provider(circuit);
        const auto malformed = point(1, 211);
        bool dimension_threw = false;
        try {
            (void)provider.evaluate(GateMleQuery{
                AffineQuery{0, malformed, malformed}});
        } catch (const std::invalid_argument &) {
            dimension_threw = true;
        }
        CHECK(dimension_threw);

    });

    return runner.summary();
}
