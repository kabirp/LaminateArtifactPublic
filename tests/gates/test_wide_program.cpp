#include "test_helpers.hpp"
#include "laminate/bench/payload_profile.hpp"
#include "laminate/gates/wide_program.hpp"
#include "laminate/gates/gate_mle.hpp"
#include "laminate/payload/compiler.hpp"
#include "laminate/poly/eq.hpp"

#include <algorithm>
#include <bit>
#include <limits>
#include <stdexcept>

using namespace laminate;
using namespace laminate::gates;
using namespace laminate::payload;

namespace {
Fpk value(std::size_t seed) {
    Fpk::Coefficients c{};
    for (std::size_t i = 0; i < c.size(); ++i)
        c[i] = Fp(seed + 13 * i + i * i);
    return Fpk(c);
}
std::vector<Fpk> point(std::size_t domain, std::size_t seed) {
    std::vector<Fpk> result;
    for (std::size_t i = 0;
         i < static_cast<std::size_t>(std::countr_zero(domain)); ++i)
        result.push_back(value(seed + 7 * i));
    return result;
}
struct Rows {
    std::size_t slots;
    std::vector<Fpk> values;
    std::size_t largest_read = 0;
    std::size_t largest_write = 0;
    Rows(std::size_t count, std::size_t width)
        : slots(width), values(count * width, Fpk::zero()) {}
    WideRowReader reader() {
        return [this](std::size_t row, std::span<Fpk> out) {
            CHECK(out.size() == slots);
            CHECK(row < values.size() / slots);
            largest_read = std::max(largest_read, out.size());
            std::copy_n(values.begin() + row * slots, slots, out.begin());
        };
    }
    WideRowWriter writer() {
        return [this](std::size_t row, std::span<const Fpk> in) {
            CHECK(in.size() == slots);
            CHECK(row < values.size() / slots);
            largest_write = std::max(largest_write, in.size());
            std::copy(in.begin(), in.end(), values.begin() + row * slots);
        };
    }
};
Fpk mle(const Rows &rows, const std::vector<Fpk> &q) {
    return poly::Multilinear<Fpk>(std::countr_zero(rows.values.size()),
                                  rows.values)
        .evaluate(q);
}
LayeredCircuit circuit() {
    const fhe::SlotVector mask{Fp(2),  Fp(3),  Fp(5),  Fp(7),
                               Fp(11), Fp(13), Fp(17), Fp(19)};
    const fhe::SlotVector constant{Fp(7), Fp(0), Fp(9), Fp(2),
                                   Fp(0), Fp(6), Fp(8), Fp(1)};
    LayeredCircuit c;
    c.shape = PayloadShape::wide(8);
    c.payload_input_count = 2;
    c.payload_output_count = 3;
    c.plaintexts = {mask, mask, fhe::SlotVector(8, Fp(3))};
    AffineLayer a;
    a.dimensions = {3, 4, 3, 0};
    a.intermediate_gates = {
        {{{0, 5, Fp(2), 0}}, constant, GateOrigin::Payload},
        {{{2, 0, Fp(1)}, {1, 0, Fp(3)}}, Fp(4), GateOrigin::Payload},
        {{{2, 0, Fp(5)}, {0, 0, Fp(2), 2}}, Fp(0), GateOrigin::Payload}};
    a.gates = {{{{4, 0, Fp(1)}}, Fp(0), GateOrigin::Payload},
               {{{3, 3, Fp(2), 1}}, Fp(0), GateOrigin::Payload},
               {{{0, 0, Fp(1)}}, constant, GateOrigin::Payload},
               {{}, Fp(0), GateOrigin::Padding}};
    c.layers = {a, InputLayer{{2, 2, 2, 0}}};
    c.validate();
    return c;
}
template <class Function> bool invalid(Function fn) {
    try {
        fn();
    } catch (const std::invalid_argument &) {
        return true;
    }
    return false;
}

WideProgramCompositionLimits no_composition() {
    return {0, 0, 0, 0};
}

void check_equivalent(const LayeredCircuit &c, const WideProgram &program) {
    const auto original = WideProgram::build(
        c, 0, WideMaskDictionary::build(c), no_composition());
    const auto &d = program.dimensions();
    Rows inputs(d.input_width, d.slots), outputs(d.output_width, d.slots),
        expected(d.output_width, d.slots), internal(d.internal_width, d.slots),
        old_internal(original.dimensions().internal_width, d.slots);
    for (std::size_t i = 0; i < inputs.values.size(); ++i)
        inputs.values[i] = value(i + 17);
    program.apply_forward(inputs.reader(), internal.reader(), internal.writer(),
                          outputs.writer());
    original.apply_forward(inputs.reader(), old_internal.reader(),
                           old_internal.writer(), expected.writer());
    CHECK(outputs.values == expected.values);
    const auto gamma = point(d.output_width * d.slots, 31);
    const auto input = point(d.input_width * d.slots, 47);
    Rows reverse(d.internal_width, d.slots);
    program.compute_reverse(gamma, reverse.reader(), reverse.writer());
    const DirectGateMle direct(c);
    CHECK(program.evaluate_from_reverse(reverse.reader(), gamma,
                                        WideColumnTarget::Input, input) ==
          direct.evaluate(GateMleQuery{AffineQuery{0, gamma, input}}));
    CHECK(program.evaluate_from_reverse(reverse.reader(), gamma,
                                        WideColumnTarget::Constant, {}) ==
          direct.evaluate_affine_constant(0, gamma));
}

LayeredCircuit composable_circuit() {
    auto c = circuit();
    auto &a = std::get<AffineLayer>(c.layers[0]);
    // BGV rotations 5 then 3 compose to 4, not integer addition modulo 8.
    a.intermediate_gates = {
        {{{0, 5, Fp(2)}}, c.plaintexts[0], GateOrigin::Payload},
        {{{2, 3, Fp(3)}, {1, 0, Fp(7)}}, Fp(4), GateOrigin::Payload},
        {{{1, 0, Fp(1), 0}}, Fp(2), GateOrigin::Payload}};
    a.gates = {{{{3, 0, Fp(1)}}, Fp(0), GateOrigin::Payload},
               {{{4, 0, Fp(1)}}, Fp(0), GateOrigin::Payload},
               {{{2, 0, Fp(5)}, {2, 0, Fp::zero() - Fp(5)}}, Fp(9),
                GateOrigin::Payload},
               {{}, Fp(0), GateOrigin::Padding}};
    c.validate();
    return c;
}
}

int main() {
    test::Runner runner("Wide local affine programs");
    runner.run(
        "normalized masks, local geometry, and canonical sparse indices", [] {
            auto c = circuit();
            const auto masks = WideMaskDictionary::build(c);
            const auto p = WideProgram::build(c, 0, masks);
            CHECK(masks->size() == 1);
            CHECK(p.nodes().size() == 5);
            CHECK(p.dimensions().input_width == 2);
            CHECK(p.dimensions().output_width == 4);
            CHECK(p.dimensions().internal_width == 8);
            CHECK(p.dimensions().row_width == 8);
            CHECK(p.dimensions().source_width == 8);
            CHECK(p.dimensions().internal_scalars == 64);
            for (const auto &node : p.nodes())
                for (const auto &term : node.terms)
                    CHECK(!term.mask || term.rotation == 0);
            for (const auto &node : p.outputs())
                for (const auto &term : node.terms)
                    CHECK(!term.mask || term.rotation == 0);
            for (auto table :
                 {WidePublicTable::UniformEdges, WidePublicTable::MaskEdges,
                  WidePublicTable::UniformConstants,
                  WidePublicTable::SlotConstants}) {
                std::size_t previous = 0;
                bool first = true;
                p.visit_entries(table, [&](const sparse::SparseEntry &e) {
                    CHECK(first || e.address > previous);
                    CHECK(!e.value.is_zero());
                    first = false;
                    previous = e.address;
                });
            }
            std::size_t mask_count = 0;
            masks->visit_entries([&](const sparse::SparseEntry &e) {
                CHECK(e.address < 8);
                ++mask_count;
            });
            CHECK(mask_count == 8);
            CHECK(p.digest() ==
                  WideProgram::build(c, 0, WideMaskDictionary::build(c))
                      .digest());
            c.plaintexts[0][0] += Fp(1);
            CHECK(invalid([&] { (void)WideProgram::build(c, 0, masks); }));
            CHECK(p.digest() !=
                  WideProgram::build(c, 0, WideMaskDictionary::build(c))
                      .digest());
        });
    runner.run(
        "forward program agrees with independent original DAG interpretation",
        [] {
            const auto c = circuit();
            const auto p =
                WideProgram::build(c, 0, WideMaskDictionary::build(c));
            Rows inputs(2, 8), internals(p.dimensions().internal_width, 8),
                outputs(4, 8);
            for (std::size_t i = 0; i < inputs.values.size(); ++i)
                inputs.values[i] = value(i + 5);
            p.apply_forward(inputs.reader(), internals.reader(),
                            internals.writer(), outputs.writer());
            const auto &a = std::get<AffineLayer>(c.layers[0]);
            std::vector<std::vector<Fpk>> values;
            values.push_back(
                {inputs.values.begin(), inputs.values.begin() + 8});
            values.push_back({inputs.values.begin() + 8, inputs.values.end()});
            const auto eval = [&](const AffineGate &gate) {
                const auto constants = materialize(gate.constant, 8);
                std::vector<Fpk> result(8);
                for (std::size_t slot = 0; slot < 8; ++slot) {
                    result[slot] = Fpk::from_base(constants[slot]);
                    for (const auto &t : gate.terms) {
                        auto v = values[t.source]
                                       [fhe::grid_source(8, t.rotation, slot)] *
                                 t.coefficient;
                        if (t.plaintext_index)
                            v = v * c.plaintexts[*t.plaintext_index][slot];
                        result[slot] += v;
                    }
                }
                return result;
            };
            for (const auto &g : a.intermediate_gates)
                values.push_back(eval(g));
            for (std::size_t i = 0; i < a.gates.size(); ++i) {
                const auto expected = eval(a.gates[i]);
                CHECK(std::equal(expected.begin(), expected.end(),
                                 outputs.values.begin() + 8 * i));
            }
            CHECK(internals.largest_read == 8);
            CHECK(internals.largest_write == 8);
        });
    runner.run(
        "internal reverse trace recovers direct coefficients, constants, and residual",
        [] {
            const auto c = circuit();
            const auto p =
                WideProgram::build(c, 0, WideMaskDictionary::build(c));
            const auto gamma = point(32, 11), input = point(16, 41),
                       tau = point(64, 77);
            Rows z(p.dimensions().internal_width, 8);
            p.compute_reverse(gamma, z.reader(), z.writer());
            const DirectGateMle direct(c);
            CHECK(p.evaluate_from_reverse(z.reader(), gamma,
                                          WideColumnTarget::Input, input) ==
                  direct.evaluate(GateMleQuery{AffineQuery{0, gamma, input}}));
            CHECK(p.evaluate_from_reverse(z.reader(), gamma,
                                          WideColumnTarget::Constant, {}) ==
                  direct.evaluate_affine_constant(0, gamma));
            CHECK(p.evaluate_from_reverse(z.reader(), gamma,
                                          WideColumnTarget::Internal,
                                          tau) == mle(z, tau));
            for (std::size_t i = p.nodes().size() * 8; i < z.values.size(); ++i)
                CHECK(z.values[i].is_zero());
            for (auto target :
                 {WideColumnTarget::Input, WideColumnTarget::Internal,
                  WideColumnTarget::Constant}) {
                const std::span<const Fpk> q =
                    target == WideColumnTarget::Input
                        ? std::span<const Fpk>(input)
                    : target == WideColumnTarget::Internal
                        ? std::span<const Fpk>(tau)
                        : std::span<const Fpk>{};
                Rows column(p.dimensions().internal_width, 8);
                p.build_internal_column(target, q, column.writer());
                auto contraction = p.evaluate_output_column(gamma, target, q);
                for (std::size_t i = 0; i < z.values.size(); ++i)
                    contraction += z.values[i] * column.values[i];
                CHECK(contraction ==
                      p.evaluate_from_reverse(z.reader(), gamma, target, q));
            }
            z.values[0] += Fpk::one();
            CHECK(p.evaluate_from_reverse(z.reader(), gamma,
                                          WideColumnTarget::Internal,
                                          tau) != mle(z, tau));
            z.values.back() += Fpk::one();
            CHECK(p.evaluate_from_reverse(z.reader(), gamma,
                                          WideColumnTarget::Internal,
                                          tau) != mle(z, tau));
        });
    runner.run("empty internal domain and malformed public inputs", [] {
        PayloadBuilder b(PayloadShape::wide(8), 2);
        b.set_outputs({0});
        auto c = compile(b.finish());
        auto p = WideProgram::build(c, 0, WideMaskDictionary::build(c));
        CHECK(p.nodes().empty());
        CHECK(p.dimensions().internal_width == 1);
        const auto gamma = point(p.dimensions().output_width * 8, 7);
        const auto input = point(p.dimensions().input_width * 8, 9);
        Rows z(1, 8);
        p.compute_reverse(gamma, z.reader(), z.writer());
        CHECK(p.evaluate_from_reverse(z.reader(), gamma,
                                      WideColumnTarget::Input, input) ==
              DirectGateMle(c).evaluate(
                  GateMleQuery{AffineQuery{0, gamma, input}}));
        CHECK(
            invalid([&] { p.compute_reverse(input, z.reader(), z.writer()); }));
        CHECK(invalid([&] {
            p.build_internal_column(WideColumnTarget::Constant, input,
                                    z.writer());
        }));
        auto bad = circuit();
        std::get<AffineLayer>(bad.layers[0])
            .intermediate_gates[0]
            .terms[0]
            .source = 9;
        CHECK(invalid([&] {
            (void)WideProgram::build(bad, 0, WideMaskDictionary::build(bad));
        }));
        bad = circuit();
        std::get<AffineLayer>(bad.layers[0])
            .intermediate_gates[0]
            .terms[0]
            .rotation = 8;
        CHECK(invalid([&] {
            (void)WideProgram::build(bad, 0, WideMaskDictionary::build(bad));
        }));
    });
    runner.run(
        "shared affine chains retain linear node and sparse table size", [] {
            PayloadBuilder b(PayloadShape::wide(8), 2);
            WireId last = 0;
            std::vector<WireId> outputs;
            for (std::size_t i = 0; i < 127; ++i) {
                last = b.add(last, 1);
                outputs.push_back(last);
            }
            b.set_outputs(outputs);
            const auto c = compile(b.finish());
            auto p = WideProgram::build(c, 0, WideMaskDictionary::build(c),
                                        no_composition());
            CHECK(p.nodes().size() == 127);
            CHECK(p.outputs().size() == 128);
            std::size_t edges = 0;
            p.visit_entries(WidePublicTable::UniformEdges,
                            [&](const auto &) { ++edges; });
            CHECK(edges == 381);
            const auto composed =
                WideProgram::build(c, 0, WideMaskDictionary::build(c));
            CHECK(composed.nodes().empty());
            check_equivalent(c, composed);
        });
    runner.run("bounded boundary composition preserves rotations, masks, constants, and cancellation", [] {
        const auto c = composable_circuit();
        const auto masks = WideMaskDictionary::build(c);
        const auto p = WideProgram::build(c, 0, masks);
        CHECK(p.nodes().empty());
        CHECK(p.outputs()[0].terms.size() == 2);
        CHECK(p.outputs()[0].terms[0].rotation == 4);
        CHECK(p.outputs()[0].terms[0].coefficient == Fp(6));
        CHECK(p.outputs()[1].terms.size() == 1);
        CHECK(p.outputs()[1].terms[0].mask == 0);
        CHECK(p.outputs()[2].terms.empty());
        CHECK(std::get<Fp>(p.outputs()[2].constant) == Fp(9));
        check_equivalent(c, p);
        CHECK(p.digest() == WideProgram::build(c, 0, masks).digest());
        auto policy = WideProgramCompositionLimits{};
        ++policy.max_work;
        CHECK(p.digest() != WideProgram::build(c, 0, masks, policy).digest());
    });
    runner.run("composition caps retain the complete local program", [] {
        const auto c = composable_circuit();
        const auto masks = WideMaskDictionary::build(c);
        auto check_fallback = [&](WideProgramCompositionLimits limits) {
            const auto p = WideProgram::build(c, 0, masks, limits);
            CHECK(p.nodes().size() == 3);
            CHECK(p.outputs()[0].terms[0].source_block ==
                  WideSourceBlock::Internal);
            check_equivalent(c, p);
        };
        check_fallback({.max_row_terms = 1});
        check_fallback({.max_retained_terms = 1});
        check_fallback({.max_work = 1});
        check_fallback({.max_constant_scalars = 4});
        check_fallback(no_composition());
    });
    runner.run("unsupported mask products and mask-rotation orders use the local fallback", [] {
        for (const auto mode : {0, 1, 2}) {
            PayloadBuilder builder(PayloadShape::wide(8), 1);
            const auto mask = builder.add_plaintext(
                {Fp(2), Fp(3), Fp(5), Fp(7), Fp(11), Fp(13), Fp(17), Fp(19)});
            const auto first = mode == 0 ? builder.rotate(0, 3)
                                         : builder.mul_plain(0, mask);
            const auto second = mode == 1 ? builder.rotate(first, 5)
                                          : builder.mul_plain(first, mask);
            builder.set_outputs({second});
            const auto c = compile(builder.finish());
            const auto p = WideProgram::build(c, 0, WideMaskDictionary::build(c));
            CHECK(!p.nodes().empty());
            check_equivalent(c, p);
        }
    });
    runner.run("constant-only masked and rotated paths compose exactly", [] {
        auto c = composable_circuit();
        auto &a = std::get<AffineLayer>(c.layers[0]);
        a.intermediate_gates = {
            {{}, c.plaintexts[0], GateOrigin::Payload},
            {{{2, 5, Fp(3), 0}}, Fp(7), GateOrigin::Payload}};
        a.gates = {{{{3, 3, Fp(2)}}, Fp(5), GateOrigin::Payload},
                   {{}, Fp(0), GateOrigin::Padding},
                   {{}, Fp(0), GateOrigin::Padding},
                   {{}, Fp(0), GateOrigin::Padding}};
        a.dimensions = {1, 4, 1, 0};
        c.payload_output_count = 1;
        c.validate();
        const auto p = WideProgram::build(c, 0, WideMaskDictionary::build(c));
        CHECK(p.nodes().empty());
        CHECK(p.outputs()[0].terms.empty());
        CHECK(std::holds_alternative<fhe::SlotVector>(p.outputs()[0].constant));
        check_equivalent(c, p);
    });
    runner.run("generic shared DAGs merge exponential paths and retain dense regions at the cap", [] {
        PayloadBuilder repeated(PayloadShape::wide(8), 1);
        WireId last = 0;
        for (std::size_t i = 0; i < 96; ++i)
            last = repeated.add(last, last);
        repeated.set_outputs({last});
        const auto c = compile(repeated.finish());
        const auto compact = WideProgram::build(c, 0, WideMaskDictionary::build(c));
        CHECK(compact.nodes().empty());
        CHECK(compact.outputs()[0].terms.size() == 1);
        Fp expected = Fp::one();
        for (std::size_t i = 0; i < 96; ++i) expected += expected;
        CHECK(compact.outputs()[0].terms[0].coefficient == expected);
        check_equivalent(c, compact);

        PayloadBuilder dense(PayloadShape::wide(8), 64);
        std::vector<WireId> frontier;
        for (std::size_t i = 0; i < 64; ++i) frontier.push_back(i);
        while (frontier.size() > 1) {
            std::vector<WireId> next;
            for (std::size_t i = 0; i < frontier.size(); i += 2)
                next.push_back(dense.add(frontier[i], frontier[i + 1]));
            frontier = std::move(next);
        }
        dense.set_outputs(frontier);
        const auto d = compile(dense.finish());
        const auto masks = WideMaskDictionary::build(d);
        const auto bounded = WideProgram::build(d, 0, masks, {.max_row_terms = 16});
        CHECK(bounded.nodes().size() == 63);
        check_equivalent(d, bounded);
        const auto full = WideProgram::build(d, 0, masks);
        CHECK(full.nodes().empty());
        CHECK(full.outputs()[0].terms.size() == 64);
        check_equivalent(d, full);
    });
    runner.run("target workload affine programs remain sparse without adjoint traces", [] {
        for (const auto name : {"target-balancedLaned", "target-mulHeavyPyramid"}) {
            const auto profile = bench::benchmark_payload_profile(name);
            const auto payload = make_payload_circuit(
                bench::benchmark_payload_workload_spec(profile, PayloadShape::wide(16384)));
            const auto c = compile(payload);
            const auto workspace = wide_program_composition_workspace_bound(c);
            CHECK(workspace > 256ULL * 1024 * 1024);
            std::cout << "[INFO] " << name
                      << " composition workspace upper bound=" << workspace << '\n';
            const auto masks = WideMaskDictionary::build(c);
            std::size_t coefficients = 0, constants = 0, layers = 0;
            for (std::size_t layer = 0; layer < c.layers.size(); ++layer) {
                if (!std::holds_alternative<AffineLayer>(c.layers[layer]))
                    continue;
                const auto p = WideProgram::build(c, layer, masks);
                CHECK(p.nodes().empty());
                ++layers;
                for (const auto &row : p.outputs()) {
                    coefficients += row.terms.size();
                    CHECK(std::holds_alternative<Fp>(row.constant));
                    constants += !std::get<Fp>(row.constant).is_zero();
                    for (const auto &term : row.terms) {
                        CHECK(term.source_block == WideSourceBlock::Input);
                        CHECK(!term.mask || term.rotation == 0);
                    }
                }
            }
            CHECK(layers == 9);
            if (profile.tier == bench::BenchmarkPayloadTier::TargetBalanced) {
                CHECK(coefficients == 1897106);
                CHECK(constants == 63977);
                CHECK(masks->size() == 0);
            } else {
                CHECK(coefficients == 4434044);
                CHECK(constants == 836);
                CHECK(masks->size() == 8);
            }
        }
    });
    runner.run("composition workspace is bounded structurally before expansion", [] {
        const auto c = composable_circuit();
        const auto bounded = wide_program_composition_workspace_bound(c);
        const auto disabled = wide_program_composition_workspace_bound(c, no_composition());
        CHECK(bounded > disabled);
        CHECK(bounded < 1024 * 1024);
        const auto program = WideProgram::build(c, 0, WideMaskDictionary::build(c));
        std::size_t retained = 0;
        for (const auto &row : program.outputs()) {
            retained += sizeof(WideProgramNode) +
                        row.terms.capacity() * sizeof(WideProgramTerm);
            if (const auto *slots = std::get_if<fhe::SlotVector>(&row.constant))
                retained += slots->capacity() * sizeof(Fp);
        }
        CHECK(bounded >= retained);
        CHECK(wide_program_composition_workspace_bound(c, {.max_row_terms = 1}) <= bounded);
        auto laned = c;
        laned.shape = PayloadShape::laned(8, 8);
        CHECK(wide_program_composition_workspace_bound(laned) == 0);
        auto enormous = c;
        enormous.shape.slot_count = std::numeric_limits<std::size_t>::max();
        bool overflow = false;
        try { (void)wide_program_composition_workspace_bound(enormous); }
        catch (const std::overflow_error &) { overflow = true; }
        CHECK(overflow);
    });
    return runner.summary();
}
