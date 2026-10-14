#ifndef LAMINATE_TESTS_NO_INTEGRITY_TARGET_NOISE_HPP
#define LAMINATE_TESTS_NO_INTEGRITY_TARGET_NOISE_HPP

#include "test_helpers.hpp"
#include "laminate/bench/no_integrity_parameters.hpp"
#include "laminate/payload/compiler.hpp"
#include "laminate/payload/evaluator.hpp"
#include "laminate/payload/input_encryption.hpp"
#include "laminate/payload/wide_fhe_evaluator.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <limits>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace laminate::test {

inline payload::PayloadCircuit no_integrity_target_cone(
    const payload::PayloadCircuit &target, payload::WireId root) {
    using namespace payload;
    std::vector<bool> retained(target.wire_count());
    std::vector<WireId> pending{root};
    std::size_t retained_count = 0;
    while (!pending.empty()) {
        const auto wire = pending.back();
        pending.pop_back();
        if (wire < target.input_count || retained[wire]) continue;
        retained[wire] = true;
        CHECK(++retained_count <= 16384);
        const auto &gate = target.gates.at(wire - target.input_count);
        pending.push_back(gate.left);
        if (gate.right != kNoWire) pending.push_back(gate.right);
    }
    PayloadCircuit cone{.shape = target.shape,
                        .input_count = target.input_count,
                        .plaintexts = target.plaintexts};
    std::vector<WireId> remap(target.wire_count(), kNoWire);
    for (WireId input = 0; input < target.input_count; ++input)
        remap[input] = input;
    for (std::size_t index = 0; index < target.gates.size(); ++index) {
        const auto wire = target.input_count + index;
        if (!retained[wire]) continue;
        auto gate = target.gates[index];
        gate.left = remap[gate.left];
        if (gate.right != kNoWire) gate.right = remap[gate.right];
        remap[wire] = cone.input_count + cone.gates.size();
        cone.gates.push_back(gate);
    }
    cone.outputs = {remap[root]};
    cone.validate();
    return cone;
}

// One fixed dependency cone per target keeps this regression bounded. It
// retains production inputs, plaintext masks, rotations, and level choices;
// passing these samples does not certify the complete target computation.
inline void check_no_integrity_target_noise(std::string_view name) {
    using namespace bench;
    using namespace fhe;
    using namespace payload;
    using Backend = SealBackend;
    const auto selected = benchmark_payload_profile(name);
    CHECK(selected.is_target());
    constexpr std::size_t slots = std::size_t{1} << 14U;
    const auto spec = benchmark_payload_workload_spec(
        selected, PayloadShape::wide(slots));
    const auto target = make_payload_circuit(spec);
    const auto target_circuit = compile(target);
    const auto parameters = no_integrity_seal_parameters(selected);
    std::cout << "[INFO] " << name << " data_bits="
              << no_integrity_data_modulus_bits(parameters)
              << " key_bits=" << no_integrity_key_modulus_bits(parameters)
              << " data_primes=";
    for (const auto prime : parameters.exact_data_primes)
        std::cout << prime << ',';
    std::cout << " special_prime=" << parameters.exact_special_prime
              << '\n' << std::flush;
    const auto plan = FheEvaluationPlan::at_evaluation_levels(
        target_circuit, parameters.fresh_rns_limbs - 1U);
    const auto inputs = make_workload_inputs(spec);
    const bool pyramid = selected.tier == BenchmarkPayloadTier::TargetMulHeavy;
    const WireId root = pyramid ? 1042862 : 917569;
    const std::size_t final_product_count = pyramid ? 3766 : 65536;
    std::vector<WireId> pending = target.outputs;
    std::size_t products = 0;
    bool found_root = false;
    while (!pending.empty()) {
        const auto wire = pending.back();
        pending.pop_back();
        CHECK(wire >= target.input_count);
        const auto &gate = target.gates.at(wire - target.input_count);
        if (gate.op == GateOp::Add) {
            pending.push_back(gate.left);
            pending.push_back(gate.right);
        } else {
            CHECK(gate.op == GateOp::Mul);
            ++products;
            found_root |= wire == root;
        }
    }
    CHECK(products == final_product_count);
    CHECK(found_root);
    const auto cone = no_integrity_target_cone(target, root);
    CHECK(cone.gates.size() == (pyramid ? 925U : 6307U));
    const auto circuit = compile(cone);
    const auto stats = analyze(cone);
    CHECK(stats.ct_ct_multiplicative_depth == 8U);
    CHECK(!pyramid || (stats.rotate_gates == 40U &&
                      stats.mul_plain_gates == 23U));
    CHECK(circuit.layers.size() == target_circuit.layers.size());
    for (std::size_t layer = 0; layer < circuit.layers.size(); ++layer)
        CHECK(layer_kind(circuit.layers[layer]) ==
              layer_kind(target_circuit.layers[layer]));
    plan.validate(circuit);
    CHECK(plan == FheEvaluationPlan::at_evaluation_levels(
                      circuit, parameters.fresh_rns_limbs - 1U));
    std::uint64_t plain_bytes = 0;
    for (const auto &layer : circuit.layers)
        plain_bytes += layer_dimensions(layer).padded_size *
                       std::uint64_t{slots} * sizeof(Fp);
    CHECK(plain_bytes <= (std::uint64_t{4} << 30U));
    const auto plain = synthesize_trace(cone, circuit, inputs);
    const auto storage = canonical_trace_storage_layout(circuit);
    auto contexts = Backend::create(parameters);
    CHECK(parameters.security_level == (pyramid ? seal::sec_level_type::none
                                                : seal::sec_level_type::tc128));
    CHECK(parameters.max_key_modulus_bits == (pyramid ? 555U : 438U));
    CHECK(Backend::fresh_ciphertext_modulus_bits(contexts.eval) ==
          no_integrity_data_modulus_bits(parameters));
    CHECK(Backend::key_modulus_bits(contexts.eval) ==
          no_integrity_key_modulus_bits(parameters));
    CHECK(Backend::fresh_ciphertext_modulus_bits(contexts.eval) ==
          (pyramid ? 500U : 398U));
    CHECK(Backend::key_modulus_bits(contexts.eval) == (pyramid ? 555U : 438U));
    auto encrypted = encrypt_wide_payload_inputs<Backend>(
        contexts.client, cone, inputs);
    std::vector<FheValue<Backend>> working;
    for (auto &ciphertext : encrypted)
        working.push_back(FheValue<Backend>::from_ciphertext(
            std::move(ciphertext)));
    encrypted.clear();
    int minimum_budget = std::numeric_limits<int>::max();
    const auto inspect = [&](std::size_t layer, std::size_t limbs,
                             std::string_view phase) {
        for (std::size_t ordinal = 0; ordinal < working.size(); ++ordinal) {
            const auto &value = working[ordinal];
            const auto &expected = plain.layers[layer][
                storage[layer].representative_padded_index_of(ordinal)];
            if (!value.is_encrypted()) {
                CHECK(value.plaintext().materialize(slots) == expected);
                continue;
            }
            const auto &ciphertext = value.ciphertext();
            CHECK(Backend::rns_limb_count(contexts.eval, ciphertext) == limbs);
            const int budget = Backend::invariant_noise_budget(
                contexts.client, ciphertext);
            const bool matches =
                Backend::decrypt(contexts.client, ciphertext) == expected;
            minimum_budget = std::min(minimum_budget, budget);
            if (budget < 15 || !matches) {
                throw CheckFailure(
                    "noIntegrity " + std::string(name) + " layer=" +
                    std::to_string(layer) + " " + std::string(phase) +
                    " budget=" + std::to_string(budget) +
                    " plaintext_matches=" + (matches ? "yes" : "no"));
            }
        }
    };
    inspect(circuit.layers.size() - 1U, parameters.fresh_rns_limbs, "input");
    for (std::size_t source = circuit.layers.size() - 1U; source > 0; --source) {
        const auto layer = source - 1U;
        working = fhe_evaluation_detail::evaluate_layer<
            Backend, fhe_evaluation_detail::WideLayout>(
                contexts.eval, circuit, layer, working,
                storage[source], storage[layer]);
        inspect(layer, plan.trace.required_mult_depth_by_layer[source] + 1U,
                "before-switch");
        for (std::size_t drop = 0;
             drop < plan.modulus_switches_after_layer[layer]; ++drop)
            for (auto &value : working)
                value_mod_switch_to_next<Backend>(contexts.eval, value);
        inspect(layer, plan.trace.required_mult_depth_by_layer[layer] + 1U,
                "after-switch");
    }
    // Correlated copies stress the full final reduction's addition count.
    auto sum = FheValue<Backend>::public_zero();
    auto term = working.at(0);
    for (auto count = final_product_count; count != 0; count >>= 1U) {
        if (count & 1U) sum = value_add<Backend>(contexts.eval, sum, term);
        if (count > 1U) term = value_add<Backend>(contexts.eval, term, term);
    }
    auto expected = plain.layers.front().front();
    for (auto &value : expected) value *= Fp(final_product_count);
    const int sum_budget = Backend::invariant_noise_budget(
        contexts.client, sum.ciphertext());
    std::cout << "[INFO] " << name << " root=" << root
              << " minimum_payload_budget=" << minimum_budget
              << " coherent_sum_budget=" << sum_budget << " bits\n";
    CHECK(Backend::rns_limb_count(contexts.eval, sum.ciphertext()) == 1U);
    CHECK(Backend::decrypt(contexts.client, sum.ciphertext()) == expected);
    CHECK(sum_budget >= 15);
    require_no_integrity_output_noise_budget(sum_budget);
}

} // namespace laminate::test

#endif // LAMINATE_TESTS_NO_INTEGRITY_TARGET_NOISE_HPP
