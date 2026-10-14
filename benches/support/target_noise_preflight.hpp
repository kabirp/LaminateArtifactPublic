#ifndef LAMINATE_BENCHES_TARGET_NOISE_PREFLIGHT_HPP
#define LAMINATE_BENCHES_TARGET_NOISE_PREFLIGHT_HPP

#include "laminate/fhe/seal_backend.hpp"
#include "laminate/payload/compiler.hpp"
#include "laminate/payload/evaluator.hpp"
#include "laminate/payload/input_encryption.hpp"
#include "laminate/payload/wide_fhe_evaluator.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <ostream>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace laminate::bench {

// Bounded target cones retain their masks, rotations, and inputs. These
// samples do not certify the complete million-gate circuit or its proof.
inline constexpr std::array<payload::WireId, 8> kPyramidNoisePreflightRoots{
    1042862, 1044489, 1043854, 1043072, 1043653,
    1041858, 1044624, 1042018};
inline constexpr std::size_t kPyramidFinalProductCount = 3766;

inline payload::PayloadCircuit pyramid_noise_preflight_cone(
    const payload::PayloadCircuit &target, payload::WireId root) {
    using namespace payload;
    if (target.shape != PayloadShape::wide(16384) || target.input_count != 64 ||
        target.gates.size() != 1048576 || target.outputs.size() != 1)
        throw std::invalid_argument("target noise preflight: unexpected pyramid geometry");
    std::vector<WireId> pending = target.outputs;
    std::size_t products = 0;
    bool found_root = false;
    while (!pending.empty()) {
        const auto wire = pending.back();
        pending.pop_back();
        const auto &gate = target.gates.at(wire - target.input_count);
        if (gate.op == GateOp::Add) {
            pending.push_back(gate.left);
            pending.push_back(gate.right);
        } else if (gate.op == GateOp::Mul) {
            ++products;
            found_root |= wire == root;
        } else {
            throw std::logic_error("target noise preflight: final layer is not a product sum");
        }
    }
    if (products != kPyramidFinalProductCount || !found_root)
        throw std::logic_error("target noise preflight: selected final product changed");

    std::vector<bool> retained(target.wire_count());
    pending = {root};
    std::size_t retained_count = 0;
    while (!pending.empty()) {
        const auto wire = pending.back();
        pending.pop_back();
        if (wire < target.input_count || retained[wire]) continue;
        retained[wire] = true;
        if (++retained_count > 4096)
            throw std::logic_error("target noise preflight: cone exceeds its gate cap");
        const auto &gate = target.gates[wire - target.input_count];
        pending.push_back(gate.left);
        if (gate.right != kNoWire) pending.push_back(gate.right);
    }
    PayloadCircuit cone{.shape = target.shape, .input_count = target.input_count,
                        .plaintexts = target.plaintexts};
    std::vector<WireId> remap(target.wire_count(), kNoWire);
    for (std::size_t input = 0; input < target.input_count; ++input) remap[input] = input;
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

// Uses a disposable, honest encryption context. It neither selects parameters
// nor retries randomness, and never supplies keys or ciphertexts to the run.
// Failure aborts setup before GateMLE preprocessing. PASS covers these exact
// samples only; the real run must still verify normally.
inline void require_target_pyramid_noise_preflight(
    const payload::PayloadCircuit &target,
    const payload::LayeredCircuit &target_circuit,
    const std::vector<fhe::SlotVector> &inputs,
    const fhe::SealParameters &parameters,
    const payload::FheEvaluationPlan &target_plan,
    std::uint64_t available_resident_bytes, std::ostream &report) {
    using namespace payload;
    using namespace fhe;
    using Backend = SealBackend;
    // Reserve an independent phase for the disposable SEAL key context, the
    // complete small plaintext trace, adjacent ciphertext layers and a proof
    // copy, in addition to the caller's already-resident target description.
    // This is an engineering admission allowance, not a measured RSS bound.
    constexpr std::uint64_t kPreflightResidentAllowance = std::uint64_t{16} << 30U;
    if (available_resident_bytes < kPreflightResidentAllowance)
        throw std::runtime_error("target noise preflight requires a 16 GiB resident allowance");
    if (parameters.poly_modulus_degree != 16384 || inputs.size() != target.input_count ||
        parameters.fresh_rns_limbs != 11 || !parameters.generate_galois_keys ||
        target_circuit.layers.size() != 18)
        throw std::invalid_argument("target noise preflight: unsupported Base target parameters");
    target_plan.validate(target_circuit);
    auto contexts = Backend::create(parameters);
    for (const auto root : kPyramidNoisePreflightRoots) {
        const auto cone = pyramid_noise_preflight_cone(target, root);
        const auto circuit = compile(cone);
        if (circuit.layers.size() != target_circuit.layers.size())
            throw std::logic_error("target noise preflight: cone depth differs from target");
        for (std::size_t layer = 0; layer < circuit.layers.size(); ++layer)
            if (layer_kind(circuit.layers[layer]) != layer_kind(target_circuit.layers[layer]))
                throw std::logic_error("target noise preflight: cone layer kinds differ from target");
        // Execute the full target's committed levels, not a schedule selected
        // independently for the smaller cone.
        target_plan.validate(circuit);
        const auto storage = canonical_trace_storage_layout(circuit);
        std::uint64_t plaintext_trace_bytes = 0;
        for (const auto &layer : storage)
            if (layer.stored_wire_count > 1024)
                throw std::logic_error("target noise preflight: cone exceeds its ciphertext cap");
        for (const auto &layer : circuit.layers)
            plaintext_trace_bytes += layer_dimensions(layer).padded_size *
                std::uint64_t{16384} * sizeof(Fp);
        if (plaintext_trace_bytes > (std::uint64_t{2} << 30U))
            throw std::logic_error("target noise preflight: plaintext trace exceeds its 2 GiB cap");
        const auto plain = synthesize_trace(cone, circuit, inputs);
        auto encrypted = encrypt_wide_payload_inputs<Backend>(contexts.client, cone, inputs);
        std::vector<FheValue<Backend>> working;
        for (auto &value : encrypted)
            working.push_back(FheValue<Backend>::from_ciphertext(std::move(value)));
        encrypted.clear();
        int minimum_budget = std::numeric_limits<int>::max();
        const auto inspect = [&](const auto &values, std::size_t layer,
                                 std::size_t expected_limbs, const char *phase) {
            for (std::size_t ordinal = 0; ordinal < values.size(); ++ordinal) {
                const auto &value = values[ordinal];
                const auto padded = storage[layer].representative_padded_index_of(ordinal);
                const auto &expected = plain.layers[layer][padded];
                bool matches = false;
                int budget = std::numeric_limits<int>::max();
                if (value.is_encrypted()) {
                    const auto &ciphertext = value.ciphertext();
                    if (Backend::rns_limb_count(contexts.eval, ciphertext) != expected_limbs)
                        throw std::logic_error("target noise preflight: target level mismatch");
                    budget = Backend::invariant_noise_budget(contexts.client, ciphertext);
                    minimum_budget = std::min(minimum_budget, budget);
                    matches = Backend::decrypt(contexts.client, ciphertext) == expected;
                } else {
                    matches = value.plaintext().materialize(parameters.poly_modulus_degree) == expected;
                }
                if (budget == 0 || !matches)
                    throw std::runtime_error("target ciphertext preflight FAILED: root " +
                        std::to_string(root) + ", layer " + std::to_string(layer) + ", " + phase +
                        ", noise budget " + std::to_string(budget) +
                        ", plaintext matches=" + (matches ? "yes" : "no") +
                        "; refusing expensive preprocessing");
            }
        };
        inspect(working, circuit.layers.size() - 1U, parameters.fresh_rns_limbs, "input");
        const auto inspect_proof_source = [&](std::size_t layer, std::size_t natural_limbs) {
            auto proof_source = working;
            const auto proof_limbs = target_plan.proof_ingress_mult_depth_by_layer[layer] + 1U;
            for (auto limbs = natural_limbs; limbs > proof_limbs; --limbs)
                for (auto &value : proof_source) value_mod_switch_to_next<Backend>(contexts.eval, value);
            inspect(proof_source, layer, proof_limbs, "proof ingress");
        };
        inspect_proof_source(circuit.layers.size() - 1U, parameters.fresh_rns_limbs);
        for (std::size_t source = circuit.layers.size() - 1U; source > 0; --source) {
            const auto layer = source - 1U;
            working = fhe_evaluation_detail::evaluate_layer<Backend, fhe_evaluation_detail::WideLayout>(
                contexts.eval, circuit, layer, working, storage[source], storage[layer]);
            inspect(working, layer, target_plan.trace.required_mult_depth_by_layer[source] + 1U,
                    "before switch");
            for (std::size_t drop = 0; drop < target_plan.modulus_switches_after_layer[layer]; ++drop)
                for (auto &value : working) value_mod_switch_to_next<Backend>(contexts.eval, value);
            const auto natural_limbs = target_plan.trace.required_mult_depth_by_layer[layer] + 1U;
            inspect(working, layer, natural_limbs, "after switch");
            if (layer != 0) inspect_proof_source(layer, natural_limbs);
        }
        // A coherent sum upper-stresses the addition count of the actual final
        // affine layer without materializing all 3,766 dependency cones.
        auto sum = FheValue<Backend>::public_zero();
        auto term = working.at(0);
        for (auto remaining = kPyramidFinalProductCount; remaining != 0; remaining >>= 1U) {
            if ((remaining & 1U) != 0) sum = value_add<Backend>(contexts.eval, sum, term);
            if (remaining > 1U) term = value_add<Backend>(contexts.eval, term, term);
        }
        auto expected_sum = plain.layers.front().front();
        for (auto &value : expected_sum) value *= Fp(kPyramidFinalProductCount);
        const auto sum_budget = Backend::invariant_noise_budget(contexts.client, sum.ciphertext());
        if (sum_budget == 0 || Backend::decrypt(contexts.client, sum.ciphertext()) != expected_sum)
            throw std::runtime_error("target ciphertext preflight FAILED at final-sum stress; "
                                     "refusing expensive preprocessing");
        report << "NOISE PREFLIGHT: root=" << root << " all sampled plaintexts match; "
               << "minimum payload/proof-ingress budget=" << minimum_budget
               << " bits; final-sum budget=" << sum_budget << " bits\n" << std::flush;
    }
}

} // namespace laminate::bench

#endif
