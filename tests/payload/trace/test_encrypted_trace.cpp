#include "test_helpers.hpp"

#include "laminate/fhe/mock_backend.hpp"
#include "laminate/gkr/laned.hpp"
#include "laminate/gkr/detail/base/validation/request.hpp"
#include "laminate/gkr/detail/laned/validation/request.hpp"
#include "laminate/payload/compiler.hpp"
#include "laminate/payload/trace/encrypted_trace.hpp"
#include "laminate/payload/trace/fhe_trace_id.hpp"
#include "laminate/payload/laned_fhe_evaluator.hpp"
#include "laminate/payload/input_encryption.hpp"
#include "laminate/payload/trace/trace_crypto.hpp"
#include "laminate/transcript/hash.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string_view>
#include <utility>
#include <vector>

namespace {

using laminate::Fp;
using laminate::fhe::MockBackend;
using laminate::fhe::MockParameters;
using laminate::fhe::SlotVector;
using laminate::payload::LayeredCircuit;
using laminate::payload::FheEvaluationPlan;
using laminate::payload::PayloadBuilder;
using laminate::payload::PayloadCircuit;
using laminate::payload::PayloadShape;
using laminate::payload::PlainTrace;
using laminate::payload::TraceEncryptionPlan;
using laminate::fhe::FheValue;

void append_u64(std::vector<std::uint8_t> &output, std::size_t value) {
    for (std::size_t byte = 0; byte < 8; ++byte) {
        output.push_back(static_cast<std::uint8_t>(
            (static_cast<std::uint64_t>(value) >> (8U * byte)) & 0xffU));
    }
}

laminate::Digest reference_trace_id_encoding(
    const PayloadCircuit &payload, const LayeredCircuit &layered,
    const std::vector<MockBackend::Ciphertext> &encrypted_inputs) {
    static constexpr std::string_view label =
        "LaminateImpl/FheEvaluatedTrace/v1";
    std::vector<std::uint8_t> encoded;
    append_u64(encoded, label.size());
    encoded.insert(encoded.end(), label.begin(), label.end());
    const laminate::Digest circuit_id =
        laminate::payload::combined_digest(payload, layered);
    encoded.insert(encoded.end(), circuit_id.begin(), circuit_id.end());
    append_u64(encoded, encrypted_inputs.size());
    for (const auto &ciphertext : encrypted_inputs) {
        const std::vector<std::uint8_t> bytes =
            MockBackend::serialize(ciphertext);
        append_u64(encoded, bytes.size());
        encoded.insert(encoded.end(), bytes.begin(), bytes.end());
    }
    return laminate::sha256(encoded);
}

bool throws_invalid_argument(const auto &body) {
    try {
        body();
    } catch (const std::invalid_argument &) {
        return true;
    }
    return false;
}

bool throws_logic_error(const auto &body) {
    try {
        body();
    } catch (const std::logic_error &) {
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

PayloadCircuit make_laned_payload() {
    PayloadBuilder builder(PayloadShape::laned(4, 16), 2);
    const std::size_t three = builder.add_scalar_plaintext(Fp(3));
    const std::size_t seven = builder.add_scalar_plaintext(Fp(7));
    const std::size_t mask = builder.add_plaintext(
        {Fp(2), Fp(3), Fp(5), Fp(7)});
    const auto first = builder.mul(0, 1);
    const auto scaled = builder.mul_plain(first, three);
    const auto mixed = builder.add_plain(builder.add(scaled, 0), seven);
    const auto masked = builder.mul(builder.add_plain(mixed, mask), first);
    const auto output = builder.mul(masked, first);
    builder.set_outputs({output});
    return builder.finish();
}

PayloadCircuit make_wide_payload() {
    PayloadBuilder builder(PayloadShape::wide(8), 1);
    const auto rotated = builder.rotate(0, 3);
    const auto output = builder.mul(0, rotated);
    builder.set_outputs({output});
    return builder.finish();
}

PayloadCircuit make_depth_eight_laned_payload() {
    PayloadBuilder builder(PayloadShape::laned(4, 16), 1);
    std::size_t wire = 0;
    for (std::size_t depth = 0; depth < 8; ++depth) {
        wire = builder.mul(wire, wire);
    }
    builder.set_outputs({wire});
    return builder.finish();
}

void test_public_zero_tag_has_no_ciphertext() {
    const auto public_zero = FheValue<MockBackend>::public_zero();
    CHECK(public_zero.is_public_zero());
    CHECK(throws_logic_error([&] { (void)public_zero.ciphertext(); }));

    auto movable_zero = FheValue<MockBackend>::public_zero();
    CHECK(throws_logic_error(
        [&] { (void)std::move(movable_zero).take_ciphertext(); }));
}

void test_laned_periodic_round_trip_and_levels() {
    const PayloadCircuit payload = make_laned_payload();
    const LayeredCircuit layered = laminate::payload::compile(payload);
    const PlainTrace plain = laminate::payload::synthesize_trace(
        payload, layered,
        std::vector<SlotVector>{sequence(4, 2), sequence(4, 9)});
    auto contexts =
        MockBackend::create(MockParameters{.slot_count = 16});
    MockBackend::reset_counts(contexts.eval);

    const TraceEncryptionPlan plan =
        TraceEncryptionPlan::uniform(layered, 3);
    const auto encrypted =
        laminate::payload::encrypt_compact_synthetic_trace<MockBackend>(
        contexts.eval, contexts.client, payload, layered, plain, plan);
    CHECK(encrypted.provenance == plain.provenance);
    CHECK(encrypted.circuit_id ==
          laminate::payload::combined_digest(payload, layered));
    CHECK(encrypted.trace_id ==
          laminate::payload::digest(plain, encrypted.circuit_id));
    CHECK(encrypted.layers.size() == plain.layers.size());
    for (const auto &layer : encrypted.layers) {
        for (const auto &wire : layer.wires) {
            CHECK(wire.is_encrypted());
            CHECK(wire.ciphertext().rns_limbs == 4);
            const SlotVector physical = MockBackend::decrypt(
                contexts.client, wire.ciphertext());
            for (std::size_t slot = 4; slot < 16; ++slot) {
                CHECK(physical[slot] == physical[slot % 4]);
            }
        }
    }
    CHECK(laminate::payload::decrypt_trace_layers<MockBackend>(
              contexts.client, layered, encrypted) == plain.layers);
}

void test_wide_round_trip() {
    const PayloadCircuit payload = make_wide_payload();
    const LayeredCircuit layered = laminate::payload::compile(payload);
    const PlainTrace plain = laminate::payload::synthesize_trace(
        payload, layered, std::vector<SlotVector>{sequence(8, 1)});
    auto contexts = MockBackend::create(MockParameters{.slot_count = 8});
    const auto encrypted = laminate::payload::encrypt_compact_synthetic_trace<MockBackend>(
        contexts.eval, contexts.client, payload, layered, plain,
        TraceEncryptionPlan::uniform(layered, 2));
    CHECK(laminate::payload::decrypt_trace_layers<MockBackend>(
              contexts.client, layered, encrypted) == plain.layers);
}

void test_laned_fhe_evaluation_matches_plain_trace() {
    const PayloadCircuit payload = make_laned_payload();
    const LayeredCircuit layered = laminate::payload::compile(payload);
    const std::vector<SlotVector> inputs{sequence(4, 2), sequence(4, 9)};
    const PlainTrace expected =
        laminate::payload::synthesize_trace(payload, layered, inputs);
    auto contexts = MockBackend::create(MockParameters{
        .slot_count = 16,
        .fresh_rns_limbs = 8,
        .bits_per_limb = 80,
    });
    const auto encrypted_inputs =
        laminate::payload::encrypt_laned_payload_inputs<MockBackend>(
            contexts.client, payload, inputs);
    const auto expected_id =
        laminate::payload::fhe_evaluated_trace_id<MockBackend>(
            payload, layered, encrypted_inputs);
    CHECK(expected_id ==
          laminate::payload::prevalidated_trace_identity::
              validated_fhe_evaluated_trace_id<MockBackend>(
                  laminate::payload::combined_digest(payload, layered),
                  payload.input_count, encrypted_inputs));
    CHECK(expected_id ==
          reference_trace_id_encoding(payload, layered, encrypted_inputs));
    std::vector<MockBackend::Ciphertext> reordered_inputs = encrypted_inputs;
    std::swap(reordered_inputs[0], reordered_inputs[1]);
    CHECK(laminate::payload::fhe_evaluated_trace_id<MockBackend>(
              payload, layered, reordered_inputs) != expected_id);

    PayloadBuilder changed_builder(PayloadShape::laned(4, 16), 2);
    const auto changed = changed_builder.mul(0, 1);
    changed_builder.set_outputs({changed});
    const PayloadCircuit changed_payload = changed_builder.finish();
    const LayeredCircuit changed_layered =
        laminate::payload::compile(changed_payload);
    CHECK(laminate::payload::fhe_evaluated_trace_id<MockBackend>(
              changed_payload, changed_layered, encrypted_inputs) !=
          expected_id);
    CHECK(throws_invalid_argument([&] {
        (void)laminate::payload::fhe_evaluated_trace_id<MockBackend>(
            payload, changed_layered, encrypted_inputs);
    }));

    MockBackend::reset_counts(contexts.eval);
    const auto evaluated =
        laminate::payload::evaluate_laned_fhe_trace<MockBackend>(
            contexts.eval, payload, layered, encrypted_inputs,
            FheEvaluationPlan::without_payload_switches(layered, 3));
    CHECK(MockBackend::counts(contexts.eval).decrypt == 0);
    CHECK(MockBackend::counts(contexts.eval).mul_plain_scalar > 0);
    CHECK(MockBackend::counts(contexts.eval).mul_plain_vector == 0);
    CHECK(MockBackend::counts(contexts.eval).add_plain > 0);
    CHECK(evaluated.provenance ==
          laminate::payload::TraceProvenance::FheEvaluated);
    CHECK(evaluated.trace_id == expected_id);
    CHECK(evaluated.circuit_id ==
          laminate::payload::combined_digest(payload, layered));
    const auto support =
        laminate::payload::canonical_trace_wire_support(layered);
    const auto storage =
        laminate::payload::canonical_trace_storage_layout(layered);
    for (std::size_t layer = 0; layer < support.size(); ++layer) {
        CHECK(evaluated.layers[layer].wires.size() ==
              storage[layer].stored_wire_count);
    }
    CHECK(laminate::payload::decrypt_trace_layers<MockBackend>(
              contexts.client, layered, evaluated) == expected.layers);
}

void test_laned_fhe_evaluation_switch_schedule() {
    const PayloadCircuit payload = make_laned_payload();
    const LayeredCircuit layered = laminate::payload::compile(payload);
    const std::vector<SlotVector> inputs{sequence(4, 4), sequence(4, 13)};
    auto contexts = MockBackend::create(MockParameters{
        .slot_count = 16,
        .fresh_rns_limbs = 12,
        .bits_per_limb = 300,
    });
    const auto encrypted_inputs =
        laminate::payload::encrypt_laned_payload_inputs<MockBackend>(
            contexts.client, payload, inputs);
    const FheEvaluationPlan natural_levels =
        FheEvaluationPlan::at_evaluation_levels(layered, 11, 1, 2);
    CHECK(natural_levels.modulus_switches_after_layer ==
          std::vector<std::size_t>({0, 0, 0, 1, 0, 1, 0, 0}));
    CHECK(natural_levels.trace.required_mult_depth_by_layer ==
          std::vector<std::size_t>({9, 9, 9, 9, 10, 10, 11, 11}));
    CHECK(natural_levels.proof_ingress_mult_depth_by_layer ==
          natural_levels.trace.required_mult_depth_by_layer);

    const FheEvaluationPlan one_switch =
        FheEvaluationPlan::at_evaluation_levels(layered, 11, 1, 1);
    CHECK(one_switch.modulus_switches_after_layer ==
          std::vector<std::size_t>({0, 0, 0, 0, 0, 1, 0, 0}));
    CHECK(one_switch.trace.required_mult_depth_by_layer ==
          std::vector<std::size_t>({10, 10, 10, 10, 10, 10, 11, 11}));

    const FheEvaluationPlan proof_floor_limited =
        FheEvaluationPlan::packed_payload_with_prompt_switches(
                layered, 11,
                std::vector<std::size_t>(layered.layers.size(), 5));
    CHECK(proof_floor_limited.modulus_switches_after_layer ==
          std::vector<std::size_t>({5, 1, 0, 1, 0, 4, 0, 0}));
    CHECK(proof_floor_limited.trace.required_mult_depth_by_layer ==
          std::vector<std::size_t>({0, 5, 6, 6, 7, 7, 11, 11}));

    const LayeredCircuit depth_eight =
        laminate::payload::compile(make_depth_eight_laned_payload());
    std::vector<std::size_t> depth_eight_floors(depth_eight.layers.size(),
                                                2);
    depth_eight_floors.front() = 1000; // Output is not a proof source.
    const FheEvaluationPlan depth_eight_plan =
        FheEvaluationPlan::packed_payload_with_prompt_switches(
                depth_eight, 10, depth_eight_floors);
    CHECK(depth_eight_plan.modulus_switches_after_layer ==
          std::vector<std::size_t>({2, 1, 0, 1, 0, 1, 0, 1, 0,
                                    1, 0, 1, 0, 1, 0, 1, 0, 0}));
    CHECK(depth_eight_plan.trace.required_mult_depth_by_layer ==
          std::vector<std::size_t>({0, 2, 3, 3, 4, 4, 5, 5, 6,
                                    6, 7, 7, 8, 8, 9, 9, 10, 10}));
    CHECK(depth_eight_plan.proof_ingress_mult_depth_by_layer.front() == 0);

    // A late source can pin one multiplication at level 10 without
    // preventing lower layers from resuming prompt drops. This distinguishes
    // per-source floors from one global floor.
    std::vector<std::size_t> nonuniform_floors(depth_eight.layers.size(), 2);
    nonuniform_floors[14] = 10;
    const FheEvaluationPlan nonuniform_plan =
        FheEvaluationPlan::packed_payload_with_prompt_switches(
            depth_eight, 11, nonuniform_floors);
    CHECK(nonuniform_plan.trace.required_mult_depth_by_layer ==
          std::vector<std::size_t>({0, 2, 3, 3, 4, 4, 5, 5, 6,
                                    6, 7, 7, 8, 8, 10, 10, 11, 11}));
    CHECK(nonuniform_plan.modulus_switches_after_layer ==
          std::vector<std::size_t>({2, 1, 0, 1, 0, 1, 0, 1, 0,
                                    1, 0, 1, 0, 2, 0, 1, 0, 0}));
    CHECK(nonuniform_plan.proof_ingress_mult_depth_by_layer[14] == 10);

    MockBackend::reset_counts(contexts.eval);
    const auto evaluated =
        laminate::payload::evaluate_laned_fhe_trace<MockBackend>(
            contexts.eval, payload, layered, encrypted_inputs,
            proof_floor_limited);
    CHECK(MockBackend::counts(contexts.eval).mod_switch > 0);
    CHECK(MockBackend::rns_limb_count(
              contexts.eval,
              evaluated.layers.front().wires.front().ciphertext()) == 1);
    CHECK(laminate::payload::decrypt_trace_layers<MockBackend>(
              contexts.client, layered, evaluated) ==
          laminate::payload::synthesize_trace(payload, layered, inputs)
              .layers);
}

void test_laned_fhe_evaluation_rejects_wide_and_bad_plan() {
    const PayloadCircuit wide = make_wide_payload();
    const LayeredCircuit wide_layered = laminate::payload::compile(wide);
    auto wide_contexts =
        MockBackend::create(MockParameters{.slot_count = 8});
    const auto wide_input = MockBackend::encrypt(
        wide_contexts.client, sequence(8, 1));
    CHECK(throws_invalid_argument([&] {
        (void)laminate::payload::evaluate_laned_fhe_trace<MockBackend>(
            wide_contexts.eval, wide, wide_layered,
            std::span<const MockBackend::Ciphertext>(&wide_input, 1),
            FheEvaluationPlan::without_payload_switches(wide_layered, 1));
    }));

    const PayloadCircuit laned = make_laned_payload();
    const LayeredCircuit laned_layered = laminate::payload::compile(laned);
    auto laned_contexts =
        MockBackend::create(MockParameters{.slot_count = 16});
    const std::vector<SlotVector> inputs{sequence(4, 2), sequence(4, 9)};
    const auto encrypted_inputs =
        laminate::payload::encrypt_laned_payload_inputs<MockBackend>(
            laned_contexts.client, laned, inputs);
    FheEvaluationPlan malformed =
        FheEvaluationPlan::without_payload_switches(laned_layered, 1);
    malformed.modulus_switches_after_layer.pop_back();
    CHECK(throws_invalid_argument([&] {
        (void)laminate::payload::evaluate_laned_fhe_trace<MockBackend>(
            laned_contexts.eval, laned, laned_layered, encrypted_inputs,
            malformed);
    }));

    malformed =
        FheEvaluationPlan::without_payload_switches(laned_layered, 1);
    malformed.proof_ingress_mult_depth_by_layer.pop_back();
    CHECK(throws_invalid_argument([&] { malformed.validate(laned_layered); }));

    malformed =
        FheEvaluationPlan::without_payload_switches(laned_layered, 1);
    ++malformed.proof_ingress_mult_depth_by_layer.front();
    CHECK(throws_invalid_argument([&] { malformed.validate(laned_layered); }));

    malformed =
        FheEvaluationPlan::without_payload_switches(laned_layered, 1);
    --malformed.proof_ingress_mult_depth_by_layer.front();
    CHECK(throws_invalid_argument([&] { malformed.validate(laned_layered); }));

    std::vector<std::size_t> proof_floors(laned_layered.layers.size(), 1);
    proof_floors[1] = 5;
    CHECK(throws_invalid_argument([&] {
        (void)FheEvaluationPlan::
            packed_payload_with_prompt_switches(
                laned_layered, 4, proof_floors);
    }));
    CHECK(throws_invalid_argument([&] {
        (void)FheEvaluationPlan::
            packed_payload_with_prompt_switches(
                laned_layered, std::numeric_limits<std::size_t>::max(),
                proof_floors);
    }));
    proof_floors.pop_back();
    CHECK(throws_invalid_argument([&] {
        (void)FheEvaluationPlan::
            packed_payload_with_prompt_switches(
                laned_layered, 4, proof_floors);
    }));

    const LayeredCircuit depth_eight =
        laminate::payload::compile(make_depth_eight_laned_payload());
    CHECK(throws_invalid_argument([&] {
        (void)FheEvaluationPlan::packed_payload_with_prompt_switches(
            depth_eight, 9,
            std::vector<std::size_t>(depth_eight.layers.size(), 2));
    }));
}

void test_plan_and_backend_mismatch_reject() {
    const PayloadCircuit payload = make_wide_payload();
    const LayeredCircuit layered = laminate::payload::compile(payload);
    const PlainTrace plain = laminate::payload::synthesize_trace(
        payload, layered, std::vector<SlotVector>{sequence(8, 1)});
    auto contexts = MockBackend::create(MockParameters{.slot_count = 8});

    PlainTrace mislabeled = plain;
    mislabeled.provenance =
        laminate::payload::TraceProvenance::FheEvaluated;
    MockBackend::reset_counts(contexts.eval);
    CHECK(throws_invalid_argument([&] {
        (void)laminate::payload::encrypt_compact_synthetic_trace<MockBackend>(
            contexts.eval, contexts.client, payload, layered, mislabeled,
            TraceEncryptionPlan::uniform(layered, 1));
    }));
    CHECK(MockBackend::counts(contexts.eval).encrypt == 0);

    CHECK(throws_invalid_argument([&] {
        (void)laminate::payload::encrypt_compact_synthetic_trace<MockBackend>(
            contexts.eval, contexts.client, payload, layered, plain,
            TraceEncryptionPlan{{1}});
    }));

    auto wrong_contexts =
        MockBackend::create(MockParameters{.slot_count = 16});
    CHECK(throws_invalid_argument([&] {
        (void)laminate::payload::encrypt_compact_synthetic_trace<MockBackend>(
            wrong_contexts.eval, wrong_contexts.client, payload, layered,
            plain, TraceEncryptionPlan::uniform(layered, 1));
    }));
}

void test_nonperiodic_laned_ciphertext_rejects() {
    const PayloadCircuit payload = make_laned_payload();
    const LayeredCircuit layered = laminate::payload::compile(payload);
    const PlainTrace plain = laminate::payload::synthesize_trace(
        payload, layered,
        std::vector<SlotVector>{sequence(4, 2), sequence(4, 9)});
    auto contexts =
        MockBackend::create(MockParameters{.slot_count = 16});
    auto encrypted =
        laminate::payload::encrypt_compact_synthetic_trace<MockBackend>(
        contexts.eval, contexts.client, payload, layered, plain,
        TraceEncryptionPlan::uniform(layered, 1));
    encrypted.layers[0].wires[0].ciphertext().slots[7] += Fp::one();
    CHECK(throws_invalid_argument([&] {
        (void)laminate::payload::decrypt_trace_layers<MockBackend>(
            contexts.client, layered, encrypted);
    }));
}

void test_insufficient_budget_rejects() {
    const PayloadCircuit payload = make_wide_payload();
    const LayeredCircuit layered = laminate::payload::compile(payload);
    const PlainTrace plain = laminate::payload::synthesize_trace(
        payload, layered, std::vector<SlotVector>{sequence(8, 1)});
    auto contexts = MockBackend::create(MockParameters{.slot_count = 8});
    bool threw = false;
    try {
        (void)laminate::payload::encrypt_compact_synthetic_trace<MockBackend>(
            contexts.eval, contexts.client, payload, layered, plain,
            TraceEncryptionPlan::uniform(layered, 100));
    } catch (const std::invalid_argument &) {
        threw = true;
    }
    CHECK(threw);
}

void test_resident_validators_accept_virtual_padding() {
    {
        PayloadBuilder builder(PayloadShape::wide(8), 3);
        builder.set_outputs({builder.add(0, 1)});
        const PayloadCircuit payload = builder.finish();
        const LayeredCircuit layered = laminate::payload::compile(payload);
        const PlainTrace plain = laminate::payload::synthesize_trace(
            payload, layered,
            std::vector<SlotVector>{sequence(8, 1), sequence(8, 11),
                                    sequence(8, 21)});
        auto contexts = MockBackend::create(MockParameters{.slot_count = 8});
        const auto compact =
            laminate::payload::encrypt_compact_synthetic_trace<MockBackend>(
                contexts.eval, contexts.client, payload, layered, plain,
                TraceEncryptionPlan::uniform(layered, 1));
        laminate::gkr::base_detail::validate_trace_shape<MockBackend>(
            layered, compact);
    }
    {
        const PayloadCircuit payload = make_laned_payload();
        const LayeredCircuit layered = laminate::payload::compile(payload);
        const PlainTrace plain = laminate::payload::synthesize_trace(
            payload, layered,
            std::vector<SlotVector>{sequence(4, 2), sequence(4, 9)});
        auto contexts =
            MockBackend::create(MockParameters{.slot_count = 16});
        const auto compact =
            laminate::payload::encrypt_compact_synthetic_trace<MockBackend>(
                contexts.eval, contexts.client, payload, layered, plain,
                TraceEncryptionPlan::uniform(layered, 1));
        laminate::gkr::laned_detail::validate_trace_shape<MockBackend>(
            contexts.eval, layered, compact,
            std::vector<std::size_t>(layered.layers.size(), 2U));
    }
}

} // namespace

int main() {
    laminate::test::Runner runner("test_encrypted_trace");
    runner.run("public padding zero has no ciphertext accessor",
               test_public_zero_tag_has_no_ciphertext);
    runner.run("laned periodic encryption and level plan",
               test_laned_periodic_round_trip_and_levels);
    runner.run("wide encrypted trace round trip", test_wide_round_trip);
    runner.run("laned FHE evaluation matches the plain relation",
               test_laned_fhe_evaluation_matches_plain_trace);
    runner.run("laned FHE evaluation follows its switch schedule",
               test_laned_fhe_evaluation_switch_schedule);
    runner.run("laned FHE evaluation rejects unsupported requests",
               test_laned_fhe_evaluation_rejects_wide_and_bad_plan);
    runner.run("plan and backend mismatches reject",
               test_plan_and_backend_mismatch_reject);
    runner.run("nonperiodic laned ciphertext rejects",
               test_nonperiodic_laned_ciphertext_rejects);
    runner.run("insufficient encryption budget rejects",
               test_insufficient_budget_rejects);
    runner.run("resident GKR accepts compact traces with virtual padding",
               test_resident_validators_accept_virtual_padding);
    return runner.summary();
}
