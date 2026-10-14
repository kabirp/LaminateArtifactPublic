/// @file test_wide_fhe_evaluator.cpp
/// @brief Compact Wide payload evaluation on the exact Mock backend.

#include "test_helpers.hpp"

#include "laminate/fhe/mock_backend.hpp"
#include "laminate/payload/compiler.hpp"
#include "laminate/payload/storage/file_trace_store.hpp"
#include "laminate/payload/input_encryption.hpp"
#include "laminate/payload/trace.hpp"
#include "laminate/payload/trace/trace_wire_support.hpp"
#include "laminate/payload/wide_fhe_evaluator.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <system_error>
#include <vector>

namespace {

using laminate::Fp;
using laminate::fhe::MockBackend;
using laminate::fhe::MockParameters;
using laminate::fhe::SlotVector;
using namespace laminate::payload;

constexpr std::size_t kSlots = 8;

class TemporaryDirectory {
  public:
    TemporaryDirectory() {
        const auto stamp = std::chrono::steady_clock::now()
                               .time_since_epoch()
                               .count();
        for (std::size_t attempt = 0; attempt < 100; ++attempt) {
            path_ = std::filesystem::temp_directory_path() /
                    ("laminate-wide-evaluator-" + std::to_string(stamp) +
                     "-" + std::to_string(attempt));
            if (!std::filesystem::exists(path_)) {
                return;
            }
        }
        throw std::runtime_error("failed to select a temporary directory");
    }

    ~TemporaryDirectory() {
        std::error_code ignored;
        std::filesystem::remove_all(path_, ignored);
    }

    const std::filesystem::path &path() const { return path_; }

  private:
    std::filesystem::path path_;
};

SlotVector values(std::uint64_t seed) {
    SlotVector result;
    result.reserve(kSlots);
    for (std::size_t slot = 0; slot < kSlots; ++slot) {
        result.emplace_back(seed + 3 * slot + slot * slot);
    }
    return result;
}

PayloadCircuit mixed_wide_payload() {
    PayloadBuilder builder(PayloadShape::wide(kSlots), 3);
    const std::size_t scalar = builder.add_scalar_plaintext(Fp(3));
    const std::size_t mask = builder.add_plaintext(
        {Fp(2), Fp(3), Fp(5), Fp(7), Fp(11), Fp(13), Fp(17), Fp(19)});
    const std::size_t bias = builder.add_plaintext(
        {Fp(23), Fp(29), Fp(31), Fp(37), Fp(41), Fp(43), Fp(47), Fp(53)});
    const std::size_t zero = builder.add_scalar_plaintext(Fp::zero());

    const auto rotated = builder.rotate(0, 3);
    const auto scaled = builder.mul_plain(rotated, scalar);
    const auto translated = builder.add_plain(scaled, scalar);
    const auto shifted = builder.add_plain(1, bias);
    const auto product = builder.mul(translated, shifted);
    const auto masked = builder.mul_plain(2, mask);
    const auto rotated_masked = builder.rotate(masked, 5);
    const auto mixed = builder.add(product, rotated_masked);
    const auto second_product = builder.mul(mixed, product);
    const auto live_zero = builder.mul_plain(0, zero);
    const auto zero_product = builder.mul(live_zero, 1);
    const auto public_constant = builder.add_plain(live_zero, scalar);
    builder.set_outputs(
        {builder.add_plain(second_product, bias),
         builder.rotate(product, 4), zero_product, public_constant});
    return builder.finish();
}

void check_compact_wide_evaluation() {
    const PayloadCircuit payload = mixed_wide_payload();
    const LayeredCircuit circuit = compile(payload);
    const std::vector<SlotVector> inputs{
        values(2), values(59), values(101)};
    const PlainTrace expected = synthesize_trace(payload, circuit, inputs);
    const auto support = canonical_trace_wire_support(circuit);
    const auto storage = canonical_trace_storage_layout(circuit);
    CHECK(support.front().live_wire_count == 4);
    CHECK(support.front().padded_wire_count == 4);
    CHECK(support.back().live_wire_count == 3);
    CHECK(support.back().padded_wire_count == 4);

    MockBackend::Contexts contexts = MockBackend::create(MockParameters{
        .slot_count = kSlots,
        .fresh_rns_limbs = 8,
        .bits_per_limb = 256,
        .initial_noise_margin_bits = 4,
    });
    const auto encrypted_inputs = encrypt_wide_payload_inputs<MockBackend>(
        contexts.client, payload, inputs);
    TemporaryDirectory directory;

    MockBackend::reset_counts(contexts.eval);
    const FileTraceStoreWriteResult written =
        evaluate_wide_fhe_trace_into<MockBackend>(
            contexts.eval, payload, circuit, encrypted_inputs,
            FheEvaluationPlan::switch_after_multiplication_layers(
                circuit, 1),
            FileEncryptedTraceSink<MockBackend>(
                contexts.eval, directory.path(),
                FileTraceStoreOptions{
                    .max_total_bytes = std::uint64_t{1} << 26U,
                    .min_free_bytes = 1,
                }));
    const auto counts = MockBackend::counts(contexts.eval);

    // Structural padding is neither evaluated nor stored. In particular,
    // evaluation performs no subtraction or encryption merely to manufacture
    // a ciphertext representation of public zero.
    CHECK(counts.sub == 0);
    CHECK(counts.encrypt == 0);
    CHECK(counts.rotate > 0);
    CHECK(counts.mul_no_relin > 0);
    CHECK(counts.relinearize > 0);
    CHECK(counts.mul_plain_scalar > 0);
    CHECK(counts.mul_plain_vector > 0);
    CHECK(counts.add_plain_scalar_api_calls > 0);
    CHECK(counts.add_plain_vector_api_calls > 0);
    CHECK(counts.mod_switch > 0);

    CHECK(written.descriptor.shape == payload.shape);
    CHECK(written.descriptor.provenance == TraceProvenance::FheEvaluated);
    for (std::size_t layer = 0; layer < circuit.layers.size(); ++layer) {
        CHECK(written.descriptor.layers[layer].layout ==
              TraceLayerLayout::Wide);
        CHECK(written.descriptor.layers[layer].record_count ==
              storage[layer].stored_wire_count);
    }

    const auto store = FileEncryptedTraceStore<MockBackend>::open(
        contexts.eval, directory.path(), payload, circuit,
        written.descriptor.provenance, written.descriptor.trace_id);
    bool saw_public_zero = false;
    bool saw_public_nonzero = false;
    for (std::size_t layer = 0; layer < circuit.layers.size(); ++layer) {
        auto reader = store.active_layer_reader(layer);
        std::size_t stored = 0;
        while (const auto record = reader.next()) {
            CHECK(record->padded_index ==
                  storage[layer].representative_padded_index_of(stored));
            const SlotVector actual = record->value.is_public()
                                          ? record->value.plaintext().materialize(
                                                kSlots)
                                          : MockBackend::decrypt(
                                                contexts.client,
                                                record->value.ciphertext());
            CHECK(actual == expected.layers[layer][record->padded_index]);
            if (record->value.is_public()) {
                saw_public_zero |= record->value.is_public_zero();
                saw_public_nonzero |= !record->value.is_public_zero();
            }
            ++stored;
        }
        CHECK(stored == storage[layer].stored_wire_count);
        CHECK(reader.serialized_records_read() == stored);
    }
    CHECK(saw_public_zero);
    CHECK(saw_public_nonzero);
}

void check_resident_proof_ingress_normalization() {
    const PayloadCircuit payload = mixed_wide_payload();
    const LayeredCircuit circuit = compile(payload);
    const std::vector<SlotVector> inputs{
        values(2), values(59), values(101)};
    MockBackend::Contexts contexts = MockBackend::create(MockParameters{
        .slot_count = kSlots,
        .fresh_rns_limbs = 8,
        .bits_per_limb = 256,
        .initial_noise_margin_bits = 4,
    });
    const auto encrypted_inputs = encrypt_wide_payload_inputs<MockBackend>(
        contexts.client, payload, inputs);
    FheEvaluationPlan plan =
        FheEvaluationPlan::at_evaluation_levels(circuit, 7, 1, 2);
    for (std::size_t layer = 1; layer < circuit.layers.size(); ++layer) {
        plan.proof_ingress_mult_depth_by_layer[layer] =
            std::min<std::size_t>(
                plan.trace.required_mult_depth_by_layer[layer], 2);
    }
    plan.validate(circuit);

    const EncryptedTrace<MockBackend> trace =
        evaluate_wide_fhe_trace_into<MockBackend>(
            contexts.eval, payload, circuit, encrypted_inputs, plan,
            InMemoryTraceSink<MockBackend>{contexts.eval});
    for (std::size_t layer = 0; layer < trace.layers.size(); ++layer) {
        const std::size_t expected_depth =
            layer == 0
                ? plan.trace.required_mult_depth_by_layer[layer]
                : std::min<std::size_t>(
                      plan.trace.required_mult_depth_by_layer[layer], 2);
        CHECK(trace.layers[layer].required_mult_depth == expected_depth);
        for (const auto &wire : trace.layers[layer].wires) {
            if (wire.is_public()) {
                continue;
            }
            CHECK(MockBackend::rns_limb_count(
                      contexts.eval, wire.ciphertext()) ==
                  expected_depth + 1U);
        }
    }
}

void check_shared_prefix_program_is_evaluated_once() {
    constexpr std::size_t count = 64;
    PayloadBuilder builder(PayloadShape::wide(kSlots), count);
    std::vector<WireId> outputs;
    WireId prefix = 0;
    for (std::size_t input = 1; input < count; ++input) {
        prefix = builder.add(prefix, input);
        outputs.push_back(prefix);
    }
    builder.set_outputs(outputs);
    const auto payload = builder.finish();
    const auto circuit = compile(payload);
    CHECK(circuit.layers.size() == 2);
    const auto &affine = std::get<AffineLayer>(circuit.layers.front());
    CHECK(affine.intermediate_gates.size() == count - 1);
    const auto storage = canonical_trace_storage_layout(circuit);
    const auto program = affine_program_plan(affine, count,
        storage.front().representative_padded_indices);
    CHECK(program.peak_live_intermediates <= 2);
    CHECK(program.steps.size() == 2 * (count - 1));
    auto contexts = MockBackend::create(MockParameters{
        .slot_count = kSlots, .fresh_rns_limbs = 8,
        .bits_per_limb = 256, .initial_noise_margin_bits = 4});
    std::vector<SlotVector> inputs;
    for (std::size_t input = 0; input < count; ++input)
        inputs.push_back(values(1 + input));
    const auto encrypted = encrypt_wide_payload_inputs<MockBackend>(contexts.client, payload, inputs);
    MockBackend::reset_counts(contexts.eval);
    const auto trace = evaluate_wide_fhe_trace_into<MockBackend>(
        contexts.eval, payload, circuit, encrypted,
        FheEvaluationPlan::at_evaluation_levels(circuit, 7, 0, 0),
        InMemoryTraceSink<MockBackend>{contexts.eval});
    CHECK(MockBackend::counts(contexts.eval).add == count - 1);
    const auto expected = synthesize_trace(payload, circuit, inputs);
    for (std::size_t output = 0; output < outputs.size(); ++output)
        CHECK(MockBackend::decrypt(contexts.client, trace.layers.front().wires[output].ciphertext())
              == expected.layers.front()[output]);
}

} // namespace

int main() {
    laminate::test::Runner runner("test_wide_fhe_evaluator");
    runner.run("Wide evaluation keeps padding public and virtual",
               check_compact_wide_evaluation);
    runner.run("resident Wide snapshots normalize once at proof ingress",
               check_resident_proof_ingress_normalization);
    runner.run("shared affine prefixes execute once with bounded frontier",
               check_shared_prefix_program_is_evaluated_once);
    return runner.summary();
}
