/// @file test_wide_fhe_evaluator_seal.cpp
/// @brief Compact Wide payload evaluation with Microsoft SEAL BGV.

#include "test_helpers.hpp"

#include "laminate/fhe/seal_backend.hpp"
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
#include <limits>
#include <stdexcept>
#include <string>
#include <system_error>
#include <vector>

namespace {

using laminate::Fp;
using laminate::fhe::SealBackend;
using laminate::fhe::SealParameters;
using laminate::fhe::SlotVector;
using namespace laminate::payload;

constexpr std::size_t kSlots = 1024;

class TemporaryDirectory {
  public:
    TemporaryDirectory() {
        const auto stamp = std::chrono::steady_clock::now()
                               .time_since_epoch()
                               .count();
        for (std::size_t attempt = 0; attempt < 100; ++attempt) {
            path_ = std::filesystem::temp_directory_path() /
                    ("laminate-wide-seal-" + std::to_string(stamp) + "-" +
                     std::to_string(attempt));
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
        result.emplace_back(seed + 5 * slot + slot * slot);
    }
    return result;
}

PayloadCircuit mixed_wide_payload() {
    PayloadBuilder builder(PayloadShape::wide(kSlots), 3);
    const std::size_t scalar = builder.add_scalar_plaintext(Fp(3));
    const std::size_t zero = builder.add_scalar_plaintext(Fp::zero());
    SlotVector mask(kSlots);
    SlotVector bias(kSlots);
    for (std::size_t slot = 0; slot < kSlots; ++slot) {
        mask[slot] = Fp(2 + slot % 251);
        bias[slot] = Fp(263 + 3 * slot);
    }
    const std::size_t mask_id = builder.add_plaintext(std::move(mask));
    const std::size_t bias_id = builder.add_plaintext(std::move(bias));

    const auto rotated = builder.rotate(0, kSlots / 2 + 3);
    const auto scaled = builder.mul_plain(rotated, scalar);
    const auto translated = builder.add_plain(scaled, scalar);
    const auto shifted = builder.add_plain(1, bias_id);
    const auto product = builder.mul(translated, shifted);
    const auto masked = builder.mul_plain(2, mask_id);
    const auto live_zero = builder.mul_plain(0, zero);
    const auto zero_product = builder.mul(live_zero, 1);
    const auto public_constant = builder.add_plain(live_zero, scalar);
    builder.set_outputs({product, masked, zero_product, public_constant});
    return builder.finish();
}

PayloadCircuit padded_wide_payload_without_live_zero() {
    PayloadBuilder builder(PayloadShape::wide(kSlots), 3);
    const std::size_t scalar = builder.add_scalar_plaintext(Fp(3));
    const auto left = builder.add_plain(0, scalar);
    const auto right = builder.rotate(1, 7);
    builder.set_outputs({builder.mul(left, right)});
    return builder.finish();
}

void check_padding_never_encrypts_zero() {
    const PayloadCircuit payload = padded_wide_payload_without_live_zero();
    const LayeredCircuit circuit = compile(payload);
    const auto support = canonical_trace_wire_support(circuit);
    CHECK(std::any_of(support.begin(), support.end(), [](const auto &layer) {
        return layer.live_wire_count < layer.padded_wire_count;
    }));

    SealBackend::Contexts contexts = SealBackend::create(SealParameters{
        .poly_modulus_degree = kSlots,
        .fresh_rns_limbs = 5,
        .bits_per_data_prime = 40,
        .special_prime_bits = 40,
        .security_level = seal::sec_level_type::none,
    });
    const auto encrypted_inputs = encrypt_wide_payload_inputs<SealBackend>(
        contexts.client, payload,
        std::vector<SlotVector>{values(7), values(71), values(137)});
    TemporaryDirectory directory;

    SealBackend::reset_counts(contexts.eval);
    SealBackend::set_counting(contexts.eval, true);
    (void)evaluate_wide_fhe_trace_into<SealBackend>(
        contexts.eval, payload, circuit, encrypted_inputs,
        FheEvaluationPlan::without_payload_switches(circuit, 4),
        FileEncryptedTraceSink<SealBackend>(
            contexts.eval, directory.path(),
            FileTraceStoreOptions{
                .max_total_bytes = std::uint64_t{1} << 30U,
                .min_free_bytes = 1,
            }));
    SealBackend::set_counting(contexts.eval, false);

    const auto counts = SealBackend::counts(contexts.eval);
    CHECK(counts.calls(SealBackend::OperationKind::Encrypt) == 0);
    CHECK(counts.calls(SealBackend::OperationKind::Sub) == 0);
}

void check_real_seal_wide_evaluation() {
    const PayloadCircuit payload = mixed_wide_payload();
    const LayeredCircuit circuit = compile(payload);
    const std::vector<SlotVector> inputs{
        values(7), values(71), values(137)};
    const PlainTrace expected = synthesize_trace(payload, circuit, inputs);
    const auto support = canonical_trace_wire_support(circuit);
    const auto storage = canonical_trace_storage_layout(circuit);
    CHECK(support.front().live_wire_count == 4);
    CHECK(support.front().padded_wire_count == 4);
    CHECK(support.back().live_wire_count == 3);
    CHECK(support.back().padded_wire_count == 4);

    SealBackend::Contexts contexts = SealBackend::create(SealParameters{
        .poly_modulus_degree = kSlots,
        .fresh_rns_limbs = 5,
        .bits_per_data_prime = 40,
        .special_prime_bits = 40,
        .security_level = seal::sec_level_type::none,
    });
    const auto encrypted_inputs = encrypt_wide_payload_inputs<SealBackend>(
        contexts.client, payload, inputs);
    TemporaryDirectory directory;

    SealBackend::reset_counts(contexts.eval);
    SealBackend::set_counting(contexts.eval, true);
    const FileTraceStoreWriteResult written =
        evaluate_wide_fhe_trace_into<SealBackend>(
            contexts.eval, payload, circuit, encrypted_inputs,
            FheEvaluationPlan::switch_after_multiplication_layers(
                circuit, 1),
            FileEncryptedTraceSink<SealBackend>(
                contexts.eval, directory.path(),
                FileTraceStoreOptions{
                    .max_total_bytes = std::uint64_t{1} << 30U,
                    .min_free_bytes = 1,
                }));
    SealBackend::set_counting(contexts.eval, false);
    const auto counts = SealBackend::counts(contexts.eval);
    // The zero-valued gate remains a public plaintext. Only genuine private
    // values enter the raw ciphertext backend.
    CHECK(counts.calls(SealBackend::OperationKind::Encrypt) == 0);
    CHECK(counts.calls(SealBackend::OperationKind::Sub) == 0);
    CHECK(counts.calls(SealBackend::OperationKind::Rotate) > 0);
    CHECK(counts.calls(SealBackend::OperationKind::MulNoRelin) > 0);
    CHECK(counts.calls(SealBackend::OperationKind::Relinearize) > 0);
    CHECK(counts.calls(SealBackend::OperationKind::MulPlainScalar) > 0);
    CHECK(counts.calls(SealBackend::OperationKind::MulPlainVector) > 0);
    CHECK(counts.add_plain_scalar_api_calls > 0);
    CHECK(counts.add_plain_vector_api_calls > 0);
    CHECK(counts.calls(SealBackend::OperationKind::ModSwitch) > 0);

    const auto store = FileEncryptedTraceStore<SealBackend>::open(
        contexts.eval, directory.path(), payload, circuit,
        written.descriptor.provenance, written.descriptor.trace_id);
    int minimum_noise = std::numeric_limits<int>::max();
    bool saw_public_zero = false;
    bool saw_public_nonzero = false;
    for (std::size_t layer = 0; layer < circuit.layers.size(); ++layer) {
        CHECK(written.descriptor.layers[layer].layout ==
              TraceLayerLayout::Wide);
        CHECK(written.descriptor.layers[layer].record_count ==
              storage[layer].stored_wire_count);
        auto reader = store.active_layer_reader(layer);
        std::size_t live = 0;
        while (const auto record = reader.next()) {
            CHECK(record->padded_index ==
                  storage[layer].representative_padded_index_of(live));
            const SlotVector actual = record->value.is_public()
                                          ? record->value.plaintext().materialize(
                                                kSlots)
                                          : SealBackend::decrypt(
                                                contexts.client,
                                                record->value.ciphertext());
            CHECK(actual == expected.layers[layer][record->padded_index]);
            if (record->value.is_encrypted()) {
                minimum_noise = std::min(
                    minimum_noise,
                    SealBackend::invariant_noise_budget(
                        contexts.client,
                        record->value.ciphertext()));
            } else {
                saw_public_zero |= record->value.is_public_zero();
                saw_public_nonzero |= !record->value.is_public_zero();
            }
            ++live;
        }
        CHECK(live == storage[layer].stored_wire_count);
    }
    CHECK(minimum_noise > 0);
    CHECK(saw_public_zero);
    CHECK(saw_public_nonzero);
}

} // namespace

int main() {
    laminate::test::Runner runner("test_wide_fhe_evaluator_seal");
    runner.run("real SEAL Wide padding performs no zero encryption",
               check_padding_never_encrypts_zero);
    runner.run("real SEAL Wide evaluation keeps padding virtual",
               check_real_seal_wide_evaluation);
    return runner.summary();
}
