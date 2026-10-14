/// @file test_file_trace_values_seal.cpp
/// @brief Value-aware trace storage with the concrete SEAL backend.

#include "test_helpers.hpp"

#include "laminate/fhe/seal_backend.hpp"
#include "laminate/payload/compiler.hpp"
#include "laminate/payload/storage/file_trace_store.hpp"
#include "laminate/payload/trace/trace_wire_support.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <system_error>
#include <vector>

namespace {

using laminate::Digest;
using laminate::Fp;
using laminate::fhe::FheValue;
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
        path_ = std::filesystem::temp_directory_path() /
                ("laminate-value-trace-seal-" + std::to_string(stamp));
    }
    ~TemporaryDirectory() {
        std::error_code ignored;
        std::filesystem::remove_all(path_, ignored);
    }
    const std::filesystem::path &path() const { return path_; }

  private:
    std::filesystem::path path_;
};

PayloadCircuit make_payload() {
    PayloadBuilder builder(PayloadShape::wide(kSlots), 4);
    const auto left = builder.add(0, 1);
    const auto right = builder.add(2, 3);
    builder.set_outputs({builder.mul(left, right)});
    return builder.finish();
}

SlotVector nonuniform_slots() {
    SlotVector result(kSlots);
    for (std::size_t slot = 0; slot < result.size(); ++slot) {
        result[slot] = Fp(31 + 5 * slot);
    }
    return result;
}

void check_seal_value_records_preserve_public_values() {
    const PayloadCircuit payload = make_payload();
    const LayeredCircuit circuit = compile(payload);
    const auto support = canonical_trace_wire_support(circuit);
    auto contexts = SealBackend::create(SealParameters{
        .poly_modulus_degree = kSlots,
        .fresh_rns_limbs = 4,
        .bits_per_data_prime = 40,
        .special_prime_bits = 40,
        .security_level = seal::sec_level_type::none,
    });
    const SlotVector private_plaintext(kSlots, Fp(43));
    const auto encrypted =
        SealBackend::encrypt(contexts.client, private_plaintext);
    const std::size_t required_mult_depth =
        SealBackend::rns_limb_count(contexts.eval, encrypted) - 1U;

    TemporaryDirectory directory;
    FileEncryptedTraceSink<SealBackend> sink(
        contexts.eval, directory.path(),
        FileTraceStoreOptions{
            .max_total_bytes = std::uint64_t{1} << 30U,
            .min_free_bytes = 1,
        });
    Digest trace_id{};
    trace_id.front() = 0x53;
    sink.begin_trace(circuit.shape, TraceProvenance::FheEvaluated,
                     combined_digest(payload, circuit), trace_id,
                     circuit.layers.size());

    std::size_t semantic_record = 0;
    SealBackend::reset_counts(contexts.eval);
    SealBackend::set_counting(contexts.eval, true);
    for (std::size_t layer = 0; layer < circuit.layers.size(); ++layer) {
        sink.begin_layer(layer, TraceLayerLayout::Wide,
                         layer_dimensions(circuit.layers[layer]),
                         required_mult_depth, support[layer].live_wire_count);
        for (std::size_t live = 0; live < support[layer].live_wire_count;
             ++live, ++semantic_record) {
            switch (semantic_record % 4U) {
            case 0:
                sink.append_value(
                    FheValue<SealBackend>::public_scalar(Fp::zero()));
                break;
            case 1:
                sink.append_value(
                    FheValue<SealBackend>::public_scalar(Fp(19)));
                break;
            case 2:
                sink.append_value(FheValue<SealBackend>::public_slots(
                    nonuniform_slots()));
                break;
            default:
                sink.append_value(
                    FheValue<SealBackend>::from_ciphertext(encrypted));
                break;
            }
        }
        sink.finish_layer();
    }
    (void)std::move(sink).finish();

    const auto store = FileEncryptedTraceStore<SealBackend>::open(
        contexts.eval, directory.path(), payload, circuit,
        TraceProvenance::FheEvaluated, trace_id);
    bool saw_zero = false;
    bool saw_scalar = false;
    bool saw_slots = false;
    bool saw_ciphertext = false;
    semantic_record = 0;
    for (std::size_t layer = 0; layer < circuit.layers.size(); ++layer) {
        auto reader = store.active_layer_reader(layer);
        while (const auto record = reader.next()) {
            switch (semantic_record % 4U) {
            case 0:
                CHECK(record->value.is_public_zero());
                saw_zero = true;
                break;
            case 1:
                CHECK(record->value.is_public());
                CHECK(record->value.plaintext().is_scalar());
                CHECK(record->value.plaintext().scalar() == Fp(19));
                saw_scalar = true;
                break;
            case 2:
                CHECK(record->value.is_public());
                CHECK(record->value.plaintext().is_slots());
                CHECK(record->value.plaintext().slots() ==
                      nonuniform_slots());
                saw_slots = true;
                break;
            default:
                CHECK(record->value.is_encrypted());
                CHECK(SealBackend::decrypt(contexts.client,
                                           record->value.ciphertext()) ==
                      private_plaintext);
                saw_ciphertext = true;
                break;
            }
            ++semantic_record;
        }
    }
    SealBackend::set_counting(contexts.eval, false);
    const auto counts = SealBackend::counts(contexts.eval);
    CHECK(saw_zero);
    CHECK(saw_scalar);
    CHECK(saw_slots);
    CHECK(saw_ciphertext);
    CHECK(counts.calls(SealBackend::OperationKind::Encrypt) == 0);
}

} // namespace

int main() {
    laminate::test::Runner runner("test_file_trace_values_seal");
    runner.run("SEAL trace records preserve public values without encryption",
               check_seal_value_records_preserve_public_values);
    return runner.summary();
}
