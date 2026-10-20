/// @file test_file_trace_values.cpp
/// @brief Value-aware Mock trace-store records and canonical decoding.

#include "test_helpers.hpp"

#include "laminate/fhe/mock_backend.hpp"
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
using laminate::fhe::MockBackend;
using laminate::fhe::MockParameters;
using laminate::fhe::SlotVector;
using namespace laminate::payload;

class TemporaryDirectory {
  public:
    TemporaryDirectory() {
        const auto stamp = std::chrono::steady_clock::now()
                               .time_since_epoch()
                               .count();
        for (std::size_t attempt = 0; attempt < 100; ++attempt) {
            path_ = std::filesystem::temp_directory_path() /
                    ("laminate-value-trace-" + std::to_string(stamp) + "-" +
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

bool throws_exception(const auto &body) {
    try {
        body();
    } catch (const std::exception &) {
        return true;
    }
    return false;
}

void append_u64(std::vector<std::uint8_t> &output, std::uint64_t value) {
    for (std::size_t byte = 0; byte < sizeof(value); ++byte) {
        output.push_back(static_cast<std::uint8_t>(
            (value >> (8U * byte)) & std::uint64_t{0xff}));
    }
}

PayloadCircuit make_payload() {
    PayloadBuilder builder(PayloadShape::laned(4, 16), 4);
    const auto left = builder.mul(0, 1);
    const auto right = builder.add(2, 3);
    builder.set_outputs({builder.mul(left, right)});
    return builder.finish();
}

SlotVector nonuniform_slots() {
    SlotVector result(16);
    for (std::size_t slot = 0; slot < result.size(); ++slot) {
        result[slot] = Fp(11 + 7 * slot);
    }
    return result;
}

bool same_value(const MockBackend::EvalContext &eval,
                const FheValue<MockBackend> &left,
                const FheValue<MockBackend> &right) {
    if (left.is_public() || right.is_public()) {
        return left.is_public() && right.is_public() &&
               left.plaintext() == right.plaintext();
    }
    return MockBackend::serialize_for_storage(eval, left.ciphertext()) ==
           MockBackend::serialize_for_storage(eval, right.ciphertext());
}

void check_value_records_round_trip() {
    const PayloadCircuit payload = make_payload();
    const LayeredCircuit circuit = compile(payload);
    const std::vector<LayerWireSupport> support =
        canonical_trace_wire_support(circuit);
    const std::vector<LayerStorageLayout> storage =
        canonical_trace_storage_layout(circuit);
    auto contexts = MockBackend::create(MockParameters{
        .slot_count = 16,
        .fresh_rns_limbs = 5,
        .bits_per_limb = 40,
    });
    const auto encrypted = MockBackend::encrypt(
        contexts.client, SlotVector(16, Fp(29)));
    const std::size_t required_mult_depth =
        MockBackend::rns_limb_count(contexts.eval, encrypted) - 1U;

    TemporaryDirectory directory;
    FileEncryptedTraceSink<MockBackend> sink(
        contexts.eval, directory.path(),
        FileTraceStoreOptions{
            .max_total_bytes = std::uint64_t{1} << 24U,
            .min_free_bytes = 1,
        });
    Digest trace_id{};
    trace_id.front() = 0x4d;
    sink.begin_trace(circuit.shape, TraceProvenance::FheEvaluated,
                     combined_digest(payload, circuit), trace_id,
                     circuit.layers.size());

    std::vector<std::vector<FheValue<MockBackend>>> expected;
    expected.reserve(circuit.layers.size());
    std::size_t semantic_record = 0;
    MockBackend::reset_counts(contexts.eval);
    for (std::size_t layer = 0; layer < circuit.layers.size(); ++layer) {
        sink.begin_layer(layer, TraceLayerLayout::BPeriodic,
                         layer_dimensions(circuit.layers[layer]),
                         required_mult_depth,
                         storage[layer].stored_wire_count);
        auto &values = expected.emplace_back();
        values.reserve(storage[layer].stored_wire_count);
        for (std::size_t stored = 0;
             stored < storage[layer].stored_wire_count;
             ++stored, ++semantic_record) {
            switch (semantic_record % 4U) {
            case 0:
                values.push_back(
                    FheValue<MockBackend>::public_scalar(Fp::zero()));
                break;
            case 1:
                values.push_back(
                    FheValue<MockBackend>::public_scalar(Fp(17)));
                break;
            case 2:
                values.push_back(FheValue<MockBackend>::public_slots(
                    nonuniform_slots()));
                break;
            default:
                values.push_back(
                    FheValue<MockBackend>::from_ciphertext(encrypted));
                break;
            }
            sink.append_value(values.back());
        }
        sink.finish_layer();
    }
    const auto written = std::move(sink).finish();
    const auto after_write = MockBackend::counts(contexts.eval);
    CHECK(after_write.encrypt == 0);
    CHECK(after_write.decrypt == 0);
    CHECK(after_write.add == 0);
    CHECK(after_write.mul_no_relin == 0);

    const auto store = FileEncryptedTraceStore<MockBackend>::open(
        contexts.eval, directory.path(), payload, circuit,
        TraceProvenance::FheEvaluated, trace_id);
    CHECK(store.report() == written.report);
    for (std::size_t layer = 0; layer < circuit.layers.size(); ++layer) {
        auto full = store.layer_reader(layer);
        for (std::size_t padded = 0;
             padded < support[layer].padded_wire_count; ++padded) {
            const auto value = full.next();
            CHECK(value.has_value());
            if (!support[layer].is_live(padded)) {
                CHECK(value->is_public_zero());
                continue;
            }
            const auto stored =
                storage[layer].stored_ordinal_of(padded);
            CHECK(stored.has_value());
            CHECK(same_value(contexts.eval, *value,
                             expected[layer][*stored]));
        }
        CHECK(!full.next().has_value());

        auto active = store.active_layer_reader(layer);
        std::size_t stored = 0;
        while (const auto record = active.next()) {
            CHECK(record->padded_index ==
                  storage[layer]
                      .representative_padded_index_of(stored));
            CHECK(same_value(contexts.eval, record->value,
                             expected[layer][stored]));
            ++stored;
        }
        CHECK(stored == expected[layer].size());
    }
    const auto after_read = MockBackend::counts(contexts.eval);
    CHECK(after_read.encrypt == 0);
    CHECK(after_read.decrypt == 0);
    CHECK(after_read.add == 0);
    CHECK(after_read.mul_no_relin == 0);
}

void check_noncanonical_public_records_are_rejected() {
    auto contexts = MockBackend::create(MockParameters{
        .slot_count = 16,
        .fresh_rns_limbs = 5,
        .bits_per_limb = 40,
    });
    using Tag = laminate::fhe::FheValueRecordTag;
    auto no_ciphertext = [](std::span<const std::uint8_t>) {
        throw std::logic_error("unexpected ciphertext decoder call");
        return MockBackend::Ciphertext{};
    };

    CHECK(throws_exception([&] {
        const std::vector<std::uint8_t> unknown{0xff};
        (void)laminate::fhe::decode_fhe_value_record<MockBackend>(
            contexts.eval, unknown, no_ciphertext);
    }));

    CHECK(throws_exception([&] {
        std::vector<std::uint8_t> wrong_width{
            static_cast<std::uint8_t>(Tag::PublicSlots)};
        append_u64(wrong_width, 15);
        for (std::size_t slot = 0; slot < 15; ++slot) {
            append_u64(wrong_width, slot);
        }
        (void)laminate::fhe::decode_fhe_value_record<MockBackend>(
            contexts.eval, wrong_width, no_ciphertext);
    }));

    CHECK(throws_exception([&] {
        std::vector<std::uint8_t> uniform{
            static_cast<std::uint8_t>(Tag::PublicSlots)};
        append_u64(uniform, 16);
        for (std::size_t slot = 0; slot < 16; ++slot) {
            append_u64(uniform, 9);
        }
        (void)laminate::fhe::decode_fhe_value_record<MockBackend>(
            contexts.eval, uniform, no_ciphertext);
    }));

    CHECK(throws_exception([&] {
        std::vector<std::uint8_t> non_field_scalar{
            static_cast<std::uint8_t>(Tag::PublicScalar)};
        append_u64(non_field_scalar, laminate::kBaseFieldOrder);
        (void)laminate::fhe::decode_fhe_value_record<MockBackend>(
            contexts.eval, non_field_scalar, no_ciphertext);
    }));
}

} // namespace

int main() {
    laminate::test::Runner runner("test_file_trace_values");
    runner.run("public and encrypted trace records round-trip",
               check_value_records_round_trip);
    runner.run("noncanonical public trace records are rejected",
               check_noncanonical_public_records_are_rejected);
    return runner.summary();
}
