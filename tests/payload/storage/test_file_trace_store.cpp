#include "test_helpers.hpp"

#include "laminate/fhe/mock_backend.hpp"
#include "laminate/payload/compiler.hpp"
#include "laminate/payload/laned_fhe_evaluator.hpp"
#include "laminate/payload/storage/file_trace_store.hpp"
#include "laminate/payload/input_encryption.hpp"
#include "laminate/payload/trace/trace_crypto.hpp"
#include "laminate/payload/trace/trace_wire_support.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iterator>
#include <limits>
#include <locale>
#include <sstream>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <type_traits>
#include <vector>

#ifndef _WIN32
#include <sys/resource.h>
#include <sys/stat.h>
#endif

namespace {

using laminate::Digest;
using laminate::Fp;
using laminate::fhe::MockBackend;
using laminate::fhe::MockParameters;
using laminate::fhe::SlotVector;
using laminate::payload::EncryptedTrace;
using laminate::payload::FileEncryptedTraceStore;
using laminate::payload::FileEncryptedTraceReclamationSession;
using laminate::payload::FileEncryptedTraceSink;
using laminate::payload::FileTraceReclamationOptions;
using laminate::payload::FileTraceStorePrivateLinkReport;
using laminate::payload::FileTraceStoreRemovalReport;
using laminate::payload::FileTraceSessionLifecycle;
using laminate::payload::FileTraceStoreOpenLimits;
using laminate::payload::FileTraceStoreOptions;
using laminate::payload::FileTraceStoreReadPattern;
using laminate::payload::FileTraceStoreIntegrityMode;
using laminate::payload::LayerDimensions;
using laminate::payload::LayeredCircuit;
using laminate::payload::PayloadBuilder;
using laminate::payload::PayloadCircuit;
using laminate::payload::PayloadShape;
using laminate::payload::TraceEncryptionPlan;
using laminate::payload::TraceLayerLayout;
using laminate::payload::TraceProvenance;
using laminate::payload::trace_storage::SerializedTraceWriter;
using laminate::payload::trace_storage::SerializedTraceStore;
using laminate::payload::trace_storage::SerializedTraceReclamationSession;

class TemporaryDirectory {
  public:
    TemporaryDirectory() {
        const auto stamp = std::chrono::steady_clock::now()
                               .time_since_epoch()
                               .count();
        for (std::size_t attempt = 0; attempt < 100; ++attempt) {
            path_ = std::filesystem::temp_directory_path() /
                    ("laminate-trace-store-" + std::to_string(stamp) + "-" +
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

bool throws_message(const auto &body, std::string_view expected) {
    try {
        body();
    } catch (const std::exception &error) {
        return std::string_view(error.what()).find(expected) !=
               std::string_view::npos;
    }
    return false;
}

PayloadCircuit make_payload() {
    PayloadBuilder builder(PayloadShape::laned(2, 8), 2);
    const std::size_t three = builder.add_scalar_plaintext(Fp(3));
    const auto product = builder.mul(0, 1);
    const auto shifted = builder.add_plain(product, three);
    const auto output = builder.mul(shifted, 0);
    builder.set_outputs({output});
    return builder.finish();
}

struct Fixture {
    PayloadCircuit payload = make_payload();
    LayeredCircuit circuit = laminate::payload::compile(payload);
    MockBackend::Contexts contexts = MockBackend::create(MockParameters{
        .slot_count = 8,
        .fresh_rns_limbs = 7,
        .bits_per_limb = 61,
    });
    EncryptedTrace<MockBackend> trace;

    Fixture() {
        const std::vector<SlotVector> inputs{
            {Fp(1), Fp(2)},
            {Fp(5), Fp(8)},
        };
        const auto plain = laminate::payload::synthesize_trace(
            payload, circuit, inputs);
        trace = laminate::payload::encrypt_compact_synthetic_trace<MockBackend>(
            contexts.eval, contexts.client, payload, circuit, plain,
            TraceEncryptionPlan::uniform(circuit, 2));
    }
};

PayloadCircuit make_split_payload() {
    PayloadBuilder builder(PayloadShape::laned(4, 16), 3);
    const auto first = builder.mul(0, 1);
    const auto second = builder.mul(1, 2);
    const auto third = builder.mul(2, 0);
    builder.set_outputs({first, second, third});
    return builder.finish();
}

PayloadCircuit make_live_zero_payload() {
    PayloadBuilder builder(PayloadShape::laned(2, 8), 3);
    const std::size_t zero = builder.add_scalar_plaintext(Fp::zero());
    builder.set_outputs({builder.mul_plain(0, zero)});
    return builder.finish();
}

struct SplitFixture {
    PayloadCircuit payload = make_split_payload();
    LayeredCircuit circuit = laminate::payload::compile(payload);
    MockBackend::Contexts contexts = MockBackend::create(MockParameters{
        .slot_count = 16,
        .fresh_rns_limbs = 7,
        .bits_per_limb = 61,
    });
    EncryptedTrace<MockBackend> trace;

    SplitFixture() {
        const std::vector<SlotVector> inputs{
            {Fp(1), Fp(2), Fp(3), Fp(4)},
            {Fp(5), Fp(8), Fp(13), Fp(21)},
            {Fp(34), Fp(55), Fp(89), Fp(144)},
        };
        const auto plain = laminate::payload::synthesize_trace(
            payload, circuit, inputs);
        trace = laminate::payload::encrypt_compact_synthetic_trace<MockBackend>(
            contexts.eval, contexts.client, payload, circuit, plain,
            TraceEncryptionPlan::uniform(circuit, 2));
    }
};

FileTraceStoreOptions options(std::uint64_t maximum_bytes = 1ULL << 24U) {
    return FileTraceStoreOptions{
        .max_total_bytes = maximum_bytes,
        .min_free_bytes = 1,
    };
}

std::filesystem::path layer_file(const std::filesystem::path &directory,
                                 std::size_t layer_index) {
    std::ostringstream name;
    name.imbue(std::locale::classic());
    name << "layer-" << std::setw(16) << std::setfill('0') << layer_index
         << ".bin";
    return directory / name.str();
}

std::uint64_t directory_file_bytes(const std::filesystem::path &directory) {
    std::uint64_t result = 0;
    for (const std::filesystem::directory_entry &entry :
         std::filesystem::directory_iterator(directory)) {
        if (entry.is_regular_file()) {
            result += entry.file_size();
        }
    }
    return result;
}

void write_text(const std::filesystem::path &path, std::string_view text) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output.write(text.data(), static_cast<std::streamsize>(text.size()));
    if (!output) {
        throw std::runtime_error("failed to write trace-store test marker");
    }
}

std::string read_text(const std::filesystem::path &path) {
    std::ifstream input(path, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(input),
                       std::istreambuf_iterator<char>());
}

class HostileNumPut final : public std::num_put<char> {
  private:
    iter_type put_hostile(iter_type output) const {
        for (const char character : std::string_view("not-a-number")) {
            *output++ = character;
        }
        return output;
    }

    iter_type do_put(iter_type output, std::ios_base &, char_type,
                     long) const override {
        return put_hostile(output);
    }

    iter_type do_put(iter_type output, std::ios_base &, char_type,
                     unsigned long) const override {
        return put_hostile(output);
    }

    iter_type do_put(iter_type output, std::ios_base &, char_type,
                     long long) const override {
        return put_hostile(output);
    }

    iter_type do_put(iter_type output, std::ios_base &, char_type,
                     unsigned long long) const override {
        return put_hostile(output);
    }
};

class GlobalLocaleGuard {
  public:
    explicit GlobalLocaleGuard(const std::locale &selected)
        : previous_(std::locale::global(selected)) {}
    ~GlobalLocaleGuard() { std::locale::global(previous_); }

    GlobalLocaleGuard(const GlobalLocaleGuard &) = delete;
    GlobalLocaleGuard &operator=(const GlobalLocaleGuard &) = delete;

  private:
    std::locale previous_;
};

std::vector<std::uint8_t> encoding(
    const Fixture &fixture, const MockBackend::Ciphertext &ciphertext) {
    return MockBackend::serialize_for_storage(fixture.contexts.eval,
                                              ciphertext);
}

std::vector<std::uint8_t> encoding(
    const Fixture &fixture,
    const laminate::fhe::FheValue<MockBackend> &value) {
    CHECK(value.is_encrypted());
    return encoding(fixture, value.ciphertext());
}

std::array<std::uint64_t, 16> operation_counts(
    const laminate::fhe::OperationCounts &counts) {
    return {counts.encrypt,
            counts.decrypt,
            counts.negate,
            counts.add,
            counts.sub,
            counts.mul_no_relin,
            counts.relinearize,
            counts.add_plain,
            counts.mul_plain_scalar,
            counts.mul_plain_vector,
            counts.rotate,
            counts.mod_switch,
            counts.logical_ext_add,
            counts.logical_ext_sub,
            counts.logical_ext_mul,
            counts.logical_ext_mul_plain};
}

std::vector<std::uint8_t> encoding(
    const SplitFixture &fixture,
    const MockBackend::Ciphertext &ciphertext) {
    return MockBackend::serialize_for_storage(fixture.contexts.eval,
                                              ciphertext);
}

std::vector<std::uint8_t> encoding(
    const SplitFixture &fixture,
    const laminate::fhe::FheValue<MockBackend> &value) {
    CHECK(value.is_encrypted());
    return encoding(fixture, value.ciphertext());
}

std::uint64_t read_u64_at(const std::filesystem::path &path,
                          std::uint64_t offset) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw std::runtime_error("failed to open trace-store integer");
    }
    input.seekg(static_cast<std::streamoff>(offset));
    std::uint64_t result = 0;
    for (std::size_t byte = 0; byte < sizeof(result); ++byte) {
        char encoded = 0;
        input.read(&encoded, 1);
        if (!input) {
            throw std::runtime_error("failed to read trace-store integer");
        }
        result |= static_cast<std::uint64_t>(
                      static_cast<unsigned char>(encoded))
                  << (8U * byte);
    }
    return result;
}

void begin_fixture_layer(FileEncryptedTraceSink<MockBackend> &sink,
                         const Fixture &fixture,
                         std::size_t layer_index) {
    const auto &layer = fixture.trace.layers.at(layer_index);
    const auto storage = laminate::payload::canonical_layer_storage_layout(
        fixture.circuit, layer_index);
    sink.begin_layer(layer_index, layer.layout, layer.dimensions,
                     layer.required_mult_depth, storage.stored_wire_count);
}

void append_fixture_stored_wires(FileEncryptedTraceSink<MockBackend> &sink,
                                 const Fixture &fixture,
                                 std::size_t layer_index) {
    const auto &wires = fixture.trace.layers.at(layer_index).wires;
    for (const auto &value : wires) {
        sink.append_value(value);
    }
}

void test_round_trip_and_byte_reports() {
    Fixture fixture;
    CHECK(fixture.trace.backend_context_id.has_value());
    CHECK(*fixture.trace.backend_context_id ==
          MockBackend::storage_context_id(fixture.contexts.eval));
    TemporaryDirectory directory;
    const FileTraceStoreOptions selected = options();
    const auto result = laminate::payload::write_file_encrypted_trace(
        fixture.contexts.eval, directory.path(), selected, fixture.circuit,
        fixture.trace);

    CHECK(result.backend_context_id ==
          MockBackend::storage_context_id(fixture.contexts.eval));
    CHECK(result.descriptor ==
          laminate::payload::descriptor_of(fixture.trace));
    CHECK(result.report.logical_record_bytes > 0);
    CHECK(result.report.physical_bytes >
          result.report.logical_record_bytes);
    CHECK(result.report.physical_bytes ==
          directory_file_bytes(directory.path()));
    CHECK(result.diagnostics.authenticated_records > 0);
    CHECK(result.diagnostics.authenticated_record_bytes ==
          result.report.logical_record_bytes);
    CHECK(result.diagnostics.same_process_unhashed_records == 0);
    CHECK(result.diagnostics.record_copy_bytes == 0);
    CHECK(result.diagnostics.writeback_files_submit_only == 0);
    CHECK(result.diagnostics.writeback_drains_skipped == 0);
    CHECK(result.diagnostics.writeback_range_bytes_without_explicit_wait == 0);
    CHECK(result.diagnostics.positional_write_calls >=
          result.descriptor.layers.size());
    CHECK(result.diagnostics.positional_write_bytes ==
          result.descriptor.layers.size() * sizeof(std::uint64_t));
    CHECK(std::filesystem::is_regular_file(directory.path() /
                                           "manifest.bin"));
    for (const std::filesystem::directory_entry &entry :
         std::filesystem::directory_iterator(directory.path())) {
        CHECK(entry.path().extension() != ".partial");
    }

    const auto store = FileEncryptedTraceStore<MockBackend>::open(
        fixture.contexts.eval, directory.path(), fixture.payload,
        fixture.circuit, fixture.trace.provenance, fixture.trace.trace_id);
    CHECK(store.descriptor() == result.descriptor);
    CHECK(store.report() == result.report);
    CHECK(store.backend_context_id() == result.backend_context_id);

    for (std::size_t layer = 0; layer < fixture.trace.layers.size(); ++layer) {
        const auto support =
            laminate::payload::canonical_layer_wire_support(
                fixture.circuit, layer);
        const auto storage =
            laminate::payload::canonical_layer_storage_layout(
                fixture.circuit, layer);
        auto reader = store.layer_reader(layer);
        std::size_t logical_live = 0;
        for (std::size_t padded = 0;
             padded < support.padded_wire_count; ++padded) {
            const auto actual = reader.next();
            CHECK(actual.has_value());
            if (support.is_live(padded)) {
                CHECK(!actual->is_public_zero());
                const std::size_t stored =
                    *storage.stored_ordinal_of(padded);
                CHECK(encoding(fixture, actual->ciphertext()) ==
                      encoding(fixture,
                               fixture.trace.layers[layer].wires[stored]));
                ++logical_live;
            } else {
                CHECK(actual->is_public_zero());
            }
        }
        CHECK(logical_live == support.live_wire_count);
        CHECK(fixture.trace.layers[layer].wires.size() ==
              storage.stored_wire_count);
        CHECK(!reader.next().has_value());
    }
}

void test_compact_split_support_and_virtual_zero_ranges() {
    SplitFixture fixture;
    constexpr std::size_t split_layer = 2;
    const auto support = laminate::payload::canonical_layer_wire_support(
        fixture.circuit, split_layer);
    const auto storage = laminate::payload::canonical_layer_storage_layout(
        fixture.circuit, split_layer);
    CHECK(support.padded_wire_count == 8);
    CHECK(support.live_wire_count == 6);
    CHECK(storage.stored_wire_count < support.live_wire_count);
    CHECK(support.live_ranges.size() == 2);
    CHECK(support.live_ranges[0] ==
          (laminate::payload::LiveWireRange{0, 3}));
    CHECK(support.live_ranges[1] ==
          (laminate::payload::LiveWireRange{4, 3}));

    TemporaryDirectory directory;
    const auto written = laminate::payload::write_file_encrypted_trace(
        fixture.contexts.eval, directory.path(), options(), fixture.circuit,
        fixture.trace);
    CHECK(written.descriptor.layers[split_layer].record_count ==
          storage.stored_wire_count);
    // Magic, version, and layer index occupy the first 24 bytes.
    CHECK(read_u64_at(layer_file(directory.path(), split_layer), 24) ==
          storage.stored_wire_count);

    const auto store = FileEncryptedTraceStore<MockBackend>::open(
        fixture.contexts.eval, directory.path(), fixture.payload,
        fixture.circuit, fixture.trace.provenance, fixture.trace.trace_id);
    CHECK(store.layer_support(split_layer) == support);

    std::uint64_t expected_logical_bytes = 0;
    auto dense = store.layer_reader(split_layer);
    CHECK(dense.begin() == 0);
    CHECK(dense.end() == 8);
    CHECK(dense.position() == 0);
    std::size_t logical_live = 0;
    for (std::size_t padded = 0; padded < support.padded_wire_count;
         ++padded) {
        const auto actual = dense.next();
        CHECK(actual.has_value());
        CHECK(dense.position() == padded + 1);
        if (support.is_live(padded)) {
            CHECK(!actual->is_public_zero());
            const std::size_t stored =
                *storage.stored_ordinal_of(padded);
            const auto &expected = fixture.trace.layers[split_layer]
                                       .wires[stored];
            const auto bytes = encoding(fixture, expected);
            expected_logical_bytes += 1U + bytes.size();
            CHECK(encoding(fixture, actual->ciphertext()) == bytes);
            ++logical_live;
        } else {
            CHECK(actual->is_public_zero());
        }
    }
    CHECK(logical_live == support.live_wire_count);
    CHECK(!dense.next().has_value());
    CHECK(dense.encoded_bytes_read() == expected_logical_bytes);
    CHECK(dense.serialized_records_read() == support.live_wire_count);

    auto gap = store.layer_reader(split_layer, 3, 4);
    CHECK(gap.begin() == 3);
    CHECK(gap.end() == 4);
    const auto operations_before =
        operation_counts(*fixture.contexts.eval.counters);
    const auto virtual_zero = gap.next();
    CHECK(virtual_zero.has_value());
    CHECK(virtual_zero->is_public_zero());
    CHECK(gap.position() == 4);
    CHECK(gap.encoded_bytes_read() == 0);
    CHECK(gap.serialized_records_read() == 0);
    CHECK(gap.resident_ciphertexts_held() == 0);
    CHECK(operation_counts(*fixture.contexts.eval.counters) ==
          operations_before);
    gap.rewind();
    CHECK(gap.position() == 3);
    CHECK(gap.next()->is_public_zero());
    CHECK(gap.encoded_bytes_read() == 0);
    CHECK(gap.serialized_records_read() == 0);
    CHECK(operation_counts(*fixture.contexts.eval.counters) ==
          operations_before);

    auto active = store.active_layer_reader(split_layer);
    std::uint64_t expected_stored_bytes = 0;
    for (std::size_t stored = 0; stored < storage.stored_wire_count;
         ++stored) {
        const auto record = active.next();
        CHECK(record.has_value());
        CHECK(record->padded_index ==
              storage.representative_padded_index_of(stored));
        expected_stored_bytes +=
            1U + encoding(fixture,
                          fixture.trace.layers[split_layer].wires[stored])
                       .size();
        CHECK(encoding(fixture, record->value) ==
              encoding(fixture,
                       fixture.trace.layers[split_layer]
                           .wires[stored]));
    }
    CHECK(!active.next().has_value());
    CHECK(active.encoded_bytes_read() == expected_stored_bytes);
    CHECK(active.serialized_records_read() == storage.stored_wire_count);
    active.rewind();
    CHECK(active.position() == active.begin());
    CHECK(active.next()->padded_index == 0);
    CHECK(active.serialized_records_read() == storage.stored_wire_count + 1);
    active.seek_to(storage.stored_wire_count - 1U);
    CHECK(active.position() == storage.stored_wire_count - 1U);
    CHECK(active.next()->padded_index ==
          storage.representative_padded_indices.back());
    active.seek_to(std::min<std::size_t>(1, active.end() - 1U));
    const auto indexed = active.next();
    CHECK(indexed.has_value());
    const std::size_t indexed_ordinal =
        std::min<std::size_t>(1, storage.stored_wire_count - 1U);
    CHECK(indexed->padded_index ==
          storage.representative_padded_index_of(indexed_ordinal));
    CHECK(encoding(fixture, indexed->value) ==
          encoding(fixture,
                   fixture.trace.layers[split_layer]
                       .wires[indexed_ordinal]));
    active.seek_to(active.end());
    CHECK(!active.next().has_value());
    CHECK(throws_exception([&] { active.seek_to(active.end() + 1U); }));

    auto tampered = laminate::payload::descriptor_of(fixture.trace);
    tampered.layers[split_layer].record_count =
        tampered.layers[split_layer].dimensions.padded_size;
    CHECK(throws_exception([&] {
        laminate::payload::validate_encrypted_trace_descriptor_for_circuit(
            tampered, fixture.payload, fixture.circuit);
    }));
}

void test_filenames_are_independent_of_the_global_locale() {
    Fixture fixture;
    TemporaryDirectory directory;
    const GlobalLocaleGuard locale_guard(
        std::locale(std::locale::classic(), new HostileNumPut));
    (void)laminate::payload::write_file_encrypted_trace(
        fixture.contexts.eval, directory.path(), options(), fixture.circuit,
        fixture.trace);
    CHECK(std::filesystem::is_regular_file(
        directory.path() / "layer-0000000000000000.bin"));

    auto store = FileEncryptedTraceStore<MockBackend>::open(
        fixture.contexts.eval, directory.path(), fixture.payload,
        fixture.circuit, fixture.trace.provenance, fixture.trace.trace_id);
    auto session =
        FileEncryptedTraceReclamationSession<MockBackend>::begin(
            std::move(store),
            FileTraceReclamationOptions{
                FileTraceSessionLifecycle::IrreversibleNoRetry});
    (void)session.retire_layer(0);
    CHECK(std::filesystem::is_regular_file(
        directory.path() / "retirement-0000000000000001.bin"));
}

void test_independent_rewindable_range_readers() {
    Fixture fixture;
    TemporaryDirectory directory;
    const FileTraceStoreOptions selected = options();
    (void)laminate::payload::write_file_encrypted_trace(
        fixture.contexts.eval, directory.path(), selected, fixture.circuit,
        fixture.trace);
    const auto store = FileEncryptedTraceStore<MockBackend>::open(
        fixture.contexts.eval, directory.path(), fixture.payload,
        fixture.circuit, fixture.trace.provenance, fixture.trace.trace_id);

    const std::size_t layer = fixture.trace.layers.size() - 1U;
    CHECK(fixture.trace.layers[layer].wires.size() == 2);
    auto first = store.layer_reader(layer);
    auto second = store.layer_reader(layer);
    const auto first_value = first.next();
    const auto second_value = second.next();
    CHECK(first_value.has_value());
    CHECK(second_value.has_value());
    CHECK(!first_value->is_public_zero());
    CHECK(!second_value->is_public_zero());
    CHECK(encoding(fixture, first_value->ciphertext()) ==
          encoding(fixture, fixture.trace.layers[layer].wires[0]));
    CHECK(encoding(fixture, second_value->ciphertext()) ==
          encoding(fixture, fixture.trace.layers[layer].wires[0]));

    const auto first_one = first.next();
    CHECK(first_one.has_value());
    CHECK(!first_one->is_public_zero());
    CHECK(encoding(fixture, first_one->ciphertext()) ==
          encoding(fixture, fixture.trace.layers[layer].wires[1]));
    first.rewind();
    CHECK(first.position() == first.begin());
    const auto repeated = first.next();
    CHECK(repeated.has_value());
    CHECK(!repeated->is_public_zero());
    CHECK(encoding(fixture, repeated->ciphertext()) ==
          encoding(fixture, first_value->ciphertext()));

    auto range = store.layer_reader(layer, 1, 2);
    CHECK(range.begin() == 1);
    CHECK(range.end() == 2);
    const auto ranged = range.next();
    CHECK(ranged.has_value());
    CHECK(!ranged->is_public_zero());
    CHECK(encoding(fixture, ranged->ciphertext()) ==
          encoding(fixture, fixture.trace.layers[layer].wires[1]));
    CHECK(!range.next().has_value());
}

void test_evaluator_emits_directly_to_file_sink() {
    Fixture fixture;
    TemporaryDirectory directory;
    const FileTraceStoreOptions selected = options();
    const std::vector<SlotVector> inputs{
        {Fp(1), Fp(2)},
        {Fp(5), Fp(8)},
    };
    const auto encrypted_inputs =
        laminate::payload::encrypt_laned_payload_inputs<MockBackend>(
            fixture.contexts.client, fixture.payload, inputs);
    MockBackend::reset_counts(fixture.contexts.eval);
    const auto result =
        laminate::payload::evaluate_laned_fhe_trace_into<MockBackend>(
            fixture.contexts.eval, fixture.payload, fixture.circuit,
            encrypted_inputs,
            laminate::payload::FheEvaluationPlan::without_payload_switches(
                fixture.circuit, 2),
            FileEncryptedTraceSink<MockBackend>(
                fixture.contexts.eval, directory.path(), selected));
    const laminate::fhe::OperationCounts counts =
        MockBackend::counts(fixture.contexts.eval);
    // The compact evaluator never constructs or evaluates the compiler's
    // padding positions. This fixture has substantial padding but no
    // semantically live zero gate, so neither subtraction nor zero
    // encryption belongs to payload evaluation.
    CHECK(counts.sub == 0);
    CHECK(counts.encrypt == 0);
    CHECK(result.descriptor.provenance ==
          laminate::payload::TraceProvenance::FheEvaluated);

    const auto store = FileEncryptedTraceStore<MockBackend>::open(
        fixture.contexts.eval, directory.path(), fixture.payload,
        fixture.circuit, result.descriptor.provenance,
        result.descriptor.trace_id);
    CHECK(store.descriptor() == result.descriptor);
    const auto plain = laminate::payload::synthesize_trace(
        fixture.payload, fixture.circuit, inputs);
    for (std::size_t layer = 0; layer < fixture.circuit.layers.size();
         ++layer) {
        auto reader = store.layer_reader(layer);
        const auto support =
            laminate::payload::canonical_layer_wire_support(
                fixture.circuit, layer);
        for (std::size_t padded = 0;
             padded < plain.layers[layer].size(); ++padded) {
            const auto value = reader.next();
            CHECK(value.has_value());
            if (!support.is_live(padded)) {
                CHECK(value->is_public_zero());
                continue;
            }
            const SlotVector physical = value->is_public()
                                            ? value->plaintext().materialize(
                                                  MockBackend::slot_count(
                                                      fixture.contexts.eval))
                                            : MockBackend::decrypt(
                                                  fixture.contexts.client,
                                                  value->ciphertext());
            CHECK(std::vector<Fp>(physical.begin(), physical.begin() + 2) ==
                  plain.layers[layer][padded]);
        }
        CHECK(!reader.next().has_value());
    }
}

void test_compact_evaluator_retains_a_live_public_zero() {
    const PayloadCircuit payload = make_live_zero_payload();
    const LayeredCircuit circuit = laminate::payload::compile(payload);
    const auto support = laminate::payload::canonical_trace_wire_support(
        circuit);
    CHECK(support.back().live_wire_count == 3);
    CHECK(support.back().padded_wire_count == 4);
    CHECK(support.front().live_wire_count == 1);

    auto contexts = MockBackend::create(MockParameters{
        .slot_count = 8,
        .fresh_rns_limbs = 7,
        .bits_per_limb = 61,
    });
    const std::vector<SlotVector> inputs{
        {Fp(3), Fp(5)},
        {Fp(7), Fp(11)},
        {Fp(13), Fp(17)},
    };
    const auto encrypted_inputs =
        laminate::payload::encrypt_laned_payload_inputs<MockBackend>(
            contexts.client, payload, inputs);
    const std::size_t fresh_chain_index =
        MockBackend::rns_limb_count(
            contexts.eval, encrypted_inputs.front()) - 1U;
    CHECK(fresh_chain_index > 0);

    MockBackend::reset_counts(contexts.eval);
    const EncryptedTrace<MockBackend> compact =
        laminate::payload::evaluate_laned_fhe_trace_into<MockBackend>(
            contexts.eval, payload, circuit, encrypted_inputs,
            laminate::payload::FheEvaluationPlan::without_payload_switches(
                circuit, fresh_chain_index),
            laminate::payload::InMemoryTraceSink<
                MockBackend>{contexts.eval});
    const laminate::fhe::OperationCounts counts =
        MockBackend::counts(contexts.eval);

    CHECK(counts.sub == 0);
    CHECK(counts.encrypt == 0);
    CHECK(counts.mul_plain_scalar == 0);
    CHECK(counts.mul_plain_vector == 0);
    CHECK(compact.layers.back().wires.size() == 3);
    CHECK(compact.layers.front().wires.size() == 1);
    CHECK(compact.layers.front().wires.front().is_public_zero());
}

void test_quota_failure_never_finalizes_manifest() {
    Fixture fixture;
    TemporaryDirectory directory;
    CHECK(throws_exception([&] {
        (void)laminate::payload::write_file_encrypted_trace(
            fixture.contexts.eval, directory.path(), options(64),
            fixture.circuit, fixture.trace);
    }));
    CHECK(!std::filesystem::exists(directory.path() / "manifest.bin"));
}

void test_runtime_write_failure_removes_partial_layer() {
#ifndef _WIN32
    class FileSizeLimitGuard {
      public:
        FileSizeLimitGuard() {
            if (::getrlimit(RLIMIT_FSIZE, &original_limit_) != 0) {
                throw std::runtime_error("cannot read file-size limit");
            }
            original_handler_ = std::signal(SIGXFSZ, SIG_IGN);
            if (original_handler_ == SIG_ERR) {
                throw std::runtime_error("cannot ignore SIGXFSZ");
            }
            rlimit limited = original_limit_;
            limited.rlim_cur = std::min<rlim_t>(limited.rlim_max, 4096);
            if (::setrlimit(RLIMIT_FSIZE, &limited) != 0) {
                (void)std::signal(SIGXFSZ, original_handler_);
                throw std::runtime_error("cannot install file-size limit");
            }
        }

        ~FileSizeLimitGuard() {
            (void)::setrlimit(RLIMIT_FSIZE, &original_limit_);
            (void)std::signal(SIGXFSZ, original_handler_);
        }

        FileSizeLimitGuard(const FileSizeLimitGuard &) = delete;
        FileSizeLimitGuard &operator=(const FileSizeLimitGuard &) = delete;

      private:
        rlimit original_limit_{};
        using SignalHandler = void (*)(int);
        SignalHandler original_handler_ = SIG_DFL;
    };

    Fixture fixture;
    TemporaryDirectory directory;
    FileSizeLimitGuard file_size_limit;
    FileTraceStoreOptions limits = options(1ULL << 20U);
    limits.transfer_buffer_bytes = 16ULL << 10U;
    SerializedTraceWriter writer(
        directory.path(), limits,
        MockBackend::storage_context_id(fixture.contexts.eval));
    Digest circuit_id{};
    circuit_id.front() = 0x41;
    Digest trace_id{};
    trace_id.front() = 0x52;
    writer.begin_trace(PayloadShape::wide(8),
                       TraceProvenance::SyntheticTrace, circuit_id,
                       trace_id, 1);
    writer.begin_layer(0, TraceLayerLayout::Wide,
                       LayerDimensions{1, 8, 1, 0}, 0, 1);
    writer.append_serialized(std::vector<std::uint8_t>(8192, 0x5a));
    CHECK(throws_exception([&] { writer.finish_layer(); }));
    CHECK(!std::filesystem::exists(directory.path() / "manifest.bin"));
    CHECK(!std::filesystem::exists(
        directory.path() / "layer-0000000000000000.bin"));
    CHECK(!std::filesystem::exists(
        directory.path() / "layer-0000000000000000.partial"));
#endif
}

void flip_byte(const std::filesystem::path &path, std::uint64_t offset) {
    std::fstream file(path, std::ios::binary | std::ios::in | std::ios::out);
    if (!file) {
        throw std::runtime_error("failed to open corruption target");
    }
    file.seekg(static_cast<std::streamoff>(offset));
    char value = 0;
    file.read(&value, 1);
    if (!file) {
        throw std::runtime_error("failed to read corruption target");
    }
    value ^= 0x5a;
    file.seekp(static_cast<std::streamoff>(offset));
    file.write(&value, 1);
    if (!file) {
        throw std::runtime_error("failed to corrupt trace store");
    }
}

void write_u64_at(const std::filesystem::path &path, std::uint64_t offset,
                  std::uint64_t value) {
    std::fstream file(path, std::ios::binary | std::ios::in | std::ios::out);
    if (!file) {
        throw std::runtime_error("failed to open integer corruption target");
    }
    file.seekp(static_cast<std::streamoff>(offset));
    for (std::size_t byte = 0; byte < sizeof(value); ++byte) {
        const char encoded = static_cast<char>(
            (value >> (8U * byte)) & std::uint64_t{0xff});
        file.write(&encoded, 1);
    }
    if (!file) {
        throw std::runtime_error("failed to rewrite trace-store integer");
    }
}

void test_reader_rejects_post_open_length_change() {
    Fixture fixture;
    TemporaryDirectory directory;
    const FileTraceStoreOptions selected = options();
    (void)laminate::payload::write_file_encrypted_trace(
        fixture.contexts.eval, directory.path(), selected, fixture.circuit,
        fixture.trace);
    const auto store = FileEncryptedTraceStore<MockBackend>::open(
        fixture.contexts.eval, directory.path(), fixture.payload,
        fixture.circuit, fixture.trace.provenance, fixture.trace.trace_id);
    auto reader = store.active_layer_reader(0);

    // V4 layer headers are 40 bytes. Changing the first record length after
    // reader construction violates the private-directory contract. The
    // validated reader still checks framing before allocation, so even this
    // concurrent mutation cannot turn a corrupt length into a large
    // allocation.
    write_u64_at(directory.path() / "layer-0000000000000000.bin", 40,
                 std::numeric_limits<std::uint64_t>::max());
    CHECK(throws_exception([&] { (void)reader.next(); }));
}

void test_reader_rejects_post_open_size_change_at_scan_end() {
    Fixture fixture;
    TemporaryDirectory directory;
    (void)laminate::payload::write_file_encrypted_trace(
        fixture.contexts.eval, directory.path(), options(), fixture.circuit,
        fixture.trace);
    const auto store = FileEncryptedTraceStore<MockBackend>::open(
        fixture.contexts.eval, directory.path(), fixture.payload,
        fixture.circuit, fixture.trace.provenance, fixture.trace.trace_id);

    const std::size_t layer_index = fixture.trace.layers.size() - 1U;
    CHECK(fixture.trace.layers[layer_index].wires.size() == 2);
    auto reader = store.active_layer_reader(layer_index);
    CHECK(reader.next().has_value());

    // Concurrent mutation is outside the private-store contract. A size
    // change is nevertheless detected at the next scan boundary, after the
    // final framed record and before that record is returned.
    const std::filesystem::path layer =
        layer_file(directory.path(), layer_index);
    std::filesystem::resize_file(
        layer, std::filesystem::file_size(layer) + 1U);
    CHECK(throws_exception([&] { (void)reader.next(); }));
}

void test_reader_rejects_post_open_replacement_at_scan_boundaries() {
#ifndef _WIN32
    Fixture fixture;
    TemporaryDirectory directory;
    TemporaryDirectory external;
    std::filesystem::create_directory(external.path());
    (void)laminate::payload::write_file_encrypted_trace(
        fixture.contexts.eval, directory.path(), options(), fixture.circuit,
        fixture.trace);
    const auto store = FileEncryptedTraceStore<MockBackend>::open(
        fixture.contexts.eval, directory.path(), fixture.payload,
        fixture.circuit, fixture.trace.provenance, fixture.trace.trace_id);

    const std::size_t layer_index = fixture.trace.layers.size() - 1U;
    auto reader = store.active_layer_reader(layer_index);
    CHECK(reader.next().has_value());

    const std::filesystem::path layer =
        layer_file(directory.path(), layer_index);
    const std::filesystem::path original =
        external.path() / "original-layer.bin";
    std::filesystem::rename(layer, original);
    std::filesystem::copy_file(original, layer);

    CHECK(throws_message([&] { reader.rewind(); },
                         "replaced after validation"));
#endif
}

void test_reclamation_requires_explicit_no_retry_lifecycle() {
    static_assert(!std::is_copy_constructible_v<
                  FileEncryptedTraceReclamationSession<MockBackend>>);
    static_assert(!std::is_copy_assignable_v<
                  FileEncryptedTraceReclamationSession<MockBackend>>);
    static_assert(std::is_move_constructible_v<
                  FileEncryptedTraceReclamationSession<MockBackend>>);

    Fixture fixture;
    TemporaryDirectory directory;
    const auto written = laminate::payload::write_file_encrypted_trace(
        fixture.contexts.eval, directory.path(), options(), fixture.circuit,
        fixture.trace);
    auto store = FileEncryptedTraceStore<MockBackend>::open(
        fixture.contexts.eval, directory.path(), fixture.payload,
        fixture.circuit, fixture.trace.provenance, fixture.trace.trace_id);
    CHECK(throws_exception([&] {
        (void)FileEncryptedTraceReclamationSession<MockBackend>::begin(
            std::move(store), FileTraceReclamationOptions{});
    }));

    auto session =
        FileEncryptedTraceReclamationSession<MockBackend>::begin(
            std::move(store),
            FileTraceReclamationOptions{
                FileTraceSessionLifecycle::IrreversibleNoRetry});
    CHECK(session.descriptor() == written.descriptor);
    CHECK(session.report() == written.report);
    const auto state = session.journal_state();
    CHECK(state.generation == 0);
    CHECK(state.reclaimed_physical_bytes == 0);
    CHECK(state.remaining_trace_physical_bytes ==
          written.report.physical_bytes);
    CHECK(std::filesystem::is_regular_file(
        directory.path() / "retirement-session.bin"));

    const auto inspected =
        laminate::payload::inspect_file_trace_retirement_journal(
            directory.path());
    CHECK(inspected.store_manifest_id == state.store_manifest_id);
    CHECK(inspected.retired_layers == state.retired_layers);
    CHECK(throws_exception([&] {
        (void)FileEncryptedTraceStore<MockBackend>::open(
            fixture.contexts.eval, directory.path(), fixture.payload,
            fixture.circuit, fixture.trace.provenance,
            fixture.trace.trace_id);
    }));
}

void test_reclamation_is_order_independent_and_exactly_accounted() {
    Fixture fixture;
    TemporaryDirectory directory;
    const auto written = laminate::payload::write_file_encrypted_trace(
        fixture.contexts.eval, directory.path(), options(), fixture.circuit,
        fixture.trace);
    auto store = FileEncryptedTraceStore<MockBackend>::open(
        fixture.contexts.eval, directory.path(), fixture.payload,
        fixture.circuit, fixture.trace.provenance, fixture.trace.trace_id);
    const auto descriptor = store.descriptor();
    auto session =
        FileEncryptedTraceReclamationSession<MockBackend>::begin(
            std::move(store),
            FileTraceReclamationOptions{
                FileTraceSessionLifecycle::IrreversibleNoRetry});

    const std::size_t first = descriptor.layers.size() - 1;
    const std::size_t second = 0;
    const std::uint64_t first_bytes =
        std::filesystem::file_size(layer_file(directory.path(), first));
    const std::uint64_t second_bytes =
        std::filesystem::file_size(layer_file(directory.path(), second));

    const auto first_report = session.retire_layer(first);
    CHECK(first_report.layer_index == first);
    CHECK(first_report.reclaimed_physical_bytes == first_bytes);
    CHECK(first_report.total_reclaimed_physical_bytes == first_bytes);
    CHECK(session.descriptor() == descriptor);

    const auto second_report = session.retire_layer(second);
    CHECK(second_report.layer_index == second);
    CHECK(second_report.reclaimed_physical_bytes == second_bytes);
    CHECK(second_report.total_reclaimed_physical_bytes ==
          first_bytes + second_bytes);
    CHECK(second_report.remaining_trace_physical_bytes ==
          written.report.physical_bytes - first_bytes - second_bytes);
    CHECK(throws_exception([&] { (void)session.retire_layer(first); }));
    CHECK(throws_exception([&] { (void)session.layer_reader(second); }));

    const auto state = session.journal_state();
    CHECK(state.generation == 2);
    CHECK(state.retired_layers[first]);
    CHECK(state.retired_layers[second]);
    const auto inspected =
        laminate::payload::inspect_file_trace_retirement_journal(
            directory.path());
    CHECK(inspected.generation == state.generation);
    CHECK(inspected.retired_layers == state.retired_layers);
    CHECK(inspected.reclaimed_physical_bytes ==
          state.reclaimed_physical_bytes);
    const std::uint64_t journal_bytes =
        std::filesystem::file_size(directory.path() /
                                   "retirement-session.bin") +
        std::filesystem::file_size(
            directory.path() / "retirement-0000000000000001.bin") +
        std::filesystem::file_size(
            directory.path() / "retirement-0000000000000002.bin");
    CHECK(directory_file_bytes(directory.path()) ==
          state.remaining_trace_physical_bytes + journal_bytes);
    flip_byte(directory.path() / "retirement-0000000000000001.bin", 16);
    CHECK(throws_exception([&] {
        (void)laminate::payload::inspect_file_trace_retirement_journal(
            directory.path());
    }));
}

void test_live_reader_blocks_retirement() {
    Fixture fixture;
    TemporaryDirectory directory;
    (void)laminate::payload::write_file_encrypted_trace(
        fixture.contexts.eval, directory.path(), options(), fixture.circuit,
        fixture.trace);
    auto store = FileEncryptedTraceStore<MockBackend>::open(
        fixture.contexts.eval, directory.path(), fixture.payload,
        fixture.circuit, fixture.trace.provenance, fixture.trace.trace_id);
    auto session =
        FileEncryptedTraceReclamationSession<MockBackend>::begin(
            std::move(store),
            FileTraceReclamationOptions{
                FileTraceSessionLifecycle::IrreversibleNoRetry});
    {
        auto reader = session.layer_reader(0);
        while (reader.next()) {
        }
        CHECK(throws_exception([&] { (void)session.retire_layer(0); }));
    }
    const auto report = session.retire_layer(0);
    CHECK(report.layer_index == 0);
}

void test_retirement_event_collision_does_not_remove_layer() {
    Fixture fixture;
    TemporaryDirectory directory;
    (void)laminate::payload::write_file_encrypted_trace(
        fixture.contexts.eval, directory.path(), options(), fixture.circuit,
        fixture.trace);
    auto store = FileEncryptedTraceStore<MockBackend>::open(
        fixture.contexts.eval, directory.path(), fixture.payload,
        fixture.circuit, fixture.trace.provenance, fixture.trace.trace_id);
    auto session =
        FileEncryptedTraceReclamationSession<MockBackend>::begin(
            std::move(store),
            FileTraceReclamationOptions{
                FileTraceSessionLifecycle::IrreversibleNoRetry});
    const std::filesystem::path collision =
        directory.path() / "retirement-0000000000000001.bin";
    write_text(collision, "caller-owned-retirement-event");

    CHECK(throws_exception([&] { (void)session.retire_layer(0); }));
    CHECK(std::filesystem::is_regular_file(layer_file(directory.path(), 0)));
    CHECK(read_text(collision) == "caller-owned-retirement-event");
    CHECK(session.journal_state().generation == 0);
    CHECK(!std::filesystem::exists(
        directory.path() / "retirement-0000000000000001.partial"));
}

void test_reclamation_rejects_replaced_layer_paths() {
    Fixture fixture;
    TemporaryDirectory directory;
    (void)laminate::payload::write_file_encrypted_trace(
        fixture.contexts.eval, directory.path(), options(), fixture.circuit,
        fixture.trace);
    auto store = FileEncryptedTraceStore<MockBackend>::open(
        fixture.contexts.eval, directory.path(), fixture.payload,
        fixture.circuit, fixture.trace.provenance, fixture.trace.trace_id);
    auto session =
        FileEncryptedTraceReclamationSession<MockBackend>::begin(
            std::move(store),
            FileTraceReclamationOptions{
                FileTraceSessionLifecycle::IrreversibleNoRetry});

    const std::filesystem::path layer =
        directory.path() / "layer-0000000000000000.bin";
    const std::filesystem::path original = directory.path() / "original.bin";
    std::filesystem::rename(layer, original);
    std::filesystem::copy_file(original, layer);
    CHECK(throws_exception([&] { (void)session.retire_layer(0); }));
    CHECK(std::filesystem::is_regular_file(layer));
    CHECK(session.journal_state().generation == 0);
}

void test_reclamation_rejects_symlink_layer_paths_where_supported() {
    Fixture fixture;
    TemporaryDirectory directory;
    (void)laminate::payload::write_file_encrypted_trace(
        fixture.contexts.eval, directory.path(), options(), fixture.circuit,
        fixture.trace);
    auto store = FileEncryptedTraceStore<MockBackend>::open(
        fixture.contexts.eval, directory.path(), fixture.payload,
        fixture.circuit, fixture.trace.provenance, fixture.trace.trace_id);
    auto session =
        FileEncryptedTraceReclamationSession<MockBackend>::begin(
            std::move(store),
            FileTraceReclamationOptions{
                FileTraceSessionLifecycle::IrreversibleNoRetry});

    const std::filesystem::path layer =
        directory.path() / "layer-0000000000000000.bin";
    const std::filesystem::path original = directory.path() / "original.bin";
    std::filesystem::rename(layer, original);
    std::error_code error;
    std::filesystem::create_symlink(original.filename(), layer, error);
    if (!error) {
        CHECK(throws_exception([&] { (void)session.retire_layer(0); }));
        CHECK(std::filesystem::is_symlink(
            std::filesystem::symlink_status(layer)));
        CHECK(session.journal_state().generation == 0);
    }
}

void test_caller_selected_open_limits_fail_closed() {
    Fixture fixture;
    TemporaryDirectory directory;
    const auto written = laminate::payload::write_file_encrypted_trace(
        fixture.contexts.eval, directory.path(), options(), fixture.circuit,
        fixture.trace);

    FileTraceStoreOpenLimits limits;
    limits.max_layers = written.descriptor.layers.size() - 1;
    CHECK(throws_exception([&] {
        (void)FileEncryptedTraceStore<MockBackend>::open(
            fixture.contexts.eval, directory.path(), fixture.payload,
            fixture.circuit, fixture.trace.provenance,
            fixture.trace.trace_id, limits);
    }));
    limits = FileTraceStoreOpenLimits{};
    limits.max_records_per_layer = 1;
    CHECK(throws_exception([&] {
        (void)FileEncryptedTraceStore<MockBackend>::open(
            fixture.contexts.eval, directory.path(), fixture.payload,
            fixture.circuit, fixture.trace.provenance,
            fixture.trace.trace_id, limits);
    }));
    limits = FileTraceStoreOpenLimits{};
    limits.max_total_bytes = written.report.physical_bytes - 1;
    CHECK(throws_exception([&] {
        (void)FileEncryptedTraceStore<MockBackend>::open(
            fixture.contexts.eval, directory.path(), fixture.payload,
            fixture.circuit, fixture.trace.provenance,
            fixture.trace.trace_id, limits);
    }));
    limits = FileTraceStoreOpenLimits{};
    limits.max_manifest_bytes =
        std::filesystem::file_size(directory.path() / "manifest.bin") - 1;
    CHECK(throws_exception([&] {
        (void)FileEncryptedTraceStore<MockBackend>::open(
            fixture.contexts.eval, directory.path(), fixture.payload,
            fixture.circuit, fixture.trace.provenance,
            fixture.trace.trace_id, limits);
    }));
    const std::size_t first_record =
        1U + encoding(fixture,
                      fixture.trace.layers.front().wires.front()).size();
    CHECK(MockBackend::storage_ciphertext_byte_limit(fixture.contexts.eval) >=
          first_record);
    limits = FileTraceStoreOpenLimits{};
    limits.max_record_bytes = first_record - 1;
    CHECK(throws_message(
        [&] {
            (void)FileEncryptedTraceStore<MockBackend>::open(
                fixture.contexts.eval, directory.path(), fixture.payload,
                fixture.circuit, fixture.trace.provenance,
                fixture.trace.trace_id, limits);
        },
        "invalid trace layer record length"));
}

void test_backend_record_limit_precedes_backend_decode() {
    Fixture fixture;
    TemporaryDirectory directory;
    const auto descriptor =
        laminate::payload::descriptor_of(fixture.trace);
    const std::uint64_t backend_limit =
        MockBackend::storage_ciphertext_byte_limit(fixture.contexts.eval);
    CHECK(backend_limit < (1ULL << 20U));
    std::vector<std::uint8_t> oversized;
    oversized.reserve(static_cast<std::size_t>(backend_limit + 2U));
    oversized.push_back(static_cast<std::uint8_t>(
        laminate::fhe::FheValueRecordTag::Ciphertext));
    oversized.insert(oversized.end(),
                     static_cast<std::size_t>(backend_limit + 1U), 0x5a);

    laminate::payload::trace_storage::SerializedTraceWriter writer(
        directory.path(), options(),
        MockBackend::storage_context_id(fixture.contexts.eval));
    writer.begin_trace(descriptor.shape, descriptor.provenance,
                       descriptor.circuit_id, descriptor.trace_id,
                       descriptor.layers.size());
    for (std::size_t layer = 0; layer < descriptor.layers.size(); ++layer) {
        const auto &selected = descriptor.layers[layer];
        writer.begin_layer(layer, selected.layout, selected.dimensions,
                           selected.required_mult_depth,
                           selected.record_count);
        for (std::size_t record = 0; record < selected.record_count;
             ++record) {
            writer.append_serialized(oversized);
        }
        writer.finish_layer();
    }
    (void)writer.finish();

    CHECK(throws_message(
        [&] {
            (void)FileEncryptedTraceStore<MockBackend>::open(
                fixture.contexts.eval, directory.path(), fixture.payload,
                fixture.circuit, fixture.trace.provenance,
                fixture.trace.trace_id);
        },
        "ciphertext trace payload exceeds its backend limit"));
}

void test_same_writer_single_layer_handoff_round_trips_and_reclaims() {
    Fixture fixture;
    TemporaryDirectory directory;
    FileTraceStoreOptions selected = options();
    selected.integrity_mode =
        laminate::payload::FileTraceStoreIntegrityMode::SameProcessEphemeral;
    FileEncryptedTraceSink<MockBackend> sink(
        fixture.contexts.eval, directory.path(), selected);
    sink.begin_trace(fixture.trace.shape, fixture.trace.provenance,
                     fixture.trace.circuit_id, fixture.trace.trace_id, 1);
    begin_fixture_layer(sink, fixture, 0);
    append_fixture_stored_wires(sink, fixture, 0);
    const auto live_write_diagnostics = sink.diagnostics_snapshot();
    CHECK(live_write_diagnostics.records ==
          fixture.trace.layers.front().wires.size());
    CHECK(live_write_diagnostics.same_process_unhashed_records ==
          live_write_diagnostics.records);
    CHECK(live_write_diagnostics.capacity_probes > 0);
    sink.finish_layer();

    auto store =
        std::move(sink).finish_private_single_layer_store();
    CHECK(store.descriptor().layers.size() == 1);
    CHECK(store.report().logical_record_bytes > 0);
    const auto write_diagnostics = store.write_diagnostics();
    const std::size_t records =
        store.descriptor().layers.front().record_count;
    CHECK(write_diagnostics.records == records);
    CHECK(write_diagnostics.authenticated_records == 0);
    CHECK(write_diagnostics.authenticated_record_bytes == 0);
    CHECK(write_diagnostics.same_process_unhashed_records == records);
    CHECK(write_diagnostics.same_process_unhashed_record_bytes ==
          store.report().logical_record_bytes);
    CHECK(write_diagnostics.record_copy_bytes == 0);
    CHECK(write_diagnostics.writeback_files_submit_only == 1);
    CHECK(write_diagnostics.writeback_wait_attempts == 0);
    CHECK(write_diagnostics.writeback_drains == 0);
    CHECK(write_diagnostics.positional_write_calls >= 1);
    CHECK(write_diagnostics.positional_write_bytes == sizeof(std::uint64_t));
    CHECK(write_diagnostics.capacity_probes == 3);
    // Records/index and the manifest are separate application batches.
    CHECK(write_diagnostics.write_batches == 3);
    CHECK(write_diagnostics.write_syscalls > 0);
    CHECK(write_diagnostics.bytes_submitted >
          store.report().logical_record_bytes);
    CHECK(write_diagnostics.maximum_batch_bytes > 0);
    CHECK(write_diagnostics.serialization.wall_ms >= 0.0);
    CHECK(write_diagnostics.hashing.wall_ms >= 0.0);
    laminate::payload::FileTraceStoreReadDiagnostics read_diagnostics;
    {
        auto reader = store.layer_range(0, 0, records,
                                        &read_diagnostics);
        CHECK(reader.next().has_value());
        std::size_t first_scan = 1;
        const auto live_read_diagnostics = reader.diagnostics();
        CHECK(live_read_diagnostics.read_batches > 0);
        CHECK(read_diagnostics.read_batches ==
              live_read_diagnostics.read_batches);
        CHECK(read_diagnostics.read_syscalls ==
              live_read_diagnostics.read_syscalls);
        CHECK(read_diagnostics.bytes_transferred ==
              live_read_diagnostics.bytes_transferred);
        CHECK(read_diagnostics.prefetch_requests ==
              live_read_diagnostics.prefetch_requests);
        CHECK(read_diagnostics.prefetch_bytes_requested ==
              live_read_diagnostics.prefetch_bytes_requested);
        while (reader.next()) {
            ++first_scan;
        }
        CHECK(first_scan == records);
        reader.rewind();
        std::size_t second_scan = 0;
        while (reader.next()) {
            ++second_scan;
        }
        CHECK(second_scan == records);
        CHECK(read_diagnostics == reader.diagnostics());
    }
    CHECK(read_diagnostics.read_batches >= 2);
    CHECK(read_diagnostics.read_syscalls >= 2);
    CHECK(read_diagnostics.bytes_transferred >
          store.report().logical_record_bytes);
    CHECK(read_diagnostics.maximum_batch_bytes > 0);
    CHECK(read_diagnostics.transfer_buffer_bytes >=
          read_diagnostics.maximum_batch_bytes);
    CHECK(read_diagnostics.prefetch_window_bytes ==
          laminate::payload::kFileTraceStorePrefetchWindowBytes);
    CHECK(read_diagnostics.maximum_prefetch_request_bytes <=
          laminate::payload::kFileTraceStorePrefetchRequestBytes);
    CHECK(throws_message(
        [&] {
            (void)laminate::payload::trace_storage::SerializedTraceStore::open(
                directory.path(),
                MockBackend::storage_context_id(fixture.contexts.eval),
                [](const auto &) {}, [](auto, auto, auto) {});
        },
        "corrupt trace layer record digest"));
    const std::uint64_t physical_bytes = store.report().physical_bytes;
    CHECK(store.remove_validated_files() == physical_bytes);
    CHECK(std::filesystem::is_empty(directory.path()));

    TemporaryDirectory rejected_directory;
    FileEncryptedTraceSink<MockBackend> rejected(
        fixture.contexts.eval, rejected_directory.path(), selected);
    rejected.begin_trace(fixture.trace.shape, fixture.trace.provenance,
                         fixture.trace.circuit_id, fixture.trace.trace_id, 1);
    begin_fixture_layer(rejected, fixture, 0);
    append_fixture_stored_wires(rejected, fixture, 0);
    rejected.finish_layer();
    CHECK(throws_message([&] { (void)std::move(rejected).finish(); },
                         "requires a consuming private handoff"));
}

void test_private_identity_links_share_bytes_and_reclaim_once() {
#ifndef _WIN32
    Fixture fixture;
    TemporaryDirectory source_directory;
    FileTraceStoreOptions selected = options();
    selected.integrity_mode = FileTraceStoreIntegrityMode::SameProcessEphemeral;
    FileEncryptedTraceSink<MockBackend> sink(
        fixture.contexts.eval, source_directory.path(), selected);
    sink.begin_trace(fixture.trace.shape, fixture.trace.provenance,
                     fixture.trace.circuit_id, fixture.trace.trace_id, 1);
    begin_fixture_layer(sink, fixture, 0);
    append_fixture_stored_wires(sink, fixture, 0);
    sink.finish_layer();
    auto source = std::move(sink).finish_private_single_layer_store();

    TemporaryDirectory first_directory;
    TemporaryDirectory second_directory;
    TemporaryDirectory mismatch_directory;
    std::filesystem::create_directory(first_directory.path());
    std::filesystem::create_directory(second_directory.path());
    std::filesystem::create_directory(mismatch_directory.path());

    auto first_descriptor = source.descriptor();
    first_descriptor.trace_id.front() ^= 0x31U;
    std::swap(first_descriptor.layers.front().dimensions.payload_size,
              first_descriptor.layers.front().dimensions.forward_size);
    CHECK(first_descriptor.layers.front().dimensions !=
          source.descriptor().layers.front().dimensions);
    auto second_descriptor = source.descriptor();
    second_descriptor.trace_id.front() ^= 0x52U;
    FileTraceStorePrivateLinkReport first_publication;
    FileTraceStorePrivateLinkReport second_publication;
    auto first = source.try_link_private_single_layer_store(
        first_directory.path(), first_descriptor, selected,
        first_publication);
    CHECK(first.has_value());
    auto second = source.try_link_private_single_layer_store(
        second_directory.path(), second_descriptor, selected,
        second_publication);
    CHECK(second.has_value());

    const std::filesystem::path source_layer =
        layer_file(source_directory.path(), 0);
    const std::filesystem::path first_layer =
        layer_file(first_directory.path(), 0);
    const std::filesystem::path second_layer =
        layer_file(second_directory.path(), 0);
    struct stat source_metadata {};
    struct stat first_metadata {};
    struct stat second_metadata {};
    CHECK(::lstat(source_layer.c_str(), &source_metadata) == 0);
    CHECK(::lstat(first_layer.c_str(), &first_metadata) == 0);
    CHECK(::lstat(second_layer.c_str(), &second_metadata) == 0);
    CHECK(source_metadata.st_dev == first_metadata.st_dev);
    CHECK(source_metadata.st_ino == first_metadata.st_ino);
    CHECK(source_metadata.st_ino == second_metadata.st_ino);
    CHECK(source_metadata.st_nlink == 3);

    const std::uint64_t manifest_bytes =
        std::filesystem::file_size(source_directory.path() / "manifest.bin");
    const std::uint64_t layer_bytes =
        std::filesystem::file_size(source_layer);
    const FileTraceStorePrivateLinkReport expected_publication{
        .reused_layer_file_bytes = layer_bytes,
        .unique_physical_bytes_added = manifest_bytes,
        .diagnostics = {}};
    CHECK(first_publication == expected_publication);
    CHECK(second_publication == first_publication);
    CHECK(first_publication.diagnostics.capacity_probes == 1);
    CHECK(first_publication.diagnostics.write_batches == 1);
    CHECK(first_publication.diagnostics.write_syscalls >= 1);
    CHECK(first_publication.diagnostics.bytes_submitted == manifest_bytes);
    CHECK(first_publication.diagnostics.maximum_batch_bytes ==
          manifest_bytes);
    CHECK(first_publication.diagnostics.storage_write.wall_ms > 0.0);
    CHECK(first_publication.diagnostics.hashing.wall_ms > 0.0);
    CHECK(first_publication.diagnostics.drain_close_and_publication.wall_ms >
          0.0);
    CHECK(first->report() == source.report());
    CHECK(second->report() == source.report());
    CHECK(first->descriptor() == first_descriptor);
    CHECK(read_text(source_directory.path() / "manifest.bin") !=
          read_text(first_directory.path() / "manifest.bin"));
    CHECK(read_text(first_directory.path() / "manifest.bin") !=
          read_text(second_directory.path() / "manifest.bin"));

    {
        auto source_reader = source.layer_range(
            0, 0, source.descriptor().layers.front().record_count);
        auto first_reader = first->layer_range(
            0, 0, first->descriptor().layers.front().record_count);
        while (const auto expected = source_reader.next()) {
            CHECK(first_reader.next() == expected);
        }
        CHECK(!first_reader.next().has_value());
    }
    {
        auto active = second->layer_range(
            0, 0, second->descriptor().layers.front().record_count);
        CHECK(throws_exception(
            [&] { (void)second->remove_validated_files_detailed(); }));
        CHECK(active.next().has_value());
    }
    CHECK(throws_message(
        [&] {
            (void)SerializedTraceReclamationSession::begin(*first);
        },
        "link-capable private stores require whole-store reclamation"));
    CHECK(!std::filesystem::exists(
        first_directory.path() / "retirement-session.bin"));
    CHECK(std::filesystem::hard_link_count(first_layer) == 3U);

    auto mismatch = source.descriptor();
    mismatch.trace_id.front() ^= 0x73U;
    ++mismatch.layers.front().required_mult_depth;
    FileTraceStorePrivateLinkReport ignored;
    CHECK(throws_exception([&] {
        (void)source.try_link_private_single_layer_store(
            mismatch_directory.path(), mismatch, selected, ignored);
    }));
    CHECK(std::filesystem::is_empty(mismatch_directory.path()));

    const FileTraceStoreRemovalReport first_removal =
        first->remove_validated_files_detailed();
    CHECK(first_removal.namespace_physical_bytes_removed ==
          source.report().physical_bytes);
    CHECK(first_removal.unique_physical_bytes_reclaimed == manifest_bytes);
    const FileTraceStoreRemovalReport source_removal =
        source.remove_validated_files_detailed();
    CHECK(source_removal.unique_physical_bytes_reclaimed == manifest_bytes);
    CHECK(std::filesystem::hard_link_count(second_layer) == 1U);
    const FileTraceStoreRemovalReport second_removal =
        second->remove_validated_files_detailed();
    CHECK(second_removal.unique_physical_bytes_reclaimed ==
          layer_bytes + manifest_bytes);
    CHECK(first_removal.unique_physical_bytes_reclaimed +
              source_removal.unique_physical_bytes_reclaimed +
              second_removal.unique_physical_bytes_reclaimed ==
          layer_bytes + 3U * manifest_bytes);
    CHECK(std::filesystem::is_empty(source_directory.path()));
    CHECK(std::filesystem::is_empty(first_directory.path()));
    CHECK(std::filesystem::is_empty(second_directory.path()));
#endif
}

void test_output_completion_policies_preserve_bytes_and_reopening() {
    Fixture fixture;
    TemporaryDirectory authenticated_directory;
    TemporaryDirectory ephemeral_directory;
    constexpr std::size_t kRecordCount = 3;
    // Each framed record is larger than one writeback submission, exercising
    // the bounded split without constructing a target-sized artifact.
    constexpr std::size_t kRecordBytes = 17ULL << 20U;
    constexpr std::uint64_t kFramedRecordBytes =
        kRecordBytes + sizeof(std::uint64_t);
    constexpr std::uint64_t kSubmissionsPerRecord =
        1U + (kFramedRecordBytes - 1U) /
                 laminate::payload::kFileTraceStoreWritebackSubmissionBytes;
    constexpr std::uint64_t kSuccessfulSubmissionCount =
        kRecordCount * kSubmissionsPerRecord;
    std::vector<std::uint8_t> record(kRecordBytes);
    for (std::size_t index = 0; index < record.size(); ++index) {
        record[index] = static_cast<std::uint8_t>(
            (index * 131U + 17U) & 0xffU);
    }

    FileTraceStoreOptions authenticated_options = options(96ULL << 20U);
    authenticated_options.transfer_buffer_bytes = 1ULL << 20U;
    authenticated_options.writeback_window_bytes = 16ULL << 20U;
    FileTraceStoreOptions ephemeral_options = authenticated_options;
    ephemeral_options.integrity_mode =
        FileTraceStoreIntegrityMode::SameProcessEphemeral;

    Digest circuit_id{};
    circuit_id.front() = 0x41;
    Digest trace_id{};
    trace_id.front() = 0x52;
    const Digest context_id =
        MockBackend::storage_context_id(fixture.contexts.eval);
    FileTraceStoreOptions undersized_writeback_options =
        authenticated_options;
    undersized_writeback_options.writeback_window_bytes =
        laminate::payload::kFileTraceStoreMinimumWritebackWindowBytes - 1U;
    TemporaryDirectory undersized_writeback_directory;
    CHECK(throws_message(
        [&] {
            SerializedTraceWriter rejected(
                undersized_writeback_directory.path(),
                undersized_writeback_options, context_id);
        },
        "writeback_window_bytes must be zero or at least 1 MiB"));

    const auto fill = [&](SerializedTraceWriter &writer) {
        writer.begin_trace(PayloadShape::wide(8),
                           TraceProvenance::SyntheticTrace, circuit_id,
                           trace_id, 1);
        writer.begin_layer(
            0, TraceLayerLayout::Wide,
            LayerDimensions{kRecordCount, 8, kRecordCount, 0}, 0,
            kRecordCount);
        for (std::size_t index = 0; index < kRecordCount; ++index) {
            writer.append_serialized(record);
        }
        writer.finish_layer();
    };

    SerializedTraceWriter authenticated_writer(
        authenticated_directory.path(), authenticated_options, context_id);
    fill(authenticated_writer);
    const auto authenticated = authenticated_writer.finish();

    SerializedTraceWriter ephemeral_writer(
        ephemeral_directory.path(), ephemeral_options, context_id);
    fill(ephemeral_writer);
    auto ephemeral =
        std::move(ephemeral_writer).finish_private_single_layer_store();

    const auto &authenticated_diagnostics = authenticated.diagnostics;
    const auto &ephemeral_diagnostics = ephemeral.write_diagnostics();
    CHECK(authenticated_diagnostics.writeback_files_submit_only == 0);
    CHECK(ephemeral_diagnostics.writeback_files_submit_only == 1);
    CHECK(authenticated_diagnostics.positional_write_calls >= 1);
    CHECK(ephemeral_diagnostics.positional_write_calls >= 1);
    CHECK(authenticated_diagnostics.positional_write_bytes ==
          sizeof(std::uint64_t));
    CHECK(ephemeral_diagnostics.positional_write_bytes ==
          sizeof(std::uint64_t));
    CHECK(ephemeral_diagnostics.writeback_wait_attempts == 0);
    CHECK(ephemeral_diagnostics.writeback_wait_successes == 0);
    CHECK(ephemeral_diagnostics.writeback_range_bytes_waited == 0);
    CHECK(ephemeral_diagnostics.writeback_drains == 0);

    if (ephemeral_diagnostics.writeback_files_enabled != 0) {
        CHECK(ephemeral_diagnostics.writeback_files_enabled == 1);
        CHECK(ephemeral_diagnostics.writeback_files_fallback == 0);
        CHECK(ephemeral_diagnostics.writeback_submission_successes ==
              kSuccessfulSubmissionCount);
        CHECK(ephemeral_diagnostics.writeback_submission_attempts >=
              ephemeral_diagnostics.writeback_submission_successes);
        CHECK(ephemeral_diagnostics.writeback_range_bytes_submitted ==
              kRecordCount * kFramedRecordBytes);
        CHECK(ephemeral_diagnostics.maximum_writeback_submission_bytes > 0);
        CHECK(ephemeral_diagnostics.maximum_writeback_submission_bytes <=
              laminate::payload::kFileTraceStoreWritebackSubmissionBytes);
        CHECK(ephemeral_diagnostics.maximum_writeback_submission_bytes <
              kFramedRecordBytes);
        CHECK(ephemeral_diagnostics.writeback_drains_skipped == 1);
        CHECK(
            ephemeral_diagnostics
                .writeback_range_bytes_without_explicit_wait ==
            ephemeral_diagnostics.writeback_range_bytes_submitted);
        CHECK(ephemeral_diagnostics.writeback_window_bytes == 0);
        CHECK(
            ephemeral_diagnostics
                .maximum_unwaited_writeback_range_bytes == 0);
    } else {
        CHECK(ephemeral_diagnostics.writeback_files_fallback == 1);
        CHECK(ephemeral_diagnostics.writeback_submission_successes == 0);
        CHECK(ephemeral_diagnostics.writeback_range_bytes_submitted == 0);
        CHECK(ephemeral_diagnostics.maximum_writeback_submission_bytes == 0);
        CHECK(ephemeral_diagnostics.writeback_drains_skipped == 0);
        CHECK(
            ephemeral_diagnostics
                .writeback_range_bytes_without_explicit_wait ==
            ephemeral_diagnostics.writeback_range_bytes_submitted);
    }

    if (authenticated_diagnostics.writeback_files_enabled != 0) {
        CHECK(authenticated_diagnostics.writeback_files_enabled == 1);
        CHECK(authenticated_diagnostics.writeback_files_fallback == 0);
        CHECK(authenticated_diagnostics.writeback_submission_successes ==
              kSuccessfulSubmissionCount);
        CHECK(authenticated_diagnostics.writeback_submission_attempts >=
              authenticated_diagnostics.writeback_submission_successes);
        CHECK(authenticated_diagnostics.maximum_writeback_submission_bytes >
              0);
        CHECK(authenticated_diagnostics.maximum_writeback_submission_bytes <=
              laminate::payload::kFileTraceStoreWritebackSubmissionBytes);
        CHECK(
            authenticated_diagnostics
                .maximum_unwaited_writeback_range_bytes <=
            authenticated_diagnostics.writeback_window_bytes);
        CHECK(authenticated_diagnostics.writeback_wait_attempts > 0);
        CHECK(authenticated_diagnostics.writeback_wait_successes > 0);
        CHECK(authenticated_diagnostics.writeback_wait_attempts >=
              authenticated_diagnostics.writeback_wait_successes);
        CHECK(authenticated_diagnostics.writeback_range_bytes_waited ==
              authenticated_diagnostics.writeback_range_bytes_submitted);
        CHECK(authenticated_diagnostics.writeback_drains > 0);
        CHECK(authenticated_diagnostics.writeback_drain_range_bytes > 0);
    } else {
        CHECK(authenticated_diagnostics.writeback_files_fallback == 1);
        CHECK(authenticated_diagnostics.writeback_submission_successes == 0);
        CHECK(authenticated_diagnostics.writeback_range_bytes_submitted == 0);
        CHECK(authenticated_diagnostics.maximum_writeback_submission_bytes ==
              0);
        CHECK(authenticated_diagnostics.writeback_range_bytes_waited <=
              authenticated_diagnostics.writeback_range_bytes_submitted);
    }
    CHECK(authenticated_diagnostics.writeback_drains_skipped == 0);
    CHECK(authenticated_diagnostics
              .writeback_range_bytes_without_explicit_wait == 0);

    const std::filesystem::path authenticated_layer =
        layer_file(authenticated_directory.path(), 0);
    const std::filesystem::path ephemeral_layer =
        layer_file(ephemeral_directory.path(), 0);
    CHECK(read_text(authenticated_layer) == read_text(ephemeral_layer));
    CHECK(std::filesystem::file_size(authenticated_layer) ==
          std::filesystem::file_size(ephemeral_layer));

    std::size_t validated_records = 0;
    auto reopened = SerializedTraceStore::open(
        authenticated_directory.path(), context_id,
        [&](const auto &descriptor) {
            CHECK(descriptor.layers.size() == 1);
            CHECK(descriptor.layers.front().record_count == kRecordCount);
        },
        [&](std::size_t layer, std::size_t index,
            std::span<const std::uint8_t> encoded) {
            CHECK(layer == 0);
            CHECK(index == validated_records);
            CHECK(std::ranges::equal(encoded, record));
            ++validated_records;
        });
    CHECK(validated_records == kRecordCount);

    {
        auto ephemeral_reader = ephemeral.layer_range(0, 0, kRecordCount);
        for (std::size_t index = 0; index < kRecordCount; ++index) {
            const auto encoded = ephemeral_reader.next_view();
            CHECK(encoded.has_value());
            CHECK(std::ranges::equal(*encoded, record));
        }
        CHECK(!ephemeral_reader.next_view().has_value());
    }

    CHECK(reopened.remove_validated_files() ==
          authenticated.report.physical_bytes);
    CHECK(ephemeral.remove_validated_files() ==
          ephemeral.report().physical_bytes);
}

void test_reusable_gathered_reader_handles_alternating_record_sizes() {
    Fixture fixture;
    TemporaryDirectory directory;
    TemporaryDirectory scalar_directory;
    std::vector<std::vector<std::uint8_t>> records;
    for (const std::size_t size :
         {1016U, 511U, 3U, 2048U, 509U, 1U, 507U}) {
        std::vector<std::uint8_t> record(size);
        for (std::size_t index = 0; index < size; ++index) {
            record[index] = static_cast<std::uint8_t>(
                (records.size() * 37U + index * 11U) & 0xffU);
        }
        records.push_back(std::move(record));
    }

    FileTraceStoreOptions buffered_options = options();
    buffered_options.transfer_buffer_bytes = 1024;
    SerializedTraceWriter writer(
        directory.path(), buffered_options,
        MockBackend::storage_context_id(fixture.contexts.eval));
    Digest circuit_id{};
    circuit_id.front() = 0x41;
    Digest trace_id{};
    trace_id.front() = 0x52;
    writer.begin_trace(PayloadShape::wide(8),
                       TraceProvenance::SyntheticTrace, circuit_id,
                       trace_id, 1);
    writer.begin_layer(
        0, TraceLayerLayout::Wide,
        LayerDimensions{records.size(), 8, records.size(), 0}, 0,
        records.size());
    for (const auto &record : records) {
        writer.append_serialized_direct(
            record.size(), [&](std::vector<std::uint8_t> &output) {
                output.insert(output.end(), record.begin(), record.end());
            });
    }
    writer.finish_layer();
    auto store =
        std::move(writer).finish_private_single_layer_store();

    FileTraceStoreOptions scalar_options = options();
    scalar_options.transfer_buffer_bytes = 1;
    scalar_options.writeback_window_bytes = 0;
    SerializedTraceWriter scalar_writer(
        scalar_directory.path(), scalar_options,
        MockBackend::storage_context_id(fixture.contexts.eval));
    scalar_writer.begin_trace(PayloadShape::wide(8),
                              TraceProvenance::SyntheticTrace,
                              circuit_id, trace_id, 1);
    scalar_writer.begin_layer(
        0, TraceLayerLayout::Wide,
        LayerDimensions{records.size(), 8, records.size(), 0}, 0,
        records.size());
    for (const auto &record : records) {
        scalar_writer.append_serialized(record);
    }
    scalar_writer.finish_layer();
    const auto scalar_written = scalar_writer.finish();
    CHECK(read_text(directory.path() / "manifest.bin") ==
          read_text(scalar_directory.path() / "manifest.bin"));
    CHECK(read_text(layer_file(directory.path(), 0)) ==
          read_text(layer_file(scalar_directory.path(), 0)));
    CHECK(store.report() == scalar_written.report);
    CHECK(store.write_diagnostics().write_batches <
          scalar_written.diagnostics.write_batches);
    CHECK(store.write_diagnostics().maximum_batch_bytes == 2056);
    CHECK(scalar_written.diagnostics.writeback_files_enabled == 0);
    CHECK(scalar_written.diagnostics.writeback_files_fallback == 0);
    CHECK(scalar_written.diagnostics.writeback_submission_attempts == 0);

    auto reader = store.layer_range(0, 0, records.size());
    std::vector<std::uint8_t> buffer;
    buffer.reserve(4096);
    const std::uint8_t *const allocation = buffer.data();
    const std::size_t capacity = buffer.capacity();
    for (std::size_t index = 0; index < records.size(); ++index) {
        reader.seek_to(reader.position());
        const auto record = reader.next_into(buffer);
        CHECK(record.has_value());
        CHECK(std::ranges::equal(*record, records[index]));
        CHECK(buffer.data() == allocation);
        CHECK(buffer.size() == record->size());
        CHECK(buffer.capacity() == capacity);
        if (index == 2) {
            CHECK(record->size() == 3);
        }
    }
    CHECK(!reader.next_into(buffer).has_value());
    CHECK(reader.diagnostics().prefetch_seek_disables == 0);

    reader.rewind();
    for (const auto &expected : records) {
        const auto record = reader.next_into(buffer);
        CHECK(record.has_value());
        CHECK(std::ranges::equal(*record, expected));
        CHECK(buffer.data() == allocation);
        CHECK(buffer.size() == expected.size());
        CHECK(buffer.capacity() == capacity);
    }

    auto compatible = store.layer_range(0, 0, records.size());
    for (const auto &expected : records) {
        const auto record = compatible.next();
        CHECK(record.has_value());
        CHECK(*record == expected);
    }
    CHECK(!compatible.next().has_value());
}

// Deterministic per-record bytes, distinct at every (record, position), so a
// misaligned, duplicated, or truncated read is caught byte-for-byte.
std::vector<std::uint8_t> synthetic_record(std::size_t index,
                                           std::size_t size) {
    std::vector<std::uint8_t> record(size);
    std::uint64_t state =
        0x9e3779b97f4a7c15ULL ^ (index * 0xd1b54a32d192ed03ULL);
    for (std::size_t position = 0; position < size; ++position) {
        state = state * 6364136223846793005ULL + 1442695040888963407ULL;
        record[position] = static_cast<std::uint8_t>(state >> 56U);
    }
    return record;
}

// Exercise a read-ahead refill with a record that straddles the block
// boundary. Check complete scans, a sub-range starting mid-layer, seeks
// across the boundary, and rewinds.
void test_range_reader_spans_multiple_read_ahead_blocks() {
    Fixture fixture;
    TemporaryDirectory directory;

    // Roughly 1 MiB records with varied lengths put a block boundary inside a
    // record. The complete layer exceeds the read-ahead buffer.
    constexpr std::size_t kRecordCount = 160;
    const auto record_size = [](std::size_t index) -> std::size_t {
        return (1ULL << 20U) + (index % 7U) * 4099U;
    };

    SerializedTraceWriter writer(
        directory.path(), options(256ULL << 20U),
        MockBackend::storage_context_id(fixture.contexts.eval));
    Digest circuit_id{};
    circuit_id.front() = 0x41;
    Digest trace_id{};
    trace_id.front() = 0x52;
    writer.begin_trace(PayloadShape::wide(8),
                       TraceProvenance::SyntheticTrace, circuit_id, trace_id,
                       1);
    // {logical_size, padded_size (power of two >= logical), payload_size,
    //  forward_size}; payload_size + forward_size == logical_size.
    writer.begin_layer(0, TraceLayerLayout::Wide,
                       LayerDimensions{kRecordCount, 256, kRecordCount, 0}, 0,
                       kRecordCount);
    for (std::size_t index = 0; index < kRecordCount; ++index) {
        writer.append_serialized(synthetic_record(index, record_size(index)));
    }
    writer.finish_layer();
    auto store = std::move(writer).finish_private_single_layer_store();
    const auto write_diagnostics = store.write_diagnostics();
    CHECK(write_diagnostics.writeback_window_bytes ==
          (256ULL << 20U));
    CHECK(write_diagnostics.maximum_unwaited_writeback_range_bytes <=
          write_diagnostics.writeback_window_bytes);
    if (write_diagnostics.writeback_files_enabled != 0) {
        CHECK(write_diagnostics.writeback_files_enabled == 1);
        CHECK(write_diagnostics.writeback_files_fallback == 0);
        CHECK(write_diagnostics.writeback_submission_attempts > 0);
        CHECK(write_diagnostics.writeback_wait_attempts > 0);
        CHECK(write_diagnostics.writeback_range_bytes_submitted > 0);
        CHECK(write_diagnostics.writeback_range_bytes_waited ==
              write_diagnostics.writeback_range_bytes_submitted);
    } else {
        CHECK(write_diagnostics.writeback_files_fallback == 1);
        CHECK(write_diagnostics.writeback_range_bytes_submitted == 0);
        CHECK(write_diagnostics.writeback_range_bytes_waited == 0);
    }

    // 1. Full sequential scan crossing every block boundary.
    {
        auto reader = store.layer_range(0, 0, kRecordCount);
        for (std::size_t index = 0; index < kRecordCount; ++index) {
            const auto record = reader.next_view();
            CHECK(record.has_value());
            CHECK(std::ranges::equal(
                *record, synthetic_record(index, record_size(index))));
        }
        CHECK(!reader.next_view().has_value());
        const auto reads = reader.diagnostics();
        CHECK(reads.prefetch_window_bytes ==
              laminate::payload::kFileTraceStorePrefetchWindowBytes);
        CHECK(reads.prefetch_fallbacks <= 1);
        CHECK(reads.maximum_prefetch_request_bytes <=
              laminate::payload::kFileTraceStorePrefetchRequestBytes);
        if (reads.prefetch_requests != 0) {
            CHECK(reads.prefetch_bytes_requested >
                  reads.maximum_prefetch_request_bytes);
            CHECK(reads.maximum_prefetch_request_bytes > 0);
            CHECK(reads.maximum_prefetch_request_bytes >=
                  laminate::payload::
                      kFileTraceStoreMinimumPrefetchRequestBytes);
            CHECK(reads.maximum_prefetch_request_bytes <=
                  laminate::payload::kFileTraceStorePrefetchRequestBytes);
        } else {
            CHECK(reads.prefetch_fallbacks == 1);
            CHECK(reads.prefetch_bytes_requested == 0);
            CHECK(reads.maximum_prefetch_request_bytes == 0);

            // A permanent capability/advice failure must remain disabled
            // across sequential rewinds; rewind only reverses temporary
            // random-seek suppression.
            reader.rewind();
            CHECK(reader.next_view().has_value());
            reader.rewind();
            CHECK(reader.next_view().has_value());
            CHECK(reader.diagnostics().prefetch_fallbacks == 1);
        }
    }

    // 2. Sub-range starting mid-layer: the first refill must seek to a
    //    non-zero offset far past the file start.
    {
        const std::size_t begin = kRecordCount / 2U;
        auto reader = store.layer_range(0, begin, kRecordCount);
        std::vector<std::uint8_t> buffer;
        for (std::size_t index = begin; index < kRecordCount; ++index) {
            const auto record = reader.next_into(buffer);
            CHECK(record.has_value());
            CHECK(std::ranges::equal(
                *record, synthetic_record(index, record_size(index))));
        }
        CHECK(!reader.next_into(buffer).has_value());
    }

    // 3. seek_to across block boundaries, then rewind, still byte-exact.
    {
        auto reader = store.layer_range(0, 0, kRecordCount);
        std::vector<std::uint8_t> buffer;
        reader.seek_to(0);
        CHECK(reader.diagnostics().prefetch_seek_disables == 0);
        const std::array random_indices{
            kRecordCount - 1U, std::size_t{0}, kRecordCount / 2U,
            std::size_t{3}};
        std::uint64_t expected_random_bytes = 0;
        std::uint64_t maximum_random_record = 0;
        for (const std::size_t index : random_indices) {
            reader.seek_to(index);
            const auto record = reader.next_into(buffer);
            CHECK(record.has_value());
            CHECK(std::ranges::equal(
                *record, synthetic_record(index, record_size(index))));
            const std::uint64_t framed =
                record_size(index) + sizeof(std::uint64_t);
            expected_random_bytes += framed;
            maximum_random_record =
                std::max(maximum_random_record, framed);
        }
        const auto random_reads = reader.diagnostics();
        CHECK(random_reads.prefetch_seek_disables == 1);
        CHECK(random_reads.prefetch_requests == 0);
        CHECK(random_reads.prefetch_bytes_requested == 0);
        CHECK(random_reads.prefetch_fallbacks == 0);
        CHECK(random_reads.read_batches == random_indices.size());
        CHECK(random_reads.bytes_transferred == expected_random_bytes);
        CHECK(random_reads.maximum_batch_bytes == maximum_random_record);
        reader.rewind();
        const auto first = reader.next_into(buffer);
        CHECK(first.has_value());
        CHECK(std::ranges::equal(*first, synthetic_record(0, record_size(0))));
        const auto rewound_reads = reader.diagnostics();
        CHECK(rewound_reads.prefetch_seek_disables == 1);
        CHECK(rewound_reads.prefetch_requests > 0 ||
              rewound_reads.prefetch_fallbacks == 1);
    }

    // 4. An explicitly random reader must suppress block read-ahead before its
    //    first access even when the selected record is ordinal zero.
    {
        auto reader = store.layer_range(
            0, 0, kRecordCount, nullptr,
            FileTraceStoreReadPattern::Random);
        const auto first = reader.next_view();
        CHECK(first.has_value());
        CHECK(std::ranges::equal(
            *first, synthetic_record(0, record_size(0))));
        const auto reads = reader.diagnostics();
        const std::uint64_t framed =
            record_size(0) + sizeof(std::uint64_t);
        CHECK(reads.prefetch_requests == 0);
        CHECK(reads.prefetch_bytes_requested == 0);
        CHECK(reads.prefetch_fallbacks == 0);
        CHECK(reads.prefetch_seek_disables == 0);
        CHECK(reads.prefetch_window_bytes == 0);
        CHECK(reads.read_batches == 1);
        CHECK(reads.bytes_transferred == framed);
        CHECK(reads.maximum_batch_bytes == framed);
    }
}

void test_same_writer_handoff_rejects_replaced_layer() {
#ifndef _WIN32
    Fixture fixture;
    TemporaryDirectory directory;
    TemporaryDirectory external;
    std::filesystem::create_directory(external.path());
    FileEncryptedTraceSink<MockBackend> sink(
        fixture.contexts.eval, directory.path(), options());
    sink.begin_trace(fixture.trace.shape, fixture.trace.provenance,
                     fixture.trace.circuit_id, fixture.trace.trace_id, 1);
    begin_fixture_layer(sink, fixture, 0);
    append_fixture_stored_wires(sink, fixture, 0);
    sink.finish_layer();
    auto store =
        std::move(sink).finish_private_single_layer_store();

    const std::filesystem::path layer = layer_file(directory.path(), 0);
    const std::filesystem::path original = external.path() / "original.bin";
    std::filesystem::rename(layer, original);
    std::filesystem::copy_file(original, layer);
    CHECK(throws_exception([&] {
        (void)store.layer_range(
            0, 0, store.descriptor().layers.front().record_count);
    }));
    CHECK(throws_exception([&] {
        (void)store.remove_validated_files();
    }));
#endif
}

void test_failed_same_writer_handoff_reclaims_owned_publications() {
    Fixture fixture;
    TemporaryDirectory directory;
    FileEncryptedTraceSink<MockBackend> sink(
        fixture.contexts.eval, directory.path(), options());
    sink.begin_trace(fixture.trace.shape, fixture.trace.provenance,
                     fixture.trace.circuit_id, fixture.trace.trace_id, 1);
    begin_fixture_layer(sink, fixture, 0);
    append_fixture_stored_wires(sink, fixture, 0);
    sink.finish_layer();

    const std::filesystem::path unexpected =
        directory.path() / "caller-owned.txt";
    {
        std::ofstream marker(unexpected, std::ios::binary);
        marker << "preserve me";
    }
    CHECK(throws_exception([&] {
        (void)std::move(sink).finish_private_single_layer_store();
    }));
    CHECK(std::filesystem::is_regular_file(unexpected));
    CHECK(!std::filesystem::exists(layer_file(directory.path(), 0)));
    CHECK(!std::filesystem::exists(directory.path() / "manifest.bin"));
}

void test_partial_layer_creation_never_truncates_an_existing_path() {
    Fixture fixture;
    TemporaryDirectory directory;
    FileEncryptedTraceSink<MockBackend> sink(
        fixture.contexts.eval, directory.path(), options());
    sink.begin_trace(fixture.trace.shape, fixture.trace.provenance,
                     fixture.trace.circuit_id, fixture.trace.trace_id,
                     fixture.trace.layers.size());
    const std::filesystem::path partial =
        directory.path() / "layer-0000000000000000.partial";
    {
        std::ofstream marker(partial, std::ios::binary);
        marker << "caller-owned";
    }
    CHECK(throws_exception([&] {
        begin_fixture_layer(sink, fixture, 0);
    }));
    std::ifstream marker(partial, std::ios::binary);
    std::string contents;
    marker >> contents;
    CHECK(contents == "caller-owned");
}

void test_layer_publication_never_replaces_an_existing_final_path() {
    Fixture fixture;
    TemporaryDirectory directory;
    FileEncryptedTraceSink<MockBackend> sink(
        fixture.contexts.eval, directory.path(), options());
    sink.begin_trace(fixture.trace.shape, fixture.trace.provenance,
                     fixture.trace.circuit_id, fixture.trace.trace_id,
                     fixture.trace.layers.size());
    begin_fixture_layer(sink, fixture, 0);
    append_fixture_stored_wires(sink, fixture, 0);
    const std::filesystem::path final = layer_file(directory.path(), 0);
    {
        std::ofstream marker(final, std::ios::binary);
        marker << "caller-owned";
    }
    CHECK(throws_exception([&] { sink.finish_layer(); }));
    std::ifstream marker(final, std::ios::binary);
    std::string contents;
    marker >> contents;
    CHECK(contents == "caller-owned");
    CHECK(!std::filesystem::exists(
        directory.path() / "layer-0000000000000000.partial"));
}

void test_symlink_and_hardlink_collisions_never_modify_targets() {
#ifndef _WIN32
    Fixture fixture;

    {
        TemporaryDirectory directory;
        TemporaryDirectory external;
        std::filesystem::create_directory(external.path());
        const std::filesystem::path sentinel = external.path() / "sentinel";
        write_text(sentinel, "symlink-partial-target");
        FileEncryptedTraceSink<MockBackend> sink(
            fixture.contexts.eval, directory.path(), options());
        sink.begin_trace(fixture.trace.shape, fixture.trace.provenance,
                         fixture.trace.circuit_id, fixture.trace.trace_id,
                         fixture.trace.layers.size());
        const std::filesystem::path partial =
            directory.path() / "layer-0000000000000000.partial";
        std::filesystem::create_symlink(sentinel, partial);
        CHECK(throws_exception([&] {
            begin_fixture_layer(sink, fixture, 0);
        }));
        CHECK(read_text(sentinel) == "symlink-partial-target");
        CHECK(std::filesystem::is_symlink(
            std::filesystem::symlink_status(partial)));
    }

    {
        TemporaryDirectory directory;
        TemporaryDirectory external;
        std::filesystem::create_directory(external.path());
        const std::filesystem::path sentinel = external.path() / "sentinel";
        write_text(sentinel, "hardlink-partial-target");
        FileEncryptedTraceSink<MockBackend> sink(
            fixture.contexts.eval, directory.path(), options());
        sink.begin_trace(fixture.trace.shape, fixture.trace.provenance,
                         fixture.trace.circuit_id, fixture.trace.trace_id,
                         fixture.trace.layers.size());
        const std::filesystem::path partial =
            directory.path() / "layer-0000000000000000.partial";
        std::filesystem::create_hard_link(sentinel, partial);
        CHECK(throws_exception([&] {
            begin_fixture_layer(sink, fixture, 0);
        }));
        CHECK(read_text(sentinel) == "hardlink-partial-target");
        CHECK(std::filesystem::equivalent(sentinel, partial));
    }

    {
        TemporaryDirectory directory;
        TemporaryDirectory external;
        std::filesystem::create_directory(external.path());
        const std::filesystem::path sentinel = external.path() / "sentinel";
        write_text(sentinel, "symlink-final-target");
        FileEncryptedTraceSink<MockBackend> sink(
            fixture.contexts.eval, directory.path(), options());
        sink.begin_trace(fixture.trace.shape, fixture.trace.provenance,
                         fixture.trace.circuit_id, fixture.trace.trace_id,
                         fixture.trace.layers.size());
        begin_fixture_layer(sink, fixture, 0);
        append_fixture_stored_wires(sink, fixture, 0);
        const std::filesystem::path final = layer_file(directory.path(), 0);
        std::filesystem::create_symlink(sentinel, final);
        CHECK(throws_exception([&] { sink.finish_layer(); }));
        CHECK(read_text(sentinel) == "symlink-final-target");
        CHECK(std::filesystem::is_symlink(
            std::filesystem::symlink_status(final)));
        CHECK(!std::filesystem::exists(
            directory.path() / "layer-0000000000000000.partial"));
    }

    {
        TemporaryDirectory directory;
        TemporaryDirectory external;
        std::filesystem::create_directory(external.path());
        const std::filesystem::path sentinel = external.path() / "sentinel";
        write_text(sentinel, "hardlink-final-target");
        FileEncryptedTraceSink<MockBackend> sink(
            fixture.contexts.eval, directory.path(), options());
        sink.begin_trace(fixture.trace.shape, fixture.trace.provenance,
                         fixture.trace.circuit_id, fixture.trace.trace_id,
                         fixture.trace.layers.size());
        begin_fixture_layer(sink, fixture, 0);
        append_fixture_stored_wires(sink, fixture, 0);
        const std::filesystem::path final = layer_file(directory.path(), 0);
        std::filesystem::create_hard_link(sentinel, final);
        CHECK(throws_exception([&] { sink.finish_layer(); }));
        CHECK(read_text(sentinel) == "hardlink-final-target");
        CHECK(std::filesystem::equivalent(sentinel, final));
        CHECK(!std::filesystem::exists(
            directory.path() / "layer-0000000000000000.partial"));
    }
#endif
}

void replace_manifest_version(const std::filesystem::path &path,
                              std::uint64_t version) {
    const std::uintmax_t length = std::filesystem::file_size(path);
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(length));
    {
        std::ifstream input(path, std::ios::binary);
        input.read(reinterpret_cast<char *>(bytes.data()),
                   static_cast<std::streamsize>(bytes.size()));
        if (!input) {
            throw std::runtime_error("failed to read manifest");
        }
    }
    if (bytes.size() < 8 + 8 + Digest{}.size()) {
        throw std::runtime_error("manifest is too short for version test");
    }
    for (std::size_t byte = 0; byte < 8; ++byte) {
        bytes[8 + byte] = static_cast<std::uint8_t>(
            (version >> (8U * byte)) & 0xffU);
    }
    const std::size_t body_size = bytes.size() - Digest{}.size();
    const Digest checksum =
        laminate::sha256(std::span<const std::uint8_t>(bytes).first(
            body_size));
    std::copy(checksum.begin(), checksum.end(),
              bytes.begin() + static_cast<std::ptrdiff_t>(body_size));
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output.write(reinterpret_cast<const char *>(bytes.data()),
                 static_cast<std::streamsize>(bytes.size()));
    if (!output) {
        throw std::runtime_error("failed to rewrite manifest");
    }
}

void test_open_rejects_pre_open_record_corruption() {
    Fixture fixture;
    TemporaryDirectory corrupt_directory;
    (void)laminate::payload::write_file_encrypted_trace(
        fixture.contexts.eval, corrupt_directory.path(), options(),
        fixture.circuit, fixture.trace);
    const std::filesystem::path first_layer =
        corrupt_directory.path() / "layer-0000000000000000.bin";
    flip_byte(first_layer, 48);
    CHECK(throws_exception([&] {
        (void)FileEncryptedTraceStore<MockBackend>::open(
            fixture.contexts.eval, corrupt_directory.path(), fixture.payload,
            fixture.circuit, fixture.trace.provenance,
            fixture.trace.trace_id);
    }));
}

void test_open_rejects_context_and_execution_mismatch() {
    Fixture fixture;
    TemporaryDirectory context_directory;
    (void)laminate::payload::write_file_encrypted_trace(
        fixture.contexts.eval, context_directory.path(), options(),
        fixture.circuit, fixture.trace);
    const std::vector<SlotVector> other_inputs{
        {Fp(13), Fp(21)},
        {Fp(34), Fp(55)},
    };
    const auto other_plain = laminate::payload::synthesize_trace(
        fixture.payload, fixture.circuit, other_inputs);
    const auto other_trace =
        laminate::payload::encrypt_compact_synthetic_trace<MockBackend>(
        fixture.contexts.eval, fixture.contexts.client, fixture.payload,
        fixture.circuit, other_plain,
        TraceEncryptionPlan::uniform(fixture.circuit, 2));
    CHECK(other_trace.trace_id != fixture.trace.trace_id);
    CHECK(throws_exception([&] {
        (void)FileEncryptedTraceStore<MockBackend>::open(
            fixture.contexts.eval, context_directory.path(), fixture.payload,
            fixture.circuit, other_trace.provenance,
            other_trace.trace_id);
    }));
    CHECK(throws_exception([&] {
        (void)FileEncryptedTraceStore<MockBackend>::open(
            fixture.contexts.eval, context_directory.path(), fixture.payload,
            fixture.circuit,
            laminate::payload::TraceProvenance::FheEvaluated,
            fixture.trace.trace_id);
    }));
    auto incompatible = MockBackend::create(MockParameters{
        .slot_count = 8,
        .fresh_rns_limbs = 8,
        .bits_per_limb = 61,
    });
    CHECK(throws_exception([&] {
        (void)FileEncryptedTraceStore<MockBackend>::open(
            incompatible.eval, context_directory.path(), fixture.payload,
            fixture.circuit, fixture.trace.provenance,
            fixture.trace.trace_id);
    }));
}

void test_open_rejects_missing_truncated_and_wrong_circuit() {
    Fixture fixture;
    const FileTraceStoreOptions selected = options();

    TemporaryDirectory missing_directory;
    (void)laminate::payload::write_file_encrypted_trace(
        fixture.contexts.eval, missing_directory.path(), selected,
        fixture.circuit, fixture.trace);
    std::filesystem::remove(
        missing_directory.path() / "layer-0000000000000000.bin");
    CHECK(throws_exception([&] {
        (void)FileEncryptedTraceStore<MockBackend>::open(
            fixture.contexts.eval, missing_directory.path(), fixture.payload,
            fixture.circuit, fixture.trace.provenance,
            fixture.trace.trace_id);
    }));

    TemporaryDirectory truncated_directory;
    (void)laminate::payload::write_file_encrypted_trace(
        fixture.contexts.eval, truncated_directory.path(), selected,
        fixture.circuit, fixture.trace);
    const std::filesystem::path layer =
        truncated_directory.path() / "layer-0000000000000000.bin";
    std::filesystem::resize_file(layer,
                                 std::filesystem::file_size(layer) - 1);
    CHECK(throws_exception([&] {
        (void)FileEncryptedTraceStore<MockBackend>::open(
            fixture.contexts.eval, truncated_directory.path(),
            fixture.payload, fixture.circuit, fixture.trace.provenance,
            fixture.trace.trace_id);
    }));

    TemporaryDirectory circuit_directory;
    (void)laminate::payload::write_file_encrypted_trace(
        fixture.contexts.eval, circuit_directory.path(), selected,
        fixture.circuit, fixture.trace);
    PayloadBuilder other_builder(PayloadShape::laned(2, 8), 2);
    const auto other_output = other_builder.add(0, 1);
    other_builder.set_outputs({other_output});
    const PayloadCircuit other_payload = other_builder.finish();
    const LayeredCircuit other_circuit =
        laminate::payload::compile(other_payload);
    CHECK(throws_exception([&] {
        (void)FileEncryptedTraceStore<MockBackend>::open(
            fixture.contexts.eval, circuit_directory.path(), other_payload,
            other_circuit, fixture.trace.provenance,
            fixture.trace.trace_id);
    }));
}

void test_open_rejects_symlink_and_fifo_inputs_without_following() {
#ifndef _WIN32
    Fixture fixture;

    {
        TemporaryDirectory directory;
        TemporaryDirectory external;
        std::filesystem::create_directory(external.path());
        (void)laminate::payload::write_file_encrypted_trace(
            fixture.contexts.eval, directory.path(), options(),
            fixture.circuit, fixture.trace);
        const std::filesystem::path manifest =
            directory.path() / "manifest.bin";
        const std::filesystem::path original =
            external.path() / "manifest.bin";
        std::filesystem::rename(manifest, original);
        std::filesystem::create_symlink(original, manifest);
        CHECK(throws_exception([&] {
            (void)FileEncryptedTraceStore<MockBackend>::open(
                fixture.contexts.eval, directory.path(), fixture.payload,
                fixture.circuit, fixture.trace.provenance,
                fixture.trace.trace_id);
        }));
        CHECK(std::filesystem::is_symlink(
            std::filesystem::symlink_status(manifest)));
    }

    {
        TemporaryDirectory directory;
        TemporaryDirectory external;
        std::filesystem::create_directory(external.path());
        (void)laminate::payload::write_file_encrypted_trace(
            fixture.contexts.eval, directory.path(), options(),
            fixture.circuit, fixture.trace);
        const std::filesystem::path layer = layer_file(directory.path(), 0);
        std::filesystem::rename(layer, external.path() / "layer.bin");
        if (::mkfifo(layer.c_str(), 0600) != 0) {
            throw std::runtime_error("failed to create trace-store FIFO");
        }
        CHECK(throws_exception([&] {
            (void)FileEncryptedTraceStore<MockBackend>::open(
                fixture.contexts.eval, directory.path(), fixture.payload,
                fixture.circuit, fixture.trace.provenance,
                fixture.trace.trace_id);
        }));
    }
#endif
}

void test_range_reader_binds_the_validated_layer_inode() {
#ifndef _WIN32
    Fixture fixture;
    TemporaryDirectory directory;
    TemporaryDirectory external;
    std::filesystem::create_directory(external.path());
    (void)laminate::payload::write_file_encrypted_trace(
        fixture.contexts.eval, directory.path(), options(), fixture.circuit,
        fixture.trace);
    const auto store = FileEncryptedTraceStore<MockBackend>::open(
        fixture.contexts.eval, directory.path(), fixture.payload,
        fixture.circuit, fixture.trace.provenance, fixture.trace.trace_id);

    const std::filesystem::path layer = layer_file(directory.path(), 0);
    const std::filesystem::path original =
        external.path() / "original-layer.bin";
    std::filesystem::rename(layer, original);
    std::filesystem::copy_file(original, layer);
    CHECK(throws_message([&] { (void)store.layer_reader(0); },
                         "replaced after validation"));
#endif
}

void test_open_rejects_unsupported_store_version() {
    Fixture fixture;
    TemporaryDirectory directory;
    const FileTraceStoreOptions selected = options();
    (void)laminate::payload::write_file_encrypted_trace(
        fixture.contexts.eval, directory.path(), selected, fixture.circuit,
        fixture.trace);
    replace_manifest_version(directory.path() / "manifest.bin", 2);
    CHECK(throws_exception([&] {
        (void)FileEncryptedTraceStore<MockBackend>::open(
            fixture.contexts.eval, directory.path(), fixture.payload,
            fixture.circuit, fixture.trace.provenance,
            fixture.trace.trace_id);
    }));
}

void test_descriptor_and_destination_validation() {
    Fixture fixture;
    auto descriptor = laminate::payload::descriptor_of(fixture.trace);
    laminate::payload::validate_encrypted_trace_descriptor_for_circuit(
        descriptor, fixture.payload, fixture.circuit);
    ++descriptor.layers.front().record_count;
    CHECK(throws_exception([&] {
        laminate::payload::validate_encrypted_trace_descriptor_for_circuit(
            descriptor, fixture.payload, fixture.circuit);
    }));

    auto malformed_trace = fixture.trace;
    malformed_trace.layers.front().wires.pop_back();
    const auto malformed_descriptor =
        laminate::payload::descriptor_of(malformed_trace);
    CHECK(malformed_descriptor.layers.front().record_count ==
          malformed_trace.layers.front().wires.size());
    CHECK(throws_exception([&] {
        laminate::payload::validate_encrypted_trace_descriptor_for_circuit(
            malformed_descriptor, fixture.payload, fixture.circuit);
    }));

    TemporaryDirectory nonempty;
    std::filesystem::create_directory(nonempty.path());
    {
        std::ofstream marker(nonempty.path() / "owned-by-caller");
        marker << "keep";
    }
    CHECK(throws_exception([&] {
        (void)laminate::payload::write_file_encrypted_trace(
            fixture.contexts.eval, nonempty.path(), options(),
            fixture.circuit, fixture.trace);
    }));
    CHECK(std::filesystem::is_regular_file(nonempty.path() /
                                           "owned-by-caller"));

    TemporaryDirectory existing_empty;
    std::filesystem::create_directory(existing_empty.path());
    (void)laminate::payload::write_file_encrypted_trace(
        fixture.contexts.eval, existing_empty.path(), options(),
        fixture.circuit, fixture.trace);
    CHECK(std::filesystem::is_regular_file(existing_empty.path() /
                                           "manifest.bin"));

    TemporaryDirectory zero_limit;
    FileTraceStoreOptions invalid = options();
    invalid.max_total_bytes = 0;
    CHECK(throws_exception([&] {
        (void)laminate::payload::write_file_encrypted_trace(
            fixture.contexts.eval, zero_limit.path(), invalid,
            fixture.circuit, fixture.trace);
    }));

    TemporaryDirectory zero_reserve;
    invalid = options();
    invalid.min_free_bytes = 0;
    CHECK(throws_exception([&] {
        (void)laminate::payload::write_file_encrypted_trace(
            fixture.contexts.eval, zero_reserve.path(), invalid,
            fixture.circuit, fixture.trace);
    }));

    TemporaryDirectory exhausted_reserve;
    invalid = options();
    invalid.min_free_bytes = std::numeric_limits<std::uint64_t>::max();
    CHECK(throws_exception([&] {
        (void)laminate::payload::write_file_encrypted_trace(
            fixture.contexts.eval, exhausted_reserve.path(), invalid,
            fixture.circuit, fixture.trace);
    }));
    CHECK(!std::filesystem::exists(exhausted_reserve.path() /
                                   "manifest.bin"));
}

} // namespace

int main() {
    laminate::test::Runner runner("file-backed encrypted trace store");
    runner.run("round trip and byte reports",
               test_round_trip_and_byte_reports);
    runner.run("compact split support and virtual-zero ranges",
               test_compact_split_support_and_virtual_zero_ranges);
    runner.run("filenames ignore the process locale",
               test_filenames_are_independent_of_the_global_locale);
    runner.run("independent rewindable range readers",
               test_independent_rewindable_range_readers);
    runner.run("evaluator emits directly to file sink",
               test_evaluator_emits_directly_to_file_sink);
    runner.run("compact evaluator retains a live public zero",
               test_compact_evaluator_retains_a_live_public_zero);
    runner.run("quota failure leaves no manifest",
               test_quota_failure_never_finalizes_manifest);
    runner.run("runtime write failure removes the partial layer",
               test_runtime_write_failure_removes_partial_layer);
    runner.run("pre-open record corruption is rejected",
               test_open_rejects_pre_open_record_corruption);
    runner.run("context and execution mismatches are rejected",
               test_open_rejects_context_and_execution_mismatch);
    runner.run("post-open length changes are rejected before allocation",
               test_reader_rejects_post_open_length_change);
    runner.run("post-open size changes are rejected at scan end",
               test_reader_rejects_post_open_size_change_at_scan_end);
    runner.run("post-open replacements are rejected at scan boundaries",
               test_reader_rejects_post_open_replacement_at_scan_boundaries);
    runner.run("reclamation requires explicit no-retry lifecycle",
               test_reclamation_requires_explicit_no_retry_lifecycle);
    runner.run("reclamation is order-independent and exactly accounted",
               test_reclamation_is_order_independent_and_exactly_accounted);
    runner.run("live readers block layer retirement",
               test_live_reader_blocks_retirement);
    runner.run("retirement event collisions preserve the layer",
               test_retirement_event_collision_does_not_remove_layer);
    runner.run("replacement layer paths are rejected",
               test_reclamation_rejects_replaced_layer_paths);
    runner.run("symlink layer paths are rejected where supported",
               test_reclamation_rejects_symlink_layer_paths_where_supported);
    runner.run("caller-selected open limits fail closed",
               test_caller_selected_open_limits_fail_closed);
    runner.run("backend record limits precede ciphertext decoding",
               test_backend_record_limit_precedes_backend_decode);
    runner.run("same-writer one-layer handoff round trips and reclaims",
               test_same_writer_single_layer_handoff_round_trips_and_reclaims);
    runner.run("private identity links share bytes and reclaim once",
               test_private_identity_links_share_bytes_and_reclaim_once);
    runner.run("output completion policies preserve bytes and reopening",
               test_output_completion_policies_preserve_bytes_and_reopening);
    runner.run("reusable gathered reads handle alternating record sizes",
               test_reusable_gathered_reader_handles_alternating_record_sizes);
    runner.run("range reader spans multiple read-ahead blocks",
               test_range_reader_spans_multiple_read_ahead_blocks);
    runner.run("same-writer handoff rejects replaced layer paths",
               test_same_writer_handoff_rejects_replaced_layer);
    runner.run("failed same-writer handoff reclaims owned publications",
               test_failed_same_writer_handoff_reclaims_owned_publications);
    runner.run("partial layer creation does not truncate existing paths",
               test_partial_layer_creation_never_truncates_an_existing_path);
    runner.run("layer publication does not replace existing paths",
               test_layer_publication_never_replaces_an_existing_final_path);
    runner.run("symlink and hardlink collisions preserve their targets",
               test_symlink_and_hardlink_collisions_never_modify_targets);
    runner.run("missing, truncated, and wrong-circuit stores are rejected",
               test_open_rejects_missing_truncated_and_wrong_circuit);
    runner.run("symlink and FIFO inputs are rejected without following",
               test_open_rejects_symlink_and_fifo_inputs_without_following);
    runner.run("range readers bind the validated layer inode",
               test_range_reader_binds_the_validated_layer_inode);
    runner.run("unsupported store versions are rejected",
               test_open_rejects_unsupported_store_version);
    runner.run("descriptor and destination validation",
               test_descriptor_and_destination_validation);
    return runner.summary();
}
