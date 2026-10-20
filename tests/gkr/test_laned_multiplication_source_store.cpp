/// @file test_laned_multiplication_source_store.cpp
/// @brief Bounded bit-reversed storage for Laned multiplication sources.

#include "test_helpers.hpp"

#include "laminate/fhe/mock_backend.hpp"
#include "laminate/gkr/laned.hpp"
#include "laminate/gkr/detail/shared/dense_multiplication/source/file.hpp"
#include "laminate/gkr/detail/shared/dense_multiplication/source/scan.hpp"
#include "laminate/packing/alignment/laned.hpp"
#include "laminate/payload/compiler.hpp"
#include "laminate/payload/storage/file_trace_store.hpp"
#include "laminate/payload/trace/trace_crypto.hpp"

#include <algorithm>
#include <bit>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <numeric>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <system_error>
#include <type_traits>
#include <vector>

namespace {

using namespace laminate;
using namespace laminate::fhe;
using namespace laminate::gkr;
using namespace laminate::payload;

class TemporaryDirectory {
  public:
    TemporaryDirectory() {
        const auto stamp = std::chrono::steady_clock::now()
                               .time_since_epoch()
                               .count();
        for (std::size_t attempt = 0; attempt < 100; ++attempt) {
            path_ = std::filesystem::temp_directory_path() /
                    ("laminate-multiplication-source-" +
                     std::to_string(stamp) + "-" +
                     std::to_string(attempt));
            if (std::filesystem::create_directory(path_)) {
                return;
            }
        }
        throw std::runtime_error("failed to create a temporary directory");
    }

    ~TemporaryDirectory() {
        std::error_code ignored;
        std::filesystem::remove_all(path_, ignored);
    }

    const std::filesystem::path &path() const { return path_; }

    std::filesystem::path make_child(const std::string &name) const {
        const std::filesystem::path child = path_ / name;
        if (!std::filesystem::create_directory(child)) {
            throw std::runtime_error("failed to create test child directory");
        }
        return child;
    }

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

Digest setup_id(std::size_t lanes) {
    const std::string label =
        "Laminate multiplication source setup " + std::to_string(lanes);
    return sha256(std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t *>(label.data()),
        label.size()));
}

PayloadCircuit make_payload(std::size_t lane_count,
                            std::size_t slot_count = 16) {
    PayloadBuilder builder(PayloadShape::laned(lane_count, slot_count), 2);
    const WireId first = builder.mul(0, 1);
    const WireId mixed = builder.add(first, 0);
    const WireId second = builder.mul(mixed, first);
    builder.set_outputs({builder.add(second, 1)});
    return builder.finish();
}

PayloadCircuit many_repeated_operands_payload() {
    PayloadBuilder builder(PayloadShape::laned(16, 16), 256);
    std::vector<WireId> outputs;
    for (std::size_t pair = 0; pair < 512; ++pair) {
        // In physical scan order, visit 128 distinct operands, reread them
        // after cache eviction, then repeat with 128 new operands. First-use
        // sequential reads must stay buffered after the earlier rereads.
        const auto physical = gkr::detail::bit_reverse_index(pair, 9);
        const auto input = (physical / 256) * 128 + physical % 128;
        outputs.push_back(builder.mul(input, input));
    }
    builder.set_outputs(outputs);
    return builder.finish();
}

SlotVector lane_values(std::size_t lanes, std::uint64_t seed) {
    SlotVector result;
    result.reserve(lanes);
    for (std::size_t lane = 0; lane < lanes; ++lane) {
        result.emplace_back(seed + 7 * lane + lane * lane);
    }
    return result;
}

std::size_t first_multiplication_layer(const LayeredCircuit &circuit) {
    for (std::size_t layer = 0; layer + 1 < circuit.layers.size(); ++layer) {
        if (layer_kind(circuit.layers[layer]) == LayerKind::Multiplication) {
            return layer;
        }
    }
    throw std::logic_error("fixture has no multiplication layer");
}

std::size_t other_multiplication_layer(const LayeredCircuit &circuit,
                                       std::size_t first) {
    for (std::size_t layer = 0; layer + 1 < circuit.layers.size(); ++layer) {
        if (layer != first &&
            layer_kind(circuit.layers[layer]) == LayerKind::Multiplication) {
            return layer;
        }
    }
    throw std::logic_error("fixture has only one multiplication layer");
}

FileTraceStoreOptions options(std::uint64_t maximum = 1ULL << 29U) {
    return FileTraceStoreOptions{
        .max_total_bytes = maximum,
        .min_free_bytes = 1,
    };
}

std::uint64_t directory_bytes(const std::filesystem::path &directory) {
    std::uint64_t result = 0;
    for (const auto &entry :
         std::filesystem::directory_iterator(directory)) {
        if (entry.is_regular_file()) {
            result += entry.file_size();
        }
    }
    return result;
}

constexpr std::size_t kSourceProofIngressRnsLimbs = 9;

struct Fixture {
    std::size_t lanes;
    TemporaryDirectory root;
    std::filesystem::path trace_directory;
    PayloadCircuit payload;
    LayeredCircuit circuit;
    CanonicalTraceLayout canonical;
    PlainTrace plain;
    MockBackend::Contexts contexts;
    EncryptedTrace<MockBackend> compact;
    std::optional<FileEncryptedTraceStore<MockBackend>> trace;
    std::size_t multiplication_layer;
    std::optional<gkr::detail::DenseMultiplicationSourcePlan>
        source_plan;

    explicit Fixture(std::size_t selected_lanes,
                     std::optional<Fp> public_source = std::nullopt,
                     bool many_aliases = false)
        : lanes(selected_lanes),
          trace_directory(root.make_child("trace")),
          payload(many_aliases ? many_repeated_operands_payload() : make_payload(lanes)),
          circuit(compile(payload)),
          canonical(canonical_trace_layout(circuit)),
          plain(synthesize_trace(
              payload, circuit,
              [&] {
                  std::vector<SlotVector> inputs;
                  for (std::size_t i = 0; i < payload.input_count; ++i)
                      inputs.push_back(lane_values(lanes, 3 + 26 * i));
                  return inputs;
              }())),
          contexts(MockBackend::create(MockParameters{
              .slot_count = 16,
              .fresh_rns_limbs = 12,
              .bits_per_limb = 80,
          })),
          compact(encrypt_compact_synthetic_trace<MockBackend>(
              contexts.eval, contexts.client, payload, circuit, plain,
              TraceEncryptionPlan::uniform(circuit, 8))),
          multiplication_layer(many_aliases ? first_multiplication_layer(circuit) :
              other_multiplication_layer(circuit, first_multiplication_layer(circuit))) {
        if (public_source) {
            auto &source = compact.layers[multiplication_layer + 1U];
            for (auto &wire : source.wires) {
                wire = fhe::FheValue<MockBackend>::public_scalar(
                    *public_source);
            }
        }
        (void)write_file_encrypted_trace(
            contexts.eval, trace_directory, options(), circuit, compact);
        trace.emplace(FileEncryptedTraceStore<MockBackend>::open(
            contexts.eval, trace_directory, payload, circuit,
            compact.provenance, compact.trace_id));
        source_plan.emplace(
            gkr::detail::make_dense_multiplication_source_plan(
                circuit, trace->descriptor(), trace->layered_circuit_id(),
                trace->backend_context_id(), multiplication_layer,
                canonical.wire_support.at(multiplication_layer + 1U),
                canonical.storage.at(multiplication_layer + 1U),
                setup_id(lanes), kSourceProofIngressRnsLimbs));
    }
};

struct StoredFixture {
    std::filesystem::path directory;
    gkr::detail::DenseMultiplicationSourcePlan source_plan;
    gkr::detail::FileDenseMultiplicationSourceWriteResult written;
    gkr::detail::FileDenseMultiplicationSource<MockBackend> artifact;
};

StoredFixture build_artifact(Fixture &fixture,
                             const std::string &directory_name =
                                 "artifact") {
    const std::filesystem::path directory =
        fixture.root.make_child(directory_name);
    auto source_plan = *fixture.source_plan;
    auto built =
        gkr::detail::build_file_dense_multiplication_source<MockBackend>(
            fixture.contexts.eval, *fixture.trace, source_plan, directory,
            options());
    return StoredFixture{directory, std::move(source_plan),
                         std::move(built.written),
                         std::move(built.source)};
}

SlotVector expected_packed_plaintext(const Fixture &fixture,
                                     std::size_t packed_index) {
    const auto &source =
        fixture.plain.layers[fixture.multiplication_layer + 1];
    const auto layout = laned_layout(
        fixture.circuit, fixture.multiplication_layer + 1);
    SlotVector result(layout.slot_count, Fp::zero());
    for (std::size_t wire = 0; wire < source.size(); ++wire) {
        for (std::size_t lane = 0; lane < layout.lane_count; ++lane) {
            const auto address = layout.address(wire, lane);
            if (address.ciphertext == packed_index) {
                result[address.slot] = source[wire][lane];
            }
        }
    }
    return result;
}

void compare_regime(std::size_t lanes) {
    using FilePair =
        gkr::detail::FileDenseMultiplicationPair<MockBackend>;
    static_assert(!std::is_copy_constructible_v<FilePair>);
    static_assert(std::is_move_constructible_v<FilePair>);

    Fixture fixture(lanes);
    StoredFixture stored = build_artifact(fixture);
    const auto &descriptor = stored.written.descriptor;
    CHECK(descriptor == stored.artifact.descriptor());
    CHECK(descriptor.chunks_per_packed_ciphertext == 16 / lanes);
    CHECK(descriptor.pair_count > 0);
    CHECK(descriptor.source_layout.padded_ciphertext_count ==
          2 * descriptor.pair_count);
    CHECK(descriptor.live_pair_count > 0);
    CHECK(descriptor.live_pair_count <= descriptor.pair_count);
    if (lanes == descriptor.shape.slot_count) {
        CHECK(descriptor.live_pair_count < descriptor.pair_count);
    }
    CHECK(stored.written.report == stored.artifact.report());
    CHECK(stored.written.report.physical_bytes ==
          directory_bytes(stored.directory));
    const auto &source_support = stored.source_plan.source_support;
    const auto &source_storage = stored.source_plan.source_storage;
    const auto &aliases = stored.source_plan.aliases;
    const bool uses_alias_storage =
        source_storage.stored_wire_count != source_support.live_wire_count;
    CHECK(stored.written.report.stored_values ==
          aliases.operands.size());

    const auto &build = stored.written.statistics;
    CHECK(build.source_range_opens == (uses_alias_storage ? 1U : 2U));
    const bool indexed_chunks = uses_alias_storage &&
        descriptor.chunks_per_packed_ciphertext != 1U;
    if (!indexed_chunks) CHECK(build.source_indexed_seeks == 0);
    CHECK(build.source_sequential_passes ==
          (indexed_chunks ? 0U : uses_alias_storage ? 1U : 2U));
    std::size_t expected_source_values = 0;
    if (indexed_chunks) {
        for (const auto &operand : aliases.operands)
            expected_source_values += static_cast<std::size_t>(std::count_if(
                operand.stored_ordinals.begin(), operand.stored_ordinals.end(),
                [](const auto &ordinal) { return ordinal.has_value(); }));
    } else {
        expected_source_values = uses_alias_storage ? source_storage.stored_wire_count
            : descriptor.source_dimensions.logical_size;
    }
    CHECK(build.source_values_read == expected_source_values);
    CHECK(build.live_pairs_written == descriptor.live_pair_count);
    CHECK(build.peak_live_source_values == 1U);
    CHECK(build.peak_live_packed_values == (indexed_chunks ? 2U : 1U));
    CHECK(build.prepared_chunk_bases ==
          static_cast<std::uint64_t>(
              descriptor.chunks_per_packed_ciphertext != 1));
    std::uint64_t expected_basis_applications = 0;
    if (descriptor.chunks_per_packed_ciphertext != 1U) {
        if (uses_alias_storage) {
            for (const auto &operand : aliases.operands) {
                expected_basis_applications +=
                    static_cast<std::uint64_t>(std::count_if(
                        operand.stored_ordinals.begin(),
                        operand.stored_ordinals.end(),
                        [](const auto &ordinal) { return ordinal.has_value(); }));
            }
        } else {
            expected_basis_applications =
                descriptor.source_dimensions.logical_size;
        }
    }
    CHECK(build.prepared_chunk_basis_applications ==
          expected_basis_applications);
    CHECK(build.online_slot_vectors_constructed == 0);
    CHECK(build.external_sort_peak_combined_artifact_bytes >=
          build.external_sort_peak_live_temporary_bytes);
    CHECK(build.external_sort_peak_combined_artifact_bytes >=
          stored.written.report.physical_bytes);
    if (uses_alias_storage) {
        CHECK(build.external_sort_peak_live_temporary_bytes == 0);
        CHECK(build.external_sort_peak_combined_artifact_bytes ==
              stored.written.report.physical_bytes);
    } else {
        // This bounded fixture fits in the admitted sort buffer and should
        // publish directly instead of creating a throwaway run file.
        CHECK(build.external_sort_temporary_bytes_written == 0);
    }
    CHECK(build.external_sort_peak_combined_artifact_bytes <=
          options().max_total_bytes);
    CHECK(build.external_sort_temporary_bytes_written ==
          build.external_sort_temporary_bytes_deleted);
    CHECK(build.external_sort_retained_temporary_bytes == 0);

    const std::size_t source_layer = fixture.multiplication_layer + 1U;
    const auto &compact_source = fixture.compact.layers[source_layer].wires;
    std::uint64_t expected_source_bytes = 0;
    const auto count_record = [&](std::size_t ordinal) {
        expected_source_bytes += fhe::encode_fhe_value_record<MockBackend>(
            fixture.contexts.eval, compact_source[ordinal]).size();
    };
    if (indexed_chunks) {
        for (const auto &operand : aliases.operands)
            for (const auto ordinal : operand.stored_ordinals)
                if (ordinal) count_record(*ordinal);
    } else {
        for (std::size_t ordinal = 0; ordinal < compact_source.size(); ++ordinal)
            count_record(ordinal);
    }
    CHECK(build.source_logical_record_bytes_read ==
          expected_source_bytes);

    auto reader = stored.artifact.reader();
    std::size_t live_pairs_seen = 0;
    std::vector<std::size_t> expected_order(descriptor.live_pair_count);
    std::iota(expected_order.begin(), expected_order.end(), std::size_t{0});
    const std::size_t pair_bits =
        std::bit_width(descriptor.pair_count) - 1U;
    std::sort(expected_order.begin(), expected_order.end(),
              [&](std::size_t left, std::size_t right) {
                  return gkr::detail::bit_reverse_index(left, pair_bits) <
                         gkr::detail::bit_reverse_index(right, pair_bits);
              });
    std::vector<const fhe::FheValue<MockBackend> *> cached_addresses(
        aliases.operands.size(), nullptr);
    const auto observe_alias = [&](std::size_t operand,
                                   const fhe::FheValue<MockBackend> &value) {
        if (aliases.operand_occurrences[operand] <= 1U) {
            return;
        }
        const auto *address = &value;
        if (cached_addresses[operand] == nullptr) {
            cached_addresses[operand] = address;
        } else {
            CHECK(cached_addresses[operand] == address);
        }
    };
    std::vector<FilePair> retained_pairs;
    retained_pairs.reserve(expected_order.size());
    for (const std::size_t expected_index : expected_order) {
        auto pair = reader.next();
        CHECK(pair.has_value());
        retained_pairs.push_back(std::move(*pair));
        const FilePair &retained = retained_pairs.back();
        CHECK(retained.packed_index == expected_index);
        observe_alias(aliases.left_operand[expected_index], retained.left());
        observe_alias(aliases.right_operand[expected_index], retained.right());
        CHECK(!retained.left().is_public_zero());
        CHECK(!retained.right().is_public_zero());
        CHECK(MockBackend::decrypt(fixture.contexts.client,
                                   retained.left().ciphertext()) ==
              expected_packed_plaintext(fixture, expected_index));
        CHECK(MockBackend::decrypt(fixture.contexts.client,
                                   retained.right().ciphertext()) ==
              expected_packed_plaintext(
                  fixture, descriptor.pair_count + expected_index));
        ++live_pairs_seen;
    }
    CHECK(live_pairs_seen == descriptor.live_pair_count);
    CHECK(!reader.next().has_value());
    CHECK(reader.position() == reader.size());
    const auto first_pass = reader.statistics();
    CHECK(first_pass.passes_started == 1);
    CHECK(first_pass.rewinds == 0);
    CHECK(reader.size() == descriptor.live_pair_count);
    CHECK(reader.domain_size() == descriptor.pair_count);
    CHECK(first_pass.pairs_read == descriptor.live_pair_count);
    CHECK(first_pass.values_read ==
          stored.written.report.stored_values);
    CHECK(first_pass.logical_record_bytes_read ==
          stored.written.report.logical_record_bytes);
    for (std::size_t operand = 0; operand < aliases.operands.size();
         ++operand) {
        if (aliases.operand_occurrences[operand] > 1U) {
            CHECK(cached_addresses[operand] != nullptr);
        }
    }
    const std::size_t reused_operands = static_cast<std::size_t>(
        std::count_if(aliases.operand_occurrences.begin(),
                      aliases.operand_occurrences.end(),
                      [](std::size_t uses) { return uses > 1U; }));
    CHECK(first_pass.peak_live_decoded_values <= reused_operands + 2U);

    reader.rewind();
    const auto repeated = reader.next();
    CHECK(repeated.has_value());
    CHECK(repeated->packed_index == 0);
    const std::uint64_t repeated_bytes =
        fhe::encode_fhe_value_record<MockBackend>(
            fixture.contexts.eval, repeated->left())
            .size() +
        fhe::encode_fhe_value_record<MockBackend>(
            fixture.contexts.eval, repeated->right())
            .size();
    CHECK(reader.statistics().passes_started == 2);
    CHECK(reader.statistics().rewinds == 1);
    CHECK(reader.statistics().pairs_read == descriptor.live_pair_count + 1);
    CHECK(reader.statistics().logical_record_bytes_read ==
          stored.written.report.logical_record_bytes + repeated_bytes);

    // Reopening uses the retained setup plan even after source-layer
    // retirement; no circuit rescan is part of the online artifact lifecycle.
    const auto reopened =
        gkr::detail::FileDenseMultiplicationSource<MockBackend>::open(
            fixture.contexts.eval, stored.directory,
            stored.written.descriptor, stored.source_plan);
    CHECK(reopened.descriptor() == descriptor);
    CHECK(reopened.report() == stored.written.report);
}

void test_all_laned_regimes() {
    compare_regime(1);
    compare_regime(4);
    compare_regime(16);
}

void test_same_writer_adoption_preserves_strict_reopen() {
    Fixture fixture(4);
    StoredFixture stored =
        build_artifact(fixture, "same-writer-adoption");

    CHECK(stored.artifact.descriptor() == stored.written.descriptor);
    CHECK(stored.artifact.report() == stored.written.report);
    auto adopted_reader = stored.artifact.reader();
    const auto adopted_pair = adopted_reader.next();
    CHECK(adopted_pair.has_value());

    const auto reopened =
        gkr::detail::FileDenseMultiplicationSource<MockBackend>::open(
            fixture.contexts.eval, stored.directory,
            stored.written.descriptor, stored.source_plan);
    CHECK(reopened.descriptor() == stored.written.descriptor);
    CHECK(reopened.report() == stored.written.report);
    auto reopened_reader = reopened.reader();
    const auto reopened_pair = reopened_reader.next();
    CHECK(reopened_pair.has_value());
    CHECK(reopened_pair->packed_index == adopted_pair->packed_index);
    CHECK(MockBackend::decrypt(fixture.contexts.client,
                               reopened_pair->left().ciphertext()) ==
          MockBackend::decrypt(fixture.contexts.client,
                               adopted_pair->left().ciphertext()));
    CHECK(MockBackend::decrypt(fixture.contexts.client,
                               reopened_pair->right().ciphertext()) ==
          MockBackend::decrypt(fixture.contexts.client,
                               adopted_pair->right().ciphertext()));
}

void test_public_values_round_trip_through_artifact() {
    for (const Fp source_value : {Fp::zero(), Fp(17)}) {
        Fixture fixture(4, source_value);
        StoredFixture stored = build_artifact(
            fixture, source_value.is_zero() ? "public-zero-artifact"
                                           : "public-value-artifact");
        auto reader = stored.artifact.reader();
        std::size_t pairs = 0;
        while (const auto pair = reader.next()) {
            CHECK(pair->left().is_public());
            CHECK(pair->right().is_public());
            CHECK(pair->left().is_public_zero() == source_value.is_zero());
            CHECK(pair->right().is_public_zero() == source_value.is_zero());
            ++pairs;
        }
        CHECK(pairs == stored.written.descriptor.live_pair_count);
        CHECK(reader.statistics().values_read == 2U * pairs);
        CHECK(reader.statistics().peak_live_decoded_values == 2);
        CHECK(stored.written.report.stored_values == 2U * pairs);
        CHECK(stored.written.statistics.peak_live_source_values == 1U);
        CHECK(stored.written.statistics.peak_live_packed_values <= 2U);
    }
}

void test_many_aliases_keep_build_and_scan_residency_bounded() {
    Fixture fixture(16, std::nullopt, true);
    auto stored = build_artifact(fixture);
    CHECK(stored.source_plan.aliases.operands.size() >
          gkr::detail::kDenseMultiplicationReaderCacheValues);
    CHECK(stored.source_plan.source_storage.stored_wire_count <
          stored.source_plan.source_support.live_wire_count);
    CHECK(stored.written.statistics.peak_live_source_values == 1U);
    CHECK(stored.written.statistics.peak_live_packed_values == 1U);
    CHECK(stored.written.statistics.source_values_read ==
          stored.source_plan.source_storage.stored_wire_count);
    auto reader = stored.artifact.reader();
    gkr::detail::FileBackedMultiplicationStatistics scans;
    for (std::size_t pass = 1; pass <= 2; ++pass) {
        const auto before =
            gkr::detail::multiplication_detail::begin_scan(reader, scans);
        std::size_t pairs = 0;
        while (auto pair = reader.next()) {
            CHECK(MockBackend::decrypt(fixture.contexts.client,
                                       pair->left().ciphertext()) ==
                  expected_packed_plaintext(fixture, pair->packed_index));
            CHECK(MockBackend::decrypt(fixture.contexts.client,
                                       pair->right().ciphertext()) ==
                  expected_packed_plaintext(
                      fixture, stored.written.descriptor.pair_count +
                                   pair->packed_index));
            ++pairs;
        }
        CHECK(pairs == stored.written.descriptor.live_pair_count);
        CHECK(reader.statistics().distinct_values_read ==
              pass * stored.written.report.stored_values);
        CHECK(reader.statistics().values_read >
              reader.statistics().distinct_values_read);
        CHECK(reader.statistics().peak_live_decoded_values <=
              gkr::detail::kDenseMultiplicationReaderCacheValues + 2U);
        gkr::detail::multiplication_detail::finish_scan(reader, before, scans);
        CHECK(scans.artifact_scans == pass);
        CHECK(scans.artifact_rewinds == pass - 1U);
        CHECK(scans.artifact_pairs_read == pass * pairs);
        CHECK(scans.artifact_values_read == reader.statistics().values_read);
        CHECK(scans.artifact_logical_record_bytes_read ==
              reader.statistics().logical_record_bytes_read);
        CHECK(scans.artifact_framed_record_bytes_read ==
              reader.statistics().logical_record_bytes_read +
                  sizeof(std::uint64_t) * reader.statistics().values_read);
        const auto sequential = reader.sequential_read_diagnostics();
        const auto aliases = reader.alias_read_diagnostics();
        CHECK(sequential.prefetch_seek_disables == 0);
        CHECK(sequential.prefetch_window_bytes ==
              kFileTraceStorePrefetchWindowBytes);
        // This small artifact fits in one sequential block on each pass,
        // even though alias rereads precede some first uses.
        CHECK(sequential.read_batches == pass);
        CHECK(sequential.bytes_transferred ==
              pass * (stored.written.report.logical_record_bytes +
                      sizeof(std::uint64_t) *
                          stored.written.report.stored_values));
        CHECK(aliases.read_batches > 0);
        CHECK(aliases.prefetch_seek_disables == 0);
        CHECK(aliases.prefetch_window_bytes == 0);
        CHECK(aliases.prefetch_requests == 0);
    }

    const auto partial =
        gkr::detail::multiplication_detail::begin_scan(reader, scans);
    CHECK(reader.next().has_value());
    CHECK(throws_exception([&] {
        gkr::detail::multiplication_detail::finish_scan(reader, partial, scans);
    }));

    const auto duplicated =
        gkr::detail::multiplication_detail::begin_scan(reader, scans);
    while (reader.next()) {}
    reader.rewind();
    while (reader.next()) {}
    CHECK(throws_exception([&] {
        gkr::detail::multiplication_detail::finish_scan(
            reader, duplicated, scans);
    }));
}

struct EagerPackedFixtureSource {
    const Fixture &fixture;
    struct Reader {
        const Fixture &fixture;
        std::size_t index = 0;
        std::uint64_t bytes = 0;
        std::optional<fhe::FheValue<MockBackend>> next() {
            const auto &descriptor = fixture.source_plan->descriptor_template;
            if (index == descriptor.source_layout.logical_ciphertext_count)
                return std::nullopt;
            auto value = fhe::FheValue<MockBackend>::from_ciphertext(
                MockBackend::encrypt(fixture.contexts.client,
                    expected_packed_plaintext(fixture, index++)));
            fhe::mod_switch_to_rns_limb_count<MockBackend>(fixture.contexts.eval,
                value.ciphertext(), descriptor.packed_proof_ingress_rns_limbs);
            bytes += fhe::encode_fhe_value_record<MockBackend>(fixture.contexts.eval, value).size();
            return value;
        }
        std::uint64_t encoded_bytes_read() const { return bytes; }
    };
    auto descriptor() const { return fixture.trace->descriptor(); }
    auto layered_circuit_id() const { return fixture.trace->layered_circuit_id(); }
    auto backend_context_id() const { return fixture.trace->backend_context_id(); }
    bool uses_eager_laned_witness_packing() const { return true; }
    auto laned_packed_layer_layout(std::size_t) const {
        return fixture.source_plan->descriptor_template.source_layout;
    }
    std::size_t laned_packed_layer_rns_limbs(std::size_t) const {
        return fixture.source_plan->descriptor_template.packed_proof_ingress_rns_limbs;
    }
    Reader laned_packed_layer_reader(std::size_t) const { return {fixture}; }
    auto active_layer_reader(std::size_t layer) const {
        return fixture.trace->active_layer_reader(layer);
    }
    auto active_layer_reader(std::size_t layer, std::size_t begin, std::size_t end) const {
        return fixture.trace->active_layer_reader(layer, begin, end);
    }
};

void test_eager_packed_source_streams_into_same_operand_order() {
    Fixture fixture(4);
    auto normal = build_artifact(fixture);
    const auto eager = gkr::detail::build_file_dense_multiplication_source<MockBackend>(
        fixture.contexts.eval, EagerPackedFixtureSource{fixture}, *fixture.source_plan,
        fixture.root.make_child("eager"), options());
    CHECK(eager.written.descriptor == normal.written.descriptor);
    CHECK(eager.written.statistics.peak_live_source_values == 1U);
    CHECK(eager.written.statistics.peak_live_packed_values == 1U);
    CHECK(eager.written.statistics.source_values_read ==
          eager.written.descriptor.source_layout.logical_ciphertext_count);
    auto eager_reader = eager.source.reader();
    auto normal_reader = normal.artifact.reader();
    while (auto pair = eager_reader.next()) {
        auto expected = normal_reader.next();
        CHECK(expected.has_value());
        CHECK(pair->packed_index == expected->packed_index);
        CHECK(MockBackend::decrypt(fixture.contexts.client, pair->left().ciphertext()) ==
              MockBackend::decrypt(fixture.contexts.client, expected->left().ciphertext()));
        CHECK(MockBackend::decrypt(fixture.contexts.client, pair->right().ciphertext()) ==
              MockBackend::decrypt(fixture.contexts.client, expected->right().ciphertext()));
    }
    CHECK(!normal_reader.next());
}

void test_live_order_ignores_huge_padded_domain() {
    constexpr std::size_t kLive = 3;
    constexpr std::size_t kPadded = std::size_t{1} << 30U;
    const auto order =
        gkr::detail::live_packed_indices_in_physical_order(
            kLive, kPadded);
    CHECK(order.size() == kLive);
    CHECK(order[0] == 0);
    CHECK(order[1] == 2);
    CHECK(order[2] == 1);
}

void flip_first_ciphertext_byte(const std::filesystem::path &directory) {
    const std::filesystem::path path =
        directory / "layer-0000000000000000.bin";
    std::fstream file(path, std::ios::binary | std::ios::in |
                                std::ios::out);
    if (!file) {
        throw std::runtime_error("failed to open corruption target");
    }
    // The layer header is 40 bytes and the first record length is eight
    // bytes, so byte 48 is the first tagged-value payload byte.
    file.seekg(48);
    char byte = 0;
    file.read(&byte, 1);
    byte ^= 0x5a;
    file.clear();
    file.seekp(48);
    file.write(&byte, 1);
}

void overwrite_manifest_version(const std::filesystem::path &directory) {
    std::fstream file(directory / "manifest.bin",
                      std::ios::binary | std::ios::in | std::ios::out);
    if (!file) {
        throw std::runtime_error("failed to open manifest version target");
    }
    constexpr std::uint64_t unsupported = ~std::uint64_t{0};
    char bytes[sizeof(unsupported)]{};
    for (std::size_t byte = 0; byte < sizeof(unsupported); ++byte) {
        bytes[byte] = static_cast<char>(unsupported >> (8U * byte));
    }
    file.seekp(8);
    file.write(bytes, sizeof(bytes));
}

void test_corruption_incomplete_and_binding_fail_closed() {
    {
        Fixture fixture(4);
        StoredFixture stored = build_artifact(fixture);
        flip_first_ciphertext_byte(stored.directory);
        CHECK(throws_exception([&] {
            (void)gkr::detail::FileDenseMultiplicationSource<
                MockBackend>::open(fixture.contexts.eval, stored.directory,
                                   stored.written.descriptor,
                                   stored.source_plan);
        }));
    }
    {
        Fixture fixture(4);
        StoredFixture stored = build_artifact(fixture);
        std::filesystem::remove(stored.directory / "manifest.bin");
        CHECK(throws_exception([&] {
            (void)gkr::detail::FileDenseMultiplicationSource<
                MockBackend>::open(fixture.contexts.eval, stored.directory,
                                   stored.written.descriptor,
                                   stored.source_plan);
        }));
    }
    {
        Fixture fixture(4);
        StoredFixture stored = build_artifact(fixture);
        overwrite_manifest_version(stored.directory);
        CHECK(throws_exception([&] {
            (void)gkr::detail::FileDenseMultiplicationSource<
                MockBackend>::open(fixture.contexts.eval, stored.directory,
                                   stored.written.descriptor,
                                   stored.source_plan);
        }));
    }
    {
        Fixture fixture(4);
        StoredFixture stored = build_artifact(fixture);
        auto other_context = MockBackend::create(MockParameters{
            .slot_count = 16,
            .fresh_rns_limbs = 13,
            .bits_per_limb = 80,
        });
        CHECK(throws_exception([&] {
            (void)gkr::detail::FileDenseMultiplicationSource<
                MockBackend>::open(other_context.eval, stored.directory,
                                   stored.written.descriptor,
                                   stored.source_plan);
        }));
        auto wrong_setup_plan = stored.source_plan;
        wrong_setup_plan.descriptor_template.setup_id.front() ^= 1U;
        CHECK(throws_exception([&] {
            (void)gkr::detail::FileDenseMultiplicationSource<
                MockBackend>::open(fixture.contexts.eval, stored.directory,
                                   stored.written.descriptor,
                                   wrong_setup_plan);
        }));
        const std::size_t other_layer = other_multiplication_layer(
            fixture.circuit, fixture.multiplication_layer);
        const auto other_layer_plan =
            gkr::detail::make_dense_multiplication_source_plan(
                fixture.circuit, fixture.trace->descriptor(),
                fixture.trace->layered_circuit_id(),
                fixture.trace->backend_context_id(), other_layer,
                fixture.canonical.wire_support.at(other_layer + 1U),
                fixture.canonical.storage.at(other_layer + 1U),
                setup_id(fixture.lanes), kSourceProofIngressRnsLimbs);
        CHECK(throws_exception([&] {
            (void)gkr::detail::FileDenseMultiplicationSource<
                MockBackend>::open(fixture.contexts.eval, stored.directory,
                                   stored.written.descriptor,
                                   other_layer_plan);
        }));

        PayloadBuilder alternate_builder(
            PayloadShape::laned(fixture.lanes, 16), 2);
        alternate_builder.set_outputs(
            {alternate_builder.mul(0, 1)});
        const LayeredCircuit alternate = compile(alternate_builder.finish());
        auto alternate_plan = stored.source_plan;
        alternate_plan.descriptor_template.layered_circuit_id =
            payload::digest(alternate);
        CHECK(throws_exception([&] {
            (void)gkr::detail::FileDenseMultiplicationSource<
                MockBackend>::open(fixture.contexts.eval, stored.directory,
                                   stored.written.descriptor,
                                   alternate_plan);
        }));
    }
}

void test_quota_and_private_directory_contract() {
    Fixture fixture(4);
    const StoredFixture measured =
        build_artifact(fixture, "measured-budget-artifact");
    const std::uint64_t combined_peak =
        measured.written.statistics
            .external_sort_peak_combined_artifact_bytes;
    const std::uint64_t temporary_peak =
        measured.written.statistics
            .external_sort_peak_live_temporary_bytes;
    CHECK(combined_peak >= temporary_peak);
    CHECK(combined_peak >= measured.written.report.physical_bytes);

    std::uint64_t maximum_record_bytes = 0;
    auto bound_reader = measured.artifact.reader();
    while (auto pair = bound_reader.next()) {
        maximum_record_bytes = std::max<std::uint64_t>(
            maximum_record_bytes,
            fhe::encode_fhe_value_record<MockBackend>(
                fixture.contexts.eval, pair->left())
                .size());
        maximum_record_bytes = std::max<std::uint64_t>(
            maximum_record_bytes,
            fhe::encode_fhe_value_record<MockBackend>(
                fixture.contexts.eval, pair->right())
                .size());
    }
    const auto disk_bounds =
        gkr::detail::file_dense_multiplication_source_disk_bounds(
            measured.written.report.stored_values,
            maximum_record_bytes,
            true);
    CHECK(measured.written.report.physical_bytes <=
          disk_bounds.completed_artifact_bytes);
    CHECK(combined_peak <= disk_bounds.build_peak_bytes);

    const std::filesystem::path exact =
        fixture.root.make_child("exact-budget");
    const auto &source_plan = *fixture.source_plan;
    const auto exact_built =
        gkr::detail::build_file_dense_multiplication_source<MockBackend>(
            fixture.contexts.eval, *fixture.trace, source_plan, exact,
            options(combined_peak));
    CHECK(exact_built.written.statistics
              .external_sort_peak_combined_artifact_bytes <=
          combined_peak);

    const std::filesystem::path overlapping =
        fixture.root.make_child("overlapping-budget");
    CHECK(throws_exception([&] {
        (void)gkr::detail::build_file_dense_multiplication_source<
            MockBackend>(
            fixture.contexts.eval, *fixture.trace, source_plan, overlapping,
            options(combined_peak - 1U));
    }));
    CHECK(!std::filesystem::exists(overlapping / "manifest.bin"));

    const std::filesystem::path quota = fixture.root.make_child("quota");
    CHECK(throws_exception([&] {
        (void)gkr::detail::build_file_dense_multiplication_source<
            MockBackend>(fixture.contexts.eval, *fixture.trace, source_plan,
                         quota, options(64));
    }));
    CHECK(!std::filesystem::exists(quota / "manifest.bin"));

    const std::filesystem::path nonempty =
        fixture.root.make_child("nonempty");
    {
        std::ofstream marker(nonempty / "owned-by-caller");
        marker << "keep";
    }
    CHECK(throws_exception([&] {
        (void)gkr::detail::build_file_dense_multiplication_source<
            MockBackend>(fixture.contexts.eval, *fixture.trace, source_plan,
                         nonempty, options());
    }));
    CHECK(std::filesystem::is_regular_file(nonempty / "owned-by-caller"));
}

} // namespace

int main() {
    laminate::test::Runner runner("Laned packed multiplication source store");
    runner.run("B=1, partial B, and B=N ordering and exact stats",
               test_all_laned_regimes);
    runner.run("same-writer adoption preserves strict persisted reopen",
               test_same_writer_adoption_preserves_strict_reopen);
    runner.run("tagged public values round trip through the artifact",
               test_public_values_round_trip_through_artifact);
    runner.run("large alias sets keep build and read residency bounded",
               test_many_aliases_keep_build_and_scan_residency_bounded);
    runner.run("eager packed sources stream into canonical operand order",
               test_eager_packed_source_streams_into_same_operand_order);
    runner.run("live order ignores a huge padded domain",
               test_live_order_ignores_huge_padded_domain);
    runner.run("corruption, incomplete publication, and binding",
               test_corruption_incomplete_and_binding_fail_closed);
    runner.run("quota and private directory",
               test_quota_and_private_directory_contract);
    return runner.summary();
}
