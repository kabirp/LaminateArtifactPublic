/// @file test_gate_tables.cpp
/// @brief Compact gate-table semantics, determinism, and sharding tests.

#include "test_helpers.hpp"

#include "laminate/gates/canonical_tables.hpp"
#include "laminate/gates/gate_mle.hpp"
#include "laminate/payload/compiler.hpp"
#include "laminate/poly/eq.hpp"

#include <algorithm>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <vector>
#include <unistd.h>

using namespace laminate;

namespace {

payload::PayloadCircuit make_wide_payload() {
    payload::PayloadBuilder builder(payload::PayloadShape::wide(8), 2);
    const std::size_t diagonal = builder.add_plaintext(
        {Fp(2), Fp(3), Fp(5), Fp(7), Fp(11), Fp(13), Fp(17), Fp(19)});
    const auto rotated = builder.rotate(0, 5);
    const auto product = builder.mul(rotated, 1);
    const auto scaled = builder.mul_plain(0, diagonal);
    builder.set_outputs({builder.add(product, scaled)});
    return builder.finish();
}

payload::PayloadCircuit make_laned_payload() {
    payload::PayloadBuilder builder(payload::PayloadShape::laned(4, 16), 2);
    const auto product = builder.mul(0, 1);
    builder.set_outputs({builder.add(product, 0)});
    return builder.finish();
}

Fpk value(std::uint64_t seed) {
    Fpk::Coefficients coefficients{};
    for (std::size_t index = 0; index < coefficients.size(); ++index) {
        coefficients[index] = Fp(seed + 19 * index + index * index);
    }
    return Fpk(coefficients);
}

std::vector<Fpk> point(std::size_t variables, std::uint64_t seed) {
    std::vector<Fpk> result;
    result.reserve(variables);
    for (std::size_t index = 0; index < variables; ++index) {
        result.push_back(value(seed + 31 * index));
    }
    return result;
}

std::vector<Fpk> concatenate(
    std::initializer_list<std::span<const Fpk>> parts) {
    std::vector<Fpk> result;
    for (const std::span<const Fpk> part : parts) {
        result.insert(result.end(), part.begin(), part.end());
    }
    return result;
}

const gates::SparseTableProverKey &table_key(
    const gates::GateTableProverKey &key,
    const gates::GateTableDescriptor &descriptor) {
    return key.tables.at(descriptor.selector);
}

Fpk evaluate_component(const gates::GateTableProverKey &key,
                       std::size_t layer, gates::GateTableKind kind,
                       std::span<const Fpk> query) {
    const gates::GateTableDescriptor *descriptor =
        gates::find_table_if(key.verifier.layout, layer, kind);
    if (descriptor == nullptr) {
        return Fpk::zero();
    }
    return gates::evaluate_sparse_table(
        table_key(key, *descriptor).entries,
        descriptor->local_variables, query);
}

struct TemporaryDirectory {
    std::filesystem::path path;
    TemporaryDirectory() {
        auto pattern = (std::filesystem::temp_directory_path() /
                        "laminate-gate-cache-test-XXXXXX").string();
        if (!::mkdtemp(pattern.data()))
            throw std::runtime_error("cannot create gate cache test directory");
        path = pattern;
    }
    ~TemporaryDirectory() {
        std::error_code ignored;
        std::filesystem::remove_all(path, ignored);
    }
};

template <class Function> bool rejects(Function function) {
    try { function(); }
    catch (const std::exception &) { return true; }
    return false;
}

std::vector<std::uint8_t> read_bytes(const std::filesystem::path &path) {
    std::ifstream file(path, std::ios::binary);
    CHECK(file.good());
    return {std::istreambuf_iterator<char>(file), {}};
}

void write_bytes(const std::filesystem::path &path,
                 std::span<const std::uint8_t> bytes) {
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    CHECK(file.good());
    file.write(reinterpret_cast<const char *>(bytes.data()), bytes.size());
    CHECK(file.good());
}

void update_cache_checksum(std::vector<std::uint8_t> &bytes) {
    CHECK(bytes.size() >= sizeof(Digest));
    const auto digest = sha256(std::span<const std::uint8_t>(bytes).first(
        bytes.size() - sizeof(Digest)));
    std::copy(digest.begin(), digest.end(), bytes.end() - sizeof(Digest));
}

Fpk public_cell(const gates::GateTableProverKey &key, std::size_t index) {
    const auto &commitment = *key.wide_public_commitment;
    return commitment.columns.at(index / commitment.metadata.m)
        .get(index % commitment.metadata.m);
}

} // namespace

int main() {
    test::Runner runner("test_gate_tables");

    runner.run("Wide batched index contains exact normalized program tables", [] {
        const auto circuit = payload::compile(make_wide_payload());
        const auto key = gates::preprocess_gate_tables(circuit, gates::GateTableSet::Wide);
        const auto masks = gates::WideMaskDictionary::build(circuit);
        CHECK(key.verifier.layout.wide_masks.mask_count == 1);
        CHECK(key.verifier.layout.wide_masks.dictionary_digest == masks->digest());
        for (const auto &layer : key.verifier.layout.wide_layers) {
            const auto program = gates::WideProgram::build(circuit, layer.layer_index, masks);
            CHECK(layer.dimensions == program.dimensions());
            CHECK(layer.node_count == program.nodes().size());
            CHECK(layer.program_digest == program.digest());
            const auto compare = [&](gates::WidePublicTable source, gates::GateTableKind kind) {
                std::vector<gates::sparse::SparseEntry> expected;
                program.visit_entries(source, [&](const auto &entry) { expected.push_back(entry); });
                const auto *descriptor = gates::find_table_if(key.verifier.layout, layer.layer_index, kind);
                if (expected.empty()) { CHECK(descriptor == nullptr); return; }
                CHECK(descriptor != nullptr);
                CHECK(key.tables.at(descriptor->selector).entries == expected);
            };
            compare(gates::WidePublicTable::UniformEdges, gates::GateTableKind::WideLocalUniformEdges);
            compare(gates::WidePublicTable::MaskEdges, gates::GateTableKind::WideLocalMaskEdges);
            compare(gates::WidePublicTable::UniformConstants, gates::GateTableKind::AffineConstantUniform);
            compare(gates::WidePublicTable::SlotConstants, gates::GateTableKind::AffineConstantSlot);
        }
        std::vector<gates::sparse::SparseEntry> dictionary;
        masks->visit_entries([&](const auto &entry) { dictionary.push_back(entry); });
        const auto &descriptor = gates::find_table(key.verifier.layout, 0,
                                                   gates::GateTableKind::WideMaskDictionary);
        CHECK(key.tables.at(descriptor.selector).entries == dictionary);
        for (std::size_t i = 0; i < key.tables.size(); ++i) {
            const auto &table = key.tables[i];
            CHECK(!table.foldable_commitment);
            CHECK(!table.commitment);
            CHECK(!table.verifier.foldable);
            CHECK(table.verifier.wide_block_offset.has_value());
            CHECK(key.wide_public_commitment.has_value());
            CHECK(table.verifier.root == key.wide_public_commitment->metadata.root);
            CHECK(table.verifier.shard_count == 1);
            CHECK(gates::valid_sparse_table_commitment(key.verifier.layout.tables[i],
                  table.verifier, key.verifier.basefold_parameters));
            const auto bits = key.verifier.layout.tables[i].local_variables;
            const auto offset = *table.verifier.wide_block_offset;
            for (std::size_t column = 0; column < table.verifier.logical_width; ++column) {
                for (std::size_t row = 0; row < table.verifier.message_size; ++row) {
                    auto expected = Fpk::zero();
                    if (row < table.entries.size()) {
                        if (column == 0) expected = Fpk::from_base(table.entries[row].value);
                        else if (column <= bits &&
                            ((table.entries[row].address >> (bits - column)) & 1U))
                            expected = Fpk::one();
                    }
                    CHECK(public_cell(key,
                        offset + column * table.verifier.message_size + row) == expected);
                }
            }
        }
    });

    runner.run("Wide shared index binds its canonical block layout", [] {
        const auto key = gates::preprocess_gate_tables(
            payload::compile(make_wide_payload()), gates::GateTableSet::Wide);
        const auto blocks = gates::make_wide_public_blocks(key.verifier.layout);
        CHECK(gates::valid_wide_public_index(key.verifier));
        std::size_t end = 0;
        const auto &metadata = key.wide_public_commitment->metadata;
        const auto public_cells = metadata.m * metadata.width;
        CHECK(metadata.width <= 256);
        CHECK(metadata.width == key.wide_public_commitment->columns.size());
        std::size_t previous = public_cells;
        for (const auto &block : blocks) {
            const auto cells = block.rows * block.columns;
            CHECK(cells <= previous);
            CHECK(block.offset == end);
            CHECK(block.offset % cells == 0);
            CHECK(key.verifier.tables[block.selector].wide_block_offset == block.offset);
            end += cells;
            previous = cells;
        }
        CHECK(public_cells == std::bit_ceil(end));
        for (const auto &block : blocks) CHECK(metadata.m >= block.rows);
        for (auto i = end; i < public_cells; ++i)
            CHECK(public_cell(key, i).is_zero());
        CHECK(key.wide_retained_disk_bytes ==
            basefold::foldable::retained_commitment_disk_bound(
                metadata.m, metadata.width));
        auto bad = key.verifier;
        ++*bad.tables.front().wide_block_offset;
        CHECK(!gates::valid_wide_public_index(bad));
        bad = key.verifier;
        bad.tables.front().root.front() ^= 1;
        CHECK(!gates::valid_wide_public_index(bad));
        bad = key.verifier;
        bad.wide_public_commitment->m *= 2;
        CHECK(!gates::valid_wide_public_index(bad));
        bad = key.verifier;
        bad.wide_public_commitment->width *= 2;
        CHECK(!gates::valid_wide_public_index(bad));
        bad = key.verifier;
        ++bad.wide_public_commitment->hierarchy_version;
        CHECK(!gates::valid_wide_public_index(bad));
        bad = key.verifier;
        bad.wide_public_commitment.reset();
        CHECK(!gates::valid_wide_public_index(bad));
        bad = key.verifier;
        bad.tables.front().foldable = *key.verifier.wide_public_commitment;
        CHECK(!gates::valid_wide_public_index(bad));
        bad = key.verifier;
        bad.layout.table_set = gates::GateTableSet::Laned;
        CHECK(!gates::valid_wide_public_index(bad));

        auto layout = key.verifier.layout;
        for (auto &table : layout.tables) {
            table.support_size = std::size_t{1} << basefold::foldable::kMaxVariables;
            table.local_variables = 1;
        }
        bool rejected = false;
        try { (void)gates::make_wide_public_blocks(layout); }
        catch (const std::length_error &) { rejected = true; }
        CHECK(rejected);
        layout.tables.clear();
        CHECK(gates::make_wide_public_blocks(layout).empty());
        gates::GateTableVerifierKey empty;
        empty.layout = layout;
        CHECK(gates::valid_wide_public_index(empty));
        empty.wide_public_commitment = key.verifier.wide_public_commitment;
        CHECK(!gates::valid_wide_public_index(empty));
    });

    runner.run("laned compact weights equal reduced wire GateMLEs", [] {
        const payload::LayeredCircuit circuit =
            payload::compile(make_laned_payload());
        const gates::DirectGateMle direct(circuit);
        const gates::GateTableProverKey key =
            gates::preprocess_gate_tables(circuit,
                                          gates::GateTableSet::Laned);
        for (std::size_t layer = 0; layer + 1 < circuit.layers.size();
             ++layer) {
            if (payload::layer_kind(circuit.layers[layer]) !=
                payload::LayerKind::Affine) {
                continue;
            }
            const std::size_t output_wires =
                payload::layer_dimensions(circuit.layers[layer]).padded_size;
            const std::size_t source_wires = payload::layer_dimensions(
                                                 circuit.layers[layer + 1])
                                                 .padded_size;
            const std::vector<Fpk> output_wire =
                point(std::bit_width(output_wires) - 1U, 601 + layer);
            const std::vector<Fpk> source_wire =
                point(std::bit_width(source_wires) - 1U, 701 + layer);
            CHECK(evaluate_component(
                      key, layer, gates::GateTableKind::LanedAffineWire,
                      concatenate({output_wire, source_wire})) ==
                  direct.evaluate(
                      gates::GateMleQuery{gates::LanedAffineWireQuery{
                          layer, output_wire, source_wire}}));
        }
    });

    runner.run("preprocessing is deterministic compact and size-limited", [] {
        const payload::LayeredCircuit circuit =
            payload::compile(make_wide_payload());
        const gates::GateTableProverKey first =
            gates::preprocess_gate_tables(circuit,
                                          gates::GateTableSet::Wide);
        const gates::GateTableProverKey second =
            gates::preprocess_gate_tables(circuit,
                                          gates::GateTableSet::Wide,
                                          {.preprocessing_threads = 4});
        CHECK(first.verifier == second.verifier);
        CHECK(first.tables.size() == second.tables.size());
        std::size_t support = 0;
        bool saw_compact_wide_table = false;
        for (std::size_t table = 0; table < first.tables.size(); ++table) {
            CHECK(first.tables[table].entries == second.tables[table].entries);
            CHECK(first.wide_public_commitment->metadata ==
                  second.wide_public_commitment->metadata);
            support += first.tables[table].entries.size();
            const auto &descriptor = first.verifier.layout.tables[table];
            if (descriptor.kind == gates::GateTableKind::WideLocalUniformEdges) {
                CHECK(descriptor.support_size == first.tables[table].entries.size());
                saw_compact_wide_table = true;
            }
        }
        CHECK(support > 0);
        CHECK(saw_compact_wide_table);

        bool rejected = false;
        try {
            (void)gates::preprocess_gate_tables(
                circuit, gates::GateTableSet::Wide,
                gates::GateTableBuildOptions{
                    .basefold_parameters = {}, .max_message_entries = 1});
        } catch (const std::length_error &) {
            rejected = true;
        }
        CHECK(rejected);
    });

    runner.run("preprocessing workers require a valid Wide worker budget", [] {
        const auto wide = payload::compile(make_wide_payload());
        for (const std::size_t count : {std::size_t{0}, std::size_t{257}}) {
            bool rejected = false;
            try {
                (void)gates::preprocess_gate_tables(
                    wide, gates::GateTableSet::Wide,
                    {.preprocessing_threads = count});
            } catch (const std::invalid_argument &) {
                rejected = true;
            }
            CHECK(rejected);
        }
        bool rejected = false;
        try {
            (void)gates::preprocess_gate_tables(
                payload::compile(make_laned_payload()), gates::GateTableSet::Laned,
                {.preprocessing_threads = 2});
        } catch (const std::invalid_argument &) {
            rejected = true;
        }
        CHECK(rejected);
    });

    runner.run("Laned sparse messages retain RS sharding", [] {
        const payload::LayeredCircuit circuit =
            payload::compile(make_laned_payload());
        const basefold::Parameters parameters{15, 1};
        const gates::GateTableProverKey key =
            gates::preprocess_gate_tables(
                circuit, gates::GateTableSet::Laned,
                gates::GateTableBuildOptions{
                    .basefold_parameters = parameters,
                    .max_message_entries = std::size_t{1} << 22});
        bool saw_shard = false;
        for (std::size_t table = 0; table < key.tables.size(); ++table) {
            const auto &metadata = key.tables[table].verifier;
            CHECK(gates::valid_sparse_table_commitment(
                key.verifier.layout.tables[table], metadata, parameters));
            CHECK(metadata.shard_size <= 2);
            saw_shard |= metadata.shard_count > 1;
        }
        CHECK(saw_shard);
    });

    runner.run("Wide private index lifetime and total disk admission", [] {
        std::filesystem::path directory;
        {
            auto key = gates::preprocess_gate_tables(
                payload::compile(make_wide_payload()), gates::GateTableSet::Wide);
            directory = key.wide_scratch_parent;
            CHECK(std::filesystem::is_directory(directory));
            CHECK(key.wide_retained_disk_bytes > 0);
            auto copy = key;
            key = {};
            CHECK(std::filesystem::is_directory(directory));
        }
        CHECK(!std::filesystem::exists(directory));
        bool rejected = false;
        try {
            gates::GateTableBuildOptions options;
            options.wide_max_disk_bytes = 1;
            (void)gates::preprocess_gate_tables(payload::compile(make_wide_payload()),
                gates::GateTableSet::Wide, options);
        } catch (const std::length_error &) { rejected = true; }
        CHECK(rejected);
    });

    runner.run("durable Wide and Laned prover keys retain exact PCS state", [] {
        for (const auto kind : {gates::GateTableSet::Wide, gates::GateTableSet::Laned}) {
            TemporaryDirectory temp;
            const auto circuit = payload::compile(kind == gates::GateTableSet::Wide
                ? make_wide_payload() : make_laned_payload());
            auto original = gates::preprocess_gate_tables(circuit, kind);
            const auto expected = original.verifier;
            const auto cache = temp.path / "key";
            gates::export_gate_table_prover_key(original, cache);
            CHECK(rejects([&] { gates::export_gate_table_prover_key(original, cache); }));
            gates::GateTableBuildOptions options;
            options.wide_scratch_parent = temp.path / "online";
            const auto reopened = gates::reopen_gate_table_prover_key(expected, cache, options);
            CHECK(reopened.verifier == expected);
            CHECK(reopened.tables.size() == original.tables.size());
            for (std::size_t i = 0; i < original.tables.size(); ++i) {
                CHECK(reopened.tables[i].entries == original.tables[i].entries);
                if (kind == gates::GateTableSet::Laned) {
                    CHECK(reopened.tables[i].commitment->columns == original.tables[i].commitment->columns);
                    CHECK(reopened.tables[i].commitment->codewords == original.tables[i].commitment->codewords);
                    CHECK(reopened.tables[i].commitment->tree.levels() == original.tables[i].commitment->tree.levels());
                }
            }
            if (kind == gates::GateTableSet::Wide) {
                CHECK(reopened.wide_public_commitment->metadata == original.wide_public_commitment->metadata);
                const auto &shape = original.wide_public_commitment->metadata;
                for (std::size_t column = 0; column < shape.width; ++column) {
                    for (std::size_t row = 0; row < shape.m; ++row)
                        CHECK(reopened.wide_public_commitment->columns[column].get(row) ==
                              original.wide_public_commitment->columns[column].get(row));
                    for (std::size_t row = 0; row < shape.m * 8; ++row)
                        CHECK(reopened.wide_public_commitment->codewords[column].get(row) ==
                              original.wide_public_commitment->codewords[column].get(row));
                }
            }
            original = {};
            CHECK(gates::reopen_gate_table_prover_key(expected, cache, options).verifier == expected);
            CHECK(std::filesystem::exists(cache / "tables.bin"));
        }
    });
    runner.run("durable keys reject missing, corrupt, noncanonical, and redirected data", [] {
        for (const auto kind : {gates::GateTableSet::Wide, gates::GateTableSet::Laned}) {
            TemporaryDirectory temp;
            const auto key = gates::preprocess_gate_tables(payload::compile(
                kind == gates::GateTableSet::Wide ? make_wide_payload() : make_laned_payload()), kind);
            const auto cache = temp.path / "key";
            gates::export_gate_table_prover_key(key, cache);
            const auto file = cache / "tables.bin";
            const auto bytes = read_bytes(file);
            const auto reopen = [&] { (void)gates::reopen_gate_table_prover_key(key.verifier, cache); };
            auto bad = bytes;
            bad.back() ^= 1;
            write_bytes(file, bad);
            CHECK(rejects(reopen));
            // Sparse entries begin after the 16-byte magic and setup hash.
            // Recompute the checksum so this exercises canonical validation.
            CHECK(bytes.size() >= 16 + sizeof(Digest) + 11 + sizeof(Digest));
            for (const auto mutation : {0, 1, 2}) {
                bad = bytes;
                const std::size_t entry = 16 + sizeof(Digest);
                if (mutation == 0) std::fill_n(bad.begin() + entry, 8, 0xff);
                if (mutation == 1) std::fill_n(bad.begin() + entry + 8, 3, 0);
                if (mutation == 2) std::fill_n(bad.begin() + entry + 8, 3, 0xff);
                update_cache_checksum(bad);
                write_bytes(file, bad);
                CHECK(rejects(reopen));
            }
            bad = bytes;
            bad.push_back(0);
            write_bytes(file, bad);
            CHECK(rejects(reopen));
            bad = bytes;
            bad.pop_back();
            write_bytes(file, bad);
            CHECK(rejects(reopen));
            write_bytes(file, bytes);
            auto wrong = key.verifier;
            wrong.tables.front().root.front() ^= 1;
            CHECK(rejects([&] { (void)gates::reopen_gate_table_prover_key(wrong, cache); }));
            wrong = key.verifier;
            if (kind == gates::GateTableSet::Wide)
                wrong.layout.wide_layers.front().program_digest.front() ^= 1;
            else
                ++wrong.basefold_parameters.num_queries;
            CHECK(gates::valid_wide_public_index(wrong));
            CHECK(rejects([&] { (void)gates::reopen_gate_table_prover_key(wrong, cache); }));
            CHECK(rejects([&] { (void)gates::reopen_gate_table_prover_key(key.verifier, cache,
                {.max_message_entries = 0}); }));
            std::filesystem::rename(file, cache / "saved.bin");
            CHECK(rejects(reopen));
            std::filesystem::create_symlink(cache / "saved.bin", file);
            CHECK(rejects(reopen));
            std::filesystem::remove(file);
            std::filesystem::rename(cache / "saved.bin", file);
            std::filesystem::create_directory_symlink(cache, temp.path / "redirect");
            CHECK(rejects([&] { (void)gates::reopen_gate_table_prover_key(key.verifier, temp.path / "redirect"); }));
            if (kind == gates::GateTableSet::Wide) {
                std::filesystem::rename(cache / "wide", temp.path / "saved-wide");
                CHECK(rejects(reopen));
                std::filesystem::create_directory_symlink(temp.path / "saved-wide", cache / "wide");
                CHECK(rejects(reopen));
                std::filesystem::remove(cache / "wide");
                std::filesystem::rename(temp.path / "saved-wide", cache / "wide");
            }
            reopen();
        }
    });

    return runner.summary();
}
