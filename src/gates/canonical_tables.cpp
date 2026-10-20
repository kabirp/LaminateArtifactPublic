#include "laminate/gates/canonical_tables.hpp"

#include "laminate/basefold/common.hpp"
#include "laminate/params.hpp"

#include <algorithm>
#include <bit>
#include <chrono>
#include <random>
#include <system_error>
#include <limits>
#include <iterator>
#include <map>
#include <stdexcept>
#include <utility>

namespace laminate::gates {
namespace {

struct SparseTableSource {
    GateTableDescriptor descriptor;
    std::vector<sparse::SparseEntry> entries;
};

std::size_t checked_add(std::size_t left, std::size_t right,
                        const char *operation) {
    if (right > std::numeric_limits<std::size_t>::max() - left) {
        throw std::overflow_error(operation);
    }
    return left + right;
}

std::size_t checked_product(std::size_t left, std::size_t right,
                            const char *operation) {
    if (right != 0 && left > std::numeric_limits<std::size_t>::max() / right) {
        throw std::overflow_error(operation);
    }
    return left * right;
}

std::size_t append_index(std::size_t prefix, std::size_t coordinate,
                         std::size_t dimension) {
    return checked_add(
        checked_product(prefix, dimension,
                        "sparse gate-table address overflows"),
        coordinate, "sparse gate-table address overflows");
}

std::size_t next_power_of_two(std::size_t value) {
    if (value <= 1) {
        return 1;
    }
    if (value > (std::numeric_limits<std::size_t>::max() >> 1U) + 1U) {
        throw std::overflow_error(
            "sparse gate-table dimension cannot be padded");
    }
    return std::bit_ceil(value);
}

std::size_t variables(std::size_t dimension) {
    return basefold::log2_exact(dimension);
}

void append_nonempty(std::vector<SparseTableSource> &tables,
                     std::size_t layer_index, GateTableKind kind,
                     std::size_t local_variables,
                     std::map<std::size_t, Fp> values) {
    std::vector<sparse::SparseEntry> entries;
    entries.reserve(values.size());
    for (const auto &[address, value] : values) {
        if (!value.is_zero()) {
            entries.push_back(sparse::SparseEntry{address, value});
        }
    }
    if (entries.empty()) {
        return;
    }
    tables.push_back(SparseTableSource{
        GateTableDescriptor{layer_index, kind, tables.size(),
                            local_variables, entries.size()},
        std::move(entries)});
}

void append_affine_sources(
    const payload::LayeredCircuit &circuit, std::size_t layer_index,
    GateTableSet table_set, std::vector<SparseTableSource> &tables) {
    const auto &layer =
        std::get<payload::AffineLayer>(circuit.layers[layer_index]);
    const std::size_t output_count = layer.dimensions.padded_size;
    const std::size_t source_count =
        payload::layer_dimensions(circuit.layers[layer_index + 1])
            .padded_size;
    const std::size_t width = circuit.shape.value_width();
    const std::size_t output_variables = variables(output_count);
    const std::size_t source_variables = variables(source_count);
    const std::size_t slot_variables = variables(width);

    std::map<std::size_t, Fp> coefficients;
    for (std::size_t gate = 0; gate < layer.gates.size(); ++gate) {
        for (const payload::AffineTerm &term : layer.gates[gate].terms) {
            std::size_t address = append_index(gate, term.source,
                                               source_count);
            if (table_set == GateTableSet::Wide) {
                address = append_index(address, term.rotation, width);
            }
            coefficients[address] += term.coefficient;
        }
    }
    append_nonempty(
        tables, layer_index,
        table_set == GateTableSet::Wide
            ? GateTableKind::WideAffineWeight
            : GateTableKind::LanedAffineWire,
        checked_add(checked_add(output_variables, source_variables,
                                "sparse affine dimension overflows"),
                    table_set == GateTableSet::Wide ? slot_variables : 0,
                    "sparse affine dimension overflows"),
        std::move(coefficients));

    std::map<std::size_t, Fp> uniform_constants;
    std::map<std::size_t, Fp> slot_constants;
    for (std::size_t gate = 0; gate < layer.gates.size(); ++gate) {
        if (const auto *scalar =
                std::get_if<Fp>(&layer.gates[gate].constant)) {
            uniform_constants[gate] += *scalar;
            continue;
        }
        const fhe::SlotVector &values =
            std::get<fhe::SlotVector>(layer.gates[gate].constant);
        for (std::size_t slot = 0; slot < width; ++slot) {
            slot_constants[append_index(gate, slot, width)] += values[slot];
        }
    }
    append_nonempty(tables, layer_index,
                    GateTableKind::AffineConstantUniform,
                    output_variables, std::move(uniform_constants));
    append_nonempty(
        tables, layer_index, GateTableKind::AffineConstantSlot,
        checked_add(output_variables, slot_variables,
                    "sparse constant dimension overflows"),
        std::move(slot_constants));
}

std::vector<SparseTableSource>
build_sources(const payload::LayeredCircuit &circuit,
              GateTableSet table_set) {
    std::vector<SparseTableSource> result;
    if (table_set == GateTableSet::Wide) {
        const auto masks = WideMaskDictionary::build(circuit);
        const auto append = [&](std::size_t layer, GateTableKind kind,
                                std::size_t domain, auto &&visit) {
            std::vector<sparse::SparseEntry> entries;
            visit([&](const auto &entry) { entries.push_back(entry); });
            if (!entries.empty()) result.push_back({
                {layer, kind, result.size(), variables(domain), entries.size()},
                std::move(entries)});
        };
        for (std::size_t layer = 0; layer + 1 < circuit.layers.size(); ++layer) {
            if (payload::layer_kind(circuit.layers[layer]) !=
                payload::LayerKind::Affine) continue;
            const auto program = WideProgram::build(circuit, layer, masks);
            const auto &d = program.dimensions();
            const auto add = [&](WidePublicTable source, GateTableKind kind,
                                 std::size_t domain) {
                append(layer, kind, domain, [&](const auto &visitor) {
                    program.visit_entries(source, visitor);
                });
            };
            add(WidePublicTable::UniformEdges,
                GateTableKind::WideLocalUniformEdges, d.uniform_edge_domain);
            add(WidePublicTable::MaskEdges,
                GateTableKind::WideLocalMaskEdges, d.mask_edge_domain);
            add(WidePublicTable::UniformConstants,
                GateTableKind::AffineConstantUniform, d.uniform_constant_domain);
            add(WidePublicTable::SlotConstants,
                GateTableKind::AffineConstantSlot, d.slot_constant_domain);
        }
        append(0, GateTableKind::WideMaskDictionary,
               checked_product(masks->padded_size(), masks->slots(),
                               "Wide dictionary domain overflows"),
               [&](const auto &visitor) { masks->visit_entries(visitor); });
        return result;
    }
    for (std::size_t layer = 0; layer + 1 < circuit.layers.size(); ++layer) {
        if (payload::layer_kind(circuit.layers[layer]) ==
            payload::LayerKind::Affine) {
            append_affine_sources(circuit, layer, table_set, result);
        }
    }
    return result;
}

bool bit_msb(std::size_t address, std::size_t variable,
             std::size_t variables) {
    return ((address >> (variables - 1U - variable)) & 1U) != 0;
}

SparseTableProverKey commit_source(
    SparseTableSource source, const basefold::Parameters &parameters) {
    const auto shape = plan_sparse_table_shape(
        source.descriptor, GateTableSet::Laned, parameters);
    const auto [message_size, shard_size, shard_count, logical_width,
                physical_width] = shape;

    std::vector<std::vector<Fp>> columns(
        physical_width, std::vector<Fp>(shard_size, Fp::zero()));
    for (std::size_t slot = 0; slot < source.entries.size(); ++slot) {
        const sparse::SparseEntry &entry = source.entries[slot];
        const std::size_t shard = slot / shard_size;
        const std::size_t offset = slot % shard_size;
        const std::size_t column_offset = shard * logical_width;
        columns[column_offset][offset] = entry.value;
        for (std::size_t variable = 0;
             variable < source.descriptor.local_variables; ++variable) {
            if (bit_msb(entry.address, variable,
                        source.descriptor.local_variables)) {
                columns[column_offset + 1U + variable][offset] = Fp::one();
            }
        }
    }
    basefold::Commitment commitment =
        basefold::commit(std::move(columns), parameters.log_rate);
    SparseTableCommitment verifier{
        message_size, shard_size, shard_count, logical_width,
        physical_width, commitment.root, std::nullopt, std::nullopt};
    return SparseTableProverKey{std::move(verifier),
                                std::move(commitment),
                                std::move(source.entries), std::nullopt};
}

std::shared_ptr<const std::filesystem::path> private_directory(
    const std::filesystem::path &parent) {
    std::filesystem::create_directories(parent);
    std::random_device random;
    for (std::size_t attempt = 0; attempt < 64; ++attempt) {
        const auto path = parent / ("gate-index-" + std::to_string(random()) +
                                   "-" + std::to_string(random()));
        if (!std::filesystem::create_directory(path)) continue;
        std::filesystem::permissions(path, std::filesystem::perms::owner_all,
                                     std::filesystem::perm_options::replace);
        return {new std::filesystem::path(path), [](const auto *owned) {
            std::error_code ignored;
            std::filesystem::remove_all(*owned, ignored);
            delete owned;
        }};
    }
    throw std::runtime_error("cannot allocate private GateMLE directory");
}


} // namespace

SparseTableShape plan_sparse_table_shape(
    const GateTableDescriptor &table, GateTableSet table_set,
    const basefold::Parameters &parameters) {
    if (table.support_size == 0 || parameters.log_rate == 0 ||
        parameters.log_rate > kBaseFieldTwoAdicity ||
        parameters.num_queries == 0 ||
        (table_set != GateTableSet::Wide && table_set != GateTableSet::Laned))
        throw std::invalid_argument("invalid sparse gate-table planning inputs");
    const auto rows = next_power_of_two(table.support_size);
    const auto width = next_power_of_two(checked_add(
        table.local_variables, 1, "sparse gate-table column count overflows"));
    if (table_set == GateTableSet::Wide) {
        const auto cells = checked_product(rows, width,
                                           "Wide public block size overflows");
        if (cells > (std::size_t{1} << basefold::foldable::kMaxVariables))
            throw std::length_error("Wide public block exceeds certified domain");
        return {rows, rows, 1, width, width};
    }
    const auto shard_log = std::min(basefold::log2_exact(rows),
                                   kBaseFieldTwoAdicity - parameters.log_rate);
    const auto shard_size = std::size_t{1} << shard_log;
    const auto shard_count = rows / shard_size;
    const auto physical_width = checked_product(
        shard_count, width, "sparse gate-table physical width overflows");
    if (!basefold::valid_shape(shard_size, physical_width, parameters))
        throw std::invalid_argument("invalid sparse BaseFold geometry");
    return {rows, shard_size, shard_count, width, physical_width};
}

std::vector<WidePublicTableBlock> make_wide_public_blocks(
    const GateTableLayout &layout) {
    if (layout.table_set != GateTableSet::Wide)
        throw std::invalid_argument("Wide public blocks require Wide layout");
    std::vector<WidePublicTableBlock> blocks;
    blocks.reserve(layout.tables.size());
    for (std::size_t i = 0; i < layout.tables.size(); ++i) {
        const auto &table = layout.tables[i];
        if (table.selector != i || table.support_size == 0)
            throw std::invalid_argument("noncanonical Wide public table selector");
        const auto rows = next_power_of_two(table.support_size);
        const auto columns = next_power_of_two(checked_add(
            table.local_variables, 1, "Wide public column width overflows"));
        const auto cells = checked_product(rows, columns,
                                           "Wide public block size overflows");
        if (cells > (std::size_t{1} << basefold::foldable::kMaxVariables))
            throw std::length_error("Wide public block exceeds certified domain");
        blocks.push_back({i, 0, rows, columns});
    }
    std::sort(blocks.begin(), blocks.end(), [](const auto &a, const auto &b) {
        const auto ac = a.rows * a.columns, bc = b.rows * b.columns;
        return ac != bc ? ac > bc : a.selector < b.selector;
    });
    std::size_t offset = 0;
    for (auto &block : blocks) {
        block.offset = offset;
        offset = checked_add(offset, block.rows * block.columns,
                             "Wide public index size overflows");
    }
    if (offset > (std::size_t{1} << basefold::foldable::kMaxVariables))
        throw std::length_error("Wide public index exceeds certified domain");
    return blocks;
}

basefold::foldable::Metadata plan_wide_public_commitment(
    const GateTableLayout &layout) {
    const auto blocks = make_wide_public_blocks(layout);
    if (blocks.empty()) return {};
    const auto cells = next_power_of_two(blocks.back().offset +
                                        blocks.back().rows * blocks.back().columns);
    std::size_t rows = 1;
    for (const auto &block : blocks) rows = std::max(rows, block.rows);
    while (cells / rows > 256) rows *= 2;
    return {.m = rows, .width = cells / rows};
}

bool valid_wide_public_index(const GateTableVerifierKey &key) {
    try {
        if (key.tables.size() != key.layout.tables.size()) return false;
        if (key.layout.table_set != GateTableSet::Wide) {
            if (key.wide_public_commitment) return false;
            return std::all_of(key.tables.begin(), key.tables.end(),
                [](const auto &table) { return !table.wide_block_offset && !table.foldable; });
        }
        const auto blocks = make_wide_public_blocks(key.layout);
        if (blocks.empty()) return !key.wide_public_commitment;
        if (!key.wide_public_commitment) return false;
        const auto &meta = *key.wide_public_commitment;
        const auto shape = plan_wide_public_commitment(key.layout);
        if (meta.m != shape.m || meta.width != shape.width ||
            !basefold::foldable::valid_shape(meta, key.foldable_parameters) ||
            std::all_of(meta.root.begin(), meta.root.end(),
                        [](auto byte) { return byte == 0; })) return false;
        for (const auto &block : blocks) {
            const auto &table = key.tables[block.selector];
            if (table.foldable || table.wide_block_offset != block.offset ||
                table.root != meta.root ||
                !valid_sparse_table_commitment(key.layout.tables[block.selector],
                                                table, key.basefold_parameters)) return false;
        }
        return true;
    } catch (const std::exception &) {
        return false;
    }
}

GateTableProverKey preprocess_gate_tables(
    const payload::LayeredCircuit &circuit, GateTableSet table_set,
    const GateTableBuildOptions &options) {
    if (options.wide_resources.diagonal_cache_bytes > (64ULL << 20))
        throw std::invalid_argument("Wide GateMLE diagonal cache exceeds its 64 MiB admission allowance");
    if (options.preprocessing_threads == 0 ||
        options.preprocessing_threads > 256 ||
        (table_set != GateTableSet::Wide && options.preprocessing_threads != 1))
        throw std::invalid_argument(
            "parallel gate preprocessing requires Wide tables and 1..256 workers");
    if (table_set == GateTableSet::Wide && !basefold::foldable::valid_shape(
            basefold::foldable::Metadata{.m = 1, .width = 1},
            options.foldable_parameters))
        throw std::invalid_argument("invalid Wide foldable parameters");
    const GateTableLayout layout = make_gate_table_layout(
        circuit, table_set, options.basefold_parameters);
    std::size_t layout_entries = 0;
    for (const auto &table : layout.tables)
        layout_entries = checked_add(layout_entries, table.support_size,
                                      "sparse gate-table support overflows");
    if (layout_entries > options.max_message_entries)
        throw std::length_error(
            "preprocess_gate_tables: compact sparse support exceeds the configured limit");
    if (table_set == GateTableSet::Wide && layout_entries > 4096 &&
        (options.wide_scratch_parent.empty() || options.wide_max_disk_bytes == 0))
        throw std::invalid_argument(
            "Wide GateMLE requires an explicit scratch parent and total disk budget "
            "outside bounded reference instances");
    std::vector<SparseTableSource> sources =
        build_sources(circuit, table_set);
    if (sources.size() != layout.tables.size()) {
        throw std::logic_error(
            "preprocess_gate_tables: sparse layout/source mismatch");
    }
    std::size_t total_entries = 0;
    for (std::size_t table = 0; table < sources.size(); ++table) {
        if (!(sources[table].descriptor == layout.tables[table])) {
            throw std::logic_error(
                "preprocess_gate_tables: noncanonical sparse source");
        }
        total_entries = checked_add(total_entries,
                                    sources[table].entries.size(),
                                    "sparse gate-table support overflows");
    }
    if (total_entries > options.max_message_entries) {
        throw std::length_error(
            "preprocess_gate_tables: compact sparse support exceeds the "
            "configured limit");
    }

    GateTableProverKey result;
    result.verifier.layout = layout;
    result.verifier.basefold_parameters = options.basefold_parameters;
    result.verifier.foldable_parameters = options.foldable_parameters;
    result.verifier.layout_digest = digest(layout);
    result.wide_resources = options.wide_resources;
    if (table_set == GateTableSet::Wide) {
        result.wide_resources.max_disk_bytes = options.wide_max_disk_bytes
            ? options.wide_max_disk_bytes : (std::uint64_t{1} << 30);
        const auto parent = options.wide_scratch_parent.empty()
            ? std::filesystem::temp_directory_path()
            : options.wide_scratch_parent;
        result.wide_directory_owner = private_directory(parent);
        result.wide_scratch_parent = *result.wide_directory_owner;
        const auto blocks = make_wide_public_blocks(layout);
        const auto cells = blocks.empty() ? 0 : next_power_of_two(
            blocks.back().offset + blocks.back().rows * blocks.back().columns);
        const auto shape = plan_wide_public_commitment(layout);
        const auto total_disk = cells == 0 ? 0 :
            basefold::foldable::commitment_disk_bound(shape.m, shape.width);
        result.wide_retained_disk_bytes = total_disk;
        if (total_disk > result.wide_resources.max_disk_bytes)
            throw std::length_error("Wide GateMLE index exceeds disk budget");
        const auto available = std::filesystem::space(parent).available;
        if (available < total_disk || available - total_disk <
            result.wide_resources.min_free_bytes)
            throw std::length_error("Wide GateMLE index lacks free disk reserve");
    }
    result.tables.reserve(sources.size());
    result.verifier.tables.reserve(sources.size());
    if (table_set == GateTableSet::Laned) {
        for (auto &source : sources) {
            auto table = commit_source(std::move(source), options.basefold_parameters);
            result.verifier.tables.push_back(table.verifier);
            result.tables.push_back(std::move(table));
        }
    } else {
        const auto blocks = make_wide_public_blocks(layout);
        std::vector<std::size_t> offsets(sources.size());
        for (const auto &block : blocks) offsets[block.selector] = block.offset;
        for (auto &source : sources) {
            const auto shape = plan_sparse_table_shape(
                source.descriptor, table_set, options.basefold_parameters);
            const auto rows = shape.message_size;
            const auto width = shape.logical_width;
            SparseTableProverKey table;
            table.verifier = {rows, rows, 1, width, width, {}, std::nullopt,
                              offsets[source.descriptor.selector]};
            table.entries = std::move(source.entries);
            result.tables.push_back(std::move(table));
        }
        if (!blocks.empty()) {
            const auto cells = next_power_of_two(
                blocks.back().offset + blocks.back().rows * blocks.back().columns);
            const basefold::foldable::ValueSource flattened{cells,
                [&](std::size_t offset, std::span<Fpk> out) {
                    if (offset > cells || out.size() > cells - offset)
                        throw std::out_of_range("Wide public source range");
                    std::fill(out.begin(), out.end(), Fpk::zero());
                    std::size_t done = 0;
                    while (done < out.size()) {
                        const auto absolute = offset + done;
                        const auto after = std::upper_bound(blocks.begin(), blocks.end(),
                            absolute, [](std::size_t index, const auto &block) {
                                return index < block.offset;
                            });
                        if (after == blocks.begin()) break;
                        const auto &block = *std::prev(after);
                        const auto local = absolute - block.offset;
                        if (local >= block.rows * block.columns) break; // Global tail padding.
                        const auto column = local / block.rows, row = local % block.rows;
                        const auto count = std::min(out.size() - done, block.rows - row);
                        const auto &table = result.tables[block.selector];
                        const auto bits = layout.tables[block.selector].local_variables;
                        for (std::size_t j = 0; j < count && row + j < table.entries.size(); ++j) {
                            const auto &entry = table.entries[row + j];
                            if (column == 0) out[done + j] = Fpk::from_base(entry.value);
                            else if (column <= bits && bit_msb(entry.address, column - 1, bits))
                                out[done + j] = Fpk::one();
                        }
                        done += count;
                    }
                }};
            const auto shape = plan_wide_public_commitment(layout);
            std::vector<basefold::foldable::ValueSource> columns;
            for (std::size_t c = 0; c < shape.width; ++c)
                columns.push_back({shape.m, [&, c](std::size_t offset, std::span<Fpk> out) {
                    if (offset > shape.m || out.size() > shape.m - offset)
                        throw std::out_of_range("Wide public column range");
                    flattened.read(c * shape.m + offset, out);
                }});
            result.wide_public_commitment = basefold::foldable::commit(
                columns, result.wide_scratch_parent / "public-index",
                result.wide_resources, options.preprocessing_threads);
            result.verifier.wide_public_commitment = result.wide_public_commitment->metadata;
            for (auto &table : result.tables)
                table.verifier.root = result.verifier.wide_public_commitment->root;
        }
        for (const auto &table : result.tables) result.verifier.tables.push_back(table.verifier);
    }
    return result;
}

Fpk evaluate_sparse_table(std::span<const sparse::SparseEntry> entries,
                          std::size_t address_variables,
                          std::span<const Fpk> point_msb) {
    return sparse::evaluate_sparse_entries(entries, address_variables, point_msb);
}

bool valid_sparse_table_commitment(
    const GateTableDescriptor &table,
    const SparseTableCommitment &commitment,
    const basefold::Parameters &parameters) {
    try {
        if (table.support_size == 0 || parameters.log_rate == 0 ||
            parameters.log_rate > kBaseFieldTwoAdicity) {
            return false;
        }
        const std::size_t message_size =
            next_power_of_two(table.support_size);
        const std::size_t message_log =
            basefold::log2_exact(message_size);
        if (commitment.wide_block_offset) {
            const auto width = next_power_of_two(checked_add(
                table.local_variables, 1, "Wide public column width overflows"));
            const auto cells = checked_product(message_size, width,
                                                "Wide public block size overflows");
            return !commitment.foldable &&
                   commitment.message_size == message_size &&
                   commitment.shard_size == message_size &&
                   commitment.shard_count == 1 &&
                   commitment.logical_width == width &&
                   commitment.physical_width == width &&
                   cells <= (std::size_t{1} << basefold::foldable::kMaxVariables) &&
                   *commitment.wide_block_offset % cells == 0;
        }
        if (commitment.foldable) return false;
        const std::size_t shard_log = std::min(
            message_log, kBaseFieldTwoAdicity - parameters.log_rate);
        const std::size_t shard_size = std::size_t{1} << shard_log;
        const std::size_t shard_count = message_size / shard_size;
        const std::size_t logical_width = next_power_of_two(
            checked_add(table.local_variables, 1,
                        "sparse gate-table width overflows"));
        const std::size_t physical_width = checked_product(
            shard_count, logical_width,
            "sparse gate-table physical width overflows");
        return commitment.message_size == message_size &&
               commitment.shard_size == shard_size &&
               commitment.shard_count == shard_count &&
               commitment.logical_width == logical_width &&
               commitment.physical_width == physical_width &&
               basefold::valid_shape(shard_size, physical_width,
                                     parameters);
    } catch (const std::invalid_argument &) {
        return false;
    } catch (const std::overflow_error &) {
        return false;
    }
}

} // namespace laminate::gates
