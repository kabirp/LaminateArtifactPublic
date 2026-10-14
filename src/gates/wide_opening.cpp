#include "laminate/gates/wide_opening.hpp"

#include "laminate/basefold/common.hpp"
#include "laminate/field/serialization.hpp"
#include "laminate/gates/canonical_tables.hpp"
#include "laminate/gates/outsourced.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <filesystem>
#include <limits>
#include <map>
#include <stdexcept>
#include <string>
#include <unistd.h>

namespace laminate::gates {
namespace {
namespace fc = basefold::foldable;

std::vector<Fpk> concat(std::initializer_list<std::span<const Fpk>> parts) {
    std::vector<Fpk> result;
    for (auto part : parts) result.insert(result.end(), part.begin(), part.end());
    return result;
}
std::vector<Fpk> reverse(std::span<const Fpk> p) {
    return {p.rbegin(), p.rend()};
}
void observe_values(std::string_view label, std::span<const Fpk> values,
                    PublicCoin &coin) {
    coin.observe(label, basefold::serialize_values(values));
}

class ScratchDirectory {
  public:
    explicit ScratchDirectory(const std::filesystem::path &parent) {
        auto pattern = (parent / "wide-opening-XXXXXX").string();
        if (!::mkdtemp(pattern.data()))
            throw std::runtime_error("Wide opening: cannot create private scratch");
        path_ = pattern;
    }
    ~ScratchDirectory() {
        std::error_code error;
        std::filesystem::remove_all(path_, error);
    }
    std::filesystem::path child(const std::string &name) const {
        const auto path = path_ / name;
        if (!std::filesystem::create_directory(path))
            throw std::runtime_error("Wide opening: scratch path already exists");
        return path;
    }
    const std::filesystem::path &path() const { return path_; }
  private:
    std::filesystem::path path_;
};

/// Equality sources retain one small low-coordinate table. Evaluating a huge
/// streamed operand does not allocate its Boolean domain or do log(M) field
/// operations separately for every cell.
fc::ValueSource equality_source(std::span<const Fpk> point_lsb) {
    if (point_lsb.size() > fc::kMaxVariables)
        throw std::invalid_argument("Wide equality operand too large");
    const auto low_variables = std::min<std::size_t>(13, point_lsb.size());
    auto low = std::make_shared<const std::vector<Fpk>>(
        basefold::equality_evaluations(point_lsb.first(low_variables)));
    const std::vector<Fpk> high(point_lsb.begin() + low_variables, point_lsb.end());
    const std::size_t size = std::size_t{1} << point_lsb.size();
    return {size, [low, high, low_variables, size](std::size_t offset,
                                                 std::span<Fpk> out) {
        if (offset > size || out.size() > size - offset)
            throw std::out_of_range("Wide equality operand read");
        std::size_t done = 0;
        while (done < out.size()) {
            const auto index = offset + done;
            const auto within = index & (low->size() - 1);
            const auto count = std::min(out.size() - done, low->size() - within);
            const auto weight = basefold::equality_evaluation(index >> low_variables, high);
            for (std::size_t j = 0; j < count; ++j)
                out[done + j] = weight * (*low)[within + j];
            done += count;
        }
    }};
}

Fpk inner_product(const fc::ValueSource &a, const fc::ValueSource &b,
                  std::size_t block) {
    if (a.size != b.size || block == 0)
        throw std::invalid_argument("Wide inner product shape");
    std::vector<Fpk> av(std::min(block, a.size)), bv(av.size());
    Fpk result = Fpk::zero();
    for (std::size_t offset = 0; offset < a.size; offset += av.size()) {
        const auto count = std::min(av.size(), a.size - offset);
        a.read(offset, std::span(av).first(count));
        b.read(offset, std::span(bv).first(count));
        for (std::size_t j = 0; j < count; ++j) result += av[j] * bv[j];
    }
    return result;
}

struct Target {
    WideColumnTarget kind;
    std::vector<Fpk> point_msb;
    Fpk claim;
};
struct Group {
    std::size_t layer;
    std::vector<Fpk> output_point;
    std::vector<Target> targets;
};
const WideLayerMetadata &layer_metadata(const GateTableLayout &layout,
                                        std::size_t layer) {
    const auto it = std::find_if(layout.wide_layers.begin(), layout.wide_layers.end(),
        [layer](const auto &entry) { return entry.layer_index == layer; });
    if (it == layout.wide_layers.end())
        throw std::invalid_argument("Wide opening: unknown affine layer");
    return *it;
}

std::vector<Group> group_queries(const GateTableLayout &layout,
                                 std::span<const RecordedGateQuery> queries,
                                 std::span<const Fpk> values) {
    if (layout.table_set != GateTableSet::Wide || queries.empty() ||
        queries.size() != values.size())
        throw std::invalid_argument("Wide opening: invalid query batch");
    std::vector<Group> groups;
    for (std::size_t i = 0; i < queries.size(); ++i) {
        const auto &query = queries[i];
        const auto &dims = layer_metadata(layout, query.layer_index).dimensions;
        const auto output_variables = basefold::log2_exact(dims.output_width) +
                                      basefold::log2_exact(dims.slots);
        const bool constant = query.kind == RecordedGateQueryKind::AffineConstant;
        const auto source_variables = constant ? 0 :
            basefold::log2_exact(dims.input_width) + basefold::log2_exact(dims.slots);
        if ((!constant && query.kind != RecordedGateQueryKind::WideAffine) ||
            query.first_point_size != output_variables ||
            query.local_point_msb.size() != output_variables + source_variables)
            throw std::invalid_argument("Wide opening: query dimensions");
        const auto points = std::span(query.local_point_msb);
        const std::vector<Fpk> output(points.begin(), points.begin() + output_variables);
        auto group = std::find_if(groups.begin(), groups.end(), [&](const Group &g) {
            return g.layer == query.layer_index && g.output_point == output;
        });
        if (group == groups.end()) {
            groups.push_back({query.layer_index, output, {}});
            group = std::prev(groups.end());
        }
        group->targets.push_back({constant ? WideColumnTarget::Constant : WideColumnTarget::Input,
            {points.begin() + output_variables, points.end()}, values[i]});
    }
    return groups;
}

struct LocalQuery {
    std::size_t layer;
    WideColumnTarget kind;
    std::vector<Fpk> row_wire;
    std::vector<Fpk> row_slot;
    std::vector<Fpk> source_wire;
    std::vector<Fpk> source_slot;
};

std::vector<Fpk> embedded_wire(std::span<const Fpk> wire,
                               std::size_t width, bool block) {
    const auto variables = basefold::log2_exact(width);
    if (wire.size() > variables) throw std::invalid_argument("Wide embedded point");
    std::vector<Fpk> result{block ? Fpk::one() : Fpk::zero()};
    result.insert(result.end(), variables - wire.size(), Fpk::zero());
    result.insert(result.end(), wire.begin(), wire.end());
    return result;
}

LocalQuery local_query(std::size_t layer, const WideProgramDimensions &dims,
                       bool output, std::span<const Fpk> row,
                       const Target &target) {
    const auto slots = basefold::log2_exact(dims.slots);
    if (row.size() < slots) throw std::invalid_argument("Wide local row point");
    LocalQuery result{layer, target.kind,
        embedded_wire(row.first(row.size() - slots), dims.row_width, output),
        {row.end() - slots, row.end()}, {}, {}};
    if (target.kind != WideColumnTarget::Constant) {
        const auto point = std::span(target.point_msb);
        if (point.size() < slots) throw std::invalid_argument("Wide local source point");
        result.source_wire = embedded_wire(point.first(point.size() - slots),
            dims.source_width, target.kind == WideColumnTarget::Internal);
        result.source_slot = {point.end() - slots, point.end()};
    }
    return result;
}

void observe_local(const LocalQuery &q, const Fpk &value, PublicCoin &coin) {
    coin.observe("wide-gates/local-query/v1", q.layer);
    coin.observe("wide-gates/local-query/kind", static_cast<std::uint64_t>(q.kind));
    observe_values("wide-gates/local-query/points",
        concat({q.row_wire, q.row_slot, q.source_wire, q.source_slot}), coin);
    const std::array<Fpk, 1> claim{value};
    observe_values("wide-gates/local-query/value", claim, coin);
}

const GateTableDescriptor *dictionary_table(const GateTableLayout &layout) {
    const auto it = std::find_if(layout.tables.begin(), layout.tables.end(),
        [](const auto &table) { return table.kind == GateTableKind::WideMaskDictionary; });
    return it == layout.tables.end() ? nullptr : &*it;
}
struct Pending {
    std::size_t selector;
    std::vector<Fpk> point_msb;
    sparse::SparseProductReduction reduction;
};

std::vector<Fpk> bind_mask_weights(std::span<const sparse::SparseEntry> entries,
                                   const LocalQuery &q, std::size_t mask_width) {
    const auto bits = basefold::log2_exact(mask_width);
    const auto point = reverse(concat({q.row_wire, q.source_wire}));
    std::vector<Fpk> result(mask_width, Fpk::zero());
    for (const auto &entry : entries)
        result[entry.address & (mask_width - 1)] +=
            basefold::equality_evaluation(entry.address >> bits, point) * entry.value;
    return result;
}

WideLocalOpeningProof prove_local(const GateTableProverKey &key,
    const WideMaskDictionary &dictionary, const LocalQuery &q, const Fpk &claim,
    std::vector<Pending> &pending, PublicCoin &coin) {
    WideLocalOpeningProof proof;
    observe_local(q, claim, coin);
    auto sparse_claim = [&](const GateTableDescriptor &table, std::vector<Fpk> point,
                             const Fpk &value) {
        const auto &state = key.tables.at(table.selector);
        auto result = sparse::prove_sparse_evaluation(state.entries,
            state.verifier.message_size, table.local_variables, point, value, coin);
        proof.products.push_back(std::move(result.proof));
        pending.push_back({table.selector, std::move(point), std::move(result.reduction)});
    };
    if (q.kind == WideColumnTarget::Constant) {
        const auto *uniform = find_table_if(key.verifier.layout, q.layer,
                                            GateTableKind::AffineConstantUniform);
        const auto *slot = find_table_if(key.verifier.layout, q.layer,
                                         GateTableKind::AffineConstantSlot);
        const auto point = concat({q.row_wire, q.row_slot});
        if (uniform) proof.first_component = evaluate_sparse_table(
            key.tables.at(uniform->selector).entries, uniform->local_variables, q.row_wire);
        if (slot) proof.second_component = evaluate_sparse_table(
            key.tables.at(slot->selector).entries, slot->local_variables, point);
        observe_values("wide-gates/local-components",
                       std::array{proof.first_component, proof.second_component}, coin);
        if (uniform) sparse_claim(*uniform, q.row_wire, proof.first_component);
        if (slot) sparse_claim(*slot, point, proof.second_component);
    } else {
        const auto *uniform = find_table_if(key.verifier.layout, q.layer,
                                            GateTableKind::WideLocalUniformEdges);
        const auto *mask = find_table_if(key.verifier.layout, q.layer,
                                         GateTableKind::WideLocalMaskEdges);
        if (uniform) proof.first_component = evaluate_wide_affine_coefficient(
            key.tables.at(uniform->selector).entries, q.row_wire, q.row_slot,
            q.source_wire, q.source_slot);
        std::vector<Fpk> weights;
        const auto plaintexts = dictionary.masks();
        if (mask) {
            weights = bind_mask_weights(key.tables.at(mask->selector).entries,
                                        q, dictionary.padded_size());
            const auto er = basefold::equality_evaluations(reverse(q.row_slot));
            const auto es = basefold::equality_evaluations(reverse(q.source_slot));
            for (std::size_t a = 0; a < plaintexts.size(); ++a)
                for (std::size_t s = 0; s < er.size(); ++s)
                    proof.second_component += weights[a] * plaintexts[a][s] * er[s] * es[s];
        }
        observe_values("wide-gates/local-components",
                       std::array{proof.first_component, proof.second_component}, coin);
        if (uniform) {
            auto action = prove_wide_action_sumcheck(key.tables.at(uniform->selector).entries,
                q.row_wire, q.row_slot, q.source_wire, q.source_slot, proof.first_component, coin);
            sparse_claim(*uniform, concat({q.row_wire, q.source_wire, action.reduction.offset_point_msb}),
                         action.reduction.compact_weight);
            proof.action = std::move(action.proof);
        }
        if (mask) {
            const auto *dictionary_descriptor = dictionary_table(key.verifier.layout);
            if (!dictionary_descriptor) throw std::invalid_argument("Wide mask dictionary missing");
            auto action = prove_masked_action(weights, plaintexts, q.row_slot,
                q.source_slot, proof.second_component, coin);
            sparse_claim(*mask, concat({q.row_wire, q.source_wire, action.reduction.mask_point_msb}),
                         action.reduction.mask_weight);
            sparse_claim(*dictionary_descriptor,
                concat({action.reduction.mask_point_msb, action.reduction.slot_point_msb}),
                action.reduction.plaintext);
            proof.masked = std::move(action.proof);
        }
    }
    if (proof.first_component + proof.second_component != claim)
        throw std::logic_error("Wide local matrix coefficient disagreement");
    return proof;
}

bool verify_local(const GateTableVerifierKey &key, const LocalQuery &q,
    const Fpk &claim, const WideLocalOpeningProof &proof,
    std::vector<Pending> &pending, PublicCoin &coin) {
    if (proof.first_component + proof.second_component != claim) return false;
    observe_local(q, claim, coin);
    observe_values("wide-gates/local-components",
                   std::array{proof.first_component, proof.second_component}, coin);
    std::size_t cursor = 0;
    auto sparse_claim = [&](const GateTableDescriptor &table, std::vector<Fpk> point,
                             const Fpk &value) {
        if (cursor >= proof.products.size()) return false;
        const auto reduction = sparse::verify_sparse_evaluation(
            key.tables.at(table.selector).message_size, table.local_variables,
            point, value, proof.products[cursor++], coin);
        if (!reduction) return false;
        pending.push_back({table.selector, std::move(point), *reduction});
        return true;
    };
    if (q.kind == WideColumnTarget::Constant) {
        if (proof.action || proof.masked) return false;
        const auto *uniform = find_table_if(key.layout, q.layer, GateTableKind::AffineConstantUniform);
        const auto *slot = find_table_if(key.layout, q.layer, GateTableKind::AffineConstantSlot);
        if (uniform ? !sparse_claim(*uniform, q.row_wire, proof.first_component)
                    : !proof.first_component.is_zero()) return false;
        if (slot ? !sparse_claim(*slot, concat({q.row_wire, q.row_slot}), proof.second_component)
                 : !proof.second_component.is_zero()) return false;
    } else {
        const auto *uniform = find_table_if(key.layout, q.layer, GateTableKind::WideLocalUniformEdges);
        const auto *mask = find_table_if(key.layout, q.layer, GateTableKind::WideLocalMaskEdges);
        if (bool(uniform) != proof.action.has_value() || bool(mask) != proof.masked.has_value()) return false;
        if (uniform) {
            const auto action = verify_wide_action_sumcheck(q.row_wire, q.row_slot,
                q.source_wire, q.source_slot, proof.first_component, *proof.action, coin);
            if (!action || !sparse_claim(*uniform,
                concat({q.row_wire, q.source_wire, action->offset_point_msb}), action->compact_weight)) return false;
        } else if (!proof.first_component.is_zero()) return false;
        if (mask) {
            const auto *dictionary = dictionary_table(key.layout);
            if (!dictionary) return false;
            const auto action = verify_masked_action(
                basefold::log2_exact(key.layout.wide_masks.mask_width), q.row_slot,
                q.source_slot, proof.second_component, *proof.masked, coin);
            if (!action || !sparse_claim(*mask,
                concat({q.row_wire, q.source_wire, action->mask_point_msb}), action->mask_weight) ||
                !sparse_claim(*dictionary, concat({action->mask_point_msb, action->slot_point_msb}),
                              action->plaintext)) return false;
        } else if (!proof.second_component.is_zero()) return false;
    }
    return cursor == proof.products.size();
}

std::vector<std::vector<const Pending *>> by_table(
    std::span<const Pending> pending, std::size_t count) {
    std::vector<std::vector<const Pending *>> grouped(count);
    for (const auto &request : pending) grouped.at(request.selector).push_back(&request);
    return grouped;
}

void observe_targets(std::size_t selector, const basefold::ColumnTargets &targets,
                      PublicCoin &coin) {
    coin.observe("wide-gates/public-target-matrix/v1", selector);
    coin.observe("wide-gates/public-target-matrix/rows", targets.size());
    for (const auto &row : targets) observe_values("wide-gates/public-target-matrix/row", row, coin);
}

bool valid_target_rows(const GateTableDescriptor &descriptor,
                       const SparseTableCommitment &table,
                       const std::vector<const Pending *> &requests,
                       const basefold::ColumnTargets &targets) {
    if (targets.size() != requests.size() || !table.wide_block_offset) return false;
    for (std::size_t row = 0; row < requests.size(); ++row) {
        if (targets[row].size() != table.physical_width) return false;
        const auto &request = *requests[row];
        if (request.reduction.entry_point_lsb.size() != basefold::log2_exact(table.message_size)) return false;
        const auto linear = sparse::linearize_sparse_leaf(descriptor.local_variables,
            request.point_msb, request.reduction.factor_point_lsb);
        if (linear.column_weights.size() > targets[row].size()) return false;
        Fpk result = linear.constant;
        for (std::size_t c = 0; c < linear.column_weights.size(); ++c)
            result += linear.column_weights[c] * targets[row][c];
        if (result != request.reduction.leaf_claim) return false;
    }
    return true;
}

std::vector<Fpk> combine_target_columns(const basefold::ColumnTargets &targets,
                                        std::span<const Fpk> weights) {
    std::vector<Fpk> result(targets.size(), Fpk::zero());
    for (std::size_t r = 0; r < targets.size(); ++r)
        for (std::size_t c = 0; c < weights.size(); ++c)
            result[r] += weights[c] * targets[r][c];
    return result;
}

fc::ValueSource slice_source(fc::ValueSource source, std::size_t offset,
                             std::size_t size) {
    if (offset > source.size || size > source.size - offset)
        throw std::invalid_argument("Wide scalar block exceeds its message");
    return {size, [source = std::move(source), offset, size](
        std::size_t begin, std::span<Fpk> out) {
        if (begin > size || out.size() > size - begin)
            throw std::out_of_range("Wide scalar block read");
        source.read(offset + begin, out);
    }};
}

// Evaluate the exact canonical public message from its compact sparse input.
// Stored address columns contain only zero/one, and the value column lies in
// Fp. Reusing row weights avoids repeated extension multiplication and disk
// reads of the much larger encoded index. Padding still evaluates to zero.
std::vector<Fpk> semantic_public_target_row(
    const GateTableProverKey &key, std::span<const WidePublicTableBlock> blocks,
    std::size_t row_offset, std::span<const Fpk> row_weights) {
    const auto &metadata = key.wide_public_commitment->metadata;
    std::vector<Fpk> result(metadata.width, Fpk::zero());
    for (std::size_t c = 0; c < metadata.width; ++c) {
        const auto begin = c * metadata.m + row_offset;
        std::size_t done = 0;
        while (done < row_weights.size()) {
            const auto absolute = begin + done;
            const auto after = std::upper_bound(blocks.begin(), blocks.end(), absolute,
                [](std::size_t index, const auto &block) { return index < block.offset; });
            if (after == blocks.begin()) break;
            const auto &block = *std::prev(after);
            const auto local = absolute - block.offset;
            if (local >= block.rows * block.columns) break; // Global tail padding.
            const auto column = local / block.rows;
            const auto row = local % block.rows;
            const auto count = std::min(row_weights.size() - done, block.rows - row);
            const auto &entries = key.tables[block.selector].entries;
            const auto bits = key.verifier.layout.tables[block.selector].local_variables;
            if (column <= bits) {
                const auto present = row < entries.size() ? std::min(count, entries.size() - row) : 0;
                for (std::size_t j = 0; j < present; ++j) {
                    const auto &entry = entries[row + j];
                    if (column == 0)
                        result[c] += row_weights[done + j] * entry.value;
                    else if ((entry.address >> (bits - column)) & 1U)
                        result[c] += row_weights[done + j];
                }
            }
            done += count;
        }
    }
    return result;
}

// Canonical operand order is table, request, first local column introducing
// its row offset. Columns at the same row offset share a transparent operand;
// the whole target row is disclosed before sampling the common column batch.
std::vector<std::size_t> append_public_operands(
    const SparseTableCommitment &table, const fc::Metadata &metadata,
    std::span<const Fpk> point_lsb, std::vector<fc::BlockOperand> &operands) {
    const auto expected = wide_public_operands_per_request(table, metadata);
    if (point_lsb.size() != basefold::log2_exact(table.message_size))
        throw std::invalid_argument("Wide public row point has wrong dimension");
    if (expected > 65536 - std::min<std::size_t>(65536, operands.size()))
        throw std::invalid_argument("Wide public operand count exceeds PCS policy");
    std::map<std::size_t, std::size_t> by_offset;
    std::vector<std::size_t> result;
    result.reserve(table.physical_width);
    for (std::size_t c = 0; c < table.physical_width; ++c) {
        const auto offset = (*table.wide_block_offset + c * table.message_size) % metadata.m;
        const auto [entry, inserted] = by_offset.emplace(offset, operands.size());
        if (inserted)
            operands.push_back({offset, {point_lsb.begin(), point_lsb.end()}, {Fpk::one()}});
        result.push_back(entry->second);
    }
    if (by_offset.size() != expected)
        throw std::logic_error("Wide public operand layout disagrees with its plan");
    return result;
}

std::vector<Fpk> public_column_weights(const basefold::ColumnTargets &targets,
                                      std::size_t width, PublicCoin &coin) {
    coin.observe("wide-gates/honest-public-targets/v1", targets.size());
    coin.observe("wide-gates/honest-public-targets/width", width);
    for (const auto &row : targets)
        observe_values("wide-gates/honest-public-targets/row", row, coin);
    // Honest setup fixes all codeword columns. Once the full target matrix is
    // fixed, any nonzero error matrix survives independent uniform column
    // weights with probability at most 1/|F|. The PCS subsequently samples its
    // independent operand batch. Sharing weights does not multiply this bound
    // by the number of target rows or columns.
    auto weights = coin.challenge_vector(width);
    if (weights.size() != width)
        throw std::runtime_error("Wide public column coin returned malformed weights");
    return weights;
}

void prove_public_tables(const GateTableProverKey &key,
    std::span<const Pending> pending, WideGateOpeningProof &proof,
    const ScratchDirectory &scratch, PublicCoin &coin) {
    if (pending.empty()) return;
    if (!key.wide_public_commitment)
        throw std::invalid_argument("Wide public commitment missing");
    const auto &commitment = *key.wide_public_commitment;
    const auto &metadata = commitment.metadata;
    const auto requests = by_table(pending, key.tables.size());
    const auto blocks = make_wide_public_blocks(key.verifier.layout);
    std::vector<fc::BlockOperand> operands;
    for (std::size_t selector = 0; selector < requests.size(); ++selector) {
        if (requests[selector].empty()) continue;
        const auto &table = key.tables[selector].verifier;
        basefold::ColumnTargets targets;
        for (const Pending *request : requests[selector]) {
            const auto first_operand = operands.size();
            const auto indices = append_public_operands(
                table, metadata, request->reduction.entry_point_lsb, operands);
            const auto row_weights = basefold::equality_evaluations(request->reduction.entry_point_lsb);
            for (std::size_t i = first_operand; i < operands.size(); ++i)
                proof.public_column_targets.push_back(semantic_public_target_row(
                    key, blocks, operands[i].offset, row_weights));
            auto &local = targets.emplace_back();
            for (std::size_t c = 0; c < table.physical_width; ++c) {
                const auto global_column =
                    (*table.wide_block_offset + c * table.message_size) / metadata.m;
                local.push_back(proof.public_column_targets[indices[c]][global_column]);
            }
        }
        if (!valid_target_rows(key.verifier.layout.tables.at(selector), table,
                               requests[selector], targets))
            throw std::logic_error("Wide public columns disagree with sparse reduction");
        observe_targets(selector, targets, coin);
        proof.tables.push_back({selector, std::move(targets)});
    }
    const auto weights = public_column_weights(proof.public_column_targets, metadata.width, coin);
    const auto values = combine_target_columns(proof.public_column_targets, weights);
    auto result = fc::prove_blocks(commitment, operands, weights, values, coin,
        scratch.child("public-pcs"), fc::CommitmentPremise::HonestCodewordColumns,
        key.verifier.foldable_parameters, key.wide_resources);
    proof.public_opening = std::move(result.proof);
}

bool empty_pcs(const fc::Proof &proof);

bool verify_public_tables(const GateTableVerifierKey &key,
    std::span<const Pending> pending, const WideGateOpeningProof &proof,
    PublicCoin &coin) {
    if (pending.empty()) return proof.tables.empty() && proof.public_column_targets.empty() &&
                                 empty_pcs(proof.public_opening);
    if (!key.wide_public_commitment) return false;
    const auto &metadata = *key.wide_public_commitment;
    for (const auto &row : proof.public_column_targets)
        if (row.size() != metadata.width) return false;
    const auto requests = by_table(pending, key.tables.size());
    std::vector<fc::BlockOperand> operands;
    std::size_t cursor = 0;
    for (std::size_t selector = 0; selector < requests.size(); ++selector) {
        if (requests[selector].empty()) continue;
        if (cursor >= proof.tables.size()) return false;
        const auto &table_proof = proof.tables[cursor++];
        const auto &table = key.tables[selector];
        if (!table.wide_block_offset || table_proof.table_selector != selector ||
            !valid_target_rows(key.layout.tables.at(selector), table,
                               requests[selector], table_proof.column_targets)) return false;
        for (std::size_t r = 0; r < requests[selector].size(); ++r) {
            const auto indices = append_public_operands(
                table, metadata, requests[selector][r]->reduction.entry_point_lsb, operands);
            if (operands.size() > proof.public_column_targets.size()) return false;
            for (std::size_t c = 0; c < table.physical_width; ++c) {
                const auto global_column =
                    (*table.wide_block_offset + c * table.message_size) / metadata.m;
                if (table_proof.column_targets[r][c] !=
                    proof.public_column_targets[indices[c]][global_column]) return false;
            }
        }
        observe_targets(selector, table_proof.column_targets, coin);
    }
    if (cursor != proof.tables.size() || operands.size() != proof.public_column_targets.size())
        return false;
    const auto weights = public_column_weights(proof.public_column_targets, metadata.width, coin);
    const auto values = combine_target_columns(proof.public_column_targets, weights);
    return fc::verify_blocks(metadata, operands, weights, values, proof.public_opening,
        coin, fc::CommitmentPremise::HonestCodewordColumns,
        key.foldable_parameters).has_value();
}

void observe_trace(const Group &group, const basefold::Digest &root,
                    PublicCoin &coin) {
    coin.observe("wide-gates/reverse-trace/v1", group.layer);
    observe_values("wide-gates/reverse-trace/output-point", group.output_point, coin);
    coin.observe("wide-gates/reverse-trace/requests", group.targets.size());
    for (const auto &target : group.targets) {
        coin.observe("wide-gates/reverse-trace/target-kind", static_cast<std::uint64_t>(target.kind));
        observe_values("wide-gates/reverse-trace/target-point", target.point_msb, coin);
        observe_values("wide-gates/reverse-trace/target-value", std::array{target.claim}, coin);
    }
    coin.observe("wide-gates/reverse-trace/root", root);
}

void observe_trace_values(const WideTraceOpeningProof &proof, PublicCoin &coin) {
    observe_values("wide-gates/reverse-trace/boundaries", proof.boundary_values, coin);
    observe_values("wide-gates/reverse-trace/residual", std::array{proof.residual_evaluation}, coin);
}

Fpk combined_claim(std::span<const Target> targets, std::span<const Fpk> boundary,
                    std::span<const Fpk> weights) {
    if (targets.size() != boundary.size() || targets.size() != weights.size())
        throw std::invalid_argument("Wide reverse claim shape");
    Fpk result = Fpk::zero();
    for (std::size_t i = 0; i < targets.size(); ++i)
        result += weights[i] * (targets[i].claim - boundary[i]);
    return result;
}

Fpk combine(std::span<const Fpk> values, std::span<const Fpk> weights) {
    if (values.size() != weights.size()) throw std::invalid_argument("Wide value batch shape");
    Fpk result = Fpk::zero();
    for (std::size_t i = 0; i < values.size(); ++i) result += values[i] * weights[i];
    return result;
}

bool empty_product(const QuadraticProductProof &proof) {
    return proof.rounds.empty() && proof.left.is_zero() && proof.right.is_zero();
}
bool empty_pcs(const fc::Proof &proof) {
    return proof.sumcheck.rounds.empty() && proof.sumcheck.operand_evaluations.empty() &&
           proof.roots.empty() && proof.final_codeword.empty() &&
           proof.initial.values.empty() && proof.initial.frontier.empty() && proof.folded.empty();
}

std::uint64_t checked_add(std::uint64_t a, std::uint64_t b) {
    if (b > std::numeric_limits<std::uint64_t>::max() - a)
        throw std::overflow_error("Wide opening disk reservation overflow");
    return a + b;
}
std::uint64_t checked_multiply(std::uint64_t a, std::uint64_t b) {
    if (b && a > std::numeric_limits<std::uint64_t>::max() / b)
        throw std::overflow_error("Wide opening disk reservation overflow");
    return a * b;
}

std::vector<std::size_t> trace_sizes(const GateTableLayout &layout,
                                     std::span<const Group> groups) {
    std::vector<std::size_t> sizes;
    for (const auto &group : groups) {
        const auto &layer = layer_metadata(layout, group.layer);
        sizes.push_back(layer.node_count ? layer.dimensions.internal_scalars : 0);
    }
    return sizes;
}

void observe_group(const WideAdjointGroupLayout &layout,
                   std::span<const Group> groups, const basefold::Digest &root,
                   PublicCoin &coin) {
    coin.observe("wide-gates/adjoint-group/v2", layout.message_size);
    coin.observe("wide-gates/adjoint-group/block-size", layout.block_size);
    coin.observe("wide-gates/adjoint-group/members", layout.trace_indices.size());
    for (const auto index : layout.trace_indices) {
        coin.observe("wide-gates/adjoint-group/trace-index", index);
        observe_trace(groups[index], root, coin);
    }
}

void admit_opening(const GateTableProverKey &key, std::span<const Group> groups,
                   std::span<const WideAdjointGroupLayout> layout) {
    if (key.wide_resources.block_elements < 2 ||
        (key.wide_resources.block_elements & 1) != 0 ||
        key.wide_resources.block_elements > 65536)
        throw std::invalid_argument("Wide opening: invalid working block size");
    std::uint64_t peak = 0;
    for (const auto &batch : layout) {
        const auto m = batch.message_size;
        const auto source = checked_multiply(m, kSerializedFpkBytes);
        const auto retained = fc::retained_commitment_disk_bound(m, 1);
        peak = std::max(peak, checked_add(source, fc::commitment_disk_bound(m, 1)));
        const auto persistent = checked_add(source, retained);
        peak = std::max(peak, checked_add(persistent,
            fc::proving_disk_bound(m, 2 * batch.trace_indices.size(), true)));
        for (const auto index : batch.trace_indices) {
            // Only one member's operator columns and quadratic-product scratch
            // coexist with the retained group. They close before its joint PCS.
            const auto local_columns = checked_add(groups[index].targets.size(), 1);
            const auto local_bytes = checked_multiply(batch.block_size,
                checked_add(checked_multiply(local_columns, kSerializedFpkBytes),
                            6 * kSerializedFpkBytes));
            peak = std::max(peak, checked_add(persistent, local_bytes));
        }
    }
    if (key.wide_public_commitment)
        // The honest-column batch has random weights, so its combined message
        // and codeword cannot alias the retained index. The disk formula only
        // materializes one batched operand and is independent of its count.
        peak = std::max(peak, fc::proving_disk_bound(
            key.wide_public_commitment->metadata.m, 1, false));
    const auto total = checked_add(key.wide_retained_disk_bytes, peak);
    const auto available = std::filesystem::space(key.wide_scratch_parent).available;
    if (total > key.wide_resources.max_disk_bytes ||
        key.wide_resources.min_free_bytes > available ||
        peak > available - key.wide_resources.min_free_bytes)
        throw std::runtime_error("Wide opening: aggregate retained-index and proof disk budget exceeded");
}

WideTraceOpeningProof prove_trace(const GateTableProverKey &key,
    const WideProgram &program, const Group &group, std::size_t group_index,
    const ScratchDirectory &scratch, std::vector<Pending> &pending,
    const fc::ValueSource &z_source, std::size_t block_offset,
    std::vector<fc::BlockOperand> &operands, std::vector<Fpk> &values,
    PublicCoin &coin) {
    WideTraceOpeningProof proof;
    const auto &dims = program.dimensions();
    auto targets = group.targets;
    const auto prefix = "trace-" + std::to_string(group_index) + "-";
    const auto local_boundary = [&](const Target &target, Fpk value) {
        return prove_local(key, program.masks(),
            local_query(group.layer, dims, true, group.output_point, target), value, pending, coin);
    };
    if (program.nodes().empty()) {
        observe_trace(group, basefold::Digest{}, coin);
        for (const auto &target : targets) proof.boundary_values.push_back(target.claim);
        observe_trace_values(proof, coin);
        for (std::size_t i = 0; i < targets.size(); ++i)
            proof.local_openings.push_back(local_boundary(targets[i], proof.boundary_values[i]));
        return proof;
    }

    proof.has_adjoint = true;
    const auto tau_msb = coin.challenge_vector(basefold::log2_exact(dims.internal_scalars));
    const auto tau_source = equality_source(reverse(tau_msb));
    proof.residual_evaluation = inner_product(z_source, tau_source, key.wide_resources.block_elements);
    targets.push_back({WideColumnTarget::Internal, tau_msb, proof.residual_evaluation});
    for (const auto &target : targets)
        proof.boundary_values.push_back(program.evaluate_output_column(
            group.output_point, target.kind, target.point_msb));
    observe_trace_values(proof, coin);
    const auto weights = coin.challenge_vector(targets.size());

    std::vector<fc::ScalarArray> columns;
    for (std::size_t i = 0; i < targets.size(); ++i) {
        auto column = fc::ScalarArray::create(scratch.path() / (prefix + "column-" + std::to_string(i)),
                                             dims.internal_scalars);
        program.build_internal_column(targets[i].kind, targets[i].point_msb,
            [&](std::size_t row, std::span<const Fpk> values) { column.write_block(row * dims.slots, values); });
        columns.push_back(std::move(column));
    }
    fc::ValueSource combined{dims.internal_scalars,
        [&columns, &weights](std::size_t offset, std::span<Fpk> out) {
            std::fill(out.begin(), out.end(), Fpk::zero());
            std::vector<Fpk> buffer(out.size());
            for (std::size_t i = 0; i < columns.size(); ++i) {
                columns[i].read_block(offset, buffer);
                for (std::size_t j = 0; j < out.size(); ++j) out[j] += weights[i] * buffer[j];
            }
        }};
    auto product = prove_quadratic_product(z_source, combined,
        combined_claim(targets, proof.boundary_values, weights), coin,
        scratch.child(prefix + "product"), key.wide_resources);
    const auto sigma_msb = reverse(product.reduction.point_lsb);
    const auto sigma_source = equality_source(product.reduction.point_lsb);
    for (const auto &column : columns)
        proof.terminal_values.push_back(inner_product(fc::source(column), sigma_source,
                                                     key.wide_resources.block_elements));
    observe_values("wide-gates/reverse-trace/local-terminals", proof.terminal_values, coin);
    if (combine(proof.terminal_values, weights) != product.reduction.right)
        throw std::logic_error("Wide reverse trace terminal disagreement");
    for (std::size_t i = 0; i < targets.size(); ++i)
        proof.local_openings.push_back(local_boundary(targets[i], proof.boundary_values[i]));
    for (std::size_t i = 0; i < targets.size(); ++i)
        proof.local_openings.push_back(prove_local(key, program.masks(),
            local_query(group.layer, dims, false, sigma_msb, targets[i]),
            proof.terminal_values[i], pending, coin));
    operands.push_back({block_offset, reverse(tau_msb)});
    operands.push_back({block_offset, product.reduction.point_lsb});
    values.push_back(proof.residual_evaluation);
    values.push_back(product.reduction.left);
    proof.product = std::move(product.proof);
    return proof;
}

bool verify_trace(const GateTableVerifierKey &key, const Group &group,
    const WideTraceOpeningProof &proof, std::vector<Pending> &pending,
    std::size_t block_offset, std::vector<fc::BlockOperand> &operands,
    std::vector<Fpk> &values, PublicCoin &coin) {
    const auto &metadata = layer_metadata(key.layout, group.layer);
    const auto &dims = metadata.dimensions;
    auto targets = group.targets;
    if (metadata.node_count == 0) {
        if (proof.has_adjoint || !proof.residual_evaluation.is_zero() ||
            !empty_product(proof.product) ||
            !proof.terminal_values.empty() || proof.boundary_values.size() != targets.size() ||
            proof.local_openings.size() != targets.size()) return false;
        observe_trace(group, basefold::Digest{}, coin);
        observe_trace_values(proof, coin);
        for (std::size_t i = 0; i < targets.size(); ++i)
            if (proof.boundary_values[i] != targets[i].claim ||
                !verify_local(key, local_query(group.layer, dims, true, group.output_point, targets[i]),
                    targets[i].claim, proof.local_openings[i], pending, coin)) return false;
        return true;
    }
    const auto count = targets.size() + 1;
    if (!proof.has_adjoint || proof.boundary_values.size() != count || proof.terminal_values.size() != count ||
        proof.local_openings.size() != 2 * count) return false;
    const auto variables = basefold::log2_exact(dims.internal_scalars);
    const auto tau_msb = coin.challenge_vector(variables);
    targets.push_back({WideColumnTarget::Internal, tau_msb, proof.residual_evaluation});
    observe_trace_values(proof, coin);
    const auto weights = coin.challenge_vector(count);
    const auto product = verify_quadratic_product(variables,
        combined_claim(targets, proof.boundary_values, weights), proof.product, coin);
    if (!product || combine(proof.terminal_values, weights) != product->right) return false;
    observe_values("wide-gates/reverse-trace/local-terminals", proof.terminal_values, coin);
    const auto sigma_msb = reverse(product->point_lsb);
    for (std::size_t i = 0; i < count; ++i)
        if (!verify_local(key, local_query(group.layer, dims, true, group.output_point, targets[i]),
            proof.boundary_values[i], proof.local_openings[i], pending, coin)) return false;
    for (std::size_t i = 0; i < count; ++i)
        if (!verify_local(key, local_query(group.layer, dims, false, sigma_msb, targets[i]),
            proof.terminal_values[i], proof.local_openings[count + i], pending, coin)) return false;
    operands.push_back({block_offset, reverse(tau_msb)});
    operands.push_back({block_offset, product->point_lsb});
    values.push_back(proof.residual_evaluation);
    values.push_back(product->left);
    return true;
}

} // namespace

std::vector<WideAdjointGroupLayout> wide_adjoint_group_layout(
    std::span<const std::size_t> sizes) {
    std::vector<WideAdjointGroupLayout> result;
    std::vector<bool> used(sizes.size(), false);
    for (std::size_t i = 0; i < sizes.size(); ++i) {
        if (used[i] || sizes[i] == 0) continue;
        const auto m = sizes[i];
        if (!std::has_single_bit(m) || basefold::log2_exact(m) > fc::kMaxVariables)
            throw std::invalid_argument("Wide adjoint block shape");
        const auto maximum_members = std::min<std::size_t>(4,
            std::max<std::size_t>(1, (std::size_t{1} << 32) / m));
        std::vector<std::size_t> candidates;
        for (std::size_t j = i; j < sizes.size() && candidates.size() < maximum_members; ++j)
            if (!used[j] && sizes[j] == m) candidates.push_back(j);
        candidates.resize(std::bit_floor(candidates.size()));
        for (const auto j : candidates) used[j] = true;
        const auto message_size = m * candidates.size();
        result.push_back({std::move(candidates), m, message_size});
    }
    return result;
}

std::size_t wide_public_operands_per_request(
    const SparseTableCommitment &table, const fc::Metadata &metadata) {
    if (!fc::valid_shape(metadata) || !table.wide_block_offset ||
        !std::has_single_bit(table.message_size) ||
        !std::has_single_bit(table.physical_width) || table.physical_width > 256 ||
        table.message_size > metadata.m ||
        table.message_size > std::numeric_limits<std::size_t>::max() / table.physical_width ||
        metadata.m > std::numeric_limits<std::size_t>::max() / metadata.width)
        throw std::invalid_argument("Wide public table has invalid honest-column shape");
    const auto cells = table.message_size * table.physical_width;
    const auto capacity = metadata.m * metadata.width;
    if (*table.wide_block_offset % cells != 0 ||
        *table.wide_block_offset > capacity || cells > capacity - *table.wide_block_offset)
        throw std::invalid_argument("Wide public table exceeds its honest-column index");
    return std::min(table.physical_width, metadata.m / table.message_size);
}

WideGateOpeningProof prove_wide_gate_opening(
    const payload::LayeredCircuit &circuit, const GateTableProverKey &key,
    std::span<const RecordedGateQuery> queries, std::span<const Fpk> values,
    PublicCoin &coin) {
    const auto groups = group_queries(key.verifier.layout, queries, values);
    const auto sizes = trace_sizes(key.verifier.layout, groups);
    const auto layout = wide_adjoint_group_layout(sizes);
    admit_opening(key, groups, layout);
    coin.observe("wide-gates/consolidated/v3", groups.size());
    const auto dictionary = WideMaskDictionary::build(circuit);
    ScratchDirectory scratch(key.wide_scratch_parent);
    WideGateOpeningProof proof;
    proof.traces.resize(groups.size());
    std::vector<Pending> pending;
    auto program_for = [&](std::size_t index) {
        auto program = WideProgram::build(circuit, groups[index].layer, dictionary);
        if (program.digest() != layer_metadata(key.verifier.layout,
                                               groups[index].layer).program_digest)
            throw std::invalid_argument("Wide opening: program does not match setup");
        return program;
    };
    // Boundary-only traces need no witness commitment.
    for (std::size_t i = 0; i < groups.size(); ++i) {
        if (sizes[i]) continue;
        std::vector<fc::BlockOperand> operands;
        std::vector<Fpk> targets;
        proof.traces[i] = prove_trace(key, program_for(i), groups[i], i,
            scratch, pending, {}, 0, operands, targets, coin);
    }
    for (const auto &batch : layout) {
        // Every large artifact closes before the next batch is built.
        ScratchDirectory batch_scratch(scratch.path());
        auto z = fc::ScalarArray::create(batch_scratch.path() / "adjoints", batch.message_size);
        for (std::size_t member = 0; member < batch.trace_indices.size(); ++member) {
            const auto index = batch.trace_indices[member];
            const auto program = program_for(index);
            const auto offset = member * batch.block_size;
            const auto slots = program.dimensions().slots;
            program.compute_reverse(groups[index].output_point,
                [&](std::size_t row, std::span<Fpk> out) {
                    z.read_block(offset + row * slots, out);
                },
                [&](std::size_t row, std::span<const Fpk> out) {
                    z.write_block(offset + row * slots, out);
                });
        }
        const std::array<fc::ValueSource, 1> source{fc::source(z)};
        const auto committed = fc::commit(source, batch_scratch.child("commit"), key.wide_resources);
        observe_group(batch, groups, committed.metadata.root, coin);
        std::vector<fc::BlockOperand> operands;
        std::vector<Fpk> targets;
        for (std::size_t member = 0; member < batch.trace_indices.size(); ++member) {
            const auto index = batch.trace_indices[member];
            const auto offset = member * batch.block_size;
            const auto local_z = slice_source(source.front(), offset, batch.block_size);
            proof.traces[index] = prove_trace(key, program_for(index), groups[index], index,
                batch_scratch, pending, local_z, offset, operands, targets, coin);
        }
        const std::array<Fpk, 1> one{Fpk::one()};
        auto pcs = fc::prove_blocks(committed, operands, one, targets, coin,
            batch_scratch.child("pcs"), fc::CommitmentPremise::ArbitrarySingleColumn,
            key.verifier.foldable_parameters, key.wide_resources);
        proof.adjoint_groups.push_back({committed.metadata.root, std::move(pcs.proof)});
    }
    prove_public_tables(key, pending, proof, scratch, coin);
    return proof;
}

bool verify_wide_gate_opening(
    const GateTableVerifierKey &key, std::span<const RecordedGateQuery> queries,
    std::span<const Fpk> values, const WideGateOpeningProof &proof, PublicCoin &coin) {
    try {
        if (!valid_wide_public_index(key)) return false;
        const auto groups = group_queries(key.layout, queries, values);
        const auto sizes = trace_sizes(key.layout, groups);
        const auto layout = wide_adjoint_group_layout(sizes);
        if (proof.traces.size() != groups.size() || proof.adjoint_groups.size() != layout.size()) return false;
        coin.observe("wide-gates/consolidated/v3", groups.size());
        std::vector<Pending> pending;
        for (std::size_t i = 0; i < groups.size(); ++i) {
            if (sizes[i]) continue;
            std::vector<fc::BlockOperand> operands;
            std::vector<Fpk> targets;
            if (!verify_trace(key, groups[i], proof.traces[i], pending,
                              0, operands, targets, coin)) return false;
        }
        for (std::size_t b = 0; b < layout.size(); ++b) {
            const auto &batch = layout[b];
            const auto &group_proof = proof.adjoint_groups[b];
            observe_group(batch, groups, group_proof.root, coin);
            std::vector<fc::BlockOperand> operands;
            std::vector<Fpk> targets;
            for (std::size_t member = 0; member < batch.trace_indices.size(); ++member) {
                const auto index = batch.trace_indices[member];
                if (!verify_trace(key, groups[index], proof.traces[index], pending,
                    member * batch.block_size, operands, targets, coin)) return false;
            }
            const std::array<Fpk, 1> one{Fpk::one()};
            if (!fc::verify_blocks({group_proof.root, batch.message_size, 1},
                operands, one, targets, group_proof.opening, coin,
                fc::CommitmentPremise::ArbitrarySingleColumn,
                key.foldable_parameters)) return false;
        }
        return verify_public_tables(key, pending, proof, coin);
    } catch (const std::exception &) {
        return false;
    }
}

} // namespace laminate::gates
