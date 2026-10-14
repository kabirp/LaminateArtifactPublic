#include "laminate/gates/wide_program.hpp"

#include "laminate/fhe/layout/slot_grid.hpp"
#include "laminate/poly/eq.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <limits>
#include <map>
#include <stdexcept>
#include <string_view>
#include <tuple>
#include <utility>

namespace laminate::gates {
namespace {

std::size_t product(std::size_t a, std::size_t b) {
    if (b && a > std::numeric_limits<std::size_t>::max() / b)
        throw std::overflow_error("WideProgram: domain size overflow");
    return a * b;
}
std::size_t padded(std::size_t count) {
    count = std::max(std::size_t{1}, count);
    if (count >
        (std::size_t{1} << (std::numeric_limits<std::size_t>::digits - 1)))
        throw std::overflow_error("WideProgram: padded width overflow");
    return std::bit_ceil(count);
}
void integer(Sha256Hasher &hash, std::size_t value) {
    std::array<std::uint8_t, 8> bytes{};
    for (std::size_t i = 0; i < bytes.size(); ++i)
        bytes[i] = static_cast<std::uint8_t>(value >> (8 * i));
    hash.update(bytes);
}
void tag(Sha256Hasher &hash, std::string_view text) {
    integer(hash, text.size());
    hash.update(
        {reinterpret_cast<const std::uint8_t *>(text.data()), text.size()});
}
void hash_slots(Sha256Hasher &hash, std::span<const Fp> slots) {
    integer(hash, slots.size());
    for (const auto &value : slots)
        integer(hash, value.value());
}
std::optional<Fp> uniform(std::span<const Fp> values) {
    if (values.empty())
        throw std::invalid_argument("WideProgram: empty mask");
    if (std::all_of(values.begin(), values.end(),
                    [&](const Fp &v) { return v == values.front(); }))
        return values.front();
    return std::nullopt;
}
payload::AffineConstant normalize_constant(const payload::AffineConstant &value,
                                           std::size_t slots) {
    if (const auto *scalar = std::get_if<Fp>(&value))
        return *scalar;
    const auto &vector = std::get<fhe::SlotVector>(value);
    if (vector.size() != slots)
        throw std::invalid_argument("WideProgram: constant width mismatch");
    if (const auto scalar = uniform(vector))
        return *scalar;
    return vector;
}
Fp constant_at(const payload::AffineConstant &constant, std::size_t slot) {
    if (const auto *scalar = std::get_if<Fp>(&constant))
        return *scalar;
    return std::get<fhe::SlotVector>(constant)[slot];
}
void hash_node(Sha256Hasher &hash, const WideProgramNode &node) {
    integer(hash, node.terms.size());
    for (const auto &term : node.terms) {
        integer(hash, static_cast<std::size_t>(term.source_block));
        integer(hash, term.source);
        integer(hash, term.rotation);
        integer(hash, term.coefficient.value());
        integer(hash, term.mask.has_value());
        if (term.mask)
            integer(hash, *term.mask);
    }
    integer(hash, node.constant.index());
    if (const auto *scalar = std::get_if<Fp>(&node.constant))
        integer(hash, scalar->value());
    else
        hash_slots(hash, std::get<fhe::SlotVector>(node.constant));
}
Fpk index_weight(std::span<const Fpk> point, std::size_t index) {
    Fpk result = Fpk::one();
    for (std::size_t i = 0; i < point.size(); ++i)
        result *= ((index >> (point.size() - 1 - i)) & 1)
                      ? point[i]
                      : Fpk::one() - point[i];
    return result;
}
struct Point {
    std::span<const Fpk> wire;
    std::vector<Fpk> slot;
};
Point split_point(std::span<const Fpk> point, std::size_t wires,
                  std::size_t slots) {
    const std::size_t wire_bits = std::countr_zero(wires);
    const std::size_t slot_bits = std::countr_zero(slots);
    if (point.size() != wire_bits + slot_bits)
        throw std::invalid_argument(
            "WideProgram: evaluation point dimension mismatch");
    const auto slot_point = point.subspan(wire_bits);
    return {point.first(wire_bits), poly::eq_evaluations(std::vector<Fpk>(
                                        slot_point.begin(), slot_point.end()))};
}
Point target_point(const WideProgramDimensions &d, WideColumnTarget target,
                   std::span<const Fpk> point) {
    switch (target) {
    case WideColumnTarget::Input:
        return split_point(point, d.input_width, d.slots);
    case WideColumnTarget::Internal:
        return split_point(point, d.internal_width, d.slots);
    case WideColumnTarget::Constant:
        if (!point.empty())
            throw std::invalid_argument(
                "WideProgram: constant target point must be empty");
        return {};
    }
    throw std::invalid_argument("WideProgram: invalid column target");
}
void column_row(const WideProgramNode &node, const WideMaskDictionary &masks,
                WideColumnTarget target, const Point &point,
                std::span<Fpk> result) {
    std::fill(result.begin(), result.end(), Fpk::zero());
    if (target == WideColumnTarget::Constant) {
        for (std::size_t slot = 0; slot < result.size(); ++slot)
            result[slot] = Fpk::from_base(constant_at(node.constant, slot));
        return;
    }
    const auto block = target == WideColumnTarget::Input
                           ? WideSourceBlock::Input
                           : WideSourceBlock::Internal;
    for (const auto &term : node.terms) {
        if (term.source_block != block)
            continue;
        const Fpk wire_weight =
            index_weight(point.wire, term.source) * term.coefficient;
        for (std::size_t slot = 0; slot < result.size(); ++slot) {
            Fpk value =
                wire_weight *
                point
                    .slot[fhe::grid_source(result.size(), term.rotation, slot)];
            if (term.mask)
                value = value * masks.masks()[*term.mask][slot];
            result[slot] += value;
        }
    }
}

// This is a resource/representation fallback, never an invalid-circuit error.
struct CompositionFallback {};

class BoundaryComposer {
  public:
    BoundaryComposer(const WideMaskDictionary &masks,
                     WideProgramCompositionLimits limits)
        : masks_(masks), limits_(limits) {}

    std::optional<std::vector<WideProgramNode>>
    compose(std::span<const WideProgramNode> nodes,
            std::span<const WideProgramNode> outputs) {
        if (!limits_.max_row_terms || !limits_.max_retained_terms ||
            !limits_.max_work || !limits_.max_constant_scalars)
            return std::nullopt;
        try {
            rows_.reserve(nodes.size());
            for (const auto &node : nodes)
                rows_.push_back(expand(node));
            std::vector<WideProgramNode> boundary;
            boundary.reserve(outputs.size());
            for (const auto &output : outputs)
                boundary.push_back(expand(output));
            return boundary;
        } catch (const CompositionFallback &) {
            return std::nullopt;
        }
    }

  private:
    using Address =
        std::tuple<std::size_t, std::size_t, std::optional<std::size_t>>;

    void charge(std::size_t amount) {
        if (amount > limits_.max_work - work_)
            throw CompositionFallback{};
        work_ += amount;
    }

    void charge_constant_storage(std::size_t amount) {
        if (amount > limits_.max_constant_scalars - constant_scalars_)
            throw CompositionFallback{};
        constant_scalars_ += amount;
    }

    void add_constant(payload::AffineConstant &destination,
                      const payload::AffineConstant &source,
                      const WideProgramTerm &action) {
        const auto *scalar = std::get_if<Fp>(&source);
        if (scalar && scalar->is_zero())
            return;
        if (scalar && !action.mask) {
            if (auto *target = std::get_if<Fp>(&destination)) {
                charge(1);
                *target += *scalar * action.coefficient;
                return;
            }
        }
        if (auto *target = std::get_if<Fp>(&destination)) {
            charge(masks_.slots());
            charge_constant_storage(masks_.slots());
            destination = fhe::SlotVector(masks_.slots(), *target);
        }
        charge(masks_.slots());
        auto &target = std::get<fhe::SlotVector>(destination);
        for (std::size_t slot = 0; slot < target.size(); ++slot) {
            Fp value = constant_at(
                source, fhe::grid_source(target.size(), action.rotation, slot));
            value *= action.coefficient;
            if (action.mask)
                value *= masks_.masks()[*action.mask][slot];
            target[slot] += value;
        }
    }

    WideProgramNode expand(const WideProgramNode &node) {
        WideProgramNode result;
        if (const auto *scalar = std::get_if<Fp>(&node.constant)) {
            result.constant = *scalar;
        } else {
            charge(masks_.slots());
            charge_constant_storage(masks_.slots());
            result.constant = node.constant;
        }
        std::map<Address, Fp> terms;
        const auto insert = [&](const WideProgramTerm &outer,
                                const WideProgramTerm &inner) {
            charge(1);
            // Reuse only the existing operator dictionary. Rotations compose
            // in BGV's two-row group; mixed/multiple masks require the DAG.
            if ((outer.mask && (inner.mask || inner.rotation)) ||
                (outer.rotation && inner.mask))
                throw CompositionFallback{};
            const std::size_t rotation = fhe::grid_compose(
                masks_.slots(), outer.rotation, inner.rotation);
            const auto mask = outer.mask ? outer.mask : inner.mask;
            const Address address{inner.source, rotation, mask};
            const Fp contribution = outer.coefficient * inner.coefficient;
            if (contribution.is_zero())
                return;
            const auto found = terms.find(address);
            if (found == terms.end()) {
                if (terms.size() >= limits_.max_row_terms ||
                    terms.size() >= limits_.max_retained_terms - retained_terms_)
                    throw CompositionFallback{};
                terms.emplace(address, contribution);
            } else {
                found->second += contribution;
                if (found->second.is_zero())
                    terms.erase(found);
            }
        };
        const WideProgramTerm identity{.coefficient = Fp::one()};
        for (const auto &term : node.terms) {
            charge(1);
            if (term.source_block == WideSourceBlock::Input) {
                insert(identity, term);
            } else {
                const auto &source = rows_.at(term.source);
                for (const auto &inner : source.terms)
                    insert(term, inner);
                add_constant(result.constant, source.constant, term);
            }
        }
        if (const auto *slots = std::get_if<fhe::SlotVector>(&result.constant)) {
            charge(slots->size());
            if (const auto scalar = uniform(*slots)) {
                constant_scalars_ -= slots->size();
                result.constant = *scalar;
            }
        }
        retained_terms_ += terms.size();
        result.terms.reserve(terms.size());
        for (const auto &[address, coefficient] : terms) {
            const auto &[source, rotation, mask] = address;
            result.terms.push_back({WideSourceBlock::Input, source, rotation,
                                    coefficient, mask});
        }
        return result;
    }

    const WideMaskDictionary &masks_;
    WideProgramCompositionLimits limits_;
    std::size_t work_ = 0;
    std::size_t retained_terms_ = 0;
    std::size_t constant_scalars_ = 0;
    std::vector<WideProgramNode> rows_;
};
} // namespace

std::uint64_t wide_program_composition_workspace_bound(
    const payload::LayeredCircuit &circuit,
    WideProgramCompositionLimits limits) {
    if (circuit.shape.kind != payload::PayloadKind::Wide)
        return 0;
    const auto add = [](std::uint64_t a, std::uint64_t b) {
        if (b > std::numeric_limits<std::uint64_t>::max() - a)
            throw std::overflow_error("WideProgram: workspace bound overflow");
        return a + b;
    };
    const auto mul = [](std::uint64_t a, std::uint64_t b) {
        if (b && a > std::numeric_limits<std::uint64_t>::max() / b)
            throw std::overflow_error("WideProgram: workspace bound overflow");
        return a * b;
    };
    // Saturating products are used only underneath an explicit policy cap.
    const auto capped_product = [](std::uint64_t a, std::uint64_t b,
                                   std::uint64_t cap) {
        return b && a > cap / b ? cap : std::min(cap, a * b);
    };
    const bool compose = limits.max_row_terms && limits.max_retained_terms &&
                         limits.max_work && limits.max_constant_scalars;
    std::uint64_t dictionary = mul(circuit.plaintexts.size(), 512);
    for (const auto &plaintext : circuit.plaintexts)
        dictionary = add(dictionary, mul(plaintext.size(), sizeof(Fp)));
    std::uint64_t maximum = 0;
    for (std::size_t layer_index = 0;
         layer_index + 1 < circuit.layers.size(); ++layer_index) {
        const auto *layer =
            std::get_if<payload::AffineLayer>(&circuit.layers[layer_index]);
        if (!layer) continue;
        std::uint64_t terms = 0, split_nodes = 0, constants = 0;
        const auto count = [&](const auto &rows) {
            for (const auto &row : rows) {
                terms = add(terms, row.terms.size());
                for (const auto &term : row.terms)
                    if (term.rotation && term.plaintext_index)
                        split_nodes = add(split_nodes, 1);
                if (const auto *slots =
                        std::get_if<fhe::SlotVector>(&row.constant))
                    constants = add(constants, slots->size());
            }
        };
        count(layer->intermediate_gates);
        count(layer->gates);
        const auto nodes = add(layer->intermediate_gates.size(), split_nodes);
        const auto rows = add(nodes, layer->gates.size());
        // Exact reserves below avoid geometric vector growth. A factor of two
        // on payload and 64 bytes per allocation cover capacity and allocator
        // rounding; headers also cover the remap and plaintext-check vectors.
        auto bytes = mul(rows, 2 * sizeof(WideProgramNode) + 128);
        bytes = add(bytes, mul(add(terms, split_nodes),
                               2 * sizeof(WideProgramTerm)));
        bytes = add(bytes, mul(constants, 2 * sizeof(Fp)));
        bytes = add(bytes, mul(layer->intermediate_gates.size(), sizeof(std::size_t)));
        bytes = add(bytes, add(circuit.plaintexts.size(), 64));
        if (compose && nodes) {
            const auto cap = std::min(limits.max_retained_terms, limits.max_work);
            const auto row_cap = std::min<std::uint64_t>(limits.max_row_terms, cap);
            // A supported boundary term has one input and either one rotation
            // or one existing mask. Unsupported products immediately fall back.
            const auto actions = add(circuit.shape.slot_count,
                                     circuit.plaintexts.size());
            const auto inputs = payload::layer_dimensions(
                circuit.layers[layer_index + 1]).padded_size;
            const auto row_terms = capped_product(inputs, actions, row_cap);
            const auto retained = capped_product(rows, row_terms, cap);
            const auto constant_count = capped_product(rows, circuit.shape.slot_count,
                                                       limits.max_constant_scalars);
            bytes = add(bytes, mul(rows, sizeof(WideProgramNode) + 64));
            bytes = add(bytes, mul(retained, 2 * sizeof(WideProgramTerm)));
            // One std::map exists during expansion, concurrently with the
            // result vector. 128 bytes covers its key/value, tree and allocator.
            bytes = add(bytes, mul(row_terms, 128));
            bytes = add(bytes, mul(constant_count, 2 * sizeof(Fp)));
        }
        maximum = std::max(maximum, bytes);
    }
    return add(dictionary, maximum);
}

std::shared_ptr<const WideMaskDictionary>
WideMaskDictionary::build(const payload::LayeredCircuit &circuit) {
    circuit.shape.validate();
    if (circuit.shape.kind != payload::PayloadKind::Wide)
        throw std::invalid_argument(
            "WideMaskDictionary: Wide circuit required");
    auto result = std::make_shared<WideMaskDictionary>();
    result->slots_ = circuit.shape.slot_count;
    result->plaintext_masks_.resize(circuit.plaintexts.size());
    result->plaintext_scalars_.resize(circuit.plaintexts.size());
    std::vector<bool> used(circuit.plaintexts.size(), false);
    for (const auto &layer_variant : circuit.layers) {
        if (const auto *layer =
                std::get_if<payload::AffineLayer>(&layer_variant)) {
            const auto collect = [&](const auto &gates) {
                for (const auto &gate : gates)
                    for (const auto &term : gate.terms)
                        if (term.plaintext_index) {
                            if (*term.plaintext_index >= used.size())
                                throw std::invalid_argument(
                                    "WideMaskDictionary: plaintext index out of range");
                            used[*term.plaintext_index] = true;
                        }
            };
            collect(layer->intermediate_gates);
            collect(layer->gates);
        }
    }
    std::map<Digest, std::vector<std::size_t>> hashes;
    for (std::size_t i = 0; i < used.size(); ++i) {
        if (!used[i])
            continue;
        const auto &mask = circuit.plaintexts[i];
        if (mask.size() != result->slots_)
            throw std::invalid_argument(
                "WideMaskDictionary: plaintext width mismatch");
        if (const auto scalar = uniform(mask)) {
            result->plaintext_scalars_[i] = *scalar;
            continue;
        }
        Sha256Hasher hash;
        hash_slots(hash, mask);
        auto &candidates = hashes[hash.finish()];
        auto match = std::find_if(
            candidates.begin(), candidates.end(),
            [&](std::size_t index) { return result->masks_[index] == mask; });
        if (match != candidates.end())
            result->plaintext_masks_[i] = *match;
        else {
            result->plaintext_masks_[i] = result->masks_.size();
            candidates.push_back(result->masks_.size());
            result->masks_.push_back(mask);
        }
    }
    result->padded_size_ = padded(result->masks_.size());
    (void)product(result->padded_size_, result->slots_);
    Sha256Hasher hash;
    tag(hash, "laminate/wide-mask-dictionary/v1");
    integer(hash, result->slots_);
    integer(hash, result->padded_size_);
    integer(hash, result->masks_.size());
    for (const auto &mask : result->masks_)
        hash_slots(hash, mask);
    result->digest_ = hash.finish();
    return result;
}

void WideMaskDictionary::visit_entries(
    const std::function<void(const sparse::SparseEntry &)> &visit) const {
    for (std::size_t mask = 0; mask < masks_.size(); ++mask)
        for (std::size_t slot = 0; slot < slots_; ++slot)
            if (!masks_[mask][slot].is_zero())
                visit({mask * slots_ + slot, masks_[mask][slot]});
}

WideProgram
WideProgram::build(const payload::LayeredCircuit &circuit,
                   std::size_t layer_index,
                   std::shared_ptr<const WideMaskDictionary> masks,
                   WideProgramCompositionLimits limits) {
    circuit.shape.validate();
    if (circuit.shape.kind != payload::PayloadKind::Wide || !masks ||
        masks->slots_ != circuit.shape.slot_count ||
        masks->plaintext_masks_.size() != circuit.plaintexts.size() ||
        layer_index >= circuit.layers.size() ||
        layer_index + 1 >= circuit.layers.size())
        throw std::invalid_argument(
            "WideProgram: invalid circuit, layer, or mask dictionary");
    const auto *layer =
        std::get_if<payload::AffineLayer>(&circuit.layers[layer_index]);
    if (!layer)
        throw std::invalid_argument("WideProgram: affine layer required");
    WideProgram result;
    result.layer_index_ = layer_index;
    result.masks_ = std::move(masks);
    auto &d = result.dimensions_;
    d.slots = circuit.shape.slot_count;
    d.input_width =
        payload::layer_dimensions(circuit.layers[layer_index + 1]).padded_size;
    d.output_width = layer->dimensions.padded_size;
    if (!std::has_single_bit(d.input_width) ||
        !std::has_single_bit(d.output_width) ||
        layer->gates.size() != d.output_width)
        throw std::invalid_argument("WideProgram: invalid layer dimensions");
    std::size_t split_node_bound = 0;
    const auto count_splits = [&](const auto &rows) {
        for (const auto &row : rows)
            for (const auto &term : row.terms)
                if (term.rotation && term.plaintext_index) {
                    if (split_node_bound == std::numeric_limits<std::size_t>::max())
                        throw std::overflow_error("WideProgram: node count overflow");
                    ++split_node_bound;
                }
    };
    count_splits(layer->intermediate_gates);
    count_splits(layer->gates);
    if (split_node_bound > std::numeric_limits<std::size_t>::max() -
                               layer->intermediate_gates.size())
        throw std::overflow_error("WideProgram: node count overflow");
    result.nodes_.reserve(layer->intermediate_gates.size() + split_node_bound);
    result.outputs_.reserve(layer->gates.size());
    std::vector<std::size_t> remap;
    remap.reserve(layer->intermediate_gates.size());
    std::vector<bool> checked(circuit.plaintexts.size(), false);
    const auto normalize = [&](const payload::AffineGate &gate) {
        WideProgramNode node;
        node.terms.reserve(gate.terms.size());
        node.constant = normalize_constant(gate.constant, d.slots);
        for (const auto &original : gate.terms) {
            WideProgramTerm term;
            if (original.source < d.input_width)
                term.source = original.source;
            else {
                const std::size_t intermediate =
                    original.source - d.input_width;
                if (intermediate >= remap.size())
                    throw std::invalid_argument(
                        "WideProgram: non-topological affine source");
                term.source_block = WideSourceBlock::Internal;
                term.source = remap[intermediate];
            }
            if (original.rotation >= d.slots)
                throw std::invalid_argument(
                    "WideProgram: noncanonical rotation");
            term.rotation = original.rotation;
            term.coefficient = original.coefficient;
            if (original.plaintext_index) {
                const std::size_t index = *original.plaintext_index;
                if (index >= checked.size())
                    throw std::invalid_argument(
                        "WideProgram: plaintext index out of range");
                const auto scalar = result.masks_->plaintext_scalars_[index];
                term.mask = result.masks_->plaintext_masks_[index];
                if (!scalar && !term.mask)
                    throw std::invalid_argument(
                        "WideProgram: dictionary does not cover plaintext");
                if (!checked[index]) {
                    const auto &plaintext = circuit.plaintexts[index];
                    if (plaintext.size() != d.slots ||
                        (scalar && uniform(plaintext) != scalar) ||
                        (term.mask &&
                         plaintext != result.masks_->masks_[*term.mask]))
                        throw std::invalid_argument(
                            "WideProgram: mask dictionary belongs to another circuit");
                    checked[index] = true;
                }
                if (scalar)
                    term.coefficient *= *scalar;
            }
            if (term.coefficient.is_zero())
                continue;
            if (term.mask && term.rotation != 0) {
                WideProgramTerm rotation = term;
                rotation.mask.reset();
                rotation.coefficient = Fp::one();
                const std::size_t index = result.nodes_.size();
                result.nodes_.push_back({{rotation}, Fp::zero()});
                term.source_block = WideSourceBlock::Internal;
                term.source = index;
                term.rotation = 0;
            }
            node.terms.push_back(term);
        }
        return node;
    };
    for (const auto &gate : layer->intermediate_gates) {
        auto node = normalize(gate);
        remap.push_back(result.nodes_.size());
        result.nodes_.push_back(std::move(node));
    }
    for (const auto &gate : layer->gates)
        result.outputs_.push_back(normalize(gate));
    bool composed = false;
    if (!result.nodes_.empty()) {
        if (auto boundary = BoundaryComposer(*result.masks_, limits).compose(
                result.nodes_, result.outputs_)) {
            result.outputs_ = std::move(*boundary);
            result.nodes_.clear();
            composed = true;
        }
    }
    d.internal_width = padded(result.nodes_.size());
    d.row_width = std::max(d.internal_width, d.output_width);
    d.source_width = std::max(d.internal_width, d.input_width);
    d.mask_width = result.masks_->padded_size();
    d.internal_scalars = product(d.internal_width, d.slots);
    const std::size_t rows = product(2, d.row_width);
    const std::size_t sources = product(2, d.source_width);
    d.uniform_edge_domain = product(product(rows, sources), d.slots);
    d.mask_edge_domain = product(product(rows, sources), d.mask_width);
    d.uniform_constant_domain = rows;
    d.slot_constant_domain = product(rows, d.slots);
    d.dictionary_domain = product(d.mask_width, d.slots);
    Sha256Hasher hash;
    tag(hash, "laminate/wide-local-affine-program/v2");
    integer(hash, limits.max_row_terms);
    integer(hash, limits.max_retained_terms);
    integer(hash, limits.max_work);
    integer(hash, limits.max_constant_scalars);
    integer(hash, composed);
    integer(hash, layer_index);
    integer(hash, d.slots);
    integer(hash, d.input_width);
    integer(hash, d.output_width);
    integer(hash, d.internal_width);
    integer(hash, d.row_width);
    integer(hash, d.source_width);
    integer(hash, d.mask_width);
    hash.update(result.masks_->digest());
    integer(hash, result.nodes_.size());
    for (const auto &node : result.nodes_)
        hash_node(hash, node);
    integer(hash, result.outputs_.size());
    for (const auto &node : result.outputs_)
        hash_node(hash, node);
    result.digest_ = hash.finish();
    return result;
}

void WideProgram::visit_entries(
    WidePublicTable table,
    const std::function<void(const sparse::SparseEntry &)> &visit) const {
    const auto visit_rows = [&](std::span<const WideProgramNode> rows,
                                std::size_t offset) {
        for (std::size_t index = 0; index < rows.size(); ++index) {
            const auto &node = rows[index];
            const std::size_t row = offset + index;
            if (table == WidePublicTable::UniformConstants) {
                if (const auto *scalar = std::get_if<Fp>(&node.constant);
                    scalar && !scalar->is_zero())
                    visit({row, *scalar});
            } else if (table == WidePublicTable::SlotConstants) {
                if (const auto *slots =
                        std::get_if<fhe::SlotVector>(&node.constant))
                    for (std::size_t slot = 0; slot < slots->size(); ++slot)
                        if (!(*slots)[slot].is_zero())
                            visit({row * dimensions_.slots + slot,
                                   (*slots)[slot]});
            } else {
                const bool masked = table == WidePublicTable::MaskEdges;
                const std::size_t actions =
                    masked ? dimensions_.mask_width : dimensions_.slots;
                std::map<std::size_t, Fp> entries;
                for (const auto &term : node.terms) {
                    if (term.mask.has_value() != masked)
                        continue;
                    const std::size_t source =
                        static_cast<std::size_t>(term.source_block) *
                            dimensions_.source_width +
                        term.source;
                    const std::size_t action =
                        masked ? *term.mask : term.rotation;
                    const std::size_t address =
                        (row * 2 * dimensions_.source_width + source) *
                            actions +
                        action;
                    entries[address] += term.coefficient;
                }
                for (const auto &[address, value] : entries)
                    if (!value.is_zero())
                        visit({address, value});
            }
        }
    };
    if (table != WidePublicTable::UniformEdges &&
        table != WidePublicTable::MaskEdges &&
        table != WidePublicTable::UniformConstants &&
        table != WidePublicTable::SlotConstants)
        throw std::invalid_argument("WideProgram: invalid public table");
    visit_rows(nodes_, 0);
    visit_rows(outputs_, dimensions_.row_width);
}

void WideProgram::apply_forward(const WideRowReader &read_input,
                                const WideRowReader &read_internal,
                                const WideRowWriter &write_internal,
                                const WideRowWriter &write_output) const {
    std::vector<Fpk> result(dimensions_.slots), source(dimensions_.slots);
    const auto evaluate = [&](const WideProgramNode &node) {
        for (std::size_t slot = 0; slot < result.size(); ++slot)
            result[slot] = Fpk::from_base(constant_at(node.constant, slot));
        for (const auto &term : node.terms) {
            (term.source_block == WideSourceBlock::Input
                 ? read_input
                 : read_internal)(term.source, source);
            for (std::size_t slot = 0; slot < result.size(); ++slot) {
                Fpk value = source[fhe::grid_source(result.size(),
                                                    term.rotation, slot)] *
                            term.coefficient;
                if (term.mask)
                    value = value * masks_->masks()[*term.mask][slot];
                result[slot] += value;
            }
        }
    };
    for (std::size_t node = 0; node < nodes_.size(); ++node) {
        evaluate(nodes_[node]);
        write_internal(node, result);
    }
    std::fill(result.begin(), result.end(), Fpk::zero());
    for (std::size_t node = nodes_.size(); node < dimensions_.internal_width;
         ++node)
        write_internal(node, result);
    for (std::size_t output = 0; output < outputs_.size(); ++output) {
        evaluate(outputs_[output]);
        write_output(output, result);
    }
}

void WideProgram::compute_reverse(std::span<const Fpk> output_point_msb,
                                  const WideRowReader &read_internal,
                                  const WideRowWriter &write_internal) const {
    const auto output_point = split_point(
        output_point_msb, dimensions_.output_width, dimensions_.slots);
    std::vector<Fpk> adjoint(dimensions_.slots, Fpk::zero()),
        source(dimensions_.slots);
    for (std::size_t node = 0; node < dimensions_.internal_width; ++node)
        write_internal(node, adjoint);
    const auto propagate = [&](const WideProgramNode &node) {
        for (const auto &term : node.terms) {
            if (term.source_block != WideSourceBlock::Internal)
                continue;
            read_internal(term.source, source);
            for (std::size_t slot = 0; slot < adjoint.size(); ++slot) {
                Fpk value = adjoint[slot] * term.coefficient;
                if (term.mask)
                    value = value * masks_->masks()[*term.mask][slot];
                source[fhe::grid_source(adjoint.size(), term.rotation, slot)] +=
                    value;
            }
            write_internal(term.source, source);
        }
    };
    for (std::size_t output = 0; output < outputs_.size(); ++output) {
        if (std::none_of(
                outputs_[output].terms.begin(), outputs_[output].terms.end(),
                [](const WideProgramTerm &term) {
                    return term.source_block == WideSourceBlock::Internal;
                }))
            continue;
        const Fpk wire = index_weight(output_point.wire, output);
        for (std::size_t slot = 0; slot < adjoint.size(); ++slot)
            adjoint[slot] = wire * output_point.slot[slot];
        propagate(outputs_[output]);
    }
    for (std::size_t index = nodes_.size(); index > 0; --index) {
        read_internal(index - 1, adjoint);
        propagate(nodes_[index - 1]);
    }
}

void WideProgram::build_internal_column(WideColumnTarget target,
                                        std::span<const Fpk> target_point_msb,
                                        const WideRowWriter &write_row) const {
    const auto point = target_point(dimensions_, target, target_point_msb);
    std::vector<Fpk> row(dimensions_.slots, Fpk::zero());
    for (std::size_t node = 0; node < nodes_.size(); ++node) {
        column_row(nodes_[node], *masks_, target, point, row);
        write_row(node, row);
    }
    std::fill(row.begin(), row.end(), Fpk::zero());
    for (std::size_t node = nodes_.size(); node < dimensions_.internal_width;
         ++node)
        write_row(node, row);
}

Fpk WideProgram::evaluate_output_column(
    std::span<const Fpk> output_point_msb, WideColumnTarget target,
    std::span<const Fpk> target_point_msb) const {
    const auto output_point = split_point(
        output_point_msb, dimensions_.output_width, dimensions_.slots);
    const auto point = target_point(dimensions_, target, target_point_msb);
    Fpk result = Fpk::zero();
    // Output boundary rows can greatly outnumber local primitives. Uniform
    // rotations use the analytic grid predicate; each shared mask is
    // contracted once, without constructing output_width*slots values.
    std::map<std::size_t, Fpk> action_values, mask_values;
    const auto slot_bits =
        static_cast<std::size_t>(std::countr_zero(dimensions_.slots));
    const std::vector<Fpk> output_slots(output_point_msb.end() - slot_bits,
                                        output_point_msb.end());
    std::vector<Fpk> target_slots;
    if (target != WideColumnTarget::Constant)
        target_slots.assign(target_point_msb.end() - slot_bits,
                            target_point_msb.end());
    for (std::size_t output = 0; output < outputs_.size(); ++output) {
        const auto &node = outputs_[output];
        const Fpk wire = index_weight(output_point.wire, output);
        if (target == WideColumnTarget::Constant) {
            if (const auto *scalar = std::get_if<Fp>(&node.constant))
                result += wire * *scalar;
            else {
                const auto &constant = std::get<fhe::SlotVector>(node.constant);
                for (std::size_t slot = 0; slot < dimensions_.slots; ++slot)
                    result += wire * output_point.slot[slot] * constant[slot];
            }
            continue;
        }
        const auto block = target == WideColumnTarget::Input
                               ? WideSourceBlock::Input
                               : WideSourceBlock::Internal;
        for (const auto &term : node.terms) {
            if (term.source_block != block)
                continue;
            Fpk slot_value;
            if (term.mask) {
                auto [it, inserted] =
                    mask_values.try_emplace(*term.mask, Fpk::zero());
                if (inserted)
                    for (std::size_t slot = 0; slot < dimensions_.slots; ++slot)
                        it->second += output_point.slot[slot] *
                                      point.slot[slot] *
                                      masks_->masks()[*term.mask][slot];
                slot_value = it->second;
            } else {
                auto [it, inserted] =
                    action_values.try_emplace(term.rotation, Fpk::zero());
                if (inserted)
                    it->second = poly::grid_rotation_eval(
                        output_slots, target_slots, term.rotation);
                slot_value = it->second;
            }
            result += wire * index_weight(point.wire, term.source) *
                      term.coefficient * slot_value;
        }
    }
    return result;
}

Fpk WideProgram::evaluate_from_reverse(
    const WideRowReader &read_internal, std::span<const Fpk> output_point_msb,
    WideColumnTarget target, std::span<const Fpk> target_point_msb) const {
    const auto point = target_point(dimensions_, target, target_point_msb);
    Fpk result =
        evaluate_output_column(output_point_msb, target, target_point_msb);
    std::vector<Fpk> row(dimensions_.slots), adjoint(dimensions_.slots);
    for (std::size_t node = 0; node < nodes_.size(); ++node) {
        column_row(nodes_[node], *masks_, target, point, row);
        read_internal(node, adjoint);
        for (std::size_t slot = 0; slot < row.size(); ++slot)
            result += row[slot] * adjoint[slot];
    }
    return result;
}

} // namespace laminate::gates
