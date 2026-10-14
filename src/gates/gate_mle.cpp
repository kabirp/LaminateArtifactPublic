/// @file gate_mle.cpp
/// @brief Direct sparse gate-MLE evaluation.

#include "laminate/gates/gate_mle.hpp"

#include "laminate/poly/eq.hpp"
#include "laminate/verification_profile.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>

namespace laminate::gates {
namespace {

constexpr std::string_view kSetupLabel = "laminate/gates/setup/v1";

bool is_power_of_two(std::size_t value) {
    return value != 0 && (value & (value - 1)) == 0;
}

std::size_t log2_exact(std::size_t value, const char *operation) {
    if (!is_power_of_two(value)) {
        throw std::invalid_argument(std::string(operation) +
                                    ": dimension is not a power of two");
    }
    return std::bit_width(value) - 1U;
}

struct SplitPoint {
    std::vector<Fpk> wire;
    std::vector<Fpk> slot;
};

SplitPoint split_point(std::span<const Fpk> point, std::size_t wire_count,
                       std::size_t slot_count, const char *operation) {
    const std::size_t wire_variables = log2_exact(wire_count, operation);
    const std::size_t slot_variables = log2_exact(slot_count, operation);
    if (wire_variables > std::numeric_limits<std::size_t>::max() -
                             slot_variables ||
        point.size() != wire_variables + slot_variables) {
        throw std::invalid_argument(std::string(operation) +
                                    ": point has the wrong dimension");
    }
    return SplitPoint{
        std::vector<Fpk>(
            point.begin(),
            point.begin() + static_cast<std::ptrdiff_t>(wire_variables)),
        std::vector<Fpk>(
            point.begin() + static_cast<std::ptrdiff_t>(wire_variables),
            point.end())};
}

const payload::AffineLayer &affine_layer(
    const payload::LayeredCircuit &circuit, std::size_t layer_index) {
    if (layer_index + 1 >= circuit.layers.size() ||
        !std::holds_alternative<payload::AffineLayer>(
            circuit.layers[layer_index])) {
        throw std::invalid_argument(
            "DirectGateMle: query does not name an affine layer");
    }
    return std::get<payload::AffineLayer>(circuit.layers[layer_index]);
}

} // namespace

struct PreparedDirectAffineMle::SharedData {
    using WeightedTerm = PreparedDirectAffineMle::WeightedTerm;

    std::size_t source_wire_count = 0;
    std::size_t slot_count = 0;
    std::vector<std::shared_ptr<const std::vector<Fpk>>> rotation_slot_tables;
    std::vector<WeightedTerm> terms;
    Fpk constant = Fpk::zero();
};

namespace {

std::size_t reverse_affine_source_bits(std::size_t value,
                                       std::size_t bit_count) {
    std::size_t result = 0;
    for (std::size_t bit = 0; bit < bit_count; ++bit) {
        result = (result << 1U) | (value & std::size_t{1});
        value >>= 1U;
    }
    return result;
}

/// Each reverse weight is a bounded sum of shared slot vectors. Scalar
/// additions and fanout therefore do not allocate an N-entry vector per
/// wire. A genuinely richer slot operator is materialized only when needed;
/// collapsing bounds work by O(N) per local equation, never by path count.
class WideReverseAffine {
  public:
    struct StorageCounts {
        std::size_t live = 0;
        std::size_t peak = 0;
    };
    struct Basis {
        std::shared_ptr<StorageCounts> storage_counts;
        ~Basis() { --storage_counts->live; }
        std::size_t id = 0;
        std::vector<Fpk> slots;
        Fpk sum = Fpk::zero();
    };
    struct Component {
        std::shared_ptr<const Basis> basis;
        Fpk coefficient = Fpk::zero();
    };
    using Weight = std::map<std::size_t, Component>;
    static constexpr std::size_t kMaximumComponents = 8;

    WideReverseAffine(const payload::LayeredCircuit &circuit,
                      const payload::AffineLayer &layer,
                      std::size_t source_count,
                      std::span<const Fpk> output_wire_weights,
                      std::vector<Fpk> output_slot_weights,
                      bool materialize_values = true, std::size_t structural_width = 0)
        : circuit_(circuit),
          width_(materialize_values ? output_slot_weights.size() : structural_width),
          materialize_(materialize_values),
          weights_(source_count + layer.intermediate_gates.size()) {
        const auto seed = make_basis(std::move(output_slot_weights));
        for (std::size_t output = 0; output < layer.gates.size(); ++output) {
            Weight weight;
            weight.emplace(seed->id, Component{seed, output_wire_weights[output]});
            propagate(layer.gates[output], weight);
        }
        for (std::size_t node = layer.intermediate_gates.size(); node > 0; --node) {
            const std::size_t address = source_count + node - 1U;
            Weight weight = std::move(weights_[address]);
            propagate(layer.intermediate_gates[node - 1U], weight);
        }
        weights_.resize(source_count);
    }

    const std::vector<Weight> &source_weights() const { return weights_; }
    Fpk constant() const { return constant_; }
    std::size_t peak_live_slot_bases() const { return storage_counts_->peak; }

  private:
    std::shared_ptr<const Basis> make_basis(std::vector<Fpk> values) {
        auto result = std::make_shared<Basis>();
        result->storage_counts = storage_counts_;
        ++storage_counts_->live;
        storage_counts_->peak = std::max(storage_counts_->peak,
                                         storage_counts_->live);
        result->id = next_basis_++;
        result->slots = std::move(values);
        for (const Fpk &value : result->slots) {
            result->sum += value;
        }
        return result;
    }

    std::shared_ptr<const Basis> transform(
        const std::shared_ptr<const Basis> &basis,
        const payload::AffineTerm &term) {
        if (term.rotation == 0 && !term.plaintext_index) {
            return basis;
        }
        const auto key = std::make_tuple(basis->id, term.rotation,
                                        term.plaintext_index);
        if (const auto found = transforms_.find(key); found != transforms_.end()) {
            if (auto shared = found->second.lock()) {
                return shared;
            }
        }
        std::vector<Fpk> values(materialize_ ? width_ : 0U, Fpk::zero());
        for (std::size_t output = 0; materialize_ && output < width_; ++output) {
            const std::size_t source = width_ == 1 ? 0
                : fhe::grid_source(width_, term.rotation, output);
            values[source] = basis->slots[output] *
                (term.plaintext_index
                    ? Fpk::from_base(circuit_.plaintexts[*term.plaintext_index][output])
                    : Fpk::one());
        }
        auto result = make_basis(std::move(values));
        transforms_[key] = result;
        return result;
    }

    void accumulate(Weight &target, std::shared_ptr<const Basis> basis,
                    const Fpk &coefficient) {
        const std::size_t id = basis->id;
        const auto [position, inserted] = target.try_emplace(
            id, Component{std::move(basis), coefficient});
        if (!inserted) {
            position->second.coefficient += coefficient;
        }
        // Keep numerical zero coefficients: their support still exists for
        // challenge-independent noise accounting.
        if (target.size() <= kMaximumComponents) {
            return;
        }
        std::vector<Fpk> values(materialize_ ? width_ : 0U, Fpk::zero());
        for (const auto &[id, component] : target) {
            (void)id;
            for (std::size_t slot = 0; materialize_ && slot < width_; ++slot) {
                values[slot] += component.coefficient * component.basis->slots[slot];
            }
        }
        auto collapsed = make_basis(std::move(values));
        target.clear();
        target.emplace(collapsed->id, Component{collapsed, Fpk::one()});
    }

    void propagate(const payload::AffineGate &gate, const Weight &weight) {
        std::map<std::tuple<std::size_t, std::size_t, std::optional<std::size_t>>, Fp>
            canonical;
        for (const auto &term : gate.terms) {
            canonical[{term.source, term.rotation, term.plaintext_index}] +=
                term.coefficient;
        }
        for (const auto &[id, component] : weight) {
            (void)id;
            if (!materialize_) {
                // Structural support depends on operators, never challenges.
            } else if (const auto *scalar = std::get_if<Fp>(&gate.constant)) {
                constant_ += component.coefficient * component.basis->sum *
                             Fpk::from_base(*scalar);
            } else {
                const auto &constant = std::get<fhe::SlotVector>(gate.constant);
                Fpk value = Fpk::zero();
                for (std::size_t slot = 0; slot < width_; ++slot) {
                    value += component.basis->slots[slot] * Fpk::from_base(constant[slot]);
                }
                constant_ += component.coefficient * value;
            }
            for (const auto &[key, coefficient] : canonical) {
                if (!coefficient.is_zero()) {
                    const payload::AffineTerm term{
                        std::get<0>(key), std::get<1>(key), coefficient,
                        std::get<2>(key)};
                    accumulate(weights_.at(term.source), transform(component.basis, term),
                               component.coefficient * Fpk::from_base(coefficient));
                }
            }
        }
    }

    const payload::LayeredCircuit &circuit_;
    std::size_t width_;
    bool materialize_;
    std::size_t next_basis_ = 0;
    std::shared_ptr<StorageCounts> storage_counts_ =
        std::make_shared<StorageCounts>();
    std::vector<Weight> weights_;
    std::map<std::tuple<std::size_t, std::size_t, std::optional<std::size_t>>,
             std::weak_ptr<const Basis>> transforms_;
    Fpk constant_ = Fpk::zero();
};

} // namespace

Fpk DirectGateMle::evaluate(const GateMleQuery &query) const {
    return std::visit(
        [&](const auto &typed_query) { return evaluate(typed_query); }, query);
}

PreparedDirectAffineMle DirectGateMle::prepare_affine(
    std::size_t layer_index, std::span<const Fpk> output_point) const {
    const payload::AffineLayer &layer =
        affine_layer(*circuit_, layer_index);
    const std::size_t width = circuit_->shape.value_width();
    const std::size_t source_count =
        payload::layer_dimensions(circuit_->layers[layer_index + 1])
            .padded_size;
    const SplitPoint output = split_point(
        output_point, layer.dimensions.padded_size, width,
        "DirectGateMle::prepare_affine output");
    const std::vector<Fpk> output_wire_weights =
        poly::eq_evaluations(output.wire);

    auto data = std::make_shared<PreparedDirectAffineMle::SharedData>();
    data->source_wire_count = source_count;
    data->slot_count = width;
    const std::vector<Fpk> output_slot_weights =
        poly::eq_evaluations(output.slot);

    if (circuit_->shape.kind == payload::PayloadKind::Wide) {
        const WideReverseAffine reverse(*circuit_, layer, source_count,
                                        output_wire_weights, output_slot_weights);
        std::map<std::size_t, std::size_t> indices;
        for (std::size_t source = 0; source < source_count; ++source) {
            for (const auto &[id, component] : reverse.source_weights()[source]) {
                const auto [position, inserted] = indices.emplace(id, indices.size());
                if (inserted) {
                    data->rotation_slot_tables.emplace_back(
                        component.basis, &component.basis->slots);
                }
                data->terms.push_back(PreparedDirectAffineMle::WeightedTerm{
                    source, position->second, component.coefficient});
            }
        }
        data->constant = reverse.constant();
    } else {
        std::size_t term_count = 0;
        for (const payload::AffineGate &gate : layer.gates) {
            term_count += gate.terms.size();
        }
        data->terms.reserve(term_count);

        std::map<std::size_t, std::size_t> rotation_indices;
        std::vector<std::size_t> rotations;
        for (std::size_t gate = 0; gate < layer.gates.size(); ++gate) {
            // Normalize public duplicate terms before multiplying by the
            // challenge-derived output weight. Only cancellations within one
            // output gate are structural; equal terms on distinct output gates
            // have independent MLE weights and must remain separate.
            std::map<std::pair<std::size_t, std::size_t>, Fp>
                canonical_terms;
            for (const payload::AffineTerm &term : layer.gates[gate].terms) {
                canonical_terms[{term.source, term.rotation}] +=
                    term.coefficient;
            }
            for (const auto &[key, coefficient] : canonical_terms) {
                if (coefficient.is_zero()) {
                    continue;
                }
                const auto [source, rotation] = key;
                const auto [position, inserted] = rotation_indices.emplace(
                    rotation, rotation_indices.size());
                if (inserted) {
                    rotations.push_back(rotation);
                }
                data->terms.push_back(
                    PreparedDirectAffineMle::SharedData::WeightedTerm{
                        source, position->second,
                        output_wire_weights[gate] *
                            Fpk::from_base(coefficient)});
            }
        }

        data->rotation_slot_tables.reserve(rotations.size());
        for (std::size_t basis = 0; basis < rotations.size(); ++basis) {
            auto values = std::make_shared<std::vector<Fpk>>(width, Fpk::zero());
            for (std::size_t output_slot = 0; output_slot < width; ++output_slot) {
                const std::size_t source_slot = width == 1 ? 0
                    : fhe::grid_source(width, rotations[basis], output_slot);
                (*values)[source_slot] += output_slot_weights[output_slot];
            }
            data->rotation_slot_tables.push_back(std::move(values));
        }
        data->constant = evaluate_affine_constant(layer_index, output_point);
    }
    const std::size_t source_variables = log2_exact(
        data->source_wire_count,
        "DirectGateMle::prepare_affine source");
    std::stable_sort(
        data->terms.begin(), data->terms.end(),
        [&](const PreparedDirectAffineMle::SharedData::WeightedTerm &left,
            const PreparedDirectAffineMle::SharedData::WeightedTerm &right) {
            const std::size_t left_reversed =
                reverse_affine_source_bits(left.source, source_variables);
            const std::size_t right_reversed =
                reverse_affine_source_bits(right.source, source_variables);
            if (left_reversed != right_reversed) {
                return left_reversed < right_reversed;
            }
            return left.rotation_index < right.rotation_index;
        });

    PreparedDirectAffineMle result;
    result.data_ = std::move(data);
    return result;
}

AffineSourceStructure DirectGateMle::affine_structure(std::size_t layer_index) const {
    const auto &layer = affine_layer(*circuit_, layer_index);
    const std::size_t source_count =
        payload::layer_dimensions(circuit_->layers[layer_index + 1]).padded_size;
    AffineSourceStructure result;
    std::map<std::size_t, std::size_t> indices;
    if (circuit_->shape.kind == payload::PayloadKind::Wide) {
        const std::vector<Fpk> output_weights(layer.gates.size(), Fpk::one());
        const WideReverseAffine reverse(*circuit_, layer, source_count,
            output_weights, {}, false, circuit_->shape.value_width());
        result.peak_live_slot_basis_count = reverse.peak_live_slot_bases();
        for (std::size_t source = 0; source < source_count; ++source) {
            for (const auto &[id, component] : reverse.source_weights()[source]) {
                (void)component;
                const auto [position, inserted] = indices.emplace(id, indices.size());
                (void)inserted;
                result.terms.push_back({source, position->second});
            }
        }
    } else {
        for (const auto &gate : layer.gates) {
            std::map<std::pair<std::size_t, std::size_t>, Fp> canonical;
            for (const auto &term : gate.terms) {
                canonical[{term.source, term.rotation}] += term.coefficient;
            }
            for (const auto &[key, coefficient] : canonical) {
                if (coefficient.is_zero()) {
                    continue;
                }
                const auto [position, inserted] = indices.emplace(key.second, indices.size());
                (void)inserted;
                result.terms.push_back({key.first, position->second});
            }
        }
    }
    result.slot_basis_count = indices.size();
    result.peak_live_slot_basis_count = std::max(
        result.peak_live_slot_basis_count, result.slot_basis_count);
    return result;
}

BoundDirectAffineMle PreparedDirectAffineMle::bind_source_ciphertext_index_point(
    std::span<const Fpk> source_wire_prefix) const {
    if (!data_) {
        throw std::logic_error(
            "PreparedDirectAffineMle is not initialized");
    }
    const std::size_t source_variables = log2_exact(
        data_->source_wire_count,
        "PreparedDirectAffineMle::bind_source_wire_prefix source");
    if (source_wire_prefix.size() > source_variables) {
        throw std::invalid_argument(
            "PreparedDirectAffineMle::bind_source_wire_prefix: source wire "
            "prefix is too long");
    }

    const std::size_t suffix_count =
        data_->source_wire_count >> source_wire_prefix.size();
    BoundDirectAffineMle result;
    result.data_ = data_;
    result.suffix_count_ = suffix_count;
    result.coefficients_.reserve(data_->terms.size());
    std::vector<Fpk> rotation_coefficients(
        data_->rotation_slot_tables.size(), Fpk::zero());
    std::vector<bool> rotation_touched(
        data_->rotation_slot_tables.size(), false);
    std::vector<std::size_t> touched_rotations;
    std::size_t cursor = 0;
    while (cursor < data_->terms.size()) {
        const std::size_t suffix =
            data_->terms[cursor].source & (suffix_count - 1U);
        const std::size_t suffix_order_key = reverse_affine_source_bits(
            suffix, log2_exact(
                        suffix_count,
                        "PreparedDirectAffineMle sparse suffix"));
        if (!result.sparse_suffix_order_keys_.empty() &&
            result.sparse_suffix_order_keys_.back() >= suffix_order_key) {
            throw std::logic_error(
                "PreparedDirectAffineMle sparse suffix is not contiguous");
        }
        result.sparse_suffixes_.push_back(suffix);
        result.sparse_suffix_order_keys_.push_back(suffix_order_key);
        result.suffix_offsets_.push_back(result.coefficients_.size());
        while (cursor < data_->terms.size() &&
               (data_->terms[cursor].source & (suffix_count - 1U)) ==
                   suffix) {
            const SharedData::WeightedTerm &term = data_->terms[cursor++];
            Fpk prefix_weight = Fpk::one();
            for (std::size_t variable = 0;
                 variable < source_wire_prefix.size(); ++variable) {
                const std::size_t shift =
                    source_variables - 1U - variable;
                prefix_weight *=
                    ((term.source >> shift) & std::size_t{1}) != 0
                        ? source_wire_prefix[variable]
                        : Fpk::one() - source_wire_prefix[variable];
            }
            if (!rotation_touched[term.rotation_index]) {
                rotation_touched[term.rotation_index] = true;
                touched_rotations.push_back(term.rotation_index);
            }
            rotation_coefficients[term.rotation_index] +=
                term.coefficient * prefix_weight;
        }
        for (const std::size_t rotation : touched_rotations) {
            result.coefficients_.push_back(
                BoundDirectAffineMle::SparseRotationCoefficient{
                    rotation, rotation_coefficients[rotation]});
            rotation_coefficients[rotation] = Fpk::zero();
            rotation_touched[rotation] = false;
        }
        touched_rotations.clear();
    }
    result.suffix_offsets_.push_back(result.coefficients_.size());
    return result;
}

RollingDirectAffineMle
PreparedDirectAffineMle::rolling_source_wire_binding() const {
    if (!data_) {
        throw std::logic_error(
            "PreparedDirectAffineMle is not initialized");
    }
    RollingDirectAffineMle result;
    result.data_ = data_;
    result.prefix_weights_.assign(data_->terms.size(), Fpk::one());
    return result;
}

std::vector<Fpk>
PreparedDirectAffineMle::evaluate_boolean_source_slots(
    std::span<const Fpk> source_wire_point) const {
    const BoundDirectAffineMle bound =
        bind_source_ciphertext_index_point(source_wire_point);
    if (bound.boolean_suffix_count() != 1) {
        throw std::logic_error(
            "PreparedDirectAffineMle full source binding left a suffix");
    }
    return bound.evaluate_boolean_source_slots(0);
}

std::size_t PreparedDirectAffineMle::rotation_basis_count() const {
    if (!data_) {
        throw std::logic_error(
            "PreparedDirectAffineMle is not initialized");
    }
    return data_->rotation_slot_tables.size();
}

std::size_t PreparedDirectAffineMle::weighted_term_count() const {
    if (!data_) {
        throw std::logic_error(
            "PreparedDirectAffineMle is not initialized");
    }
    return data_->terms.size();
}

std::span<const PreparedDirectAffineMle::WeightedTerm>
PreparedDirectAffineMle::weighted_terms() const {
    if (!data_) {
        throw std::logic_error("PreparedDirectAffineMle is not initialized");
    }
    return data_->terms;
}

Fpk PreparedDirectAffineMle::constant_evaluation() const {
    if (!data_) {
        throw std::logic_error("PreparedDirectAffineMle is not initialized");
    }
    return data_->constant;
}

std::span<const Fpk> PreparedDirectAffineMle::rotation_slot_basis(
    std::size_t rotation_index) const {
    if (!data_ || rotation_index >= data_->rotation_slot_tables.size()) {
        throw std::out_of_range(
            "PreparedDirectAffineMle rotation basis is out of range");
    }
    return *data_->rotation_slot_tables[rotation_index];
}

BoundDirectAffineMle RollingDirectAffineMle::evaluate_next(
    const Fpk &round_value) const {
    if (!data_ || prefix_weights_.size() != data_->terms.size()) {
        throw std::logic_error(
            "RollingDirectAffineMle is not initialized");
    }
    const std::size_t variables = source_variables();
    if (bound_variables_ >= variables) {
        throw std::logic_error(
            "RollingDirectAffineMle source point is complete");
    }
    const std::size_t suffix_count =
        data_->source_wire_count >> (bound_variables_ + 1U);
    const std::size_t shift = variables - 1U - bound_variables_;

    BoundDirectAffineMle result;
    result.data_ = data_;
    result.suffix_count_ = suffix_count;
    result.coefficients_.reserve(data_->terms.size());
    std::vector<Fpk> rotation_coefficients(
        data_->rotation_slot_tables.size(), Fpk::zero());
    std::vector<bool> rotation_touched(
        data_->rotation_slot_tables.size(), false);
    std::vector<bool> rotation_has_fixed_support(
        data_->rotation_slot_tables.size(), false);
    std::vector<std::size_t> touched_rotations;
    std::size_t cursor = 0;
    while (cursor < data_->terms.size()) {
        const std::size_t suffix =
            data_->terms[cursor].source & (suffix_count - 1U);
        const std::size_t suffix_order_key = reverse_affine_source_bits(
            suffix,
            log2_exact(suffix_count,
                       "RollingDirectAffineMle sparse suffix"));
        if (!result.sparse_suffix_order_keys_.empty() &&
            result.sparse_suffix_order_keys_.back() >= suffix_order_key) {
            throw std::logic_error(
                "RollingDirectAffineMle sparse suffix is not contiguous");
        }
        result.sparse_suffixes_.push_back(suffix);
        result.sparse_suffix_order_keys_.push_back(suffix_order_key);
        result.suffix_offsets_.push_back(result.coefficients_.size());
        while (cursor < data_->terms.size() &&
               (data_->terms[cursor].source & (suffix_count - 1U)) ==
                   suffix) {
            const std::size_t term_index = cursor;
            const PreparedDirectAffineMle::SharedData::WeightedTerm &term =
                data_->terms[cursor++];
            const Fpk factor =
                ((term.source >> shift) & std::size_t{1}) != 0
                    ? round_value
                    : Fpk::one() - round_value;
            if (!rotation_touched[term.rotation_index]) {
                rotation_touched[term.rotation_index] = true;
                touched_rotations.push_back(term.rotation_index);
            }
            rotation_has_fixed_support[term.rotation_index] =
                rotation_has_fixed_support[term.rotation_index] ||
                !factor.is_zero();
            rotation_coefficients[term.rotation_index] +=
                term.coefficient * prefix_weights_[term_index] * factor;
        }
        for (const std::size_t rotation : touched_rotations) {
            result.coefficients_.push_back(
                BoundDirectAffineMle::SparseRotationCoefficient{
                    rotation, rotation_coefficients[rotation],
                    rotation_has_fixed_support[rotation]});
            rotation_coefficients[rotation] = Fpk::zero();
            rotation_touched[rotation] = false;
            rotation_has_fixed_support[rotation] = false;
        }
        touched_rotations.clear();
    }
    result.suffix_offsets_.push_back(result.coefficients_.size());
    return result;
}

void RollingDirectAffineMle::bind(const Fpk &challenge) {
    if (!data_ || prefix_weights_.size() != data_->terms.size()) {
        throw std::logic_error(
            "RollingDirectAffineMle is not initialized");
    }
    const std::size_t variables = source_variables();
    if (bound_variables_ >= variables) {
        throw std::logic_error(
            "RollingDirectAffineMle source point is complete");
    }
    const std::size_t shift = variables - 1U - bound_variables_;
    for (std::size_t index = 0; index < data_->terms.size(); ++index) {
        const Fpk factor =
            ((data_->terms[index].source >> shift) & std::size_t{1}) != 0
                ? challenge
                : Fpk::one() - challenge;
        prefix_weights_[index] *= factor;
    }
    ++bound_variables_;
}

std::size_t RollingDirectAffineMle::bound_variables() const {
    if (!data_) {
        throw std::logic_error(
            "RollingDirectAffineMle is not initialized");
    }
    return bound_variables_;
}

std::size_t RollingDirectAffineMle::source_variables() const {
    if (!data_) {
        throw std::logic_error(
            "RollingDirectAffineMle is not initialized");
    }
    return log2_exact(data_->source_wire_count,
                      "RollingDirectAffineMle source");
}

bool RollingDirectAffineMle::complete() const {
    return bound_variables() == source_variables();
}

std::size_t BoundDirectAffineMle::boolean_suffix_count() const {
    if (!data_ || suffix_count_ == 0 || suffix_offsets_.empty()) {
        throw std::logic_error("BoundDirectAffineMle is not initialized");
    }
    return suffix_count_;
}

std::size_t BoundDirectAffineMle::sparse_suffix_count() const {
    if (!data_ || suffix_count_ == 0 || suffix_offsets_.empty()) {
        throw std::logic_error("BoundDirectAffineMle is not initialized");
    }
    return sparse_suffixes_.size();
}

std::size_t BoundDirectAffineMle::rotation_basis_count() const {
    if (!data_) {
        throw std::logic_error("BoundDirectAffineMle is not initialized");
    }
    return data_->rotation_slot_tables.size();
}

std::span<const BoundDirectAffineMle::SparseRotationCoefficient>
BoundDirectAffineMle::sparse_rotation_coefficients(
    std::size_t boolean_suffix) const {
    const std::size_t suffix_count = boolean_suffix_count();
    if (boolean_suffix >= suffix_count) {
        throw std::out_of_range(
            "BoundDirectAffineMle Boolean suffix is out of range");
    }
    const std::size_t suffix_order_key = reverse_affine_source_bits(
        boolean_suffix,
        log2_exact(suffix_count,
                   "BoundDirectAffineMle sparse suffix"));
    const auto found = std::lower_bound(
        sparse_suffix_order_keys_.begin(),
        sparse_suffix_order_keys_.end(), suffix_order_key);
    if (found == sparse_suffix_order_keys_.end() ||
        *found != suffix_order_key) {
        return {};
    }
    const std::size_t group = static_cast<std::size_t>(
        found - sparse_suffix_order_keys_.begin());
    return std::span<const SparseRotationCoefficient>(coefficients_)
        .subspan(suffix_offsets_[group],
                 suffix_offsets_[group + 1U] - suffix_offsets_[group]);
}

std::vector<Fpk> BoundDirectAffineMle::evaluate_boolean_source_slots(
    std::size_t boolean_suffix) const {
    const std::size_t suffix_count = boolean_suffix_count();
    if (boolean_suffix >= suffix_count) {
        throw std::out_of_range(
            "BoundDirectAffineMle Boolean suffix is out of range");
    }
    std::vector<Fpk> result(data_->slot_count, Fpk::zero());
    for (const SparseRotationCoefficient &coefficient :
         sparse_rotation_coefficients(boolean_suffix)) {
        const std::vector<Fpk> &basis =
            *data_->rotation_slot_tables[coefficient.rotation_index];
        for (std::size_t slot = 0; slot < data_->slot_count; ++slot) {
            result[slot] += coefficient.coefficient * basis[slot];
        }
    }
    return result;
}

Fpk DirectGateMle::evaluate(const AffineQuery &query) const {
    const payload::AffineLayer &layer =
        affine_layer(*circuit_, query.layer_index);
    const std::size_t width = circuit_->shape.value_width();
    const std::size_t source_count =
        payload::layer_dimensions(circuit_->layers[query.layer_index + 1])
            .padded_size;
    const SplitPoint output = split_point(
        query.output_point, layer.dimensions.padded_size, width,
        "DirectGateMle::evaluate(AffineQuery output)");
    const SplitPoint source =
        split_point(query.source_point, source_count, width,
                    "DirectGateMle::evaluate(AffineQuery source)");
    if (circuit_->shape.kind == payload::PayloadKind::Wide) {
        const auto prepared = prepare_affine(query.layer_index, query.output_point);
        const auto values = prepared.evaluate_boolean_source_slots(source.wire);
        const auto slot_weights = poly::eq_evaluations(source.slot);
        Fpk value = Fpk::zero();
        for (std::size_t slot = 0; slot < width; ++slot) {
            value += values[slot] * slot_weights[slot];
        }
        return value;
    }
    const std::vector<Fpk> output_wire_weights =
        poly::eq_evaluations(output.wire);
    const std::vector<Fpk> source_wire_weights =
        poly::eq_evaluations(source.wire);

    // The slot predicate depends only on the rotation, not on the gate:
    //
    //   G(r_out, r_in) = sum_(g,t) eq(r_out,g) eq(r_in,src(g,t))
    //       * coefficient(g,t) * Rotation_(step(g,t))(s_out,s_in).
    //
    // Real circuits repeat a small set of rotations across many gates.  Keep
    // one O(log N) evaluation per distinct step instead of repeating it for
    // every affine term.
    std::map<std::size_t, Fpk> rotation_values;
    const auto rotation_value = [&](std::size_t rotation) -> const Fpk & {
        const auto existing = rotation_values.find(rotation);
        if (existing != rotation_values.end()) {
            return existing->second;
        }
        return rotation_values
            .emplace(rotation,
                     width == 1
                         ? Fpk::one()
                         : poly::grid_rotation_eval(
                               output.slot, source.slot, rotation))
            .first->second;
    };

    Fpk result = Fpk::zero();
    for (std::size_t gate_index = 0; gate_index < layer.gates.size();
         ++gate_index) {
        for (const payload::AffineTerm &term :
             layer.gates[gate_index].terms) {
            result += output_wire_weights[gate_index] *
                      source_wire_weights[term.source] *
                      Fpk::from_base(term.coefficient) *
                      rotation_value(term.rotation);
        }
    }
    return result;
}

Fpk DirectGateMle::evaluate_affine_pair(
    std::size_t layer_index,
    std::span<const Fpk> first_output_point,
    std::span<const Fpk> second_output_point,
    std::span<const Fpk> source_point,
    const Fpk &second_weight) const {
    if (circuit_->shape.kind == payload::PayloadKind::Wide) {
        return evaluate(AffineQuery{layer_index, first_output_point, source_point}) +
               second_weight * evaluate(AffineQuery{layer_index, second_output_point, source_point});
    }
    const payload::AffineLayer &layer =
        affine_layer(*circuit_, layer_index);
    const std::size_t width = circuit_->shape.value_width();
    const std::size_t source_count =
        payload::layer_dimensions(circuit_->layers[layer_index + 1])
            .padded_size;
    const SplitPoint first_output = split_point(
        first_output_point, layer.dimensions.padded_size, width,
        "DirectGateMle::evaluate_affine_pair first output");
    const SplitPoint second_output = split_point(
        second_output_point, layer.dimensions.padded_size, width,
        "DirectGateMle::evaluate_affine_pair second output");
    const SplitPoint source = split_point(
        source_point, source_count, width,
        "DirectGateMle::evaluate_affine_pair source");
    const std::vector<Fpk> first_output_wire_weights =
        poly::eq_evaluations(first_output.wire);
    std::vector<Fpk> second_output_wire_weights =
        poly::eq_evaluations(second_output.wire);
    for (Fpk &weight : second_output_wire_weights) {
        weight *= second_weight;
    }
    const std::vector<Fpk> source_wire_weights =
        poly::eq_evaluations(source.wire);

    std::map<std::size_t, std::array<Fpk, 2>> rotation_values;
    const auto rotation_value =
        [&](std::size_t rotation) -> const std::array<Fpk, 2> & {
        const auto existing = rotation_values.find(rotation);
        if (existing != rotation_values.end()) {
            return existing->second;
        }
        const std::array<Fpk, 2> values{
            width == 1
                ? Fpk::one()
                : poly::grid_rotation_eval(
                      first_output.slot, source.slot, rotation),
            width == 1
                ? Fpk::one()
                : poly::grid_rotation_eval(
                      second_output.slot, source.slot, rotation)};
        return rotation_values.emplace(rotation, values).first->second;
    };

    Fpk result = Fpk::zero();
    for (std::size_t gate_index = 0; gate_index < layer.gates.size();
         ++gate_index) {
        for (const payload::AffineTerm &term :
             layer.gates[gate_index].terms) {
            const std::array<Fpk, 2> &rotations =
                rotation_value(term.rotation);
            const Fpk output_weight =
                first_output_wire_weights[gate_index] * rotations[0] +
                second_output_wire_weights[gate_index] * rotations[1];
            result += source_wire_weights[term.source] *
                      Fpk::from_base(term.coefficient) * output_weight;
        }
    }
    return result;
}

Fpk DirectGateMle::evaluate(const LanedAffineWireQuery &query) const {
    const payload::AffineLayer &layer =
        affine_layer(*circuit_, query.layer_index);
    if (circuit_->shape.kind != payload::PayloadKind::Laned) {
        throw std::invalid_argument(
            "DirectGateMle::evaluate(LanedAffineWireQuery): circuit is not "
            "laned");
    }
    const std::size_t source_count =
        payload::layer_dimensions(circuit_->layers[query.layer_index + 1])
            .padded_size;
    const std::size_t output_variables = log2_exact(
        layer.dimensions.padded_size,
        "DirectGateMle::evaluate(LanedAffineWireQuery output)");
    const std::size_t source_variables = log2_exact(
        source_count,
        "DirectGateMle::evaluate(LanedAffineWireQuery source)");
    if (query.output_wire_point.size() != output_variables ||
        query.source_wire_point.size() != source_variables) {
        throw std::invalid_argument(
            "DirectGateMle::evaluate(LanedAffineWireQuery): point dimension "
            "mismatch");
    }
    const std::vector<Fpk> output_weights = poly::eq_evaluations(
        std::vector<Fpk>(query.output_wire_point.begin(),
                         query.output_wire_point.end()));
    const std::vector<Fpk> source_weights = poly::eq_evaluations(
        std::vector<Fpk>(query.source_wire_point.begin(),
                         query.source_wire_point.end()));

    Fpk result = Fpk::zero();
    for (std::size_t gate = 0; gate < layer.gates.size(); ++gate) {
        for (const payload::AffineTerm &term : layer.gates[gate].terms) {
            result += output_weights[gate] * source_weights[term.source] *
                      Fpk::from_base(term.coefficient);
        }
    }
    return result;
}

Fpk DirectGateMle::evaluate_affine_constant(
    std::size_t layer_index, std::span<const Fpk> output_point) const {
    if (circuit_->shape.kind == payload::PayloadKind::Wide) {
        return prepare_affine(layer_index, output_point).constant_evaluation();
    }
    const payload::AffineLayer &layer = affine_layer(*circuit_, layer_index);
    const std::size_t width = circuit_->shape.value_width();
    const SplitPoint output = split_point(
        output_point, layer.dimensions.padded_size, width,
        "DirectGateMle::evaluate_affine_constant");
    const std::vector<Fpk> wire_weights =
        poly::eq_evaluations(output.wire);
    // Scalar constants are uniform over all slots, so their slot sum is one.
    // Build the O(N) slot table lazily only if this layer actually contains a
    // slot-vector constant.
    std::optional<std::vector<Fpk>> slot_weights;

    Fpk result = Fpk::zero();
    for (std::size_t gate = 0; gate < layer.gates.size(); ++gate) {
        if (const auto *scalar =
                std::get_if<Fp>(&layer.gates[gate].constant)) {
            result += wire_weights[gate] * Fpk::from_base(*scalar);
        } else {
            if (!slot_weights.has_value()) {
                slot_weights = poly::eq_evaluations(output.slot);
            }
            const fhe::SlotVector &constant =
                std::get<fhe::SlotVector>(layer.gates[gate].constant);
            for (std::size_t slot = 0; slot < width; ++slot) {
                result += wire_weights[gate] * (*slot_weights)[slot] *
                          Fpk::from_base(constant[slot]);
            }
        }
    }
    return result;
}

Fpk DirectGateMle::evaluate_affine_constant_pair(
    std::size_t layer_index,
    std::span<const Fpk> first_output_point,
    std::span<const Fpk> second_output_point,
    const Fpk &second_weight) const {
    if (circuit_->shape.kind == payload::PayloadKind::Wide) {
        return evaluate_affine_constant(layer_index, first_output_point) +
               second_weight * evaluate_affine_constant(layer_index, second_output_point);
    }
    const payload::AffineLayer &layer =
        affine_layer(*circuit_, layer_index);
    const std::size_t width = circuit_->shape.value_width();
    const SplitPoint first_output = split_point(
        first_output_point, layer.dimensions.padded_size, width,
        "DirectGateMle::evaluate_affine_constant_pair first output");
    const SplitPoint second_output = split_point(
        second_output_point, layer.dimensions.padded_size, width,
        "DirectGateMle::evaluate_affine_constant_pair second output");
    const std::vector<Fpk> first_wire_weights =
        poly::eq_evaluations(first_output.wire);
    std::vector<Fpk> second_wire_weights =
        poly::eq_evaluations(second_output.wire);
    for (Fpk &weight : second_wire_weights) {
        weight *= second_weight;
    }
    std::optional<std::array<std::vector<Fpk>, 2>> slot_weights;

    Fpk result = Fpk::zero();
    for (std::size_t gate = 0; gate < layer.gates.size(); ++gate) {
        if (const auto *scalar =
                std::get_if<Fp>(&layer.gates[gate].constant)) {
            result += (first_wire_weights[gate] +
                       second_wire_weights[gate]) *
                      Fpk::from_base(*scalar);
            continue;
        }
        if (!slot_weights.has_value()) {
            slot_weights.emplace(std::array<std::vector<Fpk>, 2>{
                poly::eq_evaluations(first_output.slot),
                poly::eq_evaluations(second_output.slot)});
        }
        const fhe::SlotVector &constant =
            std::get<fhe::SlotVector>(layer.gates[gate].constant);
        Fpk first_value = Fpk::zero();
        Fpk second_value = Fpk::zero();
        for (std::size_t slot = 0; slot < width; ++slot) {
            const Fpk value = Fpk::from_base(constant[slot]);
            first_value += (*slot_weights)[0][slot] * value;
            second_value += (*slot_weights)[1][slot] * value;
        }
        result += first_wire_weights[gate] * first_value +
                  second_wire_weights[gate] * second_value;
    }
    return result;
}

void observe_gate_mle_setup(const PublicSetup &setup, Transcript &transcript) {
    const verification_profile::ScopedTranscriptRecovery recovery;
    const std::vector<std::uint8_t> encoded = encode_canonical(setup);
    transcript.observe(kSetupLabel, encoded);
}

} // namespace laminate::gates
