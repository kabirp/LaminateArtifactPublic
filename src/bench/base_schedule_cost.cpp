/// @file base_schedule_cost.cpp
/// @brief Executable operation formula for LaminateBase proving.

#include "laminate/gates/gate_mle.hpp"
#include "laminate/bench/schedule_cost.hpp"
#include "laminate/gkr/detail/shared/dense_multiplication/source/file.hpp"
#include "laminate/payload/trace/trace_wire_support.hpp"

#include <algorithm>
#include <bit>
#include <limits>
#include <span>
#include <stdexcept>
#include <string>
#include <unordered_set>

namespace laminate::bench {
namespace {

using Count = std::uint64_t;

Count count(std::size_t value, const char *name) {
    if (value > std::numeric_limits<Count>::max()) {
        throw std::overflow_error(std::string(name) + " does not fit u64");
    }
    return static_cast<Count>(value);
}

Count sum(Count left, Count right, const char *name) {
    if (right > std::numeric_limits<Count>::max() - left) {
        throw std::overflow_error(std::string(name) + " overflows");
    }
    return left + right;
}

Count product(Count left, Count right, const char *name) {
    if (left != 0 && right > std::numeric_limits<Count>::max() / left) {
        throw std::overflow_error(std::string(name) + " overflows");
    }
    return left * right;
}

void add(Count &destination, Count value, const char *name) {
    destination = sum(destination, value, name);
}

void add_product(Count &destination, Count left, Count right,
                 const char *name) {
    add(destination, product(left, right, name), name);
}

std::size_t log2_exact(std::size_t value, const char *name) {
    if (!std::has_single_bit(value)) {
        throw std::invalid_argument(std::string(name) +
                                    " is not a power of two");
    }
    return std::bit_width(value) - 1U;
}

void accumulate(ScheduleOperations &destination,
                const ScheduleOperations &source) {
#define LAMINATE_ACCUMULATE(field)                                             \
    add(destination.field, source.field, "Base schedule " #field)
    LAMINATE_ACCUMULATE(weighted_base_terms);
    LAMINATE_ACCUMULATE(online_vector_weighted_base_terms);
    LAMINATE_ACCUMULATE(weighted_base_accumulations);
    LAMINATE_ACCUMULATE(base_ciphertext_multiplications);
    LAMINATE_ACCUMULATE(base_additions);
    LAMINATE_ACCUMULATE(base_subtractions);
    LAMINATE_ACCUMULATE(base_negations);
    LAMINATE_ACCUMULATE(base_rotations);
    LAMINATE_ACCUMULATE(extension_plain_multiplications);
    LAMINATE_ACCUMULATE(prepared_base_slot_extension_multiplications);
    LAMINATE_ACCUMULATE(online_vector_extension_plain_multiplications);
    LAMINATE_ACCUMULATE(extension_ciphertext_multiplications);
    LAMINATE_ACCUMULATE(extension_additions);
    LAMINATE_ACCUMULATE(extension_subtractions);
    LAMINATE_ACCUMULATE(extension_rotations);
    LAMINATE_ACCUMULATE(extension_folds);
    LAMINATE_ACCUMULATE(extension_relinearizations);
    LAMINATE_ACCUMULATE(witness_base_plain_multiplications);
    LAMINATE_ACCUMULATE(witness_base_additions);
    LAMINATE_ACCUMULATE(round_extension_values);
    LAMINATE_ACCUMULATE(aligned_round_ciphertexts);
    LAMINATE_ACCUMULATE(logical_rounds);
    LAMINATE_ACCUMULATE(terminal_messages);
#undef LAMINATE_ACCUMULATE
}

struct LayerGeometry {
    payload::LayerWireSupport source_support;
    payload::LayerStorageLayout source_storage;
    payload::LayerTraceValueCounts source_counts;
    std::size_t ciphertext_index_variables = 0;
    std::size_t slot_index_variables = 0;

    static LayerGeometry create(const payload::LayeredCircuit &circuit,
                                const payload::LayerWireSupport &source,
                                const payload::LayerStorageLayout &storage,
                                const payload::LayerTraceValueCounts &counts) {
        if (counts.virtual_wire_positions != source.padded_wire_count ||
            counts.logical_live_wires != source.live_wire_count ||
            counts.stored_values != storage.stored_wire_count ||
            counts.encrypted_ciphertexts > counts.stored_values) {
            throw std::logic_error(
                "Base source value counts disagree with canonical storage");
        }
        return LayerGeometry{
            source,
            storage,
            counts,
            log2_exact(source.padded_wire_count, "Base source domain"),
            log2_exact(circuit.shape.slot_count, "Base slot count")};
    }
};

struct AffineCandidateCost {
    Count scalar_promotions = 0;
    Count prepared_basis_applications = 0;
};

using AffineSparseCoefficient =
    std::pair<std::size_t, std::size_t>; // (suffix, rotation)

std::vector<AffineSparseCoefficient> affine_sparse_coefficients(
    const gates::AffineSourceStructure &structure, std::size_t suffix_mask,
    std::size_t current_bit, bool at_one) {
    std::vector<AffineSparseCoefficient> result;
    for (const auto &term : structure.terms) {
        if (at_one && ((term.source >> current_bit) & std::size_t{1}) == 0) {
            continue;
        }
        result.emplace_back(term.source & suffix_mask, term.basis);
    }
    std::sort(result.begin(), result.end());
    result.erase(std::unique(result.begin(), result.end()), result.end());
    return result;
}

AffineCandidateCost affine_candidate_cost(
    const payload::LayerWireSupport &support,
    std::span<const AffineSparseCoefficient> coefficients,
    std::size_t suffix_mask, std::size_t current_bit, bool at_one) {
    AffineCandidateCost result;
    std::unordered_set<std::size_t> applied_rotations;
    for (const payload::LiveWireRange &range : support.live_ranges) {
        for (std::size_t wire = range.padded_begin;
             wire < range.padded_end(); ++wire) {
            if (at_one &&
                ((wire >> current_bit) & std::size_t{1}) == 0) {
                continue;
            }
            const std::size_t suffix = wire & suffix_mask;
            const auto begin = std::lower_bound(
                coefficients.begin(), coefficients.end(),
                AffineSparseCoefficient{suffix, 0});
            const auto end = std::upper_bound(
                begin, coefficients.end(), suffix,
                [](std::size_t value,
                   const AffineSparseCoefficient &candidate) {
                    return value < candidate.first;
                });
            add(result.scalar_promotions,
                count(static_cast<std::size_t>(end - begin),
                      "Base affine scalar promotions"),
                "Base affine scalar promotions");
            for (auto coefficient = begin; coefficient != end;
                 ++coefficient) {
                applied_rotations.insert(coefficient->second);
            }
        }
    }
    result.prepared_basis_applications = count(
        applied_rotations.size(), "Base affine prepared basis applications");
    return result;
}

ScheduleLayerFormula begin_layer(const LayerGeometry &geometry,
                                 std::size_t layer,
                                 payload::LayerKind kind) {
    ScheduleLayerFormula result;
    result.layer = layer;
    result.kind = kind;
    result.source_logical_live_wires =
        geometry.source_counts.logical_live_wires;
    result.source_stored_values = geometry.source_counts.stored_values;
    result.source_encrypted_ciphertexts =
        geometry.source_counts.encrypted_ciphertexts;
    result.source_virtual_wire_positions =
        geometry.source_support.padded_wire_count;
    result.source_materialized_packed_ciphertexts =
        geometry.source_storage.stored_wire_count;
    result.source_virtual_packed_positions =
        geometry.source_support.padded_wire_count;
    result.reduction_domain_variables =
        geometry.ciphertext_index_variables;
    result.slot_variables = geometry.slot_index_variables;
    return result;
}

ScheduleLayerFormula affine_layer(const payload::LayeredCircuit &circuit,
                                  std::size_t layer,
                                  const payload::LayerWireSupport &support,
                                  const payload::LayerStorageLayout &storage,
                                  const payload::LayerTraceValueCounts
                                      &counts) {
    const LayerGeometry geometry =
        LayerGeometry::create(circuit, support, storage, counts);
    ScheduleLayerFormula result =
        begin_layer(geometry, layer, payload::LayerKind::Affine);
    ScheduleOperations &cost = result.operations;
    const Count wires = count(geometry.source_support.live_wire_count,
                              "Base affine live ciphertexts");
    const Count variables =
        count(geometry.ciphertext_index_variables,
              "Base affine ciphertext-index variables");
    const auto structure = gates::DirectGateMle(circuit).affine_structure(layer);
    const Count claim_components =
        layer != 0 &&
                payload::layer_kind(circuit.layers.at(layer - 1U)) ==
                    payload::LayerKind::Multiplication
            ? Count{2}
            : Count{1};

    // The compact affine kernel does not build an N-slot weight for every
    // source wire. It first scalar-promotes the live source into sparse
    // (claim component, rotation) aggregates, then applies one prepared
    // extension-valued slot basis to every nonempty aggregate. Count those
    // two stages separately. For R(1), only the current-bit-one structural
    // coefficients and live source records survive; R(2) visits both
    // branches. Public-zero source records are never materialized.
    for (std::size_t bound = 1;
         bound <= geometry.ciphertext_index_variables; ++bound) {
        const std::size_t suffix_count =
            geometry.source_support.padded_wire_count >> bound;
        const std::size_t suffix_mask = suffix_count - 1U;
        const std::size_t current_bit =
            geometry.ciphertext_index_variables - bound;
        for (const bool at_one : {true, false}) {
            const std::vector<AffineSparseCoefficient> coefficients =
                affine_sparse_coefficients(
                    structure, suffix_mask, current_bit, at_one);
            const AffineCandidateCost candidate = affine_candidate_cost(
                geometry.source_support, coefficients, suffix_mask,
                current_bit, at_one);
            const Count promotions = product(
                candidate.scalar_promotions, claim_components,
                "Base affine claim-component scalar promotions");
            const Count applications = product(
                candidate.prepared_basis_applications, claim_components,
                "Base affine claim-component basis applications");
            // An identically zero candidate is still a live encrypted proof
            // message and is materialized from one source reference.
            add(cost.weighted_base_terms,
                promotions == 0 ? Count{1} : promotions,
                "Base affine scalar promotions");
            if (promotions != 0) {
                add(cost.extension_additions, promotions - 1U,
                    "Base affine sparse aggregate additions");
            }
            add(cost.extension_plain_multiplications, applications,
                "Base affine prepared basis applications");
            add(cost.online_vector_extension_plain_multiplications,
                applications,
                "Base affine prepared online basis applications");
        }
    }
    add(cost.weighted_base_terms, wires,
        "Base affine scalar terminal terms");
    if (wires > 1) {
        add(cost.weighted_base_accumulations, wires - 1,
            "Base affine terminal accumulation");
    }
    cost.logical_rounds = variables;
    cost.terminal_messages = 1;
    return result;
}

struct PrefixGroupCounts {
    Count at_zero_terms = 0;
    Count all_terms = 0;
    Count at_zero_groups = 0;
    Count at_one_groups = 0;
    Count all_groups = 0;
};

PrefixGroupCounts prefix_group_counts(std::size_t live_prefix,
                                      std::size_t domain_size,
                                      std::size_t bound_variables) {
    if (live_prefix > domain_size || bound_variables == 0U ||
        bound_variables > log2_exact(domain_size, "Base pair domain")) {
        throw std::invalid_argument(
            "invalid Base dense multiplication prefix geometry");
    }
    const std::size_t suffix_count = domain_size >> bound_variables;
    const std::size_t suffix_mask = suffix_count - 1U;
    const std::size_t current_bit =
        log2_exact(domain_size, "Base pair domain") - bound_variables;
    std::unordered_set<std::size_t> at_one_groups;
    std::unordered_set<std::size_t> at_zero_groups;
    std::unordered_set<std::size_t> all_groups;
    PrefixGroupCounts result;
    for (std::size_t pair = 0; pair < live_prefix; ++pair) {
        ++result.all_terms;
        all_groups.insert(pair & suffix_mask);
        if (((pair >> current_bit) & std::size_t{1}) != 0U) {
            at_one_groups.insert(pair & suffix_mask);
        } else {
            ++result.at_zero_terms;
            at_zero_groups.insert(pair & suffix_mask);
        }
    }
    result.at_one_groups =
        count(at_one_groups.size(), "Base X=1 suffix groups");
    result.at_zero_groups =
        count(at_zero_groups.size(), "Base X=0 suffix groups");
    result.all_groups = count(all_groups.size(), "Base live suffix groups");
    return result;
}

Count nonempty_accumulations(Count terms) {
    return terms == 0U ? Count{0} : terms - 1U;
}

struct DenseMultiplicationGeometry {
    payload::LayerWireSupport source_support;
    payload::LayerStorageLayout source_storage;
    payload::LayerTraceValueCounts source_counts;
    gkr::detail::DenseMultiplicationAliasPlan aliases;
    std::size_t pair_count = 0;
    std::size_t ciphertext_index_variables = 0;
    std::size_t slot_index_variables = 0;

    static DenseMultiplicationGeometry create(
        const payload::LayeredCircuit &circuit, std::size_t layer,
        const payload::LayerWireSupport &support,
        const payload::LayerStorageLayout &storage,
        const payload::LayerTraceValueCounts &counts) {
        const payload::LayerDimensions output =
            payload::layer_dimensions(circuit.layers.at(layer));
        const payload::LayerDimensions source =
            payload::layer_dimensions(circuit.layers.at(layer + 1U));
        if (source.padded_size != 2U * output.padded_size) {
            throw std::invalid_argument(
                "Base multiplication source is not two dense halves");
        }
        DenseMultiplicationGeometry result{
            support,
            storage,
            counts,
            gkr::detail::make_dense_multiplication_alias_plan(
                circuit, layer, support, storage),
            output.padded_size,
            log2_exact(output.padded_size,
                       "Base multiplication output domain"),
            log2_exact(circuit.shape.slot_count, "Base slot count")};
        if (counts.virtual_wire_positions != support.padded_wire_count ||
            counts.logical_live_wires != support.live_wire_count ||
            counts.stored_values != storage.stored_wire_count ||
            counts.encrypted_ciphertexts > counts.stored_values ||
            result.aliases.pair_count != result.pair_count ||
            result.aliases.live_pair_count == 0U) {
            throw std::logic_error(
                "Base dense multiplication alias geometry drifted");
        }
        return result;
    }
};

void add_dense_ciphertext_index_rounds(
    const DenseMultiplicationGeometry &geometry,
    ScheduleOperations &cost) {
    for (std::size_t bound = 1U;
         bound <= geometry.ciphertext_index_variables; ++bound) {
        // The ordinary nonzero output coordinate selects h(0). High-branch
        // counts still determine the arithmetic used to form h(2).
        const PrefixGroupCounts groups = prefix_group_counts(
            geometry.aliases.live_pair_count, geometry.pair_count, bound);
        const Count product_groups =
            sum(groups.at_zero_groups, groups.all_groups,
                "Base dense multiplication product groups");

        if (bound == 1U) {
            add(cost.base_ciphertext_multiplications, product_groups,
                "Base dense first-round products");
            add_product(cost.base_additions, Count{2},
                        groups.at_one_groups,
                        "Base dense first-round doublings");
            add_product(cost.base_subtractions, Count{2},
                        groups.at_one_groups,
                        "Base dense first-round subtractions");
            add_product(cost.base_negations, Count{2},
                        groups.all_groups - groups.at_one_groups,
                        "Base dense first-round low-only negations");
            add(cost.weighted_base_terms, product_groups,
                "Base dense first-round suffix weights");
            add(cost.weighted_base_accumulations,
                sum(nonempty_accumulations(groups.at_zero_groups),
                    nonempty_accumulations(groups.all_groups),
                    "Base dense first-round accumulations"),
                "Base dense first-round accumulations");
        } else {
            const Count partial_terms =
                sum(groups.at_zero_terms, groups.all_terms,
                    "Base dense partial source terms");
            const Count partial_accumulations =
                sum(groups.at_zero_terms - groups.at_zero_groups,
                    groups.all_terms - groups.all_groups,
                    "Base dense partial source accumulations");
            add_product(cost.weighted_base_terms, Count{2}, partial_terms,
                        "Base dense partial source weights");
            add_product(cost.weighted_base_accumulations, Count{2},
                        partial_accumulations,
                        "Base dense partial source accumulations");
            add(cost.extension_ciphertext_multiplications, product_groups,
                "Base dense extension products");
            add(cost.extension_plain_multiplications, product_groups,
                "Base dense suffix weights");
            add(cost.extension_additions,
                sum(nonempty_accumulations(groups.at_zero_groups),
                    nonempty_accumulations(groups.all_groups),
                    "Base dense output accumulations"),
                "Base dense output accumulations");
        }

        add(cost.extension_relinearizations,
            (groups.at_zero_groups == 0U ? Count{0} : Count{1}) +
                (groups.all_groups == 0U ? Count{0} : Count{1}),
            "Base dense round relinearizations");
    }
}

ScheduleLayerFormula multiplication_layer(
    const payload::LayeredCircuit &circuit, std::size_t layer,
    const payload::LayerWireSupport &support,
    const payload::LayerStorageLayout &storage,
    const payload::LayerTraceValueCounts &counts) {
    const DenseMultiplicationGeometry geometry =
        DenseMultiplicationGeometry::create(circuit, layer, support,
                                            storage, counts);

    ScheduleLayerFormula result;
    result.layer = layer;
    result.kind = payload::LayerKind::Multiplication;
    result.source_logical_live_wires =
        geometry.source_counts.logical_live_wires;
    result.source_stored_values = geometry.source_counts.stored_values;
    result.source_encrypted_ciphertexts =
        geometry.source_counts.encrypted_ciphertexts;
    result.source_virtual_wire_positions =
        geometry.source_support.padded_wire_count;
    result.source_materialized_packed_ciphertexts =
        geometry.aliases.operands.size();
    result.source_reused_packed_ciphertexts =
        static_cast<std::size_t>(std::count_if(
            geometry.aliases.operand_occurrences.begin(),
            geometry.aliases.operand_occurrences.end(),
            [](std::size_t uses) { return uses > 1U; }));
    result.source_virtual_packed_positions =
        geometry.source_support.padded_wire_count;
    result.reduction_domain_variables =
        geometry.ciphertext_index_variables;
    result.slot_variables = geometry.slot_index_variables;

    ScheduleOperations &cost = result.operations;
    add_dense_ciphertext_index_rounds(geometry, cost);

    const Count live_pairs = count(
        geometry.aliases.live_pair_count,
        "Base dense multiplication live pairs");
    add_product(cost.weighted_base_terms, Count{2}, live_pairs,
                "Base dense terminal checkpoint terms");
    add_product(cost.weighted_base_accumulations, Count{2},
                nonempty_accumulations(live_pairs),
                "Base dense terminal checkpoint accumulations");
    cost.logical_rounds =
        count(geometry.ciphertext_index_variables,
              "Base dense multiplication ciphertext-index rounds");
    cost.terminal_messages = 1U;
    return result;
}

} // namespace

ScheduleFormula base_schedule_formula(
    const payload::LayeredCircuit &circuit) {
    circuit.validate();
    if (circuit.shape.kind != payload::PayloadKind::Wide) {
        throw std::invalid_argument(
            "base_schedule_formula requires a wide circuit");
    }

    ScheduleFormula result;
    result.protocol = ScheduleProtocol::Base;
    result.layers.reserve(circuit.layers.size() - 1);
    const payload::CanonicalTraceLayout trace =
        payload::canonical_trace_layout(circuit);
    for (std::size_t layer = 0; layer + 1 < circuit.layers.size(); ++layer) {
        ScheduleLayerFormula layer_formula =
            payload::layer_kind(circuit.layers[layer]) ==
                    payload::LayerKind::Affine
                ? affine_layer(circuit, layer,
                               trace.wire_support[layer + 1U],
                               trace.storage[layer + 1U],
                               trace.value_counts[layer + 1U])
                : multiplication_layer(circuit, layer,
                                       trace.wire_support[layer + 1U],
                                       trace.storage[layer + 1U],
                                       trace.value_counts[layer + 1U]);
        accumulate(result.operations, layer_formula.operations);
        result.layers.push_back(std::move(layer_formula));
    }
    return result;
}

} // namespace laminate::bench
