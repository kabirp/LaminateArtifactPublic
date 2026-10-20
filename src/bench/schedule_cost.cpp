#include "laminate/gates/gate_mle.hpp"
#include "laminate/bench/schedule_cost.hpp"

#include "laminate/gkr/detail/laned/affine/source/chunk_batches.hpp"
#include "laminate/gkr/detail/shared/dense_multiplication/source/file.hpp"
#include "laminate/packing/alignment/laned.hpp"
#include "laminate/params.hpp"
#include "laminate/payload/trace/trace_wire_support.hpp"

#include <algorithm>
#include <bit>
#include <limits>
#include <span>
#include <stdexcept>
#include <string>
#include <tuple>
#include <unordered_set>
#include <utility>

namespace laminate::bench {
namespace {

using Count = std::uint64_t;

Count as_count(std::size_t value, const char *name) {
    if (value > std::numeric_limits<Count>::max()) {
        throw std::overflow_error(std::string(name) + " does not fit u64");
    }
    return static_cast<Count>(value);
}

Count checked_add(Count left, Count right, const char *name) {
    if (right > std::numeric_limits<Count>::max() - left) {
        throw std::overflow_error(std::string(name) + " overflows");
    }
    return left + right;
}

Count checked_mul(Count left, Count right, const char *name) {
    if (left != 0 && right > std::numeric_limits<Count>::max() / left) {
        throw std::overflow_error(std::string(name) + " overflows");
    }
    return left * right;
}

void add(Count &destination, Count value, const char *name) {
    destination = checked_add(destination, value, name);
}

void add_scaled(Count &destination, Count left, Count right,
                const char *name) {
    add(destination, checked_mul(left, right, name), name);
}

std::size_t log2_exact(std::size_t value, const char *name) {
    if (value == 0 || !std::has_single_bit(value)) {
        throw std::invalid_argument(std::string(name) +
                                    " is not a power of two");
    }
    return std::bit_width(value) - 1U;
}

void accumulate(ScheduleOperations &destination,
                const ScheduleOperations &source) {
#define LAMINATE_ACCUMULATE(field)                                             \
    add(destination.field, source.field, "schedule " #field)
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

void add_online_extension_plain_multiplications(
    ScheduleOperations &operations, Count value, const char *name) {
    add(operations.extension_plain_multiplications, value, name);
    add(operations.online_vector_extension_plain_multiplications, value,
        name);
}

void add_round_encoding(ScheduleOperations &operations, Count rounds,
                        Count terminal_values) {
    add_scaled(operations.round_extension_values, Count{2}, rounds,
               "BhIP round extension values");
    add(operations.round_extension_values, terminal_values,
        "BhIP terminal extension values");
    add(operations.aligned_round_ciphertexts, rounds,
        "aligned BhIP round ciphertexts");
    add(operations.aligned_round_ciphertexts, Count{1},
        "aligned BhIP terminal ciphertext");
    add(operations.logical_rounds, rounds, "logical rounds");
    add(operations.terminal_messages, Count{1}, "terminal messages");
}

Count nonempty_accumulations(Count terms) {
    return terms == 0 ? Count{0} : terms - 1;
}

Count live_at_domain_bit_one(const payload::LayerWireSupport &support,
                             std::size_t variables,
                             std::size_t bound_variables,
                             std::size_t indices_per_domain_position = 1) {
    if (bound_variables == 0 || bound_variables > variables ||
        indices_per_domain_position == 0) {
        throw std::invalid_argument("invalid live-domain bit query");
    }
    const std::size_t bit = variables - bound_variables;
    Count result = 0;
    for (const payload::LiveWireRange &range : support.live_ranges) {
        for (std::size_t index = range.padded_begin;
             index < range.padded_end(); ++index) {
            const std::size_t domain_index =
                index / indices_per_domain_position;
            if (((domain_index >> bit) & std::size_t{1}) != 0) {
                add(result, Count{1}, "live domain-bit terms");
            }
        }
    }
    return result;
}

std::vector<std::size_t> materialized_packed_indices(
    const payload::LayerWireSupport &support,
    const packing::LanedPackingLayout &layout) {
    if (support.padded_wire_count != layout.original_wire_count) {
        throw std::invalid_argument(
            "Laned support and packed layout domains disagree");
    }
    std::unordered_set<std::size_t> unique;
    const std::size_t chunks = layout.chunks_per_ciphertext();
    for (const payload::LiveWireRange &range : support.live_ranges) {
        for (std::size_t wire = range.padded_begin;
             wire < range.padded_end(); ++wire) {
            unique.insert(wire / chunks);
        }
    }
    std::vector<std::size_t> result(unique.begin(), unique.end());
    std::sort(result.begin(), result.end());
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
    if (live_prefix > domain_size || bound_variables == 0 ||
        bound_variables > log2_exact(domain_size, "packed pair domain")) {
        throw std::invalid_argument("invalid packed live-prefix geometry");
    }
    const std::size_t suffix_count = domain_size >> bound_variables;
    const std::size_t suffix_mask = suffix_count - 1U;
    const std::size_t current_bit =
        log2_exact(domain_size, "packed pair domain") - bound_variables;
    std::unordered_set<std::size_t> one_groups;
    std::unordered_set<std::size_t> zero_groups;
    std::unordered_set<std::size_t> all_groups;
    PrefixGroupCounts result;
    for (std::size_t index = 0; index < live_prefix; ++index) {
        add(result.all_terms, Count{1}, "packed live terms");
        all_groups.insert(index & suffix_mask);
        if (((index >> current_bit) & std::size_t{1}) != 0) {
            one_groups.insert(index & suffix_mask);
        } else {
            add(result.at_zero_terms, Count{1}, "packed live X=0 terms");
            zero_groups.insert(index & suffix_mask);
        }
    }
    result.at_one_groups = as_count(one_groups.size(), "packed X=1 groups");
    result.at_zero_groups = as_count(zero_groups.size(), "packed X=0 groups");
    result.all_groups = as_count(all_groups.size(), "packed live groups");
    return result;
}

std::vector<std::size_t> live_wire_indices(
    const payload::LayerWireSupport &support) {
    std::vector<std::size_t> result;
    result.reserve(support.live_wire_count);
    for (const payload::LiveWireRange &range : support.live_ranges) {
        for (std::size_t wire = range.padded_begin;
             wire < range.padded_end(); ++wire) {
            result.push_back(wire);
        }
    }
    if (result.size() != support.live_wire_count) {
        throw std::logic_error("Folded live-wire support is malformed");
    }
    return result;
}

struct FoldedAffineStructuralTerm {
    std::size_t source = 0;
    std::size_t basis = 0;
};

struct FoldedAffineStructuralSchedule {
    std::size_t basis_count = 0;
    std::vector<FoldedAffineStructuralTerm> terms;
};

FoldedAffineStructuralSchedule folded_affine_structural_schedule(
    const payload::LayeredCircuit &circuit, std::size_t layer) {
    const auto structure = gates::DirectGateMle(circuit).affine_structure(layer);
    FoldedAffineStructuralSchedule result;
    for (const auto &term : structure.terms) {
        result.terms.push_back(FoldedAffineStructuralTerm{term.source, term.basis});
    }
    result.basis_count = structure.slot_basis_count;
    return result;
}

ScheduleLayerFormula folded_affine_layer(const payload::LayeredCircuit &circuit,
                                         std::size_t layer,
                                         const payload::LayerWireSupport
                                             &source_support,
                                         const payload::LayerTraceValueCounts
                                             &source_counts) {
    const std::size_t source_width = source_support.padded_wire_count;
    const std::size_t wire_variables =
        log2_exact(source_width, "Folded affine source width");
    const std::size_t slot_variables =
        log2_exact(circuit.shape.slot_count, "Folded slot count");
    const Count wires = as_count(source_support.live_wire_count,
                                 "Folded affine live ciphertexts");
    const Count wire_vars = as_count(wire_variables, "Folded wire variables");
    const Count slot_vars = as_count(slot_variables, "Folded slot variables");
    const FoldedAffineStructuralSchedule schedule =
        folded_affine_structural_schedule(circuit, layer);
    const std::vector<std::size_t> live_indices =
        live_wire_indices(source_support);

    ScheduleLayerFormula result;
    result.layer = layer;
    result.kind = payload::LayerKind::Affine;
    result.source_logical_live_wires = source_counts.logical_live_wires;
    result.source_stored_values = source_counts.stored_values;
    result.source_encrypted_ciphertexts =
        source_counts.encrypted_ciphertexts;
    result.source_virtual_wire_positions = source_width;
    result.source_materialized_packed_ciphertexts =
        source_support.live_wire_count;
    result.source_virtual_packed_positions = source_width;
    result.reduction_domain_variables = wire_variables;
    result.slot_variables = slot_variables;

    ScheduleOperations &cost = result.operations;
    // Each batch first reduces public gate terms by (suffix,basis), then makes
    // one sequential compact-source pass. A source is promoted once for each
    // active basis at its suffix and each of the two round evaluations. The
    // prepared slot basis is applied after scalar aggregation; no online
    // N-slot plaintext is constructed.
    for (std::size_t bound = 1; bound <= wire_variables; ++bound) {
        const std::size_t suffix_count = source_width >> bound;
        std::vector<std::vector<bool>> active_suffixes(
            schedule.basis_count,
            std::vector<bool>(suffix_count, false));
        for (const FoldedAffineStructuralTerm &term : schedule.terms) {
            active_suffixes.at(term.basis)
                .at(term.source & (suffix_count - 1U)) = true;
        }
        Count promotions_per_evaluation = 0;
        Count active_bases = 0;
        for (const auto &basis : active_suffixes) {
            Count basis_promotions = 0;
            for (std::size_t wire : live_indices) {
                if (basis[wire & (suffix_count - 1U)]) {
                    add(basis_promotions, Count{1},
                        "Folded affine basis promotions");
                }
            }
            if (basis_promotions != 0) {
                ++active_bases;
                add(promotions_per_evaluation, basis_promotions,
                    "Folded affine promotions per evaluation");
            }
        }
        add_scaled(cost.weighted_base_terms, Count{2},
                   promotions_per_evaluation,
                   "Folded affine scalar promotions");
        add_scaled(cost.extension_plain_multiplications, Count{2},
                   active_bases,
                   "Folded affine prepared-basis applications");
        if (promotions_per_evaluation != 0) {
            add_scaled(cost.extension_additions, Count{2},
                       promotions_per_evaluation - 1U,
                       "Folded affine scalar/basis accumulations");
        }
    }
    add_scaled(cost.extension_folds, Count{2}, wire_vars,
               "Folded affine wire folds");

    // The full wire checkpoint is evaluated once before the slot phase.
    add(cost.weighted_base_terms, wires, "Folded affine checkpoint terms");
    add(cost.weighted_base_accumulations, wires - 1,
        "Folded affine checkpoint additions");
    add(cost.extension_additions, wires - 1,
        "Folded affine checkpoint extension additions");

    for (Count prefix = 0; prefix < slot_vars; ++prefix) {
        if (prefix != 0) {
            add_online_extension_plain_multiplications(
                cost, Count{1}, "Folded affine prefix multiplication");
            add(cost.extension_rotations, prefix,
                "Folded affine prefix rotations");
            add(cost.extension_additions, prefix,
                "Folded affine prefix additions");
        }
        // Sibling alignment and independent X=2 extrapolation.
        add(cost.extension_rotations, Count{1},
            "Folded affine sibling rotation");
        add(cost.extension_additions, Count{1},
            "Folded affine extrapolation addition");
        add(cost.extension_subtractions, Count{1},
            "Folded affine extrapolation subtraction");
        add_online_extension_plain_multiplications(
            cost, Count{2}, "Folded affine gate weighting");
        add(cost.extension_folds, Count{2}, "Folded affine slot folds");
    }

    // Terminal source evaluation binds every slot variable from scratch.
    add_online_extension_plain_multiplications(
        cost, Count{1}, "Folded affine terminal multiplication");
    add(cost.extension_rotations, slot_vars,
        "Folded affine terminal rotations");
    add(cost.extension_additions, slot_vars,
        "Folded affine terminal additions");

    add_round_encoding(cost, checked_add(wire_vars, slot_vars,
                                         "Folded affine rounds"),
                       Count{1});
    return result;
}

ScheduleLayerFormula dense_packed_multiplication_layer(
    const payload::LayeredCircuit &circuit, std::size_t layer,
    bool packs_laned_witness,
    const payload::LayerWireSupport &source_support,
    const payload::LayerStorageLayout &source_storage,
    const payload::LayerTraceValueCounts &source_counts) {
    const packing::LanedPackingLayout output =
        gkr::detail::dense_multiplication_storage_layout(circuit, layer);
    const packing::LanedPackingLayout source =
        gkr::detail::dense_multiplication_storage_layout(circuit,
                                                         layer + 1U);
    const gkr::detail::DenseMultiplicationAliasPlan aliases =
        gkr::detail::make_dense_multiplication_alias_plan(
            circuit, layer, source_support, source_storage);
    if (source.padded_ciphertext_count !=
            2U * output.padded_ciphertext_count ||
        aliases.pair_count != output.padded_ciphertext_count ||
        aliases.live_pair_count == 0U) {
        throw std::invalid_argument(
            "packed multiplication geometry is not two dense halves");
    }

    const std::size_t wire_variables = log2_exact(
        output.padded_ciphertext_count,
        "packed multiplication output width");
    const std::size_t slot_variables =
        log2_exact(output.slot_count, "packed multiplication slot count");
    const Count live_pairs = as_count(
        aliases.live_pair_count, "packed multiplication live pairs");
    const Count wire_vars =
        as_count(wire_variables, "packed multiplication wire variables");
    const Count slot_vars =
        as_count(slot_variables, "packed multiplication slot variables");

    ScheduleLayerFormula result;
    result.layer = layer;
    result.kind = payload::LayerKind::Multiplication;
    result.source_logical_live_wires = source_counts.logical_live_wires;
    result.source_stored_values = source_counts.stored_values;
    result.source_encrypted_ciphertexts =
        source_counts.encrypted_ciphertexts;
    result.source_virtual_wire_positions = source.original_wire_count;
    result.source_materialized_packed_ciphertexts =
        aliases.operands.size();
    result.source_reused_packed_ciphertexts =
        static_cast<std::size_t>(std::count_if(
            aliases.operand_occurrences.begin(),
            aliases.operand_occurrences.end(),
            [](std::size_t uses) { return uses > 1U; }));
    result.source_virtual_packed_positions =
        source.padded_ciphertext_count;
    result.reduction_domain_variables = wire_variables;
    result.slot_variables = slot_variables;
    ScheduleOperations &cost = result.operations;

    // Laned must first place each distinct compact operand into its protocol
    // slots. Alias-backed logical positions reuse the resulting ciphertext;
    // neither storage nor this accounting duplicates it.
    if (packs_laned_witness && source.chunks_per_ciphertext() != 1U) {
        for (const auto &operand : aliases.operands) {
            Count terms = 0;
            for (std::size_t chunk = 0;
                 chunk < operand.stored_ordinals.size(); ++chunk) {
                if (!operand.stored_ordinals[chunk]) {
                    continue;
                }
                ++terms;
                ++cost.witness_base_plain_multiplications;
                if (chunk != 0U) {
                    ++cost.base_rotations;
                }
            }
            add(cost.witness_base_additions,
                nonempty_accumulations(terms),
                "Laned distinct-operand packing additions");
        }
    }

    for (std::size_t bound = 1U; bound <= wire_variables; ++bound) {
        // The ordinary nonzero output coordinate selects h(0). Counts for
        // the high branch remain separate: evaluating each linear source
        // operand at X=2 doubles its high branch and subtracts its low branch.
        const PrefixGroupCounts groups = prefix_group_counts(
            aliases.live_pair_count, output.padded_ciphertext_count, bound);
        const Count product_groups = checked_add(
            groups.at_zero_groups, groups.all_groups,
            "packed multiplication live product groups");
        if (bound == 1U) {
            add(cost.base_ciphertext_multiplications, product_groups,
                "packed multiplication base-first products");
            add_scaled(cost.base_additions, Count{2},
                       groups.at_one_groups,
                       "packed multiplication base-first doublings");
            add_scaled(cost.base_subtractions, Count{2},
                       groups.at_one_groups,
                       "packed multiplication base-first subtractions");
            add_scaled(cost.base_negations, Count{2},
                       groups.all_groups - groups.at_one_groups,
                       "packed multiplication base-first negations");
            add(cost.weighted_base_terms, product_groups,
                "packed multiplication base-first scalar promotions");
            add(cost.weighted_base_accumulations,
                checked_add(
                    nonempty_accumulations(groups.at_zero_groups),
                    nonempty_accumulations(groups.all_groups),
                    "packed multiplication first-round accumulations"),
                "packed multiplication first-round accumulations");
        } else {
            add_scaled(
                cost.weighted_base_terms, Count{2},
                checked_add(groups.at_zero_terms, groups.all_terms,
                            "packed multiplication partial source terms"),
                "packed multiplication partial source terms");
            add_scaled(
                cost.weighted_base_accumulations, Count{2},
                checked_add(
                    groups.at_zero_terms - groups.at_zero_groups,
                    groups.all_terms - groups.all_groups,
                    "packed multiplication partial source accumulations"),
                "packed multiplication partial source accumulations");
            add(cost.extension_plain_multiplications, product_groups,
                "packed multiplication wire suffix weights");
            add(cost.extension_ciphertext_multiplications, product_groups,
                "packed multiplication wire products");
            add(cost.extension_additions,
                checked_add(
                    nonempty_accumulations(groups.at_zero_groups),
                    nonempty_accumulations(groups.all_groups),
                    "packed multiplication wire output accumulations"),
                "packed multiplication wire output accumulations");
        }

        // The two round evaluations share a prepared output-slot basis but
        // each applies it to its own accumulated extension value.
        add(cost.extension_plain_multiplications, Count{2},
            "packed multiplication prepared output-slot basis");
        add(cost.extension_relinearizations,
            (groups.at_zero_groups == 0U ? Count{0} : Count{1}) +
                (groups.all_groups == 0U ? Count{0} : Count{1}),
            "packed multiplication wire relinearizations");
        add(cost.extension_folds, Count{2},
            "packed multiplication wire folds");
    }

    // Bind the common wire point once for each operand half.
    add_scaled(cost.weighted_base_terms, Count{2}, live_pairs,
               "packed multiplication checkpoint terms");
    add_scaled(cost.weighted_base_accumulations, Count{2},
               nonempty_accumulations(live_pairs),
               "packed multiplication checkpoint accumulations");

    ScheduleOperations &slot = result.multiplication_slot_rounds;
    for (Count prefix = 0; prefix < slot_vars; ++prefix) {
        if (prefix != 0U) {
            add_online_extension_plain_multiplications(
                cost, Count{2},
                "packed multiplication shared slot-prefix bindings");
            add_online_extension_plain_multiplications(
                slot, Count{2},
                "packed multiplication shared slot-prefix bindings");
            add_scaled(cost.extension_rotations, Count{2}, prefix,
                       "packed multiplication prefix rotations");
            add_scaled(slot.extension_rotations, Count{2}, prefix,
                       "packed multiplication prefix rotations");
            add_scaled(cost.extension_additions, Count{2}, prefix,
                       "packed multiplication prefix additions");
            add_scaled(slot.extension_additions, Count{2}, prefix,
                       "packed multiplication prefix additions");
        }

        add(cost.extension_rotations, Count{2},
            "packed multiplication sibling rotations");
        add(slot.extension_rotations, Count{2},
            "packed multiplication sibling rotations");
        add(cost.extension_additions, Count{2},
            "packed multiplication extrapolation additions");
        add(slot.extension_additions, Count{2},
            "packed multiplication extrapolation additions");
        add(cost.extension_subtractions, Count{2},
            "packed multiplication extrapolation subtractions");
        add(slot.extension_subtractions, Count{2},
            "packed multiplication extrapolation subtractions");
        add_online_extension_plain_multiplications(
            cost, Count{2}, "packed multiplication slot masks");
        add_online_extension_plain_multiplications(
            slot, Count{2}, "packed multiplication slot masks");
        add(cost.extension_ciphertext_multiplications, Count{2},
            "packed multiplication slot products");
        add(slot.extension_ciphertext_multiplications, Count{2},
            "packed multiplication slot products");
        add(cost.extension_relinearizations, Count{2},
            "packed multiplication slot relinearizations");
        add(slot.extension_relinearizations, Count{2},
            "packed multiplication slot relinearizations");
        add(cost.extension_folds, Count{2},
            "packed multiplication slot folds");
        add(slot.extension_folds, Count{2},
            "packed multiplication slot folds");
    }
    slot.logical_rounds = slot_vars;
    add_scaled(slot.round_extension_values, Count{2}, slot_vars,
               "packed multiplication slot round values");
    slot.aligned_round_ciphertexts = slot_vars;

    // The terminal carries both fully bound source values.
    add_online_extension_plain_multiplications(
        cost, Count{2}, "packed multiplication terminal bindings");
    add_scaled(cost.extension_rotations, Count{2}, slot_vars,
               "packed multiplication terminal rotations");
    add_scaled(cost.extension_additions, Count{2}, slot_vars,
               "packed multiplication terminal additions");

    add_round_encoding(
        cost,
        checked_add(wire_vars, slot_vars,
                    "packed multiplication rounds"),
        Count{2});
    return result;
}

ScheduleLayerFormula
folded_multiplication_layer(const payload::LayeredCircuit &circuit,
                            std::size_t layer,
                            const payload::LayerWireSupport &support,
                            const payload::LayerStorageLayout &storage,
                            const payload::LayerTraceValueCounts &counts) {
    return dense_packed_multiplication_layer(
        circuit, layer, false, support, storage, counts);
}

packing::LanedPackingLayout
laned_layout(const payload::LayeredCircuit &circuit, std::size_t layer) {
    return packing::LanedPackingLayout::create(
        circuit.shape,
        payload::layer_dimensions(circuit.layers.at(layer)).padded_size);
}

ScheduleLayerFormula laned_affine_layer(const payload::LayeredCircuit &circuit,
                                        std::size_t layer,
                                        const payload::LayerWireSupport
                                            &source_support,
                                        const payload::LayerTraceValueCounts
                                            &source_counts) {
    const packing::LanedPackingLayout source =
        laned_layout(circuit, layer + 1);
    const std::vector<std::size_t> packed_indices =
        materialized_packed_indices(source_support, source);
    const std::size_t variables =
        log2_exact(source.padded_ciphertext_count,
                   "Laned affine packed width") +
        log2_exact(source.slot_count, "Laned affine slot count");
    const Count original = as_count(source_support.live_wire_count,
                                    "Laned affine live ciphertexts");
    const Count ct_vars = as_count(
        log2_exact(source.padded_ciphertext_count,
                   "Laned affine packed width"),
        "Laned affine ciphertext variables");
    const Count slot_vars = as_count(
        log2_exact(source.slot_count, "Laned affine slot count"),
        "Laned affine slot variables");
    const Count rounds = as_count(variables, "Laned affine variables");
    ScheduleLayerFormula result;
    result.layer = layer;
    result.kind = payload::LayerKind::Affine;
    result.source_logical_live_wires = source_counts.logical_live_wires;
    result.source_stored_values = source_counts.stored_values;
    result.source_encrypted_ciphertexts =
        source_counts.encrypted_ciphertexts;
    result.source_virtual_wire_positions = source.original_wire_count;
    result.source_materialized_packed_ciphertexts = packed_indices.size();
    result.source_virtual_packed_positions =
        source.padded_ciphertext_count;
    result.reduction_domain_variables =
        log2_exact(source.padded_ciphertext_count,
                   "Laned affine packed width");
    result.slot_variables =
        log2_exact(source.slot_count, "Laned affine slot count");
    ScheduleOperations &cost = result.operations;
    const std::size_t chunks_per_ciphertext =
        source.chunks_per_ciphertext();
    std::vector<bool> rotating_chunks(chunks_per_ciphertext, false);
    for (const std::size_t wire : live_wire_indices(source_support)) {
        const std::size_t chunk = wire % chunks_per_ciphertext;
        if (chunk != 0U) {
            rotating_chunks[chunk] = true;
        }
    }
    const Count rotating_chunk_aggregates =
        static_cast<Count>(std::count(rotating_chunks.begin(),
                                      rotating_chunks.end(), true));
    const std::size_t ct_variables = static_cast<std::size_t>(ct_vars);
    const Count chunks = as_count(source.chunks_per_ciphertext(),
                                  "Laned affine lane-placement chunks");
    const bool materializes_packed_source =
        source.logical_ciphertext_count <=
        gkr::laned_detail::affine_detail::
            kLanedAffineMaterializedPackedCiphertextLimit;
    if (materializes_packed_source) {
        const Count packed = as_count(
            packed_indices.size(),
            "Laned affine materialized packed source values");

        // Place every B-periodic source into its S/N base-field ciphertext
        // once. Subsequent challenge-dependent work is a general Fpk SIMD
        // mask on each retained packed value, with no per-round source scan
        // or lane-placement rotation.
        if (chunks_per_ciphertext != 1U) {
            add(cost.witness_base_plain_multiplications, original,
                "Laned affine source packing products");
            add(cost.witness_base_additions, original - packed,
                "Laned affine source packing additions");
            Count source_rotations = 0;
            for (const std::size_t wire :
                 live_wire_indices(source_support)) {
                if (wire % chunks_per_ciphertext != 0U) {
                    ++source_rotations;
                }
            }
            add(cost.base_rotations, source_rotations,
                "Laned affine source packing rotations");
        }

        for (std::size_t bound = 1; bound <= ct_variables; ++bound) {
            const std::size_t bit = ct_variables - bound;
            const Count at_one = static_cast<Count>(std::count_if(
                packed_indices.begin(), packed_indices.end(),
                [&](std::size_t packed_index) {
                    return ((packed_index >> bit) & 1U) != 0U;
                }));
            const Count round_terms = checked_add(
                at_one, packed, "Laned affine packed round terms");
            add(cost.weighted_base_terms,
                round_terms, "Laned affine packed ciphertext terms");
            add(cost.online_vector_weighted_base_terms, round_terms,
                "Laned affine packed online SIMD terms");
            add(cost.weighted_base_accumulations,
                checked_add(nonempty_accumulations(at_one),
                            nonempty_accumulations(packed),
                            "Laned affine packed round additions"),
                "Laned affine packed ciphertext additions");
        }
        add_scaled(cost.extension_folds, Count{2}, ct_vars,
                   "Laned affine ciphertext folds");

        // One challenge-dependent checkpoint serves every slot round.
        add(cost.weighted_base_terms, packed,
            "Laned affine packed checkpoint terms");
        add(cost.online_vector_weighted_base_terms, packed,
            "Laned affine packed checkpoint online SIMD terms");
        add(cost.weighted_base_accumulations,
            nonempty_accumulations(packed),
            "Laned affine packed checkpoint additions");
    } else {
        // Wider packed domains retain the bounded streaming schedule. Each
        // ciphertext-index round starts from the B-periodic base trace and
        // applies one prepared lane-placement basis per nonempty chunk.
        for (std::size_t bound = 1; bound <= ct_variables; ++bound) {
            const Count at_one = live_at_domain_bit_one(
                source_support, ct_variables, bound,
                source.chunks_per_ciphertext());
            add(cost.weighted_base_terms,
                checked_add(at_one, original,
                            "Laned affine live round terms"),
                "Laned affine ciphertext terms");
            add_scaled(cost.extension_plain_multiplications, Count{2},
                       chunks,
                       "Laned affine prepared lane placements");
            add(cost.extension_additions,
                checked_add(nonempty_accumulations(at_one),
                            nonempty_accumulations(original),
                            "Laned affine live round additions"),
                "Laned affine ciphertext additions");
        }
        add_scaled(cost.extension_folds, Count{2}, ct_vars,
                   "Laned affine ciphertext folds");
        add_scaled(cost.extension_rotations, Count{2} * ct_vars,
                   rotating_chunk_aggregates,
                   "Laned affine ciphertext lane placements");

        add(cost.weighted_base_terms, original,
            "Laned affine checkpoint terms");
        add(cost.extension_plain_multiplications, chunks,
            "Laned affine checkpoint lane placements");
        add(cost.extension_rotations, rotating_chunk_aggregates,
            "Laned affine checkpoint lane placements");
        if (original > 1) {
            add(cost.extension_additions, original - 1,
                "Laned affine checkpoint additions");
        }
    }
        // The paired slot evaluator binds the existing prefix once, then
        // derives R(1) and R(2) from the shared partial checkpoint. It still
        // applies one public suffix mask to each transmitted value.
        if (slot_vars > 1U) {
            add_online_extension_plain_multiplications(
                cost, slot_vars - 1U,
                "Laned affine shared slot-prefix bindings");
            for (Count prefix = 1; prefix < slot_vars; ++prefix) {
                add(cost.extension_rotations, prefix,
                    "Laned affine prefix rotations");
                add(cost.extension_additions, prefix,
                    "Laned affine prefix additions");
            }
        }
        add(cost.extension_rotations, slot_vars,
            "Laned affine sibling rotations");
        add(cost.extension_additions, slot_vars,
            "Laned affine extrapolation additions");
        add(cost.extension_subtractions, slot_vars,
            "Laned affine extrapolation subtractions");
        const Count slot_evaluations = checked_add(
            checked_mul(Count{2}, slot_vars,
                        "Laned affine slot evaluations"),
            Count{1}, "Laned affine terminal evaluation");
        add_online_extension_plain_multiplications(
            cost, checked_add(checked_mul(Count{2}, slot_vars,
                                         "Laned affine slot masks"),
                              Count{1},
                              "Laned affine terminal mask"),
            "Laned affine checkpoint weighting");
        add(cost.extension_folds, slot_evaluations,
            "Laned affine checkpoint folds");
    add_round_encoding(cost, rounds, Count{1});
    return result;
}

ScheduleLayerFormula
laned_multiplication_layer(const payload::LayeredCircuit &circuit,
                           std::size_t layer,
                           const payload::LayerWireSupport &support,
                           const payload::LayerStorageLayout &storage,
                           const payload::LayerTraceValueCounts &counts) {
    return dense_packed_multiplication_layer(
        circuit, layer, true, support, storage, counts);
}

void finish_formula(ScheduleFormula &formula) {
    for (const ScheduleLayerFormula &layer : formula.layers) {
        accumulate(formula.operations, layer.operations);
        accumulate(formula.multiplication_slot_rounds,
                   layer.multiplication_slot_rounds);
    }
}

} // namespace

ScheduleFormula
folded_schedule_formula(const payload::LayeredCircuit &circuit) {
    circuit.validate();
    if (circuit.shape.kind != payload::PayloadKind::Wide ||
        circuit.shape.slot_count < 2 * kExtensionDegree) {
        throw std::invalid_argument(
            "folded_schedule_formula requires a wide circuit with N >= 16");
    }
    ScheduleFormula result;
    result.protocol = ScheduleProtocol::Folded;
    result.layers.reserve(circuit.layers.size() - 1);
    const payload::CanonicalTraceLayout trace =
        payload::canonical_trace_layout(circuit);
    for (std::size_t layer = 0; layer + 1 < circuit.layers.size(); ++layer) {
        if (payload::layer_kind(circuit.layers[layer]) ==
            payload::LayerKind::Affine) {
            result.layers.push_back(folded_affine_layer(
                circuit, layer, trace.wire_support[layer + 1U],
                trace.value_counts[layer + 1U]));
        } else {
            result.layers.push_back(
                folded_multiplication_layer(
                    circuit, layer, trace.wire_support[layer + 1U],
                    trace.storage[layer + 1U],
                    trace.value_counts[layer + 1U]));
        }
    }
    finish_formula(result);
    return result;
}

ScheduleFormula laned_schedule_formula(const payload::LayeredCircuit &circuit) {
    circuit.validate();
    if (circuit.shape.kind != payload::PayloadKind::Laned ||
        circuit.shape.slot_count < 2 * kExtensionDegree) {
        throw std::invalid_argument(
            "laned_schedule_formula requires a laned circuit with N >= 16");
    }
    ScheduleFormula result;
    result.protocol = ScheduleProtocol::Laned;
    result.layers.reserve(circuit.layers.size() - 1);
    const payload::CanonicalTraceLayout trace =
        payload::canonical_trace_layout(circuit);
    for (std::size_t layer = 0; layer + 1 < circuit.layers.size(); ++layer) {
        if (payload::layer_kind(circuit.layers[layer]) ==
            payload::LayerKind::Affine) {
            result.layers.push_back(laned_affine_layer(
                circuit, layer, trace.wire_support[layer + 1U],
                trace.value_counts[layer + 1U]));
        } else {
            result.layers.push_back(
                laned_multiplication_layer(
                    circuit, layer, trace.wire_support[layer + 1U],
                    trace.storage[layer + 1U],
                    trace.value_counts[layer + 1U]));
        }
    }
    finish_formula(result);
    return result;
}

ConcretePrimitiveUpperBound concrete_primitive_upper_bound(
    const ScheduleOperations &operations, std::size_t slot_count) {
    const Count extension = as_count(kExtensionDegree, "extension degree");
    const Count slot_variables =
        as_count(log2_exact(slot_count, "formula slot count"),
                 "slot variables");
    const Count extension_square =
        checked_mul(extension, extension, "extension square");

    // A dense degree-eight product has R^2 products, R^2-(2R-1)
    // convolution additions, then two negations/additions for each of the
    // R-1 high coefficients under x^R + x^3 + 1.
    const Count two_extension_minus_one =
        checked_mul(Count{2}, extension, "extension convolution width") - 1;
    const Count high_coefficients = extension - 1;
    const Count reduction_additions = checked_add(
        extension_square - two_extension_minus_one,
        checked_mul(Count{2}, high_coefficients,
                    "extension reduction additions"),
        "extension product additions");
    const Count reduction_negations =
        checked_mul(Count{2}, high_coefficients,
                    "extension reduction negations");
    const Count extension_products = checked_add(
        operations.extension_plain_multiplications,
        operations.extension_ciphertext_multiplications,
        "extension products");

    ConcretePrimitiveUpperBound result;
    add_scaled(result.plain_multiplications,
               operations.weighted_base_terms, extension,
               "weighted base plaintext multiplications");
    add_scaled(result.plain_multiplications,
               operations.extension_plain_multiplications,
               extension_square, "extension plaintext multiplications");
    add_scaled(result.plain_multiplications,
               operations.prepared_base_slot_extension_multiplications,
               extension,
               "prepared base-slot extension multiplications");
    add(result.plain_multiplications,
        operations.witness_base_plain_multiplications,
        "witness plaintext multiplications");
    add_scaled(result.plain_multiplications,
               operations.round_extension_values, extension,
               "BhIP round-encoding plaintext multiplications");

    add_scaled(result.online_vector_plain_multiplications,
               operations.online_vector_weighted_base_terms, extension,
               "online vector weighted-base multiplications");
    add_scaled(result.online_vector_plain_multiplications,
               operations.online_vector_extension_plain_multiplications,
               extension_square,
               "online vector extension plaintext multiplications");
    add_scaled(result.online_vector_plaintext_preparations,
               operations.online_vector_weighted_base_terms, extension,
               "online vector weighted-base preparations");
    add_scaled(result.online_vector_plaintext_preparations,
               operations.online_vector_extension_plain_multiplications,
               extension,
               "online vector extension plaintext preparations");
    if (result.online_vector_plain_multiplications >
        result.plain_multiplications) {
        throw std::logic_error(
            "online vector plaintext products exceed all plaintext products");
    }

    result.ciphertext_multiplications_no_relinearization = checked_add(
        operations.base_ciphertext_multiplications,
        checked_mul(operations.extension_ciphertext_multiplications,
                    extension_square,
                    "extension ciphertext multiplications"),
        "ciphertext multiplications");
    result.relinearizations = checked_mul(
        operations.extension_relinearizations, extension,
        "relinearizations");
    result.negations = checked_mul(extension_products, reduction_negations,
                                   "extension negations");
    add(result.negations, operations.base_negations,
        "direct base negations");

    add_scaled(result.additions, operations.weighted_base_accumulations,
               extension, "weighted base additions");
    add(result.additions, operations.base_additions,
        "direct base additions");
    add_scaled(result.additions, operations.extension_additions, extension,
               "extension additions");
    add_scaled(result.additions, extension_products, reduction_additions,
               "extension product additions");
    add_scaled(result.additions, operations.extension_folds,
               checked_mul(extension, slot_variables,
                           "fold base additions"),
               "fold additions");
    add(result.additions, operations.witness_base_additions,
        "witness base additions");
    const Count round_encoding_terms = checked_mul(
        operations.round_extension_values, extension,
        "BhIP round-encoding additions");
    if (round_encoding_terms < operations.aligned_round_ciphertexts) {
        throw std::logic_error(
            "aligned BhIP round ciphertext count is malformed");
    }
    add(result.additions,
        round_encoding_terms - operations.aligned_round_ciphertexts,
        "BhIP round-encoding additions");
    result.subtractions = operations.base_subtractions;

    const Count rotations_per_extension = checked_add(
        operations.extension_rotations,
        checked_mul(operations.extension_folds, slot_variables,
                    "fold rotations"),
        "extension rotations");
    result.rotations = checked_mul(rotations_per_extension, extension,
                                   "base rotations");
    add(result.rotations, operations.base_rotations,
        "direct base rotations");
    return result;
}

FormulaComparisonStatus compare_measured_to_upper_bound(
    Count measured, Count upper_bound) {
    if (measured > upper_bound) {
        return FormulaComparisonStatus::Investigate;
    }
    return measured == upper_bound ? FormulaComparisonStatus::Match
                                   : FormulaComparisonStatus::ExpectedDelta;
}

std::string_view comparison_status_name(FormulaComparisonStatus status) {
    switch (status) {
    case FormulaComparisonStatus::Match:
        return "MATCH";
    case FormulaComparisonStatus::ExpectedDelta:
        return "EXPECTED_DELTA";
    case FormulaComparisonStatus::Investigate:
        return "INVESTIGATE";
    }
    throw std::logic_error("unknown formula comparison status");
}

std::string_view schedule_protocol_name(ScheduleProtocol protocol) {
    switch (protocol) {
    case ScheduleProtocol::Base:
        return "base";
    case ScheduleProtocol::Folded:
        return "folded";
    case ScheduleProtocol::Laned:
        return "laned";
    }
    throw std::logic_error("unknown schedule protocol");
}

} // namespace laminate::bench
