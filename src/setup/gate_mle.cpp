#include "laminate/setup/gate_mle.hpp"
#include "laminate/basefold/soundness.hpp"
#include "laminate/gates/gate_mle.hpp"
#include "laminate/gates/wide_opening.hpp"
#include "laminate/gkr/challenge_limits.hpp"
#include "laminate/field/serialization.hpp"

#include <algorithm>
#include <bit>
#include <limits>
#include <stdexcept>
#include <utility>

namespace laminate {
namespace {

std::uint64_t checked_add(std::uint64_t left, std::uint64_t right,
                          const char *label) {
    if (right > std::numeric_limits<std::uint64_t>::max() - left) {
        throw std::overflow_error(label);
    }
    return left + right;
}

std::uint64_t checked_multiply(std::uint64_t left, std::uint64_t right,
                               const char *label) {
    if (left != 0 &&
        right > std::numeric_limits<std::uint64_t>::max() / left) {
        throw std::overflow_error(label);
    }
    return left * right;
}

std::uint64_t log2_power_of_two(std::uint64_t value, const char *label) {
    if (value == 0 || (value & (value - 1U)) != 0) {
        throw std::invalid_argument(label);
    }
    std::uint64_t result = 0;
    while (value > 1U) {
        value >>= 1U;
        ++result;
    }
    return result;
}

std::size_t total_sparse_support(const gates::GateTableLayout &layout) {
    std::size_t result = 0;
    for (const gates::GateTableDescriptor &table : layout.tables) {
        if (table.support_size >
            std::numeric_limits<std::size_t>::max() - result) {
            throw std::overflow_error(
                "restore_gate_mle_prover_key: sparse support overflows");
        }
        result += table.support_size;
    }
    return result;
}

GateMleProverResourceBounds wide_resource_bounds(
    const GateMlePreprocessingPlan &key) {
    GateMleProverResourceBounds result;
    const auto add = [](std::uint64_t a, std::uint64_t b) {
        return checked_add(a, b, "Wide GateMLE resource bound overflows");
    };
    const auto mul = [](std::uint64_t a, std::uint64_t b) {
        return checked_multiply(a, b, "Wide GateMLE resource bound overflows");
    };
    const auto layers = std::max<std::size_t>(1, key.layout.wide_layers.size());
    const auto targets = mul(24, layers);
    const auto queries = key.foldable_parameters.num_queries;
    // Bound compact multiproofs by separate deepest authentication paths.
    // This deliberately allows duplicate paths; actual shared frontiers are
    // smaller. Canonical framing, field values and in-memory vector objects
    // are covered together so the same cap admits decoding and proving.
    const auto opening_bytes = [&](std::size_t m, std::size_t width,
                                   std::uint64_t operands) {
        const auto depth = add(m, basefold::foldable::kLogRate);
        const auto per_query = add(
            mul(add(width, add(m, 1)), 2U * sizeof(Fpk) + 128U),
            mul(mul(2U, mul(add(m, 1), depth)), sizeof(basefold::Digest)));
        return add(mul(queries, per_query),
            add(mul(mul(operands, width), 2U * sizeof(Fpk)), 1U << 20U));
    };
    result.proof_bytes_upper_bound = 256;
    result.retained_prover_key_disk_bytes = 4096;
    if (key.wide_public_message_size != 0) {
        const auto message_size = key.wide_public_message_size;
        std::uint64_t public_operands = 0;
        for (std::size_t i = 0; i < key.tables.size(); ++i) {
            const auto &table = key.tables[i];
            const auto requests = key.layout.tables[i].kind == gates::GateTableKind::WideMaskDictionary
                ? targets : 24;
            public_operands = add(public_operands, mul(requests,
                std::min(table.physical_width, message_size / table.message_size)));
        }
        result.retained_prover_key_disk_bytes = add(result.retained_prover_key_disk_bytes,
            basefold::foldable::retained_commitment_disk_bound(message_size, key.wide_public_width));
        result.opening_workspace_disk_bytes =
            basefold::foldable::proving_disk_bound(message_size, public_operands, false);
        // Each distinct row interval becomes one transparent operand. The
        // full operand-by-column target matrix remains live through the PCS.
        result.proof_bytes_upper_bound = add(result.proof_bytes_upper_bound,
            opening_bytes(log2_power_of_two(message_size, "invalid Wide public size"),
                          key.wide_public_width, public_operands));
        result.opening_workspace_bytes = mul(mul(public_operands, key.wide_public_width),
                                             2U * sizeof(Fpk));
    }
    for (std::size_t i = 0; i < key.tables.size(); ++i) {
        const auto &table = key.tables[i];
        const auto &descriptor = key.layout.tables.at(i);
        const auto width = table.logical_width;
        result.retained_prover_key_disk_bytes = add(result.retained_prover_key_disk_bytes,
            mul(descriptor.support_size, 11));
        result.retained_prover_key_bytes = add(result.retained_prover_key_bytes,
            add(mul(descriptor.support_size, sizeof(gates::sparse::SparseEntry)),
                mul(width, 4096)));
        // Local sparse products retain address/value trees and small target
        // matrices. The shared scalar commitment and its folds stay on disk.
        result.opening_workspace_bytes = std::max(result.opening_workspace_bytes,
            add(mul(mul(table.message_size, width), 2U * sizeof(Fpk)),
                mul(mul(targets, width), 2U * sizeof(Fpk))));
        result.proof_bytes_upper_bound = add(result.proof_bytes_upper_bound,
                                             mul(targets, 1U << 20U));
    }
    std::vector<std::size_t> trace_sizes;
    for (const auto &layer : key.layout.wide_layers) {
        trace_sizes.push_back(layer.node_count ? layer.dimensions.internal_scalars : 0);
        if (layer.node_count == 0) continue;
        // Two recorded GKR claims add one internal residual column.
        result.proof_bytes_upper_bound = add(result.proof_bytes_upper_bound,
                                             12U << 20U);
        result.retained_prover_key_bytes = add(result.retained_prover_key_bytes,
            mul(layer.node_count, 256));
        result.opening_workspace_bytes = std::max(result.opening_workspace_bytes,
            mul(layer.dimensions.slots, 16U * sizeof(Fpk)));
    }
    for (const auto &group : gates::wide_adjoint_group_layout(trace_sizes)) {
        const auto cells = group.message_size;
        const auto source = mul(cells, 24U);
        const auto retained = basefold::foldable::retained_commitment_disk_bound(cells, 1);
        const auto persistent = add(source, retained);
        const auto operands = mul(2, group.trace_indices.size());
        // A group lives only until its PCS is opened. Within the group, each
        // member's three operator columns and six quadratic scratch arrays
        // are retired before the next member starts.
        const auto commit_peak = add(source,
            basefold::foldable::commitment_disk_bound(cells, 1));
        const auto pcs_peak = add(persistent,
            basefold::foldable::proving_disk_bound(cells, operands, true));
        const auto local_peak = add(persistent, mul(group.block_size, 9U * 24U));
        result.opening_workspace_disk_bytes = std::max({
            result.opening_workspace_disk_bytes, commit_peak, pcs_peak, local_peak});
        result.proof_bytes_upper_bound = add(result.proof_bytes_upper_bound,
            opening_bytes(log2_power_of_two(cells, "invalid Wide group size"),
                          1, operands));
    }
    // Includes the at-most-64-MiB diagonal cache and bounded encoding buffers.
    constexpr std::uint64_t slack = 256ULL << 20U;
    result.retained_prover_key_bytes = add(result.retained_prover_key_bytes, slack);
    result.opening_workspace_bytes = add(result.opening_workspace_bytes,
        add(result.proof_bytes_upper_bound, slack));
    return result;
}

} // namespace

std::uint64_t affine_gate_preparation_workspace_bytes(
    const payload::LayeredCircuit &circuit) {
    if (circuit.shape.kind != payload::PayloadKind::Wide) return 0;
    const gates::DirectGateMle provider(circuit);
    // Compilation and GKR preparation happen in separate phases. Include the
    // compiler's simultaneously live local/composed rows in the same admission
    // envelope, including restore-time layout validation.
    std::uint64_t maximum =
        gates::wide_program_composition_workspace_bound(circuit);
    for (std::size_t layer = 0; layer + 1 < circuit.layers.size(); ++layer) {
        const auto *affine = std::get_if<payload::AffineLayer>(&circuit.layers[layer]);
        if (!affine) continue;
        const auto structure = provider.affine_structure(layer);
        const auto add = [](std::uint64_t a, std::uint64_t b) {
            return checked_add(a, b, "affine preparation RAM bound overflows");
        };
        const auto mul = [](std::uint64_t a, std::uint64_t b) {
            return checked_multiply(a, b, "affine preparation RAM bound overflows");
        };
        // Conservatively retain an extra basis family, although current GKR
        // carries one claim. Four vectors cover equality/contraction buffers.
        const auto basis_vectors = add(add(structure.peak_live_slot_basis_count,
                                           structure.slot_basis_count), 4);
        auto bytes = mul(mul(basis_vectors, circuit.shape.value_width()), sizeof(Fpk));
        const auto sources = payload::layer_dimensions(circuit.layers[layer + 1]).padded_size;
        const auto nodes = add(sources, affine->intermediate_gates.size());
        // At most eight map components per node, with 256 bytes each covering
        // coefficient, shared pointer, tree-node links, and allocator overhead.
        // Transform-cache entries are bounded by eight times local edge count.
        std::uint64_t edges = 0;
        for (const auto &node : affine->intermediate_gates) edges = add(edges, node.terms.size());
        for (const auto &node : affine->gates) edges = add(edges, node.terms.size());
        bytes = add(bytes, mul(nodes, 8U * 256U));
        bytes = add(bytes, mul(edges, 8U * 128U));
        bytes = add(bytes, mul(structure.terms.size(), 2U * 256U));
        bytes = add(bytes, mul(affine->dimensions.padded_size, sizeof(Fpk)));
        maximum = std::max(maximum, bytes);
    }
    return maximum;
}

namespace {

std::size_t planned_basefold_soundness_bits(
    const GateMlePreprocessingPlan &key) {
    const auto &parameters = key.basefold_parameters;
    if (basefold::conservative_rbr_soundness_bound(
            0, 0, parameters.log_rate, parameters.num_queries,
            16U * kExtensionDegree).rbr_bits == 0) {
        return 0;
    }
    if (key.layout.table_set == gates::GateTableSet::Wide) {
        if (!basefold::foldable::valid_shape(
                basefold::foldable::Metadata{.m = 1, .width = 1},
                key.foldable_parameters)) return 0;
        std::vector<std::size_t> trace_sizes;
        for (const auto &layer : key.layout.wide_layers) {
            if (!std::has_single_bit(layer.dimensions.internal_scalars) ||
                std::bit_width(layer.dimensions.internal_scalars) - 1U >
                    basefold::foldable::kMaxVariables) return 0;
            trace_sizes.push_back(layer.node_count ? layer.dimensions.internal_scalars : 0);
        }
        for (const auto &group : gates::wide_adjoint_group_layout(trace_sizes)) {
            if (!basefold::foldable::valid_shape(
                    {.m = group.message_size, .width = 1}, key.foldable_parameters))
                return 0;
        }
        return basefold::foldable::conservative_rbr_soundness_bits(
            basefold::foldable::Metadata{.m = 1, .width = 1},
            key.foldable_parameters,
            basefold::foldable::CommitmentPremise::HonestCodewordColumns);
    }
    // With valid parameters, an empty table set has no PCS transitions.
    std::size_t minimum_bits = std::numeric_limits<std::size_t>::max();
    for (const auto &table : key.tables) {
        if (!std::has_single_bit(table.shard_size) ||
            !std::has_single_bit(table.physical_width)) {
            return 0;
        }
        const auto bound = basefold::conservative_rbr_soundness_bound(
            std::bit_width(table.shard_size) - 1U,
            basefold::ceil_log2_count(table.physical_width) + 1U,
            parameters.log_rate, parameters.num_queries,
            16U * kExtensionDegree);
        minimum_bits = std::min(minimum_bits, bound.rbr_bits);
    }
    return minimum_bits;
}

GateMleProverResourceBounds planned_resource_bounds(
    const GateMlePreprocessingPlan &key) {
    if (key.layout.tables.size() != key.tables.size() ||
        key.basefold_parameters.log_rate > kBaseFieldTwoAdicity ||
        key.basefold_parameters.num_queries == 0) {
        throw std::invalid_argument(
            "gate_mle_prover_resource_bounds: malformed verifier key");
    }
    if (key.layout.table_set == gates::GateTableSet::Wide)
        return wide_resource_bounds(key);
    const std::uint64_t rate =
        std::uint64_t{1} << key.basefold_parameters.log_rate;
    const std::uint64_t query_count =
        static_cast<std::uint64_t>(key.basefold_parameters.num_queries);
    GateMleProverResourceBounds result;
    // The outer label and vector-count framing remain present even when
    // there are no compact tables or online claims.
    result.proof_bytes_upper_bound = 256U;
    result.retained_prover_key_disk_bytes = 4096;
    for (std::size_t selector = 0; selector < key.tables.size();
         ++selector) {
        const gates::SparseTableShape &table = key.tables[selector];
        const gates::GateTableDescriptor &descriptor =
            key.layout.tables[selector];
        const std::uint64_t message_cells = checked_multiply(
            table.physical_width, table.shard_size,
            "GateMLE message-cell count overflows");
        const std::uint64_t codeword_cells = checked_multiply(
            message_cells, rate, "GateMLE codeword-cell count overflows");
        const std::uint64_t codeword_rows = checked_multiply(
            table.shard_size, rate, "GateMLE codeword rows overflow");
        const std::uint64_t message_variables = log2_power_of_two(
            table.shard_size, "GateMLE shard size is not a power of two");
        const std::uint64_t codeword_depth = checked_add(
            message_variables, key.basefold_parameters.log_rate,
            "GateMLE codeword depth overflows");
        const std::uint64_t field_storage = checked_multiply(
            checked_add(message_cells, codeword_cells,
                        "GateMLE field storage overflows"),
            sizeof(Fp), "GateMLE field storage overflows");
        const std::uint64_t merkle_storage = checked_multiply(
            checked_multiply(2U, codeword_rows,
                             "GateMLE Merkle-node count overflows"),
            basefold::Digest{}.size(),
            "GateMLE Merkle storage overflows");
        const std::uint64_t sparse_entries = checked_multiply(
            descriptor.support_size, sizeof(gates::sparse::SparseEntry),
            "GateMLE sparse-entry storage overflows");
        result.retained_prover_key_disk_bytes = checked_add(
            result.retained_prover_key_disk_bytes,
            checked_add(checked_multiply(checked_add(message_cells, codeword_cells,
                "GateMLE persisted cells"), kSerializedFpBytes, "GateMLE persisted fields"),
                checked_add(merkle_storage, checked_multiply(descriptor.support_size, 11,
                    "GateMLE persisted entries"), "GateMLE persisted metadata"),
                "GateMLE persisted table"), "GateMLE persisted key");
        result.retained_prover_key_bytes = checked_add(
            result.retained_prover_key_bytes,
            checked_add(
                checked_add(field_storage, merkle_storage,
                            "GateMLE retained table overflows"),
                sparse_entries, "GateMLE retained table overflows"),
            "GateMLE retained key overflows");

        const std::uint64_t product_tree = checked_multiply(
            checked_multiply(table.message_size, table.logical_width,
                             "GateMLE product leaves overflow"),
            2U * sizeof(Fpk), "GateMLE product tree overflows");
        const std::uint64_t basefold_workspace = checked_multiply(
            checked_add(
                checked_multiply(table.shard_size, 4U,
                                 "GateMLE operands overflow"),
                checked_multiply(codeword_rows, 2U,
                                 "GateMLE folds overflow"),
                "GateMLE BaseFold workspace overflows"),
            sizeof(Fpk), "GateMLE BaseFold workspace overflows");

        // Keep a conservative allowance of two target rows for independent
        // gate-query callers. Current GKR contributes one row per compact
        // polynomial; physical-leaf linearizations coexist with target rows.
        constexpr std::uint64_t kMaximumRowsPerTable = 2U;
        const std::uint64_t target_and_linearization_cells =
            checked_multiply(
                checked_multiply(
                    table.physical_width, kMaximumRowsPerTable,
                    "GateMLE target-matrix cells overflow"),
                2U,
                "GateMLE target/linearization matrix cells overflow");
        const std::uint64_t target_and_linearization_storage =
            checked_multiply(
                target_and_linearization_cells, sizeof(Fpk),
                "GateMLE target/linearization matrix storage overflows");

        // Every BaseFold spot query copies both halves of one interleaved
        // physical leaf into the proof.  This q * width term can dominate a
        // highly sharded compact table even though its message is small.
        const std::uint64_t query_leaf_cells = checked_multiply(
            checked_multiply(query_count, table.physical_width,
                             "GateMLE query-leaf cells overflow"),
            2U, "GateMLE query-leaf cells overflow");
        const std::uint64_t query_leaf_storage = checked_multiply(
            query_leaf_cells, sizeof(Fp),
            "GateMLE query-leaf storage overflows");

        // Query openings additionally retain FRI fold values, every Merkle
        // authentication path, and their nested vector objects.  Bound each
        // possible opened layer by the deepest (base-codeword) path.  This is
        // deliberately loose but remains q-scaled for arbitrary parameters.
        const std::uint64_t opened_layers = checked_add(
            message_variables, 1U,
            "GateMLE query opened-layer count overflows");
        const std::uint64_t query_path_digests = checked_multiply(
            checked_multiply(
                checked_multiply(query_count, 2U,
                                 "GateMLE query path count overflows"),
                opened_layers, "GateMLE query path count overflows"),
            codeword_depth, "GateMLE query path depth overflows");
        const std::uint64_t query_path_storage = checked_multiply(
            query_path_digests, basefold::Digest{}.size(),
            "GateMLE query path storage overflows");
        const std::uint64_t fold_count =
            message_variables == 0 ? 0 : message_variables - 1U;
        const std::uint64_t query_object_storage = checked_add(
            checked_multiply(
                query_count, sizeof(basefold::QueryOpening),
                "GateMLE query-object storage overflows"),
            checked_multiply(
                checked_multiply(query_count, fold_count,
                                 "GateMLE fold-opening count overflows"),
                sizeof(basefold::FoldOpening),
                "GateMLE fold-opening storage overflows"),
            "GateMLE query-object storage overflows");
        const std::uint64_t query_sampling_storage = checked_add(
            checked_multiply(query_count, sizeof(std::size_t),
                             "GateMLE query-index storage overflows"),
            checked_multiply(query_count, codeword_depth,
                             "GateMLE challenge-bit storage overflows"),
            "GateMLE query-sampling storage overflows");
        const std::uint64_t query_storage = checked_add(
            checked_add(query_leaf_storage, query_path_storage,
                        "GateMLE query-proof storage overflows"),
            checked_add(query_object_storage, query_sampling_storage,
                        "GateMLE query-proof storage overflows"),
            "GateMLE query-proof storage overflows");

        // sizeof(field) is at least its canonical encoding width. Bound each
        // authentication path by the original codeword depth and every fold
        // by two extension values; all nested vector/index framing is covered
        // by 128 bytes per opened layer. The fixed allowance covers the
        // action and logarithmic sparse-product proofs, labels and targets'
        // vector framing for two claims per table (address widths <= 64).
        const std::uint64_t query_encoding = checked_add(
            checked_add(query_leaf_storage / query_count,
                        checked_multiply(
                            opened_layers, 2U * sizeof(Fpk) + 128U,
                            "GateMLE query field/framing cap overflows"),
                        "GateMLE query encoding cap overflows"),
            checked_multiply(
                checked_multiply(2U * opened_layers, codeword_depth,
                                 "GateMLE query path cap overflows"),
                basefold::Digest{}.size(),
                "GateMLE query digest cap overflows"),
            "GateMLE query encoding cap overflows");
        const std::uint64_t opening_encoding = checked_add(
            checked_add(
                checked_multiply(3U * message_variables + 2U + rate,
                                 sizeof(Fpk),
                                 "GateMLE fixed field cap overflows"),
                checked_add(
                    checked_multiply(fold_count, basefold::Digest{}.size(),
                                     "GateMLE root cap overflows"),
                    128U, "GateMLE fixed framing cap overflows"),
                "GateMLE opening cap overflows"),
            checked_multiply(query_count, query_encoding,
                             "GateMLE queries cap overflows"),
            "GateMLE opening cap overflows");
        const std::uint64_t table_encoding = checked_add(
            checked_add(target_and_linearization_storage, 1ULL << 20U,
                        "GateMLE reduction cap overflows"),
            opening_encoding,
            "GateMLE table proof cap overflows");
        result.proof_bytes_upper_bound = checked_add(
            result.proof_bytes_upper_bound, table_encoding,
            "GateMLE total proof cap overflows");
        const std::uint64_t opening_storage = checked_add(
            checked_add(product_tree, basefold_workspace,
                        "GateMLE opening workspace overflows"),
            checked_add(target_and_linearization_storage,
                        query_storage,
                        "GateMLE proof workspace overflows"),
            "GateMLE opening workspace overflows");
        result.opening_workspace_bytes = std::max(
            result.opening_workspace_bytes, opening_storage);
    }
    constexpr std::uint64_t kAllocatorSlack = 256ULL << 20U;
    result.retained_prover_key_bytes = checked_add(
        result.retained_prover_key_bytes, kAllocatorSlack,
        "GateMLE retained-key allowance overflows");
    result.opening_workspace_bytes = checked_add(
        checked_add(result.opening_workspace_bytes,
                    result.proof_bytes_upper_bound,
                    "GateMLE retained proof allowance overflows"),
        kAllocatorSlack,
        "GateMLE opening allowance overflows");
    return result;
}

GateMlePreprocessingPlan resource_geometry(
    const gates::GateTableVerifierKey &key) {
    GateMlePreprocessingPlan result;
    result.layout = key.layout;
    result.basefold_parameters = key.basefold_parameters;
    result.foldable_parameters = key.foldable_parameters;
    result.wide_public_message_size = key.wide_public_commitment
        ? key.wide_public_commitment->m : 0;
    result.wide_public_width = key.wide_public_commitment
        ? key.wide_public_commitment->width : 0;
    result.tables.reserve(key.tables.size());
    for (const auto &table : key.tables)
        result.tables.push_back({table.message_size, table.shard_size,
            table.shard_count, table.logical_width, table.physical_width});
    return result;
}

} // namespace

std::size_t gate_mle_basefold_soundness_bits(
    const gates::GateTableVerifierKey &key) {
    if (key.layout.table_set == gates::GateTableSet::Wide &&
        !gates::valid_wide_public_index(key)) return 0;
    return planned_basefold_soundness_bits(resource_geometry(key));
}

GateMleProverResourceBounds gate_mle_prover_resource_bounds(
    const gates::GateTableVerifierKey &key) {
    if (key.layout.table_set == gates::GateTableSet::Wide &&
        !gates::valid_wide_public_index(key))
        throw std::invalid_argument("malformed Wide GateMLE index");
    return planned_resource_bounds(resource_geometry(key));
}

GateMlePreprocessingPlan plan_gate_mle_preprocessing(
    const payload::LayeredCircuit &circuit,
    gates::GateTableSet table_set,
    const gates::GateTableBuildOptions &options) {
    gkr::validate_challenge_dimensions(circuit);
    if (options.preprocessing_threads == 0 ||
        options.preprocessing_threads > 256 ||
        (table_set != gates::GateTableSet::Wide &&
         options.preprocessing_threads != 1))
        throw std::invalid_argument(
            "parallel gate preprocessing requires Wide tables and 1..256 workers");
    if (table_set == gates::GateTableSet::Wide &&
        (!basefold::foldable::valid_shape({.m = 1, .width = 1},
                                         options.foldable_parameters) ||
         options.wide_resources.block_elements == 0 ||
         options.wide_resources.block_elements > 65536 ||
         options.wide_resources.diagonal_cache_bytes > (64ULL << 20)))
        throw std::invalid_argument("invalid Wide foldable planning parameters");
    GateMlePreprocessingPlan result;
    result.layout = gates::make_gate_table_layout(
        circuit, table_set, options.basefold_parameters);
    result.basefold_parameters = options.basefold_parameters;
    result.foldable_parameters = options.foldable_parameters;
    const auto entries = total_sparse_support(result.layout);
    if (entries > options.max_message_entries)
        throw std::length_error(
            "preprocess_gate_tables: compact sparse support exceeds the configured limit");
    result.tables.reserve(result.layout.tables.size());
    for (const auto &table : result.layout.tables)
        result.tables.push_back(gates::plan_sparse_table_shape(
            table, table_set, options.basefold_parameters));
    if (table_set == gates::GateTableSet::Wide) {
        if (entries > 4096 && (options.wide_scratch_parent.empty() ||
                              options.wide_max_disk_bytes == 0))
            throw std::invalid_argument(
                "Wide GateMLE requires an explicit scratch parent and total disk budget "
                "outside bounded reference instances");
        const auto blocks = gates::make_wide_public_blocks(result.layout);
        if (!blocks.empty()) {
            const auto shape = gates::plan_wide_public_commitment(result.layout);
            result.wide_public_message_size = shape.m;
            result.wide_public_width = shape.width;
            if (!basefold::foldable::valid_shape(
                    {.m = result.wide_public_message_size, .width = result.wide_public_width},
                    options.foldable_parameters))
                throw std::invalid_argument("invalid Wide public foldable geometry");
            result.commitment_peak_disk_bytes =
                basefold::foldable::commitment_disk_bound(
                    result.wide_public_message_size, result.wide_public_width);
        }
        const auto disk_cap = options.wide_max_disk_bytes
            ? options.wide_max_disk_bytes : (std::uint64_t{1} << 30);
        if (result.commitment_peak_disk_bytes > disk_cap)
            throw std::length_error("Wide GateMLE index exceeds disk budget");
    }
    result.resources = planned_resource_bounds(result);
    if (table_set == gates::GateTableSet::Wide && result.commitment_peak_disk_bytes)
        result.commitment_peak_disk_bytes = checked_add(result.commitment_peak_disk_bytes,
            checked_add(4096, checked_multiply(entries, 11, "GateMLE cache entries"),
                "GateMLE cache metadata"), "GateMLE setup disk peak");
    if (table_set == gates::GateTableSet::Wide &&
        result.commitment_peak_disk_bytes > (options.wide_max_disk_bytes
            ? options.wide_max_disk_bytes : (std::uint64_t{1} << 30)))
        throw std::length_error("Wide GateMLE persisted index exceeds disk budget");
    result.basefold_soundness_bits = planned_basefold_soundness_bits(result);
    return result;
}

OutsourcedGateMleSetupArtifacts preprocess_outsourced_gate_mle_setup(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    gates::GateTableSet table_set,
    const gates::GateTableBuildOptions &options) {
    gkr::validate_challenge_dimensions(circuit);
    auto prover_key = std::make_shared<gates::GateTableProverKey>(
        gates::preprocess_gate_tables(circuit, table_set, options));
    if (!options.prover_key_directory.empty()) {
        gates::export_gate_table_prover_key(*prover_key, options.prover_key_directory);
        const auto expected = prover_key->verifier;
        prover_key.reset();
        prover_key = std::make_shared<gates::GateTableProverKey>(
            gates::reopen_gate_table_prover_key(expected, options.prover_key_directory, options));
    }
    PublicSetup public_setup = make_outsourced_gate_setup(
        payload, circuit, prover_key->verifier);
    return {std::move(public_setup), std::move(prover_key)};
}

std::shared_ptr<const gates::GateTableProverKey>
restore_gate_mle_prover_key(const payload::LayeredCircuit &circuit,
                            const PublicSetup &public_setup,
                            const gates::GateTableBuildOptions &runtime_options) {
    if (public_setup.gate_mle_profile !=
        GateMleProfile::OutsourcedBaseFold) {
        return {};
    }
    if (!public_setup.outsourced_gate_mle) {
        throw std::invalid_argument(
            "restore_gate_mle_prover_key: outsourced setup omits its "
            "verifier key");
    }
    gkr::validate_challenge_dimensions(circuit);
    const gates::GateTableVerifierKey &verifier =
        *public_setup.outsourced_gate_mle;
    gates::GateTableBuildOptions options = runtime_options;
    options.foldable_parameters = verifier.foldable_parameters;
    options.basefold_parameters = verifier.basefold_parameters;
    options.max_message_entries = total_sparse_support(verifier.layout);
    if (!options.prover_key_directory.empty()) {
        if (gates::make_gate_table_layout(circuit, verifier.layout.table_set,
                                         verifier.basefold_parameters) != verifier.layout)
            throw std::invalid_argument("persisted GateMLE circuit/layout mismatch");
        return std::make_shared<gates::GateTableProverKey>(
            gates::reopen_gate_table_prover_key(verifier, options.prover_key_directory, options));
    }
    auto result = std::make_shared<gates::GateTableProverKey>(
        gates::preprocess_gate_tables(circuit, verifier.layout.table_set,
                                      options));
    if (!(result->verifier == verifier)) {
        throw std::invalid_argument(
            "restore_gate_mle_prover_key: reconstructed prover key does "
            "not match authenticated setup");
    }
    return result;
}

} // namespace laminate
