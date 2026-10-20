#ifndef LAMINATE_BENCHES_GATE_MLE_BENCHMARK_HPP
#define LAMINATE_BENCHES_GATE_MLE_BENCHMARK_HPP

/// @file gate_mle_benchmark.hpp
/// @brief Setup and reporting adapter for direct versus outsourced gate MLEs.

#include "benchmark_support.hpp"
#include "gate_mle_report_policy.hpp"

#include "laminate/gates/canonical_tables.hpp"
#include "laminate/gates/outsourced.hpp"
#include "laminate/setup.hpp"

#include <cstddef>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>

namespace laminate::bench {

enum class GateMleBenchmarkProfile {
    Direct,
    OutsourcedBaseFold,
};

inline GateMleBenchmarkProfile parse_gate_mle_profile(
    std::string_view name) {
    if (name == "direct") {
        return GateMleBenchmarkProfile::Direct;
    }
    if (name == "outsourced-basefold") {
        return GateMleBenchmarkProfile::OutsourcedBaseFold;
    }
    throw std::invalid_argument(
        "--gate-mle must be direct or outsourced-basefold");
}

inline std::string_view gate_mle_profile_name(
    GateMleBenchmarkProfile profile) {
    return profile == GateMleBenchmarkProfile::Direct
               ? "direct"
               : "outsourced-basefold";
}

/// Public setup plus server-only structured sparse-table state.
struct GateMleSetupArtifacts {
    PublicSetup public_setup;
    std::shared_ptr<const gates::GateTableProverKey> prover_key;
};

inline GateMleSetupArtifacts prepare_gate_mle_setup(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    GateMleBenchmarkProfile profile, std::size_t max_message_entries) {
    if (profile == GateMleBenchmarkProfile::Direct) {
        return GateMleSetupArtifacts{make_direct_setup(payload, circuit), {}};
    }

    const gates::GateTableSet table_set =
        circuit.shape.kind == payload::PayloadKind::Laned
            ? gates::GateTableSet::Laned
            : gates::GateTableSet::Wide;
    auto key = std::make_shared<gates::GateTableProverKey>(
        gates::preprocess_gate_tables(
            circuit, table_set,
            gates::GateTableBuildOptions{
                .basefold_parameters = {},
                .max_message_entries = max_message_entries}));
    PublicSetup setup =
        make_outsourced_gate_setup(payload, circuit, key->verifier);
    return GateMleSetupArtifacts{std::move(setup), std::move(key)};
}

inline std::size_t checked_product(std::size_t left, std::size_t right,
                                   std::string_view label) {
    if (right != 0 && left > std::numeric_limits<std::size_t>::max() / right) {
        throw std::overflow_error(std::string(label) + " overflows size_t");
    }
    return left * right;
}

inline std::size_t checked_sum(std::size_t left, std::size_t right,
                               std::string_view label) {
    if (left > std::numeric_limits<std::size_t>::max() - right) {
        throw std::overflow_error(std::string(label) + " overflows size_t");
    }
    return left + right;
}

inline std::size_t encoded_row_count(
    const gates::SparseTableCommitment &table,
    const basefold::Parameters &parameters) {
    if (parameters.log_rate >=
        std::numeric_limits<std::size_t>::digits) {
        throw std::overflow_error("gate codeword row count overflows size_t");
    }
    return checked_product(
        table.shard_size,
        std::size_t{1} << parameters.log_rate,
        "gate codeword row count");
}

inline void emit_gate_mle_setup(
    const Record &record,
    const std::shared_ptr<const gates::GateTableProverKey> &prover_key,
    std::size_t configured_max_message_entries) {
    record.text(
        "classification.gate_mle",
        std::string(gate_mle_profile_name(
            prover_key ? GateMleBenchmarkProfile::OutsourcedBaseFold
                       : GateMleBenchmarkProfile::Direct)));
    if (!prover_key) {
        record.text("classification.gate_mle_scalability", "not-applicable");
        record.text("classification.gate_mle_security_model",
                    "direct-public-evaluation");
        record.integer("setup.gate_mle.table_count", 0);
        record.integer("setup.gate_mle.support_entries", 0);
        record.integer("setup.gate_mle.message_rows", 0);
        record.integer("setup.gate_mle.columns", 0);
        record.integer("setup.gate_mle.shards", 0);
        record.integer("setup.gate_mle.message_entries", 0);
        record.integer("setup.gate_mle.codeword_entries", 0);
        return;
    }

    const gates::GateTableVerifierKey &key = prover_key->verifier;
    const bool wide = key.layout.table_set == gates::GateTableSet::Wide;
    record.text("classification.gate_mle_strategy",
                std::string(gate_mle_strategy_name(key)));
    std::size_t support_entries = 0;
    std::size_t message_rows = 0;
    std::size_t physical_columns = 0;
    std::size_t shards = 0;
    std::size_t message_entries = 0;
    std::size_t codeword_entries = 0;
    for (std::size_t selector = 0; selector < key.tables.size();
         ++selector) {
        const gates::GateTableDescriptor &descriptor =
            key.layout.tables.at(selector);
        const gates::SparseTableCommitment &table =
            key.tables[selector];
        support_entries = checked_sum(
            support_entries, descriptor.support_size,
            "gate sparse support entry count");
        message_rows = checked_sum(
            message_rows, table.message_size,
            "gate padded message row count");
        physical_columns = checked_sum(
            physical_columns, table.physical_width,
            "gate physical column count");
        shards = checked_sum(shards, table.shard_count,
                             "gate shard count");
        message_entries = checked_sum(
            message_entries,
            checked_product(table.shard_size, table.physical_width,
                            "gate table message entry count"),
            "gate message entry count");
        codeword_entries = checked_sum(
            codeword_entries,
            checked_product(
                encoded_row_count(table, key.basefold_parameters),
                table.physical_width,
                "gate table codeword entry count"),
            "gate codeword entry count");
    }
    if (wide) {
        record.integer("setup.gate_mle.logical_table_rows", message_rows);
        record.integer("setup.gate_mle.logical_table_columns", physical_columns);
        record.integer("setup.gate_mle.logical_message_entries", message_entries);
        message_rows = key.wide_public_commitment ? key.wide_public_commitment->m : 0;
        physical_columns = key.wide_public_commitment ? key.wide_public_commitment->width : 0;
        shards = physical_columns;
        message_entries = message_rows;
        codeword_entries = checked_product(message_rows,
            std::size_t{1} << basefold::foldable::kLogRate, "Wide public codeword entries");
    }
    record.text("classification.gate_mle_scalability",
                wide ? "LOCAL-ADJOINT-EXTERNAL-FOLDABLE"
                     : "STRUCTURED-SPARSE-SHARDED");
    record.text("classification.gate_mle_security_model",
                "proven-local-interactive-rbr;composition-and-fiat-shamir-separate");
    record.text("setup.gate_mle.commitment_digest",
                digest_hex(sha256(gates::encode_canonical(key))));
    record.text("setup.gate_mle.layout_digest",
                digest_hex(key.layout_digest));
    record.integer("setup.gate_mle.table_count", key.layout.tables.size());
    record.integer("setup.gate_mle.support_entries", support_entries);
    record.integer("setup.gate_mle.message_rows", message_rows);
    record.integer("setup.gate_mle.columns", physical_columns);
    record.integer("setup.gate_mle.shards", shards);
    record.integer("setup.gate_mle.message_entries", message_entries);
    record.integer("setup.gate_mle.codeword_entries", codeword_entries);
    record.integer("setup.gate_mle.max_message_entries",
                   configured_max_message_entries);
    record.integer("setup.gate_mle.basefold_log_rate",
                   wide ? basefold::foldable::kLogRate : key.basefold_parameters.log_rate);
    record.integer("setup.gate_mle.basefold_queries",
                   gate_mle_query_count(key));
}

template <typename Proof>
void emit_gate_mle_proof(const Record &record, const Proof &proof) {
    if (!proof.gate_mle_opening) {
        record.integer("proof.gate_mle.claims", 0);
        record.integer("proof.gate_mle.action_sumchecks", 0);
        record.integer("proof.gate_mle.sparse_products", 0);
        record.integer("proof.gate_mle.table_openings", 0);
        record.integer("proof.gate_mle.target_rows", 0);
        record.integer("proof.gate_mle.target_cells", 0);
        record.integer("proof.gate_mle.basefold_query_openings", 0);
        return;
    }
    const gates::OutsourcedGateMleProof &opening = *proof.gate_mle_opening;
    if (opening.wide) {
        std::size_t actions = 0, masks = 0, products = 0, witnesses = 0;
        std::size_t target_rows = 0, target_cells = 0, pairs = 0;
        const auto count_pairs = [&](const basefold::foldable::Proof &pcs,
                                     std::size_t width) {
            if (pcs.final_codeword.empty()) return;
            pairs = checked_sum(pairs, pcs.initial.values.size() / (2 * width),
                                "Wide initial authenticated pairs");
            for (const auto &fold : pcs.folded)
                pairs = checked_sum(pairs, fold.values.size() / 2,
                                    "Wide folded authenticated pairs");
        };
        for (const auto &trace : opening.wide->traces) {
            for (const auto &local : trace.local_openings) {
                actions += local.action.has_value();
                masks += local.masked.has_value();
                products += local.products.size();
            }
        }
        for (const auto &table : opening.wide->tables) {
            target_rows += table.column_targets.size();
            for (const auto &row : table.column_targets) target_cells += row.size();
        }
        witnesses = opening.wide->adjoint_groups.size();
        for (const auto &group : opening.wide->adjoint_groups) count_pairs(group.opening, 1);
        count_pairs(opening.wide->public_opening, 1);
        record.integer("proof.gate_mle.claims", opening.claimed_values.size());
        record.integer("proof.gate_mle.action_sumchecks", actions);
        record.integer("proof.gate_mle.masked_action_sumchecks", masks);
        record.integer("proof.gate_mle.sparse_products", products);
        record.integer("proof.gate_mle.witness_openings", witnesses);
        record.integer("proof.gate_mle.table_openings", opening.wide->tables.empty() ? 0 : 1);
        record.integer("proof.gate_mle.public_tables", opening.wide->tables.size());
        record.integer("proof.gate_mle.target_rows", target_rows);
        record.integer("proof.gate_mle.target_cells", target_cells);
        record.integer("proof.gate_mle.foldable_authenticated_pairs", pairs);
        return;
    }
    std::size_t target_rows = 0;
    std::size_t target_cells = 0;
    std::size_t query_openings = 0;
    for (const gates::SparseTableOpeningProof &table :
         opening.table_openings) {
        target_rows = checked_sum(
            target_rows, table.column_targets.size(),
            "gate target row count");
        for (const std::vector<Fpk> &row : table.column_targets) {
            target_cells = checked_sum(
                target_cells, row.size(), "gate target cell count");
        }
        query_openings = checked_sum(
            query_openings, table.opening.queries.openings.size(),
            "gate BaseFold query opening count");
    }
    record.integer("proof.gate_mle.claims", opening.claimed_values.size());
    record.integer("proof.gate_mle.action_sumchecks",
                   opening.action_sumchecks.size());
    record.integer("proof.gate_mle.sparse_products",
                   opening.sparse_products.size());
    record.integer("proof.gate_mle.table_openings",
                   opening.table_openings.size());
    record.integer("proof.gate_mle.target_rows", target_rows);
    record.integer("proof.gate_mle.target_cells", target_cells);
    record.integer("proof.gate_mle.basefold_query_openings",
                   query_openings);
}

} // namespace laminate::bench

#endif // LAMINATE_BENCHES_GATE_MLE_BENCHMARK_HPP
