#include "outsourced_io.hpp"

#include "laminate/basefold/common.hpp"

#include <array>
#include <limits>
#include <span>
#include <stdexcept>
#include <string_view>

namespace laminate::gates {
namespace {

using Bytes = std::vector<std::uint8_t>;

constexpr std::string_view kKeyLabel =
    "laminate/gates/outsourced-key/v2";
constexpr std::string_view kClaimLabel =
    "laminate/gates/outsourced-claim/v2";
constexpr std::string_view kTargetsLabel =
    "laminate/gates/outsourced-targets/v2";

void append_u64(Bytes &output, std::size_t value) {
    if (value > std::numeric_limits<std::uint64_t>::max()) {
        throw std::overflow_error("outsourced gate encoding exceeds u64");
    }
    const auto word = static_cast<std::uint64_t>(value);
    for (std::size_t byte = 0; byte < 8; ++byte) {
        output.push_back(static_cast<std::uint8_t>(
            (word >> (8U * byte)) & std::uint64_t{0xff}));
    }
}

void append_label(Bytes &output, std::string_view label) {
    append_u64(output, label.size());
    output.insert(output.end(), label.begin(), label.end());
}

void append_bytes(Bytes &output, std::span<const std::uint8_t> bytes) {
    append_u64(output, bytes.size());
    output.insert(output.end(), bytes.begin(), bytes.end());
}

void append_fpk_values(Bytes &output, std::span<const Fpk> values) {
    append_u64(output, values.size());
    const Bytes encoded = basefold::serialize_values(values);
    output.insert(output.end(), encoded.begin(), encoded.end());
}

void append_fpk(Bytes &output, const Fpk &value) {
    const std::array<Fpk, 1> values{value};
    const Bytes encoded = basefold::serialize_values(values);
    output.insert(output.end(), encoded.begin(), encoded.end());
}

void append_action_sumcheck(Bytes &output,
                            const WideActionSumcheckProof &proof) {
    append_u64(output, proof.rounds.size());
    for (const WideActionSumcheckRound &round : proof.rounds) {
        const std::array<Fpk, 2> values{round.at_one, round.at_two};
        const Bytes encoded = basefold::serialize_values(values);
        output.insert(output.end(), encoded.begin(), encoded.end());
    }
    append_fpk(output, proof.terminal_compact_weight);
}

void append_sparse_product(Bytes &output,
                           const sparse::SparseProductProof &proof) {
    append_fpk_values(output, proof.root_rounds);
    append_u64(output, proof.layers.size());
    for (const sparse::ProductLayerProof &layer : proof.layers) {
        append_u64(output, layer.rounds.size());
        for (const std::array<Fpk, 2> &round : layer.rounds) {
            const Bytes encoded = basefold::serialize_values(round);
            output.insert(output.end(), encoded.begin(), encoded.end());
        }
        append_fpk(output, layer.left_claim);
        append_fpk(output, layer.right_claim);
    }
}


void append_quadratic_product(Bytes &output,
                              const QuadraticProductProof &proof) {
    append_u64(output, proof.rounds.size());
    for (const auto &round : proof.rounds) {
        const auto bytes = basefold::serialize_values(round);
        output.insert(output.end(), bytes.begin(), bytes.end());
    }
    append_fpk(output, proof.left);
    append_fpk(output, proof.right);
}

void append_wide_local(Bytes &output, const WideLocalOpeningProof &proof) {
    append_fpk(output, proof.first_component);
    append_fpk(output, proof.second_component);
    output.push_back(proof.action.has_value());
    if (proof.action) append_action_sumcheck(output, *proof.action);
    output.push_back(proof.masked.has_value());
    if (proof.masked) {
        append_quadratic_product(output, proof.masked->masks);
        append_quadratic_product(output, proof.masked->slots);
    }
    append_u64(output, proof.products.size());
    for (const auto &product : proof.products) append_sparse_product(output, product);
}

bool empty_foldable(const basefold::foldable::Proof &proof) {
    return proof.sumcheck.rounds.empty() && proof.sumcheck.operand_evaluations.empty() &&
        proof.roots.empty() && proof.final_codeword.empty() &&
        proof.initial.values.empty() && proof.initial.frontier.empty() && proof.folded.empty();
}

void append_wide(Bytes &output, const WideGateOpeningProof &proof) {
    append_u64(output, proof.traces.size());
    for (const auto &trace : proof.traces) {
        output.push_back(trace.has_adjoint);
        append_fpk_values(output, trace.boundary_values);
        append_fpk(output, trace.residual_evaluation);
        append_quadratic_product(output, trace.product);
        append_fpk_values(output, trace.terminal_values);
        append_u64(output, trace.local_openings.size());
        for (const auto &local : trace.local_openings) append_wide_local(output, local);
    }
    append_u64(output, proof.adjoint_groups.size());
    for (const auto &group : proof.adjoint_groups) {
        output.insert(output.end(), group.root.begin(), group.root.end());
        append_bytes(output, basefold::foldable::encode_canonical(group.opening));
    }
    append_u64(output, proof.tables.size());
    for (const auto &table : proof.tables) {
        append_u64(output, table.table_selector);
        Bytes targets;
        append_u64(targets, table.column_targets.size());
        for (const auto &row : table.column_targets) append_fpk_values(targets, row);
        append_bytes(output, targets);
    }
    if (!proof.tables.empty()) {
        append_u64(output, proof.public_column_targets.size());
        for (const auto &row : proof.public_column_targets) append_fpk_values(output, row);
        append_bytes(output, basefold::foldable::encode_canonical(proof.public_opening));
    } else if (!proof.public_column_targets.empty() || !empty_foldable(proof.public_opening)) {
        throw std::invalid_argument("Wide proof: unexpected public opening");
    }
}

Bytes encode_claim(const RecordedGateQuery &query, const Fpk &value) {
    Bytes encoded;
    append_u64(encoded, query.layer_index);
    encoded.push_back(static_cast<std::uint8_t>(query.kind));
    append_u64(encoded, query.first_point_size);
    append_fpk_values(encoded, query.local_point_msb);
    const std::array<Fpk, 1> claim{value};
    const Bytes value_bytes = basefold::serialize_values(claim);
    encoded.insert(encoded.end(), value_bytes.begin(), value_bytes.end());
    return encoded;
}

Bytes encode_targets(const basefold::ColumnTargets &targets) {
    Bytes encoded;
    append_u64(encoded, targets.size());
    for (const std::vector<Fpk> &row : targets) {
        append_fpk_values(encoded, row);
    }
    return encoded;
}

} // namespace

std::vector<std::uint8_t>
encode_canonical(const GateTableVerifierKey &key) {
    Bytes output;
    append_label(output, "LaminateImpl/GateTableVerifierKey/v5");
    const Bytes layout = gates::encode_canonical(key.layout);
    append_bytes(output, layout);
    append_u64(output, key.basefold_parameters.log_rate);
    append_u64(output, key.basefold_parameters.num_queries);
    append_u64(output, key.foldable_parameters.num_queries);
    output.insert(output.end(), key.layout_digest.begin(),
                  key.layout_digest.end());
    append_u64(output, key.tables.size());
    for (const SparseTableCommitment &table : key.tables) {
        append_u64(output, table.message_size);
        append_u64(output, table.shard_size);
        append_u64(output, table.shard_count);
        append_u64(output, table.logical_width);
        append_u64(output, table.physical_width);
        output.insert(output.end(), table.root.begin(), table.root.end());
        output.push_back(table.foldable ? 1U : 0U);
        if (table.foldable) {
            append_u64(output, table.foldable->m);
            append_u64(output, table.foldable->width);
            append_u64(output, table.foldable->hierarchy_version);
        }
        output.push_back(table.wide_block_offset.has_value());
        if (table.wide_block_offset) append_u64(output, *table.wide_block_offset);
    }
    output.push_back(key.wide_public_commitment.has_value());
    if (key.wide_public_commitment) {
        const auto &commitment = *key.wide_public_commitment;
        output.insert(output.end(), commitment.root.begin(), commitment.root.end());
        append_u64(output, commitment.m);
        append_u64(output, commitment.width);
        append_u64(output, commitment.hierarchy_version);
    }
    return output;
}

std::vector<std::uint8_t>
encode_canonical(const OutsourcedGateMleProof &proof) {
    Bytes output;
    append_label(output, "LaminateImpl/OutsourcedGateMleProof/v5");
    append_fpk_values(output, proof.claimed_values);
    output.push_back(proof.wide.has_value());
    if (proof.wide) {
        if (!proof.sparse_values.empty() || !proof.action_sumchecks.empty() ||
            !proof.sparse_products.empty() || !proof.table_openings.empty())
            throw std::invalid_argument("Wide proof: unexpected Laned proof fields");
        append_wide(output, *proof.wide);
        return output;
    }
    append_fpk_values(output, proof.sparse_values);

    append_u64(output, proof.action_sumchecks.size());
    for (const WideActionSumcheckProof &action :
         proof.action_sumchecks) {
        append_action_sumcheck(output, action);
    }

    append_u64(output, proof.sparse_products.size());
    for (const sparse::SparseProductProof &product :
         proof.sparse_products) {
        append_sparse_product(output, product);
    }

    append_u64(output, proof.table_openings.size());
    for (const SparseTableOpeningProof &table : proof.table_openings) {
        append_u64(output, table.table_selector);
        const Bytes targets = encode_targets(table.column_targets);
        append_bytes(output, targets);
        const Bytes opening = basefold::encode_canonical(table.opening);
        append_bytes(output, opening);
    }
    return output;
}

void observe_gate_table_key(const GateTableVerifierKey &key,
                            Transcript &transcript) {
    transcript.observe(kKeyLabel, encode_canonical(key));
}

namespace detail {

void observe_claim(const RecordedGateQuery &query, const Fpk &value,
                   Transcript &transcript) {
    transcript.observe(kClaimLabel, encode_claim(query, value));
}

void observe_targets(std::size_t table_selector,
                     const basefold::ColumnTargets &targets,
                     Transcript &transcript) {
    Bytes encoded;
    append_u64(encoded, table_selector);
    const Bytes rows = encode_targets(targets);
    encoded.insert(encoded.end(), rows.begin(), rows.end());
    transcript.observe(kTargetsLabel, encoded);
}

} // namespace detail
} // namespace laminate::gates
