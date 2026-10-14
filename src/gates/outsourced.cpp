#include "laminate/gates/outsourced.hpp"

#include "laminate/basefold/common.hpp"

#include "outsourced_io.hpp"

#include <algorithm>
#include <limits>
#include <stdexcept>
#include <type_traits>
#include <utility>
#include <variant>

namespace laminate::gates {
namespace {

std::vector<Fpk> concatenate(
    std::initializer_list<std::span<const Fpk>> parts) {
    std::vector<Fpk> result;
    for (const std::span<const Fpk> part : parts) {
        result.insert(result.end(), part.begin(), part.end());
    }
    return result;
}

RecordedGateQuery normalize(const GateTableLayout &layout,
                            const GateMleQuery &query) {
    return std::visit(
        [&](const auto &typed) -> RecordedGateQuery {
            using Query = std::decay_t<decltype(typed)>;
            if constexpr (std::is_same_v<Query, AffineQuery>) {
                if (layout.table_set != GateTableSet::Wide) {
                    throw std::invalid_argument(
                        "structured GateMLE: Wide query uses Laned key");
                }
                return RecordedGateQuery{
                    typed.layer_index,
                    RecordedGateQueryKind::WideAffine,
                    typed.output_point.size(),
                    concatenate({typed.output_point, typed.source_point})};
            } else {
                static_assert(std::is_same_v<Query,
                                             LanedAffineWireQuery>);
                if (layout.table_set != GateTableSet::Laned) {
                    throw std::invalid_argument(
                        "structured GateMLE: Laned query uses Wide key");
                }
                return RecordedGateQuery{
                    typed.layer_index,
                    RecordedGateQueryKind::LanedAffineWire,
                    typed.output_wire_point.size(),
                    concatenate({typed.output_wire_point,
                                 typed.source_wire_point})};
            }
        },
        query);
}

RecordedGateQuery normalize_affine_constant(
    std::size_t layer_index, std::span<const Fpk> output_point) {
    return RecordedGateQuery{
        layer_index, RecordedGateQueryKind::AffineConstant,
        output_point.size(),
        std::vector<Fpk>(output_point.begin(), output_point.end())};
}

struct PairOfPoints {
    std::span<const Fpk> first;
    std::span<const Fpk> second;
};

PairOfPoints split_recorded(const RecordedGateQuery &query) {
    if (query.first_point_size > query.local_point_msb.size()) {
        throw std::invalid_argument(
            "structured GateMLE recorded point split is invalid");
    }
    const std::span<const Fpk> point(query.local_point_msb);
    return PairOfPoints{point.first(query.first_point_size),
                        point.subspan(query.first_point_size)};
}

struct WideQueryPoints {
    std::span<const Fpk> output_wire;
    std::span<const Fpk> output_slot;
    std::span<const Fpk> source_wire;
    std::span<const Fpk> source_slot;
};

WideQueryPoints split_wide_query(const RecordedGateQuery &query,
                                 std::size_t compact_variables) {
    const PairOfPoints points = split_recorded(query);
    if (points.first.size() >
            std::numeric_limits<std::size_t>::max() - points.second.size() ||
        points.first.size() + points.second.size() < compact_variables) {
        throw std::invalid_argument(
            "structured Wide GateMLE has inconsistent dimensions");
    }
    const std::size_t slot_variables =
        points.first.size() + points.second.size() - compact_variables;
    if (slot_variables == 0 || slot_variables > points.first.size() ||
        slot_variables > points.second.size()) {
        throw std::invalid_argument(
            "structured Wide GateMLE has invalid slot dimensions");
    }
    return WideQueryPoints{
        points.first.first(points.first.size() - slot_variables),
        points.first.last(slot_variables),
        points.second.first(points.second.size() - slot_variables),
        points.second.last(slot_variables)};
}

bool all_zero(const basefold::Digest &digest) {
    return std::all_of(digest.begin(), digest.end(),
                       [](std::uint8_t byte) { return byte == 0; });
}

void validate_prover_key(const GateTableProverKey &key,
                         const GateTableLayout &layout) {
    if (!(key.verifier.layout == layout) ||
        key.verifier.layout_digest != digest(layout) ||
        key.tables.size() != layout.tables.size() ||
        key.verifier.tables.size() != layout.tables.size() ||
        !valid_wide_public_index(key.verifier) ||
        key.wide_public_commitment.has_value() !=
            key.verifier.wide_public_commitment.has_value() ||
        (key.wide_public_commitment &&
         key.wide_public_commitment->metadata !=
            *key.verifier.wide_public_commitment)) {
        throw std::invalid_argument(
            "GateClaimProver::finish: sparse key/layout mismatch");
    }
    for (std::size_t table = 0; table < key.tables.size(); ++table) {
        const SparseTableProverKey &prover = key.tables[table];
        const SparseTableCommitment &verifier = key.verifier.tables[table];
        if (layout.table_set == GateTableSet::Wide) {
            if (prover.verifier != verifier || !verifier.wide_block_offset ||
                prover.foldable_commitment || prover.commitment ||
                prover.entries.size() != layout.tables[table].support_size ||
                all_zero(verifier.root) ||
                !valid_sparse_table_commitment(layout.tables[table], verifier,
                                                key.verifier.basefold_parameters)) {
                throw std::invalid_argument("GateClaimProver::finish: malformed Wide key");
            }
            continue;
        }
        if (!(prover.verifier == verifier) ||
            prover.entries.size() != layout.tables[table].support_size ||
            !prover.commitment ||
            prover.commitment->m != verifier.shard_size ||
            prover.commitment->width != verifier.physical_width ||
            prover.commitment->log_rate !=
                key.verifier.basefold_parameters.log_rate ||
            prover.commitment->root != verifier.root || all_zero(verifier.root) ||
            !valid_sparse_table_commitment(
                layout.tables[table], verifier,
                key.verifier.basefold_parameters)) {
            throw std::invalid_argument(
                "GateClaimProver::finish: malformed sparse prover key");
        }
    }
}

struct PendingSparseOpening {
    std::size_t table_selector = 0;
    std::vector<Fpk> point_msb;
    sparse::SparseProductReduction reduction;
};

std::vector<Fpk> row_operand(std::span<const Fpk> point_lsb,
                             std::size_t row_count) {
    std::vector<Fpk> result(row_count);
    for (std::size_t row = 0; row < row_count; ++row) {
        result[row] = basefold::equality_evaluation(row, point_lsb);
    }
    return result;
}

Fpk equality_of_points(std::span<const Fpk> left,
                       std::span<const Fpk> right) {
    if (left.size() != right.size()) {
        throw std::invalid_argument(
            "structured GateMLE terminal equality dimension mismatch");
    }
    Fpk result = Fpk::one();
    for (std::size_t variable = 0; variable < left.size(); ++variable) {
        result *= left[variable] * right[variable] +
                  (Fpk::one() - left[variable]) *
                      (Fpk::one() - right[variable]);
    }
    return result;
}

struct PhysicalLeafLinearization {
    std::vector<Fpk> column_weights;
    Fpk constant = Fpk::zero();
    std::vector<Fpk> inner_point_lsb;
};

PhysicalLeafLinearization linearize_physical_leaf(
    const GateTableDescriptor &descriptor,
    const SparseTableCommitment &table,
    std::span<const Fpk> query_point_msb,
    const sparse::SparseProductReduction &reduction) {
    if (query_point_msb.size() != descriptor.local_variables ||
        reduction.entry_point_lsb.size() !=
            basefold::log2_exact(table.message_size)) {
        throw std::invalid_argument(
            "structured GateMLE sparse reduction has wrong dimensions");
    }
    const std::size_t inner_variables =
        basefold::log2_exact(table.shard_size);
    const std::size_t outer_variables =
        basefold::log2_exact(table.shard_count);
    if (inner_variables + outer_variables !=
        reduction.entry_point_lsb.size()) {
        throw std::invalid_argument(
            "structured GateMLE sparse shard split is inconsistent");
    }
    const sparse::SparseLeafLinearization logical =
        sparse::linearize_sparse_leaf(
            descriptor.local_variables, query_point_msb,
            reduction.factor_point_lsb);
    if ((table.logical_width != 0 &&
         table.shard_count >
             std::numeric_limits<std::size_t>::max() /
                 table.logical_width) ||
        logical.column_weights.size() > table.logical_width ||
        table.physical_width != table.shard_count * table.logical_width) {
        throw std::invalid_argument(
            "structured GateMLE sparse column geometry is invalid");
    }
    const std::span<const Fpk> outer =
        std::span<const Fpk>(reduction.entry_point_lsb)
            .subspan(inner_variables);
    std::vector<Fpk> physical(table.physical_width, Fpk::zero());
    for (std::size_t shard = 0; shard < table.shard_count; ++shard) {
        const Fpk shard_weight =
            basefold::equality_evaluation(shard, outer);
        for (std::size_t column = 0;
             column < logical.column_weights.size(); ++column) {
            physical[shard * table.logical_width + column] =
                shard_weight * logical.column_weights[column];
        }
    }
    return PhysicalLeafLinearization{
        std::move(physical), logical.constant,
        std::vector<Fpk>(reduction.entry_point_lsb.begin(),
                         reduction.entry_point_lsb.begin() +
                             static_cast<std::ptrdiff_t>(inner_variables))};
}

Fpk combine_targets(std::span<const Fpk> weights,
                    std::span<const Fpk> targets,
                    const Fpk &constant) {
    if (weights.size() != targets.size()) {
        throw std::invalid_argument(
            "structured GateMLE target/weight width mismatch");
    }
    Fpk result = constant;
    for (std::size_t column = 0; column < weights.size(); ++column) {
        result += weights[column] * targets[column];
    }
    return result;
}

} // namespace

GateClaimProver::GateClaimProver(
    const payload::LayeredCircuit &circuit,
    const GateTableLayout &layout, Transcript &transcript)
    : circuit_(circuit), layout_(layout), direct_(circuit), transcript_(transcript) {}

Fpk GateClaimProver::record(RecordedGateQuery query, const Fpk &value) {
    detail::observe_claim(query, value, transcript_);
    queries_.push_back(std::move(query));
    claimed_values_.push_back(value);
    return value;
}

Fpk GateClaimProver::evaluate(const GateMleQuery &query) {
    return record(normalize(layout_, query), direct_.evaluate(query));
}

Fpk GateClaimProver::evaluate_affine_constant(
    std::size_t layer_index, std::span<const Fpk> output_point) {
    return record(normalize_affine_constant(layer_index, output_point),
                  direct_.evaluate_affine_constant(layer_index,
                                                   output_point));
}

OutsourcedGateMleProof
GateClaimProver::finish(const GateTableProverKey &key) {
    if (queries_.empty()) {
        throw std::invalid_argument(
            "GateClaimProver::finish: empty claim batch");
    }
    validate_prover_key(key, layout_);

    OutsourcedGateMleProof proof;
    proof.claimed_values = claimed_values_;
    if (layout_.table_set == GateTableSet::Wide) {
        proof.wide = prove_wide_gate_opening(circuit_, key, queries_,
                                             claimed_values_, transcript_);
        return proof;
    }
    std::vector<PendingSparseOpening> pending;
    auto append_sparse = [&](const GateTableDescriptor &descriptor,
                             std::vector<Fpk> point,
                             const Fpk &claimed) {
        const SparseTableProverKey &table =
            key.tables.at(descriptor.selector);
        sparse::SparseProductProverOutput product =
            sparse::prove_sparse_evaluation(
                table.entries, table.verifier.message_size,
                descriptor.local_variables, point, claimed,
                transcript_);
        proof.sparse_values.push_back(claimed);
        proof.sparse_products.push_back(std::move(product.proof));
        pending.push_back(PendingSparseOpening{
            descriptor.selector, std::move(point),
            std::move(product.reduction)});
    };

    for (std::size_t index = 0; index < queries_.size(); ++index) {
        const RecordedGateQuery &query = queries_[index];
        const Fpk &claimed = claimed_values_[index];
        switch (query.kind) {
        case RecordedGateQueryKind::WideAffine: {
            const GateTableDescriptor *descriptor = find_table_if(
                layout_, query.layer_index,
                GateTableKind::WideAffineWeight);
            if (descriptor == nullptr) {
                if (!claimed.is_zero()) {
                    throw std::logic_error(
                        "structured Wide zero table has nonzero claim");
                }
                break;
            }
            const WideQueryPoints points = split_wide_query(
                query, descriptor->local_variables);
            WideActionSumcheckProverOutput action =
                prove_wide_action_sumcheck(
                    key.tables.at(descriptor->selector).entries,
                    points.output_wire, points.output_slot,
                    points.source_wire, points.source_slot, claimed,
                    transcript_);
            const Fpk compact = action.reduction.compact_weight;
            const std::vector<Fpk> compact_point = concatenate(
                {points.output_wire, points.source_wire,
                 action.reduction.offset_point_msb});
            proof.action_sumchecks.push_back(std::move(action.proof));
            append_sparse(*descriptor, compact_point, compact);
            break;
        }
        case RecordedGateQueryKind::LanedAffineWire: {
            const GateTableDescriptor *descriptor = find_table_if(
                layout_, query.layer_index,
                GateTableKind::LanedAffineWire);
            if (descriptor == nullptr) {
                if (!claimed.is_zero()) {
                    throw std::logic_error(
                        "structured Laned zero table has nonzero claim");
                }
                break;
            }
            append_sparse(*descriptor, query.local_point_msb, claimed);
            break;
        }
        case RecordedGateQueryKind::AffineConstant: {
            const std::span<const Fpk> output(query.local_point_msb);
            Fpk reconstructed = Fpk::zero();
            if (const GateTableDescriptor *uniform = find_table_if(
                    layout_, query.layer_index,
                    GateTableKind::AffineConstantUniform)) {
                if (uniform->local_variables > output.size()) {
                    throw std::invalid_argument(
                        "structured uniform constant point is too short");
                }
                std::vector<Fpk> point(
                    output.begin(),
                    output.begin() + static_cast<std::ptrdiff_t>(
                                         uniform->local_variables));
                const Fpk value = evaluate_sparse_table(
                    key.tables.at(uniform->selector).entries,
                    uniform->local_variables, point);
                reconstructed += value;
                append_sparse(*uniform, std::move(point), value);
            }
            if (const GateTableDescriptor *slot = find_table_if(
                    layout_, query.layer_index,
                    GateTableKind::AffineConstantSlot)) {
                if (slot->local_variables != output.size()) {
                    throw std::invalid_argument(
                        "structured slot constant point has wrong size");
                }
                const Fpk value = evaluate_sparse_table(
                    key.tables.at(slot->selector).entries,
                    slot->local_variables, output);
                reconstructed += value;
                append_sparse(*slot, query.local_point_msb, value);
            }
            if (!(reconstructed == claimed)) {
                throw std::logic_error(
                    "structured constant tables disagree with direct gate");
            }
            break;
        }
        }
    }

    std::vector<std::vector<std::size_t>> by_table(key.tables.size());
    for (std::size_t request = 0; request < pending.size(); ++request) {
        by_table.at(pending[request].table_selector).push_back(request);
    }
    for (std::size_t selector = 0; selector < by_table.size(); ++selector) {
        if (by_table[selector].empty()) {
            continue;
        }
        const GateTableDescriptor &descriptor = layout_.tables[selector];
        const SparseTableProverKey &table = key.tables[selector];
        std::vector<std::vector<Fpk>> operands;
        std::vector<PhysicalLeafLinearization> linearizations;
        operands.reserve(by_table[selector].size());
        linearizations.reserve(by_table[selector].size());
        for (const std::size_t request : by_table[selector]) {
            linearizations.push_back(linearize_physical_leaf(
                descriptor, table.verifier, pending[request].point_msb,
                pending[request].reduction));
            operands.push_back(row_operand(
                linearizations.back().inner_point_lsb,
                table.verifier.shard_size));
        }
        basefold::ColumnTargets targets =
            basefold::prepare_all_column_targets(*table.commitment, operands);
        for (std::size_t row = 0; row < targets.size(); ++row) {
            const PendingSparseOpening &request =
                pending[by_table[selector][row]];
            if (!(combine_targets(
                      linearizations[row].column_weights, targets[row],
                      linearizations[row].constant) ==
                  request.reduction.leaf_claim)) {
                throw std::logic_error(
                    "structured sparse table and BaseFold columns disagree");
            }
        }
        detail::observe_targets(selector, targets, transcript_);
        basefold::ProverOutput opening = basefold::prove_all_columns(
            *table.commitment, operands, targets, transcript_,
            key.verifier.basefold_parameters);
        proof.table_openings.push_back(SparseTableOpeningProof{
            selector, std::move(targets), std::move(opening.proof)});
    }
    return proof;
}

GateClaimVerifier::GateClaimVerifier(
    const GateTableVerifierKey &key,
    const OutsourcedGateMleProof &proof, Transcript &transcript)
    : key_(key), proof_(proof), transcript_(transcript) {}

Fpk GateClaimVerifier::consume(RecordedGateQuery query) {
    if (cursor_ >= proof_.claimed_values.size()) {
        throw std::invalid_argument(
            "GateClaimVerifier: proof has too few online claims");
    }
    const Fpk value = proof_.claimed_values[cursor_++];
    detail::observe_claim(query, value, transcript_);
    queries_.push_back(std::move(query));
    return value;
}

Fpk GateClaimVerifier::evaluate(const GateMleQuery &query) {
    return consume(normalize(key_.layout, query));
}

Fpk GateClaimVerifier::evaluate_affine_constant(
    std::size_t layer_index, std::span<const Fpk> output_point) {
    return consume(normalize_affine_constant(layer_index, output_point));
}

bool GateClaimVerifier::finish() {
    if (cursor_ == 0 || cursor_ != proof_.claimed_values.size() ||
        key_.tables.size() != key_.layout.tables.size()) {
        return false;
    }
    if (key_.layout.table_set == GateTableSet::Wide) {
        return proof_.wide && proof_.sparse_values.empty() &&
            proof_.action_sumchecks.empty() && proof_.sparse_products.empty() &&
            proof_.table_openings.empty() && verify_wide_gate_opening(
                key_, queries_, proof_.claimed_values, *proof_.wide, transcript_);
    }
    if (proof_.wide) return false;
    try {
        std::size_t action_cursor = 0;
        std::size_t sparse_cursor = 0;
        std::vector<PendingSparseOpening> pending;
        auto verify_sparse = [&](
            const GateTableDescriptor &descriptor, std::vector<Fpk> point,
            const Fpk &expected) -> bool {
            if (sparse_cursor >= proof_.sparse_values.size() ||
                sparse_cursor >= proof_.sparse_products.size() ||
                !(proof_.sparse_values[sparse_cursor] == expected)) {
                return false;
            }
            const SparseTableCommitment &table =
                key_.tables.at(descriptor.selector);
            const std::optional<sparse::SparseProductReduction> reduction =
                sparse::verify_sparse_evaluation(
                    table.message_size, descriptor.local_variables, point,
                    expected, proof_.sparse_products[sparse_cursor],
                    transcript_);
            ++sparse_cursor;
            if (!reduction.has_value()) {
                return false;
            }
            pending.push_back(PendingSparseOpening{
                descriptor.selector, std::move(point), *reduction});
            return true;
        };

        for (std::size_t index = 0; index < queries_.size(); ++index) {
            const RecordedGateQuery &query = queries_[index];
            const Fpk &claimed = proof_.claimed_values[index];
            switch (query.kind) {
            case RecordedGateQueryKind::WideAffine: {
                const GateTableDescriptor *descriptor = find_table_if(
                    key_.layout, query.layer_index,
                    GateTableKind::WideAffineWeight);
                if (descriptor == nullptr) {
                    if (!claimed.is_zero()) {
                        return false;
                    }
                    break;
                }
                if (action_cursor >= proof_.action_sumchecks.size()) {
                    return false;
                }
                const WideQueryPoints points = split_wide_query(
                    query, descriptor->local_variables);
                const std::optional<WideActionSumcheckReduction> action =
                    verify_wide_action_sumcheck(
                        points.output_wire, points.output_slot,
                        points.source_wire, points.source_slot, claimed,
                        proof_.action_sumchecks[action_cursor++],
                        transcript_);
                if (!action.has_value()) {
                    return false;
                }
                if (!verify_sparse(
                        *descriptor,
                        concatenate({points.output_wire,
                                     points.source_wire,
                                     action->offset_point_msb}),
                        action->compact_weight)) {
                    return false;
                }
                break;
            }
            case RecordedGateQueryKind::LanedAffineWire: {
                const GateTableDescriptor *descriptor = find_table_if(
                    key_.layout, query.layer_index,
                    GateTableKind::LanedAffineWire);
                if (descriptor == nullptr) {
                    if (!claimed.is_zero()) {
                        return false;
                    }
                } else if (!verify_sparse(
                               *descriptor, query.local_point_msb,
                               claimed)) {
                    return false;
                }
                break;
            }
            case RecordedGateQueryKind::AffineConstant: {
                const std::span<const Fpk> output(query.local_point_msb);
                Fpk reconstructed = Fpk::zero();
                if (const GateTableDescriptor *uniform = find_table_if(
                        key_.layout, query.layer_index,
                        GateTableKind::AffineConstantUniform)) {
                    if (uniform->local_variables > output.size() ||
                        sparse_cursor >= proof_.sparse_values.size()) {
                        return false;
                    }
                    const Fpk value = proof_.sparse_values[sparse_cursor];
                    reconstructed += value;
                    if (!verify_sparse(
                            *uniform,
                            std::vector<Fpk>(
                                output.begin(),
                                output.begin() +
                                    static_cast<std::ptrdiff_t>(
                                        uniform->local_variables)),
                            value)) {
                        return false;
                    }
                }
                if (const GateTableDescriptor *slot = find_table_if(
                        key_.layout, query.layer_index,
                        GateTableKind::AffineConstantSlot)) {
                    if (slot->local_variables != output.size() ||
                        sparse_cursor >= proof_.sparse_values.size()) {
                        return false;
                    }
                    const Fpk value = proof_.sparse_values[sparse_cursor];
                    reconstructed += value;
                    if (!verify_sparse(*slot, query.local_point_msb,
                                       value)) {
                        return false;
                    }
                }
                if (!(reconstructed == claimed)) {
                    return false;
                }
                break;
            }
            }
        }
        if (action_cursor != proof_.action_sumchecks.size() ||
            sparse_cursor != proof_.sparse_values.size() ||
            sparse_cursor != proof_.sparse_products.size()) {
            return false;
        }

        std::vector<std::vector<std::size_t>> by_table(key_.tables.size());
        for (std::size_t request = 0; request < pending.size(); ++request) {
            by_table.at(pending[request].table_selector).push_back(request);
        }
        std::size_t opening_cursor = 0;
        for (std::size_t selector = 0; selector < by_table.size();
             ++selector) {
            if (by_table[selector].empty()) {
                continue;
            }
            if (opening_cursor >= proof_.table_openings.size()) {
                return false;
            }
            const SparseTableOpeningProof &opening =
                proof_.table_openings[opening_cursor++];
            const GateTableDescriptor &descriptor =
                key_.layout.tables[selector];
            const SparseTableCommitment &table = key_.tables[selector];
            if (opening.table_selector != selector ||
                opening.column_targets.size() != by_table[selector].size()) {
                return false;
            }
            std::vector<PhysicalLeafLinearization> linearizations;
            linearizations.reserve(by_table[selector].size());
            for (std::size_t row = 0; row < by_table[selector].size(); ++row) {
                const PendingSparseOpening &request =
                    pending[by_table[selector][row]];
                linearizations.push_back(linearize_physical_leaf(
                    descriptor, table, request.point_msb,
                    request.reduction));
                if (opening.column_targets[row].size() !=
                        table.physical_width ||
                    !(combine_targets(
                          linearizations[row].column_weights,
                          opening.column_targets[row],
                          linearizations[row].constant) ==
                      request.reduction.leaf_claim)) {
                    return false;
                }
            }
            detail::observe_targets(selector, opening.column_targets,
                                    transcript_);
            const std::optional<basefold::OperandReduction> reduction =
                basefold::verify_all_columns(
                    table.root, table.shard_size,
                    table.physical_width, by_table[selector].size(),
                    opening.column_targets, opening.opening, transcript_,
                    key_.basefold_parameters);
            if (!reduction.has_value() ||
                reduction->operand_evaluations.size() !=
                    by_table[selector].size()) {
                return false;
            }
            for (std::size_t row = 0; row < by_table[selector].size(); ++row) {
                if (!(reduction->operand_evaluations[row] ==
                      equality_of_points(
                          linearizations[row].inner_point_lsb,
                          reduction->point))) {
                    return false;
                }
            }
        }
        return opening_cursor == proof_.table_openings.size();
    } catch (const std::invalid_argument &) {
        return false;
    } catch (const std::overflow_error &) {
        return false;
    } catch (const std::out_of_range &) {
        return false;
    }
}

} // namespace laminate::gates
