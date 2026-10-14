#include "laminate/basefold/basefold.hpp"

#include "laminate/basefold/common.hpp"
#include "laminate/params.hpp"

#include "reduction.hpp"

#include <limits>
#include <stdexcept>
#include <utility>

namespace laminate::basefold {
namespace {

bool is_power_of_two(std::size_t value) {
    return value != 0 && (value & (value - 1)) == 0;
}

} // namespace

bool valid_shape(std::size_t m, std::size_t width,
                 const Parameters &parameters) {
    if (!is_power_of_two(m) || !is_power_of_two(width) ||
        parameters.num_queries == 0 ||
        parameters.log_rate >= std::numeric_limits<std::size_t>::digits) {
        return false;
    }
    const std::size_t log_m = log2_exact(m);
    if (parameters.log_rate > kBaseFieldTwoAdicity ||
        log_m > kBaseFieldTwoAdicity - parameters.log_rate) {
        return false;
    }
    return log_m + parameters.log_rate >= 1;
}

PreparedLinearCombination prepare_linear_combination(
    const Commitment &commitment,
    const std::vector<std::vector<Fpk>> &operands,
    std::span<const Fpk> column_weights) {
    detail::validate_commitment(commitment, operands);
    if (column_weights.size() != commitment.width) {
        throw std::invalid_argument(
            "basefold::prepare_linear_combination: wrong weight count");
    }

    PreparedLinearCombination result;
    result.message = detail::combine_columns(
        commitment.columns, column_weights, commitment.m);
    result.targets.assign(operands.size(), Fpk::zero());
    for (std::size_t operand = 0; operand < operands.size(); ++operand) {
        for (std::size_t index = 0; index < commitment.m; ++index) {
            result.targets[operand] +=
                result.message[index] * operands[operand][index];
        }
    }
    return result;
}

ColumnTargets prepare_all_column_targets(
    const Commitment &commitment,
    const std::vector<std::vector<Fpk>> &operands) {
    detail::validate_commitment(commitment, operands);
    ColumnTargets targets(
        operands.size(), std::vector<Fpk>(commitment.width, Fpk::zero()));
    for (std::size_t operand = 0; operand < operands.size(); ++operand) {
        for (std::size_t column = 0; column < commitment.width; ++column) {
            for (std::size_t index = 0; index < commitment.m; ++index) {
                targets[operand][column] +=
                    operands[operand][index] *
                    commitment.columns[column][index];
            }
        }
    }
    return targets;
}

ProverOutput prove(const Commitment &commitment,
                   const std::vector<std::vector<Fpk>> &operands,
                   std::span<const Fpk> column_weights,
                   PreparedLinearCombination combination,
                   PublicCoin &public_coin, const Parameters &parameters) {
    detail::validate_commitment(commitment, operands);
    if (parameters.log_rate != commitment.log_rate ||
        parameters.num_queries == 0 ||
        column_weights.size() != commitment.width ||
        combination.message.size() != commitment.m ||
        combination.targets.size() != operands.size()) {
        throw std::invalid_argument("basefold::prove: inconsistent inputs");
    }
    const std::vector<Fpk> batching =
        detail::derive_operand_batching(public_coin, operands.size());
    return detail::prove_combined(
        commitment, operands, batching, std::move(combination.message),
        public_coin, parameters);
}

ProverOutput prove_all_columns(
    const Commitment &commitment,
    const std::vector<std::vector<Fpk>> &operands,
    const ColumnTargets &targets, PublicCoin &public_coin,
    const Parameters &parameters) {
    detail::validate_commitment(commitment, operands);
    detail::validate_targets(targets, operands.size(), commitment.width,
                             "basefold::prove_all_columns");
    if (parameters.log_rate != commitment.log_rate ||
        parameters.num_queries == 0) {
        throw std::invalid_argument(
            "basefold::prove_all_columns: inconsistent parameters");
    }
    const detail::BatchingChallenges batching =
        detail::derive_two_dimensional_batching(
            public_coin, operands.size(), commitment.width);
    return detail::prove_combined(
        commitment, operands, batching.operands,
        detail::combine_columns(commitment.columns, batching.columns,
                                commitment.m),
        public_coin, parameters);
}

std::optional<OperandReduction> verify(
    const Digest &commitment_root, std::size_t m, std::size_t width,
    std::size_t num_operands, std::span<const Fpk> column_weights,
    std::span<const Fpk> targets, const Proof &proof,
    PublicCoin &public_coin, const Parameters &parameters) {
    if (!valid_shape(m, width, parameters) || num_operands == 0 ||
        column_weights.size() != width || targets.size() != num_operands) {
        return std::nullopt;
    }
    const std::vector<Fpk> batching =
        detail::derive_operand_batching(public_coin, num_operands);
    return detail::verify_combined(
        commitment_root, m, width, batching, column_weights,
        detail::initial_claim(targets, batching), proof, public_coin,
        parameters);
}

std::optional<OperandReduction> verify_all_columns(
    const Digest &commitment_root, std::size_t m, std::size_t width,
    std::size_t num_operands, const ColumnTargets &targets,
    const Proof &proof, PublicCoin &public_coin,
    const Parameters &parameters) {
    if (!valid_shape(m, width, parameters) || num_operands == 0) {
        return std::nullopt;
    }
    try {
        detail::validate_targets(targets, num_operands, width,
                                 "basefold::verify_all_columns");
    } catch (const std::invalid_argument &) {
        return std::nullopt;
    }
    const detail::BatchingChallenges batching =
        detail::derive_two_dimensional_batching(public_coin, num_operands,
                                                width);
    return detail::verify_combined(
        commitment_root, m, width, batching.operands, batching.columns,
        detail::initial_claim(targets, batching), proof, public_coin,
        parameters);
}

bool verify_with_materialized_operands(
    const Digest &commitment_root, std::size_t m, std::size_t width,
    const std::vector<std::vector<Fpk>> &operands,
    std::span<const Fpk> column_weights, std::span<const Fpk> targets,
    const Proof &proof, PublicCoin &public_coin,
    const Parameters &parameters) {
    const std::optional<OperandReduction> reduction = verify(
        commitment_root, m, width, operands.size(), column_weights, targets,
        proof, public_coin, parameters);
    if (!reduction.has_value() || operands.size() != targets.size()) {
        return false;
    }
    for (std::size_t operand = 0; operand < operands.size(); ++operand) {
        if (operands[operand].size() != m ||
            !(evaluate_multilinear(operands[operand], reduction->point) ==
              reduction->operand_evaluations[operand])) {
            return false;
        }
    }
    return true;
}

} // namespace laminate::basefold
