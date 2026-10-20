#ifndef LAMINATE_BASEFOLD_REDUCTION_HPP
#define LAMINATE_BASEFOLD_REDUCTION_HPP

/// @file reduction.hpp
/// @brief Private shared mechanics for BaseFold's two public batching modes.

#include "laminate/basefold/basefold.hpp"

#include <cstddef>
#include <optional>
#include <span>
#include <vector>

namespace laminate::basefold::detail {

struct BatchingChallenges {
    std::vector<Fpk> operands;
    std::vector<Fpk> columns;
};

void validate_commitment(
    const Commitment &commitment,
    const std::vector<std::vector<Fpk>> &operands);
void validate_targets(const ColumnTargets &targets,
                      std::size_t num_operands, std::size_t width,
                      const char *operation);

std::vector<Fpk> combine_columns(
    const std::vector<std::vector<Fp>> &columns,
    std::span<const Fpk> weights, std::size_t length);
std::vector<Fpk> derive_operand_batching(PublicCoin &public_coin,
                                         std::size_t count);
BatchingChallenges derive_two_dimensional_batching(
    PublicCoin &public_coin, std::size_t num_operands,
    std::size_t width);

Fpk initial_claim(std::span<const Fpk> targets,
                  std::span<const Fpk> batching);
Fpk initial_claim(const ColumnTargets &targets,
                  const BatchingChallenges &batching);

ProverOutput prove_combined(
    const Commitment &commitment,
    const std::vector<std::vector<Fpk>> &operands,
    std::span<const Fpk> operand_batching, std::vector<Fpk> message,
    PublicCoin &public_coin, const Parameters &parameters);

std::optional<OperandReduction> verify_combined(
    const Digest &commitment_root, std::size_t m, std::size_t width,
    std::span<const Fpk> operand_batching,
    std::span<const Fpk> column_weights, const Fpk &batched_claim,
    const Proof &proof, PublicCoin &public_coin,
    const Parameters &parameters);

} // namespace laminate::basefold::detail

#endif // LAMINATE_BASEFOLD_REDUCTION_HPP
