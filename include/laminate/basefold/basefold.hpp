#ifndef LAMINATE_BASEFOLD_BASEFOLD_HPP
#define LAMINATE_BASEFOLD_BASEFOLD_HPP

/// @file basefold.hpp
/// @brief A focused BaseFold proof for fixed combinations of committed columns.
///
/// This is the smallest BaseFold subset needed by Laminate gate outsourcing.
/// Given public extension-field weights `lambda_c`, it proves all relations
///
///   target_j = <operand_j, sum_c lambda_c * committed_column_c>.
///
/// The caller must absorb the commitment metadata, weights, and targets before
/// calling `prove` or `verify`; both functions then append the same BaseFold
/// messages and challenges to that caller-owned public-coin channel.

#include "laminate/basefold/commitment.hpp"
#include "laminate/basefold/folding.hpp"
#include "laminate/basefold/query.hpp"
#include "laminate/basefold/sumcheck.hpp"
#include "laminate/params.hpp"

#include <cstddef>
#include <optional>
#include <span>
#include <vector>

namespace laminate::basefold {

struct Parameters {
    std::size_t log_rate = kGateMleBaseFoldLogRate;
    /// Query paths through one folding transcript, sampled as one final
    /// verifier challenge block. See docs/BASEFOLD_SOUNDNESS.md.
    std::size_t num_queries = kGateMleBaseFoldQueries;

    bool operator==(const Parameters &) const = default;
};

struct Proof {
    SumcheckProof sumcheck;
    FoldingProof folding;
    QueryProof queries;
};

struct PreparedLinearCombination {
    std::vector<Fpk> message;
    std::vector<Fpk> targets;
};

/// All per-operand, per-column dot products. This mode supports a distinct
/// verifier-specified column point for every composed MLE claim.
using ColumnTargets = std::vector<std::vector<Fpk>>;

struct ProverOutput {
    Proof proof;
    OperandReduction reduction;
};

/// Verify that dimensions and Fp's two-adicity support these parameters.
bool valid_shape(std::size_t m, std::size_t width,
                 const Parameters &parameters);

/// Form the weighted committed message and its claimed inner products.
PreparedLinearCombination prepare_linear_combination(
    const Commitment &commitment,
    const std::vector<std::vector<Fpk>> &operands,
    std::span<const Fpk> column_weights);

/// Compute `targets[j][c] = <operands[j], committed_column[c]>`.
ColumnTargets prepare_all_column_targets(
    const Commitment &commitment,
    const std::vector<std::vector<Fpk>> &operands);

/// Produce an argument after the caller has bound the root and claims.
ProverOutput prove(const Commitment &commitment,
                   const std::vector<std::vector<Fpk>> &operands,
                   std::span<const Fpk> column_weights,
                   PreparedLinearCombination combination,
                   PublicCoin &public_coin,
                   const Parameters &parameters = {});

/// Prove all operand/column relations in one two-dimensional random batch.
/// The caller must bind the complete target matrix before this call.
ProverOutput prove_all_columns(
    const Commitment &commitment,
    const std::vector<std::vector<Fpk>> &operands,
    const ColumnTargets &targets, PublicCoin &public_coin,
    const Parameters &parameters = {});

/// Verify BaseFold and return the transparent operand claims to be discharged
/// by the composing protocol. No materialized table is needed by this call.
std::optional<OperandReduction> verify(
    const Digest &commitment_root, std::size_t m, std::size_t width,
    std::size_t num_operands, std::span<const Fpk> column_weights,
    std::span<const Fpk> targets, const Proof &proof,
    PublicCoin &public_coin, const Parameters &parameters = {});

std::optional<OperandReduction> verify_all_columns(
    const Digest &commitment_root, std::size_t m, std::size_t width,
    std::size_t num_operands, const ColumnTargets &targets,
    const Proof &proof, PublicCoin &public_coin,
    const Parameters &parameters = {});

/// Test/reference helper that also evaluates every materialized operand.
bool verify_with_materialized_operands(
    const Digest &commitment_root, std::size_t m, std::size_t width,
    const std::vector<std::vector<Fpk>> &operands,
    std::span<const Fpk> column_weights, std::span<const Fpk> targets,
    const Proof &proof, PublicCoin &public_coin,
    const Parameters &parameters = {});

} // namespace laminate::basefold

#endif // LAMINATE_BASEFOLD_BASEFOLD_HPP
