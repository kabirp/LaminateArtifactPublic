#include "reduction.hpp"

#include "laminate/basefold/common.hpp"
#include "laminate/basefold/reed_solomon.hpp"

#include <stdexcept>
#include <string>
#include <utility>

namespace laminate::basefold::detail {
namespace {

std::vector<Fpk> combine_operands(
    const std::vector<std::vector<Fpk>> &operands,
    std::span<const Fpk> batching, std::size_t m) {
    std::vector<Fpk> result(m, Fpk::zero());
    for (std::size_t operand = 0; operand < operands.size(); ++operand) {
        for (std::size_t index = 0; index < m; ++index) {
            result[index] += batching[operand] * operands[operand][index];
        }
    }
    return result;
}

bool valid_proof_shape(const Proof &proof, std::size_t mu,
                       std::size_t log_rate, std::size_t num_operands,
                       std::size_t num_queries) {
    return proof.sumcheck.rounds.size() == mu &&
           proof.sumcheck.operand_evaluations.size() == num_operands &&
           proof.folding.roots.size() == (mu == 0 ? 0 : mu - 1) &&
           proof.folding.final_codeword.size() ==
               (std::size_t{1} << log_rate) &&
           proof.queries.openings.size() == num_queries;
}

} // namespace

void validate_commitment(
    const Commitment &commitment,
    const std::vector<std::vector<Fpk>> &operands) {
    if (!valid_shape(commitment.m, commitment.width,
                     Parameters{commitment.log_rate, 1}) ||
        commitment.columns.size() != commitment.width ||
        commitment.codewords.size() != commitment.width ||
        commitment.tree.leaf_count() !=
            codeword_length(commitment.m, commitment.log_rate) ||
        commitment.tree.root() != commitment.root || operands.empty()) {
        throw std::invalid_argument(
            "basefold::prove: malformed commitment or empty operand batch");
    }
    const std::size_t encoded_size =
        codeword_length(commitment.m, commitment.log_rate);
    for (std::size_t column = 0; column < commitment.width; ++column) {
        if (commitment.columns[column].size() != commitment.m ||
            commitment.codewords[column].size() != encoded_size) {
            throw std::invalid_argument(
                "basefold::prove: malformed commitment column");
        }
    }
    for (const std::vector<Fpk> &operand : operands) {
        if (operand.size() != commitment.m) {
            throw std::invalid_argument(
                "basefold::prove: malformed transparent operand");
        }
    }
}

void validate_targets(const ColumnTargets &targets,
                      std::size_t num_operands, std::size_t width,
                      const char *operation) {
    if (targets.size() != num_operands) {
        throw std::invalid_argument(std::string(operation) +
                                    ": wrong operand count");
    }
    for (const std::vector<Fpk> &row : targets) {
        if (row.size() != width) {
            throw std::invalid_argument(std::string(operation) +
                                        ": wrong column count");
        }
    }
}

std::vector<Fpk> combine_columns(
    const std::vector<std::vector<Fp>> &columns,
    std::span<const Fpk> weights, std::size_t length) {
    std::vector<Fpk> result(length, Fpk::zero());
    for (std::size_t column = 0; column < columns.size(); ++column) {
        for (std::size_t index = 0; index < length; ++index) {
            result[index] += weights[column] * columns[column][index];
        }
    }
    return result;
}

std::vector<Fpk> derive_operand_batching(PublicCoin &public_coin,
                                         std::size_t count) {
    std::vector<Fpk> challenges;
    challenges.reserve(count);
    for (std::size_t index = 0; index < count; ++index) {
        challenges.push_back(public_coin.challenge_fpk());
    }
    return challenges;
}

BatchingChallenges derive_two_dimensional_batching(
    PublicCoin &public_coin, std::size_t num_operands,
    std::size_t width) {
    BatchingChallenges result;
    result.operands = derive_operand_batching(public_coin, num_operands);
    // For authenticated, honestly preprocessed columns, an incorrect target
    // matrix yields a nonzero polynomial of total degree at most
    // log2(width)+1, including the independent linear operand batch.
    std::vector<Fpk> column_point;
    const std::size_t column_variables = log2_exact(width);
    column_point.reserve(column_variables);
    for (std::size_t variable = 0; variable < column_variables; ++variable) {
        column_point.push_back(public_coin.challenge_fpk());
    }
    result.columns = equality_evaluations(column_point);
    return result;
}

Fpk initial_claim(std::span<const Fpk> targets,
                  std::span<const Fpk> batching) {
    Fpk result = Fpk::zero();
    for (std::size_t operand = 0; operand < targets.size(); ++operand) {
        result += batching[operand] * targets[operand];
    }
    return result;
}

Fpk initial_claim(const ColumnTargets &targets,
                  const BatchingChallenges &batching) {
    Fpk result = Fpk::zero();
    for (std::size_t operand = 0; operand < targets.size(); ++operand) {
        for (std::size_t column = 0; column < targets[operand].size();
             ++column) {
            result += batching.operands[operand] *
                      batching.columns[column] * targets[operand][column];
        }
    }
    return result;
}

ProverOutput prove_combined(
    const Commitment &commitment,
    const std::vector<std::vector<Fpk>> &operands,
    std::span<const Fpk> operand_batching, std::vector<Fpk> message,
    PublicCoin &public_coin, const Parameters &parameters) {
    FoldingProver folding(reed_solomon_encode(
        evaluations_to_coefficients(message), commitment.log_rate));
    SumcheckProver sumcheck(
        std::move(message),
        combine_operands(operands, operand_batching, commitment.m));

    Proof proof;
    const std::size_t mu = log2_exact(commitment.m);
    proof.sumcheck.rounds.reserve(mu);
    proof.folding.roots.reserve(mu == 0 ? 0 : mu - 1);
    for (std::size_t round = 0; round < mu; ++round) {
        const Fpk challenge =
            sumcheck.prove_round(proof.sumcheck, public_coin);
        folding.fold_round(challenge, round + 1 < mu, proof.folding,
                           public_coin);
    }
    prove_operand_evaluations(operands, sumcheck.point(), proof.sumcheck,
                              public_coin);
    folding.finish(proof.folding, public_coin);
    proof.queries = prove_queries(commitment, folding, public_coin,
                                  parameters.num_queries);
    OperandReduction reduction{sumcheck.point(),
                               proof.sumcheck.operand_evaluations};
    return {std::move(proof), std::move(reduction)};
}

std::optional<OperandReduction> verify_combined(
    const Digest &commitment_root, std::size_t m, std::size_t width,
    std::span<const Fpk> operand_batching,
    std::span<const Fpk> column_weights, const Fpk &batched_claim,
    const Proof &proof, PublicCoin &public_coin,
    const Parameters &parameters) {
    const std::size_t mu = log2_exact(m);
    if (!valid_proof_shape(proof, mu, parameters.log_rate,
                           operand_batching.size(),
                           parameters.num_queries)) {
        return std::nullopt;
    }

    SumcheckVerifier sumcheck(batched_claim);
    for (std::size_t round = 0; round < mu; ++round) {
        if (!sumcheck.verify_round(proof.sumcheck.rounds[round],
                                   public_coin)) {
            return std::nullopt;
        }
        if (round + 1 < mu) {
            observe_folded_root(proof.folding.roots[round], public_coin);
        }
    }
    observe_operand_evaluations(proof.sumcheck.operand_evaluations,
                                public_coin);
    if (!terminal_codeword_is_constant(proof.folding) ||
        !sumcheck.verify_terminal(proof.folding.final_codeword.front(),
                                  operand_batching,
                                  proof.sumcheck.operand_evaluations)) {
        return std::nullopt;
    }
    observe_final_codeword(proof.folding.final_codeword, public_coin);
    if (!verify_queries(commitment_root, m, width, parameters.log_rate,
                        column_weights, proof.folding, proof.queries,
                        sumcheck.point(), public_coin,
                        parameters.num_queries)) {
        return std::nullopt;
    }
    return OperandReduction{sumcheck.point(),
                            proof.sumcheck.operand_evaluations};
}

} // namespace laminate::basefold::detail
