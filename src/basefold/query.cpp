#include "laminate/basefold/query.hpp"

#include "laminate/basefold/common.hpp"

#include <array>
#include <limits>
#include <stdexcept>
#include <utility>

namespace laminate::basefold {
namespace {

std::vector<Fp> read_interleaved_leaf(
    const std::vector<std::vector<Fp>> &codewords, std::size_t position) {
    std::vector<Fp> leaf;
    leaf.reserve(codewords.size());
    for (const std::vector<Fp> &codeword : codewords) {
        leaf.push_back(codeword[position]);
    }
    return leaf;
}

Fpk weighted_leaf(std::span<const Fp> leaf,
                  std::span<const Fpk> weights) {
    Fpk result = Fpk::zero();
    for (std::size_t column = 0; column < leaf.size(); ++column) {
        result += weights[column] * leaf[column];
    }
    return result;
}

bool verify_base_opening(const Digest &root, std::size_t codeword_size,
                         std::size_t index,
                         const std::vector<Fp> &leaf,
                         const std::vector<Digest> &path) {
    return MerkleTree::verify(root, codeword_size, index,
                              serialize_values(leaf), path);
}

bool verify_fold_opening(const Digest &root, std::size_t layer_size,
                         std::size_t index, const Fpk &value,
                         const std::vector<Digest> &path) {
    const std::array<Fpk, 1> leaf{value};
    return MerkleTree::verify(root, layer_size, index,
                              serialize_values(leaf), path);
}

} // namespace

std::vector<std::size_t>
derive_query_indices(PublicCoin &public_coin, std::size_t num_queries,
                     std::size_t half_codeword_length) {
    const std::size_t bits = log2_exact(half_codeword_length);
    if (bits != 0 &&
        num_queries > std::numeric_limits<std::size_t>::max() / bits) {
        throw std::overflow_error(
            "basefold::derive_query_indices: challenge-bit count overflows");
    }
    const std::vector<bool> challenge_bits =
        public_coin.challenge_bits(num_queries * bits);
    std::vector<std::size_t> indices(num_queries, 0);
    for (std::size_t query = 0; query < num_queries; ++query) {
        for (std::size_t bit = 0; bit < bits; ++bit) {
            if (challenge_bits[query * bits + bit]) {
                indices[query] |= std::size_t{1} << bit;
            }
        }
    }
    return indices;
}

QueryProof prove_queries(const Commitment &commitment,
                         const FoldingProver &folding,
                         PublicCoin &public_coin,
                         std::size_t num_queries) {
    const std::size_t mu = log2_exact(commitment.m);
    const std::size_t encoded_size =
        codeword_length(commitment.m, commitment.log_rate);
    const std::size_t half_base = encoded_size / 2;
    const std::vector<std::size_t> indices =
        derive_query_indices(public_coin, num_queries, half_base);
    if (folding.layers().size() != mu + 1 ||
        folding.trees().size() != (mu == 0 ? 0 : mu - 1)) {
        throw std::logic_error(
            "basefold::prove_queries: incomplete folding state");
    }

    QueryProof proof;
    proof.openings.reserve(num_queries);
    for (const std::size_t query_index : indices) {
        QueryOpening opening;
        opening.index = query_index;
        opening.base_lo =
            read_interleaved_leaf(commitment.codewords, query_index);
        opening.base_hi = read_interleaved_leaf(
            commitment.codewords, query_index + half_base);
        opening.base_path_lo = commitment.tree.open(query_index);
        opening.base_path_hi =
            commitment.tree.open(query_index + half_base);

        std::size_t layer_half = half_base;
        std::size_t layer_index = query_index;
        for (std::size_t round = 0; round + 1 < mu; ++round) {
            layer_half /= 2;
            layer_index %= layer_half;
            FoldOpening fold;
            fold.lo = folding.layers()[round + 1][layer_index];
            fold.hi =
                folding.layers()[round + 1][layer_index + layer_half];
            fold.path_lo = folding.trees()[round].open(layer_index);
            fold.path_hi =
                folding.trees()[round].open(layer_index + layer_half);
            opening.folds.push_back(std::move(fold));
        }
        proof.openings.push_back(std::move(opening));
    }
    return proof;
}

bool verify_queries(const Digest &commitment_root, std::size_t m,
                    std::size_t width, std::size_t log_rate,
                    std::span<const Fpk> column_weights,
                    const FoldingProof &folding, const QueryProof &proof,
                    std::span<const Fpk> folding_challenges,
                    PublicCoin &public_coin, std::size_t num_queries) {
    const std::size_t mu = log2_exact(m);
    const std::size_t encoded_size = codeword_length(m, log_rate);
    if (encoded_size < 2 || column_weights.size() != width ||
        folding_challenges.size() != mu ||
        proof.openings.size() != num_queries) {
        return false;
    }

    const std::size_t half_base = encoded_size / 2;
    const std::vector<std::size_t> expected_indices =
        derive_query_indices(public_coin, num_queries, half_base);
    const Fp omega =
        Fp::two_adic_generator(log2_exact(encoded_size));
    const Fp inverse_omega = omega.inverse();
    const Fp inverse_two = Fp(2).inverse();

    for (std::size_t query = 0; query < num_queries; ++query) {
        const QueryOpening &opening = proof.openings[query];
        const std::size_t expected_folds = mu == 0 ? 0 : mu - 1;
        if (opening.index != expected_indices[query] ||
            opening.base_lo.size() != width ||
            opening.base_hi.size() != width ||
            opening.folds.size() != expected_folds ||
            !verify_base_opening(commitment_root, encoded_size,
                                 opening.index, opening.base_lo,
                                 opening.base_path_lo) ||
            !verify_base_opening(commitment_root, encoded_size,
                                 opening.index + half_base,
                                 opening.base_hi,
                                 opening.base_path_hi)) {
            return false;
        }

        Fpk lo = weighted_leaf(opening.base_lo, column_weights);
        Fpk hi = weighted_leaf(opening.base_hi, column_weights);
        std::size_t index = opening.index;
        std::size_t layer_half = half_base;
        Fp inverse_generator = inverse_omega;

        if (mu == 0 &&
            (!(lo == folding.final_codeword[index]) ||
             !(hi == folding.final_codeword[index + half_base]))) {
            return false;
        }

        for (std::size_t round = 0; round < mu; ++round) {
            const Fp inverse_generator_power =
                field_power(inverse_generator, index);
            const Fpk folded = fold_codeword_pair(
                lo, hi, folding_challenges[round],
                inverse_generator_power, inverse_two);
            const std::size_t next_half = layer_half / 2;
            const std::size_t next_index =
                index % (next_half == 0 ? 1 : next_half);

            if (round + 1 < mu) {
                const FoldOpening &next = opening.folds[round];
                const std::size_t next_layer_size = layer_half;
                if (!verify_fold_opening(
                        folding.roots[round], next_layer_size, next_index,
                        next.lo, next.path_lo) ||
                    !verify_fold_opening(
                        folding.roots[round], next_layer_size,
                        next_index + next_half, next.hi,
                        next.path_hi)) {
                    return false;
                }
                const Fpk &expected =
                    index < next_half ? next.lo : next.hi;
                if (!(folded == expected)) {
                    return false;
                }
                lo = next.lo;
                hi = next.hi;
            } else if (index >= folding.final_codeword.size() ||
                       !(folded == folding.final_codeword[index])) {
                return false;
            }

            inverse_generator *= inverse_generator;
            layer_half = next_half;
            index = next_index;
        }
    }
    return true;
}

} // namespace laminate::basefold
