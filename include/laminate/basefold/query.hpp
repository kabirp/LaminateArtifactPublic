#ifndef LAMINATE_BASEFOLD_QUERY_HPP
#define LAMINATE_BASEFOLD_QUERY_HPP

/// @file query.hpp
/// @brief Merkle query generation and verification for BaseFold.

#include "laminate/basefold/commitment.hpp"
#include "laminate/basefold/folding.hpp"

#include <cstddef>
#include <span>
#include <vector>

namespace laminate::basefold {

struct FoldOpening {
    Fpk lo{};
    Fpk hi{};
    std::vector<Digest> path_lo;
    std::vector<Digest> path_hi;
};

struct QueryOpening {
    std::size_t index = 0;
    std::vector<Fp> base_lo;
    std::vector<Fp> base_hi;
    std::vector<Digest> base_path_lo;
    std::vector<Digest> base_path_hi;
    std::vector<FoldOpening> folds;
};

struct QueryProof {
    std::vector<QueryOpening> openings;
};

std::vector<std::size_t>
derive_query_indices(PublicCoin &public_coin, std::size_t num_queries,
                     std::size_t half_codeword_length);

QueryProof prove_queries(const Commitment &commitment,
                         const FoldingProver &folding,
                         PublicCoin &public_coin,
                         std::size_t num_queries);

bool verify_queries(const Digest &commitment_root, std::size_t m,
                    std::size_t width, std::size_t log_rate,
                    std::span<const Fpk> column_weights,
                    const FoldingProof &folding, const QueryProof &proof,
                    std::span<const Fpk> folding_challenges,
                    PublicCoin &public_coin, std::size_t num_queries);

} // namespace laminate::basefold

#endif // LAMINATE_BASEFOLD_QUERY_HPP
