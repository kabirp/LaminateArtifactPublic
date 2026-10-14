#ifndef LAMINATE_BASEFOLD_COMMITMENT_HPP
#define LAMINATE_BASEFOLD_COMMITMENT_HPP

/// @file commitment.hpp
/// @brief Interleaved Reed--Solomon commitment used by BaseFold.

#include "laminate/basefold/merkle.hpp"
#include "laminate/field/fp.hpp"

#include <cstddef>
#include <vector>

namespace laminate::basefold {

/// Prover state. Public setup retains only `root`, `m`, `width`, and rate.
struct Commitment {
    std::size_t m;
    std::size_t log_rate;
    std::size_t width;
    std::vector<std::vector<Fp>> columns;
    std::vector<std::vector<Fp>> codewords;
    MerkleTree tree;
    Digest root;

    Commitment(std::size_t message_length, std::size_t inverse_rate_log,
               std::vector<std::vector<Fp>> message_columns,
               std::vector<std::vector<Fp>> encoded_columns,
               MerkleTree commitment_tree);
};

/// Commit equal-length power-of-two columns under one interleaved tree.
Commitment commit(std::vector<std::vector<Fp>> columns,
                  std::size_t log_rate);

} // namespace laminate::basefold

#endif // LAMINATE_BASEFOLD_COMMITMENT_HPP
