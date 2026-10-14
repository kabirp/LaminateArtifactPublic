#ifndef LAMINATE_BASEFOLD_FOLDING_HPP
#define LAMINATE_BASEFOLD_FOLDING_HPP

/// @file folding.hpp
/// @brief FRI-style codeword folding and folded-oracle commitments.

#include "laminate/basefold/merkle.hpp"
#include "laminate/field/fp.hpp"
#include "laminate/field/fpk.hpp"
#include "laminate/transcript/public_coin.hpp"

#include <cstddef>
#include <span>
#include <vector>

namespace laminate::basefold {

struct FoldingProof {
    /// Roots for the nonterminal folded codewords c_1 through c_(mu-1).
    std::vector<Digest> roots;
    /// The final inverse-rate-sized codeword, which must be constant.
    std::vector<Fpk> final_codeword;
};

Fpk fold_codeword_pair(const Fpk &lo, const Fpk &hi,
                       const Fpk &challenge,
                       const Fp &inverse_generator_power,
                       const Fp &inverse_two);

std::vector<Fpk> fold_codeword(std::span<const Fpk> codeword,
                               const Fpk &challenge,
                               const Fp &generator);

void observe_folded_root(const Digest &root, PublicCoin &public_coin);
void observe_final_codeword(std::span<const Fpk> codeword,
                            PublicCoin &public_coin);

class FoldingProver {
  public:
    explicit FoldingProver(std::vector<Fpk> combined_codeword);

    /// Fold once and optionally commit the nonterminal result.
    void fold_round(const Fpk &challenge, bool commit_result,
                    FoldingProof &proof, PublicCoin &public_coin);
    void finish(FoldingProof &proof, PublicCoin &public_coin) const;

    const std::vector<std::vector<Fpk>> &layers() const { return layers_; }
    const std::vector<MerkleTree> &trees() const { return trees_; }

  private:
    std::vector<std::vector<Fpk>> layers_;
    std::vector<MerkleTree> trees_;
    Fp generator_;
};

bool terminal_codeword_is_constant(const FoldingProof &proof);

} // namespace laminate::basefold

#endif // LAMINATE_BASEFOLD_FOLDING_HPP
