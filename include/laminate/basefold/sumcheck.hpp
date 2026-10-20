#ifndef LAMINATE_BASEFOLD_SUMCHECK_HPP
#define LAMINATE_BASEFOLD_SUMCHECK_HPP

/// @file sumcheck.hpp
/// @brief Degree-two sumcheck for the BaseFold linear relation.
///
/// The round polynomial is
/// `h_j(X) = sum_suffix M(prefix, X, suffix) O(prefix, X, suffix)`.
/// Its three evaluations determine a quadratic. The least-significant
/// variable is bound first so the same challenge can fold the RS codeword.

#include "laminate/field/fpk.hpp"
#include "laminate/transcript/public_coin.hpp"

#include <array>
#include <cstddef>
#include <span>
#include <vector>

namespace laminate::basefold {

struct SumcheckProof {
    std::vector<std::array<Fpk, 3>> rounds;
    std::vector<Fpk> operand_evaluations;
};

struct OperandReduction {
    std::vector<Fpk> point;
    std::vector<Fpk> operand_evaluations;
};

std::vector<Fpk> fold_evaluations(std::span<const Fpk> table,
                                  const Fpk &challenge);

class SumcheckProver {
  public:
    SumcheckProver(std::vector<Fpk> message,
                   std::vector<Fpk> combined_operand);

    /// Append one round message, sample its challenge, and fold both tables.
    Fpk prove_round(SumcheckProof &proof, PublicCoin &public_coin);

    const std::vector<Fpk> &point() const { return point_; }

  private:
    std::vector<Fpk> message_;
    std::vector<Fpk> combined_operand_;
    std::vector<Fpk> point_;
};

/// Evaluate each transparent operand at the terminal sumcheck point, append
/// the claims to `proof`, and bind them to the public-coin channel.
void prove_operand_evaluations(
    const std::vector<std::vector<Fpk>> &operands,
    std::span<const Fpk> point, SumcheckProof &proof,
    PublicCoin &public_coin);

class SumcheckVerifier {
  public:
    explicit SumcheckVerifier(Fpk initial_claim);

    bool verify_round(const std::array<Fpk, 3> &round,
                      PublicCoin &public_coin);
    bool verify_terminal(
        const Fpk &message_evaluation,
        std::span<const Fpk> operand_batching_challenges,
        std::span<const Fpk> operand_evaluations) const;

    const std::vector<Fpk> &point() const { return point_; }

  private:
    Fpk claim_;
    Fpk inverse_two_;
    std::vector<Fpk> point_;
};

void observe_operand_evaluations(std::span<const Fpk> evaluations,
                                 PublicCoin &public_coin);

} // namespace laminate::basefold

#endif // LAMINATE_BASEFOLD_SUMCHECK_HPP
