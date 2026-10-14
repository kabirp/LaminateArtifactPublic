#include "laminate/basefold/sumcheck.hpp"

#include "laminate/basefold/common.hpp"

#include <stdexcept>
#include <string_view>
#include <utility>

namespace laminate::basefold {
namespace {

constexpr std::string_view kRoundLabel = "basefold/round";
constexpr std::string_view kOperandEvaluationsLabel =
    "basefold/operand-evaluations";

Fpk interpolate_quadratic(const std::array<Fpk, 3> &evaluations,
                          const Fpk &point, const Fpk &inverse_two) {
    const Fpk one = Fpk::one();
    const Fpk two = one + one;
    const Fpk l0 = (point - one) * (point - two) * inverse_two;
    const Fpk l1 = point * (point - two);
    const Fpk l2 = point * (point - one) * inverse_two;
    return evaluations[0] * l0 - evaluations[1] * l1 +
           evaluations[2] * l2;
}

void observe_round(const std::array<Fpk, 3> &round,
                   PublicCoin &public_coin) {
    public_coin.observe(kRoundLabel, serialize_values(round));
}

} // namespace

std::vector<Fpk> fold_evaluations(std::span<const Fpk> table,
                                  const Fpk &challenge) {
    if (table.size() < 2 || (table.size() & 1U) != 0) {
        throw std::invalid_argument(
            "basefold::fold_evaluations: table length must be even");
    }
    std::vector<Fpk> result(table.size() / 2);
    for (std::size_t index = 0; index < result.size(); ++index) {
        const Fpk &lo = table[2 * index];
        const Fpk &hi = table[2 * index + 1];
        result[index] = lo + challenge * (hi - lo);
    }
    return result;
}

SumcheckProver::SumcheckProver(std::vector<Fpk> message,
                               std::vector<Fpk> combined_operand)
    : message_(std::move(message)),
      combined_operand_(std::move(combined_operand)) {
    if (message_.empty() || message_.size() != combined_operand_.size() ||
        (message_.size() & (message_.size() - 1)) != 0) {
        throw std::invalid_argument(
            "basefold::SumcheckProver: malformed input tables");
    }
}

Fpk SumcheckProver::prove_round(SumcheckProof &proof,
                                PublicCoin &public_coin) {
    if (message_.size() < 2) {
        throw std::logic_error(
            "basefold::SumcheckProver: no round remains");
    }

    std::array<Fpk, 3> round{Fpk::zero(), Fpk::zero(), Fpk::zero()};
    for (std::size_t index = 0; index < message_.size() / 2; ++index) {
        const Fpk &message_zero = message_[2 * index];
        const Fpk &message_one = message_[2 * index + 1];
        const Fpk &operand_zero = combined_operand_[2 * index];
        const Fpk &operand_one = combined_operand_[2 * index + 1];
        round[0] += message_zero * operand_zero;
        round[1] += message_one * operand_one;
        round[2] += (message_one + message_one - message_zero) *
                    (operand_one + operand_one - operand_zero);
    }

    proof.rounds.push_back(round);
    observe_round(round, public_coin);
    const Fpk challenge = public_coin.challenge_fpk();
    point_.push_back(challenge);
    message_ = fold_evaluations(message_, challenge);
    combined_operand_ = fold_evaluations(combined_operand_, challenge);
    return challenge;
}

void prove_operand_evaluations(
    const std::vector<std::vector<Fpk>> &operands,
    std::span<const Fpk> point, SumcheckProof &proof,
    PublicCoin &public_coin) {
    proof.operand_evaluations.reserve(operands.size());
    for (const std::vector<Fpk> &operand : operands) {
        proof.operand_evaluations.push_back(
            evaluate_multilinear(operand, point));
    }
    observe_operand_evaluations(proof.operand_evaluations, public_coin);
}

SumcheckVerifier::SumcheckVerifier(Fpk initial_claim)
    : claim_(std::move(initial_claim)),
      inverse_two_(Fpk::from_base(Fp(2).inverse())) {}

bool SumcheckVerifier::verify_round(const std::array<Fpk, 3> &round,
                                    PublicCoin &public_coin) {
    if (!(round[0] + round[1] == claim_)) {
        return false;
    }
    observe_round(round, public_coin);
    const Fpk challenge = public_coin.challenge_fpk();
    point_.push_back(challenge);
    claim_ = interpolate_quadratic(round, challenge, inverse_two_);
    return true;
}

bool SumcheckVerifier::verify_terminal(
    const Fpk &message_evaluation,
    std::span<const Fpk> operand_batching_challenges,
    std::span<const Fpk> operand_evaluations) const {
    if (operand_batching_challenges.size() != operand_evaluations.size()) {
        return false;
    }
    Fpk combined_operand = Fpk::zero();
    for (std::size_t operand = 0;
         operand < operand_batching_challenges.size(); ++operand) {
        combined_operand += operand_batching_challenges[operand] *
                            operand_evaluations[operand];
    }
    return claim_ == message_evaluation * combined_operand;
}

void observe_operand_evaluations(std::span<const Fpk> evaluations,
                                 PublicCoin &public_coin) {
    public_coin.observe(kOperandEvaluationsLabel,
                        serialize_values(evaluations));
}

} // namespace laminate::basefold
