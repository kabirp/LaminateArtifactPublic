/// @file sumcheck.cpp
/// @brief Linear-time Spartan sumchecks with omitted endpoint messages.

#include "laminate/spartan/sumcheck.hpp"

#include "laminate/field/serialization.hpp"
#include "laminate/transcript/hash.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <limits>
#include <memory>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace laminate::spartan {
namespace {

constexpr std::string_view kConstraintRoundLabel =
    "laminate/spartan/constraint-round/v2";
constexpr std::string_view kWiringRoundLabel =
    "laminate/spartan/wiring-round/v2";
constexpr std::string_view kArtifactSelectionDomain =
    "LaminateImpl/SpartanConstraintArtifactSelection/v2";
constexpr std::string_view kArtifactCheckpointDomain =
    "LaminateImpl/SpartanConstraintArtifactCheckpoint/v2";
constexpr std::array<std::string_view, 3> kConstraintArtifactArrays{
    "az", "bz", "cz"};

struct ConstraintState {
    std::vector<Fq2> suffix_equality;
    std::vector<Fq2> az;
    std::vector<Fq2> bz;
    std::vector<Fq2> cz;
    Fq2 stripped_claim = Fq2::zero();
    Fq2 equality_prefix = Fq2::one();
};

struct WiringState {
    std::vector<Fq2> matrix;
    std::vector<Fq2> assignment;
    Fq2 claim = Fq2::zero();
};

struct SourcePair {
    Fq2 at_zero{};
    Fq2 at_one{};
};

std::size_t log2_exact(std::size_t value);
std::vector<Fq2> equality_table(std::span<const Fq2> point);
template <typename Value>
SourcePair source_pair(std::span<const Value> values,
                       std::span<const Fq2> prefix_weights,
                       std::size_t suffix_count,
                       std::size_t suffix);
template <typename Value>
std::vector<Fq2> materialize_prefix(
    std::span<const Value> values,
    std::span<const Fq2> prefix_weights);
ConstraintSumcheckRound evaluate_constraint_source_round(
    std::span<const Fq> az, std::span<const Fq> bz,
    std::span<const Fq> cz,
    std::span<const Fq2> prefix_weights,
    std::span<const Fq2> suffix_equality, const Fq2 &tau);
WiringSumcheckRound evaluate_wiring_source_round(
    std::span<const Fq2> matrix, std::span<const Fq> assignment,
    std::span<const Fq2> prefix_weights);
ConstraintSumcheckRound evaluate_constraint_round(
    const ConstraintState &state, const Fq2 &tau);
WiringSumcheckRound evaluate_wiring_round(const WiringState &state);
Fq2 evaluate_quadratic(const Fq2 &at_zero, const Fq2 &at_one,
                       const Fq2 &at_two, const Fq2 &point);
Fq2 equality_factor(const Fq2 &left, const Fq2 &right);
void advance_constraint_claim(Fq2 &stripped_claim,
                              Fq2 &equality_prefix, const Fq2 &tau,
                              const Fq2 &challenge,
                              const ConstraintSumcheckRound &round);
void advance_wiring_claim(Fq2 &claim, const Fq2 &challenge,
                          const WiringSumcheckRound &round);
void drop_first_equality_variable(std::vector<Fq2> &table);
void bind_constraint_state(ConstraintState &state, const Fq2 &tau,
                           const Fq2 &challenge,
                           const ConstraintSumcheckRound &round);
void bind_wiring_state(WiringState &state, const Fq2 &challenge,
                       const WiringSumcheckRound &round);
void observe_constraint_round(const ConstraintSumcheckRound &round,
                              PublicCoin &public_coin);
void observe_wiring_round(const WiringSumcheckRound &round,
                          PublicCoin &public_coin);

} // namespace

ConstraintSumcheckOutput prove_constraint_sumcheck(
    std::span<const Fq2> tau, std::vector<Fq> az_values,
    std::vector<Fq> bz_values, std::vector<Fq> cz_values,
    PublicCoin &public_coin, std::size_t source_rounds) {
    const std::size_t variables = log2_exact(az_values.size());
    if (tau.size() != variables || bz_values.size() != az_values.size() ||
        cz_values.size() != az_values.size()) {
        throw std::invalid_argument(
            "constraint sumcheck dimensions are inconsistent");
    }
    if (source_rounds > kDefaultSourceSumcheckRounds) {
        throw std::invalid_argument(
            "constraint sumcheck supports at most two source rounds");
    }

    // Step 1: retain the base-field source for a few leading rounds. Building
    // full Fq2 copies up front is unnecessary: a round message only needs the
    // source MLE after the previously sampled prefix has been fixed.
    std::vector<Fq2> suffix_equality =
        equality_table(tau.empty() ? tau : tau.subspan(1));
    Fq2 stripped_claim = Fq2::zero();
    Fq2 equality_prefix = Fq2::one();
    ConstraintSumcheckOutput output;
    output.proof.rounds.reserve(variables);
    output.point.reserve(variables);

    const std::size_t source_round_count =
        std::min(source_rounds, variables);
    std::vector<Fq2> prefix_weights{Fq2::one()};
    for (std::size_t variable = 0; variable < source_round_count;
         ++variable) {
        const ConstraintSumcheckRound round =
            evaluate_constraint_source_round(
                az_values, bz_values, cz_values, prefix_weights,
                suffix_equality, tau[variable]);
        output.proof.rounds.push_back(round);
        observe_constraint_round(round, public_coin);
        const Fq2 challenge = public_coin.challenge_fq2();
        output.point.push_back(challenge);
        advance_constraint_claim(stripped_claim, equality_prefix,
                                 tau[variable], challenge, round);
        if (suffix_equality.size() > 1) {
            drop_first_equality_variable(suffix_equality);
        }
        prefix_weights = equality_table(output.point);
    }
    if (source_round_count > 0 &&
        suffix_equality.capacity() != suffix_equality.size()) {
        std::vector<Fq2> compacted(
            suffix_equality.begin(), suffix_equality.end());
        suffix_equality.swap(compacted);
    }

    // Step 2: materialize only the state left after the source rounds. Release
    // each base table immediately after converting it so the transition does
    // not retain all source and folded tables at once.
    std::vector<Fq2> folded_az =
        materialize_prefix<Fq>(az_values, prefix_weights);
    std::vector<Fq>{}.swap(az_values);
    std::vector<Fq2> folded_bz =
        materialize_prefix<Fq>(bz_values, prefix_weights);
    std::vector<Fq>{}.swap(bz_values);
    std::vector<Fq2> folded_cz =
        materialize_prefix<Fq>(cz_values, prefix_weights);
    std::vector<Fq>{}.swap(cz_values);
    ConstraintState state{
        .suffix_equality = std::move(suffix_equality),
        .az = std::move(folded_az),
        .bz = std::move(folded_bz),
        .cz = std::move(folded_cz),
        .stripped_claim = stripped_claim,
        .equality_prefix = equality_prefix,
    };

    // Step 3: continue the linear-time recurrence on the folded tables.
    for (std::size_t variable = source_round_count; variable < variables;
         ++variable) {
        const ConstraintSumcheckRound round =
            evaluate_constraint_round(state, tau[variable]);
        output.proof.rounds.push_back(round);
        observe_constraint_round(round, public_coin);
        const Fq2 challenge = public_coin.challenge_fq2();
        output.point.push_back(challenge);
        bind_constraint_state(state, tau[variable], challenge, round);
    }

    // Step 4: expose the three terminal wire claims used by wiring sumcheck.
    output.az_evaluation = state.az.front();
    output.bz_evaluation = state.bz.front();
    output.cz_evaluation = state.cz.front();
    output.final_claim = state.equality_prefix * state.stripped_claim;
    if (state.stripped_claim !=
        output.az_evaluation * output.bz_evaluation -
            output.cz_evaluation) {
        throw std::logic_error("constraint sumcheck terminal mismatch");
    }
    return output;
}

WiringSumcheckOutput prove_wiring_sumcheck(
    std::vector<Fq2> matrix_values,
    std::vector<Fq> assignment_values, const Fq2 &claimed_value,
    PublicCoin &public_coin, std::size_t source_rounds) {
    const std::size_t variables = log2_exact(matrix_values.size());
    if (assignment_values.size() != matrix_values.size()) {
        throw std::invalid_argument(
            "wiring sumcheck dimensions are inconsistent");
    }
    if (source_rounds > kDefaultSourceSumcheckRounds) {
        throw std::invalid_argument(
            "wiring sumcheck supports at most two source rounds");
    }

    WiringSumcheckOutput output;
    output.proof.rounds.reserve(variables);
    output.point.reserve(variables);

    // Step 1: scan the source matrix and base-field assignment for the leading
    // rounds instead of copying and lifting both full-domain tables.
    const std::size_t source_round_count =
        std::min(source_rounds, variables);
    Fq2 running_claim = claimed_value;
    std::vector<Fq2> prefix_weights{Fq2::one()};
    for (std::size_t variable = 0; variable < source_round_count;
         ++variable) {
        const WiringSumcheckRound round = evaluate_wiring_source_round(
            matrix_values, assignment_values, prefix_weights);
        output.proof.rounds.push_back(round);
        observe_wiring_round(round, public_coin);
        const Fq2 challenge = public_coin.challenge_fq2();
        output.point.push_back(challenge);
        advance_wiring_claim(running_claim, challenge, round);
        prefix_weights = equality_table(output.point);
    }

    // Step 2: construct the reduced tables. Moving the row-bound matrix into
    // this function and releasing it after conversion avoids the former full
    // Fq2 matrix copy.
    std::vector<Fq2> folded_matrix =
        source_round_count == 0
            ? std::move(matrix_values)
            : materialize_prefix<Fq2>(matrix_values, prefix_weights);
    std::vector<Fq2>{}.swap(matrix_values);
    WiringState state{
        .matrix = std::move(folded_matrix),
        .assignment =
            materialize_prefix<Fq>(assignment_values, prefix_weights),
        .claim = running_claim,
    };
    std::vector<Fq>{}.swap(assignment_values);

    // Step 3: finish with the ordinary linear-time prover.
    for (std::size_t variable = source_round_count; variable < variables;
         ++variable) {
        const WiringSumcheckRound round = evaluate_wiring_round(state);
        output.proof.rounds.push_back(round);
        observe_wiring_round(round, public_coin);
        const Fq2 challenge = public_coin.challenge_fq2();
        output.point.push_back(challenge);
        bind_wiring_state(state, challenge, round);
    }

    // Step 4: expose the terminal product checked by the verifier.
    output.matrix_evaluation = state.matrix.front();
    output.assignment_evaluation = state.assignment.front();
    output.final_claim = state.claim;
    if (state.claim !=
        output.matrix_evaluation * output.assignment_evaluation) {
        throw std::logic_error("wiring sumcheck terminal mismatch");
    }
    return output;
}

SumcheckVerification verify_constraint_sumcheck(
    const ConstraintSumcheckProof &proof, const Fq2 &claimed_sum,
    std::span<const Fq2> tau, PublicCoin &public_coin) {
    SumcheckVerification result;
    if (proof.rounds.size() != tau.size()) {
        return result;
    }

    Fq2 stripped_claim = claimed_sum;
    Fq2 equality_prefix = Fq2::one();
    result.point.reserve(proof.rounds.size());
    for (std::size_t variable = 0; variable < proof.rounds.size();
         ++variable) {
        const auto &round = proof.rounds[variable];
        const bool singular = tau[variable] == Fq2::one();
        const Fq2 at_zero =
            singular
                ? round.endpoint
                : (stripped_claim - tau[variable] * round.endpoint) *
                      (Fq2::one() - tau[variable]).inverse();
        const Fq2 at_one = singular ? stripped_claim : round.endpoint;
        observe_constraint_round(round, public_coin);
        const Fq2 challenge = public_coin.challenge_fq2();
        result.point.push_back(challenge);
        stripped_claim = evaluate_quadratic(
            at_zero, at_one, round.at_two, challenge);
        equality_prefix *= equality_factor(tau[variable], challenge);
    }
    result.accepts = true;
    result.final_claim = equality_prefix * stripped_claim;
    return result;
}

SumcheckVerification verify_wiring_sumcheck(
    const WiringSumcheckProof &proof, const Fq2 &claimed_sum,
    PublicCoin &public_coin) {
    SumcheckVerification result;
    Fq2 running_claim = claimed_sum;
    result.point.reserve(proof.rounds.size());
    for (const auto &round : proof.rounds) {
        const Fq2 at_zero = running_claim - round.at_one;
        observe_wiring_round(round, public_coin);
        const Fq2 challenge = public_coin.challenge_fq2();
        result.point.push_back(challenge);
        running_claim = evaluate_quadratic(
            at_zero, round.at_one, round.at_two, challenge);
    }
    result.accepts = true;
    result.final_claim = running_claim;
    return result;
}

namespace {

std::size_t log2_exact(std::size_t value) {
    if (value == 0 || !std::has_single_bit(value)) {
        throw std::invalid_argument("sumcheck table is not a power of two");
    }
    return std::bit_width(value) - 1U;
}

std::vector<Fq2> equality_table(std::span<const Fq2> point) {
    if (point.size() >= std::numeric_limits<std::size_t>::digits) {
        throw std::overflow_error("sumcheck equality table is too large");
    }
    std::vector<Fq2> result(std::size_t{1} << point.size(), Fq2::zero());
    result.front() = Fq2::one();
    std::size_t active = 1;
    for (const Fq2 &coordinate : point) {
        for (std::size_t index = active; index-- > 0;) {
            const Fq2 previous = result[index];
            const Fq2 high = previous * coordinate;
            result[2 * index] = previous - high;
            result[2 * index + 1] = high;
        }
        active *= 2;
    }
    return result;
}

template <typename Value>
SourcePair source_pair(std::span<const Value> values,
                       std::span<const Fq2> prefix_weights,
                       std::size_t suffix_count,
                       std::size_t suffix) {
    if (prefix_weights.empty() || suffix_count == 0 ||
        suffix >= suffix_count ||
        prefix_weights.size() >
            std::numeric_limits<std::size_t>::max() / 2U ||
        2U * prefix_weights.size() >
            std::numeric_limits<std::size_t>::max() / suffix_count ||
        values.size() !=
            2U * prefix_weights.size() * suffix_count) {
        throw std::logic_error("source sumcheck pair has malformed geometry");
    }
    SourcePair result;
    const std::size_t prefix_stride = 2U * suffix_count;
    for (std::size_t prefix = 0; prefix < prefix_weights.size(); ++prefix) {
        const std::size_t begin = prefix * prefix_stride + suffix;
        result.at_zero += prefix_weights[prefix] * values[begin];
        result.at_one +=
            prefix_weights[prefix] * values[begin + suffix_count];
    }
    return result;
}

template <typename Value>
std::vector<Fq2> materialize_prefix(
    std::span<const Value> values,
    std::span<const Fq2> prefix_weights) {
    if (prefix_weights.empty() ||
        values.size() % prefix_weights.size() != 0) {
        throw std::logic_error(
            "source sumcheck checkpoint has malformed geometry");
    }
    const std::size_t suffix_count =
        values.size() / prefix_weights.size();
    std::vector<Fq2> result(suffix_count, Fq2::zero());
    for (std::size_t prefix = 0; prefix < prefix_weights.size(); ++prefix) {
        const std::size_t begin = prefix * suffix_count;
        for (std::size_t suffix = 0; suffix < suffix_count; ++suffix) {
            result[suffix] +=
                prefix_weights[prefix] * values[begin + suffix];
        }
    }
    return result;
}

ConstraintSumcheckRound evaluate_constraint_source_round(
    std::span<const Fq> az, std::span<const Fq> bz,
    std::span<const Fq> cz,
    std::span<const Fq2> prefix_weights,
    std::span<const Fq2> suffix_equality, const Fq2 &tau) {
    if (az.size() != bz.size() || az.size() != cz.size() ||
        suffix_equality.empty()) {
        throw std::logic_error(
            "constraint source round has malformed tables");
    }
    ConstraintSumcheckRound result;
    const bool transmit_at_zero = tau == Fq2::one();
    for (std::size_t suffix = 0; suffix < suffix_equality.size(); ++suffix) {
        const SourcePair a = source_pair<Fq>(
            az, prefix_weights, suffix_equality.size(), suffix);
        const SourcePair b = source_pair<Fq>(
            bz, prefix_weights, suffix_equality.size(), suffix);
        const SourcePair c = source_pair<Fq>(
            cz, prefix_weights, suffix_equality.size(), suffix);
        const Fq2 &a_endpoint =
            transmit_at_zero ? a.at_zero : a.at_one;
        const Fq2 &b_endpoint =
            transmit_at_zero ? b.at_zero : b.at_one;
        const Fq2 &c_endpoint =
            transmit_at_zero ? c.at_zero : c.at_one;
        const Fq2 &weight = suffix_equality[suffix];
        result.endpoint +=
            weight * (a_endpoint * b_endpoint - c_endpoint);
        const Fq2 a_two = a.at_one + a.at_one - a.at_zero;
        const Fq2 b_two = b.at_one + b.at_one - b.at_zero;
        const Fq2 c_two = c.at_one + c.at_one - c.at_zero;
        result.at_two += weight * (a_two * b_two - c_two);
    }
    return result;
}

WiringSumcheckRound evaluate_wiring_source_round(
    std::span<const Fq2> matrix, std::span<const Fq> assignment,
    std::span<const Fq2> prefix_weights) {
    if (matrix.size() != assignment.size() || prefix_weights.empty() ||
        prefix_weights.size() >
            std::numeric_limits<std::size_t>::max() / 2U) {
        throw std::logic_error("wiring source round has malformed tables");
    }
    const std::size_t fixed_prefixes = 2U * prefix_weights.size();
    if (matrix.size() % fixed_prefixes != 0) {
        throw std::logic_error("wiring source round has malformed tables");
    }
    const std::size_t suffix_count =
        matrix.size() / fixed_prefixes;
    WiringSumcheckRound result;
    for (std::size_t suffix = 0; suffix < suffix_count; ++suffix) {
        const SourcePair matrix_pair = source_pair<Fq2>(
            matrix, prefix_weights, suffix_count, suffix);
        const SourcePair assignment_pair = source_pair<Fq>(
            assignment, prefix_weights, suffix_count, suffix);
        result.at_one +=
            matrix_pair.at_one * assignment_pair.at_one;
        result.at_two +=
            (matrix_pair.at_one + matrix_pair.at_one -
             matrix_pair.at_zero) *
            (assignment_pair.at_one + assignment_pair.at_one -
             assignment_pair.at_zero);
    }
    return result;
}

ConstraintSumcheckRound evaluate_constraint_round(
    const ConstraintState &state, const Fq2 &tau) {
    const std::size_t size = state.az.size();
    if (size < 2 || (size & 1U) != 0 || state.bz.size() != size ||
        state.cz.size() != size || state.suffix_equality.size() != size / 2) {
        throw std::logic_error("malformed constraint sumcheck state");
    }

    ConstraintSumcheckRound result;
    const bool transmit_at_zero = tau == Fq2::one();
    const std::size_t half = size / 2;
    // S(X)=sum_u eq(tau_suffix,u)(A(X,u)B(X,u)-C(X,u)).
    for (std::size_t suffix = 0; suffix < half; ++suffix) {
        const Fq2 &weight = state.suffix_equality[suffix];
        const Fq2 &a0 = state.az[suffix];
        const Fq2 &a1 = state.az[half + suffix];
        const Fq2 &b0 = state.bz[suffix];
        const Fq2 &b1 = state.bz[half + suffix];
        const Fq2 &c0 = state.cz[suffix];
        const Fq2 &c1 = state.cz[half + suffix];
        result.endpoint +=
            weight * (transmit_at_zero ? a0 * b0 - c0
                                       : a1 * b1 - c1);
        // A(2)=2*A(1)-A(0), and likewise for B and C.
        const Fq2 a2 = a1 + a1 - a0;
        const Fq2 b2 = b1 + b1 - b0;
        const Fq2 c2 = c1 + c1 - c0;
        result.at_two += weight * (a2 * b2 - c2);
    }
    return result;
}

WiringSumcheckRound evaluate_wiring_round(const WiringState &state) {
    const std::size_t size = state.matrix.size();
    if (size < 2 || (size & 1U) != 0 ||
        state.assignment.size() != size) {
        throw std::logic_error("malformed wiring sumcheck state");
    }

    WiringSumcheckRound result;
    const std::size_t half = size / 2;
    // R(X)=sum_u M(X,u)z(X,u), evaluated only at X=1,2.
    for (std::size_t suffix = 0; suffix < half; ++suffix) {
        const Fq2 &m0 = state.matrix[suffix];
        const Fq2 &m1 = state.matrix[half + suffix];
        const Fq2 &z0 = state.assignment[suffix];
        const Fq2 &z1 = state.assignment[half + suffix];
        result.at_one += m1 * z1;
        result.at_two += (m1 + m1 - m0) * (z1 + z1 - z0);
    }
    return result;
}

Fq2 evaluate_quadratic(const Fq2 &at_zero, const Fq2 &at_one,
                       const Fq2 &at_two, const Fq2 &point) {
    const Fq2 one = Fq2::one();
    const Fq2 two = one + one;
    const Fq2 inverse_two = Fq2::from_base(Fq(2).inverse());
    const Fq2 basis_zero = (point - one) * (point - two) * inverse_two;
    const Fq2 basis_one = Fq2::zero() - point * (point - two);
    const Fq2 basis_two = point * (point - one) * inverse_two;
    return at_zero * basis_zero + at_one * basis_one + at_two * basis_two;
}

Fq2 equality_factor(const Fq2 &left, const Fq2 &right) {
    return (Fq2::one() - left) * (Fq2::one() - right) + left * right;
}

void fold_msb_in_place(std::vector<Fq2> &table,
                       const Fq2 &challenge) {
    if (table.size() < 2 || (table.size() & 1U) != 0) {
        throw std::logic_error("sumcheck table cannot be folded");
    }
    const std::size_t half = table.size() / 2;
    for (std::size_t index = 0; index < half; ++index) {
        table[index] += challenge * (table[half + index] - table[index]);
    }
    table.resize(half);
}

void drop_first_equality_variable(std::vector<Fq2> &table) {
    if (table.size() < 2 || (table.size() & 1U) != 0) {
        throw std::logic_error("equality suffix cannot be reduced");
    }
    const std::size_t half = table.size() / 2;
    // eq(tau_i,0)+eq(tau_i,1)=1, leaving eq(tau[i+1..],suffix).
    for (std::size_t index = 0; index < half; ++index) {
        table[index] += table[half + index];
    }
    table.resize(half);
}

void advance_constraint_claim(Fq2 &stripped_claim,
                              Fq2 &equality_prefix, const Fq2 &tau,
                              const Fq2 &challenge,
                              const ConstraintSumcheckRound &round) {
    const bool singular = tau == Fq2::one();
    // (1-tau)S(0)+tau*S(1)=claim. If tau=1, S(1)=claim and the
    // transmitted endpoint is S(0); otherwise it is S(1).
    const Fq2 at_zero =
        singular
            ? round.endpoint
            : (stripped_claim - tau * round.endpoint) *
                  (Fq2::one() - tau).inverse();
    const Fq2 at_one = singular ? stripped_claim : round.endpoint;
    stripped_claim = evaluate_quadratic(
        at_zero, at_one, round.at_two, challenge);
    equality_prefix *= equality_factor(tau, challenge);
}

void advance_wiring_claim(Fq2 &claim, const Fq2 &challenge,
                          const WiringSumcheckRound &round) {
    const Fq2 at_zero = claim - round.at_one;
    claim = evaluate_quadratic(
        at_zero, round.at_one, round.at_two, challenge);
}

void bind_constraint_state(ConstraintState &state, const Fq2 &tau,
                           const Fq2 &challenge,
                           const ConstraintSumcheckRound &round) {
    advance_constraint_claim(state.stripped_claim, state.equality_prefix,
                             tau, challenge, round);
    fold_msb_in_place(state.az, challenge);
    fold_msb_in_place(state.bz, challenge);
    fold_msb_in_place(state.cz, challenge);
    if (state.suffix_equality.size() > 1) {
        drop_first_equality_variable(state.suffix_equality);
    }
}

void bind_wiring_state(WiringState &state, const Fq2 &challenge,
                       const WiringSumcheckRound &round) {
    advance_wiring_claim(state.claim, challenge, round);
    fold_msb_in_place(state.matrix, challenge);
    fold_msb_in_place(state.assignment, challenge);
}

void observe_round(std::string_view label, const Fq2 &first,
                   const Fq2 &second,
                   PublicCoin &public_coin) {
    std::array<std::uint8_t, 2 * kSerializedFq2Bytes> bytes{};
    const std::array<Fq2, 2> values{first, second};
    for (std::size_t index = 0; index < values.size(); ++index) {
        const SerializedFq2 encoded = serialize(values[index]);
        std::copy(encoded.begin(), encoded.end(),
                  bytes.begin() + static_cast<std::ptrdiff_t>(
                                      index * kSerializedFq2Bytes));
    }
    public_coin.observe(label, bytes);
}

void observe_constraint_round(const ConstraintSumcheckRound &round,
                              PublicCoin &public_coin) {
    observe_round(kConstraintRoundLabel, round.endpoint, round.at_two,
                  public_coin);
}

void observe_wiring_round(const WiringSumcheckRound &round,
                          PublicCoin &public_coin) {
    observe_round(kWiringRoundLabel, round.at_one, round.at_two,
                  public_coin);
}

std::uint64_t checked_u64(std::size_t value, const char *label) {
    if constexpr (sizeof(std::size_t) > sizeof(std::uint64_t)) {
        if (value > std::numeric_limits<std::uint64_t>::max()) {
            throw std::overflow_error(std::string(label) + " exceeds u64");
        }
    }
    return static_cast<std::uint64_t>(value);
}

std::size_t checked_size(std::uint64_t value, const char *label) {
    if (value > std::numeric_limits<std::size_t>::max()) {
        throw std::overflow_error(std::string(label) + " exceeds size_t");
    }
    return static_cast<std::size_t>(value);
}

std::uint64_t checked_add(std::uint64_t left, std::uint64_t right,
                          const char *label) {
    if (right > std::numeric_limits<std::uint64_t>::max() - left) {
        throw std::overflow_error(std::string(label) + " overflows");
    }
    return left + right;
}

std::uint64_t checked_multiply(std::uint64_t left, std::uint64_t right,
                               const char *label) {
    if (left != 0 &&
        right > std::numeric_limits<std::uint64_t>::max() / left) {
        throw std::overflow_error(std::string(label) + " overflows");
    }
    return left * right;
}

std::size_t floor_power_of_two(std::size_t value) {
    if (value == 0) {
        throw std::invalid_argument("sumcheck block size is zero");
    }
    return std::size_t{1} << (std::bit_width(value) - 1U);
}

std::filesystem::path normalized_path(const std::filesystem::path &path) {
    if (path.empty()) {
        throw std::invalid_argument("constraint sumcheck path is empty");
    }
    return std::filesystem::canonical(path);
}

bool path_prefix(const std::filesystem::path &prefix,
                 const std::filesystem::path &path) {
    auto prefix_part = prefix.begin();
    auto path_part = path.begin();
    while (prefix_part != prefix.end() && path_part != path.end() &&
           *prefix_part == *path_part) {
        ++prefix_part;
        ++path_part;
    }
    return prefix_part == prefix.end();
}

void validate_empty_real_directory(const std::filesystem::path &directory) {
    const std::filesystem::file_status status =
        std::filesystem::symlink_status(directory);
    if (!std::filesystem::is_directory(status) ||
        std::filesystem::is_symlink(status) ||
        !std::filesystem::is_empty(directory)) {
        throw std::invalid_argument(
            "constraint sumcheck scratch must be an empty real directory");
    }
}

bool zero_digest(const Digest &digest) {
    return std::all_of(digest.begin(), digest.end(),
                       [](std::uint8_t value) { return value == 0; });
}

void append_u64(std::vector<std::uint8_t> &output, std::uint64_t value) {
    for (std::size_t byte = 0; byte < sizeof(value); ++byte) {
        output.push_back(
            static_cast<std::uint8_t>(value >> (8U * byte)));
    }
}

void append_string(std::vector<std::uint8_t> &output,
                   std::string_view value) {
    append_u64(output, checked_u64(value.size(), "identity string"));
    output.insert(output.end(), value.begin(), value.end());
}

void append_digest(std::vector<std::uint8_t> &output,
                   const Digest &digest) {
    output.insert(output.end(), digest.begin(), digest.end());
}

void append_fq2(std::vector<std::uint8_t> &output, const Fq2 &value) {
    const SerializedFq2 encoded = serialize(value);
    output.insert(output.end(), encoded.begin(), encoded.end());
}

Digest artifact_selection_identity(
    const storage::NativeFieldArtifact &source,
    const ConstraintSumcheckArtifactArrays &names,
    std::size_t logical_domain_size, std::span<const Fq2> tau) {
    std::vector<std::uint8_t> encoding(kArtifactSelectionDomain.begin(),
                                       kArtifactSelectionDomain.end());
    append_digest(encoding, source.identity());
    const std::array<std::string_view, 3> selected{
        names.az, names.bz, names.cz};
    for (const std::string_view name : selected) {
        const storage::NativeFieldArrayDescriptor &array =
            source.array(name);
        append_string(encoding, name);
        append_u64(encoding, static_cast<std::uint64_t>(array.kind));
        append_u64(encoding, array.element_count);
        append_digest(encoding, array.file_digest);
    }
    append_u64(encoding, checked_u64(logical_domain_size,
                                     "logical constraint domain"));
    append_u64(encoding, checked_u64(tau.size(), "tau size"));
    for (const Fq2 &coordinate : tau) {
        append_fq2(encoding, coordinate);
    }
    return sha256(encoding);
}

Digest artifact_checkpoint_identity(
    const Digest &selection, std::size_t element_count,
    std::span<const Fq2> fixed_prefix) {
    std::vector<std::uint8_t> encoding(kArtifactCheckpointDomain.begin(),
                                       kArtifactCheckpointDomain.end());
    append_digest(encoding, selection);
    append_u64(encoding,
               checked_u64(element_count, "checkpoint element count"));
    append_u64(encoding,
               checked_u64(fixed_prefix.size(), "fixed prefix size"));
    for (const Fq2 &coordinate : fixed_prefix) {
        append_fq2(encoding, coordinate);
    }
    return sha256(encoding);
}

std::uint64_t directory_regular_bytes(
    const std::filesystem::path &directory) {
    std::uint64_t bytes = 0;
    for (const auto &entry :
         std::filesystem::recursive_directory_iterator(directory)) {
        if (entry.is_regular_file()) {
            bytes = checked_add(bytes, entry.file_size(),
                                "constraint scratch directory bytes");
        }
    }
    return bytes;
}

class ScratchRootCleanup {
  public:
    explicit ScratchRootCleanup(std::filesystem::path root)
        : root_(std::move(root)) {}

    ScratchRootCleanup(const ScratchRootCleanup &) = delete;
    ScratchRootCleanup &operator=(const ScratchRootCleanup &) = delete;

    ~ScratchRootCleanup() {
        if (!armed_) {
            return;
        }
        std::error_code error;
        std::filesystem::directory_iterator entry(root_, error);
        const std::filesystem::directory_iterator end;
        while (!error && entry != end) {
            const std::filesystem::path child = entry->path();
            entry.increment(error);
            std::error_code ignored;
            std::filesystem::remove_all(child, ignored);
        }
    }

    void disarm() { armed_ = false; }

  private:
    std::filesystem::path root_;
    bool armed_ = true;
};

struct ConstraintScratchArtifact {
    std::filesystem::path directory;
    Digest identity{};
    std::shared_ptr<const storage::NativeFieldArtifact> artifact;
    std::uint64_t physical_bytes = 0;
    std::size_t element_count = 0;
};

class ConstraintScratchTracker {
  public:
    ConstraintScratchTracker(
        std::filesystem::path root, std::uint64_t max_bytes,
        std::uint64_t min_free_bytes,
        ConstraintSumcheckArtifactReport &report)
        : root_(std::move(root)), max_bytes_(max_bytes),
          min_free_bytes_(min_free_bytes), report_(report) {}

    std::filesystem::path create_directory(std::string name) const {
        if (name.empty() || name.find('/') != std::string::npos ||
            name.find('\\') != std::string::npos) {
            throw std::invalid_argument(
                "invalid constraint sumcheck scratch name");
        }
        const std::filesystem::path directory = root_ / std::move(name);
        if (!std::filesystem::create_directory(directory)) {
            throw std::runtime_error(
                "failed to create constraint sumcheck scratch directory");
        }
        return directory;
    }

    storage::NativeFieldArtifactOptions next_limits() const {
        if (current_bytes_ >= max_bytes_) {
            throw std::runtime_error(
                "constraint sumcheck scratch quota exhausted");
        }
        return {
            .max_total_bytes = max_bytes_ - current_bytes_,
            .min_free_bytes = min_free_bytes_,
        };
    }

    void published(std::uint64_t physical_bytes) {
        current_bytes_ = checked_add(current_bytes_, physical_bytes,
                                     "live constraint scratch bytes");
        if (current_bytes_ > max_bytes_) {
            throw std::logic_error(
                "constraint scratch writer exceeded its quota");
        }
        report_.scratch_written_physical_bytes = checked_add(
            report_.scratch_written_physical_bytes, physical_bytes,
            "written constraint scratch bytes");
        report_.scratch_peak_physical_bytes = std::max(
            report_.scratch_peak_physical_bytes, current_bytes_);
    }

    void erase(const ConstraintScratchArtifact &artifact) {
        const std::filesystem::path selected =
            normalized_path(artifact.directory);
        if (selected.parent_path() != root_ ||
            std::filesystem::is_symlink(
                std::filesystem::symlink_status(selected)) ||
            directory_regular_bytes(selected) != artifact.physical_bytes ||
            artifact.physical_bytes > current_bytes_) {
            throw std::runtime_error(
                "refusing to remove changed constraint scratch data");
        }
        std::filesystem::remove_all(selected);
        current_bytes_ -= artifact.physical_bytes;
        report_.scratch_deleted_physical_bytes = checked_add(
            report_.scratch_deleted_physical_bytes,
            artifact.physical_bytes,
            "deleted constraint scratch bytes");
    }

    std::uint64_t current_bytes() const { return current_bytes_; }

  private:
    std::filesystem::path root_;
    std::uint64_t max_bytes_ = 0;
    std::uint64_t min_free_bytes_ = 0;
    ConstraintSumcheckArtifactReport &report_;
    std::uint64_t current_bytes_ = 0;
};

void retire_constraint_scratch(
    ConstraintScratchArtifact &artifact,
    ConstraintScratchTracker &tracker) {
    artifact.artifact.reset();
    tracker.erase(artifact);
    artifact = {};
}

void account_field_payload(
    ConstraintSumcheckArtifactReport &report,
    const ConstraintSumcheckArtifactOptions &options,
    std::uint64_t bytes) {
    report.peak_working_field_bytes =
        std::max(report.peak_working_field_bytes, bytes);
    if (bytes > options.max_working_field_bytes) {
        throw std::runtime_error(
            "constraint sumcheck field-memory limit exceeded");
    }
}

std::uint64_t field_payload_bytes(std::size_t count,
                                  std::size_t width,
                                  const char *label) {
    return checked_multiply(checked_u64(count, label),
                            checked_u64(width, "field payload width"),
                            label);
}

std::uint64_t expected_field_peak(std::size_t domain_size,
                                  std::size_t source_rounds,
                                  std::size_t block_elements) {
    const std::size_t prefix_count =
        std::size_t{1} << source_rounds;
    const std::size_t checkpoint_size = domain_size / prefix_count;
    const std::uint64_t prefix_bytes = field_payload_bytes(
        prefix_count, sizeof(Fq2), "prefix field payload");
    const auto with_prefix = [&](std::size_t count,
                                 std::size_t per_element,
                                 const char *label) {
        return checked_add(
            prefix_bytes,
            field_payload_bytes(std::min(block_elements, count),
                                per_element, label),
            label);
    };

    std::uint64_t peak = with_prefix(
        checkpoint_size, sizeof(Fq2) + sizeof(Fq),
        "checkpoint working field payload");
    for (std::size_t round = 0; round < source_rounds; ++round) {
        const std::size_t suffix_count = domain_size >> (round + 1U);
        peak = std::max(
            peak,
            with_prefix(suffix_count,
                        7U * sizeof(Fq2) + sizeof(Fq),
                        "source-round working field payload"));
    }
    for (std::size_t size = checkpoint_size; size > 1; size >>= 1U) {
        const std::size_t half = size / 2U;
        peak = std::max(
            peak,
            field_payload_bytes(std::min(block_elements, half),
                                7U * sizeof(Fq2),
                                "fold-message working field payload"));
        peak = std::max(
            peak,
            field_payload_bytes(std::min(block_elements, half),
                                2U * sizeof(Fq2),
                                "fold-write working field payload"));
    }
    return std::max<std::uint64_t>(peak, sizeof(Fq2));
}

std::uint64_t constraint_scratch_physical_bytes(
    std::size_t element_count) {
    const std::array<storage::NativeFieldArrayLayout, 3> layout{{
        {std::string(kConstraintArtifactArrays[0]),
         storage::NativeFieldElementKind::Fq2,
         checked_u64(element_count, "scratch Az size")},
        {std::string(kConstraintArtifactArrays[1]),
         storage::NativeFieldElementKind::Fq2,
         checked_u64(element_count, "scratch Bz size")},
        {std::string(kConstraintArtifactArrays[2]),
         storage::NativeFieldElementKind::Fq2,
         checked_u64(element_count, "scratch Cz size")},
    }};
    return storage::native_field_artifact_physical_bytes(layout);
}

struct ScratchPreflight {
    std::uint64_t peak_bytes = 0;
    std::uint64_t cumulative_bytes = 0;
};

ScratchPreflight scratch_preflight(std::size_t checkpoint_size) {
    ScratchPreflight result;
    std::uint64_t previous = 0;
    for (std::size_t size = checkpoint_size;; size >>= 1U) {
        const std::uint64_t current =
            constraint_scratch_physical_bytes(size);
        result.cumulative_bytes = checked_add(
            result.cumulative_bytes, current,
            "cumulative constraint scratch bytes");
        result.peak_bytes = std::max(
            result.peak_bytes,
            checked_add(previous, current,
                        "peak constraint scratch bytes"));
        previous = current;
        if (size == 1) {
            break;
        }
    }
    return result;
}

Fq2 equality_weight_at(std::span<const Fq2> point,
                       std::size_t index) {
    if (point.size() >= std::numeric_limits<std::size_t>::digits ||
        index >= (std::size_t{1} << point.size())) {
        throw std::logic_error("equality weight index is out of range");
    }
    Fq2 result = Fq2::one();
    for (std::size_t variable = 0; variable < point.size(); ++variable) {
        const std::size_t bit_index =
            point.size() - 1U - variable;
        result *= ((index >> bit_index) & 1U) != 0
                      ? point[variable]
                      : Fq2::one() - point[variable];
    }
    return result;
}

struct EqualityBlockPlan {
    std::vector<Fq2> low_weights;
    std::span<const Fq2> high_point;
    std::size_t block_count = 0;

    Fq2 high_weight(std::size_t block) const {
        return equality_weight_at(high_point, block);
    }
};

EqualityBlockPlan equality_block_plan(std::span<const Fq2> point,
                                      std::size_t evaluation_count,
                                      std::size_t block_elements) {
    if (!std::has_single_bit(evaluation_count) ||
        !std::has_single_bit(block_elements) ||
        block_elements > evaluation_count ||
        point.size() != log2_exact(evaluation_count)) {
        throw std::logic_error("invalid equality block geometry");
    }
    const std::size_t low_variables = log2_exact(block_elements);
    const std::size_t high_variables = point.size() - low_variables;
    return {
        .low_weights = equality_table(point.subspan(high_variables)),
        .high_point = point.first(high_variables),
        .block_count = evaluation_count / block_elements,
    };
}

void add_indexed_read(ConstraintSumcheckArtifactReport &report,
                      std::uint64_t bytes,
                      std::uint64_t operations) {
    report.indexed_read_payload_bytes = checked_add(
        report.indexed_read_payload_bytes, bytes,
        "indexed constraint read bytes");
    report.indexed_read_operations = checked_add(
        report.indexed_read_operations, operations,
        "indexed constraint read operations");
}

void read_exact(storage::NativeFieldArrayReader &reader,
                std::span<Fq> output) {
    if (reader.read(output) != output.size()) {
        throw std::runtime_error(
            "truncated constraint sumcheck Fq source");
    }
}

void read_exact(storage::NativeFieldArrayReader &reader,
                std::span<Fq2> output) {
    if (reader.read(output) != output.size()) {
        throw std::runtime_error(
            "truncated constraint sumcheck Fq2 checkpoint");
    }
}

struct ActiveFqSegmentReader {
    std::unique_ptr<storage::NativeFieldArrayReader> reader;
    std::size_t remaining = 0;
};

ActiveFqSegmentReader open_active_fq_segment(
    const storage::NativeFieldArtifact &source, std::string_view name,
    std::size_t begin, std::size_t extent, std::size_t active_size) {
    if (begin >= active_size) {
        return {};
    }
    const std::size_t available =
        std::min(extent, active_size - begin);
    auto reader = std::make_unique<storage::NativeFieldArrayReader>(
        source.open_array(name));
    reader->seek(checked_u64(begin, "active source segment begin"));
    return {std::move(reader), available};
}

std::size_t read_active_fq_segment(ActiveFqSegmentReader &segment,
                                   std::span<Fq> output) {
    const std::size_t count = std::min(segment.remaining, output.size());
    if (count == 0) {
        return 0;
    }
    if (!segment.reader) {
        throw std::logic_error("active source segment has no reader");
    }
    read_exact(*segment.reader, output.first(count));
    segment.remaining -= count;
    return count;
}

void add_sequential_read(ConstraintSumcheckArtifactReport &report,
                         std::uint64_t bytes,
                         std::uint64_t operations) {
    report.sequential_read_payload_bytes = checked_add(
        report.sequential_read_payload_bytes, bytes,
        "sequential constraint read bytes");
    report.sequential_read_operations = checked_add(
        report.sequential_read_operations, operations,
        "sequential constraint read operations");
}

void add_sequential_write(ConstraintSumcheckArtifactReport &report,
                          std::uint64_t bytes,
                          std::uint64_t operations) {
    report.sequential_write_payload_bytes = checked_add(
        report.sequential_write_payload_bytes, bytes,
        "sequential constraint write bytes");
    report.sequential_write_operations = checked_add(
        report.sequential_write_operations, operations,
        "sequential constraint write operations");
}

ConstraintScratchArtifact publish_constraint_scratch(
    const std::filesystem::path &directory, const Digest &identity,
    std::size_t element_count,
    storage::NativeFieldArtifactWriter &writer,
    ConstraintScratchTracker &tracker,
    ConstraintSumcheckArtifactReport &report) {
    const storage::NativeFieldArtifactWriteResult written = writer.finish();
    tracker.published(written.physical_bytes);
    report.scratch_artifact_validation_bytes = checked_add(
        report.scratch_artifact_validation_bytes,
        written.physical_bytes,
        "constraint scratch validation bytes");
    auto artifact = std::make_shared<storage::NativeFieldArtifact>(
        storage::NativeFieldArtifact::open(directory, identity));
    if (artifact->arrays().size() != kConstraintArtifactArrays.size()) {
        throw std::logic_error("malformed constraint scratch artifact");
    }
    for (const std::string_view name : kConstraintArtifactArrays) {
        const storage::NativeFieldArrayDescriptor &array =
            artifact->array(name);
        if (array.kind != storage::NativeFieldElementKind::Fq2 ||
            array.element_count != element_count) {
            throw std::logic_error(
                "malformed constraint scratch checkpoint");
        }
    }
    return {directory, identity, std::move(artifact),
            written.physical_bytes, element_count};
}

void expand_prefix_weights(std::vector<Fq2> &weights,
                           std::size_t &active,
                           const Fq2 &challenge) {
    if (active == 0 || active > weights.size() / 2U) {
        throw std::logic_error("constraint prefix table cannot expand");
    }
    for (std::size_t index = active; index-- > 0;) {
        const Fq2 previous = weights[index];
        const Fq2 high = previous * challenge;
        weights[2U * index] = previous - high;
        weights[2U * index + 1U] = high;
    }
    active *= 2U;
}

ConstraintSumcheckRound evaluate_artifact_source_round(
    const storage::NativeFieldArtifact &source,
    const ConstraintSumcheckArtifactArrays &names,
    std::size_t domain_size, std::size_t active_size,
    std::size_t variable,
    std::span<const Fq2> prefix_weights,
    std::size_t prefix_capacity, std::span<const Fq2> tau,
    std::size_t block_elements,
    const ConstraintSumcheckArtifactOptions &options,
    ConstraintSumcheckArtifactReport &report) {
    const std::size_t suffix_count = domain_size >> (variable + 1U);
    const std::size_t block = std::min(block_elements, suffix_count);
    const EqualityBlockPlan equality = equality_block_plan(
        tau.subspan(variable + 1U), suffix_count, block);
    account_field_payload(
        report, options,
        checked_add(
            field_payload_bytes(prefix_capacity, sizeof(Fq2),
                                "prefix field payload"),
            field_payload_bytes(block,
                                7U * sizeof(Fq2) + sizeof(Fq),
                                "source-round field payload"),
            "source-round working field payload"));

    std::array<std::vector<Fq2>, 6> values;
    for (auto &buffer : values) {
        buffer.resize(block);
    }
    std::vector<Fq> input(block);
    const std::size_t prefix_stride = 2U * suffix_count;
    std::array<std::vector<ActiveFqSegmentReader>, 6> readers;
    const std::array<std::string_view, 3> source_names{
        names.az, names.bz, names.cz};
    for (std::size_t column = 0; column < source_names.size(); ++column) {
        readers[2U * column].reserve(prefix_weights.size());
        readers[2U * column + 1U].reserve(prefix_weights.size());
        for (std::size_t prefix = 0; prefix < prefix_weights.size();
             ++prefix) {
            const std::size_t low_begin = prefix * prefix_stride;
            readers[2U * column].push_back(open_active_fq_segment(
                source, source_names[column], low_begin, suffix_count,
                active_size));
            readers[2U * column + 1U].push_back(open_active_fq_segment(
                source, source_names[column], low_begin + suffix_count,
                suffix_count, active_size));
        }
    }

    ConstraintSumcheckRound result;
    const bool transmit_at_zero = tau[variable] == Fq2::one();
    std::uint64_t read_elements = 0;
    std::uint64_t read_operations = 0;
    const auto accumulate = [&](ActiveFqSegmentReader &reader,
                                std::vector<Fq2> &output,
                                std::size_t prefix) {
        const std::size_t count = read_active_fq_segment(reader, input);
        if (count != 0) {
            read_elements = checked_add(
                read_elements, checked_u64(count, "active source read"),
                "active source read elements");
            read_operations = checked_add(
                read_operations, 1U, "active source read operations");
        }
        for (std::size_t index = 0; index < count; ++index) {
            output[index] += prefix_weights[prefix] *
                             Fq2::from_base(input[index]);
        }
    };

    for (std::size_t high = 0; high < equality.block_count; ++high) {
        for (auto &buffer : values) {
            std::fill(buffer.begin(), buffer.end(), Fq2::zero());
        }
        for (std::size_t prefix = 0; prefix < prefix_weights.size();
             ++prefix) {
            for (std::size_t segment = 0; segment < readers.size();
                 ++segment) {
                accumulate(readers[segment][prefix], values[segment],
                           prefix);
            }
        }
        const Fq2 high_weight = equality.high_weight(high);
        for (std::size_t index = 0; index < block; ++index) {
            const Fq2 weight =
                high_weight * equality.low_weights[index];
            const Fq2 &a0 = values[0][index];
            const Fq2 &a1 = values[1][index];
            const Fq2 &b0 = values[2][index];
            const Fq2 &b1 = values[3][index];
            const Fq2 &c0 = values[4][index];
            const Fq2 &c1 = values[5][index];
            result.endpoint +=
                weight * (transmit_at_zero ? a0 * b0 - c0
                                           : a1 * b1 - c1);
            const Fq2 a2 = a1 + a1 - a0;
            const Fq2 b2 = b1 + b1 - b0;
            const Fq2 c2 = c1 + c1 - c0;
            result.at_two += weight * (a2 * b2 - c2);
        }
    }

    const std::uint64_t expected_elements = checked_multiply(
        3U, checked_u64(active_size, "active source size"),
        "active source elements");
    if (read_elements != expected_elements) {
        throw std::logic_error(
            "constraint source round did not consume its active prefix");
    }
    add_indexed_read(
        report,
        checked_multiply(
            read_elements,
            kSerializedFqBytes, "source-round read bytes"),
        read_operations);
    return result;
}

ConstraintScratchArtifact materialize_constraint_checkpoint(
    const storage::NativeFieldArtifact &source,
    const ConstraintSumcheckArtifactArrays &names,
    std::size_t domain_size, std::size_t active_size,
    std::span<const Fq2> prefix_weights,
    std::size_t prefix_capacity, std::size_t block_elements,
    const Digest &identity, std::string directory_name,
    const ConstraintSumcheckArtifactOptions &options,
    ConstraintScratchTracker &tracker,
    ConstraintSumcheckArtifactReport &report) {
    const std::size_t checkpoint_size =
        domain_size / prefix_weights.size();
    const std::size_t block =
        std::min(block_elements, checkpoint_size);
    account_field_payload(
        report, options,
        checked_add(
            field_payload_bytes(prefix_capacity, sizeof(Fq2),
                                "prefix field payload"),
            field_payload_bytes(block, sizeof(Fq2) + sizeof(Fq),
                                "checkpoint field payload"),
            "checkpoint working field payload"));

    const std::filesystem::path directory =
        tracker.create_directory(std::move(directory_name));
    storage::NativeFieldArtifactWriter writer(
        directory, tracker.next_limits(), identity);
    std::vector<Fq> input(block);
    std::vector<Fq2> output(block);
    const std::array<std::string_view, 3> source_names{
        names.az, names.bz, names.cz};
    const std::size_t block_count = checkpoint_size / block;
    std::uint64_t read_elements = 0;
    std::uint64_t read_operations = 0;
    for (std::size_t column = 0; column < source_names.size(); ++column) {
        writer.begin_array(std::string(kConstraintArtifactArrays[column]),
                           storage::NativeFieldElementKind::Fq2,
                           checked_u64(checkpoint_size,
                                       "checkpoint array size"));
        std::vector<ActiveFqSegmentReader> readers;
        readers.reserve(prefix_weights.size());
        for (std::size_t prefix = 0; prefix < prefix_weights.size();
             ++prefix) {
            readers.push_back(open_active_fq_segment(
                source, source_names[column], prefix * checkpoint_size,
                checkpoint_size, active_size));
        }
        for (std::size_t block_index = 0; block_index < block_count;
             ++block_index) {
            std::fill(output.begin(), output.end(), Fq2::zero());
            for (std::size_t prefix = 0;
                 prefix < prefix_weights.size(); ++prefix) {
                const std::size_t count =
                    read_active_fq_segment(readers[prefix], input);
                if (count != 0) {
                    read_elements = checked_add(
                        read_elements,
                        checked_u64(count, "active checkpoint read"),
                        "active checkpoint read elements");
                    read_operations = checked_add(
                        read_operations, 1U,
                        "active checkpoint read operations");
                }
                for (std::size_t index = 0; index < count; ++index) {
                    output[index] += prefix_weights[prefix] *
                                     Fq2::from_base(input[index]);
                }
            }
            writer.append(output);
        }
        writer.finish_array();
    }
    const std::uint64_t expected_elements = checked_multiply(
        3U, checked_u64(active_size, "active checkpoint size"),
        "active checkpoint elements");
    if (read_elements != expected_elements) {
        throw std::logic_error(
            "constraint checkpoint did not consume its active prefix");
    }
    add_indexed_read(
        report,
        checked_multiply(
            read_elements,
            kSerializedFqBytes, "checkpoint source read bytes"),
        read_operations);
    add_sequential_write(
        report,
        checked_multiply(
            checked_multiply(3U,
                             checked_u64(checkpoint_size,
                                         "checkpoint size"),
                             "checkpoint fields"),
            kSerializedFq2Bytes, "checkpoint write bytes"),
        checked_multiply(3U, checked_u64(block_count, "checkpoint blocks"),
                         "checkpoint write operations"));
    return publish_constraint_scratch(directory, identity, checkpoint_size,
                                      writer, tracker, report);
}

ConstraintSumcheckRound evaluate_artifact_fold_round(
    const ConstraintScratchArtifact &current, std::size_t variable,
    std::span<const Fq2> tau, std::size_t block_elements,
    const ConstraintSumcheckArtifactOptions &options,
    ConstraintSumcheckArtifactReport &report) {
    const std::size_t size = current.element_count;
    const std::size_t half = size / 2U;
    const std::size_t block = std::min(block_elements, half);
    const EqualityBlockPlan equality = equality_block_plan(
        tau.subspan(variable + 1U), half, block);
    account_field_payload(
        report, options,
        field_payload_bytes(block, 7U * sizeof(Fq2),
                            "fold-message field payload"));

    std::array<std::vector<Fq2>, 6> values;
    for (auto &buffer : values) {
        buffer.resize(block);
    }
    std::array<storage::NativeFieldArrayReader, 6> readers{
        current.artifact->open_array(kConstraintArtifactArrays[0]),
        current.artifact->open_array(kConstraintArtifactArrays[0]),
        current.artifact->open_array(kConstraintArtifactArrays[1]),
        current.artifact->open_array(kConstraintArtifactArrays[1]),
        current.artifact->open_array(kConstraintArtifactArrays[2]),
        current.artifact->open_array(kConstraintArtifactArrays[2]),
    };
    for (std::size_t high = 1; high < readers.size(); high += 2U) {
        readers[high].seek(checked_u64(half, "fold high segment"));
    }

    ConstraintSumcheckRound result;
    const bool transmit_at_zero = tau[variable] == Fq2::one();
    for (std::size_t high = 0; high < equality.block_count; ++high) {
        for (std::size_t segment = 0; segment < readers.size(); ++segment) {
            read_exact(readers[segment], values[segment]);
        }
        const Fq2 high_weight = equality.high_weight(high);
        for (std::size_t index = 0; index < block; ++index) {
            const Fq2 weight =
                high_weight * equality.low_weights[index];
            const Fq2 &a0 = values[0][index];
            const Fq2 &a1 = values[1][index];
            const Fq2 &b0 = values[2][index];
            const Fq2 &b1 = values[3][index];
            const Fq2 &c0 = values[4][index];
            const Fq2 &c1 = values[5][index];
            result.endpoint +=
                weight * (transmit_at_zero ? a0 * b0 - c0
                                           : a1 * b1 - c1);
            const Fq2 a2 = a1 + a1 - a0;
            const Fq2 b2 = b1 + b1 - b0;
            const Fq2 c2 = c1 + c1 - c0;
            result.at_two += weight * (a2 * b2 - c2);
        }
    }
    add_indexed_read(
        report,
        checked_multiply(
            checked_multiply(3U, checked_u64(size, "fold size"),
                             "fold-message fields"),
            kSerializedFq2Bytes, "fold-message read bytes"),
        checked_multiply(6U,
                         checked_u64(equality.block_count,
                                     "fold-message blocks"),
                         "fold-message read operations"));
    return result;
}

ConstraintScratchArtifact fold_constraint_checkpoint(
    const ConstraintScratchArtifact &current, const Fq2 &challenge,
    std::size_t block_elements, const Digest &identity,
    std::string directory_name,
    const ConstraintSumcheckArtifactOptions &options,
    ConstraintScratchTracker &tracker,
    ConstraintSumcheckArtifactReport &report) {
    const std::size_t half = current.element_count / 2U;
    const std::size_t block = std::min(block_elements, half);
    const std::size_t block_count = half / block;
    account_field_payload(
        report, options,
        field_payload_bytes(block, 2U * sizeof(Fq2),
                            "fold-write field payload"));
    const std::filesystem::path directory =
        tracker.create_directory(std::move(directory_name));
    storage::NativeFieldArtifactWriter writer(
        directory, tracker.next_limits(), identity);
    std::vector<Fq2> low(block);
    std::vector<Fq2> high(block);
    for (const std::string_view name : kConstraintArtifactArrays) {
        writer.begin_array(std::string(name),
                           storage::NativeFieldElementKind::Fq2,
                           checked_u64(half, "folded checkpoint size"));
        storage::NativeFieldArrayReader low_reader =
            current.artifact->open_array(name);
        storage::NativeFieldArrayReader high_reader =
            current.artifact->open_array(name);
        high_reader.seek(checked_u64(half, "fold source high segment"));
        for (std::size_t block_index = 0; block_index < block_count;
             ++block_index) {
            read_exact(low_reader, low);
            read_exact(high_reader, high);
            for (std::size_t index = 0; index < block; ++index) {
                low[index] += challenge * (high[index] - low[index]);
            }
            writer.append(low);
        }
        writer.finish_array();
    }
    add_indexed_read(
        report,
        checked_multiply(
            checked_multiply(3U,
                             checked_u64(current.element_count,
                                         "fold source size"),
                             "fold source fields"),
            kSerializedFq2Bytes, "fold source read bytes"),
        checked_multiply(6U, checked_u64(block_count, "fold blocks"),
                         "fold source read operations"));
    add_sequential_write(
        report,
        checked_multiply(
            checked_multiply(3U, checked_u64(half, "fold output size"),
                             "fold output fields"),
            kSerializedFq2Bytes, "fold output write bytes"),
        checked_multiply(3U, checked_u64(block_count, "fold blocks"),
                         "fold output write operations"));
    return publish_constraint_scratch(directory, identity, half, writer,
                                      tracker, report);
}

std::array<Fq2, 3> read_constraint_terminal(
    const ConstraintScratchArtifact &current,
    ConstraintSumcheckArtifactReport &report) {
    if (current.element_count != 1) {
        throw std::logic_error("constraint terminal is not a singleton");
    }
    std::array<Fq2, 3> result{};
    for (std::size_t column = 0; column < result.size(); ++column) {
        storage::NativeFieldArrayReader reader =
            current.artifact->open_array(kConstraintArtifactArrays[column]);
        read_exact(reader, std::span<Fq2>(&result[column], 1));
    }
    add_sequential_read(
        report, 3U * kSerializedFq2Bytes, 3U);
    return result;
}

} // namespace

ConstraintSumcheckArtifactPlan plan_constraint_sumcheck_artifact(
    std::size_t logical_domain_size, std::size_t source_rounds,
    std::uint64_t max_working_field_bytes,
    std::size_t requested_block_elements) {
    if (max_working_field_bytes == 0 || requested_block_elements == 0 ||
        source_rounds > kDefaultArtifactConstraintSourceRounds) {
        throw std::invalid_argument(
            "ConstraintCheck planning needs explicit valid resources");
    }
    const std::size_t variables = log2_exact(logical_domain_size);
    const std::size_t effective_rounds =
        std::min(source_rounds, variables);
    const std::size_t checkpoint_size =
        logical_domain_size /
        (std::size_t{1} << effective_rounds);
    const ScratchPreflight scratch = scratch_preflight(checkpoint_size);
    const std::uint64_t minimum_working_field_bytes =
        expected_field_peak(logical_domain_size, effective_rounds, 1);
    if (max_working_field_bytes < minimum_working_field_bytes) {
        throw std::invalid_argument(
            "constraint field-memory limit cannot hold one block");
    }
    std::size_t block_elements = floor_power_of_two(
        std::min(requested_block_elements, logical_domain_size));
    while (expected_field_peak(logical_domain_size, effective_rounds,
                               block_elements) >
           max_working_field_bytes) {
        block_elements >>= 1U;
    }
    return {
        .scratch_peak_physical_bytes = scratch.peak_bytes,
        .scratch_written_physical_bytes = scratch.cumulative_bytes,
        .minimum_working_field_bytes = minimum_working_field_bytes,
        .effective_block_elements = block_elements,
        .peak_working_field_bytes = expected_field_peak(
            logical_domain_size, effective_rounds, block_elements),
    };
}

std::uint64_t constraint_sumcheck_artifact_scratch_peak_physical_bytes(
    std::size_t logical_domain_size, std::size_t source_rounds) {
    const std::size_t variables = log2_exact(logical_domain_size);
    const std::size_t effective_rounds =
        std::min(source_rounds, variables);
    return scratch_preflight(
               logical_domain_size /
               (std::size_t{1} << effective_rounds))
        .peak_bytes;
}

ConstraintSumcheckArtifactOutput prove_constraint_sumcheck_artifact(
    const storage::NativeFieldArtifact &source,
    const ConstraintSumcheckArtifactArrays &arrays,
    std::span<const Fq2> tau, PublicCoin &public_coin,
    ConstraintSumcheckArtifactOptions options) {
    if (zero_digest(options.expected_source_identity) ||
        options.scratch_directory.empty() ||
        options.max_live_storage_bytes == 0 ||
        options.max_total_scratch_bytes == 0 ||
        options.min_free_bytes == 0 ||
        options.max_working_field_bytes == 0 ||
        options.block_elements == 0 ||
        options.source_rounds >
            kDefaultArtifactConstraintSourceRounds) {
        throw std::invalid_argument(
            "constraint artifact sumcheck needs explicit valid resources");
    }

    const std::filesystem::path source_directory =
        normalized_path(source.directory());
    options.scratch_directory = normalized_path(options.scratch_directory);
    validate_empty_real_directory(options.scratch_directory);
    if (path_prefix(source_directory, options.scratch_directory) ||
        path_prefix(options.scratch_directory, source_directory)) {
        throw std::invalid_argument(
            "constraint source and scratch directories must be disjoint");
    }

    auto validated_source =
        std::make_shared<storage::NativeFieldArtifact>(
            storage::NativeFieldArtifact::open(
                source_directory, options.expected_source_identity));
    ConstraintSumcheckArtifactOutput output;
    output.report.source_artifact_physical_bytes =
        validated_source->physical_bytes();
    output.report.source_validation_bytes =
        validated_source->physical_bytes();

    const std::array<std::string_view, 3> selected_names{
        arrays.az, arrays.bz, arrays.cz};
    std::set<std::string_view> unique_names;
    std::size_t active_size = 0;
    for (const std::string_view name : selected_names) {
        if (name.empty() || !unique_names.insert(name).second) {
            throw std::invalid_argument(
                "constraint source array names must be nonempty and unique");
        }
        const storage::NativeFieldArrayDescriptor &array =
            validated_source->array(name);
        if (array.kind != storage::NativeFieldElementKind::Fq ||
            array.encoded_element_bytes != kSerializedFqBytes ||
            array.element_count == 0 ||
            array.element_count >
                std::numeric_limits<std::size_t>::max()) {
            throw std::invalid_argument(
                "constraint source is not a canonical Fq array");
        }
        const std::size_t count =
            checked_size(array.element_count, "constraint source size");
        if (active_size == 0) {
            active_size = count;
        } else if (count != active_size) {
            throw std::invalid_argument(
                "constraint source arrays have different lengths");
        }
    }
    const std::size_t domain_size =
        options.logical_domain_size == 0
            ? active_size
            : options.logical_domain_size;
    const std::size_t variables = log2_exact(domain_size);
    if (active_size > domain_size || tau.size() != variables) {
        throw std::invalid_argument(
            "constraint active prefix or tau disagrees with the logical "
            "domain");
    }
    output.report.selected_source_payload_bytes = checked_multiply(
        checked_multiply(3U, checked_u64(active_size, "active source size"),
                         "selected source fields"),
        kSerializedFqBytes, "selected source payload bytes");

    const std::size_t source_rounds =
        std::min(options.source_rounds, variables);
    const std::size_t prefix_count = std::size_t{1} << source_rounds;
    const std::size_t checkpoint_size = domain_size / prefix_count;
    const ConstraintSumcheckArtifactPlan resource_plan =
        plan_constraint_sumcheck_artifact(
            domain_size, source_rounds,
            options.max_working_field_bytes, options.block_elements);
    const ScratchPreflight scratch{
        .peak_bytes = resource_plan.scratch_peak_physical_bytes,
        .cumulative_bytes =
            resource_plan.scratch_written_physical_bytes,
    };
    if (options.max_total_scratch_bytes < scratch.peak_bytes) {
        throw std::invalid_argument(
            "constraint scratch quota is below its exact physical peak");
    }
    output.report.peak_live_storage_bytes = checked_add(
        output.report.source_artifact_physical_bytes,
        scratch.peak_bytes, "peak live ConstraintCheck storage");
    if (output.report.peak_live_storage_bytes >
        options.max_live_storage_bytes) {
        throw std::invalid_argument(
            "ConstraintCheck live-storage quota is below its exact peak");
    }
    const std::uint64_t required_free = checked_add(
        scratch.peak_bytes, options.min_free_bytes,
        "constraint scratch free-space preflight");
    if (std::filesystem::space(options.scratch_directory).available <
        required_free) {
        throw std::runtime_error(
            "constraint sumcheck scratch has insufficient free space");
    }

    const std::size_t block_elements =
        resource_plan.effective_block_elements;
    const std::uint64_t exact_field_peak =
        resource_plan.peak_working_field_bytes;
    output.report.effective_block_elements = block_elements;
    output.report.source_rescan_rounds = source_rounds;

    const Digest selection = artifact_selection_identity(
        *validated_source, arrays, domain_size, tau);
    ScratchRootCleanup cleanup(options.scratch_directory);
    ConstraintScratchTracker tracker(
        options.scratch_directory, options.max_total_scratch_bytes,
        options.min_free_bytes, output.report);

    output.sumcheck.proof.rounds.reserve(variables);
    output.sumcheck.point.reserve(variables);
    Fq2 stripped_claim = Fq2::zero();
    Fq2 equality_prefix = Fq2::one();
    std::vector<Fq2> prefix_weights(prefix_count, Fq2::zero());
    prefix_weights.front() = Fq2::one();
    std::size_t active_prefixes = 1;
    for (std::size_t variable = 0; variable < source_rounds;
         ++variable) {
        const ConstraintSumcheckRound round =
            evaluate_artifact_source_round(
                *validated_source, arrays, domain_size, active_size,
                variable,
                std::span<const Fq2>(prefix_weights).first(
                    active_prefixes),
                prefix_count, tau, block_elements, options,
                output.report);
        output.sumcheck.proof.rounds.push_back(round);
        observe_constraint_round(round, public_coin);
        const Fq2 challenge = public_coin.challenge_fq2();
        output.sumcheck.point.push_back(challenge);
        advance_constraint_claim(stripped_claim, equality_prefix,
                                 tau[variable], challenge, round);
        expand_prefix_weights(prefix_weights, active_prefixes, challenge);
    }
    if (active_prefixes != prefix_count) {
        throw std::logic_error(
            "constraint prefix checkpoint is incomplete");
    }

    const Digest checkpoint_identity = artifact_checkpoint_identity(
        selection, checkpoint_size, output.sumcheck.point);
    ConstraintScratchArtifact current =
        materialize_constraint_checkpoint(
            *validated_source, arrays, domain_size, active_size,
            std::span<const Fq2>(prefix_weights).first(active_prefixes),
            prefix_count, block_elements, checkpoint_identity,
            "checkpoint-" + std::to_string(source_rounds), options,
            tracker, output.report);
    std::vector<Fq2>{}.swap(prefix_weights);

    for (std::size_t variable = source_rounds; variable < variables;
         ++variable) {
        const ConstraintSumcheckRound round =
            evaluate_artifact_fold_round(
                current, variable, tau, block_elements, options,
                output.report);
        output.sumcheck.proof.rounds.push_back(round);
        observe_constraint_round(round, public_coin);
        const Fq2 challenge = public_coin.challenge_fq2();
        output.sumcheck.point.push_back(challenge);
        advance_constraint_claim(stripped_claim, equality_prefix,
                                 tau[variable], challenge, round);

        const std::size_t next_size = current.element_count / 2U;
        const Digest next_identity = artifact_checkpoint_identity(
            selection, next_size, output.sumcheck.point);
        ConstraintScratchArtifact next = fold_constraint_checkpoint(
            current, challenge, block_elements, next_identity,
            "fold-" + std::to_string(variable), options, tracker,
            output.report);
        retire_constraint_scratch(current, tracker);
        current = std::move(next);
        ++output.report.fold_passes;
    }

    const std::array<Fq2, 3> terminal =
        read_constraint_terminal(current, output.report);
    output.sumcheck.az_evaluation = terminal[0];
    output.sumcheck.bz_evaluation = terminal[1];
    output.sumcheck.cz_evaluation = terminal[2];
    output.sumcheck.final_claim = equality_prefix * stripped_claim;
    if (stripped_claim !=
        terminal[0] * terminal[1] - terminal[2]) {
        throw std::logic_error(
            "artifact constraint sumcheck terminal mismatch");
    }
    retire_constraint_scratch(current, tracker);
    output.report.scratch_retained_physical_bytes =
        tracker.current_bytes();
    if (output.report.scratch_peak_physical_bytes != scratch.peak_bytes ||
        output.report.scratch_written_physical_bytes !=
            scratch.cumulative_bytes ||
        output.report.scratch_deleted_physical_bytes !=
            scratch.cumulative_bytes ||
        output.report.scratch_artifact_validation_bytes !=
            scratch.cumulative_bytes ||
        output.report.scratch_retained_physical_bytes != 0 ||
        output.report.peak_working_field_bytes != exact_field_peak ||
        !std::filesystem::is_empty(options.scratch_directory)) {
        throw std::logic_error(
            "constraint artifact accounting or cleanup mismatch");
    }
    cleanup.disarm();
    return output;
}

} // namespace laminate::spartan
