/// @file layer_reduction_sumcheck.cpp
/// @brief Plaintext reference sumchecks for Laminate layer reductions.

#include "laminate/gkr/layer_reduction_sumcheck.hpp"

#include "laminate/field/fp.hpp"
#include "laminate/field/serialization.hpp"
#include "laminate/gkr/detail/shared/reduction/sumcheck.hpp"
#include "laminate/poly/eq.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace laminate::gkr {
namespace {

/// Values are part of the transcript format. Keep them stable across renames.
enum class LayerReductionKind : std::uint64_t {
    Affine = 0,
    Multiplication = 2,
};

constexpr std::string_view kKindLabel = "laminate/gkr/sumcheck/kind/v1";
constexpr std::string_view kRoundCountLabel =
    "laminate/gkr/sumcheck/round-count/v1";
constexpr std::string_view kRoundIndexLabel =
    "laminate/gkr/sumcheck/round-index/v1";
constexpr std::string_view kRoundValuesLabel =
    "laminate/gkr/sumcheck/round-values/v2";

void begin_sumcheck(Transcript &transcript, LayerReductionKind kind,
                    std::size_t round_count) {
    transcript.observe(kKindLabel, static_cast<std::uint64_t>(kind));
    transcript.observe(kRoundCountLabel,
                       static_cast<std::uint64_t>(round_count));
}

void observe_round(Transcript &transcript, std::size_t round_index,
                   const LayerReductionSumcheckRound &round) {
    transcript.observe(kRoundIndexLabel,
                       static_cast<std::uint64_t>(round_index));
    std::array<std::uint8_t, 2 * kSerializedFpkBytes> bytes{};
    const SerializedFpk endpoint = serialize(round.at_endpoint);
    const SerializedFpk at_two = serialize(round.at_two);
    std::copy(endpoint.begin(), endpoint.end(), bytes.begin());
    std::copy(at_two.begin(), at_two.end(),
              bytes.begin() + static_cast<std::ptrdiff_t>(
                                  kSerializedFpkBytes));
    transcript.observe(kRoundValuesLabel, std::span<const std::uint8_t>(bytes));
}

std::vector<Fpk> extend_prefix_weights(const std::vector<Fpk> &weights,
                                       const Fpk &challenge) {
    std::vector<Fpk> result(weights.size() * 2, Fpk::zero());
    for (std::size_t index = 0; index < weights.size(); ++index) {
        const Fpk high = weights[index] * challenge;
        result[2 * index] = weights[index] - high;
        result[2 * index + 1] = high;
    }
    return result;
}

/// Bind a prefix directly from the original table. The supplied weights are
/// [eq(prefix_challenges, prefix_vertex)] in MSB-first order.
std::vector<Fpk> partial_eval_prefix(const poly::Multilinear<Fpk> &table,
                                     const std::vector<Fpk> &weights,
                                     std::size_t bound) {
    if (bound > table.num_vars() ||
        weights.size() != poly::hypercube_size(bound)) {
        throw std::invalid_argument(
            "partial_eval_prefix: invalid prefix dimensions");
    }
    const std::size_t remaining = table.num_vars() - bound;
    const std::size_t remaining_size = poly::hypercube_size(remaining);
    std::vector<Fpk> result(remaining_size, Fpk::zero());
    for (std::size_t suffix = 0; suffix < remaining_size; ++suffix) {
        for (std::size_t prefix = 0; prefix < weights.size(); ++prefix) {
            result[suffix] +=
                weights[prefix] * table.on_hypercube(
                                      (prefix << remaining) | suffix);
        }
    }
    return result;
}

/// Evaluate the two values sent in one affine reference round.
///
/// With the existing challenge prefix fixed, the round polynomial is
///
///   S_j(X) = sum_u A(r_0,...,r_{j-1},X,u)
///                  Z(r_0,...,r_{j-1},X,u).
///
/// Its degree is two. The prover sends S_j(1) and S_j(2); the verifier obtains
/// S_j(0) from the invariant claim_j = S_j(0) + S_j(1).
LayerReductionSumcheckRound evaluate_affine_reference_round(
    const poly::Multilinear<Fpk> &gate_weights,
    const poly::Multilinear<Fpk> &source_values,
    const std::vector<Fpk> &prefix_weights, std::size_t round_index) {
    const std::vector<Fpk> weights = partial_eval_prefix(
        gate_weights, prefix_weights, round_index);
    const std::vector<Fpk> source = partial_eval_prefix(
        source_values, prefix_weights, round_index);
    const std::size_t suffix_count = weights.size() / 2;

    Fpk at_one = Fpk::zero();
    Fpk at_two = Fpk::zero();
    for (std::size_t suffix = 0; suffix < suffix_count; ++suffix) {
        const Fpk &weight_zero = weights[suffix];
        const Fpk &weight_one = weights[suffix_count + suffix];
        const Fpk &source_zero = source[suffix];
        const Fpk &source_one = source[suffix_count + suffix];
        const Fpk weight_two = weight_one + weight_one - weight_zero;
        const Fpk source_two = source_one + source_one - source_zero;
        at_one += weight_one * source_one;
        at_two += weight_two * source_two;
    }
    return LayerReductionSumcheckRound{at_one, at_two};
}

ProvedLayerReductionSumcheck prove_affine_sumcheck(
    const poly::Multilinear<Fpk> &gate_weights,
    const poly::Multilinear<Fpk> &source_values, Transcript &transcript) {
    if (gate_weights.num_vars() != source_values.num_vars()) {
        throw std::invalid_argument(
            "AffineLayerReductionSumcheck: table dimensions differ");
    }
    const std::size_t num_vars = gate_weights.num_vars();
    begin_sumcheck(transcript, LayerReductionKind::Affine, num_vars);

    ProvedLayerReductionSumcheck output;
    output.proof.rounds.reserve(num_vars);
    output.challenges.reserve(num_vars);
    std::vector<Fpk> prefix_weights{Fpk::one()};

    for (std::size_t round_index = 0; round_index < num_vars; ++round_index) {
        // Step 1: Evaluate S_j(1) and S_j(2) from the original tables.
        const LayerReductionSumcheckRound round =
            evaluate_affine_reference_round(
                gate_weights, source_values, prefix_weights, round_index);

        // Step 2: Publish and transcript-bind this round message.
        observe_round(transcript, round_index, round);
        output.proof.rounds.push_back(round);

        // Step 3: Sample r_j only after the message is bound.
        const Fpk challenge = transcript.challenge_fpk();
        output.challenges.push_back(challenge);

        // Step 4: Extend the equality weights that fix the next prefix.
        prefix_weights = extend_prefix_weights(prefix_weights, challenge);
    }
    return output;
}

std::vector<Fpk> oracle_point(const std::vector<Fpk> &prefix,
                              const Fpk &round_value,
                              std::size_t suffix_index,
                              std::size_t suffix_vars) {
    std::vector<Fpk> point;
    point.reserve(prefix.size() + 1 + suffix_vars);
    point.insert(point.end(), prefix.begin(), prefix.end());
    point.push_back(round_value);
    for (std::size_t variable = 0; variable < suffix_vars; ++variable) {
        const bool bit =
            ((suffix_index >> (suffix_vars - 1 - variable)) & 1U) != 0;
        point.push_back(bit ? Fpk::one() : Fpk::zero());
    }
    return point;
}

/// Evaluate the two values sent in one dense-multiplication reference round.
///
/// Ciphertext-index rounds use the full relation L(X,u)R(X,u). Slot-index
/// rounds use the relation with the public output-equality factor stripped.
/// In both cases the prover sends the nonsingular Boolean endpoint and S_j(2);
/// the verifier reconstructs the omitted endpoint from its running claim.
LayerReductionSumcheckRound evaluate_multiplication_reference_round(
    std::size_t round_index, std::size_t round_count,
    std::size_t ciphertext_index_variables,
    const std::vector<Fpk> &output_claim_point,
    const std::vector<Fpk> &challenge_prefix,
    const MultiplicationLayerReductionSumcheck::Oracle
        &multiplication_relation,
    const MultiplicationLayerReductionSumcheck::Oracle
        &stripped_multiplication_relation) {
    const std::size_t suffix_variables = round_count - round_index - 1U;
    const std::size_t suffix_count =
        poly::hypercube_size(suffix_variables);

    std::vector<Fpk> suffix_weights(suffix_count, Fpk::one());
    if (round_index >= ciphertext_index_variables) {
        const std::size_t slot_round =
            round_index - ciphertext_index_variables;
        suffix_weights = poly::eq_evaluations(std::vector<Fpk>(
            output_claim_point.begin() +
                static_cast<std::ptrdiff_t>(slot_round + 1U),
            output_claim_point.end()));
    }

    const Fpk endpoint =
        round_index >= ciphertext_index_variables &&
                !output_claim_point[round_index -
                                    ciphertext_index_variables].is_zero()
            ? Fpk::zero()
            : Fpk::one();
    const detail::LayerReductionRoundPoints points{.endpoint = endpoint};
    const auto &oracle = round_index < ciphertext_index_variables
                             ? multiplication_relation
                             : stripped_multiplication_relation;

    Fpk at_endpoint = Fpk::zero();
    Fpk at_two = Fpk::zero();
    for (std::size_t suffix = 0; suffix < suffix_count; ++suffix) {
        const std::vector<Fpk> endpoint_point = oracle_point(
            challenge_prefix, points.endpoint, suffix, suffix_variables);
        const std::vector<Fpk> two_point = oracle_point(
            challenge_prefix, points.at_two, suffix, suffix_variables);
        at_endpoint += suffix_weights[suffix] * oracle(endpoint_point);
        at_two += suffix_weights[suffix] * oracle(two_point);
    }
    return LayerReductionSumcheckRound{at_endpoint, at_two};
}

VerifiedLayerReductionSumcheck verify_affine_sumcheck(
    const LayerReductionSumcheckProof &proof, const Fpk &claimed_sum,
    std::size_t num_vars, Transcript &transcript) {
    VerifiedLayerReductionSumcheck result;
    if (proof.rounds.size() != num_vars) {
        return result;
    }

    begin_sumcheck(transcript, LayerReductionKind::Affine, num_vars);
    result.challenges.reserve(num_vars);
    Fpk running_claim = claimed_sum;

    for (std::size_t round_index = 0; round_index < num_vars; ++round_index) {
        const LayerReductionSumcheckRound &round = proof.rounds[round_index];

        // Step 1: Recover S_j(0) from
        //   claim_j = S_j(0) + S_j(1).
        // The proof transmits S_j(1), so no division is required.
        const Fpk &at_one = round.at_endpoint;
        const Fpk at_zero = running_claim - at_one;
        const detail::LayerReductionRoundEvaluations polynomial{
            at_zero, at_one, round.at_two};

        // Step 2: Bind the message and sample r_j.
        observe_round(transcript, round_index, round);
        const Fpk challenge = transcript.challenge_fpk();
        result.challenges.push_back(challenge);

        // Step 3: Carry claim_{j+1}=S_j(r_j) into the next round.
        running_claim = polynomial.interpolate_at(challenge);
    }

    result.structurally_valid = true;
    result.final_claim = running_claim;
    return result;
}

} // namespace

ProvedLayerReductionSumcheck AffineLayerReductionSumcheck::prove(
    const poly::Multilinear<Fpk> &affine_coefficients,
    const poly::Multilinear<Fpk> &source_layer_values,
    Transcript &transcript) {
    return prove_affine_sumcheck(affine_coefficients, source_layer_values,
                                 transcript);
}

VerifiedLayerReductionSumcheck AffineLayerReductionSumcheck::verify(
    const LayerReductionSumcheckProof &proof,
    const Fpk &adjusted_claim, std::size_t source_variables,
    Transcript &transcript) {
    return verify_affine_sumcheck(proof, adjusted_claim, source_variables,
                                  transcript);
}

ProvedLayerReductionSumcheck MultiplicationLayerReductionSumcheck::prove(
    std::size_t ciphertext_index_variables,
    const std::vector<Fpk> &output_claim_point,
    const Oracle &multiplication_relation,
    const Oracle &stripped_multiplication_relation,
    Transcript &transcript) {
    if (!multiplication_relation || !stripped_multiplication_relation ||
        ciphertext_index_variables >
            std::numeric_limits<std::size_t>::max() -
                output_claim_point.size()) {
        throw std::invalid_argument(
            "MultiplicationLayerReductionSumcheck: invalid arguments");
    }
    const std::size_t num_vars =
        ciphertext_index_variables + output_claim_point.size();
    (void)poly::hypercube_size(num_vars);
    begin_sumcheck(transcript, LayerReductionKind::Multiplication, num_vars);

    ProvedLayerReductionSumcheck output;
    output.proof.rounds.reserve(num_vars);
    output.challenges.reserve(num_vars);
    std::vector<Fpk> prefix;
    prefix.reserve(num_vars);

    for (std::size_t round_index = 0; round_index < num_vars;
         ++round_index) {
        // Step 1: Evaluate the nonsingular Boolean endpoint and S_j(2).
        const LayerReductionSumcheckRound round =
            evaluate_multiplication_reference_round(
                round_index, num_vars, ciphertext_index_variables,
                output_claim_point, prefix, multiplication_relation,
                stripped_multiplication_relation);

        // Step 2: Publish and transcript-bind this round message.
        observe_round(transcript, round_index, round);
        output.proof.rounds.push_back(round);

        // Step 3: Sample r_j only after the message is bound.
        const Fpk challenge = transcript.challenge_fpk();
        output.challenges.push_back(challenge);

        // Step 4: Fix this coordinate for the next oracle evaluation.
        prefix.push_back(challenge);
    }
    return output;
}

VerifiedLayerReductionSumcheck MultiplicationLayerReductionSumcheck::verify(
    const LayerReductionSumcheckProof &proof, const Fpk &claimed_sum,
    std::size_t ciphertext_index_variables,
    const std::vector<Fpk> &output_claim_point,
    Transcript &transcript) {
    VerifiedLayerReductionSumcheck result;
    if (ciphertext_index_variables >
        std::numeric_limits<std::size_t>::max() -
            output_claim_point.size()) {
        return result;
    }
    const std::size_t num_vars =
        ciphertext_index_variables + output_claim_point.size();
    if (proof.rounds.size() != num_vars) {
        return result;
    }

    begin_sumcheck(transcript, LayerReductionKind::Multiplication, num_vars);
    result.challenges.reserve(num_vars);
    Fpk running_claim = claimed_sum;
    for (std::size_t round_index = 0; round_index < num_vars;
         ++round_index) {
        const LayerReductionSumcheckRound &round = proof.rounds[round_index];

        // Step 1: Recover the omitted Boolean endpoint from
        //
        //   claim_j = (1 - tau_j) S_j(0) + tau_j S_j(1).
        //
        // Ciphertext-index rounds use the ordinary identity
        // claim_j=S_j(0)+S_j(1). Slot-index rounds use the weighted identity
        // above and transmit S_j(0) when tau_j!=0; otherwise they transmit
        // S_j(1) and recover S_j(0)=claim_j without division.
        const Fpk &endpoint = round.at_endpoint;
        Fpk at_zero;
        Fpk at_one;
        if (round_index < ciphertext_index_variables) {
            at_one = endpoint;
            at_zero = running_claim - at_one;
        } else {
            const Fpk &tau =
                output_claim_point[round_index -
                                   ciphertext_index_variables];
            if (tau.is_zero()) {
                at_zero = running_claim;
                at_one = endpoint;
            } else {
                at_zero = endpoint;
                at_one = (running_claim - (Fpk::one() - tau) * at_zero) *
                         tau.inverse();
            }
        }
        const detail::LayerReductionRoundEvaluations polynomial{
            at_zero, at_one, round.at_two};

        // Step 2: Bind the message and sample r_j.
        observe_round(transcript, round_index, round);
        const Fpk challenge = transcript.challenge_fpk();
        result.challenges.push_back(challenge);

        // Step 3: Set claim_{j+1}=S_j(r_j).
        running_claim = polynomial.interpolate_at(challenge);

    }
    result.structurally_valid = true;
    result.final_claim = running_claim;
    return result;
}

} // namespace laminate::gkr
