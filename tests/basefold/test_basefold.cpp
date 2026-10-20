/// @file test_basefold.cpp
/// @brief Algebraic and tamper tests for Laminate's focused BaseFold subset.

#include "test_helpers.hpp"

#include "laminate/basefold/basefold.hpp"
#include "laminate/basefold/common.hpp"
#include "laminate/basefold/merkle.hpp"
#include "laminate/basefold/reed_solomon.hpp"
#include "laminate/transcript/transcript.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <limits>
#include <span>
#include <vector>

using namespace laminate;

namespace {

std::vector<Fp> deterministic_base_vector(std::size_t size,
                                          std::uint64_t offset) {
    std::vector<Fp> values(size);
    for (std::size_t index = 0; index < size; ++index) {
        values[index] = Fp(offset + 37 * index + index * index);
    }
    return values;
}

Fp horner(std::span<const Fp> coefficients, const Fp &point) {
    Fp result = Fp::zero();
    for (std::size_t index = coefficients.size(); index-- > 0;) {
        result = result * point + coefficients[index];
    }
    return result;
}

std::vector<Fpk> equality_table(std::span<const Fpk> point) {
    std::vector<Fpk> table(std::size_t{1} << point.size());
    for (std::size_t index = 0; index < table.size(); ++index) {
        table[index] = basefold::equality_evaluation(index, point);
    }
    return table;
}

Fpk equality_of_points(std::span<const Fpk> left,
                       std::span<const Fpk> right) {
    CHECK(left.size() == right.size());
    Fpk result = Fpk::one();
    for (std::size_t variable = 0; variable < left.size(); ++variable) {
        result *= (Fpk::one() - left[variable]) *
                      (Fpk::one() - right[variable]) +
                  left[variable] * right[variable];
    }
    return result;
}

void seed_transcript(Transcript &transcript,
                     const basefold::Commitment &commitment,
                     std::span<const Fpk> weights,
                     std::span<const Fpk> targets) {
    transcript.observe("test/basefold/root", commitment.root);
    transcript.observe("test/basefold/m", commitment.m);
    transcript.observe("test/basefold/width", commitment.width);
    transcript.observe("test/basefold/weights",
                       basefold::serialize_values(weights));
    transcript.observe("test/basefold/targets",
                       basefold::serialize_values(targets));
}

void seed_target_matrix(Transcript &transcript,
                        const basefold::Commitment &commitment,
                        const basefold::ColumnTargets &targets) {
    transcript.observe("test/basefold/root", commitment.root);
    transcript.observe("test/basefold/m", commitment.m);
    transcript.observe("test/basefold/width", commitment.width);
    for (const std::vector<Fpk> &row : targets) {
        transcript.observe("test/basefold/target-row",
                           basefold::serialize_values(row));
    }
}

} // namespace

int main() {
    test::Runner runner("test_basefold");

    runner.run("linear equality table matches scalar LSB evaluations", [] {
        for (const std::size_t variables : {0U, 1U, 2U, 5U, 14U}) {
            std::vector<Fpk> point;
            point.reserve(variables);
            for (std::size_t variable = 0; variable < variables;
                 ++variable) {
                Fpk::Coefficients coefficients{};
                for (std::size_t coefficient = 0;
                     coefficient < coefficients.size(); ++coefficient) {
                    coefficients[coefficient] = Fp(
                        17U + 31U * variable + 7U * coefficient);
                }
                point.emplace_back(coefficients);
            }
            const std::vector<Fpk> table =
                basefold::equality_evaluations(point);
            CHECK(table.size() == (std::size_t{1} << variables));
            Fpk sum = Fpk::zero();
            for (std::size_t index = 0; index < table.size(); ++index) {
                CHECK(table[index] ==
                      basefold::equality_evaluation(index, point));
                sum += table[index];
            }
            CHECK(sum == Fpk::one());
        }
    });

    runner.run("query sampling rejects challenge-bit count overflow", [] {
        Transcript transcript("Laminate/BaseFold/QueryOverflow/v1");
        bool rejected = false;
        try {
            (void)basefold::derive_query_indices(
                transcript,
                std::numeric_limits<std::size_t>::max() / 2U + 1U,
                4U);
        } catch (const std::overflow_error &) {
            rejected = true;
        }
        CHECK(rejected);
    });

    runner.run("NTT evaluates the coefficient polynomial", [] {
        for (const std::size_t log_size : {1U, 3U, 6U}) {
            const std::size_t size = std::size_t{1} << log_size;
            const std::vector<Fp> coefficients =
                deterministic_base_vector(size, 11);
            std::vector<Fp> encoded = coefficients;
            const Fp generator = Fp::two_adic_generator(log_size);
            basefold::ntt_in_place(encoded, generator);
            Fp point = Fp::one();
            for (std::size_t index = 0; index < size; ++index) {
                CHECK(encoded[index] == horner(coefficients, point));
                point *= generator;
            }
        }
    });

    runner.run("BCS16 BLAKE2b-320 leaf domain has a pinned vector", [] {
        const std::vector<std::uint8_t> input{'a', 'b', 'c'};
        const basefold::Digest expected{
            0xa1, 0xa4, 0xb7, 0xc5, 0x46, 0xb0, 0xc1, 0xc9,
            0xe8, 0x59, 0xa9, 0x49, 0xca, 0x50, 0xa3, 0xfe,
            0xea, 0x33, 0x4b, 0xef, 0x7b, 0x85, 0xcd, 0xb7,
            0x28, 0x50, 0x00, 0xaf, 0x01, 0x11, 0x75, 0xd9,
            0x3f, 0x6d, 0x62, 0x09, 0x2f, 0x71, 0x75, 0x4f};
        CHECK(basefold::MerkleTree::hash_leaf(input) == expected);
        CHECK(basefold::MerkleTree::hash_leaf({}) != expected);
    });

    runner.run("Merkle union-frontier multiproofs are canonical", [] {
        std::vector<std::vector<std::uint8_t>> leaves(8);
        for (std::size_t index = 0; index < leaves.size(); ++index) {
            leaves[index] = {static_cast<std::uint8_t>(index),
                             static_cast<std::uint8_t>(3U * index + 1U)};
        }
        const basefold::MerkleTree tree(leaves);
        const auto hashes_for = [&](std::span<const std::size_t> indices) {
            std::vector<basefold::Digest> result;
            result.reserve(indices.size());
            for (const std::size_t index : indices) {
                result.push_back(
                    basefold::MerkleTree::hash_leaf(leaves[index]));
            }
            return result;
        };
        const auto verifies = [&](std::span<const std::size_t> indices,
                                  std::span<const basefold::Digest> frontier) {
            const std::vector<basefold::Digest> hashes =
                hashes_for(indices);
            return basefold::MerkleTree::verify_many_hashes(
                tree.root(), tree.leaf_count(), indices, hashes, frontier);
        };

        const std::array<std::size_t, 2> adjacent{2, 3};
        const std::vector<basefold::Digest> adjacent_frontier =
            tree.open_many(adjacent);
        CHECK(adjacent_frontier.size() == 2U);
        CHECK(verifies(adjacent, adjacent_frontier));

        const std::array<std::size_t, 2> separated{1, 6};
        const std::vector<basefold::Digest> separated_frontier =
            tree.open_many(separated);
        CHECK(separated_frontier.size() == 4U);
        CHECK(verifies(separated, separated_frontier));

        const std::array<std::size_t, 8> all{0, 1, 2, 3, 4, 5, 6, 7};
        const std::vector<basefold::Digest> all_frontier =
            tree.open_many(all);
        CHECK(all_frontier.empty());
        CHECK(verifies(all, all_frontier));

        const std::vector<std::vector<std::uint8_t>> singleton_leaf{{9, 7}};
        const basefold::MerkleTree singleton(singleton_leaf);
        const std::array<std::size_t, 1> singleton_index{0};
        const std::vector<basefold::Digest> singleton_frontier =
            singleton.open_many(singleton_index);
        const std::array<basefold::Digest, 1> singleton_hash{
            basefold::MerkleTree::hash_leaf(singleton_leaf.front())};
        CHECK(singleton_frontier.empty());
        CHECK(basefold::MerkleTree::verify_many_hashes(
            singleton.root(), 1U, singleton_index, singleton_hash,
            singleton_frontier));

        const auto throws = [](const auto &body) {
            try {
                body();
                return false;
            } catch (const std::exception &) {
                return true;
            }
        };
        const std::array<std::size_t, 2> unsorted{3, 2};
        const std::array<std::size_t, 2> duplicate{2, 2};
        const std::array<std::size_t, 1> out_of_range{8};
        const std::vector<std::size_t> empty;
        CHECK(throws([&] { (void)tree.open_many(unsorted); }));
        CHECK(throws([&] { (void)tree.open_many(duplicate); }));
        CHECK(throws([&] { (void)tree.open_many(out_of_range); }));
        CHECK(throws([&] { (void)tree.open_many(empty); }));
        CHECK(!verifies(unsorted, adjacent_frontier));
        CHECK(!verifies(duplicate, adjacent_frontier));
        const std::array<basefold::Digest, 1> dummy_hash{};
        CHECK(!basefold::MerkleTree::verify_many_hashes(
            tree.root(), tree.leaf_count(), out_of_range, dummy_hash,
            adjacent_frontier));
        CHECK(!basefold::MerkleTree::verify_many_hashes(
            tree.root(), tree.leaf_count(), empty,
            std::span<const basefold::Digest>{}, adjacent_frontier));

        CHECK(!verifies(
            separated,
            std::span<const basefold::Digest>(separated_frontier)
                .first(separated_frontier.size() - 1U)));
        std::vector<basefold::Digest> extra = separated_frontier;
        extra.push_back({});
        CHECK(!verifies(separated, extra));
        std::vector<basefold::Digest> tampered = separated_frontier;
        tampered.front().front() ^= 1U;
        CHECK(!verifies(separated, tampered));
        std::vector<basefold::Digest> tampered_hashes =
            hashes_for(separated);
        tampered_hashes.front().front() ^= 1U;
        CHECK(!basefold::MerkleTree::verify_many_hashes(
            tree.root(), tree.leaf_count(), separated, tampered_hashes,
            separated_frontier));
    });

    runner.run("Mobius transform preserves the LSB-first MLE", [] {
        const std::vector<Fp> evaluations =
            deterministic_base_vector(32, 19);
        const std::vector<Fp> coefficients =
            basefold::evaluations_to_coefficients(evaluations);
        CHECK(basefold::coefficients_to_evaluations(coefficients) ==
              evaluations);

        const std::vector<Fpk> point = {Fpk::random_element(),
                                        Fpk::random_element(),
                                        Fpk::random_element(),
                                        Fpk::random_element(),
                                        Fpk::random_element()};
        Fpk via_evaluations = Fpk::zero();
        Fpk via_coefficients = Fpk::zero();
        for (std::size_t index = 0; index < evaluations.size(); ++index) {
            via_evaluations +=
                basefold::equality_evaluation(index, point) *
                evaluations[index];
            Fpk monomial = Fpk::one();
            for (std::size_t variable = 0; variable < point.size();
                 ++variable) {
                if (((index >> variable) & 1U) != 0) {
                    monomial *= point[variable];
                }
            }
            via_coefficients += monomial * coefficients[index];
        }
        CHECK(via_evaluations == via_coefficients);
    });

    runner.run("fixed-column reduction accepts and exposes analytic claims",
               [] {
                   constexpr std::size_t kM = 16;
                   constexpr std::size_t kWidth = 4;
                   const basefold::Parameters parameters{2, 10};
                   std::vector<std::vector<Fp>> columns(kWidth);
                   for (std::size_t column = 0; column < kWidth; ++column) {
                       columns[column] = deterministic_base_vector(
                           kM, 1000 * (column + 1));
                   }
                   const basefold::Commitment commitment =
                       basefold::commit(columns, parameters.log_rate);

                   const std::vector<Fpk> low_point_a = {
                       Fpk::random_element(), Fpk::random_element(),
                       Fpk::random_element(), Fpk::random_element()};
                   const std::vector<Fpk> low_point_b = {
                       Fpk::random_element(), Fpk::random_element(),
                       Fpk::random_element(), Fpk::random_element()};
                   const std::vector<std::vector<Fpk>> operands = {
                       equality_table(low_point_a),
                       equality_table(low_point_b)};
                   const std::vector<Fpk> high_point = {
                       Fpk::random_element(), Fpk::random_element()};
                   std::vector<Fpk> weights(kWidth);
                   for (std::size_t column = 0; column < kWidth; ++column) {
                       weights[column] = basefold::equality_evaluation(
                           column, high_point);
                   }

                   basefold::PreparedLinearCombination combination =
                       basefold::prepare_linear_combination(
                           commitment, operands, weights);
                   const std::vector<Fpk> targets = combination.targets;
                   Transcript prover_transcript("Laminate/BaseFold/Test/v1");
                   seed_transcript(prover_transcript, commitment, weights,
                                   targets);
                   const basefold::ProverOutput prover = basefold::prove(
                       commitment, operands, weights, std::move(combination),
                       prover_transcript, parameters);

                   Transcript verifier_transcript(
                       "Laminate/BaseFold/Test/v1");
                   seed_transcript(verifier_transcript, commitment, weights,
                                   targets);
                   const auto reduction = basefold::verify(
                       commitment.root, commitment.m, commitment.width,
                       operands.size(), weights, targets, prover.proof,
                       verifier_transcript, parameters);
                   CHECK(reduction.has_value());
                   CHECK(reduction->point == prover.reduction.point);
                   CHECK(reduction->operand_evaluations ==
                         prover.reduction.operand_evaluations);
                   CHECK(reduction->operand_evaluations[0] ==
                         equality_of_points(low_point_a, reduction->point));
                   CHECK(reduction->operand_evaluations[1] ==
                         equality_of_points(low_point_b, reduction->point));
                   CHECK(prover_transcript.challenge_fpk() ==
                         verifier_transcript.challenge_fpk());
               });

    runner.run("default rate-eight openings reject tampered claims", [] {
        constexpr std::size_t kM = 8;
        constexpr std::size_t kWidth = 2;
        const basefold::Parameters parameters{};
        CHECK(parameters.log_rate == 3U);
        CHECK(parameters.num_queries == kGateMleBaseFoldQueries);
        std::vector<std::vector<Fp>> columns(kWidth);
        for (std::size_t column = 0; column < kWidth; ++column) {
            columns[column] =
                deterministic_base_vector(kM, 71 * (column + 1));
        }
        const basefold::Commitment commitment =
            basefold::commit(columns, parameters.log_rate);
        const std::vector<Fpk> point = {
            Fpk::random_element(), Fpk::random_element(),
            Fpk::random_element()};
        const std::vector<std::vector<Fpk>> operands = {
            equality_table(point)};
        const std::vector<Fpk> weights = {Fpk::random_element(),
                                          Fpk::random_element()};
        auto combination = basefold::prepare_linear_combination(
            commitment, operands, weights);
        const std::vector<Fpk> targets = combination.targets;
        Transcript prover_transcript("Laminate/BaseFold/Tamper/v1");
        seed_transcript(prover_transcript, commitment, weights, targets);
        const basefold::ProverOutput prover = basefold::prove(
            commitment, operands, weights, std::move(combination),
            prover_transcript, parameters);

        auto verifies = [&](const std::vector<Fpk> &claims,
                            const basefold::Proof &proof) {
            Transcript verifier_transcript(
                "Laminate/BaseFold/Tamper/v1");
            seed_transcript(verifier_transcript, commitment, weights,
                            claims);
            return basefold::verify_with_materialized_operands(
                commitment.root, commitment.m, commitment.width, operands,
                weights, claims, proof, verifier_transcript, parameters);
        };
        CHECK(verifies(targets, prover.proof));
        CHECK(prover.proof.queries.openings.size() == parameters.num_queries);

        basefold::Proof missing_query = prover.proof;
        missing_query.queries.openings.pop_back();
        CHECK(!verifies(targets, missing_query));
        basefold::Proof extra_query = prover.proof;
        extra_query.queries.openings.push_back(
            extra_query.queries.openings.front());
        CHECK(!verifies(targets, extra_query));

        std::vector<Fpk> bad_targets = targets;
        bad_targets[0] += Fpk::one();
        CHECK(!verifies(bad_targets, prover.proof));

        basefold::Proof bad_query = prover.proof;
        bad_query.queries.openings[0].base_lo[0] += Fp::one();
        CHECK(!verifies(targets, bad_query));

        basefold::Proof bad_operand = prover.proof;
        bad_operand.sumcheck.operand_evaluations[0] += Fpk::one();
        CHECK(!verifies(targets, bad_operand));
    });

    runner.run("distinct column points share one two-dimensional batch", [] {
        constexpr std::size_t kM = 8;
        constexpr std::size_t kWidth = 4;
        const basefold::Parameters parameters{2, 8};
        std::vector<std::vector<Fp>> columns(kWidth);
        for (std::size_t column = 0; column < kWidth; ++column) {
            columns[column] = deterministic_base_vector(
                kM, 313 * (column + 1));
        }
        const basefold::Commitment commitment =
            basefold::commit(columns, parameters.log_rate);
        const std::vector<Fpk> low_a = {
            Fpk::random_element(), Fpk::random_element(),
            Fpk::random_element()};
        const std::vector<Fpk> low_b = {
            Fpk::random_element(), Fpk::random_element(),
            Fpk::random_element()};
        const std::vector<std::vector<Fpk>> operands = {
            equality_table(low_a), equality_table(low_b)};
        const basefold::ColumnTargets targets =
            basefold::prepare_all_column_targets(commitment, operands);

        Transcript prover_transcript("Laminate/BaseFold/Matrix/v1");
        seed_target_matrix(prover_transcript, commitment, targets);
        const basefold::ProverOutput prover = basefold::prove_all_columns(
            commitment, operands, targets, prover_transcript, parameters);

        Transcript verifier_transcript("Laminate/BaseFold/Matrix/v1");
        seed_target_matrix(verifier_transcript, commitment, targets);
        const auto reduction = basefold::verify_all_columns(
            commitment.root, commitment.m, commitment.width,
            operands.size(), targets, prover.proof, verifier_transcript,
            parameters);
        CHECK(reduction.has_value());
        CHECK(reduction->operand_evaluations[0] ==
              equality_of_points(low_a, reduction->point));
        CHECK(reduction->operand_evaluations[1] ==
              equality_of_points(low_b, reduction->point));
        CHECK(prover_transcript.challenge_fpk() ==
              verifier_transcript.challenge_fpk());

        basefold::ColumnTargets bad_targets = targets;
        bad_targets[1][2] += Fpk::one();
        Transcript bad_transcript("Laminate/BaseFold/Matrix/v1");
        seed_target_matrix(bad_transcript, commitment, bad_targets);
        CHECK(!basefold::verify_all_columns(
                   commitment.root, commitment.m, commitment.width,
                   operands.size(), bad_targets, prover.proof,
                   bad_transcript, parameters)
                   .has_value());
    });

    return runner.summary();
}
