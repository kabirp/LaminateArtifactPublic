/// @file test_sparse_product.cpp
/// @brief Correctness and forgery tests for sparse product-tree reductions.

#include "test_helpers.hpp"

#include "laminate/basefold/common.hpp"
#include "laminate/gates/sparse_product.hpp"
#include "laminate/transcript/transcript.hpp"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <stdexcept>
#include <string_view>
#include <vector>

using namespace laminate;

namespace {

Fpk extension(std::uint64_t seed) {
    Fpk::Coefficients coefficients{};
    for (std::size_t index = 0; index < coefficients.size(); ++index) {
        coefficients[index] =
            Fp(seed + 17U * index + 3U * index * index);
    }
    return Fpk(coefficients);
}

std::vector<Fpk> query(std::size_t variables, std::uint64_t seed) {
    std::vector<Fpk> result;
    result.reserve(variables);
    for (std::size_t variable = 0; variable < variables; ++variable) {
        result.push_back(extension(seed + 29U * variable));
    }
    return result;
}

/// Deterministic public coin whose first product-root challenge and first
/// child-batching challenge are exactly one.  They exercise Gruen's
/// division-free singular endpoint branch on both the entry and gate axes.
class TauOneCoin final : public PublicCoin {
  public:
    void observe(std::string_view,
                 std::span<const std::uint8_t>) override {}
    void observe(std::string_view, std::uint64_t) override {}

    Fpk challenge_fpk() override {
        const std::size_t index = next_fpk_++;
        return index == 0 || index == 4
                   ? Fpk::one()
                   : Fpk::from_base(Fp(2U + index));
    }

    Fq challenge_fq() override {
        throw std::logic_error("TauOneCoin sampled an unexpected Fq");
    }
    Fq2 challenge_fq2() override {
        throw std::logic_error("TauOneCoin sampled an unexpected Fq2");
    }
    std::vector<Fq2> challenge_fq2_vector(std::size_t) override {
        throw std::logic_error(
            "TauOneCoin sampled an unexpected Fq2 vector");
    }
    std::vector<Fpk> challenge_vector(std::size_t count) override {
        std::vector<Fpk> result;
        result.reserve(count);
        for (std::size_t index = 0; index < count; ++index) {
            result.push_back(challenge_fpk());
        }
        return result;
    }
    std::vector<bool> challenge_bits(std::size_t) override {
        throw std::logic_error(
            "TauOneCoin sampled unexpected challenge bits");
    }

  private:
    std::size_t next_fpk_ = 0;
};

/// Forces the first stripped equality factor to vanish: tau=0 and r=1.
/// A terminal check that multiplies both sides by eq(tau,r) would therefore
/// accept arbitrary child claims.
class EqualityRootCoin final : public PublicCoin {
  public:
    void observe(std::string_view,
                 std::span<const std::uint8_t>) override {}
    void observe(std::string_view, std::uint64_t) override {}

    Fpk challenge_fpk() override {
        const std::size_t index = next_fpk_++;
        if (index == 0) {
            return Fpk::zero();
        }
        if (index == 1) {
            return Fpk::one();
        }
        return Fpk::from_base(Fp(3U + index));
    }

    Fq challenge_fq() override {
        throw std::logic_error("EqualityRootCoin sampled an unexpected Fq");
    }
    Fq2 challenge_fq2() override {
        throw std::logic_error("EqualityRootCoin sampled an unexpected Fq2");
    }
    std::vector<Fq2> challenge_fq2_vector(std::size_t) override {
        throw std::logic_error(
            "EqualityRootCoin sampled an unexpected Fq2 vector");
    }
    std::vector<Fpk> challenge_vector(std::size_t count) override {
        std::vector<Fpk> result;
        result.reserve(count);
        for (std::size_t index = 0; index < count; ++index) {
            result.push_back(challenge_fpk());
        }
        return result;
    }
    std::vector<bool> challenge_bits(std::size_t) override {
        throw std::logic_error(
            "EqualityRootCoin sampled unexpected challenge bits");
    }

  private:
    std::size_t next_fpk_ = 0;
};

Fpk evaluate_committed_column(
    std::span<const gates::sparse::SparseEntry> entries,
    std::size_t message_size, std::size_t address_variables,
    std::size_t logical_column,
    std::span<const Fpk> entry_point_lsb) {
    std::vector<Fpk> table(message_size, Fpk::zero());
    for (std::size_t slot = 0; slot < entries.size(); ++slot) {
        if (logical_column == 0) {
            table[slot] = Fpk::from_base(entries[slot].value);
        } else {
            const std::size_t bit = logical_column - 1U;
            const std::size_t shift = address_variables - 1U - bit;
            table[slot] = ((entries[slot].address >> shift) & 1U) != 0
                              ? Fpk::one()
                              : Fpk::zero();
        }
    }
    return basefold::evaluate_multilinear(table, entry_point_lsb);
}

} // namespace

int main() {
    test::Runner runner("test_sparse_product");

    runner.run("bounded equality chunks match direct sparse semantics", [] {
        for (const std::size_t variables :
             {std::size_t{0}, std::size_t{1}, std::size_t{7}, std::size_t{8},
              std::size_t{9}, std::size_t{17}, std::size_t{33},
              std::size_t{std::numeric_limits<std::size_t>::digits}}) {
            for (const std::size_t count : {std::size_t{0}, std::size_t{1},
                                            std::size_t{3}, std::size_t{300}}) {
                for (const bool singular : {false, true}) {
                  auto point = query(variables, 401);
                  // Zero/one coordinates must work without division or a
                  // nonzero-selector assumption, including chunk boundaries.
                  if (singular)
                      for (std::size_t i = 0; i < point.size(); i += 7)
                          point[i] = i % 2 ? Fpk::one() : Fpk::zero();
                  const auto mask = variables == std::numeric_limits<std::size_t>::digits
                      ? std::numeric_limits<std::size_t>::max()
                      : (std::size_t{1} << variables) - 1;
                  std::vector<gates::sparse::SparseEntry> entries;
                  Fpk expected = Fpk::zero();
                  for (std::size_t i = 0; i < count; ++i) {
                      // Includes duplicate addresses and a zero coefficient.
                      const auto address = (mask ^ (i * 1297U)) & mask;
                      const Fp scalar((i + 1) % 19);
                      entries.push_back({address, scalar});
                      Fpk weight = Fpk::one();
                      for (std::size_t bit = 0; bit < variables; ++bit)
                          weight *= (address >> (variables - bit - 1)) & 1U
                              ? point[bit] : Fpk::one() - point[bit];
                      expected += weight * scalar;
                  }
                  CHECK(gates::sparse::evaluate_sparse_entries(
                            entries, variables, point) == expected);
                }
            }
        }
    });

    runner.run("low-degree tree reduces a sparse MLE to its columns", [] {
        const std::vector<gates::sparse::SparseEntry> entries = {
            {0, Fp(3)}, {2, Fp(5)}, {5, Fp(7)}, {7, Fp(11)}};
        constexpr std::size_t message_size = 8;
        constexpr std::size_t address_variables = 3;
        const std::vector<Fpk> point = query(address_variables, 101);
        const Fpk claimed = gates::sparse::evaluate_sparse_entries(
            entries, address_variables, point);

        Transcript prover("Laminate/gates/sparse/test/v1");
        const gates::sparse::SparseProductProverOutput output =
            gates::sparse::prove_sparse_evaluation(
                entries, message_size, address_variables, point, claimed,
                prover);
        CHECK(output.proof.root_rounds.size() == 3);
        CHECK(output.proof.layers.size() == 2);
        CHECK(output.reduction.entry_point_lsb.size() == 3);
        CHECK(output.reduction.factor_point_lsb.size() == 2);
        for (const gates::sparse::ProductLayerProof &layer :
             output.proof.layers) {
            for (const auto &round : layer.rounds) {
                CHECK(round.size() == 2);
            }
        }

        const gates::sparse::SparseLeafLinearization linearization =
            gates::sparse::linearize_sparse_leaf(
                address_variables, point,
                output.reduction.factor_point_lsb);
        CHECK(linearization.column_weights.size() ==
              address_variables + 1U);
        Fpk opened = linearization.constant;
        for (std::size_t column = 0;
             column < linearization.column_weights.size(); ++column) {
            opened += linearization.column_weights[column] *
                      evaluate_committed_column(
                          entries, message_size, address_variables, column,
                          output.reduction.entry_point_lsb);
        }
        CHECK(opened == output.reduction.leaf_claim);

        Transcript verifier("Laminate/gates/sparse/test/v1");
        const auto verified = gates::sparse::verify_sparse_evaluation(
            message_size, address_variables, point, claimed,
            output.proof, verifier);
        CHECK(verified.has_value());
        CHECK(*verified == output.reduction);
    });

    runner.run("non-power-of-two factor count pads with constant ones", [] {
        const std::vector<gates::sparse::SparseEntry> entries = {
            {1, Fp(13)}, {8, Fp(17)}, {15, Fp(19)}};
        constexpr std::size_t message_size = 4;
        constexpr std::size_t address_variables = 4;
        const std::vector<Fpk> point = query(address_variables, 211);
        const Fpk claimed = gates::sparse::evaluate_sparse_entries(
            entries, address_variables, point);

        Transcript prover("Laminate/gates/sparse/padding/v1");
        const auto output = gates::sparse::prove_sparse_evaluation(
            entries, message_size, address_variables, point, claimed,
            prover);
        CHECK(output.proof.layers.size() == 3);
        CHECK(output.reduction.factor_point_lsb.size() == 3);

        const gates::sparse::SparseLeafLinearization linearization =
            gates::sparse::linearize_sparse_leaf(
                address_variables, point,
                output.reduction.factor_point_lsb);
        Fpk opened = linearization.constant;
        for (std::size_t column = 0;
             column < linearization.column_weights.size(); ++column) {
            opened += linearization.column_weights[column] *
                      evaluate_committed_column(
                          entries, message_size, address_variables, column,
                          output.reduction.entry_point_lsb);
        }
        CHECK(opened == output.reduction.leaf_claim);

        Transcript verifier("Laminate/gates/sparse/padding/v1");
        CHECK(gates::sparse::verify_sparse_evaluation(
                  message_size, address_variables, point, claimed,
                  output.proof, verifier)
                  .has_value());
    });

    runner.run("checkpointed tree preserves a wider address relation", [] {
        const std::vector<gates::sparse::SparseEntry> entries = {
            {1, Fp(3)}, {257, Fp(5)}, {4099, Fp(7)},
            {32767, Fp(11)}, {65535, Fp(13)}};
        constexpr std::size_t message_size = 8;
        constexpr std::size_t address_variables = 16;
        const std::vector<Fpk> point = query(address_variables, 401);
        const Fpk claimed = gates::sparse::evaluate_sparse_entries(
            entries, address_variables, point);

        Transcript prover("Laminate/gates/sparse/checkpoint/v1");
        const auto output = gates::sparse::prove_sparse_evaluation(
            entries, message_size, address_variables, point, claimed,
            prover);
        CHECK(output.proof.layers.size() == 5);
        CHECK(output.reduction.factor_point_lsb.size() == 5);

        Transcript verifier("Laminate/gates/sparse/checkpoint/v1");
        const auto reduction = gates::sparse::verify_sparse_evaluation(
            message_size, address_variables, point, claimed,
            output.proof, verifier);
        CHECK(reduction.has_value());
        CHECK(*reduction == output.reduction);
    });

    runner.run("Gruen layer supports an equality coordinate equal to one", [] {
        const std::vector<gates::sparse::SparseEntry> entries = {
            {0, Fp(2)}, {1, Fp(3)}, {5, Fp(7)}, {7, Fp(11)}};
        constexpr std::size_t message_size = 4;
        constexpr std::size_t address_variables = 3;
        const std::vector<Fpk> point = query(address_variables, 503);
        const Fpk claimed = gates::sparse::evaluate_sparse_entries(
            entries, address_variables, point);

        TauOneCoin prover;
        const auto output = gates::sparse::prove_sparse_evaluation(
            entries, message_size, address_variables, point, claimed,
            prover);
        CHECK(!output.proof.layers.empty());
        CHECK(!output.proof.layers.front().rounds.empty());

        TauOneCoin verifier;
        const auto reduction = gates::sparse::verify_sparse_evaluation(
            message_size, address_variables, point, claimed,
            output.proof, verifier);
        CHECK(reduction.has_value());
        CHECK(*reduction == output.reduction);
    });

    runner.run("stripped terminal rejects at an equality-factor root", [] {
        const std::vector<gates::sparse::SparseEntry> entries = {
            {0, Fp(2)}, {1, Fp(3)}};
        constexpr std::size_t message_size = 2;
        constexpr std::size_t address_variables = 1;
        const std::vector<Fpk> point{Fpk::from_base(Fp(7))};
        const Fpk claimed = gates::sparse::evaluate_sparse_entries(
            entries, address_variables, point);

        EqualityRootCoin prover;
        const auto honest = gates::sparse::prove_sparse_evaluation(
            entries, message_size, address_variables, point, claimed,
            prover);
        CHECK(honest.proof.layers.size() == 1);

        gates::sparse::SparseProductProof tampered = honest.proof;
        tampered.layers.front().left_claim += Fpk::one();
        EqualityRootCoin verifier;
        CHECK(!gates::sparse::verify_sparse_evaluation(
                   message_size, address_variables, point, claimed,
                   tampered, verifier)
                   .has_value());
    });

    runner.run("tampered product-tree messages are rejected", [] {
        const std::vector<gates::sparse::SparseEntry> entries = {
            {0, Fp(2)}, {3, Fp(7)}, {6, Fp(23)}};
        constexpr std::size_t message_size = 4;
        constexpr std::size_t address_variables = 3;
        const std::vector<Fpk> point = query(address_variables, 307);
        const Fpk claimed = gates::sparse::evaluate_sparse_entries(
            entries, address_variables, point);
        Transcript prover("Laminate/gates/sparse/tamper/v1");
        const auto honest = gates::sparse::prove_sparse_evaluation(
            entries, message_size, address_variables, point, claimed,
            prover);

        gates::sparse::SparseProductProof bad_round = honest.proof;
        bad_round.layers.front().rounds.front()[1] += Fpk::one();
        Transcript round_verifier("Laminate/gates/sparse/tamper/v1");
        CHECK(!gates::sparse::verify_sparse_evaluation(
                   message_size, address_variables, point, claimed,
                   bad_round, round_verifier)
                   .has_value());

        gates::sparse::SparseProductProof bad_claim = honest.proof;
        bad_claim.layers.front().left_claim += Fpk::one();
        Transcript claim_verifier("Laminate/gates/sparse/tamper/v1");
        CHECK(!gates::sparse::verify_sparse_evaluation(
                   message_size, address_variables, point, claimed,
                   bad_claim, claim_verifier)
                   .has_value());

        gates::sparse::SparseProductProof bad_shape = honest.proof;
        bad_shape.root_rounds.pop_back();
        Transcript shape_verifier("Laminate/gates/sparse/tamper/v1");
        CHECK(!gates::sparse::verify_sparse_evaluation(
                   message_size, address_variables, point, claimed,
                   bad_shape, shape_verifier)
                   .has_value());
    });

    runner.run("one-entry constant-domain relation is supported", [] {
        const std::vector<gates::sparse::SparseEntry> entries = {
            {0, Fp(37)}};
        const std::vector<Fpk> point;
        const Fpk claimed = Fpk::from_base(Fp(37));
        Transcript prover("Laminate/gates/sparse/single/v1");
        const auto output = gates::sparse::prove_sparse_evaluation(
            entries, 1, 0, point, claimed, prover);
        CHECK(output.proof.root_rounds.empty());
        CHECK(output.proof.layers.empty());
        CHECK(output.reduction.entry_point_lsb.empty());
        CHECK(output.reduction.factor_point_lsb.empty());
        CHECK(output.reduction.leaf_claim == claimed);

        Transcript verifier("Laminate/gates/sparse/single/v1");
        CHECK(gates::sparse::verify_sparse_evaluation(
                  1, 0, point, claimed, output.proof, verifier)
                  .has_value());

        bool rejected = false;
        try {
            Transcript bad_prover("Laminate/gates/sparse/single/v1");
            (void)gates::sparse::prove_sparse_evaluation(
                entries, 1, 0, point, claimed + Fpk::one(), bad_prover);
        } catch (const std::invalid_argument &) {
            rejected = true;
        }
        CHECK(rejected);
    });

    return runner.summary();
}
