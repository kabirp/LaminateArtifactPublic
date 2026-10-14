/// @file test_sumcheck.cpp
/// @brief Differential tests for the plaintext sumcheck oracle.

#include "test_helpers.hpp"

#include "laminate/gkr/detail/shared/reduction/sumcheck.hpp"
#include "laminate/gkr/layer_reduction_sumcheck.hpp"
#include "laminate/poly/eq.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <vector>

using namespace laminate;
using namespace laminate::gkr;
using namespace laminate::poly;

namespace {

Fpk value(std::uint64_t seed) {
    Fpk::Coefficients coefficients{};
    for (std::size_t index = 0; index < coefficients.size(); ++index) {
        coefficients[index] = Fp(seed + index * 19 + index * index * 3);
    }
    return Fpk(coefficients);
}

Multilinear<Fpk> polynomial(std::size_t num_vars, std::uint64_t seed) {
    std::vector<Fpk> evaluations;
    evaluations.reserve(hypercube_size(num_vars));
    for (std::size_t index = 0; index < hypercube_size(num_vars); ++index) {
        evaluations.push_back(value(seed + index * 23));
    }
    return Multilinear<Fpk>(num_vars, std::move(evaluations));
}

std::vector<Fpk> point(std::size_t num_vars, std::uint64_t seed) {
    std::vector<Fpk> result;
    result.reserve(num_vars);
    for (std::size_t index = 0; index < num_vars; ++index) {
        result.push_back(value(seed + index * 31));
    }
    return result;
}

Fpk sum_products(const Multilinear<Fpk> &left,
                 const Multilinear<Fpk> &right) {
    Fpk result = Fpk::zero();
    for (std::size_t index = 0; index < left.evaluations().size(); ++index) {
        result += left.on_hypercube(index) * right.on_hypercube(index);
    }
    return result;
}

Fpk sum_relation(
    std::size_t num_vars,
    const MultiplicationLayerReductionSumcheck::Oracle &relation) {
    Fpk result = Fpk::zero();
    for (std::size_t vertex = 0; vertex < hypercube_size(num_vars); ++vertex) {
        std::vector<Fpk> evaluation_point(num_vars, Fpk::zero());
        for (std::size_t variable = 0; variable < num_vars; ++variable) {
            const bool bit =
                ((vertex >> (num_vars - 1 - variable)) & 1U) != 0;
            evaluation_point[variable] = bit ? Fpk::one() : Fpk::zero();
        }
        result += relation(evaluation_point);
    }
    return result;
}

/// Independent fold-per-round reference. It is intentionally test-only: this
/// is the depth-growing schedule encrypted proving must never use.
std::vector<LayerReductionSumcheckRound>
naive_affine_rounds(Multilinear<Fpk> gate_weights,
                    Multilinear<Fpk> source_values,
                    const std::vector<Fpk> &challenges) {
    std::vector<LayerReductionSumcheckRound> rounds;
    rounds.reserve(challenges.size());
    for (std::size_t round_index = 0; round_index < challenges.size();
         ++round_index) {
        const std::size_t half = gate_weights.evaluations().size() / 2;
        Fpk at_one = Fpk::zero();
        Fpk at_two = Fpk::zero();
        for (std::size_t suffix = 0; suffix < half; ++suffix) {
            const Fpk weight_two =
                gate_weights.on_hypercube(half + suffix) *
                    Fpk::from_base(Fp(2)) -
                gate_weights.on_hypercube(suffix);
            const Fpk source_two =
                source_values.on_hypercube(half + suffix) *
                    Fpk::from_base(Fp(2)) -
                source_values.on_hypercube(suffix);
            at_one += gate_weights.on_hypercube(half + suffix) *
                      source_values.on_hypercube(half + suffix);
            at_two += weight_two * source_two;
        }
        rounds.push_back(LayerReductionSumcheckRound{at_one, at_two});
        gate_weights =
            gate_weights.fix_first_variable(challenges[round_index]);
        source_values =
            source_values.fix_first_variable(challenges[round_index]);
    }
    return rounds;
}

} // namespace

int main() {
    test::Runner runner("test_sumcheck");

    runner.run("degree-two round interpolation matches its polynomial", [] {
        // p(x) = a*x^2 + b*x + c is the independent oracle for the three
        // evaluations transmitted by one Laminate layer-reduction round.
        const Fpk a = value(5);
        const Fpk b = value(7);
        const Fpk c = value(11);
        const auto polynomial = [&](const Fpk &x) {
            return a * x * x + b * x + c;
        };
        const Fpk zero = Fpk::zero();
        const Fpk one = Fpk::one();
        const Fpk two = Fpk::from_base(Fp(2));
        const Fpk challenge = value(13);
        const ::laminate::gkr::detail::LayerReductionRoundEvaluations round{
            polynomial(zero), polynomial(one), polynomial(two)};

        CHECK(round.interpolate_at(challenge) == polynomial(challenge));

        // Affine reductions transmit R(1), R(2); the verifier recovers R(0)
        // from the sumcheck invariant R(0) + R(1) = the running claim.
        const Fpk running_claim = round.at_zero + round.at_one;
        const ::laminate::gkr::detail::LayerReductionRoundEvaluations
            recovered{running_claim - round.at_one, round.at_one,
                      round.at_two};
        CHECK(recovered.at_zero == round.at_zero);
        CHECK(recovered.at_one == round.at_one);
        CHECK(recovered.at_two == round.at_two);
    });

    runner.run("affine layer reduction reaches its source oracle", [] {
        const auto gate_weights = polynomial(4, 5);
        const auto source_values = polynomial(4, 17);
        const Fpk claimed = sum_products(gate_weights, source_values);

        Transcript prover_transcript("test/sumcheck/regular");
        const auto output = AffineLayerReductionSumcheck::prove(
            gate_weights, source_values, prover_transcript);
        Transcript verifier_transcript("test/sumcheck/regular");
        const auto verification = AffineLayerReductionSumcheck::verify(
            output.proof, claimed, 4, verifier_transcript);

        CHECK(verification.structurally_valid);
        CHECK(verification.challenges == output.challenges);
        CHECK(verification.accepts(
            gate_weights.evaluate(output.challenges) *
            source_values.evaluate(output.challenges)));
    });

    runner.run("affine rounds match an independent folded oracle", [] {
        const auto gate_weights = polynomial(5, 29);
        const auto source_values = polynomial(5, 43);
        Transcript transcript("test/sumcheck/differential");
        const auto output = AffineLayerReductionSumcheck::prove(
            gate_weights, source_values, transcript);
        CHECK(output.proof.rounds ==
              naive_affine_rounds(gate_weights, source_values,
                                  output.challenges));
    });

    runner.run("affine verification rejects false terminal claims", [] {
        const auto gate_weights = polynomial(3, 61);
        const auto source_values = polynomial(3, 73);
        const Fpk claimed = sum_products(gate_weights, source_values);
        Transcript prover_transcript("test/sumcheck/adversarial");
        const auto output = AffineLayerReductionSumcheck::prove(
            gate_weights, source_values, prover_transcript);

        Transcript wrong_claim_transcript("test/sumcheck/adversarial");
        const auto wrong_claim = AffineLayerReductionSumcheck::verify(
            output.proof, claimed + Fpk::one(), 3,
            wrong_claim_transcript);
        CHECK(wrong_claim.structurally_valid);
        CHECK(!wrong_claim.accepts(
            gate_weights.evaluate(wrong_claim.challenges) *
            source_values.evaluate(wrong_claim.challenges)));

        LayerReductionSumcheckProof altered = output.proof;
        altered.rounds[1].at_two += Fpk::one();
        Transcript altered_transcript("test/sumcheck/adversarial");
        const auto altered_verification =
            AffineLayerReductionSumcheck::verify(
                altered, claimed, 3, altered_transcript);
        CHECK(altered_verification.structurally_valid);
        CHECK(!altered_verification.accepts(
            gate_weights.evaluate(altered_verification.challenges) *
            source_values.evaluate(altered_verification.challenges)));
    });

    runner.run("multiplication layer reduction strips slot equality", [] {
        constexpr std::size_t wire_vars = 2;
        constexpr std::size_t slot_vars = 2;
        const auto left = polynomial(wire_vars + slot_vars, 139);
        const auto right = polynomial(wire_vars + slot_vars, 149);
        const auto slot_eq_point = point(slot_vars, 157);
        const MultiplicationLayerReductionSumcheck::Oracle stripped =
            [&](std::span<const Fpk> evaluation_point) {
                const std::vector<Fpk> owned(evaluation_point.begin(),
                                             evaluation_point.end());
                return left.evaluate(owned) * right.evaluate(owned);
            };
        const MultiplicationLayerReductionSumcheck::Oracle full =
            [&](std::span<const Fpk> evaluation_point) {
                const std::vector<Fpk> owned(evaluation_point.begin(),
                                             evaluation_point.end());
                const std::vector<Fpk> slot(
                    owned.end() - static_cast<std::ptrdiff_t>(slot_vars),
                    owned.end());
                return eq_eval(slot_eq_point, slot) * stripped(owned);
            };
        const Fpk claimed = sum_relation(wire_vars + slot_vars, full);

        Transcript prover_transcript("test/sumcheck/mixed");
        const auto output = MultiplicationLayerReductionSumcheck::prove(
            wire_vars, slot_eq_point, full, stripped, prover_transcript);
        Transcript verifier_transcript("test/sumcheck/mixed");
        const auto verification = MultiplicationLayerReductionSumcheck::verify(
            output.proof, claimed, wire_vars, slot_eq_point,
            verifier_transcript);

        CHECK(verification.structurally_valid);
        CHECK(verification.challenges == output.challenges);
        CHECK(verification.accepts(stripped(output.challenges)));
    });

    runner.run("multiplication reduction handles a unit equality coordinate", [] {
        const auto left = polynomial(2, 227);
        const auto right = polynomial(2, 239);
        const std::vector<Fpk> equality_point{Fpk::one(), value(241)};
        const MultiplicationLayerReductionSumcheck::Oracle stripped =
            [&](std::span<const Fpk> evaluation_point) {
                const std::vector<Fpk> owned(evaluation_point.begin(),
                                             evaluation_point.end());
                return left.evaluate(owned) * right.evaluate(owned);
            };
        const MultiplicationLayerReductionSumcheck::Oracle full =
            [&](std::span<const Fpk> evaluation_point) {
                const std::vector<Fpk> owned(evaluation_point.begin(),
                                             evaluation_point.end());
                return eq_eval(equality_point, owned) * stripped(owned);
            };
        const Fpk claimed = sum_relation(2, full);

        Transcript prover_transcript("test/sumcheck/mixed-unit");
        const auto output = MultiplicationLayerReductionSumcheck::prove(
            0, equality_point, full, stripped, prover_transcript);
        Transcript verifier_transcript("test/sumcheck/mixed-unit");
        const auto verification = MultiplicationLayerReductionSumcheck::verify(
            output.proof, claimed, 0, equality_point, verifier_transcript);

        CHECK(verification.structurally_valid);
        CHECK(verification.challenges == output.challenges);
        CHECK(verification.accepts(stripped(output.challenges)));
    });

    runner.run("zero equality does not erase multiplication terminal claims", [] {
        const auto left = polynomial(1, 251);
        const auto right = polynomial(1, 263);
        const MultiplicationLayerReductionSumcheck::Oracle stripped =
            [&](std::span<const Fpk> p) {
                const std::vector<Fpk> owned(p.begin(), p.end());
                return left.evaluate(owned) * right.evaluate(owned);
            };
        std::vector<Fpk> output_point{Fpk::one()};
        const MultiplicationLayerReductionSumcheck::Oracle full =
            [&](std::span<const Fpk> p) {
                const std::vector<Fpk> owned(p.begin(), p.end());
                return eq_eval(output_point, owned) * stripped(p);
            };
        // For this one-round helper, h(0),h(2) and therefore r are independent
        // of any nonzero output coordinate. Choose that coordinate to force
        // eq(gamma,r)=0; this tests the rare boundary without brute forcing FS.
        Transcript preview("test/sumcheck/zero-equality");
        const auto first = MultiplicationLayerReductionSumcheck::prove(
            0, output_point, full, stripped, preview);
        const Fpk r = first.challenges.front();
        const Fpk denominator = Fpk::from_base(Fp(2)) * r - Fpk::one();
        CHECK(!denominator.is_zero());
        output_point.front() = (r - Fpk::one()) * denominator.inverse();
        CHECK(!output_point.front().is_zero());
        CHECK(eq_eval(output_point, first.challenges).is_zero());
        Transcript prover("test/sumcheck/zero-equality");
        const auto proved = MultiplicationLayerReductionSumcheck::prove(
            0, output_point, full, stripped, prover);
        CHECK(proved.proof == first.proof);
        CHECK(proved.challenges == first.challenges);
        Transcript verifier("test/sumcheck/zero-equality");
        const auto checked = MultiplicationLayerReductionSumcheck::verify(
            proved.proof, sum_relation(1, full), 0, output_point, verifier);
        CHECK(checked.accepts(stripped(checked.challenges)));
        CHECK(!checked.accepts(stripped(checked.challenges) + Fpk::one()));
        CHECK(!checked.accepts(Fpk::zero()));
    });

    runner.run("zero-round multiplication checks its terminal product", [] {
        const Fpk product = value(271) * value(277);
        const MultiplicationLayerReductionSumcheck::Oracle oracle =
            [&](std::span<const Fpk> p) {
                CHECK(p.empty());
                return product;
            };
        Transcript prover("test/sumcheck/constant-multiplication");
        const auto proved = MultiplicationLayerReductionSumcheck::prove(
            0, {}, oracle, oracle, prover);
        CHECK(proved.proof.rounds.empty());
        Transcript verifier("test/sumcheck/constant-multiplication");
        const auto checked = MultiplicationLayerReductionSumcheck::verify(
            proved.proof, product, 0, {}, verifier);
        CHECK(checked.challenges.empty());
        CHECK(checked.accepts(product));
        CHECK(!checked.accepts(product + Fpk::one()));
    });

    runner.run("constant affine reductions need no round messages", [] {
        const Multilinear<Fpk> gate_weights(0, {value(151)});
        const Multilinear<Fpk> source_values(0, {value(163)});
        Transcript prover_transcript("test/sumcheck/constant");
        const auto output = AffineLayerReductionSumcheck::prove(
            gate_weights, source_values, prover_transcript);
        CHECK(output.proof.rounds.empty());
        CHECK(output.challenges.empty());

        Transcript verifier_transcript("test/sumcheck/constant");
        const auto verification = AffineLayerReductionSumcheck::verify(
            output.proof, sum_products(gate_weights, source_values), 0,
            verifier_transcript);
        CHECK(verification.accepts(gate_weights.on_hypercube(0) *
                                   source_values.on_hypercube(0)));
    });

    runner.run("malformed affine dimensions and round counts reject", [] {
        const auto gate_weights = polynomial(2, 179);
        const auto source_values = polynomial(2, 191);
        Transcript prover_transcript("test/sumcheck/errors");
        const auto output = AffineLayerReductionSumcheck::prove(
            gate_weights, source_values, prover_transcript);

        Transcript count_transcript("test/sumcheck/errors");
        const auto wrong_count = AffineLayerReductionSumcheck::verify(
            output.proof, sum_products(gate_weights, source_values), 3,
            count_transcript);
        CHECK(!wrong_count.structurally_valid);

        bool dimensions_threw = false;
        try {
            Transcript mismatch_transcript("test/sumcheck/mismatch");
            (void)AffineLayerReductionSumcheck::prove(
                gate_weights, polynomial(3, 223), mismatch_transcript);
        } catch (const std::invalid_argument &) {
            dimensions_threw = true;
        }
        CHECK(dimensions_threw);
    });

    return runner.summary();
}
