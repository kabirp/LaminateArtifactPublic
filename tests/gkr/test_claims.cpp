/// @file test_claims.cpp
/// @brief Standard GKR claim-batching and terminal-check tests.

#include "test_helpers.hpp"

#include "laminate/gkr/claims.hpp"
#include "laminate/poly/multilinear.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <vector>

using namespace laminate;
using namespace laminate::gkr;

namespace {

Fpk value(std::uint64_t seed) {
    Fpk::Coefficients coefficients{};
    for (std::size_t index = 0; index < coefficients.size(); ++index) {
        coefficients[index] = Fp(seed + 7 * index + 5 * index * index);
    }
    return Fpk(coefficients);
}

std::vector<Fpk> point(std::size_t size, std::uint64_t seed) {
    std::vector<Fpk> result;
    result.reserve(size);
    for (std::size_t index = 0; index < size; ++index) {
        result.push_back(value(seed + 13 * index));
    }
    return result;
}

std::vector<fhe::SlotVector> layer(std::size_t wires, std::size_t slots) {
    std::vector<fhe::SlotVector> result(
        wires, fhe::SlotVector(slots, Fp::zero()));
    for (std::size_t wire = 0; wire < wires; ++wire) {
        for (std::size_t slot = 0; slot < slots; ++slot) {
            result[wire][slot] = Fp(3 + 17 * wire + slot * slot + 5 * slot);
        }
    }
    return result;
}

} // namespace

int main() {
    test::Runner runner("test_claims");

    runner.run("layer evaluation matches a flattened dense MLE", [] {
        const auto values = layer(4, 8);
        std::vector<Fp> flattened;
        for (const auto &wire : values) {
            flattened.insert(flattened.end(), wire.begin(), wire.end());
        }
        const poly::Multilinear<Fp> dense(5, std::move(flattened));
        const auto evaluation_point = point(5, 11);
        CHECK(evaluate_layer_mle(values, evaluation_point) ==
              dense.evaluate(evaluation_point));
    });

    runner.run("compact input evaluation accounts for implicit zero padding",
               [] {
                   const fhe::SlotVector logical_input{
                       Fp(3), Fp(5), Fp(8), Fp(13),
                       Fp(21), Fp(34), Fp(55), Fp(89)};
                   fhe::SlotVector padded_input(32, Fp::zero());
                   std::copy(logical_input.begin(), logical_input.end(),
                             padded_input.begin());
                   const std::vector<fhe::SlotVector> explicit_layer{
                       padded_input};
                   const std::vector<Fpk> evaluation_point = point(5, 23);

                   CHECK(evaluate_prefix_input_mle(logical_input,
                                                   evaluation_point) ==
                         evaluate_layer_mle(explicit_layer,
                                            evaluation_point));
               });

    runner.run("two claims batch identically under transcript replay", [] {
        const auto values = layer(4, 8);
        const SingleClaim first = make_layer_claim(values, point(5, 29));
        const SingleClaim second = make_layer_claim(values, point(5, 47));

        Transcript prover_transcript("test/gkr/claims");
        const BatchedClaim prover =
            batch_claims(first, second, prover_transcript);
        Transcript verifier_transcript("test/gkr/claims");
        const BatchedClaim verifier =
            batch_claims(first, second, verifier_transcript);
        CHECK(prover == verifier);
        CHECK(prover.value ==
              first.value + prover.challenge * second.value);
        CHECK(verify_terminal_claim(values, prover));

        const LayerClaim tagged = prover;
        CHECK(verify_terminal_claim(values, tagged));
    });

    runner.run("claim order is transcript-bound", [] {
        const auto values = layer(2, 4);
        const SingleClaim first = make_layer_claim(values, point(3, 61));
        const SingleClaim second = make_layer_claim(values, point(3, 79));
        Transcript forward_transcript("test/gkr/order");
        Transcript reverse_transcript("test/gkr/order");
        const auto forward =
            batch_claims(first, second, forward_transcript);
        const auto reverse =
            batch_claims(second, first, reverse_transcript);
        CHECK(forward.challenge != reverse.challenge);
    });

    runner.run("terminal checks reject altered claim state", [] {
        const auto values = layer(4, 4);
        SingleClaim first = make_layer_claim(values, point(4, 97));
        const SingleClaim second = make_layer_claim(values, point(4, 109));
        CHECK(verify_terminal_claim(values, first));
        first.value += Fpk::one();
        CHECK(!verify_terminal_claim(values, first));
        first.value -= Fpk::one();

        Transcript transcript("test/gkr/mutations");
        const BatchedClaim original = batch_claims(first, second, transcript);
        BatchedClaim altered_value = original;
        altered_value.value += Fpk::one();
        CHECK(!verify_terminal_claim(values, altered_value));
        BatchedClaim altered_point = original;
        altered_point.second.point[0] += Fpk::one();
        CHECK(!verify_terminal_claim(values, altered_point));
        BatchedClaim altered_component = original;
        altered_component.first.value += Fpk::one();
        CHECK(!verify_terminal_claim(values, altered_component));
    });

    runner.run("invalid table and point dimensions are rejected", [] {
        bool wire_count_threw = false;
        try {
            (void)evaluate_layer_mle(layer(3, 4), point(4, 127));
        } catch (const std::invalid_argument &) {
            wire_count_threw = true;
        }
        CHECK(wire_count_threw);

        bool point_threw = false;
        try {
            (void)evaluate_layer_mle(layer(4, 4), point(3, 139));
        } catch (const std::invalid_argument &) {
            point_threw = true;
        }
        CHECK(point_threw);

        bool batch_threw = false;
        try {
            Transcript transcript("test/gkr/bad-batch");
            (void)batch_claims(SingleClaim{point(2, 151), value(3)},
                               SingleClaim{point(3, 163), value(5)},
                               transcript);
        } catch (const std::invalid_argument &) {
            batch_threw = true;
        }
        CHECK(batch_threw);
    });

    return runner.summary();
}
