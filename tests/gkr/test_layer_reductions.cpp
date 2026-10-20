/// @file test_layer_reductions.cpp
/// @brief End-to-end plaintext reductions across alternating layers.

#include "test_helpers.hpp"

#include "laminate/gkr/layer_reductions.hpp"
#include "laminate/payload/compiler.hpp"

#include <bit>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <variant>
#include <vector>

using namespace laminate;
using namespace laminate::gkr;
using namespace laminate::payload;

namespace {

Fpk value(std::uint64_t seed) {
    Fpk::Coefficients coefficients{};
    for (std::size_t index = 0; index < coefficients.size(); ++index) {
        coefficients[index] = Fp(seed + 13 * index + 7 * index * index);
    }
    return Fpk(coefficients);
}

std::vector<Fpk> point(std::size_t size, std::uint64_t seed) {
    std::vector<Fpk> result;
    result.reserve(size);
    for (std::size_t index = 0; index < size; ++index) {
        result.push_back(value(seed + 37 * index));
    }
    return result;
}

std::size_t layer_vars(const LayeredCircuit &circuit,
                       std::size_t layer_index) {
    const std::size_t wires =
        layer_dimensions(circuit.layers[layer_index]).padded_size;
    const std::size_t width = circuit.shape.value_width();
    return (std::bit_width(wires) - 1U) +
           (std::bit_width(width) - 1U);
}

fhe::SlotVector sequence(std::size_t size, std::uint64_t seed) {
    fhe::SlotVector result;
    result.reserve(size);
    for (std::size_t index = 0; index < size; ++index) {
        result.push_back(Fp(seed + 3 * index + index * index));
    }
    return result;
}

PayloadCircuit wide_payload() {
    PayloadBuilder builder(PayloadShape::wide(8), 2);
    const std::size_t diagonal = builder.add_plaintext(
        {Fp(2), Fp(3), Fp(5), Fp(7), Fp(11), Fp(13), Fp(17), Fp(19)});
    const auto rotated = builder.rotate(0, 5);
    const auto ctct = builder.mul(rotated, 1);
    const auto plainct = builder.mul_plain(0, diagonal);
    const auto mixed = builder.add(ctct, plainct);
    const auto output = builder.mul(mixed, ctct);
    builder.set_outputs({output});
    return builder.finish();
}

PayloadCircuit laned_payload(std::size_t lanes) {
    PayloadBuilder builder(PayloadShape::laned(lanes, 8), 2);
    const auto first = builder.mul(0, 1);
    const auto mixed = builder.add(first, 0);
    const auto output = builder.mul(mixed, first);
    builder.set_outputs({output});
    return builder.finish();
}

struct Fixture {
    PayloadCircuit payload;
    LayeredCircuit circuit;
    PlainTrace trace;
    PublicSetup setup;
};

Fixture make_fixture(PayloadCircuit payload) {
    const std::size_t width = payload.shape.value_width();
    LayeredCircuit circuit = compile(payload);
    PlainTrace trace = synthesize_trace(
        payload, circuit,
        std::vector<fhe::SlotVector>{sequence(width, 3),
                                     sequence(width, 17)});
    PublicSetup setup = make_direct_setup(payload, circuit);
    return Fixture{std::move(payload), std::move(circuit), std::move(trace),
                   std::move(setup)};
}

void run_full_reduction(const Fixture &fixture, std::uint64_t seed) {
    const gates::DirectGateMle provider(fixture.circuit);
    const SingleClaim initial = make_layer_claim(
        fixture.trace.layers.front(),
        point(layer_vars(fixture.circuit, 0), seed));
    LayerClaim prover_claim = initial;
    LayerClaim verifier_claim = initial;
    Transcript prover_transcript("test/gkr/full-reduction");
    Transcript verifier_transcript("test/gkr/full-reduction");
    gates::observe_gate_mle_setup(fixture.setup, prover_transcript);
    gates::observe_gate_mle_setup(fixture.setup, verifier_transcript);
    observe_claim(initial, prover_transcript);
    observe_claim(initial, verifier_transcript);

    for (std::size_t layer_index = 0;
         layer_index + 1 < fixture.circuit.layers.size(); ++layer_index) {
        if (layer_kind(fixture.circuit.layers[layer_index]) ==
            LayerKind::Affine) {
            const auto proved = prove_affine_layer_reduction(
                fixture.circuit, fixture.trace, layer_index, prover_claim,
                provider, prover_transcript);
            const auto verified = verify_affine_layer_reduction(
                fixture.circuit, layer_index, verifier_claim, proved.proof,
                provider, verifier_transcript);
            CHECK(verified.has_value());
            CHECK(*verified == proved.next_claim);
            prover_claim = proved.next_claim;
            verifier_claim = *verified;
        } else {
            CHECK(std::holds_alternative<SingleClaim>(prover_claim));
            CHECK(std::holds_alternative<SingleClaim>(verifier_claim));
            const auto proved = prove_multiplication_layer_reduction(
                fixture.circuit, fixture.trace, layer_index,
                std::get<SingleClaim>(prover_claim), prover_transcript);
            const auto verified = verify_multiplication_layer_reduction(
                fixture.circuit, layer_index,
                std::get<SingleClaim>(verifier_claim), proved.proof,
                verifier_transcript);
            CHECK(verified.has_value());
            CHECK(*verified == proved.next_claim);
            CHECK(*verified == make_layer_claim(
                fixture.trace.layers[layer_index + 1U], verified->point));
            prover_claim = proved.next_claim;
            verifier_claim = *verified;
        }
        CHECK(std::holds_alternative<SingleClaim>(prover_claim));
        CHECK(std::holds_alternative<SingleClaim>(verifier_claim));
    }
    CHECK(prover_claim == verifier_claim);
    CHECK(verify_terminal_claim(fixture.trace.layers.back(), verifier_claim));
}

} // namespace

int main() {
    test::Runner runner("test_layer_reductions");

    runner.run("wide mixed CT-CT/PT-CT circuit reduces to its inputs", [] {
        run_full_reduction(make_fixture(wide_payload()), 11);
    });

    runner.run("laned B=1 and partial-lane circuits share the oracle", [] {
        run_full_reduction(make_fixture(laned_payload(1)), 43);
        run_full_reduction(make_fixture(laned_payload(4)), 59);
        run_full_reduction(make_fixture(laned_payload(8)), 71);
    });

    runner.run("altered affine terminal value rejects", [] {
        const Fixture fixture = make_fixture(wide_payload());
        const gates::DirectGateMle provider(fixture.circuit);
        const SingleClaim initial = make_layer_claim(
            fixture.trace.layers.front(),
            point(layer_vars(fixture.circuit, 0), 83));
        Transcript prover_transcript("test/gkr/affine-mutation");
        gates::observe_gate_mle_setup(fixture.setup, prover_transcript);
        observe_claim(initial, prover_transcript);
        const auto proved = prove_affine_layer_reduction(
            fixture.circuit, fixture.trace, 0, LayerClaim{initial}, provider,
            prover_transcript);
        AffineLayerReductionProof altered = proved.proof;
        altered.source_value += Fpk::one();

        Transcript verifier_transcript("test/gkr/affine-mutation");
        gates::observe_gate_mle_setup(fixture.setup, verifier_transcript);
        observe_claim(initial, verifier_transcript);
        CHECK(!verify_affine_layer_reduction(
                   fixture.circuit, 0, LayerClaim{initial}, altered, provider,
                   verifier_transcript)
                   .has_value());
    });

    runner.run("altered multiplication operand value rejects", [] {
        const Fixture fixture = make_fixture(wide_payload());
        const std::size_t layer_index = 1;
        const SingleClaim current = make_layer_claim(
            fixture.trace.layers[layer_index],
            point(layer_vars(fixture.circuit, layer_index), 101));
        Transcript prover_transcript("test/gkr/multiplication-mutation");
        observe_claim(current, prover_transcript);
        const auto proved = prove_multiplication_layer_reduction(
            fixture.circuit, fixture.trace, layer_index, current,
            prover_transcript);
        MultiplicationLayerReductionProof altered = proved.proof;
        altered.left_value += Fpk::one();

        Transcript verifier_transcript("test/gkr/multiplication-mutation");
        observe_claim(current, verifier_transcript);
        CHECK(!verify_multiplication_layer_reduction(
                   fixture.circuit, layer_index, current, altered,
                   verifier_transcript)
                   .has_value());
    });

    runner.run("prover rejects a source trace inconsistent with its claim", [] {
        Fixture fixture = make_fixture(wide_payload());
        const gates::DirectGateMle provider(fixture.circuit);
        const SingleClaim initial = make_layer_claim(
            fixture.trace.layers.front(),
            point(layer_vars(fixture.circuit, 0), 127));
        fixture.trace.layers[1][0][0] += Fp::one();
        bool threw = false;
        try {
            Transcript transcript("test/gkr/bad-trace");
            (void)prove_affine_layer_reduction(
                fixture.circuit, fixture.trace, 0, LayerClaim{initial},
                provider, transcript);
        } catch (const std::invalid_argument &) {
            threw = true;
        }
        CHECK(threw);
    });

    return runner.summary();
}
