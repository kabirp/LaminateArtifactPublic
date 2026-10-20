/// @file test_proof.cpp
/// @brief Profile-tagged logical proof encoding and replay tests.

#include "test_helpers.hpp"

#include "laminate/gkr/proof.hpp"
#include "laminate/payload/compiler.hpp"

#include <bit>
#include <cstddef>
#include <cstdint>
#include <vector>

using namespace laminate;
using namespace laminate::gkr;
using namespace laminate::payload;

namespace {

Fpk value(std::uint64_t seed) {
    Fpk::Coefficients coefficients{};
    for (std::size_t index = 0; index < coefficients.size(); ++index) {
        coefficients[index] = Fp(seed + 23 * index + index * index);
    }
    return Fpk(coefficients);
}

std::vector<Fpk> point(std::size_t size, std::uint64_t seed) {
    std::vector<Fpk> result;
    result.reserve(size);
    for (std::size_t index = 0; index < size; ++index) {
        result.push_back(value(seed + 31 * index));
    }
    return result;
}

fhe::SlotVector sequence(std::size_t size, std::uint64_t seed) {
    fhe::SlotVector result;
    result.reserve(size);
    for (std::size_t index = 0; index < size; ++index) {
        result.push_back(Fp(seed + 5 * index + index * index));
    }
    return result;
}

PayloadCircuit wide_payload() {
    PayloadBuilder builder(PayloadShape::wide(4), 2);
    const std::size_t diagonal =
        builder.add_plaintext({Fp(2), Fp(3), Fp(5), Fp(7)});
    const auto product = builder.mul(builder.rotate(0, 3), 1);
    const auto scaled = builder.mul_plain(0, diagonal);
    builder.set_outputs({builder.add(product, scaled)});
    return builder.finish();
}

PayloadCircuit laned_payload() {
    PayloadBuilder builder(PayloadShape::laned(4, 8), 2);
    const auto product = builder.mul(0, 1);
    builder.set_outputs({builder.add(product, 0)});
    return builder.finish();
}

struct Fixture {
    PayloadCircuit payload;
    LayeredCircuit circuit;
    PlainTrace trace;
};

Fixture fixture(PayloadCircuit payload) {
    LayeredCircuit circuit = compile(payload);
    const std::size_t width = payload.shape.value_width();
    PlainTrace trace = synthesize_trace(
        payload, circuit,
        std::vector<fhe::SlotVector>{sequence(width, 3),
                                     sequence(width, 19)});
    return Fixture{std::move(payload), std::move(circuit), std::move(trace)};
}

std::size_t output_vars(const Fixture &fixture) {
    const std::size_t wires =
        layer_dimensions(fixture.circuit.layers.front()).padded_size;
    const std::size_t width = fixture.circuit.shape.value_width();
    return (std::bit_width(wires) - 1U) +
           (std::bit_width(width) - 1U);
}

struct ProvedFixture {
    Fixture fixture;
    PublicSetup setup;
    ProtocolProfile profile;
    Digest trace_id{};
    SingleClaim output_claim;
    DecryptedGkrProof proof;
};

ProvedFixture prove_fixture(Fixture fixture, PublicSetup setup,
                            ProtocolProfile profile, std::uint64_t seed) {
    const auto output_point = point(output_vars(fixture), seed);
    const SingleClaim output_claim =
        make_layer_claim(fixture.trace.layers.front(), output_point);
    const Digest trace_id =
        digest(fixture.trace, setup.circuit_digest);
    Transcript transcript("test/logical-proof");
    DecryptedGkrProof proof = prove_plaintext_gkr(
        fixture.payload, fixture.circuit, fixture.trace, setup, profile,
        output_point, transcript);
    return ProvedFixture{std::move(fixture), std::move(setup), profile,
                         trace_id, output_claim, std::move(proof)};
}

bool verify(const ProvedFixture &proved, const DecryptedGkrProof &proof) {
    Transcript transcript("test/logical-proof");
    return verify_plaintext_gkr(
        proved.fixture.payload, proved.fixture.circuit,
        proved.fixture.trace.layers.back(), proved.setup, proved.profile,
        proved.fixture.trace.provenance, proved.trace_id, proved.output_claim,
        proof, transcript);
}

} // namespace

int main() {
    test::Runner runner("test_proof");

    runner.run("Base, Folded, and Laned logical profiles replay", [] {
        Fixture base_fixture = fixture(wide_payload());
        const PublicSetup base_setup =
            make_direct_setup(base_fixture.payload, base_fixture.circuit);
        const ProvedFixture base = prove_fixture(
            std::move(base_fixture), base_setup,
            ProtocolProfile{ProtocolVariant::LaminateBase,
                            GateMleProfile::Direct,
                            CrossRoundPacking::None},
            11);
        CHECK(verify(base, base.proof));

        Fixture folded_fixture = fixture(wide_payload());
        const PublicSetup folded_setup = make_dummy_committed_setup(
            folded_fixture.payload, folded_fixture.circuit);
        const ProvedFixture folded = prove_fixture(
            std::move(folded_fixture), folded_setup,
            ProtocolProfile{ProtocolVariant::LaminateFolded,
                            GateMleProfile::DummyCommittedDirect,
                            CrossRoundPacking::None},
            29);
        CHECK(verify(folded, folded.proof));

        Fixture lane_fixture = fixture(laned_payload());
        const PublicSetup lane_setup =
            make_direct_setup(lane_fixture.payload, lane_fixture.circuit);
        const ProvedFixture laned = prove_fixture(
            std::move(lane_fixture), lane_setup,
            ProtocolProfile{ProtocolVariant::LaminateLaned,
                            GateMleProfile::Direct,
                            CrossRoundPacking::None},
            47);
        CHECK(verify(laned, laned.proof));
    });

    runner.run("canonical proof and identity encodings are deterministic", [] {
        Fixture first_fixture = fixture(wide_payload());
        const PublicSetup setup =
            make_direct_setup(first_fixture.payload, first_fixture.circuit);
        const ProtocolProfile profile{ProtocolVariant::LaminateBase,
                                      GateMleProfile::Direct,
                                      CrossRoundPacking::None};
        const ProvedFixture first = prove_fixture(
            std::move(first_fixture), setup, profile, 61);
        const ProvedFixture second =
            prove_fixture(fixture(wide_payload()), setup, profile, 61);
        CHECK(first.proof == second.proof);
        CHECK(encode_canonical(first.proof) ==
              encode_canonical(second.proof));
        CHECK(setup_digest(first.setup) == setup_digest(second.setup));
        CHECK(first.trace_id == second.trace_id);

        PlainTrace changed = first.fixture.trace;
        changed.layers.back()[0][0] += Fp::one();
        CHECK(digest(changed, first.setup.circuit_digest) != first.trace_id);
    });

    runner.run("header profile and ID mutations reject before replay", [] {
        Fixture source = fixture(wide_payload());
        const PublicSetup setup =
            make_direct_setup(source.payload, source.circuit);
        const ProvedFixture proved = prove_fixture(
            std::move(source), setup,
            ProtocolProfile{ProtocolVariant::LaminateBase,
                            GateMleProfile::Direct,
                            CrossRoundPacking::None},
            79);

        DecryptedGkrProof changed = proved.proof;
        changed.header.trace_id[0] ^= 1U;
        CHECK(!verify(proved, changed));
        changed = proved.proof;
        changed.header.setup_id[0] ^= 1U;
        CHECK(!verify(proved, changed));
        changed = proved.proof;
        changed.header.circuit_id[0] ^= 1U;
        CHECK(!verify(proved, changed));
        changed = proved.proof;
        changed.header.version += 1;
        CHECK(!verify(proved, changed));
        changed = proved.proof;
        changed.header.profile.variant = ProtocolVariant::LaminateFolded;
        CHECK(!verify(proved, changed));
        changed = proved.proof;
        changed.header.provenance = TraceProvenance::FheEvaluated;
        CHECK(!verify(proved, changed));
    });

    runner.run("round counts, dimensions, and terminal values reject", [] {
        Fixture source = fixture(wide_payload());
        const PublicSetup setup =
            make_direct_setup(source.payload, source.circuit);
        const ProvedFixture proved = prove_fixture(
            std::move(source), setup,
            ProtocolProfile{ProtocolVariant::LaminateFolded,
                            GateMleProfile::Direct,
                            CrossRoundPacking::None},
            97);

        DecryptedGkrProof changed = proved.proof;
        changed.output_claim.point.pop_back();
        CHECK(!verify(proved, changed));
        changed = proved.proof;
        changed.reductions.pop_back();
        CHECK(!verify(proved, changed));
        changed = proved.proof;
        std::get<AffineLayerReductionProof>(changed.reductions.front())
            .sumcheck.rounds.pop_back();
        CHECK(!verify(proved, changed));
        changed = proved.proof;
        std::get<AffineLayerReductionProof>(changed.reductions.front())
            .source_value += Fpk::one();
        CHECK(!verify(proved, changed));

        SingleClaim wrong_output = proved.output_claim;
        wrong_output.value += Fpk::one();
        Transcript transcript("test/logical-proof");
        CHECK(!verify_plaintext_gkr(
            proved.fixture.payload, proved.fixture.circuit,
            proved.fixture.trace.layers.back(), proved.setup, proved.profile,
            proved.fixture.trace.provenance, proved.trace_id, wrong_output,
            proved.proof, transcript));
    });

    runner.run("profile shape mismatches are rejected", [] {
        Fixture wide = fixture(wide_payload());
        const PublicSetup wide_setup =
            make_direct_setup(wide.payload, wide.circuit);
        bool wide_threw = false;
        try {
            validate_profile(
                ProtocolProfile{ProtocolVariant::LaminateLaned,
                                GateMleProfile::Direct,
                                CrossRoundPacking::None},
                wide_setup, wide.circuit);
        } catch (const std::invalid_argument &) {
            wide_threw = true;
        }
        CHECK(wide_threw);

        Fixture laned = fixture(laned_payload());
        const PublicSetup lane_setup =
            make_direct_setup(laned.payload, laned.circuit);
        bool lane_threw = false;
        try {
            validate_profile(
                ProtocolProfile{ProtocolVariant::LaminateBase,
                                GateMleProfile::Direct,
                                CrossRoundPacking::None},
                lane_setup, laned.circuit);
        } catch (const std::invalid_argument &) {
            lane_threw = true;
        }
        CHECK(lane_threw);
    });

    runner.run("every serialized message mutation changes proof bytes", [] {
        Fixture source = fixture(wide_payload());
        const PublicSetup setup =
            make_direct_setup(source.payload, source.circuit);
        const ProvedFixture proved = prove_fixture(
            std::move(source), setup,
            ProtocolProfile{ProtocolVariant::LaminateBase,
                            GateMleProfile::Direct,
                            CrossRoundPacking::None},
            113);
        const auto original = encode_canonical(proved.proof);
        CHECK(!original.empty());
        DecryptedGkrProof changed = proved.proof;
        auto &round = std::get<AffineLayerReductionProof>(changed.reductions.front())
                          .sumcheck.rounds.front();
        round.at_two += Fpk::one();
        CHECK(encode_canonical(changed) != original);
    });

    return runner.summary();
}
