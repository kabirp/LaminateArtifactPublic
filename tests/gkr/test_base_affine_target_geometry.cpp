/// @file test_base_affine_target_geometry.cpp
/// @brief Exact target wire geometry without target-sized SEAL ciphertexts.

#include "test_helpers.hpp"

#include "laminate/bench/payload_profile.hpp"
#include "laminate/fhe/mock_backend.hpp"
#include "laminate/gkr/detail/base/affine/verifier.hpp"
#include "laminate/gkr/detail/base/reference/affine_prover.hpp"
#include "laminate/gkr/detail/base/verification/proof_reader.hpp"
#include "laminate/payload/compiler.hpp"
#include "laminate/poly/eq.hpp"

#include <algorithm>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <vector>

namespace {

using namespace laminate;
using namespace laminate::fhe;
using namespace laminate::gkr;
using namespace laminate::payload;

constexpr std::size_t kSlots = 4;
LayeredCircuit target_output_reduction(bench::BenchmarkPayloadTier tier,
                                       std::size_t source_wires,
                                       std::size_t padded_wires) {
    const auto profile = bench::benchmark_payload_profile(tier);
    auto target = compile(make_payload_circuit(
        bench::benchmark_payload_workload_spec(profile, PayloadShape::wide(16384), 1)));
    const auto source_dimensions = layer_dimensions(target.layers.at(1));
    CHECK(source_dimensions.logical_size == source_wires);
    CHECK(source_dimensions.padded_size == padded_wires);
    CHECK(std::get<AffineLayer>(target.layers.front()).intermediate_gates.size() ==
          source_wires - 1U);

    // Generate the exact target at N=16,384: pyramid mask generation consumes
    // random values before later wiring is chosen. Its final sum has no slot
    // actions, so only then reduce slots for this algebra/scan-order check.
    // Keep the original DAG and padded wire domain; substitute explicit inputs
    // for the preceding payload. This does not test SEAL noise or a full run.
    const auto &affine = std::get<AffineLayer>(target.layers.front());
    const auto check_slot_independent = [](const AffineGate &gate) {
        CHECK(std::holds_alternative<Fp>(gate.constant));
        CHECK(std::get<Fp>(gate.constant) == Fp::zero());
        for (const auto &term : gate.terms) {
            CHECK(term.rotation == 0);
            CHECK(!term.plaintext_index.has_value());
        }
    };
    for (const auto &gate : affine.gates) check_slot_independent(gate);
    for (const auto &gate : affine.intermediate_gates) check_slot_independent(gate);
    LayeredCircuit isolated;
    isolated.shape = PayloadShape::wide(kSlots);
    isolated.payload_input_count = source_wires;
    isolated.payload_output_count = 1;
    isolated.layers.push_back(std::move(target.layers.front()));
    isolated.layers.push_back(InputLayer{source_dimensions});
    isolated.validate();
    return isolated;
}

SlotVector source_value(std::size_t wire) {
    SlotVector result(kSlots);
    for (std::size_t slot = 0; slot < kSlots; ++slot) {
        const std::uint64_t index = wire;
        result[slot] = Fp(17U * index * index + 31U * index + 7U +
                          19U * slot + (index >> 3U) * (slot + 1U));
    }
    return result;
}

void full_width_affine_reduction(bench::BenchmarkPayloadTier tier,
                                 std::size_t source_wires,
                                 std::size_t padded_wires) {
    const auto circuit = target_output_reduction(tier, source_wires, padded_wires);
    const auto rounds = static_cast<std::size_t>(std::countr_zero(padded_wires));
    auto contexts = MockBackend::create({
        .slot_count = kSlots, .fresh_rns_limbs = 3, .bits_per_limb = 80});
    std::vector<SlotVector> inputs;
    inputs.reserve(source_wires);
    SlotVector output(kSlots, Fp::zero());
    EncryptedTrace<MockBackend> trace;
    trace.shape = circuit.shape;
    trace.layers.resize(2);
    for (std::size_t layer = 0; layer < trace.layers.size(); ++layer) {
        trace.layers[layer].dimensions = layer_dimensions(circuit.layers[layer]);
        trace.layers[layer].required_mult_depth = 2;
    }
    trace.layers[1].wires.reserve(source_wires);
    for (std::size_t wire = 0; wire < source_wires; ++wire) {
        inputs.push_back(source_value(wire));
        for (std::size_t slot = 0; slot < kSlots; ++slot)
            output[slot] += inputs.back()[slot];
        trace.layers[1].wires.push_back(FheValue<MockBackend>::from_ciphertext(
            MockBackend::encrypt(contexts.client, inputs.back())));
    }
    trace.layers[0].wires.push_back(FheValue<MockBackend>::from_ciphertext(
        MockBackend::encrypt(contexts.client, output)));

    Transcript coins("test/base/target-affine-geometry/point/v1");
    const auto output_point = coins.challenge_vector(2);
    const SingleClaim claim = make_layer_claim(
        std::vector<SlotVector>{output}, output_point);
    const gates::DirectGateMle provider(circuit);
    const auto prepared = provider.prepare_affine(0, output_point);
    CHECK(prepared.constant_evaluation() == Fpk::zero());
    CHECK(prepared.weighted_term_count() == source_wires);
    CHECK(prepared.rotation_basis_count() == 1);
    std::vector<bool> seen(source_wires);
    for (const auto &term : prepared.weighted_terms()) {
        CHECK(term.source < source_wires);
        CHECK(!seen[term.source]);
        seen[term.source] = true;
        CHECK(term.coefficient == Fpk::one());
        CHECK(term.rotation_index == 0);
    }

    constexpr const char *domain = "test/base/target-affine-geometry/reduction/v1";
    Transcript prover_transcript(domain);
    base_detail::BaseAffineStatistics statistics;
    const auto proved = base_detail::prove_affine_resident<MockBackend>(
        contexts.eval, circuit, trace, 0, LayerClaim{claim}, provider,
        prover_transcript, nullptr, &statistics);
    CHECK(proved.proof.rounds.size() == rounds);
    CHECK(statistics.source_scans == rounds + 1U);
    CHECK(statistics.source_ciphertexts_read == (rounds + 1U) * source_wires);
    CHECK(statistics.distinct_rotation_bases == 1);
    // Independently evaluate the live-prefix indicator. Pyramid's 3,766
    // sources occupy a padded 4,096-wire cube, unlike balanced's full cube.
    const auto wire_weights = poly::eq_evaluations(
        std::vector<Fpk>(proved.next_claim.point.begin(),
                         proved.next_claim.point.begin() + rounds));
    Fpk live_prefix = Fpk::zero();
    for (std::size_t wire = 0; wire < source_wires; ++wire)
        live_prefix += wire_weights[wire];
    auto expected_partial = poly::eq_evaluations(output_point);
    for (auto &weight : expected_partial) weight *= live_prefix;
    CHECK(proved.proof.partial_gate_mle.evaluations == expected_partial);

    base_detail::ProofReader<MockBackend> reader(contexts.client);
    gates::DirectGateMle verifier_provider(circuit);
    Transcript verifier_transcript(domain);
    const auto verified = base_detail::verify_affine_reduction<MockBackend>(
        reader, circuit, 0, LayerClaim{claim}, proved.proof, verifier_provider,
        verifier_transcript);
    CHECK(verified.has_value());
    CHECK(verified->point == proved.next_claim.point);
    // Independent plaintext MLE checks the source-prefix bit order as well
    // as the final relation. It does not replay the affine implementation.
    inputs.resize(padded_wires, SlotVector(kSlots, Fp::zero()));
    CHECK(*verified == make_layer_claim(inputs, verified->point));
    CHECK(prover_transcript.challenge_fpk() == verifier_transcript.challenge_fpk());

    auto wrong_claim = claim;
    wrong_claim.value += Fpk::one();
    Transcript bad_claim_transcript(domain);
    CHECK(!base_detail::verify_affine_reduction<MockBackend>(
        reader, circuit, 0, LayerClaim{wrong_claim}, proved.proof,
        verifier_provider, bad_claim_transcript));
    auto corrupted = proved.proof;
    corrupted.partial_gate_mle.evaluations.front() += Fpk::one();
    Transcript bad_partial_transcript(domain);
    CHECK(!base_detail::verify_affine_reduction<MockBackend>(
        reader, circuit, 0, LayerClaim{claim}, corrupted,
        verifier_provider, bad_partial_transcript));
}

} // namespace

int main() {
    laminate::test::Runner runner("Base target affine geometry");
    runner.run("65,536-wire target output DAG passes the production affine reduction",
               [] { full_width_affine_reduction(
                   bench::BenchmarkPayloadTier::TargetBalanced, 65'536, 65'536); });
    runner.run("3,766-wire pyramid output DAG passes its padded affine reduction",
               [] { full_width_affine_reduction(
                   bench::BenchmarkPayloadTier::TargetMulHeavy, 3'766, 4'096); });
    return runner.summary();
}
