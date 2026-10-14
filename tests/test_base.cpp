/// @file test_base.cpp
/// @brief Mock-encrypted LaminateBase prover/verifier tests.

#include "test_helpers.hpp"
#include "gkr_reference_helpers.hpp"

#include "laminate/fhe/mock_backend.hpp"
#include "laminate/gkr/detail/base/multiplication/verifier.hpp"
#include "laminate/gkr/detail/base/reference/multiplication_prover.hpp"
#include "laminate/gkr/detail/base/verification/proof_reader.hpp"
#include "laminate/payload/compiler.hpp"
#include "laminate/payload/trace/trace_crypto.hpp"
#include "laminate/poly/eq.hpp"
#include "laminate/protocol/base.hpp"
#include "laminate/protocol/metrics/profiling.hpp"
#include "laminate/protocol/metrics/proof_size.hpp"
#include "laminate/protocol/reference/base.hpp"
#include "laminate/verification_profile.hpp"

#include <bit>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <utility>
#include <vector>

using namespace laminate;
using namespace laminate::fhe;
using namespace laminate::gkr;
using namespace laminate::payload;
using namespace laminate::protocol;

namespace {

Fpk value(std::uint64_t seed) {
    Fpk::Coefficients coefficients{};
    for (std::size_t coefficient = 0; coefficient < kExtensionDegree;
         ++coefficient) {
        coefficients[coefficient] =
            Fp(seed + 13 * coefficient + coefficient * coefficient);
    }
    return Fpk(coefficients);
}

std::vector<Fpk> point(std::size_t size, std::uint64_t seed) {
    std::vector<Fpk> result;
    result.reserve(size);
    for (std::size_t index = 0; index < size; ++index) {
        result.push_back(value(seed + 23 * index));
    }
    return result;
}

SlotVector slots(std::size_t count, std::uint64_t seed) {
    SlotVector result;
    result.reserve(count);
    for (std::size_t slot = 0; slot < count; ++slot) {
        result.emplace_back(seed + 7 * slot + slot * slot);
    }
    return result;
}

PayloadCircuit affine_payload() {
    PayloadBuilder builder(PayloadShape::wide(8), 2);
    const std::size_t diagonal = builder.add_plaintext(
        {Fp(2), Fp(3), Fp(5), Fp(7), Fp(11), Fp(13), Fp(17), Fp(19)});
    const std::size_t scalar = builder.add_plaintext(SlotVector(8, Fp(3)));
    const auto rotated = builder.rotate(0, 5);
    const auto scaled = builder.mul_plain(1, scalar);
    const auto sum = builder.add(rotated, scaled);
    const auto output = builder.add_plain(sum, diagonal);
    builder.set_outputs({output});
    return builder.finish();
}

PayloadCircuit sequential_multiplication_payload() {
    PayloadBuilder builder(PayloadShape::wide(8), 2);
    const std::size_t diagonal = builder.add_plaintext(
        {Fp(2), Fp(3), Fp(5), Fp(7), Fp(11), Fp(13), Fp(17), Fp(19)});
    const auto rotated = builder.rotate(0, 5);
    const auto ctct = builder.mul(rotated, 1);
    const auto plainct = builder.mul_plain(ctct, diagonal);
    builder.set_outputs({plainct});
    return builder.finish();
}

PayloadCircuit ctct_payload() {
    PayloadBuilder builder(PayloadShape::wide(8), 2);
    builder.set_outputs({builder.mul(0, 1)});
    return builder.finish();
}

PayloadCircuit parallel_multiplication_payload() {
    PayloadBuilder builder(PayloadShape::wide(8), 4);
    const WireId first = builder.mul(0, 1);
    const WireId second = builder.mul(2, 3);
    builder.set_outputs({first, second});
    return builder.finish();
}

PayloadCircuit public_operand_multiplication_payload() {
    PayloadBuilder builder(PayloadShape::wide(8), 2);
    const std::size_t zero =
        builder.add_plaintext(SlotVector(8, Fp::zero()));
    const std::size_t three =
        builder.add_plaintext(SlotVector(8, Fp(3)));
    const WireId public_zero = builder.mul_plain(0, zero);
    const WireId public_three = builder.add_plain(public_zero, three);
    const WireId nonzero_product = builder.mul(public_three, 1);
    const WireId zero_product = builder.mul(public_zero, 0);
    builder.set_outputs({nonzero_product, zero_product});
    return builder.finish();
}

PayloadCircuit padded_rotation_payload() {
    PayloadBuilder builder(PayloadShape::wide(8), 3);
    const auto first = builder.rotate(0, 1);
    const auto second = builder.rotate(1, 3);
    const auto third = builder.rotate(2, 5);
    builder.set_outputs({first, second, third});
    return builder.finish();
}

std::vector<SlotVector> fixture_inputs(const PayloadCircuit &payload) {
    std::vector<SlotVector> result;
    result.reserve(payload.input_count);
    for (std::size_t input = 0; input < payload.input_count; ++input) {
        result.push_back(slots(8, 3 + 38 * input));
    }
    return result;
}

std::uint64_t counted_fhe_operations(const OperationCounts &counts) {
    return counts.encrypt + counts.decrypt + counts.negate + counts.add +
           counts.sub + counts.mul_no_relin + counts.relinearize +
           counts.add_plain + counts.mul_plain_scalar +
           counts.mul_plain_vector + counts.rotate + counts.mod_switch +
           counts.logical_ext_add + counts.logical_ext_sub +
           counts.logical_ext_mul + counts.logical_ext_mul_plain;
}

struct Fixture {
    PayloadCircuit payload;
    LayeredCircuit circuit;
    PlainTrace trace;
    PublicSetup public_setup;
    MockBackend::Contexts contexts;
    EncryptedTrace<MockBackend> encrypted;
    SingleClaim output_claim;

    Fixture(PayloadCircuit input_payload = affine_payload(),
            std::size_t required_depth = 2)
        : payload(std::move(input_payload)), circuit(compile(payload)),
          trace(synthesize_trace(payload, circuit,
                                 fixture_inputs(payload))),
          public_setup(make_direct_setup(payload, circuit)),
          contexts(MockBackend::create(MockParameters{.slot_count = 8})),
          encrypted(encrypt_compact_synthetic_trace<MockBackend>(
              contexts.eval, contexts.client, payload, circuit, trace,
              TraceEncryptionPlan::uniform(circuit, required_depth))),
          output_claim(make_layer_claim(
              trace.layers.front(),
              point((std::bit_width(
                         layer_dimensions(circuit.layers.front()).padded_size) -
                     1U) +
                        (std::bit_width(circuit.shape.value_width()) - 1U),
                    101))) {}
};

std::shared_ptr<const gates::GateTableProverKey>
enable_outsourced_gate_mles(Fixture &fixture) {
    auto key = std::make_shared<gates::GateTableProverKey>(
        gates::preprocess_gate_tables(fixture.circuit,
                                      gates::GateTableSet::Wide));
    fixture.public_setup = make_outsourced_gate_setup(
        fixture.payload, fixture.circuit, key->verifier);
    return key;
}

bool verify(Fixture &fixture,
            const EncryptedBaseProof<MockBackend> &proof,
            const SingleClaim &expected_output) {
    const auto client = make_client_setup<MockBackend>(
        fixture.public_setup, fixture.contexts.client);
    Transcript transcript("test/base/affine");
    return reference::verify_base<MockBackend>(
        fixture.payload, fixture.circuit, fixture.trace.layers.back(), client,
        fixture.trace.provenance, fixture.encrypted.trace_id, expected_output,
        proof, transcript);
}

bool is_lowest(const ExtensionValue<MockBackend> &value) {
    for (const auto &coefficient : value) {
        if (coefficient.is_encrypted() &&
            coefficient.ciphertext().rns_limbs != 1) {
            return false;
        }
    }
    return true;
}

Fpk wire_value(std::span<const SlotVector> layer,
               std::span<const Fpk> wire_point, std::size_t slot) {
    const std::vector<Fpk> owned(wire_point.begin(), wire_point.end());
    const std::vector<Fpk> weights = poly::eq_evaluations(owned);
    Fpk result = Fpk::zero();
    for (std::size_t wire = 0; wire < layer.size(); ++wire) {
        result += weights[wire] * layer[wire][slot];
    }
    return result;
}

std::vector<Fpk> expected_dense_multiplication_round(
    const Fixture &fixture, std::size_t layer, const SingleClaim &claim,
    std::span<const Fpk> prefix, const Fpk &round_value) {
    const auto &source = fixture.trace.layers[layer + 1];
    const std::size_t wire_variables =
        base_detail::ciphertext_index_variables(fixture.circuit, layer);
    std::vector<Fpk> bound(prefix.begin(), prefix.end());
    bound.push_back(round_value);
    const std::size_t remaining = wire_variables - bound.size();
    const std::vector<Fpk> suffix_weights = poly::eq_evaluations(
        std::vector<Fpk>(
            claim.point.begin() +
                static_cast<std::ptrdiff_t>(bound.size()),
            claim.point.begin() +
                static_cast<std::ptrdiff_t>(wire_variables)));
    std::vector<Fpk> result(fixture.circuit.shape.value_width(), Fpk::zero());

    for (std::size_t suffix = 0; suffix < poly::hypercube_size(remaining);
         ++suffix) {
        const std::vector<Fpk> wire_point = base_detail::concatenate(
            bound, test::hypercube_vertex(suffix, remaining));
        for (std::size_t slot = 0; slot < result.size(); ++slot) {
            std::vector<Fpk> right_point;
            right_point.reserve(wire_point.size() + 1U);
            right_point.push_back(Fpk::one());
            right_point.insert(right_point.end(), wire_point.begin(),
                               wire_point.end());
            std::vector<Fpk> left_point = right_point;
            left_point.front() = Fpk::zero();
            result[slot] += suffix_weights[suffix] *
                            wire_value(source, left_point, slot) *
                            wire_value(source, right_point, slot);
        }
    }
    return result;
}

std::vector<Fpk> expected_affine_round(
    const Fixture &fixture, const gates::DirectGateMle &provider,
    std::span<const Fpk> prefix, const Fpk &round_value) {
    std::vector<Fpk> bound(prefix.begin(), prefix.end());
    bound.push_back(round_value);
    const std::vector<Fpk> prefix_weights = poly::eq_evaluations(bound);
    const auto &source = fixture.trace.layers.at(1);
    const std::size_t wire_vars = std::bit_width(source.size()) - 1U;
    const std::size_t suffix_vars = wire_vars - bound.size();
    const std::size_t suffix_count = poly::hypercube_size(suffix_vars);
    const std::size_t slot_vars =
        std::bit_width(fixture.circuit.shape.value_width()) - 1U;
    std::vector<Fpk> result(fixture.circuit.shape.value_width(), Fpk::zero());

    for (std::size_t suffix = 0; suffix < suffix_count; ++suffix) {
        const std::vector<Fpk> suffix_point =
            test::hypercube_vertex(suffix, suffix_vars);
        const std::vector<Fpk> wire_point =
            base_detail::concatenate(bound, suffix_point);
        for (std::size_t slot = 0; slot < result.size(); ++slot) {
            Fpk witness = Fpk::zero();
            for (std::size_t bound_index = 0;
                 bound_index < prefix_weights.size(); ++bound_index) {
                witness +=
                    prefix_weights[bound_index] *
                    source[bound_index * suffix_count + suffix][slot];
            }
            const std::vector<Fpk> source_point = base_detail::concatenate(
                wire_point, test::hypercube_vertex(slot, slot_vars));
            result[slot] +=
                provider.evaluate(gates::GateMleQuery{gates::AffineQuery{
                    0, fixture.output_claim.point, source_point}}) *
                witness;
        }
    }
    return result;
}

std::size_t expected_base_gate_claims(const LayeredCircuit &circuit) {
    std::size_t result = 0;
    for (std::size_t layer = 0; layer + 1 < circuit.layers.size(); ++layer) {
        if (layer_kind(circuit.layers[layer]) == LayerKind::Affine) {
            // Selector interpolation leaves one output point per layer.
            result += 2;
            continue;
        }
        // Dense multiplication wiring is fixed by the layer dimensions and
        // contributes no GateMLE claim.
    }
    return result;
}

std::size_t first_layer_of_kind(const LayeredCircuit &circuit,
                                LayerKind kind) {
    for (std::size_t layer = 0; layer + 1 < circuit.layers.size(); ++layer) {
        if (layer_kind(circuit.layers[layer]) == kind) {
            return layer;
        }
    }
    return circuit.layers.size();
}

void check_structured_affine_partial_gate_mle() {
    const PayloadCircuit payload = padded_rotation_payload();
    const LayeredCircuit circuit = compile(payload);
    const PlainTrace trace = synthesize_trace(
        payload, circuit, fixture_inputs(payload));
    const SingleClaim output_claim = make_layer_claim(
        trace.layers.front(),
        point((std::bit_width(
                   layer_dimensions(circuit.layers.front()).padded_size) -
               1U) +
                  (std::bit_width(circuit.shape.value_width()) - 1U),
              101));
    CHECK(layer_dimensions(circuit.layers.front()).padding_size() != 0);
    const gates::DirectGateMle provider(circuit);
    const std::size_t slot_variables =
        base_detail::slot_index_variables(circuit);
    const std::vector<Fpk> fixed_wire =
        point(base_detail::ciphertext_index_variables(circuit, 1), 503);

    const SingleClaim second{
        point(output_claim.point.size(), 607), value(701)};
    const Fpk rho = value(809);
    const BatchedClaim batch{
        output_claim, second, rho,
        output_claim.value + rho * second.value};
    const PartialGateMleVector partial =
        base_detail::make_affine_partial_gate_mle(
            circuit, 0, LayerClaim{batch}, fixed_wire);

    CHECK(partial.evaluations.size() == circuit.shape.value_width());
    for (std::size_t slot = 0; slot < partial.evaluations.size(); ++slot) {
        const std::vector<Fpk> source = base_detail::concatenate(
            fixed_wire,
            test::hypercube_vertex(slot, slot_variables));
        const Fpk expected =
            provider.evaluate(gates::GateMleQuery{gates::AffineQuery{
                0, batch.first.point, source}}) +
            rho * provider.evaluate(gates::GateMleQuery{gates::AffineQuery{
                      0, batch.second.point, source}});
        CHECK(partial.evaluations[slot] == expected);
    }
}

} // namespace

int main() {
    test::Runner runner("test_base");

    runner.run("bound schedules reject resident proving before work", [] {
        Fixture fixture;
        Digest schedule_digest{};
        schedule_digest.front() = 1U;
        Digest assessment_digest{};
        assessment_digest.front() = 2U;
        fixture.public_setup.honest_payload_noise_schedule_digest =
            schedule_digest;
        fixture.public_setup.honest_base_proof_noise_assessment_digest =
            assessment_digest;
        const auto evaluation = make_evaluation_setup<MockBackend>(
            fixture.public_setup, fixture.contexts.eval);
        MockBackend::reset_counts(fixture.contexts.eval);
        Transcript attempted("test/base/bound-resident-rejection/v1");
        bool rejected = false;
        try {
            (void)reference::prove_base<MockBackend>(
                fixture.payload, fixture.circuit, fixture.encrypted,
                evaluation, fixture.output_claim.point, attempted);
        } catch (const std::invalid_argument &) {
            rejected = true;
        }
        CHECK(rejected);
        CHECK(counted_fhe_operations(
                  MockBackend::counts(fixture.contexts.eval)) == 0);
        Transcript pristine("test/base/bound-resident-rejection/v1");
        CHECK(attempted.challenge_fpk() == pristine.challenge_fpk());
    });

    runner.run("FHE-evaluated resident traces are non-admitting", [] {
        Fixture fixture;
        fixture.encrypted.provenance = TraceProvenance::FheEvaluated;
        const auto evaluation = make_evaluation_setup<MockBackend>(
            fixture.public_setup, fixture.contexts.eval);
        MockBackend::reset_counts(fixture.contexts.eval);
        Transcript attempted("test/base/fhe-resident-rejection/v1");
        bool rejected = false;
        try {
            (void)reference::prove_base<MockBackend>(
                fixture.payload, fixture.circuit, fixture.encrypted,
                evaluation, fixture.output_claim.point, attempted);
        } catch (const std::invalid_argument &) {
            rejected = true;
        }
        CHECK(rejected);
        CHECK(counted_fhe_operations(
                  MockBackend::counts(fixture.contexts.eval)) == 0);
        Transcript pristine("test/base/fhe-resident-rejection/v1");
        CHECK(attempted.challenge_fpk() == pristine.challenge_fpk());
    });

    runner.run("encrypted affine Base proof verifies", [] {
        Fixture fixture;
        const auto evaluation = make_evaluation_setup<MockBackend>(
            fixture.public_setup, fixture.contexts.eval);
        Transcript prover_transcript("test/base/affine");
        BaseProverTimings prover_timings;
        const auto proof = prove_base_reference_profiled<MockBackend>(
            fixture.payload, fixture.circuit, fixture.encrypted, evaluation,
            fixture.output_claim.point, prover_transcript, prover_timings);

        CHECK(proof.reductions.size() + 1 == fixture.circuit.layers.size());
        CHECK(prover_timings.layers.size() == proof.reductions.size());
        CHECK(prover_timings.layers.front().layer == 0);
        CHECK(prover_timings.layers.front().kind == LayerKind::Affine);
        CHECK(prover_timings.layers.front().wall_ms >= 0);

        const auto client = make_client_setup<MockBackend>(
            fixture.public_setup, fixture.contexts.client);
        Transcript verifier_transcript("test/base/affine");
        BaseVerifierTimings verifier_timings;
        verification_profile::VerificationBreakdown breakdown;
        {
            const verification_profile::ScopedVerificationSession session(
                breakdown);
            CHECK(verify_base_reference_profiled<MockBackend>(
                fixture.payload, fixture.circuit, fixture.trace.layers.back(),
                client, fixture.trace.provenance, fixture.encrypted.trace_id,
                fixture.output_claim, proof, verifier_transcript,
                verifier_timings));
        }
        using verification_profile::Category;
        CHECK(breakdown.phase_entries(Category::Recovery) > 0);
        CHECK(breakdown.phase_entries(Category::GkrPlaintext) > 0);
        CHECK(breakdown.phase_entries(Category::TerminalInputMLE) == 1);
        CHECK(breakdown.phase_entries(Category::PackingSNARK) == 0);
        CHECK(breakdown.phase_entries(Category::WFNoise) == 0);
        CHECK(breakdown.phase_entries(Category::OutputDecryption) == 0);
        Transcript unprofiled_transcript("test/base/affine");
        CHECK(reference::verify_base<MockBackend>(
            fixture.payload, fixture.circuit, fixture.trace.layers.back(),
            client, fixture.trace.provenance, fixture.encrypted.trace_id,
            fixture.output_claim, proof, unprofiled_transcript));
        CHECK(verifier_transcript.challenge_fpk() ==
              unprofiled_transcript.challenge_fpk());
        CHECK(verifier_timings.layers.size() == proof.reductions.size());
        CHECK(verifier_timings.layers.front().layer == 0);
        CHECK(verifier_timings.layers.front().kind == LayerKind::Affine);
        CHECK(verifier_timings.packed_message_verification_wall_ms >= 0);
        CHECK(encode_canonical(proof) == encode_canonical(proof));

        const BaseProofSizeBreakdown size = measure_proof_size(proof);
        CHECK(size.total_bytes == encode_canonical(proof).size());
        CHECK(size.total_bytes == size.statement_and_metadata_bytes +
                                      size.round_message_bytes +
                                      size.terminal_message_bytes +
                                      size.partial_gate_mle_bytes);
        CHECK(size.logical_round_messages ==
              std::get<EncryptedBaseAffineLayerReduction<MockBackend>>(
                  proof.reductions.front())
                  .rounds.size());
        CHECK(size.base_ciphertexts ==
              size.extension_ciphertexts * kExtensionDegree);
        CHECK(size.gate_mle_opening_bytes == 0);
        CHECK(size.partial_gate_mle_bytes ==
              8 + 8 * kSerializedFpkBytes);
        CHECK(size.transcript_packing_bytes == 0);

        CHECK(proof.reductions.size() == 1);
        const auto &affine =
            std::get<EncryptedBaseAffineLayerReduction<MockBackend>>(
                proof.reductions.front());
        const gates::DirectGateMle provider(fixture.circuit);
        Transcript replay("test/base/affine");
        observe_proof_header(proof.header, replay);
        gates::observe_gate_mle_setup(fixture.public_setup, replay);
        base_detail::observe_output_point(fixture.output_claim.point, replay);
        base_detail::observe_begin(
            0, LayerKind::Affine, affine.rounds.size(), replay);
        std::vector<Fpk> prefix;
        for (std::size_t round = 0; round < affine.rounds.size(); ++round) {
            CHECK(read_extension_value<MockBackend>(
                      fixture.contexts.client,
                      affine.rounds[round].evaluations[0]) ==
                  expected_affine_round(fixture, provider, prefix,
                                        Fpk::one()));
            CHECK(read_extension_value<MockBackend>(
                      fixture.contexts.client,
                      affine.rounds[round].evaluations[1]) ==
                  expected_affine_round(fixture, provider, prefix,
                                        Fpk::from_base(Fp(2))));
            base_detail::observe_round<MockBackend>(
                0, round, affine.rounds[round], replay);
            prefix.push_back(replay.challenge_fpk());
        }
        base_detail::observe_terminal<MockBackend>(
            0,
            std::span<const ExtensionValue<MockBackend>>(
                &affine.source_vector, 1),
            replay);
        base_detail::observe_partial_gate_mle(
            0, base_detail::PartialGateMleKind::Affine,
            affine.partial_gate_mle, replay);
        const std::vector<Fpk> eta = replay.challenge_vector(3);
        const std::vector<Fpk> full_source =
            base_detail::concatenate(prefix, eta);
        CHECK(test::evaluate_mle_reference(
                  affine.partial_gate_mle.evaluations, eta) ==
              provider.evaluate(gates::GateMleQuery{gates::AffineQuery{
                  0, fixture.output_claim.point, full_source}}));
    });

    runner.run("round, terminal, and statement mutations reject", [] {
        Fixture fixture;
        const auto evaluation = make_evaluation_setup<MockBackend>(
            fixture.public_setup, fixture.contexts.eval);
        Transcript prover_transcript("test/base/affine");
        const auto proof = reference::prove_base<MockBackend>(
            fixture.payload, fixture.circuit, fixture.encrypted, evaluation,
            fixture.output_claim.point, prover_transcript);
        const auto &honest_affine =
            std::get<EncryptedBaseAffineLayerReduction<MockBackend>>(
                proof.reductions.front());
        CHECK(!honest_affine.rounds.empty());

        auto changed_round = proof;
        auto &round = std::get<EncryptedBaseAffineLayerReduction<MockBackend>>(
            changed_round.reductions.front());
        CHECK(round.rounds.front().evaluations[0][0].is_encrypted());
        round.rounds.front()
            .evaluations[0][0]
            .ciphertext()
            .slots[0] += Fp::one();
        CHECK(!verify(fixture, changed_round, fixture.output_claim));
        CHECK(encode_canonical(changed_round) != encode_canonical(proof));

        auto changed_terminal = proof;
        auto &terminal = std::get<EncryptedBaseAffineLayerReduction<MockBackend>>(
            changed_terminal.reductions.front());
        CHECK(terminal.source_vector[0].is_encrypted());
        terminal.source_vector[0].ciphertext().slots[3] += Fp::one();
        CHECK(!verify(fixture, changed_terminal, fixture.output_claim));

        auto changed_partial = proof;
        auto &changed_affine =
            std::get<EncryptedBaseAffineLayerReduction<MockBackend>>(
                changed_partial.reductions.front());
        changed_affine.partial_gate_mle.evaluations[3] += Fpk::one();
        CHECK(!verify(fixture, changed_partial, fixture.output_claim));

        auto short_partial = proof;
        std::get<EncryptedBaseAffineLayerReduction<MockBackend>>(
            short_partial.reductions.front())
            .partial_gate_mle.evaluations.pop_back();
        CHECK(!verify(fixture, short_partial, fixture.output_claim));

        SingleClaim wrong_output = fixture.output_claim;
        wrong_output.value += Fpk::one();
        CHECK(!verify(fixture, proof, wrong_output));
    });

    runner.run("dense multiplication rounds match direct enumeration", [] {
        Fixture fixture(parallel_multiplication_payload(), 4);
        std::size_t multiplication_layer = fixture.circuit.layers.size();
        for (std::size_t layer = 0; layer + 1 < fixture.circuit.layers.size();
             ++layer) {
            if (layer_kind(fixture.circuit.layers[layer]) ==
                    LayerKind::Multiplication &&
                base_detail::ciphertext_index_variables(
                    fixture.circuit, layer) != 0) {
                multiplication_layer = layer;
                break;
            }
        }
        CHECK(multiplication_layer + 1 < fixture.circuit.layers.size());
        const auto &plain_layer = fixture.trace.layers[multiplication_layer];
        std::vector<Fpk> claim_point = point(
            base_detail::layer_vars(fixture.circuit, multiplication_layer),
            307);
        CHECK(base_detail::ciphertext_index_variables(
                  fixture.circuit, multiplication_layer) != 0U);
        // Exercise the singular endpoint-recovery branch explicitly.
        claim_point.front() = Fpk::zero();
        const SingleClaim claim = make_layer_claim(plain_layer, claim_point);

        Transcript prover_transcript("test/base/dense-rounds/v1");
        const auto proved =
            base_detail::ResidentBaseMultiplicationLayerReductionProver<
                MockBackend>(
                fixture.contexts.eval, fixture.circuit,
                fixture.encrypted, multiplication_layer, claim,
                prover_transcript)
                .run();
        CHECK(proved.proof.rounds.size() ==
              base_detail::ciphertext_index_variables(
                  fixture.circuit, multiplication_layer));

        Transcript replay("test/base/dense-rounds/v1");
        base_detail::observe_begin(
            multiplication_layer, LayerKind::Multiplication,
            proved.proof.rounds.size(), replay);
        std::vector<Fpk> prefix;
        for (std::size_t round = 0; round < proved.proof.rounds.size();
             ++round) {
            const Fpk primary = gkr::detail::
                dense_multiplication_primary_point(claim.point[round]);
            CHECK(read_extension_value<MockBackend>(
                      fixture.contexts.client,
                      proved.proof.rounds[round].evaluations[0]) ==
                  expected_dense_multiplication_round(
                      fixture, multiplication_layer, claim, prefix,
                      primary));
            CHECK(read_extension_value<MockBackend>(
                      fixture.contexts.client,
                      proved.proof.rounds[round].evaluations[1]) ==
                  expected_dense_multiplication_round(
                      fixture, multiplication_layer, claim, prefix,
                      Fpk::from_base(Fp(2))));
            base_detail::observe_round<MockBackend>(
                multiplication_layer, round,
                proved.proof.rounds[round], replay);
            prefix.push_back(replay.challenge_fpk());
        }

        Transcript verifier_transcript("test/base/dense-rounds/v1");
        base_detail::ProofReader<MockBackend> reader(
            fixture.contexts.client);
        const auto next =
            base_detail::verify_multiplication_reduction<MockBackend>(
                reader, fixture.circuit, multiplication_layer, claim,
                proved.proof, verifier_transcript);
        CHECK(next.has_value());
    });

    runner.run("Base multiplication keeps its terminal check at zero equality", [] {
        Fixture fixture(parallel_multiplication_payload(), 4);
        std::size_t layer = 0;
        while (layer_kind(fixture.circuit.layers[layer]) !=
               LayerKind::Multiplication) {
            ++layer;
        }
        CHECK(base_detail::ciphertext_index_variables(fixture.circuit, layer) ==
              1U);
        auto output_point = point(base_detail::layer_vars(fixture.circuit, layer),
                                  353);
        output_point.front() = Fpk::one();
        auto claim = make_layer_claim(fixture.trace.layers[layer], output_point);
        Transcript preview("test/base/zero-equality");
        auto proof = base_detail::ResidentBaseMultiplicationLayerReductionProver<
            MockBackend>(fixture.contexts.eval, fixture.circuit,
                         fixture.encrypted, layer, claim, preview).run().proof;
        Transcript first_round("test/base/zero-equality");
        base_detail::observe_begin(layer, LayerKind::Multiplication, 1,
                                   first_round);
        base_detail::observe_round<MockBackend>(layer, 0, proof.rounds[0],
                                                first_round);
        const Fpk r = first_round.challenge_fpk();
        const Fpk denominator = Fpk::from_base(Fp(2)) * r - Fpk::one();
        CHECK(!denominator.is_zero());
        output_point.front() = (r - Fpk::one()) * denominator.inverse();
        CHECK(!output_point.front().is_zero());
        CHECK(gkr::detail::dense_multiplication_equality_factor(
                  output_point.front(), r).is_zero());
        claim = make_layer_claim(fixture.trace.layers[layer], output_point);
        // The one Base round sends h(0),h(2), independent of gamma_ct. The
        // previously constructed messages therefore remain honest at this
        // output point, chosen to exercise the zero-equality boundary.
        base_detail::ProofReader<MockBackend> reader(fixture.contexts.client);
        Transcript honest("test/base/zero-equality");
        CHECK(base_detail::verify_multiplication_reduction<MockBackend>(
                  reader, fixture.circuit, layer, claim, proof, honest));
        proof.source_vectors[0][0].ciphertext().slots[0] += Fp::one();
        Transcript changed("test/base/zero-equality");
        CHECK(!base_detail::verify_multiplication_reduction<MockBackend>(
                  reader, fixture.circuit, layer, claim, proof, changed));
    });

    runner.run("Base zero-round multiplication still checks terminal vectors", [] {
        Fixture fixture(ctct_payload(), 4);
        std::size_t layer = 0;
        while (layer_kind(fixture.circuit.layers[layer]) !=
               LayerKind::Multiplication) {
            ++layer;
        }
        CHECK(base_detail::ciphertext_index_variables(fixture.circuit, layer) ==
              0U);
        const auto claim = make_layer_claim(fixture.trace.layers[layer],
            point(base_detail::layer_vars(fixture.circuit, layer), 367));
        Transcript prover("test/base/zero-round");
        auto proof = base_detail::ResidentBaseMultiplicationLayerReductionProver<
            MockBackend>(fixture.contexts.eval, fixture.circuit,
                         fixture.encrypted, layer, claim, prover).run().proof;
        CHECK(proof.rounds.empty());
        base_detail::ProofReader<MockBackend> reader(fixture.contexts.client);
        Transcript honest("test/base/zero-round");
        CHECK(base_detail::verify_multiplication_reduction<MockBackend>(
                  reader, fixture.circuit, layer, claim, proof, honest));
        proof.source_vectors[0][0].ciphertext().slots[0] += Fp::one();
        Transcript changed("test/base/zero-round");
        CHECK(!base_detail::verify_multiplication_reduction<MockBackend>(
                  reader, fixture.circuit, layer, claim, proof, changed));
    });

    runner.run("structured affine GateMLE vector matches generic query", [] {
        check_structured_affine_partial_gate_mle();
    });

    runner.run("dense multiplication omits a multiplication GateMLE", [] {
        Fixture fixture(ctct_payload(), 4);
        const auto evaluation = make_evaluation_setup<MockBackend>(
            fixture.public_setup, fixture.contexts.eval);
        Transcript prover_transcript("test/base/ctct-only");
        const auto proof = reference::prove_base<MockBackend>(
            fixture.payload, fixture.circuit, fixture.encrypted, evaluation,
            fixture.output_claim.point, prover_transcript);

        bool saw_multiplication = false;
        for (const auto &reduction : proof.reductions) {
            if (const auto *multiplication = std::get_if<
                    EncryptedBaseMultiplicationLayerReduction<MockBackend>>(
                    &reduction)) {
                saw_multiplication = true;
            }
        }
        CHECK(saw_multiplication);

        const auto client = make_client_setup<MockBackend>(
            fixture.public_setup, fixture.contexts.client);
        Transcript verifier_transcript("test/base/ctct-only");
        CHECK(reference::verify_base<MockBackend>(
            fixture.payload, fixture.circuit, fixture.trace.layers.back(),
            client, fixture.trace.provenance, fixture.encrypted.trace_id,
            fixture.output_claim, proof, verifier_transcript));
    });

    runner.run("resident multiplication accepts public zero and nonzero wires",
               [] {
                   Fixture fixture(public_operand_multiplication_payload(),
                                   4);
                   const std::size_t layer = first_layer_of_kind(
                       fixture.circuit, LayerKind::Multiplication);
                   CHECK(layer + 1 < fixture.circuit.layers.size());

                   auto &encrypted_source =
                       fixture.encrypted.layers[layer + 1].wires;
                   const auto &plain_source = fixture.trace.layers[layer + 1];
                   bool replaced_zero = false;
                   bool replaced_nonzero = false;
                   for (std::size_t wire = 0;
                        wire < plain_source.size(); ++wire) {
                       const bool is_zero = std::all_of(
                           plain_source[wire].begin(),
                           plain_source[wire].end(),
                           [](const Fp &slot) { return slot.is_zero(); });
                       const bool is_three = std::all_of(
                           plain_source[wire].begin(),
                           plain_source[wire].end(), [](const Fp &slot) {
                               return slot == Fp(3);
                           });
                       if (!replaced_zero && is_zero) {
                           encrypted_source[wire] =
                               FheValue<MockBackend>::public_zero();
                           replaced_zero = true;
                       } else if (!replaced_nonzero && is_three) {
                           encrypted_source[wire] =
                               FheValue<MockBackend>::public_slots(
                                   plain_source[wire]);
                           replaced_nonzero = true;
                       }
                   }
                   CHECK(replaced_zero);
                   CHECK(replaced_nonzero);

                   const auto evaluation =
                       make_evaluation_setup<MockBackend>(
                           fixture.public_setup, fixture.contexts.eval);
                   Transcript prover_transcript(
                       "test/base/resident-public-operands/v1");
                   const auto proof =
                       reference::prove_base<MockBackend>(
                           fixture.payload, fixture.circuit,
                           fixture.encrypted, evaluation,
                           fixture.output_claim.point, prover_transcript);

                   const auto client = make_client_setup<MockBackend>(
                       fixture.public_setup, fixture.contexts.client);
                   Transcript verifier_transcript(
                       "test/base/resident-public-operands/v1");
                   CHECK(reference::verify_base<MockBackend>(
                       fixture.payload, fixture.circuit,
                       fixture.trace.layers.back(), client,
                       fixture.trace.provenance,
                       fixture.encrypted.trace_id, fixture.output_claim,
                       proof, verifier_transcript));
               });

    runner.run("dense multiplication and affine reductions reject edits",
               [] {
                   Fixture fixture(sequential_multiplication_payload(), 4);
                   MockBackend::reset_counts(fixture.contexts.eval);
                   const auto evaluation =
                       make_evaluation_setup<MockBackend>(
                           fixture.public_setup, fixture.contexts.eval);
                   Transcript prover_transcript("test/base/mixed");
                   const auto proof =
                       reference::prove_base<MockBackend>(
                       fixture.payload, fixture.circuit, fixture.encrypted,
                       evaluation, fixture.output_claim.point,
                       prover_transcript);
                   CHECK(MockBackend::counts(fixture.contexts.eval).decrypt ==
                         0);
                   CHECK(MockBackend::counts(fixture.contexts.eval)
                             .prepared_extension_basis_setup_calls > 0);
                   CHECK(MockBackend::counts(fixture.contexts.eval)
                             .prepared_extension_basis_api_calls > 0);
                   for (const auto &reduction : proof.reductions) {
                       if (const auto *affine = std::get_if<
                               EncryptedBaseAffineLayerReduction<MockBackend>>(
                               &reduction)) {
                           for (const auto &round : affine->rounds) {
                               CHECK(is_lowest(round.evaluations[0]));
                               CHECK(is_lowest(round.evaluations[1]));
                           }
                           CHECK(is_lowest(affine->source_vector));
                       } else {
                           const auto &product = std::get<
                               EncryptedBaseMultiplicationLayerReduction<
                                   MockBackend>>(reduction);
                           for (const auto &round : product.rounds) {
                               CHECK(is_lowest(round.evaluations[0]));
                               CHECK(is_lowest(round.evaluations[1]));
                           }
                           CHECK(is_lowest(product.source_vectors[0]));
                           CHECK(is_lowest(product.source_vectors[1]));
                       }
                   }

                   const auto client = make_client_setup<MockBackend>(
                       fixture.public_setup, fixture.contexts.client);
                   Transcript verifier_transcript("test/base/mixed");
                   CHECK(reference::verify_base<MockBackend>(
                       fixture.payload, fixture.circuit,
                       fixture.trace.layers.back(), client,
                       fixture.trace.provenance, fixture.encrypted.trace_id,
                       fixture.output_claim, proof, verifier_transcript));

                   std::size_t multiplication = proof.reductions.size();
                   for (std::size_t layer = 0;
                        layer < proof.reductions.size(); ++layer) {
                       if (std::holds_alternative<
                               EncryptedBaseMultiplicationLayerReduction<
                                   MockBackend>>(proof.reductions[layer])) {
                           multiplication = layer;
                           break;
                       }
                   }
                   CHECK(multiplication < proof.reductions.size());
                   const auto &honest = std::get<
                       EncryptedBaseMultiplicationLayerReduction<MockBackend>>(
                       proof.reductions[multiplication]);
                   CHECK(honest.rounds.size() ==
                         base_detail::ciphertext_index_variables(
                             fixture.circuit, multiplication));

                   auto changed = proof;
                   auto &bad = std::get<
                       EncryptedBaseMultiplicationLayerReduction<MockBackend>>(
                       changed.reductions[multiplication]);
                   CHECK(bad.source_vectors[1][0].is_encrypted());
                   bad.source_vectors[1][0].ciphertext().slots[2] +=
                       Fp::one();
                   Transcript changed_transcript("test/base/mixed");
                   CHECK(!reference::verify_base<MockBackend>(
                       fixture.payload, fixture.circuit,
                       fixture.trace.layers.back(), client,
                       fixture.trace.provenance, fixture.encrypted.trace_id,
                       fixture.output_claim, changed, changed_transcript));

               });

    runner.run("outsourced Base gate claims open and reject tampering", [] {
        Fixture fixture(sequential_multiplication_payload(), 4);
        const auto key = enable_outsourced_gate_mles(fixture);
        const auto evaluation = make_evaluation_setup<MockBackend>(
            fixture.public_setup, fixture.contexts.eval, key);
        Transcript prover_transcript("test/base/outsourced/v1");
        const auto proof = reference::prove_base<MockBackend>(
            fixture.payload, fixture.circuit, fixture.encrypted, evaluation,
            fixture.output_claim.point, prover_transcript);

        CHECK(proof.gate_mle_opening.has_value());
        CHECK(!proof.gate_mle_opening->claimed_values.empty());
        CHECK(proof.gate_mle_opening->claimed_values.size() ==
              expected_base_gate_claims(fixture.circuit));
        const BaseProofSizeBreakdown size = measure_proof_size(proof);
        CHECK(size.gate_mle_opening_bytes > 0);
        CHECK(size.total_bytes == size.statement_and_metadata_bytes +
                                      size.round_message_bytes +
                                      size.terminal_message_bytes +
                                      size.partial_gate_mle_bytes +
                                      size.gate_mle_opening_bytes);

        const auto client = make_client_setup<MockBackend>(
            fixture.public_setup, fixture.contexts.client);
        auto verifies = [&](const EncryptedBaseProof<MockBackend> &candidate) {
            Transcript transcript("test/base/outsourced/v1");
            return reference::verify_base<MockBackend>(
                fixture.payload, fixture.circuit,
                fixture.trace.layers.back(), client,
                fixture.trace.provenance, fixture.encrypted.trace_id,
                fixture.output_claim, candidate, transcript);
        };
        CHECK(verifies(proof));

        auto changed_claim = proof;
        changed_claim.gate_mle_opening->claimed_values.front() += Fpk::one();
        CHECK(!verifies(changed_claim));

        auto missing_opening = proof;
        missing_opening.gate_mle_opening.reset();
        CHECK(!verifies(missing_opening));
    });

    return runner.summary();
}
