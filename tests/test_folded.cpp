/// @file test_folded.cpp
/// @brief Focused LaminateFolded dense-reduction tests.

#include "test_helpers.hpp"
#include "packed_setup_fixture.hpp"

#include "laminate/fhe/mock_backend.hpp"
#include "laminate/fhe/storage/value_codec.hpp"
#include "laminate/gkr/detail/folded/reference/prover.hpp"
#include "laminate/gkr/detail/folded/verifier.hpp"
#include "laminate/gkr/detail/shared/dense_multiplication/geometry.hpp"
#include "laminate/gkr/detail/shared/dense_multiplication/source/file.hpp"
#include "laminate/payload/compiler.hpp"
#include "laminate/payload/trace/trace_crypto.hpp"
#include "laminate/poly/eq.hpp"
#include "laminate/protocol/packed/setup.hpp"
#include "laminate/protocol/metrics/proof_size.hpp"

#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

using namespace laminate;
using namespace laminate::fhe;
using namespace laminate::gkr;
using namespace laminate::payload;
using namespace laminate::protocol;

namespace {

PayloadCircuit dense_payload(std::size_t slot_count) {
    PayloadBuilder builder(PayloadShape::wide(slot_count), 4);
    const auto first = builder.mul(0, 1);
    const auto second = builder.mul(2, 3);
    const auto repeated = builder.mul(0, 1);
    const auto square = builder.mul(0, 0);
    builder.set_outputs({first, second, repeated, square});
    return builder.finish();
}

PayloadCircuit singleton_dense_payload(std::size_t slot_count) {
    PayloadBuilder builder(PayloadShape::wide(slot_count), 1);
    builder.set_outputs({builder.mul(0, 0)});
    return builder.finish();
}

SlotVector slots(std::size_t count, std::size_t seed) {
    SlotVector result;
    result.reserve(count);
    for (std::size_t slot = 0; slot < count; ++slot) {
        result.emplace_back(seed + 5U * slot + slot * slot);
    }
    return result;
}

struct Fixture {
    PayloadCircuit payload;
    LayeredCircuit circuit;
    PlainTrace trace;
    PublicSetup public_setup;
    MockBackend::Contexts contexts;
    EncryptedTrace<MockBackend> encrypted;
    SingleClaim output_claim;

    explicit Fixture(std::size_t slot_count = 16)
        : Fixture(dense_payload(slot_count),
                  std::vector<SlotVector>{slots(slot_count, 7),
                                          slots(slot_count, 29),
                                          slots(slot_count, 53),
                                          slots(slot_count, 79)},
                  slot_count) {}

    Fixture(PayloadCircuit input_payload,
            std::vector<SlotVector> inputs, std::size_t slot_count)
        : payload(std::move(input_payload)), circuit(compile(payload)),
          trace(synthesize_trace(payload, circuit, inputs)),
          public_setup(make_direct_setup(payload, circuit)),
          contexts(MockBackend::create(MockParameters{
              .slot_count = slot_count,
              .fresh_rns_limbs = 10,
              .bits_per_limb = 60,
          })),
          encrypted(encrypt_compact_synthetic_trace<MockBackend>(
              contexts.eval, contexts.client, payload, circuit, trace,
              TraceEncryptionPlan::uniform(
                  circuit,
                  kFoldedFixtureProofIngressRnsLimbs - 1U))),
          output_claim(make_layer_claim(
              trace.layers.front(),
              std::vector<Fpk>(
                  base_detail::layer_vars(circuit, 0),
                  Fpk::from_base(Fp(19))))) {
        MockBackend::preprocess_fixed_message_cells(contexts.eval);
    }
};

std::size_t multiplication_layer(const LayeredCircuit &circuit) {
    for (std::size_t layer = 0; layer + 1U < circuit.layers.size();
         ++layer) {
        if (layer_kind(circuit.layers[layer]) ==
            LayerKind::Multiplication) {
            return layer;
        }
    }
    throw std::logic_error("Folded test circuit has no multiplication layer");
}

bool verify_full(Fixture &fixture,
                 const EncryptedFoldedProof<MockBackend> &proof,
                 const SingleClaim &expected,
                 const PublicSetup *public_setup = nullptr) {
    const PublicSetup &setup =
        public_setup != nullptr ? *public_setup : fixture.public_setup;
    const auto client = make_client_setup<MockBackend>(
        setup, fixture.contexts.client);
    Transcript transcript("test/folded/full/v2");
    return folded_detail::verify_encrypted_gkr<MockBackend>(
        fixture.payload, fixture.circuit, fixture.trace.layers.back(),
        client, fixture.trace.provenance, fixture.encrypted.trace_id,
        expected, proof, transcript);
}

EncryptedFoldedProof<MockBackend> prove_full(
    Fixture &fixture, const PublicSetup &public_setup,
    std::shared_ptr<const gates::GateTableProverKey> gate_key = {}) {
    const auto evaluation = make_packed_evaluation_setup<MockBackend>(
        public_setup, fixture.contexts.eval, std::move(gate_key));
    Transcript transcript("test/folded/full/v2");
    return folded_detail::prove_folded_gkr_resident<MockBackend>(
        fixture.payload, fixture.circuit, fixture.encrypted, evaluation,
        fixture.output_claim.point, transcript,
        std::vector<std::size_t>(
            fixture.circuit.layers.size(),
            kFoldedFixtureProofIngressRnsLimbs));
}

std::vector<Fpk> boolean_point(std::size_t value,
                               std::size_t variables) {
    std::vector<Fpk> result(variables, Fpk::zero());
    for (std::size_t variable = 0; variable < variables; ++variable) {
        const std::size_t shift = variables - variable - 1U;
        result[variable] = Fpk::from_base(Fp((value >> shift) & 1U));
    }
    return result;
}

Fpk dense_round_value(std::span<const SlotVector> source,
                      std::span<const Fpk> output_point,
                      std::span<const Fpk> prefix,
                      const Fpk &round_value) {
    if (prefix.size() >= output_point.size()) {
        throw std::invalid_argument("dense test prefix is complete");
    }
    const std::size_t remaining =
        output_point.size() - prefix.size() - 1U;
    Fpk result = Fpk::zero();
    for (std::size_t suffix_index = 0;
         suffix_index < poly::hypercube_size(remaining);
         ++suffix_index) {
        const std::vector<Fpk> suffix =
            boolean_point(suffix_index, remaining);
        std::vector<Fpk> shared(prefix.begin(), prefix.end());
        shared.push_back(round_value);
        shared.insert(shared.end(), suffix.begin(), suffix.end());
        const std::vector<Fpk> left =
            ::laminate::gkr::detail::dense_multiplication_source_point(
                Fpk::zero(), shared);
        const std::vector<Fpk> right =
            ::laminate::gkr::detail::dense_multiplication_source_point(
                Fpk::one(), shared);
        const std::vector<Fpk> output_suffix(
            output_point.begin() +
                static_cast<std::ptrdiff_t>(prefix.size() + 1U),
            output_point.end());
        result += poly::eq_eval(output_suffix, suffix) *
                  evaluate_layer_mle(source, left) *
                  evaluate_layer_mle(source, right);
    }
    return result;
}

void check_resident_dense_rounds(
    Fixture &fixture,
    std::optional<std::size_t> unit_equality_coordinate) {
    const std::size_t layer = multiplication_layer(fixture.circuit);
    std::vector<Fpk> point;
    point.reserve(base_detail::layer_vars(fixture.circuit, layer));
    for (std::size_t variable = 0;
         variable < base_detail::layer_vars(fixture.circuit, layer);
         ++variable) {
        point.push_back(Fpk::from_base(Fp(31U + 17U * variable)));
    }
    if (unit_equality_coordinate) {
        point.at(*unit_equality_coordinate) = Fpk::one();
    }
    const SingleClaim claim =
        make_layer_claim(fixture.trace.layers[layer], point);

    std::vector<std::vector<std::uint8_t>> commitment_inputs;
    const PackedMessageCommitmentFunction<MockBackend> commitment =
        [&commitment_inputs](const FheValue<MockBackend> &message) {
            commitment_inputs.push_back(
                encode_canonical_fhe_value<MockBackend>(message));
            return hash_commit_packed_message<MockBackend>(message);
        };
    std::vector<RuntimeProgressEvent> progress_events;
    const RuntimeProgressCallback progress =
        [&progress_events](const RuntimeProgressEvent &event) {
            progress_events.push_back(event);
        };

    Transcript prover("test/folded/dense-rounds/v2");
    const auto proved =
        folded_detail::prove_multiplication_resident_dense<MockBackend>(
            fixture.contexts.eval, fixture.circuit, fixture.encrypted,
            layer, claim, prover, 0, commitment, progress);
    CHECK(proved.proof.rounds.size() == claim.point.size());
    CHECK(commitment_inputs.size() == proved.proof.rounds.size() + 1U);
    for (std::size_t round = 0; round < proved.proof.rounds.size();
         ++round) {
        CHECK(commitment_inputs[round] ==
              encode_canonical_fhe_value<MockBackend>(
                  proved.proof.rounds[round].packed_evaluations));
    }
    CHECK(commitment_inputs.back() ==
          encode_canonical_fhe_value<MockBackend>(
              proved.proof.packed_source_values));

    const std::size_t wire_variables =
        base_detail::ciphertext_index_variables(fixture.circuit, layer);
    const std::size_t live_pairs = ::laminate::gkr::detail::
        make_dense_multiplication_alias_plan(fixture.circuit, layer)
            .live_pair_count;
    std::vector<RuntimeProgressEvent> expected_progress;
    const auto add_span = [&expected_progress](RuntimeProgressEvent begin) {
        expected_progress.push_back(begin);
        begin.boundary = RuntimeProgressBoundary::End;
        expected_progress.push_back(begin);
    };
    for (std::size_t round = 0; round < wire_variables; ++round) {
        add_span(RuntimeProgressEvent{
            .boundary = RuntimeProgressBoundary::Begin,
            .stage = RuntimeProgressStage::
                FoldedMultiplicationSumcheckRound,
            .layer_kind = RuntimeProgressLayerKind::Multiplication,
            .coordinate_domain =
                RuntimeProgressCoordinateDomain::CiphertextIndex,
            .reduction_layer = layer,
            .source_layer = layer + 1U,
            .round = round,
            .round_count = claim.point.size(),
            .work_units = 2U * live_pairs,
        });
    }
    add_span(RuntimeProgressEvent{
        .boundary = RuntimeProgressBoundary::Begin,
        .stage = RuntimeProgressStage::
            FoldedMultiplicationSlotCheckpoint,
        .layer_kind = RuntimeProgressLayerKind::Multiplication,
        .coordinate_domain =
            RuntimeProgressCoordinateDomain::SlotIndex,
        .reduction_layer = layer,
        .source_layer = layer + 1U,
        .checkpoint_layer = layer + 1U,
        .work_units = 2U * live_pairs,
    });
    for (std::size_t round = wire_variables; round < claim.point.size();
         ++round) {
        add_span(RuntimeProgressEvent{
            .boundary = RuntimeProgressBoundary::Begin,
            .stage = RuntimeProgressStage::
                FoldedMultiplicationSumcheckRound,
            .layer_kind = RuntimeProgressLayerKind::Multiplication,
            .coordinate_domain =
                RuntimeProgressCoordinateDomain::SlotIndex,
            .reduction_layer = layer,
            .source_layer = layer + 1U,
            .round = round,
            .round_count = claim.point.size(),
            .work_units = 2U,
        });
    }
    CHECK(progress_events == expected_progress);

    Transcript replay("test/folded/dense-rounds/v2");
    gkr::detail::observe_packed_reduction_begin<
        ProtocolVariant::LaminateFolded>(
        layer, LayerKind::Multiplication, proved.proof.rounds.size(), replay);
    std::vector<Fpk> prefix;
    for (std::size_t round = 0; round < proved.proof.rounds.size();
         ++round) {
        gkr::detail::observe_packed_round<
            ProtocolVariant::LaminateFolded, MockBackend>(
            layer, round, proved.proof.rounds[round], replay);
        const std::vector<Fpk> actual =
            unpack_extension_scalars<MockBackend>(
                fixture.contexts.client,
                proved.proof.rounds[round].packed_evaluations, 2);
        const Fpk primary = ::laminate::gkr::detail::
            dense_multiplication_primary_point(claim.point[round]);
        CHECK(actual[0] == dense_round_value(
                               fixture.trace.layers[layer + 1U],
                               claim.point, prefix, primary));
        CHECK(actual[1] == dense_round_value(
                               fixture.trace.layers[layer + 1U],
                               claim.point, prefix,
                               Fpk::from_base(Fp(2))));
        prefix.push_back(replay.challenge_fpk());
    }

    gkr::detail::FixedMessageReader<MockBackend> reader(
        fixture.contexts.client);
    Transcript verifier("test/folded/dense-rounds/v2");
    const auto next =
        folded_detail::verify_multiplication_reduction<MockBackend>(
        reader, fixture.circuit, layer, claim, proved.proof, verifier);
    CHECK(next.has_value());
    gkr::detail::observe_packed_terminal<
        ProtocolVariant::LaminateFolded, MockBackend>(
            layer, proved.proof.packed_source_values, replay);
    const Fpk selector = replay.challenge_fpk();
    CHECK(next->point.front() == selector);
    CHECK(std::vector<Fpk>(next->point.begin() + 1, next->point.end()) ==
          prefix);
    CHECK(next->point == proved.next_claim.point);
    CHECK(*next == make_layer_claim(fixture.trace.layers[layer + 1U],
                                    next->point));
}

} // namespace

int main() {
    test::Runner runner("test_folded");

    runner.run("compiler emits one dense halves relation with aliases", [] {
        Fixture fixture;
        const std::size_t layer = multiplication_layer(fixture.circuit);
        const auto &multiplication =
            std::get<MultiplicationLayer>(fixture.circuit.layers[layer]);
        const std::size_t width = multiplication.dimensions.padded_size;
        CHECK(layer_dimensions(fixture.circuit.layers[layer + 1U])
                  .padded_size == 2U * width);
        for (std::size_t gate = 0; gate < width; ++gate) {
            CHECK(multiplication.gates[gate].origin !=
                  GateOrigin::Padding ||
                  gate >= multiplication.dimensions.logical_size);
        }
        const auto aliases = ::laminate::gkr::detail::
            make_dense_multiplication_alias_plan(fixture.circuit, layer);
        CHECK(aliases.pair_count == width);
        CHECK(aliases.has_aliases());
        CHECK(fixture.encrypted.layers[layer + 1U].wires.size() ==
              aliases.operands.size());
        CHECK(aliases.operands.size() < 2U * aliases.live_pair_count);
    });

    runner.run("resident dense rounds match direct enumeration", [] {
        Fixture fixture;
        check_resident_dense_rounds(fixture, std::nullopt);
    });

    runner.run("resident dense ciphertext-index rounds handle tau equal to one", [] {
        Fixture fixture;
        check_resident_dense_rounds(fixture, 0U);
    });

    runner.run("resident dense slot rounds handle tau equal to one", [] {
        Fixture fixture;
        const std::size_t layer = multiplication_layer(fixture.circuit);
        const std::size_t first_slot =
            base_detail::ciphertext_index_variables(
                fixture.circuit, layer);
        CHECK(first_slot < base_detail::layer_vars(fixture.circuit, layer));
        check_resident_dense_rounds(fixture, first_slot);
    });

    runner.run("resident dense rounds support zero wire variables", [] {
        constexpr std::size_t slot_count = 16;
        Fixture fixture(singleton_dense_payload(slot_count),
                        {slots(slot_count, 7)}, slot_count);
        const std::size_t layer = multiplication_layer(fixture.circuit);
        CHECK(payload::layer_dimensions(fixture.circuit.layers[layer])
                  .padded_size == 1U);
        CHECK(base_detail::ciphertext_index_variables(
                  fixture.circuit, layer) == 0U);
        check_resident_dense_rounds(fixture, std::nullopt);
    });

    runner.run("complete Folded proof verifies with dense round counts", [] {
        Fixture fixture;
        MockBackend::reset_counts(fixture.contexts.eval);
        const auto proof = prove_full(fixture, fixture.public_setup);
        CHECK(MockBackend::counts(fixture.contexts.eval).decrypt == 0);
        CHECK(proof.header.version == kEncryptedFoldedProofVersion);
        CHECK(verify_full(fixture, proof, fixture.output_claim));

        for (std::size_t layer = 0; layer < proof.reductions.size();
             ++layer) {
            if (const auto *multiplication = std::get_if<
                    EncryptedFoldedMultiplicationLayerReduction<MockBackend>>(
                    &proof.reductions[layer])) {
                CHECK(multiplication->rounds.size() ==
                      base_detail::layer_vars(fixture.circuit, layer));
            }
        }
        const FoldedProofSizeBreakdown size =
            measure_proof_size<MockBackend>(proof);
        CHECK(size.total_bytes ==
              encode_canonical<MockBackend>(proof).size());
        CHECK(size.total_bytes == size.statement_and_metadata_bytes +
                                      size.round_message_bytes +
                                      size.terminal_message_bytes);

        auto changed = proof;
        auto &first = std::get<EncryptedFoldedAffineLayerReduction<MockBackend>>(
            changed.reductions.front());
        first.rounds.front().packed_evaluations.ciphertext().slots[0] +=
            Fp::one();
        CHECK(!verify_full(fixture, changed, fixture.output_claim));
    });

    runner.run("affine round-count rejection precedes transcript binding",
               [] {
                   Fixture fixture;
                   const auto proof =
                       prove_full(fixture, fixture.public_setup);
                   auto malformed = std::get<
                       EncryptedFoldedAffineLayerReduction<MockBackend>>(
                       proof.reductions.front());
                   CHECK(!malformed.rounds.empty());
                   malformed.rounds.pop_back();

                   gates::DirectGateMle gate_mles(fixture.circuit);
                   gkr::detail::FixedMessageReader<MockBackend> reader(
                       fixture.contexts.client);
                   Transcript rejected(
                       "test/folded/affine-shape-rejection/v1");
                   Transcript pristine(
                       "test/folded/affine-shape-rejection/v1");
                   CHECK(!folded_detail::verify_affine_reduction<MockBackend>(
                              reader, fixture.circuit, 0,
                              fixture.output_claim, malformed, gate_mles,
                              rejected)
                              .has_value());
                   CHECK(rejected.challenge_fpk() ==
                         pristine.challenge_fpk());
               });

    runner.run("outsourced Folded claims cover affine gates only", [] {
        Fixture fixture;
        auto key = std::make_shared<gates::GateTableProverKey>(
            gates::preprocess_gate_tables(fixture.circuit,
                                          gates::GateTableSet::Wide));
        const PublicSetup outsourced = make_outsourced_gate_setup(
            fixture.payload, fixture.circuit, key->verifier);
        const auto proof = prove_full(fixture, outsourced, key);
        CHECK(proof.gate_mle_opening.has_value());
        CHECK(!proof.gate_mle_opening->claimed_values.empty());
        CHECK(verify_full(fixture, proof, fixture.output_claim,
                          &outsourced));

        auto changed = proof;
        changed.gate_mle_opening->claimed_values.front() += Fpk::one();
        CHECK(!verify_full(fixture, changed, fixture.output_claim,
                           &outsourced));
    });

    return runner.summary();
}
