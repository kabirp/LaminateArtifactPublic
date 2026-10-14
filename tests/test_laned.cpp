/// @file test_laned.cpp
/// @brief Mock-encrypted LaminateLaned tests.

#include "test_helpers.hpp"
#include "gkr_reference_helpers.hpp"
#include "packed_setup_fixture.hpp"

#include "laminate/fhe/mock_backend.hpp"
#include "laminate/gkr/detail/base/claims/evaluation.hpp"
#include "laminate/gkr/detail/laned/reference/prover.hpp"
#include "laminate/gkr/detail/laned/verifier.hpp"
#include "laminate/gkr/detail/shared/dense_multiplication/geometry.hpp"
#include "laminate/gkr/detail/shared/packed/message_reader.hpp"
#include "laminate/gkr/detail/shared/packed/transcript.hpp"
#include "laminate/gkr/laned.hpp"
#include "laminate/payload/compiler.hpp"
#include "laminate/payload/laned_fhe_evaluator.hpp"
#include "laminate/payload/input_encryption.hpp"
#include "laminate/payload/trace/trace_crypto.hpp"
#include "laminate/poly/eq.hpp"
#include "laminate/protocol/laned.hpp"
#include "laminate/protocol/metrics/proof_size.hpp"
#include "laminate/protocol/reference/laned.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <vector>

using namespace laminate;
using namespace laminate::fhe;
using namespace laminate::gkr;
using namespace laminate::payload;
using namespace laminate::protocol;

namespace {

template <typename Proof>
concept HasPlaintextOutputClaim = requires(Proof proof) {
    proof.output_claim;
};

static_assert(!HasPlaintextOutputClaim<EncryptedLanedProof<MockBackend>>);

SlotVector lanes(std::size_t count, std::size_t seed) {
    SlotVector result;
    result.reserve(count);
    for (std::size_t lane = 0; lane < count; ++lane) {
        result.emplace_back(seed + 7 * lane + lane * lane);
    }
    return result;
}

PayloadCircuit make_payload(std::size_t lane_count, std::size_t slot_count) {
    const std::size_t output_count =
        std::max<std::size_t>(4, slot_count / lane_count);
    PayloadBuilder builder(PayloadShape::laned(lane_count, slot_count),
                           4 * output_count);
    std::vector<WireId> first_layer;
    for (std::size_t product = 0; product < 2 * output_count; ++product) {
        first_layer.push_back(
            builder.mul(2 * product, 2 * product + 1));
    }
    std::vector<WireId> outputs;
    for (std::size_t output = 0; output < output_count; ++output) {
        outputs.push_back(builder.mul(first_layer[2 * output],
                                      first_layer[2 * output + 1]));
    }
    builder.set_outputs(outputs);
    return builder.finish();
}

LanedSetup make_test_laned_packing_setup(
    const MockBackend::EvalContext &eval, const LayeredCircuit &circuit) {
    auto parameters = packing::selected_lazy_ternary_parameters();
    parameters.repetitions = 1;
    return LanedSetup{make_transcript_packing_spartan_setup(
        PackingGkrVariant::Laned, MockBackend::slot_count(eval),
        laned_bhip_round_count(circuit),
        {.centered_coefficients =
             [&eval](const SlotVector &slots) {
                 return MockBackend::encode_centered_plaintext_coefficients(
                     eval, slots);
             },
         .native_ntt =
             [&eval](std::span<const std::int64_t> coefficients) {
                 return MockBackend::encode_lowest_plaintext_ntt_coordinates(
                     eval, coefficients);
             }},
        parameters,
        spartan::BaseFoldPcsParameters{.log_rate = 1, .query_count = 1},
        spartan::Options{
            .matrix_evaluation =
                spartan::MatrixEvaluationMode::CommittedFactored}),
        std::vector<std::size_t>(
            circuit.layers.size(),
            kLanedFixtureProofIngressRnsLimbs)};
}

void normalize_laned_proof_sources(
    MockBackend::EvalContext &eval,
    EncryptedTrace<MockBackend> &trace,
    std::span<const std::size_t> ingress_rns_limbs_by_layer) {
    if (trace.layers.size() != ingress_rns_limbs_by_layer.size()) {
        throw std::invalid_argument(
            "test proof-ingress schedule has the wrong layer count");
    }
    // Layer zero is the payload output/decryption ciphertext. Reverse GKR
    // starts from layer one, so only the actual proof sources are normalized.
    for (std::size_t layer = 1; layer < trace.layers.size(); ++layer) {
        for (auto &value : trace.layers[layer].wires) {
            if (value.is_encrypted()) {
                mod_switch_to_rns_limb_count<MockBackend>(
                    eval, value.ciphertext(),
                    ingress_rns_limbs_by_layer[layer]);
            }
        }
        trace.layers[layer].required_mult_depth =
            ingress_rns_limbs_by_layer[layer] - 1U;
    }
}

void test_fhe_evaluated_payload_proves_and_verifies() {
    constexpr std::size_t kLanes = 4;
    constexpr std::size_t kSlots = 32;
    constexpr std::size_t kOutputCount = kSlots / kLanes;
    const Fp multiplier(3);
    PayloadBuilder builder(PayloadShape::laned(kLanes, kSlots),
                           2 * kOutputCount);
    const std::size_t multiplier_index =
        builder.add_scalar_plaintext(multiplier);
    std::vector<WireId> products;
    for (std::size_t output = 0; output < kOutputCount; ++output) {
        const WireId product =
            builder.mul(2 * output, 2 * output + 1);
        products.push_back(builder.mul_plain(product, multiplier_index));
    }
    builder.set_outputs(products);
    const PayloadCircuit payload = builder.finish();
    const LayeredCircuit circuit = compile(payload);
    std::vector<SlotVector> inputs;
    for (std::size_t input = 0; input < 2 * kOutputCount; ++input) {
        inputs.push_back(lanes(kLanes, 5 + 26 * input));
    }
    const PlainTrace plain = synthesize_trace(payload, circuit, inputs);

    auto contexts = MockBackend::create(MockParameters{
        .slot_count = kSlots,
        .fresh_rns_limbs = 14,
        .bits_per_limb = 300,
    });
    const auto encrypted_inputs =
        encrypt_laned_payload_inputs<MockBackend>(contexts.client, payload,
                                                  inputs);
    const LanedSetup packing_setup =
        make_test_laned_packing_setup(contexts.eval, circuit);
    const FheEvaluationPlan evaluation_plan =
        apply_packed_proof_ingress_schedule(
            circuit,
            FheEvaluationPlan::without_payload_switches(circuit, 9),
            packing_setup);

    MockBackend::reset_counts(contexts.eval);
    EncryptedTrace<MockBackend> trace =
        evaluate_laned_fhe_trace<MockBackend>(
            contexts.eval, payload, circuit, encrypted_inputs,
            evaluation_plan);
    CHECK(MockBackend::counts(contexts.eval).decrypt == 0);
    CHECK(MockBackend::counts(contexts.eval).mul_plain_scalar ==
          kOutputCount);
    CHECK(MockBackend::counts(contexts.eval).mul_plain_vector == 0);
    CHECK(trace.provenance == TraceProvenance::FheEvaluated);
    CHECK(trace.trace_id == fhe_evaluated_trace_id<MockBackend>(
                                  payload, circuit, encrypted_inputs));

    MockBackend::reset_counts(contexts.eval);
    const std::vector<SlotVector> output_layer =
        decrypt_trace_layer<MockBackend>(contexts.client, circuit, trace, 0);
    CHECK(MockBackend::counts(contexts.eval).decrypt ==
          trace.layers.front().wires.size());
    CHECK(output_layer.size() == kOutputCount);
    for (std::size_t output = 0; output < kOutputCount; ++output) {
        SlotVector expected_output(kLanes);
        for (std::size_t lane = 0; lane < kLanes; ++lane) {
            expected_output[lane] =
                inputs[2 * output][lane] * inputs[2 * output + 1][lane] *
                multiplier;
        }
        CHECK(output_layer[output] == expected_output);
    }

    const PublicSetup public_setup = make_direct_setup(payload, circuit);
    const auto evaluation = make_packed_evaluation_setup<MockBackend>(
        public_setup, contexts.eval);
    const std::vector<Fpk> claim_point(
        laned_layer_variables(circuit, 0), Fpk::from_base(Fp(19)));
    const SingleClaim output_claim = make_packed_laned_claim(
        plain.layers.front(), laned_layout(circuit, 0), claim_point);
    MockBackend::reset_counts(contexts.eval);
    Transcript prover_transcript("test/laned/fhe-evaluated/v1");
    const LaminateLanedProof<MockBackend> proof =
        protocol::reference::prove_laned<MockBackend>(
            payload, circuit, trace, evaluation, packing_setup,
            output_claim.point, prover_transcript);
    CHECK(MockBackend::counts(contexts.eval).decrypt == 0);
    const auto client = make_client_setup<MockBackend>(
        public_setup, contexts.client);
    const LanedVerifierSetup compact_setup = verifier_setup(packing_setup);
    const std::vector<SlotVector> input_layer =
        make_plain_input_layer(circuit, inputs);
    Transcript verifier_transcript("test/laned/fhe-evaluated/v1");
    CHECK(verify_laned<MockBackend>(
        payload, circuit, input_layer, contexts.eval, compact_setup, client,
        TraceProvenance::FheEvaluated, trace.trace_id, output_claim, proof,
        verifier_transcript));
}

struct Fixture {
    PayloadCircuit payload;
    LayeredCircuit circuit;
    PlainTrace trace;
    PublicSetup public_setup;
    MockBackend::Contexts contexts;
    EncryptedTrace<MockBackend> encrypted;
    SingleClaim output_claim;

    explicit Fixture(std::size_t lane_count = 4,
                     std::size_t slot_count = 16)
        : payload(make_payload(lane_count, slot_count)),
          circuit(compile(payload)),
          trace(synthesize_trace(payload, circuit, [&] {
              std::vector<SlotVector> result;
              for (std::size_t input = 0; input < payload.input_count;
                   ++input) {
                  result.push_back(lanes(lane_count, 3 + 26 * input));
              }
              return result;
          }())),
          public_setup(make_direct_setup(payload, circuit)),
          contexts(MockBackend::create(MockParameters{
              .slot_count = slot_count,
              .fresh_rns_limbs = 12,
              .bits_per_limb = 60,
          })),
          encrypted(encrypt_compact_synthetic_trace<MockBackend>(
              contexts.eval, contexts.client, payload, circuit, trace,
              TraceEncryptionPlan::uniform(circuit, 9))),
          output_claim(make_packed_laned_claim(
              trace.layers.front(), laned_layout(circuit, 0),
              std::vector<Fpk>(laned_layer_variables(circuit, 0),
                               Fpk::from_base(Fp(19))))) {
        MockBackend::preprocess_fixed_message_cells(contexts.eval);
        const std::vector<std::size_t> ingress(
            circuit.layers.size(),
            kLanedFixtureProofIngressRnsLimbs);
        normalize_laned_proof_sources(contexts.eval, encrypted, ingress);
    }
};

std::shared_ptr<const gates::GateTableProverKey>
enable_outsourced_gate_mles(Fixture &fixture) {
    auto key = std::make_shared<gates::GateTableProverKey>(
        gates::preprocess_gate_tables(fixture.circuit,
                                      gates::GateTableSet::Laned));
    fixture.public_setup = make_outsourced_gate_setup(
        fixture.payload, fixture.circuit, key->verifier);
    return key;
}

bool verify(Fixture &fixture,
            const EncryptedLanedProof<MockBackend> &proof,
            const SingleClaim &expected) {
    const auto client = make_client_setup<MockBackend>(
        fixture.public_setup, fixture.contexts.client);
    Transcript transcript("test/laned/e2e/v1");
    return laned_detail::verify_encrypted_gkr<MockBackend>(
        fixture.payload, fixture.circuit, fixture.trace.layers.back(), client,
        fixture.trace.provenance, fixture.encrypted.trace_id, expected, proof,
        transcript);
}

EncryptedLanedProof<MockBackend> prove(Fixture &fixture) {
    const auto evaluation = make_packed_evaluation_setup<MockBackend>(
        fixture.public_setup, fixture.contexts.eval);
    Transcript transcript("test/laned/e2e/v1");
    std::vector<std::size_t> ingress;
    ingress.reserve(fixture.encrypted.layers.size());
    for (const auto &layer : fixture.encrypted.layers) {
        ingress.push_back(layer.wires.front().ciphertext().rns_limbs);
    }
    return laned_detail::prove_laned_gkr_resident<MockBackend>(
        fixture.payload, fixture.circuit, fixture.encrypted, evaluation,
        ingress, fixture.output_claim.point, transcript);
}

Fpk weighted_layer_mle(const Fixture &fixture, std::size_t layer,
                       const packing::LanedPackingLayout &layout,
                       std::span<const Fpk> lane_point,
                       std::span<const Fpk> point) {
    const std::size_t ciphertext_variables =
        std::bit_width(layout.padded_ciphertext_count) - 1U;
    const std::vector<Fpk> ciphertext_point(
        point.begin(), point.begin() +
                           static_cast<std::ptrdiff_t>(ciphertext_variables));
    const std::vector<Fpk> slot_point(
        point.begin() + static_cast<std::ptrdiff_t>(ciphertext_variables),
        point.end());
    const std::vector<Fpk> ciphertext_weights =
        poly::eq_evaluations(ciphertext_point);
    const std::vector<Fpk> slot_weights = poly::eq_evaluations(slot_point);
    const std::size_t lane_variables =
        std::bit_width(layout.lane_count) - 1U;
    Fpk result = Fpk::zero();
    for (std::size_t wire = 0; wire < fixture.trace.layers[layer].size();
         ++wire) {
        for (std::size_t lane = 0; lane < layout.lane_count; ++lane) {
            const packing::LanedPackedAddress address =
                layout.address(wire, lane);
            const Fpk lazy_weight = poly::eq_eval(
                std::vector<Fpk>(lane_point.begin(), lane_point.end()),
                test::hypercube_vertex(lane, lane_variables));
            result += ciphertext_weights[address.ciphertext] *
                      slot_weights[address.slot] * lazy_weight *
                      Fpk::from_base(fixture.trace.layers[layer][wire][lane]);
        }
    }
    return result;
}

std::array<Fpk, 2> expected_affine_round(
    const Fixture &fixture, std::size_t layer, const LayerClaim &claim,
    std::span<const Fpk> lane_point, std::span<const Fpk> prefix) {
    const gates::DirectGateMle provider(fixture.circuit);
    const auto output_layout = laned_layout(fixture.circuit, layer);
    const auto source_layout = laned_layout(fixture.circuit, layer + 1);
    const std::size_t variables = laned_layer_variables(
        fixture.circuit, layer + 1);
    const std::array<Fpk, 2> round_values{
        Fpk::one(), Fpk::from_base(Fp(2))};
    std::array<Fpk, 2> result{Fpk::zero(), Fpk::zero()};
    for (std::size_t evaluation = 0; evaluation < 2; ++evaluation) {
        std::vector<Fpk> bound(prefix.begin(), prefix.end());
        bound.push_back(round_values[evaluation]);
        const std::size_t remaining = variables - bound.size();
        for (std::size_t suffix = 0;
             suffix < poly::hypercube_size(remaining); ++suffix) {
            const std::vector<Fpk> point = base_detail::concatenate(
                bound, test::hypercube_vertex(suffix, remaining));
            result[evaluation] +=
                laned_detail::affine_wire_at(
                    provider, layer, output_layout, source_layout, claim,
                    point) *
                weighted_layer_mle(fixture, layer + 1, source_layout,
                                   lane_point, point);
        }
    }
    return result;
}

Fpk expected_multiplication_value(const Fixture &fixture, std::size_t layer,
                                  const SingleClaim &claim,
                                  std::span<const Fpk> prefix,
                                  const Fpk &round_value) {
    std::vector<Fpk> bound(prefix.begin(), prefix.end());
    bound.push_back(round_value);
    const std::size_t variables = laned_layer_variables(
        fixture.circuit, layer);
    const std::size_t remaining = variables - bound.size();
    const std::vector<Fpk> gamma_suffix(
        claim.point.begin() + static_cast<std::ptrdiff_t>(bound.size()),
        claim.point.end());
    const auto source_layout = laned_layout(fixture.circuit, layer + 1);
    Fpk result = Fpk::zero();
    for (std::size_t suffix = 0;
         suffix < poly::hypercube_size(remaining); ++suffix) {
        const std::vector<Fpk> boolean =
            test::hypercube_vertex(suffix, remaining);
        const std::vector<Fpk> point =
            base_detail::concatenate(bound, boolean);
        std::vector<Fpk> left_point;
        left_point.reserve(point.size() + 1);
        left_point.push_back(Fpk::zero());
        left_point.insert(left_point.end(), point.begin(), point.end());
        std::vector<Fpk> right_point = left_point;
        right_point.front() = Fpk::one();
        result += poly::eq_eval(gamma_suffix, boolean) *
                  evaluate_packed_laned_layer(
                      fixture.trace.layers[layer + 1], source_layout,
                      left_point) *
                  evaluate_packed_laned_layer(
                      fixture.trace.layers[layer + 1], source_layout,
                      right_point);
    }
    return result;
}

void check_every_round(Fixture &fixture,
                       const EncryptedLanedProof<MockBackend> &proof) {
    Transcript replay("test/laned/e2e/v1");
    observe_proof_header(proof.header, replay);
    gates::observe_gate_mle_setup(fixture.public_setup, replay);
    base_detail::observe_output_point(fixture.output_claim.point, replay);
    LayerClaim current = fixture.output_claim;

    for (std::size_t layer = 0; layer < proof.reductions.size(); ++layer) {
        const LayerKind kind = layer_kind(fixture.circuit.layers[layer]);
        if (kind == LayerKind::Affine) {
            const auto &reduction =
                std::get<EncryptedLanedAffineLayerReduction<MockBackend>>(
                    proof.reductions[layer]);
            const auto output_layout = laned_layout(fixture.circuit, layer);
            const auto source_layout =
                laned_layout(fixture.circuit, layer + 1);
            const std::vector<Fpk> lane_point =
                laned_detail::common_lane_point(output_layout, current);
            const std::size_t lane_begin =
                reduction.rounds.size() - lane_point.size();
            ::laminate::gkr::detail::observe_packed_reduction_begin<
                ProtocolVariant::LaminateLaned>(
                layer, kind, reduction.rounds.size(), replay);
            std::vector<Fpk> prefix;
            for (std::size_t round = 0; round < reduction.rounds.size();
                 ++round) {
                const auto actual = unpack_extension_scalars<MockBackend>(
                    fixture.contexts.client,
                    reduction.rounds[round].packed_evaluations, 2);
                const auto expected = expected_affine_round(
                    fixture, layer, current, lane_point, prefix);
                CHECK(actual[0] == expected[0]);
                CHECK(actual[1] == expected[1]);
                ::laminate::gkr::detail::observe_packed_round<
                    ProtocolVariant::LaminateLaned, MockBackend>(
                        layer, round, reduction.rounds[round], replay);
                prefix.push_back(
                    round < lane_begin
                        ? replay.challenge_fpk()
                        : laned_detail::challenge_hadamard_safe(
                              replay, lane_point[round - lane_begin]));
            }
            ::laminate::gkr::detail::observe_packed_terminal<
                ProtocolVariant::LaminateLaned, MockBackend>(
                    layer, reduction.packed_terminal_value, replay);
            const Fpk terminal =
                unpack_extension_scalars<MockBackend>(
                    fixture.contexts.client,
                    reduction.packed_terminal_value, 1)
                    .front();
            CHECK(terminal == weighted_layer_mle(
                                  fixture, layer + 1, source_layout,
                                  lane_point, prefix));
            const std::vector<Fpk> raw_lane(
                prefix.begin() + static_cast<std::ptrdiff_t>(lane_begin),
                prefix.end());
            const auto transform =
                laned_detail::hadamard_transform(lane_point, raw_lane);
            std::copy(transform.point.begin(), transform.point.end(),
                      prefix.begin() +
                          static_cast<std::ptrdiff_t>(lane_begin));
            current = SingleClaim{
                prefix,
                evaluate_packed_laned_layer(
                    fixture.trace.layers[layer + 1], source_layout, prefix)};
        } else {
            const auto *single = std::get_if<SingleClaim>(&current);
            CHECK(single != nullptr);
            const auto &reduction =
                std::get<EncryptedLanedMultiplicationLayerReduction<MockBackend>>(
                    proof.reductions[layer]);
            ::laminate::gkr::detail::observe_packed_reduction_begin<
                ProtocolVariant::LaminateLaned>(
                layer, kind, reduction.rounds.size(), replay);
            std::vector<Fpk> prefix;
            for (std::size_t round = 0; round < reduction.rounds.size();
                 ++round) {
                const auto actual = unpack_extension_scalars<MockBackend>(
                    fixture.contexts.client,
                    reduction.rounds[round].packed_evaluations, 2);
                const Fpk primary = single->point[round].is_zero()
                                        ? Fpk::one()
                                        : Fpk::zero();
                CHECK(actual[0] == expected_multiplication_value(
                                       fixture, layer, *single, prefix,
                                       primary));
                CHECK(actual[1] == expected_multiplication_value(
                                       fixture, layer, *single, prefix,
                                       Fpk::from_base(Fp(2))));
                ::laminate::gkr::detail::observe_packed_round<
                    ProtocolVariant::LaminateLaned, MockBackend>(
                        layer, round, reduction.rounds[round], replay);
                prefix.push_back(replay.challenge_fpk());
            }
            ::laminate::gkr::detail::observe_packed_terminal<
                ProtocolVariant::LaminateLaned, MockBackend>(
                    layer, reduction.packed_source_values, replay);
            const auto terminal = unpack_extension_scalars<MockBackend>(
                fixture.contexts.client, reduction.packed_source_values, 2);
            const auto source_layout =
                laned_layout(fixture.circuit, layer + 1);
            std::vector<Fpk> left_point;
            left_point.reserve(prefix.size() + 1);
            left_point.push_back(Fpk::zero());
            left_point.insert(left_point.end(), prefix.begin(), prefix.end());
            std::vector<Fpk> right_point = left_point;
            right_point.front() = Fpk::one();
            CHECK(terminal[0] == evaluate_packed_laned_layer(
                                     fixture.trace.layers[layer + 1],
                                     source_layout, left_point));
            CHECK(terminal[1] == evaluate_packed_laned_layer(
                                     fixture.trace.layers[layer + 1],
                                     source_layout, right_point));
            const Fpk selector = replay.challenge_fpk();
            std::vector<Fpk> next_point = left_point;
            next_point.front() = selector;
            const Fpk next_value = (Fpk::one() - selector) * terminal[0] +
                                   selector * terminal[1];
            CHECK(next_value == evaluate_packed_laned_layer(
                fixture.trace.layers[layer + 1], source_layout, next_point));
            current = SingleClaim{std::move(next_point), next_value};
        }
    }
    const auto *terminal = std::get_if<SingleClaim>(&current);
    CHECK(terminal != nullptr);
    CHECK(terminal->value == evaluate_packed_laned_layer(
                                 fixture.trace.layers.back(),
                                 laned_layout(fixture.circuit,
                                              fixture.circuit.layers.size() -
                                                  1),
                                 terminal->point));
}

std::size_t first_multiplication_layer(const LayeredCircuit &circuit) {
    for (std::size_t layer = 0; layer + 1 < circuit.layers.size(); ++layer) {
        if (layer_kind(circuit.layers[layer]) == LayerKind::Multiplication) {
            return layer;
        }
    }
    throw std::logic_error("test fixture has no multiplication layer");
}

std::size_t maximum_slot_round_depth(Fixture &fixture) {
    const std::size_t layer = first_multiplication_layer(fixture.circuit);
    std::vector<Fpk> point(laned_layer_variables(fixture.circuit, layer),
                           Fpk::from_base(Fp(47)));
    const SingleClaim claim = make_packed_laned_claim(
        fixture.trace.layers[layer], laned_layout(fixture.circuit, layer),
        std::move(point));
    Transcript transcript("test/laned/depth/v1");
    const auto proved =
        laned_detail::prove_multiplication_resident_reference<MockBackend>(
        fixture.contexts.eval, fixture.circuit, fixture.encrypted, layer,
        claim, transcript,
        fixture.encrypted.layers[layer + 1U]
            .wires.front().ciphertext().rns_limbs);
    const std::size_t packed_variables =
        std::bit_width(
            laned_layout(fixture.circuit, layer).padded_ciphertext_count) -
        1U;
    std::size_t maximum = 0;
    for (std::size_t round = packed_variables;
         round < proved.proof.rounds.size(); ++round) {
        maximum = std::max(
            maximum,
            proved.proof.rounds[round]
                .packed_evaluations.ciphertext().depth_half_levels);
    }
    return maximum;
}

void run_end_to_end(std::size_t lane_count) {
    Fixture fixture(lane_count);
    MockBackend::reset_counts(fixture.contexts.eval);
    const auto proof = prove(fixture);
    CHECK(MockBackend::counts(fixture.contexts.eval).decrypt == 0);
    CHECK(proof.reductions.size() + 1 == fixture.circuit.layers.size());
    const LanedProofSizeBreakdown size =
        measure_proof_size<MockBackend>(proof);
    CHECK(size.base_ciphertexts > 0);
    CHECK(size.extension_ciphertexts == 0);
    CHECK(size.total_bytes ==
          encode_canonical<MockBackend>(proof).size());
    CHECK(size.total_bytes == size.statement_and_metadata_bytes +
                                  size.round_message_bytes +
                                  size.terminal_message_bytes);
    CHECK(verify(fixture, proof, fixture.output_claim));

    SingleClaim wrong_output = fixture.output_claim;
    wrong_output.value += Fpk::one();
    CHECK(!verify(fixture, proof, wrong_output));

    auto wrong_profile = proof;
    wrong_profile.header.profile.variant = ProtocolVariant::LaminateFolded;
    CHECK(!verify(fixture, wrong_profile, fixture.output_claim));
}

} // namespace

int main() {
    test::Runner runner("test_laned");

    runner.run("shared dense multiplication algebra matches Laned", [] {
        const auto dimensions =
            gkr::detail::DenseMultiplicationDimensions::create(4, 8, 16);
        CHECK(dimensions.ciphertext_index_variables == 2);
        CHECK(dimensions.slot_index_variables == 4);
        CHECK(dimensions.round_count() == 6);
        CHECK(dimensions.source_point_size() == 7);

        const Fpk at_zero = Fpk::from_base(Fp(5));
        const Fpk at_one = Fpk::from_base(Fp(11));
        const Fpk ordinary_tau = Fpk::from_base(Fp(7));
        const Fpk ordinary_running =
            (Fpk::one() - ordinary_tau) * at_zero +
            ordinary_tau * at_one;
        CHECK(gkr::detail::dense_multiplication_primary_point(ordinary_tau) ==
              Fpk::zero());
        const auto ordinary =
            gkr::detail::recover_dense_multiplication_endpoints(
                ordinary_running, ordinary_tau, at_zero);
        CHECK(ordinary.zero == at_zero);
        CHECK(ordinary.one == at_one);

        CHECK(gkr::detail::dense_multiplication_primary_point(Fpk::one()) ==
              Fpk::zero());
        const auto singular =
            gkr::detail::recover_dense_multiplication_endpoints(
                at_one, Fpk::one(), at_zero);
        CHECK(singular.zero == at_zero);
        CHECK(singular.one == at_one);

        CHECK(gkr::detail::dense_multiplication_primary_point(Fpk::zero()) ==
              Fpk::one());
        const auto zero =
            gkr::detail::recover_dense_multiplication_endpoints(
                at_zero, Fpk::zero(), at_one);
        CHECK(zero.zero == at_zero);
        CHECK(zero.one == at_one);

        const std::vector<Fpk> challenges{
            Fpk::from_base(Fp(13)), Fpk::from_base(Fp(17))};
        const Fpk left = Fpk::from_base(Fp(19));
        const Fpk right = Fpk::from_base(Fp(23));
        CHECK(gkr::detail::dense_multiplication_terminal_is_valid(
            left, right, left * right));
        CHECK(!gkr::detail::dense_multiplication_terminal_is_valid(
            left, right, left * right + Fpk::one()));

        // A zero equality prefix must not erase the terminal equation.
        const std::vector<Fpk> zero_output{Fpk::zero()};
        const std::vector<Fpk> one_challenge{Fpk::one()};
        CHECK(gkr::detail::dense_multiplication_equality(
                  zero_output, one_challenge).is_zero());
        CHECK(gkr::detail::dense_multiplication_terminal_is_valid(
            left, right, left * right));
        CHECK(!gkr::detail::dense_multiplication_terminal_is_valid(
            left + Fpk::one(), right, left * right));

        const std::vector<Fpk> source_point =
            gkr::detail::dense_multiplication_source_point(Fpk::one(),
                                                           challenges);
        CHECK(source_point.size() == challenges.size() + 1U);
        CHECK(source_point.front() == Fpk::one());
        CHECK(std::equal(challenges.begin(), challenges.end(),
                         source_point.begin() + 1));
    });

    runner.run("minimal laned input MLE uses one value per lane", [] {
        constexpr std::size_t kSlots = 16;
        constexpr std::size_t kLanes = 4;
        const SlotVector logical_input = lanes(kLanes, 41);
        const std::vector<SlotVector> input_layer{logical_input};
        const packing::LanedPackingLayout layout =
            packing::LanedPackingLayout::create(
                PayloadShape::laned(kLanes, kSlots), 1);
        const std::vector<Fpk> evaluation_point{
            Fpk::from_base(Fp(3)), Fpk::from_base(Fp(5)),
            Fpk::from_base(Fp(7)), Fpk::from_base(Fp(11))};

        CHECK(evaluate_prefix_input_mle(logical_input,
                                        evaluation_point) ==
              evaluate_packed_laned_layer(input_layer, layout,
                                           evaluation_point));
    });

    runner.run("B=1, partial B, and B=N proofs verify", [] {
        run_end_to_end(1);
        run_end_to_end(4);
        run_end_to_end(16);
    });

    runner.run("FHE-evaluated Laned payload proves and verifies",
               test_fhe_evaluated_payload_proves_and_verifies);

    runner.run("every encrypted round matches direct enumeration", [] {
        Fixture fixture;
        const auto proof = prove(fixture);
        check_every_round(fixture, proof);
    });

    runner.run("every reduction retains the full slot schedule", [] {
        Fixture fixture(4, 64);
        const auto proof = prove(fixture);
        CHECK(proof.reductions.size() + 1 ==
              fixture.circuit.layers.size());
        for (std::size_t layer = 0; layer < proof.reductions.size();
             ++layer) {
            if (const auto *affine = std::get_if<
                    EncryptedLanedAffineLayerReduction<MockBackend>>(
                    &proof.reductions[layer])) {
                CHECK(affine->rounds.size() ==
                      laned_layer_variables(fixture.circuit, layer + 1));
            } else {
                const auto &multiplication = std::get<
                    EncryptedLanedMultiplicationLayerReduction<MockBackend>>(
                    proof.reductions[layer]);
                CHECK(multiplication.rounds.size() ==
                      laned_layer_variables(fixture.circuit, layer));
            }
        }
    });

    runner.run("round and terminal mutations reject", [] {
        Fixture fixture;
        const auto proof = prove(fixture);
        auto changed_round = proof;
        auto &first = std::get<EncryptedLanedAffineLayerReduction<MockBackend>>(
            changed_round.reductions.front());
        first.rounds.front().packed_evaluations.ciphertext().slots[0] +=
            Fp::one();
        CHECK(!verify(fixture, changed_round, fixture.output_claim));

        auto changed_terminal = proof;
        auto &terminal =
            std::get<EncryptedLanedAffineLayerReduction<MockBackend>>(
                changed_terminal.reductions.front());
        terminal.packed_terminal_value.ciphertext().slots[0] +=
            Fp::one();
        CHECK(!verify(fixture, changed_terminal, fixture.output_claim));

        const auto client = make_client_setup<MockBackend>(
            fixture.public_setup, fixture.contexts.client);
        Digest wrong_trace = fixture.encrypted.trace_id;
        wrong_trace.front() ^= 1U;
        Transcript trace_transcript("test/laned/e2e/v1");
        CHECK(!laned_detail::verify_encrypted_gkr<MockBackend>(
            fixture.payload, fixture.circuit, fixture.trace.layers.back(),
            client, fixture.trace.provenance, wrong_trace,
            fixture.output_claim, proof, trace_transcript));

        Transcript wrong_domain("test/laned/wrong-domain/v1");
        CHECK(!laned_detail::verify_encrypted_gkr<MockBackend>(
            fixture.payload, fixture.circuit, fixture.trace.layers.back(),
            client, fixture.trace.provenance, fixture.encrypted.trace_id,
            fixture.output_claim, proof, wrong_domain));

        LayeredCircuit changed_gate = fixture.circuit;
        auto &output_layer =
            std::get<AffineLayer>(changed_gate.layers.front());
        CHECK(!output_layer.gates.front().terms.empty());
        output_layer.gates.front().terms.front().coefficient += Fp::one();
        Transcript gate_transcript("test/laned/e2e/v1");
        CHECK(!laned_detail::verify_encrypted_gkr<MockBackend>(
            fixture.payload, changed_gate, fixture.trace.layers.back(),
            client, fixture.trace.provenance, fixture.encrypted.trace_id,
            fixture.output_claim, proof, gate_transcript));
    });

    runner.run("Hadamard terminal transform is exact and skips singularity",
               [] {
                   const std::vector<Fpk> left{
                       Fpk::from_base(Fp(3)), Fpk::from_base(Fp(5))};
                   const std::vector<Fpk> right{
                       Fpk::from_base(Fp(7)), Fpk::from_base(Fp(11))};
                   const std::vector<Fpk> table{
                       Fpk::from_base(Fp(13)), Fpk::from_base(Fp(17)),
                       Fpk::from_base(Fp(19)), Fpk::from_base(Fp(23))};
                   const auto transform =
                       laned_detail::hadamard_transform(left, right);
                   const std::vector<Fpk> left_weights =
                       poly::eq_evaluations(left);
                   const std::vector<Fpk> right_weights =
                       poly::eq_evaluations(right);
                   const std::vector<Fpk> transformed_weights =
                       poly::eq_evaluations(transform.point);
                   Fpk hadamard = Fpk::zero();
                   Fpk transformed = Fpk::zero();
                   for (std::size_t index = 0; index < table.size();
                        ++index) {
                       hadamard += left_weights[index] *
                                   right_weights[index] * table[index];
                       transformed +=
                           transformed_weights[index] * table[index];
                   }
                   CHECK(hadamard == transform.factor * transformed);

                   Transcript probe("test/laned/singular-challenge/v1");
                   const Fpk first = probe.challenge_fpk();
                   const Fpk denominator =
                       Fpk::from_base(Fp(2)) * first - Fpk::one();
                   CHECK(!denominator.is_zero());
                   const Fpk singular_left =
                       (first - Fpk::one()) * denominator.inverse();
                   CHECK(laned_detail::hadamard_factor(singular_left, first)
                             .is_zero());
                   Transcript replay("test/laned/singular-challenge/v1");
                   const Fpk accepted =
                       laned_detail::challenge_hadamard_safe(replay,
                                                            singular_left);
                   CHECK(accepted != first);
                   CHECK(!laned_detail::hadamard_factor(singular_left,
                                                        accepted)
                              .is_zero());
               });

    runner.run("tau=1 dense round uses the zero branch", [] {
        Fixture fixture;
        const std::size_t layer =
            first_multiplication_layer(fixture.circuit);
        std::vector<Fpk> point(
            laned_layer_variables(fixture.circuit, layer),
            Fpk::from_base(Fp(37)));
        point.front() = Fpk::one();
        const SingleClaim claim = make_packed_laned_claim(
            fixture.trace.layers[layer],
            laned_layout(fixture.circuit, layer), point);
        Transcript prover_transcript("test/laned/tau-one/v1");
        const auto proved =
            laned_detail::prove_multiplication_resident_reference<MockBackend>(
                fixture.contexts.eval, fixture.circuit, fixture.encrypted,
                layer, claim, prover_transcript,
                fixture.encrypted.layers[layer + 1U]
                    .wires.front().ciphertext().rns_limbs);
        const auto first = unpack_extension_scalars<MockBackend>(
            fixture.contexts.client,
            proved.proof.rounds.front().packed_evaluations, 2);
        CHECK(first[0] == expected_multiplication_value(
                              fixture, layer, claim, {}, Fpk::zero()));

        Transcript verifier_transcript("test/laned/tau-one/v1");
        ::laminate::gkr::detail::FixedMessageReader<MockBackend> reader(
            fixture.contexts.client);
        CHECK(laned_detail::verify_multiplication_reduction<MockBackend>(
                  reader, fixture.circuit, layer, claim,
                  proved.proof, verifier_transcript)
                  .has_value());
    });

    runner.run("slot-round depth is independent of log N", [] {
        Fixture slots_16(4, 16);
        Fixture slots_32(4, 32);
        CHECK(maximum_slot_round_depth(slots_16) ==
              maximum_slot_round_depth(slots_32));
    });

    runner.run("public-zero slot checkpoints skip Laned FHE work", [] {
        constexpr std::size_t kSlots = 16;
        auto contexts = MockBackend::create(
            MockParameters{.slot_count = kSlots});
        const ExtensionValue<MockBackend> zero;
        const std::vector<Fpk> prefix{Fpk::from_base(Fp(7))};
        const std::vector<Fpk> output_slot(
            4, Fpk::from_base(Fp(11)));
        const auto layout = packing::LanedPackingLayout::create(
            PayloadShape::laned(4, kSlots), 8);
        const laned_detail::LanedAffineGateRestrictions gate_values{
            .at_one = std::vector<Fpk>{Fpk::one()},
            .at_two = std::vector<Fpk>{Fpk::one()}};

        MockBackend::reset_counts(contexts.eval);
        const auto affine =
            laned_detail::affine_slot_round_evaluations<MockBackend>(
                contexts.eval, zero, layout, gate_values, prefix);
        CHECK(affine.at_one.is_public_zero());
        CHECK(affine.at_two.is_public_zero());
        CHECK(laned_detail::evaluate_affine_checkpoint<MockBackend>(
                  contexts.eval, zero, output_slot)
                  .is_public_zero());
        OperationCounts counts = MockBackend::counts(contexts.eval);
        CHECK(counts.rotate == 0);
        CHECK(counts.logical_ext_add == 0);
        CHECK(counts.logical_ext_mul_plain == 0);
        CHECK(counts.mul_plain_vector_api_elements == 0);

        MockBackend::ExtCiphertext encrypted_coordinates{};
        encrypted_coordinates[0] = MockBackend::encrypt(
            contexts.client, SlotVector(kSlots, Fp(13)));
        const ExtensionValue<MockBackend> encrypted(
            std::move(encrypted_coordinates));
        MockBackend::reset_counts(contexts.eval);
        const auto paired =
            gkr::detail::evaluate_multiplication_slot_round<MockBackend>(
                contexts.eval, zero, encrypted, output_slot, prefix,
                Fpk::zero());
        CHECK(paired.at_endpoint.is_public_zero());
        CHECK(paired.at_two.is_public_zero());
        counts = MockBackend::counts(contexts.eval);
        CHECK(counts.rotate == 0);
        CHECK(counts.logical_ext_add == 0);
        CHECK(counts.logical_ext_mul == 0);
        CHECK(counts.logical_ext_mul_plain == 0);
        CHECK(counts.mul_plain_vector_api_elements == 0);
    });

    runner.run("resident wire-prefix weights use scalar plaintexts", [] {
        constexpr std::size_t kSlots = 16;
        auto contexts =
            MockBackend::create(MockParameters{.slot_count = kSlots});
        std::vector<MockBackend::Ciphertext> wires;
        for (std::size_t wire = 0; wire < 4; ++wire) {
            wires.push_back(MockBackend::encrypt(
                contexts.client, SlotVector(kSlots, Fp(7U + wire))));
        }
        Fpk::Coefficients coefficients{};
        for (std::size_t index = 0; index < coefficients.size(); ++index) {
            coefficients[index] = Fp(23U + index);
        }
        MockBackend::reset_counts(contexts.eval);
        (void)partial_evaluate_ciphertext_index_point<MockBackend>(
            contexts.eval, wires, std::vector<Fpk>{Fpk(coefficients)});
        const OperationCounts counts = MockBackend::counts(contexts.eval);
        CHECK(counts.mul_plain_scalar_api_calls ==
              wires.size() * kExtensionDegree);
        CHECK(counts.mul_plain_vector_api_calls == 0);
        CHECK(counts.mul_plain_vector_api_elements == 0);
    });

    runner.run("resident prover rejects a false proof-ingress RNS level", [] {
        Fixture fixture;
        EncryptedTrace<MockBackend> mismatched = fixture.encrypted;
        CHECK(mismatched.layers.size() > 1);
        CHECK(!mismatched.layers[1].wires.empty());
        ++mismatched.layers[1].wires.front().ciphertext().rns_limbs;
        const auto evaluation = make_packed_evaluation_setup<MockBackend>(
            fixture.public_setup, fixture.contexts.eval);
        bool rejected = false;
        try {
            Transcript transcript("test/laned/rns-ingress-reject/v1");
            std::vector<std::size_t> ingress;
            for (const auto &layer : fixture.encrypted.layers) {
                ingress.push_back(
                    layer.wires.front().ciphertext().rns_limbs);
            }
            (void)laned_detail::prove_laned_gkr_resident<MockBackend>(
                fixture.payload, fixture.circuit, mismatched, evaluation,
                ingress, fixture.output_claim.point, transcript);
        } catch (const std::invalid_argument &) {
            rejected = true;
        }
        CHECK(rejected);
    });

    runner.run("outsourced Laned gate claims open and reject tampering", [] {
        Fixture fixture;
        const auto key = enable_outsourced_gate_mles(fixture);
        const auto evaluation = make_packed_evaluation_setup<MockBackend>(
            fixture.public_setup, fixture.contexts.eval, key);
        Transcript transcript("test/laned/e2e/v1");
        std::vector<std::size_t> ingress;
        for (const auto &layer : fixture.encrypted.layers) {
            ingress.push_back(
                layer.wires.front().ciphertext().rns_limbs);
        }
        const auto proof =
            laned_detail::prove_laned_gkr_resident<MockBackend>(
            fixture.payload, fixture.circuit, fixture.encrypted, evaluation,
            ingress, fixture.output_claim.point, transcript);

        CHECK(proof.gate_mle_opening.has_value());
        CHECK(!proof.gate_mle_opening->claimed_values.empty());
        const LanedProofSizeBreakdown size =
            measure_proof_size<MockBackend>(proof);
        CHECK(size.gate_mle_opening_bytes > 0);
        CHECK(size.total_bytes == size.statement_and_metadata_bytes +
                                      size.round_message_bytes +
                                      size.terminal_message_bytes +
                                      size.gate_mle_opening_bytes);
        CHECK(verify(fixture, proof, fixture.output_claim));

        auto changed_merkle = proof;
        changed_merkle.gate_mle_opening->table_openings.front()
            .opening.queries.openings.front()
            .base_lo.front() += Fp::one();
        CHECK(!verify(fixture, changed_merkle, fixture.output_claim));

        auto missing_opening = proof;
        missing_opening.gate_mle_opening.reset();
        CHECK(!verify(fixture, missing_opening, fixture.output_claim));
    });

    return runner.summary();
}
