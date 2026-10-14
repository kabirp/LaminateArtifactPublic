/// @file test_noise_envelope_protocol.cpp
/// @brief Folded/Laned Fiat--Shamir topology-envelope regression tests.

#include "test_helpers.hpp"

#include "laminate/fhe/noise/envelope_backend.hpp"
#include "laminate/fhe/mock_backend.hpp"
#include "laminate/gkr/detail/folded/reference/prover.hpp"
#include "laminate/gkr/detail/laned/reference/prover.hpp"
#include "laminate/gkr/folded.hpp"
#include "laminate/gkr/laned.hpp"
#include "laminate/packing/analysis/deterministic_completeness.hpp"
#include "laminate/packing/evaluation/lazy_ternary.hpp"
#include "laminate/packing/analysis/operator.hpp"
#include "laminate/payload/compiler.hpp"
#include "laminate/payload/trace/trace_crypto.hpp"
#include "laminate/protocol/analysis/packing_completeness.hpp"
#include "laminate/protocol/detail/packing/messages.hpp"
#include "laminate/protocol/analysis/packing_prerequisites.hpp"
#include "laminate/protocol/packed/setup.hpp"
#include "laminate/protocol/analysis/noise_completeness.hpp"

#include <algorithm>
#include <bit>
#include <cstddef>
#include <stdexcept>
#include <string_view>
#include <variant>
#include <vector>

using namespace laminate;
using namespace laminate::fhe;
using namespace laminate::gkr;
using namespace laminate::payload;
using namespace laminate::protocol;

namespace {

constexpr std::size_t kSlots = 32;
constexpr std::size_t kLanes = 4;
constexpr std::size_t kRequiredDepth = 9;

bool throws_invalid_argument(const auto &body) {
    try {
        body();
    } catch (const std::invalid_argument &) {
        return true;
    }
    return false;
}

NoiseEnvelopeParameters envelope_parameters() {
    constexpr std::uint64_t data_prime =
        kOuterFieldOrder;
    return NoiseEnvelopeParameters{
        .policy = DeterministicNoisePolicy{
            .ring_degree = kSlots,
            .plaintext_modulus = kBaseFieldOrder,
            .secret_hamming_weight_upper = kSlots,
            .sampled_error_coefficient_bound = 21,
        },
        .data_moduli = std::vector<std::uint64_t>(12, data_prime),
        .special_modulus = 1'152'921'422'732'700'001ULL,
    };
}

SlotVector values(std::size_t width, std::size_t seed) {
    SlotVector result;
    result.reserve(width);
    for (std::size_t index = 0; index < width; ++index) {
        result.emplace_back(seed + 3 * index + index * index);
    }
    return result;
}

PayloadCircuit folded_payload() {
    PayloadBuilder builder(PayloadShape::wide(kSlots), 2);
    const std::size_t diagonal =
        builder.add_plaintext(values(kSlots, 5));
    const auto product = builder.mul(0, 1);
    const auto scaled = builder.mul_plain(0, diagonal);
    builder.set_outputs({builder.add(product, scaled)});
    return builder.finish();
}

PayloadCircuit laned_payload() {
    constexpr std::size_t kOutputs = kSlots / kLanes;
    PayloadBuilder builder(PayloadShape::laned(kLanes, kSlots),
                           2 * kOutputs);
    std::vector<WireId> outputs;
    for (std::size_t output = 0; output < kOutputs; ++output) {
        outputs.push_back(builder.mul(2 * output, 2 * output + 1));
    }
    builder.set_outputs(outputs);
    return builder.finish();
}

std::vector<SlotVector> laned_inputs(const PayloadCircuit &payload) {
    std::vector<SlotVector> result;
    for (std::size_t input = 0; input < payload.input_count; ++input) {
        result.push_back(values(kLanes, 3 + 26 * input));
    }
    return result;
}

SingleClaim folded_claim(const LayeredCircuit &circuit,
                         const PlainTrace &trace) {
    const std::size_t variables =
        (std::bit_width(
             layer_dimensions(circuit.layers.front()).padded_size) -
         1U) +
        (std::bit_width(circuit.shape.value_width()) - 1U);
    return make_layer_claim(
        trace.layers.front(),
        std::vector<Fpk>(variables, Fpk::from_base(Fp(19))));
}

SingleClaim laned_claim(const LayeredCircuit &circuit,
                        const PlainTrace &trace) {
    return make_packed_laned_claim(
        trace.layers.front(), laned_layout(circuit, 0),
        std::vector<Fpk>(laned_layer_variables(circuit, 0),
                         Fpk::from_base(Fp(19))));
}

packing::SignedDigitPackingWeightAnalysis operator_weights_for(
    const PackingNoiseEnvelopeResult &envelope,
    packing::BalancedRadix radix =
        packing::selected_lazy_ternary_parameters().packing_radix) {
    const packing::PackingLayout layout =
        packing::make_fixed_message_coset_packing_layout(
            envelope.ring_degree, envelope.bhip_round_count,
            envelope.ring_degree / fhe::kFixedMessageCellCount);
    const packing::PackingLinearOperator packing_operator =
        packing::make_packing_linear_operator(layout);
    return packing::analyze_signed_digit_packing_weights(
        packing_operator,
        [](const SlotVector &mask) {
            std::vector<std::int64_t> coefficients;
            coefficients.reserve(mask.size());
            for (const Fp &coefficient : mask) {
                coefficients.push_back(
                    static_cast<std::int64_t>(coefficient.value()));
            }
            return coefficients;
        },
        radix);
}

struct BoundShape {
    NaturalMagnitude partial_decryption_bound;
    std::size_t operation_count = 0;
    std::size_t rns_limbs = 0;
    bool no_wrap = false;

    bool operator==(const BoundShape &) const = default;
};

BoundShape shape(const NoiseEnvelopeBackend::Ciphertext &ciphertext) {
    return BoundShape{
        ciphertext.deterministic_noise_bound.partial_decryption_bound,
        ciphertext.deterministic_noise_bound.operation_count,
        ciphertext.rns_limbs,
        ciphertext.deterministic_noise_bound.certifies_no_wrap(),
    };
}

template <typename Proof>
std::vector<BoundShape> bound_shapes(const Proof &proof) {
    std::vector<BoundShape> result;
    for (const auto &value :
         collect_transcript_packing_round_values<NoiseEnvelopeBackend>(
             proof)) {
        if (value.is_encrypted()) {
            result.push_back(shape(value.ciphertext()));
        }
    }
    return result;
}

template <typename Proof>
void check_finalization(const NoiseEnvelopeBackend::EvalContext &eval,
                        const Proof &proof) {
    const auto round_values =
        collect_transcript_packing_round_values<NoiseEnvelopeBackend>(
            proof);
    const auto layout = packing::make_fixed_message_coset_packing_layout(
        kSlots, round_values.size(),
        kSlots / fhe::kFixedMessageCellCount);
    const auto certificate =
        packing::certify_deterministic_packing_completeness<
            NoiseEnvelopeBackend>(
            eval, round_values, layout, eval.parameters.policy,
            kSelectedPackingHonestErrorBound,
            packing::DeterministicPackingCertificateScope::
                ChallengeIndependentEnvelope);
    CHECK(certificate.is_circuit_wide());
    CHECK(certificate.passes());
    CHECK(certificate.final.minimum_rns_limbs == 1);
    CHECK(certificate.final.maximum_rns_limbs == 1);
}

EncryptedFoldedProof<NoiseEnvelopeBackend> prove_folded_envelope(
    const PayloadCircuit &payload, const LayeredCircuit &circuit,
    const PlainTrace &trace, const PublicSetup &public_setup,
    const NoiseEnvelopeBackend::Contexts &contexts,
    std::string_view transcript_domain) {
    const auto encrypted =
        encrypt_compact_synthetic_trace<NoiseEnvelopeBackend>(
            contexts.eval, contexts.client, payload, circuit, trace,
            TraceEncryptionPlan::uniform(circuit, kRequiredDepth));
    const SingleClaim claim = folded_claim(circuit, trace);
    const auto setup = make_evaluation_setup<NoiseEnvelopeBackend>(
        public_setup, contexts.eval);
    Transcript transcript(transcript_domain);
    return folded_detail::prove_folded_gkr_resident<NoiseEnvelopeBackend>(
        payload, circuit, encrypted, setup, claim.point, transcript,
        std::vector<std::size_t>(circuit.layers.size(),
                                 kRequiredDepth + 1U),
        ProofTransportPolicy{.reserved_mult_depth =
                                 kPackingReservedMultDepth});
}

EncryptedLanedProof<NoiseEnvelopeBackend> prove_laned_envelope(
    const PayloadCircuit &payload, const LayeredCircuit &circuit,
    const PlainTrace &trace, const PublicSetup &public_setup,
    const NoiseEnvelopeBackend::Contexts &contexts,
    std::string_view transcript_domain) {
    const auto encrypted = encrypt_compact_synthetic_trace<NoiseEnvelopeBackend>(
        contexts.eval, contexts.client, payload, circuit, trace,
        TraceEncryptionPlan::uniform(circuit, kRequiredDepth));
    const SingleClaim claim = laned_claim(circuit, trace);
    const auto setup = make_packed_evaluation_setup<NoiseEnvelopeBackend>(
        public_setup, contexts.eval);
    Transcript transcript(transcript_domain);
    return laned_detail::prove_laned_gkr_resident<NoiseEnvelopeBackend>(
        payload, circuit, encrypted, setup,
        std::vector<std::size_t>(circuit.layers.size(),
                                 kRequiredDepth + 1U),
        claim.point, transcript,
        ProofTransportPolicy{.reserved_mult_depth =
                                 kPackingReservedMultDepth});
}

} // namespace

int main() {
    test::Runner runner("test_noise_envelope_protocol");

    runner.run("Folded bound shape is challenge independent", [] {
        const PayloadCircuit payload = folded_payload();
        const LayeredCircuit circuit = compile(payload);
        const PlainTrace trace = synthesize_trace(
            payload, circuit,
            std::vector<SlotVector>{values(kSlots, 7),
                                    values(kSlots, 31)});
        const PublicSetup public_setup = make_direct_setup(payload, circuit);
        const auto contexts =
            NoiseEnvelopeBackend::create(envelope_parameters());
        const auto first = prove_folded_envelope(
            payload, circuit, trace, public_setup, contexts,
            "test/noise-envelope/folded/a");
        const auto second = prove_folded_envelope(
            payload, circuit, trace, public_setup, contexts,
            "test/noise-envelope/folded/b");
        CHECK(bound_shapes(first) == bound_shapes(second));
        check_finalization(contexts.eval, first);

        const auto certificate = certify_folded_packing_completeness(
            PackingNoiseEnvelopeStatement{
                payload, circuit, trace, public_setup,
                folded_claim(circuit, trace),
                {}},
            PackingNoiseEnvelopeSchedule{
                .fhe_parameters = envelope_parameters(),
                .required_proof_mult_depth = kRequiredDepth,
            });
        CHECK(certificate.passes());
        CHECK(certificate.certificate.is_circuit_wide());
        CHECK(certificate.bhip_round_count ==
              collect_transcript_packing_round_values<
                  NoiseEnvelopeBackend>(first)
                  .size());
        CHECK(certificate.logical_packed_output_count ==
              (certificate.bhip_round_count + 1) / 2);
        CHECK(certificate.ring_degree == kSlots);
        CHECK(certificate.plaintext_modulus == kBaseFieldOrder);
        CHECK(certificate.packing_modulus ==
              envelope_parameters().data_moduli.front());

        const auto weights = operator_weights_for(certificate);
        const SelectedPackingPrerequisiteCertificate prerequisites =
            assess_selected_packing_prerequisites(certificate, weights);
        CHECK(prerequisites.selected_parameters_match);
        CHECK(prerequisites.circuit_wide_noise_certificate);
        CHECK(prerequisites.noise_certificate_passes);
        CHECK(prerequisites.noise_cap_matches_parameters);
        CHECK(prerequisites.one_prime_boundary);
        CHECK(prerequisites.operator_radix_matches_parameters);
        CHECK(prerequisites.envelope_shape_matches_operator);
        CHECK(prerequisites.modulus_capacity_admits_selected_error);
        CHECK(prerequisites.interactive_theorem
                  .interactive_certificate_holds);
        CHECK(prerequisites.passes_arithmetic_prerequisites());

        PackingNoiseEnvelopeResult wrong_scope = certificate;
        wrong_scope.certificate.scope =
            packing::DeterministicPackingCertificateScope::
                ExecutedChallengePath;
        CHECK(!assess_selected_packing_prerequisites(wrong_scope, weights)
                   .passes_arithmetic_prerequisites());

        auto wrong_radix = packing::selected_lazy_ternary_parameters();
        wrong_radix.packing_radix =
            packing::make_minimal_balanced_radix(kBaseFieldOrder, 41);
        const auto wrong_profile = assess_selected_packing_prerequisites(
            certificate, operator_weights_for(
                             certificate, wrong_radix.packing_radix),
            wrong_radix);
        CHECK(!wrong_profile.selected_parameters_match);
        CHECK(!wrong_profile.passes_arithmetic_prerequisites());

        const auto wrong_operator = assess_selected_packing_prerequisites(
            certificate,
            operator_weights_for(certificate, wrong_radix.packing_radix));
        CHECK(!wrong_operator.operator_radix_matches_parameters);
        CHECK(!wrong_operator.passes_arithmetic_prerequisites());
    });

    runner.run("Laned bound shape is challenge independent", [] {
        const PayloadCircuit payload = laned_payload();
        const LayeredCircuit circuit = compile(payload);
        const PlainTrace trace = synthesize_trace(
            payload, circuit, laned_inputs(payload));
        const PublicSetup public_setup = make_direct_setup(payload, circuit);
        const auto contexts =
            NoiseEnvelopeBackend::create(envelope_parameters());
        const auto first = prove_laned_envelope(
            payload, circuit, trace, public_setup, contexts,
            "test/noise-envelope/laned/a");
        const auto second = prove_laned_envelope(
            payload, circuit, trace, public_setup, contexts,
            "test/noise-envelope/laned/b");
        CHECK(bound_shapes(first) == bound_shapes(second));
        check_finalization(contexts.eval, first);

        const auto certificate = certify_laned_packing_completeness(
            PackingNoiseEnvelopeStatement{
                payload, circuit, trace, public_setup,
                laned_claim(circuit, trace),
                {}},
            PackingNoiseEnvelopeSchedule{
                .fhe_parameters = envelope_parameters(),
                .required_proof_mult_depth = kRequiredDepth,
            });
        CHECK(certificate.passes());
        CHECK(certificate.certificate.is_circuit_wide());
        CHECK(certificate.bhip_round_count ==
              collect_transcript_packing_round_values<
                  NoiseEnvelopeBackend>(first)
                  .size());
        CHECK(certificate.logical_packed_output_count ==
              (certificate.bhip_round_count + 1) / 2);
    });

    runner.run("Folded affine4 ingress is explicit and separately bound", [] {
        const auto payload = folded_payload();
        const auto circuit = compile(payload);
        const auto setup = make_direct_setup(payload, circuit);
        const auto legacy = derive_conservative_packed_proof_ingress_schedule(
            PackingGkrVariant::Folded, payload, circuit, setup);
        const auto selected = derive_conservative_packed_proof_ingress_schedule(
            PackingGkrVariant::Folded, payload, circuit, setup,
            ConservativePackedProofIngressPolicy::FoldedAffine4);
        CHECK(legacy.policy() == kConservativePackedProofIngressPolicyV1);
        CHECK(selected.policy() == kConservativePackedProofIngressPolicyV4);
        CHECK(selected.digest() != legacy.digest());
        validate_conservative_packed_proof_ingress_schedule(payload, circuit, setup, selected);
        for (std::size_t source = 1; source < circuit.layers.size(); ++source) {
            const bool affine = layer_kind(circuit.layers[source - 1]) == LayerKind::Affine;
            CHECK(selected.rns_limbs_by_layer()[source] == (affine ? 4U : 6U));
            CHECK(legacy.rns_limbs_by_layer()[source] == (affine ? 3U : 6U));
        }
        CHECK(selected.digest() != conservative_packed_proof_ingress_schedule_digest(
            PackingGkrVariant::Folded, selected.circuit_id(), selected.public_setup_id(),
            selected.rns_limbs_by_layer()));
        CHECK(conservative_packed_proof_ingress_policy_selection(
            PackingGkrVariant::Folded, selected.policy()) ==
              ConservativePackedProofIngressPolicy::FoldedAffine4);
        CHECK(throws_invalid_argument([&] {
            (void)conservative_packed_proof_ingress_policy_selection(
                PackingGkrVariant::Laned, selected.policy());
        }));
        CHECK(throws_invalid_argument([&] {
            (void)conservative_packed_proof_ingress_policy(
                PackingGkrVariant::Laned, ConservativePackedProofIngressPolicy::FoldedAffine4);
        }));
    });

    runner.run("fixed packed ingress is topology-derived and setup-bound", [] {
        const PayloadCircuit folded = folded_payload();
        const LayeredCircuit folded_circuit = compile(folded);
        const PublicSetup folded_public =
            make_direct_setup(folded, folded_circuit);
        const ConservativePackedProofIngressSchedule folded_schedule =
            derive_conservative_packed_proof_ingress_schedule(
                PackingGkrVariant::Folded, folded, folded_circuit,
                folded_public);
        const ConservativePackedProofIngressSchedule folded_again =
            derive_conservative_packed_proof_ingress_schedule(
                PackingGkrVariant::Folded, folded, folded_circuit,
                folded_public);
        CHECK(folded_schedule == folded_again);
        CHECK(folded_schedule.policy() ==
              kConservativePackedProofIngressPolicyV1);
        CHECK(folded_schedule.circuit_id() ==
              folded_public.circuit_digest);
        CHECK(folded_schedule.public_setup_id() ==
              setup_digest(folded_public));

        std::vector<std::size_t> expected_folded(
            folded_circuit.layers.size(), 1U);
        for (std::size_t source = 1;
             source < folded_circuit.layers.size(); ++source) {
            expected_folded[source] =
                layer_kind(folded_circuit.layers[source - 1U]) ==
                        LayerKind::Affine
                    ? kConservativeFoldedAffineProofDepth + 1U
                    : kConservativeFoldedMultiplicationProofDepth + 1U;
        }
        CHECK(std::vector<std::size_t>(
                  folded_schedule.rns_limbs_by_layer().begin(),
                  folded_schedule.rns_limbs_by_layer().end()) ==
              expected_folded);
        CHECK(folded_schedule.digest() ==
              conservative_packed_proof_ingress_schedule_digest(
                  PackingGkrVariant::Folded,
                  folded_schedule.circuit_id(),
                  folded_schedule.public_setup_id(), expected_folded));

        // Every coordinate, including the non-authoritative output
        // placeholder, is authenticated by the canonical setup binding.
        for (std::size_t layer = 0; layer < expected_folded.size(); ++layer) {
            std::vector<std::size_t> changed = expected_folded;
            ++changed[layer];
            CHECK(conservative_packed_proof_ingress_schedule_digest(
                      PackingGkrVariant::Folded,
                      folded_schedule.circuit_id(),
                      folded_schedule.public_setup_id(), changed) !=
                  folded_schedule.digest());
        }
        Digest changed_circuit = folded_schedule.circuit_id();
        changed_circuit.front() ^= 1U;
        CHECK(conservative_packed_proof_ingress_schedule_digest(
                  PackingGkrVariant::Folded, changed_circuit,
                  folded_schedule.public_setup_id(), expected_folded) !=
              folded_schedule.digest());
        Digest changed_setup = folded_schedule.public_setup_id();
        changed_setup.back() ^= 1U;
        CHECK(conservative_packed_proof_ingress_schedule_digest(
                  PackingGkrVariant::Folded,
                  folded_schedule.circuit_id(), changed_setup,
                  expected_folded) != folded_schedule.digest());
        CHECK(conservative_packed_proof_ingress_schedule_digest(
                  PackingGkrVariant::Laned,
                  folded_schedule.circuit_id(),
                  folded_schedule.public_setup_id(), expected_folded) !=
              folded_schedule.digest());

        const PublicSetup differently_committed =
            make_dummy_committed_setup(folded, folded_circuit);
        CHECK(throws_invalid_argument([&] {
            validate_conservative_packed_proof_ingress_schedule(
                folded, folded_circuit, differently_committed,
                folded_schedule);
        }));

        const PayloadCircuit laned = laned_payload();
        const LayeredCircuit laned_circuit = compile(laned);
        const PublicSetup laned_public =
            make_direct_setup(laned, laned_circuit);
        const ConservativePackedProofIngressSchedule laned_schedule =
            derive_conservative_packed_proof_ingress_schedule(
                PackingGkrVariant::Laned, laned, laned_circuit,
                laned_public);
        CHECK(laned_schedule.policy() ==
              kConservativePackedProofIngressPolicyV3);
        std::vector<std::size_t> expected_laned(
            laned_circuit.layers.size(), 1U);
        for (std::size_t source = 1;
             source < laned_circuit.layers.size(); ++source) {
            expected_laned[source] =
                layer_kind(laned_circuit.layers[source - 1U]) ==
                        LayerKind::Affine
                    ? kConservativeLanedAffineProofDepth + 1U
                    : kConservativeLanedMultiplicationProofDepth + 1U;
        }
        CHECK(std::vector<std::size_t>(
                  laned_schedule.rns_limbs_by_layer().begin(),
                  laned_schedule.rns_limbs_by_layer().end()) ==
              expected_laned);

        FheEvaluationPlan natural =
            FheEvaluationPlan::without_payload_switches(
                folded_circuit, kRequiredDepth);
        FoldedSetup setup;
        setup.transcript_packing.variant = PackingGkrVariant::Folded;
        setup.proof_ingress_rns_limbs_by_layer = expected_folded;
        setup.conservative_proof_ingress_schedule = folded_schedule;
        const FheEvaluationPlan applied =
            apply_packed_proof_ingress_schedule(
                folded_circuit, natural, setup);
        CHECK(applied.proof_ingress_mult_depth_by_layer.front() ==
              natural.trace.required_mult_depth_by_layer.front());
        for (std::size_t source = 1; source < expected_folded.size();
             ++source) {
            CHECK(applied.proof_ingress_mult_depth_by_layer[source] + 1U ==
                  expected_folded[source]);
        }
        ++setup.proof_ingress_rns_limbs_by_layer.back();
        CHECK(throws_invalid_argument([&] {
            (void)apply_packed_proof_ingress_schedule(
                folded_circuit, natural, setup);
        }));
    });

    runner.run("full-width policy binds the omitted witness-packing level", [] {
        const auto make_payload = [](std::size_t lanes) {
            PayloadBuilder builder(PayloadShape::laned(lanes, kSlots), 2);
            WireId product = builder.mul(0, 1);
            for (std::size_t depth = 1; depth < 8; ++depth) {
                product = builder.mul(product, product);
            }
            builder.set_outputs({product});
            return builder.finish();
        };
        const PayloadCircuit full = make_payload(kSlots);
        const LayeredCircuit full_circuit = compile(full);
        const PublicSetup full_setup = make_direct_setup(full, full_circuit);
        const auto full_schedule =
            derive_conservative_packed_proof_ingress_schedule(
                PackingGkrVariant::Laned, full, full_circuit, full_setup);
        const PayloadCircuit narrow = make_payload(kLanes);
        const LayeredCircuit narrow_circuit = compile(narrow);
        const PublicSetup narrow_setup =
            make_direct_setup(narrow, narrow_circuit);
        const auto narrow_schedule =
            derive_conservative_packed_proof_ingress_schedule(
                PackingGkrVariant::Laned, narrow, narrow_circuit, narrow_setup);
        CHECK(full_schedule.policy() == kConservativePackedProofIngressPolicyV3);
        CHECK(full_schedule.rns_limbs_by_layer().size() ==
              narrow_schedule.rns_limbs_by_layer().size());
        std::vector<std::size_t> full_depths(full_circuit.layers.size(), 0);
        std::vector<std::size_t> narrow_depths(narrow_circuit.layers.size(), 0);
        for (std::size_t source = 1; source < full_circuit.layers.size();
             ++source) {
            const bool multiplication =
                layer_kind(full_circuit.layers[source - 1U]) ==
                LayerKind::Multiplication;
            const auto full_limbs = full_schedule.rns_limbs_by_layer()[source];
            const auto narrow_limbs = narrow_schedule.rns_limbs_by_layer()[source];
            CHECK(full_limbs == (multiplication ? 6U : 4U));
            CHECK(narrow_limbs == full_limbs + (multiplication ? 1U : 0U));
            full_depths[source] = full_limbs - 1U;
            narrow_depths[source] = narrow_limbs - 1U;
        }
        const auto full_plan = FheEvaluationPlan::packed_payload_with_prompt_switches(
            full_circuit, 12, full_depths);
        CHECK(full_plan.trace.required_mult_depth_by_layer.back() == 12);
        CHECK(throws_invalid_argument([&] {
            (void)FheEvaluationPlan::packed_payload_with_prompt_switches(
                narrow_circuit, 12, narrow_depths);
        }));
        (void)FheEvaluationPlan::packed_payload_with_prompt_switches(
            narrow_circuit, 13, narrow_depths);
        CHECK(full_schedule.digest() != narrow_schedule.digest());
        CHECK(throws_invalid_argument([&] {
            validate_conservative_packed_proof_ingress_schedule(
                narrow, narrow_circuit, narrow_setup, full_schedule);
        }));
        CHECK(conservative_packed_proof_ingress_schedule_digest(
                  PackingGkrVariant::Laned, full_schedule.circuit_id(),
                  full_schedule.public_setup_id(),
                  narrow_schedule.rns_limbs_by_layer()) != full_schedule.digest());
        const auto encoding = encode_conservative_packed_proof_ingress_schedule(
            PackingGkrVariant::Laned, full_schedule.circuit_id(),
            full_schedule.public_setup_id(), full_schedule.rns_limbs_by_layer());
        auto old_policy_encoding = encoding;
        const auto found = std::search(
            old_policy_encoding.begin(), old_policy_encoding.end(),
            kConservativePackedProofIngressPolicyV3.begin(),
            kConservativePackedProofIngressPolicyV3.end());
        CHECK(found != old_policy_encoding.end());
        *(found + static_cast<std::ptrdiff_t>(
                      kConservativePackedProofIngressPolicyV3.size() - 1U)) = '2';
        CHECK(sha256(old_policy_encoding) != full_schedule.digest());
    });

    runner.run("prefix analyzer covers Base Folded and Laned", [] {
        const RnsPrefixSearchSpace search_space{
            .maximum_parameters = envelope_parameters(),
            .required_proof_mult_depths = {kRequiredDepth},
        };
        const auto encoder_contexts = MockBackend::create(MockParameters{
            .slot_count = kSlots,
            .fresh_rns_limbs = envelope_parameters().data_moduli.size(),
        });

        const PayloadCircuit folded = folded_payload();
        const LayeredCircuit folded_circuit = compile(folded);
        const PlainTrace folded_trace = synthesize_trace(
            folded, folded_circuit,
            std::vector<SlotVector>{values(kSlots, 7),
                                    values(kSlots, 31)});
        const PublicSetup folded_setup =
            make_direct_setup(folded, folded_circuit);
        const PackingNoiseEnvelopeStatement folded_statement{
            folded, folded_circuit, folded_trace, folded_setup,
            folded_claim(folded_circuit, folded_trace),
            {}};
        const auto base_analysis = analyze_base_minimum_rns_limbs(
            folded_statement, search_space);
        CHECK(base_analysis.candidates.size() ==
              envelope_parameters().data_moduli.size());
        CHECK(base_analysis.certifies_search_space_minimum());
        CHECK(*base_analysis.minimum_fresh_rns_limbs ==
              kRequiredDepth + 1);
        CHECK(*base_analysis.selected_required_proof_mult_depth ==
              kRequiredDepth);
        CHECK(base_analysis.analyzed_search_space.maximum_parameters
                  .data_moduli == envelope_parameters().data_moduli);
        CHECK(!base_analysis.live_schedule_parity_established);
        CHECK(base_analysis.candidates.front().status ==
              RnsPrefixAssessmentStatus::InvalidSchedule);

        const auto folded_analysis =
            analyze_folded_minimum_rns_limbs<MockBackend>(
                folded_statement, search_space, encoder_contexts.eval);
        CHECK(folded_analysis.certifies_search_space_minimum());
        CHECK(*folded_analysis.minimum_fresh_rns_limbs ==
              kRequiredDepth + 1);
        CHECK(folded_analysis
                  .coordinatewise_proof_ingress_minimum_established);
        CHECK(folded_analysis.selected_proof_ingress_rns_limbs_by_layer
                  .size() == folded_circuit.layers.size());
        CHECK(!folded_analysis.proof_ingress_coordinate_candidates.empty());
        const auto folded_ingress =
            select_proof_ingress_rns_limbs(folded_analysis);
        CHECK(folded_ingress.variant() == PackingGkrVariant::Folded);
        CHECK(std::vector<std::size_t>(
                  folded_ingress.exact_rns_limbs_by_layer().begin(),
                  folded_ingress.exact_rns_limbs_by_layer().end()) ==
              folded_analysis.selected_proof_ingress_rns_limbs_by_layer);
        const auto &folded_selected = *std::find_if(
            folded_analysis.candidates.begin(),
            folded_analysis.candidates.end(),
            [](const auto &candidate) { return candidate.passes(); });
        CHECK(folded_selected.prerequisites.has_value());
        CHECK(folded_selected.prerequisites
                  ->interactive_theorem.interactive_certificate_holds);
        CHECK(folded_analysis.packing_operator.has_value());
        CHECK(folded_analysis.packing_operator->weights
                  .maximum_digit_row_weight_upper ==
              folded_selected.prerequisites->maximum_row_weight_upper);
        CHECK(folded_analysis.packing_operator->linear_operator
                  .source_ciphertext_count ==
              folded_selected.packed->bhip_round_count);
        CHECK(folded_analysis.packing_operator->canonical_digest ==
              packing_operator_analysis_digest(
                  folded_analysis.packing_operator->linear_operator,
                  folded_analysis.packing_operator->weights));
        CHECK(folded_analysis.packing_operator->canonical_digest != Digest{});
        auto malformed_weights =
            folded_analysis.packing_operator->weights;
        --malformed_weights.maximum_digit_row_weight_upper;
        CHECK(throws_invalid_argument([&] {
            (void)packing_operator_analysis_digest(
                folded_analysis.packing_operator->linear_operator,
                malformed_weights);
        }));

        const auto wrong_encoder_contexts =
            MockBackend::create(MockParameters{.slot_count = kSlots / 2});
        CHECK(throws_invalid_argument([&] {
            (void)analyze_folded_minimum_rns_limbs<MockBackend>(
                folded_statement, search_space,
                wrong_encoder_contexts.eval);
        }));
        RnsPrefixSearchSpace wrong_bottom = search_space;
        wrong_bottom.maximum_parameters.data_moduli.front() += 2;
        CHECK(throws_invalid_argument([&] {
            (void)analyze_folded_minimum_rns_limbs<MockBackend>(
                folded_statement, wrong_bottom, encoder_contexts.eval);
        }));
        RnsPrefixSearchSpace empty_chain = search_space;
        empty_chain.maximum_parameters.data_moduli.clear();
        CHECK(throws_invalid_argument([&] {
            (void)analyze_folded_minimum_rns_limbs<MockBackend>(
                folded_statement, empty_chain, encoder_contexts.eval);
        }));

        RnsPrefixSearchSpace all_invalid = search_space;
        all_invalid.required_proof_mult_depths = {0};
        const auto invalid_packed =
            analyze_folded_minimum_rns_limbs<MockBackend>(
                folded_statement, all_invalid, encoder_contexts.eval);
        CHECK(invalid_packed.all_search_space_candidates_resolved);
        CHECK(!invalid_packed.minimum_fresh_rns_limbs.has_value());
        CHECK(!invalid_packed.packing_operator.has_value());
        CHECK(std::all_of(
            invalid_packed.candidates.begin(),
            invalid_packed.candidates.end(), [](const auto &candidate) {
                return candidate.status ==
                       RnsPrefixAssessmentStatus::InvalidSchedule;
            }));

        const PayloadCircuit laned = laned_payload();
        const LayeredCircuit laned_circuit = compile(laned);
        const PlainTrace laned_trace = synthesize_trace(
            laned, laned_circuit, laned_inputs(laned));
        const PublicSetup laned_setup =
            make_direct_setup(laned, laned_circuit);
        const PackingNoiseEnvelopeStatement laned_statement{
            laned, laned_circuit, laned_trace, laned_setup,
            laned_claim(laned_circuit, laned_trace),
            {}};
        const auto laned_analysis =
            analyze_laned_minimum_rns_limbs<MockBackend>(
                laned_statement, search_space, encoder_contexts.eval);
        CHECK(laned_analysis.certifies_search_space_minimum());
        CHECK(*laned_analysis.minimum_fresh_rns_limbs ==
              kRequiredDepth + 1);
        CHECK(laned_analysis
                  .coordinatewise_proof_ingress_minimum_established);
        CHECK(laned_analysis.selected_proof_ingress_rns_limbs_by_layer
                  .size() == laned_circuit.layers.size());
        const auto laned_ingress =
            select_proof_ingress_rns_limbs(laned_analysis);
        CHECK(laned_ingress.variant() == PackingGkrVariant::Laned);

        RnsPrefixSearchSpace impossible = search_space;
        impossible.maximum_parameters.data_moduli = {65'539};
        impossible.required_proof_mult_depths = {0};
        const auto no_minimum = analyze_base_minimum_rns_limbs(
            folded_statement, impossible);
        CHECK(!no_minimum.minimum_fresh_rns_limbs.has_value());
        CHECK(!no_minimum.certifies_search_space_minimum());
        CHECK(no_minimum.all_search_space_candidates_resolved);
        CHECK(no_minimum.candidates.size() == 1);
        CHECK(no_minimum.candidates.front().status ==
              RnsPrefixAssessmentStatus::ArithmeticRejected);
    });

    return runner.summary();
}
