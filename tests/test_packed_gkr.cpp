/// @file test_packed_gkr.cpp
/// @brief Selected Folded/Laned proof composition and adversarial checks.

#include "test_helpers.hpp"
#include "packed_setup_fixture.hpp"

#include "laminate/delegation/packed/statement.hpp"
#include "laminate/fhe/mock_backend.hpp"
#include "laminate/gkr/detail/shared/encoding/canonical.hpp"
#include "laminate/payload/compiler.hpp"
#include "laminate/payload/trace/fhe_trace_id.hpp"
#include "laminate/payload/trace/trace_crypto.hpp"
#include "laminate/protocol/folded.hpp"
#include "laminate/protocol/laned.hpp"
#include "laminate/protocol/detail/packing/messages.hpp"
#include "laminate/protocol/detail/packing/gkr_transcript_replay.hpp"
#include "laminate/protocol/packed/wire/proof.hpp"
#include "laminate/protocol/metrics/profiling.hpp"
#include "laminate/protocol/metrics/proof_size.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <optional>
#include <vector>

using namespace laminate;
using namespace laminate::delegation;
using namespace laminate::fhe;
using namespace laminate::gkr;
using namespace laminate::payload;
using namespace laminate::protocol;

namespace {

// Count every secret-key entry point used by packing verification. Public
// transcript or PCS failures must not reach threshold checks or decryption.
struct AuditedMockBackend : MockBackend {
    static inline std::size_t secret_key_calls = 0;

    static SlotVector decrypt(const ClientContext &context,
                              const Ciphertext &ciphertext) {
        ++secret_key_calls;
        return MockBackend::decrypt(context, ciphertext);
    }

    static std::uint64_t partial_decryption_infinity_norm(
        const ClientContext &context, const Ciphertext &ciphertext) {
        ++secret_key_calls;
        return MockBackend::partial_decryption_infinity_norm(
            context, ciphertext);
    }

    static std::uint64_t
    partial_decryption_with_public_ntt_offset_infinity_norm(
        const ClientContext &context, const Ciphertext *ciphertext,
        std::span<const std::uint64_t> public_c0_coordinates) {
        ++secret_key_calls;
        return MockBackend::
            partial_decryption_with_public_ntt_offset_infinity_norm(
                context, ciphertext, public_c0_coordinates);
    }

    static bool partial_decryption_within_bound(
        const ClientContext &context, const Ciphertext &ciphertext,
        std::uint64_t threshold) {
        ++secret_key_calls;
        return MockBackend::partial_decryption_within_bound(
            context, ciphertext, threshold);
    }
};

bool transcripts_match(Transcript left, Transcript right) {
    return left.challenge_fq2() == right.challenge_fq2();
}

SlotVector values(std::size_t count, std::uint64_t seed) {
    SlotVector result;
    result.reserve(count);
    for (std::size_t index = 0; index < count; ++index) {
        result.emplace_back(seed + 3 * index + index * index);
    }
    return result;
}

template <typename Proof>
void corrupt_first_commitment(Proof &proof) {
    std::visit(
        [](auto &reduction) {
            auto &message =
                reduction.rounds.front().packed_evaluations;
            if (!message.is_encrypted()) {
                throw std::logic_error(
                    "test fixture's first packed message is public");
            }
            auto commitment = message.commitment();
            commitment.digest.front() ^= 0x80U;
            message = CommittedPackedMessage::encrypted_message(
                std::move(commitment));
        },
        proof.gkr.reductions.front());
}

packing::LazyTernaryParameters test_packing_parameters() {
    auto result = packing::selected_lazy_ternary_parameters();
    result.repetitions = 1;
    return result;
}

PackedProofDecodeLimits packed_decode_limits(std::size_t proof_bytes) {
    return PackedProofDecodeLimits{
        .max_proof_bytes = proof_bytes,
        .max_ciphertexts = 1U << 12U,
        .max_ciphertext_bytes = proof_bytes,
        .max_total_ciphertext_bytes = proof_bytes,
        .max_collection_elements = 1U << 16U,
        .max_total_field_elements = 1U << 22U,
        .max_total_digests = 1U << 22U,
    };
}

void overwrite_u64(std::vector<std::uint8_t> &bytes,
                   std::size_t offset, std::uint64_t value) {
    CHECK(offset <= bytes.size());
    CHECK(bytes.size() - offset >= sizeof(value));
    for (std::size_t byte = 0; byte < sizeof(value); ++byte) {
        bytes[offset + byte] = static_cast<std::uint8_t>(
            value >> (8U * byte));
    }
}

bool throws_invalid_argument(const auto &body) {
    try {
        body();
    } catch (const std::invalid_argument &) {
        return true;
    }
    return false;
}

template <typename TypedSetup>
TypedSetup make_test_packing_setup(
    PackingGkrVariant variant,
    const AuditedMockBackend::EvalContext &eval, std::size_t message_count,
    std::size_t layer_count) {
    const std::size_t ingress_rns_limbs =
        variant == PackingGkrVariant::Folded
            ? kFoldedFixtureProofIngressRnsLimbs
            : kLanedFixtureProofIngressRnsLimbs;
    return TypedSetup{make_transcript_packing_spartan_setup(
        variant, AuditedMockBackend::slot_count(eval), message_count,
        {.centered_coefficients =
             [&eval](const SlotVector &slots) {
                 return AuditedMockBackend::encode_centered_plaintext_coefficients(
                     eval, slots);
             },
         .native_ntt =
             [&eval](std::span<const std::int64_t> coefficients) {
                 return AuditedMockBackend::encode_lowest_plaintext_ntt_coordinates(
                     eval, coefficients);
             }},
        test_packing_parameters(),
        spartan::BaseFoldPcsParameters{.log_rate = 1, .query_count = 1},
        spartan::Options{
            .matrix_evaluation =
                spartan::MatrixEvaluationMode::CommittedFactored}),
        std::vector<std::size_t>(layer_count, ingress_rns_limbs)};
}

void normalize_packed_proof_sources(
    AuditedMockBackend::EvalContext &eval,
    EncryptedTrace<AuditedMockBackend> &trace,
    std::span<const std::size_t> ingress_rns_limbs_by_layer) {
    CHECK(trace.layers.size() == ingress_rns_limbs_by_layer.size());
    for (std::size_t layer = 1; layer < trace.layers.size(); ++layer) {
        for (auto &value : trace.layers[layer].wires) {
            CHECK(value.is_encrypted());
            mod_switch_to_rns_limb_count<AuditedMockBackend>(
                eval, value.ciphertext(),
                ingress_rns_limbs_by_layer[layer]);
        }
        trace.layers[layer].required_mult_depth =
            ingress_rns_limbs_by_layer[layer] - 1U;
    }
}

struct WideFixture {
    PayloadCircuit payload;
    LayeredCircuit circuit;
    PlainTrace trace;
    PublicSetup public_setup;
    AuditedMockBackend::Contexts contexts;
    FoldedSetup packing_setup;
    EncryptedTrace<AuditedMockBackend> encrypted;
    SingleClaim output_claim;

    WideFixture()
        : payload([] {
              PayloadBuilder builder(PayloadShape::wide(32), 2);
              const auto product = builder.mul(0, 1);
              builder.set_outputs({product});
              return builder.finish();
          }()),
          circuit(compile(payload)),
          trace(synthesize_trace(
              payload, circuit,
              std::vector<SlotVector>{values(32, 5), values(32, 71)})),
          public_setup(make_direct_setup(payload, circuit)),
          contexts(AuditedMockBackend::create(MockParameters{
              .slot_count = 32,
              .fresh_rns_limbs = 14,
              .bits_per_limb = 300,
          })),
          packing_setup(make_test_packing_setup<FoldedSetup>(
              PackingGkrVariant::Folded, contexts.eval,
              folded_bhip_round_count(circuit), circuit.layers.size())),
          encrypted(encrypt_compact_synthetic_trace<AuditedMockBackend>(
              contexts.eval, contexts.client, payload, circuit, trace,
              TraceEncryptionPlan::uniform(circuit, 9))),
          output_claim(make_layer_claim(
              trace.layers.front(),
              std::vector<Fpk>(
                  (std::bit_width(layer_dimensions(circuit.layers.front())
                                      .padded_size) -
                   1U) +
                      5,
                  Fpk::from_base(Fp(23))))) {
        normalize_packed_proof_sources(
            contexts.eval, encrypted,
            packing_setup.proof_ingress_rns_limbs_by_layer);
    }
};

bool verify_wide(WideFixture &fixture,
                 const LaminateFoldedProof<AuditedMockBackend> &proof,
                 const Transcript *expected_final = nullptr) {
    const auto client = make_client_setup<AuditedMockBackend>(
        fixture.public_setup, fixture.contexts.client);
    const FoldedVerifierSetup compact_setup =
        verifier_setup(fixture.packing_setup);
    Transcript transcript("test/packed-gkr/folded/v1");
    const Transcript before = transcript;
    const bool accepted = verify_folded<AuditedMockBackend>(
        fixture.payload, fixture.circuit, fixture.trace.layers.back(),
        fixture.contexts.eval, compact_setup, client,
        fixture.trace.provenance,
        fixture.encrypted.trace_id, fixture.output_claim, proof, transcript);
    if (!accepted) {
        CHECK(transcripts_match(transcript, before));
    } else if (expected_final) {
        CHECK(transcripts_match(transcript, *expected_final));
    }
    return accepted;
}

struct LanedFixture {
    PayloadCircuit payload;
    LayeredCircuit circuit;
    PlainTrace trace;
    OutsourcedGateMleSetupArtifacts gate_setup;
    PublicSetup public_setup;
    AuditedMockBackend::Contexts contexts;
    LanedSetup packing_setup;
    EncryptedTrace<AuditedMockBackend> encrypted;
    SingleClaim output_claim;

    LanedFixture()
        : payload([] {
              PayloadBuilder builder(PayloadShape::laned(4, 32), 2);
              const auto product = builder.mul(0, 1);
              builder.set_outputs({builder.add(product, 0)});
              return builder.finish();
          }()),
          circuit(compile(payload)),
          trace(synthesize_trace(
              payload, circuit,
              std::vector<SlotVector>{values(4, 11), values(4, 41)})),
          gate_setup(preprocess_outsourced_gate_mle_setup(
              payload, circuit, gates::GateTableSet::Laned)),
          public_setup(gate_setup.public_setup),
          contexts(AuditedMockBackend::create(MockParameters{
              .slot_count = 32,
              .fresh_rns_limbs = 14,
              .bits_per_limb = 300,
          })),
          packing_setup(make_test_packing_setup<LanedSetup>(
              PackingGkrVariant::Laned, contexts.eval,
              laned_bhip_round_count(circuit), circuit.layers.size())),
          encrypted(encrypt_compact_synthetic_trace<AuditedMockBackend>(
              contexts.eval, contexts.client, payload, circuit, trace,
              TraceEncryptionPlan::uniform(circuit, 9))),
          output_claim(make_packed_laned_claim(
              trace.layers.front(), laned_layout(circuit, 0),
              std::vector<Fpk>(laned_layer_variables(circuit, 0),
                               Fpk::from_base(Fp(29))))) {
        normalize_packed_proof_sources(
            contexts.eval, encrypted,
            packing_setup.proof_ingress_rns_limbs_by_layer);
    }
};

bool verify_lanes(LanedFixture &fixture,
                  const LaminateLanedProof<AuditedMockBackend> &proof,
                  const Transcript *expected_final = nullptr) {
    const auto client = make_client_setup<AuditedMockBackend>(
        fixture.public_setup, fixture.contexts.client);
    const LanedVerifierSetup compact_setup =
        verifier_setup(fixture.packing_setup);
    Transcript transcript("test/packed-gkr/laned/v1");
    const Transcript before = transcript;
    const bool accepted = verify_laned<AuditedMockBackend>(
        fixture.payload, fixture.circuit, fixture.trace.layers.back(),
        fixture.contexts.eval, compact_setup, client,
        fixture.trace.provenance,
        fixture.encrypted.trace_id, fixture.output_claim, proof, transcript);
    if (!accepted) {
        CHECK(transcripts_match(transcript, before));
    } else if (expected_final) {
        CHECK(transcripts_match(transcript, *expected_final));
    }
    return accepted;
}

std::size_t progress_begin_count(
    std::span<const RuntimeProgressEvent> events,
    RuntimeProgressStage stage) {
    return static_cast<std::size_t>(std::count_if(
        events.begin(), events.end(), [stage](const auto &event) {
            return event.boundary == RuntimeProgressBoundary::Begin &&
                   event.stage == stage;
        }));
}

std::size_t progress_end_count(
    std::span<const RuntimeProgressEvent> events,
    RuntimeProgressStage stage) {
    return static_cast<std::size_t>(std::count_if(
        events.begin(), events.end(), [stage](const auto &event) {
            return event.boundary == RuntimeProgressBoundary::End &&
                   event.stage == stage;
        }));
}

void check_single_progress_span(
    std::span<const RuntimeProgressEvent> events,
    RuntimeProgressStage stage) {
    CHECK(progress_begin_count(events, stage) == 1U);
    CHECK(progress_end_count(events, stage) == 1U);
}

void check_progress_events_are_balanced(
    std::span<const RuntimeProgressEvent> events) {
    std::vector<RuntimeProgressEvent> active;
    for (const RuntimeProgressEvent &event : events) {
        if (event.boundary == RuntimeProgressBoundary::Update) {
            CHECK(!active.empty());
            continue;
        }
        if (event.boundary == RuntimeProgressBoundary::Begin) {
            active.push_back(event);
            continue;
        }
        CHECK(!active.empty());
        RuntimeProgressEvent expected = active.back();
        active.pop_back();
        expected.boundary = RuntimeProgressBoundary::End;
        CHECK(event == expected);
    }
    CHECK(active.empty());
}

template <typename GkrProof>
void check_profiled_gkr_progress(
    const LayeredCircuit &circuit, const GkrProof &proof,
    std::span<const RuntimeProgressEvent> events,
    RuntimeProgressStage reduction_stage,
    RuntimeProgressStage affine_round_stage,
    RuntimeProgressStage multiplication_round_stage,
    RuntimeProgressStage gate_stage) {
    CHECK(!events.empty());
    check_progress_events_are_balanced(events);

    std::size_t next_reduction = 0;
    std::size_t affine_rounds = 0;
    std::size_t multiplication_rounds = 0;
    for (std::size_t layer = 0; layer < proof.reductions.size(); ++layer) {
        const std::size_t rounds = std::visit(
            [](const auto &reduction) { return reduction.rounds.size(); },
            proof.reductions[layer]);
        if (payload::layer_kind(circuit.layers[layer]) ==
            LayerKind::Affine) {
            affine_rounds += rounds;
        } else {
            multiplication_rounds += rounds;
        }
    }

    for (const RuntimeProgressEvent &event : events) {
        if (event.boundary != RuntimeProgressBoundary::Begin ||
            event.stage != reduction_stage) {
            continue;
        }
        CHECK(next_reduction < proof.reductions.size());
        CHECK(event.reduction_layer == next_reduction);
        CHECK(event.source_layer == next_reduction + 1U);
        const bool affine =
            payload::layer_kind(circuit.layers[next_reduction]) ==
            LayerKind::Affine;
        CHECK(event.layer_kind ==
              (affine ? RuntimeProgressLayerKind::Affine
                      : RuntimeProgressLayerKind::Multiplication));
        ++next_reduction;
    }

    CHECK(next_reduction == proof.reductions.size());
    CHECK(progress_begin_count(events, reduction_stage) ==
          proof.reductions.size());
    CHECK(progress_begin_count(events, affine_round_stage) ==
          affine_rounds);
    CHECK(progress_begin_count(events, multiplication_round_stage) ==
          multiplication_rounds);
    CHECK(progress_begin_count(events, gate_stage) == 1U);
}

void check_transcript_packing_prover_progress(
    std::span<const RuntimeProgressEvent> events) {
    check_single_progress_span(
        events, RuntimeProgressStage::TranscriptPackingRevealEvaluation);
    check_single_progress_span(
        events, RuntimeProgressStage::TranscriptPackingAssignment);
    check_single_progress_span(
        events, RuntimeProgressStage::TranscriptPackingSpartanProve);
}

void check_transcript_packing_verifier_progress(
    std::span<const RuntimeProgressEvent> events) {
    check_progress_events_are_balanced(events);
    check_single_progress_span(
        events, RuntimeProgressStage::TranscriptPackingVerifierStatement);
    check_single_progress_span(
        events, RuntimeProgressStage::TranscriptPackingSpartanVerify);
    check_single_progress_span(
        events, RuntimeProgressStage::TranscriptPackingThresholdChecks);
    check_single_progress_span(
        events, RuntimeProgressStage::TranscriptPackingUnpack);
}

} // namespace

int main() {
    test::Runner runner("test_packed_gkr");

    runner.run("packed reveal appender preserves canonical value bytes", [] {
        auto contexts = AuditedMockBackend::create(MockParameters{
            .slot_count = 8,
            .fresh_rns_limbs = 3,
            .bits_per_limb = 60,
        });
        const AuditedMockBackend::Ciphertext ciphertext =
            AuditedMockBackend::encrypt(contexts.client, values(8, 23));
        for (const std::optional<AuditedMockBackend::Ciphertext> &reveal :
             std::array<std::optional<AuditedMockBackend::Ciphertext>, 2>{
                 std::nullopt, ciphertext}) {
            const FheValue<AuditedMockBackend> logical =
                reveal ? FheValue<AuditedMockBackend>::from_ciphertext(*reveal)
                       : FheValue<AuditedMockBackend>::public_zero();
            const std::vector<std::uint8_t> record =
                encode_canonical_fhe_value<AuditedMockBackend>(logical);
            std::vector<std::uint8_t> expected;
            gkr::detail::canonical_encoding::append_size(
                expected, record.size());
            expected.insert(expected.end(), record.begin(), record.end());

            std::vector<std::uint8_t> direct;
            const std::size_t appended =
                laminate::protocol::detail::packed_proof_io_detail::
                    append_reveal_value<AuditedMockBackend>(direct, reveal);
            CHECK(appended == direct.size());
            CHECK(direct == expected);
        }
    });

    runner.run("packed statement binds variant request and output", [] {
        auto contexts = AuditedMockBackend::create(MockParameters{
            .slot_count = 8,
            .fresh_rns_limbs = 3,
            .bits_per_limb = 60,
        });
        Digest setup_id{};
        Digest session_id{};
        Digest circuit_id{};
        setup_id.front() = 1;
        session_id.front() = 2;
        circuit_id.front() = 3;
        std::vector<AuditedMockBackend::Ciphertext> inputs{
            AuditedMockBackend::encrypt(contexts.client, values(8, 5)),
            AuditedMockBackend::encrypt(contexts.client, values(8, 9))};
        const Digest trace_id =
            prevalidated_trace_identity::validated_fhe_evaluated_trace_id<
                AuditedMockBackend>(circuit_id, inputs.size(), inputs);
        std::vector<FheValue<AuditedMockBackend>> output{
            FheValue<AuditedMockBackend>::from_ciphertext(
                AuditedMockBackend::encrypt(contexts.client, values(8, 11))),
            FheValue<AuditedMockBackend>::public_scalar(Fp(17))};
        const LayerDimensions dimensions{16, 16, 8, 8};

        const Digest request = packed_request_commitment<AuditedMockBackend>(
            PackedProtocolVariant::Folded, setup_id, session_id,
            circuit_id, trace_id);
        const Digest statement =
            packed_encrypted_statement_digest<AuditedMockBackend>(
                PackedProtocolVariant::Folded, request, setup_id,
                session_id, circuit_id, trace_id, dimensions, output);
        CHECK(statement == packed_encrypted_statement_digest<AuditedMockBackend>(
                               PackedProtocolVariant::Folded, request,
                               setup_id, session_id, circuit_id, trace_id,
                               dimensions, output));

        const Digest laned_request = packed_request_commitment<AuditedMockBackend>(
            PackedProtocolVariant::Laned, setup_id, session_id,
            circuit_id, trace_id);
        CHECK(laned_request != request);
        auto changed_inputs = inputs;
        changed_inputs.front() =
            AuditedMockBackend::encrypt(contexts.client, values(8, 6));
        const Digest changed_trace_id =
            prevalidated_trace_identity::validated_fhe_evaluated_trace_id<
                AuditedMockBackend>(circuit_id, changed_inputs.size(),
                             changed_inputs);
        CHECK(changed_trace_id != trace_id);
        CHECK(packed_request_commitment<AuditedMockBackend>(
                  PackedProtocolVariant::Folded, setup_id, session_id,
                  circuit_id, changed_trace_id) != request);
        CHECK(packed_encrypted_statement_digest<AuditedMockBackend>(
                  PackedProtocolVariant::Laned, laned_request, setup_id,
                  session_id, circuit_id, trace_id, dimensions, output) !=
              statement);

        auto changed_output = output;
        changed_output.back() =
            FheValue<AuditedMockBackend>::public_scalar(Fp(18));
        CHECK(packed_encrypted_statement_digest<AuditedMockBackend>(
                  PackedProtocolVariant::Folded, request, setup_id,
                  session_id, circuit_id, trace_id, dimensions,
                  changed_output) != statement);

        Transcript prover("test/packed-statement/v1");
        Transcript verifier("test/packed-statement/v1");
        CHECK(derive_packed_output_point(
                  prover, PackedProtocolVariant::Folded, statement, 5) ==
              derive_packed_output_point(
                  verifier, PackedProtocolVariant::Folded, statement, 5));
        Transcript cross_variant("test/packed-statement/v1");
        Transcript folded_again("test/packed-statement/v1");
        CHECK(derive_packed_output_point(
                  cross_variant, PackedProtocolVariant::Laned, statement,
                  5) !=
              derive_packed_output_point(
                  folded_again, PackedProtocolVariant::Folded, statement,
                  5));
    });

    runner.run("threshold assessment identifies every failing reveal", [] {
        auto contexts = AuditedMockBackend::create(MockParameters{
            .slot_count = 8,
            .fresh_rns_limbs = 3,
            .bits_per_limb = 300,
        });
        packing::LazyTernaryParameters parameters =
            packing::selected_lazy_ternary_parameters();
        parameters.repetitions = 3;
        parameters.honest_error_bound = 1;
        const std::uint64_t threshold =
            packing::lazy_ternary_test_threshold(
                parameters.honest_partial_decryption_bound(), 1);

        std::vector<packing::MixedPackingValue<AuditedMockBackend>> reveals(3);
        for (auto &reveal : reveals) {
            reveal.public_c0_coordinates.assign(8, 0);
        }
        reveals[0].public_c0_coordinates[0] = threshold;
        reveals[1].public_c0_coordinates[0] = threshold + 1;
        reveals[2].public_c0_coordinates[0] = threshold + 7;

        const auto assessment =
            protocol::detail::packing_protocol_detail::
                assess_threshold_checks<AuditedMockBackend>(
                    contexts.client, reveals, 1, parameters);
        CHECK(assessment.checks_performed);
        CHECK(assessment.expected_reveal_count == 3);
        CHECK(assessment.observed_reveal_count == 3);
        CHECK(assessment.checked_reveal_count == 3);
        CHECK(assessment.configured_threshold == threshold);
        CHECK(assessment.maximum_observed_norm == threshold + 7);
        CHECK(assessment.first_failing_reveal_index == 1);
        CHECK(assessment.failing_reveal_count == 2);
        CHECK(!assessment.accepts());

        parameters.repetitions = 4;
        const auto malformed =
            protocol::detail::packing_protocol_detail::
                assess_threshold_checks<AuditedMockBackend>(
                    contexts.client, reveals, 1, parameters);
        CHECK(!malformed.checks_performed);
        CHECK(malformed.expected_reveal_count == 4);
        CHECK(malformed.observed_reveal_count == 3);
        CHECK(malformed.checked_reveal_count == 0);
        CHECK(!malformed.accepts());
    });

    runner.run("Folded composes GKR then packing in one transcript", [] {
        WideFixture fixture;
        const auto evaluation = make_packed_evaluation_setup<AuditedMockBackend>(
            fixture.public_setup, fixture.contexts.eval);
        Transcript transcript("test/packed-gkr/folded/v1");
        FoldedProverTimings prover_timings;
        std::vector<RuntimeProgressEvent> progress_events;
        const auto proof = prove_folded_reference_profiled<AuditedMockBackend>(
            fixture.payload, fixture.circuit, fixture.encrypted, evaluation,
            fixture.packing_setup, fixture.output_claim.point, transcript,
            prover_timings, {}, {},
            [&progress_events](const RuntimeProgressEvent &event) {
                progress_events.push_back(event);
            });

        check_profiled_gkr_progress(
            fixture.circuit, proof.gkr, progress_events,
            RuntimeProgressStage::FoldedReduction,
            RuntimeProgressStage::FoldedAffineSumcheckRound,
            RuntimeProgressStage::FoldedMultiplicationSumcheckRound,
            RuntimeProgressStage::FoldedGateMleFinish);
        check_transcript_packing_prover_progress(progress_events);

        const auto commitments =
            collect_transcript_packing_committed_messages(proof.gkr);
        CHECK(!commitments.empty());
        CHECK(commitments.size() ==
              fixture.packing_setup.transcript_packing.relation_plan.shape
                  .aligned_ciphertexts);
        CHECK(!proof.transcript_packing.well_formedness_reveals.empty());
        CHECK(!proof.transcript_packing
                   .digit_decomposed_packed_values.empty());
        const FoldedProofSizeBreakdown size =
            measure_proof_size(proof);
        CHECK(size.total_bytes == encode_canonical(proof).size());
        CHECK(size.committed_gkr_bytes > 0);
        CHECK(size.total_bytes == size.statement_and_metadata_bytes +
                                      size.committed_gkr_bytes +
                                      size.well_formedness_reveal_bytes +
                                      size.digit_packing_ciphertext_bytes +
                                      size.spartan_packing_proof_bytes);
        CHECK(protocol::detail::committed_gkr_encoding_digest(proof.gkr) ==
              sha256(protocol::detail::encode_committed_gkr(proof.gkr)));
        CHECK(size.gkr_commitment_bytes ==
              static_cast<std::size_t>(std::count_if(
                  commitments.begin(), commitments.end(),
                  [](const auto &message) {
                      return message.is_encrypted();
                  })) *
                  PoseidonDigest{}.size());
        CHECK(size.spartan_packing_proof_bytes > 0);
        CHECK(verify_wide(fixture, proof, &transcript));

        const std::vector<std::uint8_t> encoded =
            encode_canonical(proof);
        const FoldedVerifierSetup wire_setup =
            verifier_setup(fixture.packing_setup);
        const PackedProofDecodeLimits limits =
            packed_decode_limits(encoded.size());
        const auto decoded = decode_canonical_folded_proof<AuditedMockBackend>(
            fixture.contexts.eval, encoded, fixture.circuit,
            fixture.public_setup, wire_setup, limits);
        CHECK(encode_canonical(decoded) == encoded);
        auto unsupported_wire_version = encoded;
        unsupported_wire_version[13] = '4';
        CHECK(throws_invalid_argument([&] {
            (void)decode_canonical_folded_proof<AuditedMockBackend>(
                fixture.contexts.eval, unsupported_wire_version,
                fixture.circuit, fixture.public_setup, wire_setup, limits);
        }));
        CHECK(decoded.transcript_packing.well_formedness_reveals.size() ==
              proof.transcript_packing.well_formedness_reveals.size());
        for (std::size_t index = 0;
             index < proof.transcript_packing.well_formedness_reveals.size();
             ++index) {
            const auto &before =
                proof.transcript_packing.well_formedness_reveals[index];
            const auto &after =
                decoded.transcript_packing.well_formedness_reveals[index];
            CHECK(before.has_value() == after.has_value());
            if (before) {
                CHECK(before->slots == after->slots);
                CHECK(before->coefficient_commitment_coordinates ==
                      after->coefficient_commitment_coordinates);
            }
        }
        CHECK(verify_wide(fixture, decoded));

        auto old_wire_version = encoded;
        CHECK(old_wire_version.size() > 13U);
        CHECK(old_wire_version[13] == static_cast<std::uint8_t>('7'));
        old_wire_version[13] = static_cast<std::uint8_t>('6');
        CHECK(throws_invalid_argument([&] {
            (void)decode_canonical_folded_proof<AuditedMockBackend>(
                fixture.contexts.eval, old_wire_version, fixture.circuit,
                fixture.public_setup, wire_setup,
                packed_decode_limits(old_wire_version.size()));
        }));

        auto trailing = encoded;
        trailing.push_back(0);
        CHECK(throws_invalid_argument([&] {
            (void)decode_canonical_folded_proof<AuditedMockBackend>(
                fixture.contexts.eval, trailing, fixture.circuit,
                fixture.public_setup, wire_setup,
                packed_decode_limits(trailing.size()));
        }));
        auto truncated = encoded;
        truncated.pop_back();
        CHECK(throws_invalid_argument([&] {
            (void)decode_canonical_folded_proof<AuditedMockBackend>(
                fixture.contexts.eval, truncated, fixture.circuit,
                fixture.public_setup, wire_setup,
                packed_decode_limits(encoded.size()));
        }));
        auto malformed_witness_opening = encoded;
        const auto &spartan_setup =
            wire_setup.transcript_packing.spartan;
        const std::size_t witness_log =
            std::bit_width(
                spartan_setup.circuit_metadata.assignment_half_size()) -
            1U;
        const std::size_t witness_opening_bytes =
            proof.transcript_packing.proof_of_packing
                .witness_opening.bytes.size();
        const std::size_t witness_opening_max_bytes =
            spartan::basefold_opening_proof_max_size_bytes(
                witness_log, 1U,
                wire_setup.transcript_packing.basefold_parameters);
        CHECK(witness_opening_bytes <= witness_opening_max_bytes);
        CHECK(witness_opening_bytes <= malformed_witness_opening.size());
        overwrite_u64(
            malformed_witness_opening,
            malformed_witness_opening.size() - witness_opening_bytes,
            3U);
        const auto decoded_malformed_witness =
            decode_canonical_folded_proof<AuditedMockBackend>(
                fixture.contexts.eval, malformed_witness_opening,
                fixture.circuit, fixture.public_setup, wire_setup, limits);
        CHECK(encode_canonical(decoded_malformed_witness) ==
              malformed_witness_opening);
        CHECK(!verify_wide(fixture, decoded_malformed_witness));

        auto oversized_witness_opening = encoded;
        overwrite_u64(
            oversized_witness_opening,
            oversized_witness_opening.size() - witness_opening_bytes -
                sizeof(std::uint64_t),
            witness_opening_max_bytes + 1U);
        CHECK(throws_invalid_argument([&] {
            (void)decode_canonical_folded_proof<AuditedMockBackend>(
                fixture.contexts.eval, oversized_witness_opening,
                fixture.circuit, fixture.public_setup, wire_setup, limits);
        }));
        auto wrong_reveal_count = encoded;
        constexpr std::size_t packed_tag_bytes = 14U;
        std::uint64_t committed_bytes = 0;
        for (std::size_t byte = 0; byte < sizeof(committed_bytes); ++byte) {
            committed_bytes |=
                static_cast<std::uint64_t>(
                    wrong_reveal_count[packed_tag_bytes + byte])
                << (8U * byte);
        }
        overwrite_u64(wrong_reveal_count,
                      packed_tag_bytes + sizeof(committed_bytes) +
                          static_cast<std::size_t>(committed_bytes),
                      test_packing_parameters().repetitions + 1U);
        CHECK(throws_invalid_argument([&] {
            (void)decode_canonical_folded_proof<AuditedMockBackend>(
                fixture.contexts.eval, wrong_reveal_count, fixture.circuit,
                fixture.public_setup, wire_setup, limits);
        }));
        PackedProofDecodeLimits too_small = limits;
        too_small.max_proof_bytes = encoded.size() - 1U;
        CHECK(throws_invalid_argument([&] {
            (void)decode_canonical_folded_proof<AuditedMockBackend>(
                fixture.contexts.eval, encoded, fixture.circuit,
                fixture.public_setup, wire_setup, too_small);
        }));
        PackedProofDecodeLimits ciphertext_too_large = limits;
        ciphertext_too_large.max_ciphertext_bytes = 1U;
        CHECK(throws_invalid_argument([&] {
            (void)decode_canonical_folded_proof<AuditedMockBackend>(
                fixture.contexts.eval, encoded, fixture.circuit,
                fixture.public_setup, wire_setup, ciphertext_too_large);
        }));
        CHECK(prover_timings.layers.size() == proof.gkr.reductions.size());
        CHECK(prover_timings.transcript_packing_wall_ms >= 0);

        // A packing suffix must continue the GKR transcript. Restarting
        // with only its final digest does not reproduce its transcript state.
        Transcript restarted_packing_branch("test/packed-gkr/folded/v1");
        protocol::detail::bind_committed_gkr_for_packing(
            proof.gkr, restarted_packing_branch);
        AuditedMockBackend::secret_key_calls = 0;
        const auto detached_packing =
            protocol::detail::verify_transcript_packing<AuditedMockBackend>(
                fixture.contexts.eval, fixture.contexts.client,
                fixture.packing_setup.transcript_packing, commitments,
                proof.transcript_packing, restarted_packing_branch);
        CHECK(!detached_packing.accepts());
        CHECK(AuditedMockBackend::secret_key_calls == 0);

        Transcript packing_diagnostic("test/packed-gkr/folded/v1");
        const auto public_gkr =
            protocol::detail::replay_packed_gkr_transcript<
                ProtocolVariant::LaminateFolded, AuditedMockBackend>(
                fixture.circuit, fixture.public_setup, proof.gkr,
                fixture.output_claim.point, packing_diagnostic);
        CHECK(public_gkr.has_value());
        protocol::detail::bind_committed_gkr_for_packing(
            proof.gkr, packing_diagnostic);
        const auto packed =
            protocol::detail::verify_transcript_packing<AuditedMockBackend>(
                fixture.contexts.eval, fixture.contexts.client,
                fixture.packing_setup.transcript_packing, commitments,
                proof.transcript_packing, packing_diagnostic);
        CHECK(packed.accepts());
        CHECK(AuditedMockBackend::secret_key_calls > 0);
        CHECK(transcripts_match(packing_diagnostic, transcript));
        CHECK(packed.threshold_assessment.checks_performed);
        CHECK(packed.threshold_assessment.checked_reveal_count ==
              test_packing_parameters().repetitions);
        CHECK(packed.threshold_assessment.configured_threshold ==
              packing::lazy_ternary_test_threshold(
                  test_packing_parameters()
                      .honest_partial_decryption_bound(),
                  commitments.size()));
        CHECK(packed.threshold_assessment.maximum_observed_norm <=
              packed.threshold_assessment.configured_threshold);
        CHECK(!packed.threshold_assessment.first_failing_reveal_index);
        CHECK(packed.threshold_assessment.failing_reveal_count == 0);

        const auto client = make_client_setup<AuditedMockBackend>(
            fixture.public_setup, fixture.contexts.client);
        FoldedVerifierTimings verifier_timings;
        std::vector<RuntimeProgressEvent> verifier_progress_events;
        const FoldedVerifierSetup compact_setup =
            protocol::verifier_setup(fixture.packing_setup);
        Transcript profiled_verifier("test/packed-gkr/folded/v1");
        CHECK(verify_folded_profiled<AuditedMockBackend>(
            fixture.payload, fixture.circuit, fixture.trace.layers.back(),
            fixture.contexts.eval, compact_setup, client,
            fixture.trace.provenance, fixture.encrypted.trace_id,
            fixture.output_claim, proof, profiled_verifier,
            verifier_timings,
            [&verifier_progress_events](
                const RuntimeProgressEvent &event) {
                verifier_progress_events.push_back(event);
            }));
        check_transcript_packing_verifier_progress(
            verifier_progress_events);
        CHECK(transcripts_match(profiled_verifier, transcript));
        CHECK(verifier_timings.layers.size() == proof.gkr.reductions.size());
        CHECK(verifier_timings.packed_message_verification_wall_ms >= 0);
        CHECK(verifier_timings.transcript_packing_threshold ==
              packed.threshold_assessment);

        FoldedVerifierSetup wrong_setup = compact_setup;
        wrong_setup.transcript_packing.variant = PackingGkrVariant::Laned;
        Transcript wrong_setup_verifier("test/packed-gkr/folded/v1");
        CHECK(!verify_folded<AuditedMockBackend>(
            fixture.payload, fixture.circuit, fixture.trace.layers.back(),
            fixture.contexts.eval, wrong_setup, client,
            fixture.trace.provenance, fixture.encrypted.trace_id,
            fixture.output_claim, proof, wrong_setup_verifier));
        FoldedVerifierTimings wrong_setup_timings;
        Transcript wrong_profiled_verifier("test/packed-gkr/folded/v1");
        CHECK(!verify_folded_profiled<AuditedMockBackend>(
            fixture.payload, fixture.circuit, fixture.trace.layers.back(),
            fixture.contexts.eval, wrong_setup, client,
            fixture.trace.provenance, fixture.encrypted.trace_id,
            fixture.output_claim, proof, wrong_profiled_verifier,
            wrong_setup_timings));

        // An initial statement prefix and the GKR output point are part of
        // the same coin history as Spartan, not merely separate GKR inputs.
        const auto reject_public_prefix = [&](Transcript candidate,
                                              SingleClaim output_claim) {
            const Transcript before = candidate;
            AuditedMockBackend::secret_key_calls = 0;
            CHECK(!verify_folded<AuditedMockBackend>(
                fixture.payload, fixture.circuit,
                fixture.trace.layers.back(), fixture.contexts.eval,
                compact_setup, client, fixture.trace.provenance,
                fixture.encrypted.trace_id, output_claim, proof,
                candidate));
            CHECK(AuditedMockBackend::secret_key_calls == 0);
            CHECK(transcripts_match(candidate, before));
        };
        Transcript changed_prefix("test/packed-gkr/folded/v1");
        changed_prefix.observe("test/changed-initial-statement", 1U);
        reject_public_prefix(changed_prefix, fixture.output_claim);
        SingleClaim changed_point = fixture.output_claim;
        changed_point.point.front() += Fpk::one();
        reject_public_prefix(Transcript("test/packed-gkr/folded/v1"),
                             changed_point);

        auto changed_spartan = proof;
        changed_spartan.transcript_packing.proof_of_packing
            .witness_commitment.root.front() ^= 1U;
        AuditedMockBackend::secret_key_calls = 0;
        CHECK(!verify_wide(fixture, changed_spartan));
        CHECK(AuditedMockBackend::secret_key_calls == 0);

        Transcript rejected_profiled("test/packed-gkr/folded/v1");
        const Transcript before_rejected_profiled = rejected_profiled;
        FoldedVerifierTimings rejected_timings;
        CHECK(!verify_folded_profiled<AuditedMockBackend>(
            fixture.payload, fixture.circuit, fixture.trace.layers.back(),
            fixture.contexts.eval, compact_setup, client,
            fixture.trace.provenance, fixture.encrypted.trace_id,
            fixture.output_claim, changed_spartan, rejected_profiled,
            rejected_timings));
        CHECK(AuditedMockBackend::secret_key_calls == 0);
        CHECK(transcripts_match(rejected_profiled,
                                before_rejected_profiled));

        // A failure after successful packing and decryption is transactional
        // too: the claimed output value is checked by deferred GKR algebra.
        SingleClaim wrong_value = fixture.output_claim;
        wrong_value.value += Fpk::one();
        Transcript late_rejection("test/packed-gkr/folded/v1");
        const Transcript before_late_rejection = late_rejection;
        FoldedVerifierTimings late_rejection_timings;
        AuditedMockBackend::secret_key_calls = 0;
        CHECK(!verify_folded_profiled<AuditedMockBackend>(
            fixture.payload, fixture.circuit, fixture.trace.layers.back(),
            fixture.contexts.eval, compact_setup, client,
            fixture.trace.provenance, fixture.encrypted.trace_id,
            wrong_value, proof, late_rejection, late_rejection_timings));
        CHECK(AuditedMockBackend::secret_key_calls > 0);
        CHECK(transcripts_match(late_rejection, before_late_rejection));

        CHECK(proof.transcript_packing.proof_of_packing
                  .factored_evaluation.has_value());
        auto changed_factored_claim = proof;
        changed_factored_claim.transcript_packing.proof_of_packing
            .factored_evaluation->tensors.front().claim += Fq2::one();
        CHECK(!verify_wide(fixture, changed_factored_claim));

        auto changed_factored_opening = proof;
        auto &factored_opening = changed_factored_opening.transcript_packing
                                     .proof_of_packing
                                     .factored_evaluation->tensors.front()
                                     .opening.bytes;
        factored_opening[factored_opening.size() / 2U] ^= 1U;
        const auto malformed_factored_wire =
            encode_canonical(changed_factored_opening);
        const auto decoded_malformed_factored =
            decode_canonical_folded_proof<AuditedMockBackend>(
                fixture.contexts.eval, malformed_factored_wire,
                fixture.circuit, fixture.public_setup, wire_setup, limits);
        CHECK(encode_canonical(decoded_malformed_factored) ==
              malformed_factored_wire);
        CHECK(!verify_wide(fixture, decoded_malformed_factored));

        auto changed_commitment = proof;
        corrupt_first_commitment(changed_commitment);
        AuditedMockBackend::secret_key_calls = 0;
        CHECK(!verify_wide(fixture, changed_commitment));
        CHECK(AuditedMockBackend::secret_key_calls == 0);

        auto changed_digit = proof;
        auto changed_digit_value = std::find_if(
            changed_digit.transcript_packing
                .digit_decomposed_packed_values.begin(),
            changed_digit.transcript_packing
                .digit_decomposed_packed_values.end(),
            [](const auto &candidate) { return candidate.has_value(); });
        CHECK(changed_digit_value !=
              changed_digit.transcript_packing
                  .digit_decomposed_packed_values.end());
        (*changed_digit_value)->slots.front() += Fp::one();
        CHECK(!verify_wide(fixture, changed_digit));

    });

    runner.run("Laned composes GKR and gate PCS then packing", [] {
        LanedFixture fixture;
        const auto evaluation = make_packed_evaluation_setup<AuditedMockBackend>(
            fixture.public_setup, fixture.contexts.eval,
            fixture.gate_setup.prover_key);
        Transcript transcript("test/packed-gkr/laned/v1");
        LanedProverTimings prover_timings;
        std::vector<RuntimeProgressEvent> progress_events;
        const auto proof = prove_laned_reference_profiled<AuditedMockBackend>(
            fixture.payload, fixture.circuit, fixture.encrypted, evaluation,
            fixture.packing_setup, fixture.output_claim.point, transcript,
            prover_timings, {}, {},
            [&progress_events](const RuntimeProgressEvent &event) {
                progress_events.push_back(event);
            });

        check_profiled_gkr_progress(
            fixture.circuit, proof.gkr, progress_events,
            RuntimeProgressStage::LanedReduction,
            RuntimeProgressStage::LanedAffineSumcheckRound,
            RuntimeProgressStage::LanedMultiplicationSumcheckRound,
            RuntimeProgressStage::LanedGateMleFinish);
        check_transcript_packing_prover_progress(progress_events);
        CHECK(progress_begin_count(
                  progress_events,
                  RuntimeProgressStage::LanedAffineSumcheckRound) > 0U);
        CHECK(progress_begin_count(
                  progress_events,
                  RuntimeProgressStage::LanedMultiplicationSumcheckRound) >
              0U);
        CHECK(progress_begin_count(
                  progress_events,
                  RuntimeProgressStage::LanedAffineSlotCheckpoint) +
                  progress_begin_count(
                      progress_events,
                      RuntimeProgressStage::
                          LanedMultiplicationSlotCheckpoint) ==
              proof.gkr.reductions.size());
        CHECK(prover_timings.layers.size() == proof.gkr.reductions.size());

        CHECK(collect_transcript_packing_committed_messages(proof.gkr).size() ==
              fixture.packing_setup.transcript_packing.relation_plan.shape
                  .aligned_ciphertexts);
        CHECK(verify_lanes(fixture, proof, &transcript));

        const std::vector<std::uint8_t> encoded =
            encode_canonical(proof);
        const LanedVerifierSetup wire_setup =
            verifier_setup(fixture.packing_setup);
        const auto decoded = decode_canonical_laned_proof<AuditedMockBackend>(
            fixture.contexts.eval, encoded, fixture.circuit,
            fixture.public_setup, wire_setup,
            packed_decode_limits(encoded.size()));
        CHECK(encode_canonical(decoded) == encoded);
        CHECK(verify_lanes(fixture, decoded));

        const auto client = make_client_setup<AuditedMockBackend>(
            fixture.public_setup, fixture.contexts.client);
        const LanedVerifierSetup compact_setup =
            protocol::verifier_setup(fixture.packing_setup);
        LanedVerifierTimings verifier_timings;
        std::vector<RuntimeProgressEvent> verifier_progress_events;
        Transcript profiled_verifier("test/packed-gkr/laned/v1");
        CHECK(verify_laned_profiled<AuditedMockBackend>(
            fixture.payload, fixture.circuit, fixture.trace.layers.back(),
            fixture.contexts.eval, compact_setup, client,
            fixture.trace.provenance, fixture.encrypted.trace_id,
            fixture.output_claim, proof, profiled_verifier,
            verifier_timings,
            [&verifier_progress_events](
                const RuntimeProgressEvent &event) {
                verifier_progress_events.push_back(event);
            }));
        check_transcript_packing_verifier_progress(
            verifier_progress_events);
        CHECK(transcripts_match(profiled_verifier, transcript));

        CHECK(proof.gkr.gate_mle_opening.has_value());
        CHECK(!proof.gkr.gate_mle_opening->table_openings.empty());
        auto changed_gate_opening = proof;
        auto &gate_pcs = changed_gate_opening.gkr.gate_mle_opening
                             ->table_openings.front().opening;
        CHECK(!gate_pcs.folding.final_codeword.empty());
        gate_pcs.folding.final_codeword.front() += Fpk::one();
        AuditedMockBackend::secret_key_calls = 0;
        CHECK(!verify_lanes(fixture, changed_gate_opening));
        CHECK(AuditedMockBackend::secret_key_calls == 0);

        auto changed_gate_claim = proof;
        CHECK(!changed_gate_claim.gkr.gate_mle_opening
                   ->claimed_values.empty());
        changed_gate_claim.gkr.gate_mle_opening
            ->claimed_values.front() += Fpk::one();
        CHECK(!verify_lanes(fixture, changed_gate_claim));
        CHECK(AuditedMockBackend::secret_key_calls == 0);

        auto changed_spartan = proof;
        changed_spartan.transcript_packing.proof_of_packing
            .witness_commitment.root.front() ^= 1U;
        CHECK(!verify_lanes(fixture, changed_spartan));
        CHECK(AuditedMockBackend::secret_key_calls == 0);

        auto changed_commitment = proof;
        corrupt_first_commitment(changed_commitment);
        CHECK(!verify_lanes(fixture, changed_commitment));
        CHECK(AuditedMockBackend::secret_key_calls == 0);

        auto changed_reveal = proof;
        auto &first_present = *std::find_if(
            changed_reveal.transcript_packing.well_formedness_reveals.begin(),
            changed_reveal.transcript_packing.well_formedness_reveals.end(),
            [](const auto &candidate) { return candidate.has_value(); });
        first_present->coefficient_commitment_coordinates.front() += 1;
        CHECK(!verify_lanes(fixture, changed_reveal));
    });

    return runner.summary();
}
