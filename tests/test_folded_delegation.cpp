/// @file test_folded_delegation.cpp
/// @brief One-request/one-response Folded delegation across all trace paths.

#include "test_helpers.hpp"
#include "packed_setup_fixture.hpp"

#include "laminate/delegation/folded/client.hpp"
#include "laminate/delegation/folded/profiling/client.hpp"
#include "laminate/delegation/folded/reference/client.hpp"
#include "laminate/delegation/folded/reference/server.hpp"
#include "laminate/delegation/folded/wire/codec.hpp"
#include "laminate/fhe/layout/slot_grid.hpp"
#include "laminate/fhe/mock_backend.hpp"
#include "laminate/gkr/detail/folded/verifier.hpp"
#include "laminate/payload/compiler.hpp"
#include "laminate/payload/wide_fhe_evaluator.hpp"
#include "laminate/protocol/detail/packing/transcript_reader.hpp"
#include "delegation/packed_external_test_support.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <system_error>
#include <type_traits>
#include <vector>

using namespace laminate;
using namespace laminate::delegation;
using namespace laminate::fhe;
using namespace laminate::gkr;
using namespace laminate::payload;
using namespace laminate::protocol;

namespace {

struct ReplayMockBackend : MockBackend {
    static std::size_t remaining_mult_depth(
        const EvalContext &context, const Ciphertext &ciphertext) {
        (void)context;
        return ciphertext.rns_limbs - 1U;
    }
};

static_assert(fhe::PersistableFheBackend<ReplayMockBackend>);
static_assert(fhe::PublicVerifierFheBackend<ReplayMockBackend>);
static_assert(protocol::PackedProofDecodeContext<
              ReplayMockBackend,
              ReplayMockBackend::PublicVerifierContext>);
static_assert(!std::is_convertible_v<
              PackedClientSetup<ReplayMockBackend>,
              EvaluationSetup<ReplayMockBackend>>);
static_assert(!std::is_copy_constructible_v<FoldedClientAwaitingResponse>);
static_assert(!std::is_copy_constructible_v<FoldedClientOpenedResponse>);
static_assert(!std::is_default_constructible_v<FoldedClientNonce>);
static_assert(!std::is_constructible_v<FoldedClientNonce, Digest>);
static_assert(!std::is_copy_constructible_v<
              FoldedServerReadyToProve<ReplayMockBackend>>);
static_assert(std::is_move_constructible_v<
              FoldedServerReadyToProve<ReplayMockBackend>>);
static_assert(!std::is_copy_constructible_v<FileFoldedServerReadyToProve>);
static_assert(std::is_move_constructible_v<FileFoldedServerReadyToProve>);
static_assert(!std::is_copy_constructible_v<
              CheckpointReplayFoldedServerReadyToProve<
                  ReplayMockBackend>>);

class TemporaryDirectory {
  public:
    TemporaryDirectory() {
        const auto stamp = std::chrono::steady_clock::now()
                               .time_since_epoch()
                               .count();
        for (std::size_t attempt = 0; attempt < 100; ++attempt) {
            path_ = std::filesystem::temp_directory_path() /
                    ("laminate-folded-delegation-" +
                     std::to_string(stamp) + "-" +
                     std::to_string(attempt));
            if (std::filesystem::create_directory(path_)) {
                return;
            }
        }
        throw std::runtime_error("failed to create temporary directory");
    }

    ~TemporaryDirectory() {
        std::error_code ignored;
        std::filesystem::remove_all(path_, ignored);
    }

    std::filesystem::path make_child(const std::string &name) const {
        const std::filesystem::path child = path_ / name;
        if (!std::filesystem::create_directory(child)) {
            throw std::runtime_error("failed to create test directory");
        }
        return child;
    }

  private:
    std::filesystem::path path_;
};

FoldedClientNonce test_nonce(std::uint8_t seed) {
    std::array<std::uint8_t, 32> bytes{};
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        bytes[index] = static_cast<std::uint8_t>(seed + index);
    }
    return make_folded_client_nonce(bytes);
}

SlotVector values(std::size_t count, std::uint64_t seed) {
    SlotVector result;
    result.reserve(count);
    for (std::size_t index = 0; index < count; ++index) {
        result.emplace_back(seed + 5U * index + index * index);
    }
    return result;
}

PayloadCircuit test_payload(std::size_t slots, bool with_adjoint = false) {
    PayloadBuilder builder(PayloadShape::wide(slots), 2);
    WireId left = 0;
    if (with_adjoint) {
        // A rotation followed by a nonuniform mask retains an internal Wide
        // adjoint; x*y+x alone composes entirely into public boundary rows.
        const auto mask = builder.add_plaintext(values(slots, 13));
        left = builder.mul_plain(builder.rotate(left, 5), mask);
    }
    const WireId product = builder.mul(left, 1);
    builder.set_outputs({builder.add(product, 0)});
    return builder.finish();
}

FoldedSetup make_test_packing_setup(
    const ReplayMockBackend::EvalContext &eval,
    const LayeredCircuit &circuit) {
    auto parameters = packing::selected_lazy_ternary_parameters();
    parameters.repetitions = 1;
    return FoldedSetup{make_transcript_packing_spartan_setup(
        PackingGkrVariant::Folded, ReplayMockBackend::slot_count(eval),
        folded_bhip_round_count(circuit),
        {.centered_coefficients =
             [&eval](const SlotVector &slots) {
                 return ReplayMockBackend::
                     encode_centered_plaintext_coefficients(eval, slots);
             },
         .native_ntt =
             [&eval](std::span<const std::int64_t> coefficients) {
                 return ReplayMockBackend::
                     encode_lowest_plaintext_ntt_coordinates(
                         eval, coefficients);
             }},
        parameters,
        spartan::BaseFoldPcsParameters{.log_rate = 1, .query_count = 1},
        spartan::Options{
            .matrix_evaluation =
                spartan::MatrixEvaluationMode::CommittedFactored}),
        std::vector<std::size_t>(
            circuit.layers.size(),
            kFoldedFixtureProofIngressRnsLimbs)};
}

std::vector<std::size_t>
multiplication_layers(const LayeredCircuit &circuit) {
    std::vector<std::size_t> result;
    for (std::size_t layer = 0; layer + 1U < circuit.layers.size(); ++layer) {
        if (layer_kind(circuit.layers[layer]) == LayerKind::Multiplication) {
            result.push_back(layer);
        }
    }
    return result;
}

SlotVector expected_output(std::span<const SlotVector> inputs,
                           bool with_adjoint = false) {
    SlotVector left = inputs[0];
    if (with_adjoint) {
        left = grid_rotate(left, 5);
        const auto mask = values(left.size(), 13);
        for (std::size_t slot = 0; slot < left.size(); ++slot) {
            left[slot] *= mask[slot];
        }
    }
    SlotVector result(inputs.front().size());
    for (std::size_t slot = 0; slot < result.size(); ++slot) {
        result[slot] =
            left[slot] * inputs[1][slot] + inputs[0][slot];
    }
    return result;
}

bool throws_invalid_argument(const auto &body) {
    try {
        body();
    } catch (const std::invalid_argument &) {
        return true;
    }
    return false;
}

void corrupt_first_commitment(
    LaminateFoldedProof<ReplayMockBackend> &proof) {
    std::visit(
        [](auto &reduction) {
            auto &message = reduction.rounds.front().packed_evaluations;
            CHECK(message.is_encrypted());
            auto commitment = message.commitment();
            commitment.digest.front() ^= 0x80U;
            message = CommittedPackedMessage::encrypted_message(
                std::move(commitment));
        },
        proof.gkr.reductions.front());
}

PayloadCheckpointReplayProblem checkpoint_replay_problem(
    const LayeredCircuit &circuit, const FheEvaluationPlan &evaluation,
    const ReplayMockBackend::EvalContext &eval,
    const EncryptedTrace<ReplayMockBackend> &trace) {
    const std::vector<std::uint64_t> work =
        payload_replay_work_units(circuit);
    std::vector<PayloadLayerResourceEstimate> resources;
    resources.reserve(trace.layers.size());
    for (std::size_t layer = 0; layer < trace.layers.size(); ++layer) {
        const auto &wires = trace.layers[layer].wires;
        CHECK(!wires.empty());
        std::uint64_t encoded_bound = 0;
        for (const auto &wire : wires) {
            encoded_bound = std::max<std::uint64_t>(
                encoded_bound,
                fhe::encode_fhe_value_record<ReplayMockBackend>(eval, wire)
                    .size());
        }
        const auto encrypted = std::find_if(
            wires.begin(), wires.end(),
            [](const auto &wire) { return wire.is_encrypted(); });
        CHECK(encrypted != wires.end());
        auto proof_ingress = encrypted->ciphertext();
        normalize_ciphertext_for_proof<
            ReplayMockBackend>(
            eval, proof_ingress,
            evaluation.proof_ingress_mult_depth_by_layer[layer]);
        const std::uint64_t proof_ingress_encoded =
            fhe::encode_fhe_value_record<ReplayMockBackend>(
                eval, fhe::FheValue<ReplayMockBackend>::from_ciphertext(
                          proof_ingress))
                .size();
        const bool aliases_natural =
            ReplayMockBackend::rns_limb_count(eval, proof_ingress) ==
            ReplayMockBackend::rns_limb_count(
                eval, encrypted->ciphertext());
        resources.push_back(PayloadLayerResourceEstimate{
            .rns_limb_count = ReplayMockBackend::rns_limb_count(
                eval, encrypted->ciphertext()),
            .checkpoint_bytes = standalone_checkpoint_layer_artifact_bytes(
                canonical_layer_storage_layout(circuit, layer)
                    .stored_wire_count,
                encoded_bound),
            .serialized_ciphertext_bytes = encoded_bound,
            .resident_ciphertext_bytes = encoded_bound + 4096U,
            .replay_work_units = work[layer],
            .proof_ingress_serialized_ciphertext_bytes =
                aliases_natural ? 0 : proof_ingress_encoded,
            .proof_ingress_resident_ciphertext_bytes =
                aliases_natural ? 0 : proof_ingress_encoded + 4096U,
        });
    }
    return make_payload_checkpoint_replay_problem(
        circuit, evaluation, resources, 512, 0);
}

PayloadCheckpointReplayBudgets checkpoint_budgets() {
    return PayloadCheckpointReplayBudgets{
        .max_live_scratch_bytes = std::uint64_t{1} << 30U,
        .max_resident_ciphertext_bytes = std::uint64_t{1} << 30U,
        .max_ciphertexts_per_chunk = 8,
        .max_recomputation_factor = {100, 1},
        .reserved_live_scratch_bytes = 4096,
        .reserved_resident_bytes = 2048,
    };
}

CheckpointReplayServerStorageLimits checkpoint_storage_limits(
    const LayeredCircuit &circuit,
    const PayloadCheckpointReplayBudgets &budgets) {
    CheckpointReplayServerStorageLimits result{
        .caps =
            {
                .max_total_local_disk_bytes =
                    budgets.max_live_scratch_bytes,
                .max_resident_ram_bytes =
                    budgets.max_resident_ciphertext_bytes,
                .max_phase_combined_bytes =
                    budgets.max_live_scratch_bytes +
                    budgets.max_resident_ciphertext_bytes,
            },
        .common = {.local_disk_bytes = 1024,
                   .resident_ram_bytes = 512},
        .payload_gkr_only =
            {.local_disk_bytes =
                 budgets.reserved_live_scratch_bytes - 1024,
             .resident_ram_bytes =
                 budgets.reserved_resident_bytes - 512},
        .transcript_packing_only =
            {.local_disk_bytes = 4096, .resident_ram_bytes = 4096},
    };
    for (std::size_t layer = 0; layer + 1U < circuit.layers.size(); ++layer) {
        result.reduction_workspaces.push_back(
            CheckpointReplayReductionResidentWorkspace{
                .reduction_layer = layer,
                .kind = layer_kind(circuit.layers[layer]),
                .multiplication_builder_phase_bytes =
                    layer_kind(circuit.layers[layer]) ==
                            LayerKind::Multiplication
                        ? std::uint64_t{4096}
                        : std::uint64_t{0},
                .reduction_phase_bytes = 4096,
            });
    }
    return result;
}

FoldedServerProofOptions make_proof_options(
    const LayeredCircuit &circuit, const TemporaryDirectory &directory,
    const std::string &prefix) {
    FoldedServerProofOptions options;
    options.lifecycle = FileTraceSessionLifecycle::IrreversibleNoRetry;
    options.reclaim_completed_multiplication_scratch = true;
    for (std::size_t layer : multiplication_layers(circuit)) {
        options.proof.multiplication_scratch.push_back(
            folded_detail::FileFoldedMultiplicationScratch{
                layer, directory.make_child(prefix + std::to_string(layer)),
                FileTraceStoreOptions{
                    .max_total_bytes = std::uint64_t{1} << 26U,
                    .min_free_bytes = 1,
                }});
    }
    return options;
}

struct Fixture {
    static constexpr std::size_t kSlots = 32;
    PayloadCircuit payload = test_payload(kSlots);
    LayeredCircuit circuit = compile(payload);
    std::vector<SlotVector> inputs{values(kSlots, 7), values(kSlots, 31)};
    ReplayMockBackend::Contexts contexts =
        ReplayMockBackend::create(MockParameters{
            .slot_count = kSlots,
            .fresh_rns_limbs = 14,
            .bits_per_limb = 300,
        });
    std::shared_ptr<const gates::GateTableProverKey> gate_key;
    PublicSetup public_setup;
    EvaluationSetup<ReplayMockBackend> server =
        make_packed_evaluation_setup<ReplayMockBackend>(public_setup,
                                                        contexts.eval, gate_key);
    ClientSetup<ReplayMockBackend> client =
        make_client_setup<ReplayMockBackend>(public_setup,
                                              contexts.client);
    PackedClientSetup<ReplayMockBackend> packed_client =
        make_packed_client_setup_from_verifier_context<ReplayMockBackend>(
            client,
            ReplayMockBackend::make_public_verifier_context(
                contexts.eval));
    FoldedSetup packing_setup =
        make_test_packing_setup(contexts.eval, circuit);
    FheEvaluationPlan evaluation = apply_packed_proof_ingress_schedule(
        circuit, FheEvaluationPlan::without_payload_switches(circuit, 9),
        packing_setup);

    explicit Fixture(bool outsourced = false)
        : payload(test_payload(kSlots, outsourced)),
          gate_key(outsourced
              ? std::make_shared<gates::GateTableProverKey>(
                    gates::preprocess_gate_tables(
                        circuit, gates::GateTableSet::Wide))
              : nullptr),
          public_setup(gate_key
              ? make_outsourced_gate_setup(payload, circuit, gate_key->verifier)
              : make_direct_setup(payload, circuit)) {}
};

void check_response(Fixture &fixture, FoldedClientAwaitingResponse state,
                    const FoldedResponse<ReplayMockBackend> &response,
                    std::string_view domain,
                    const Transcript &prover_transcript) {
    const FoldedVerifierSetup verifier =
        protocol::verifier_setup(fixture.packing_setup);
    Transcript transcript(domain);
    auto opened = open_folded_response<ReplayMockBackend>(
        fixture.payload, fixture.circuit, fixture.packed_client,
        std::move(state), response, transcript);
    CHECK(opened.has_value());
    FoldedVerifierTimings timings;
    auto outputs = verify_opened_folded_response_profiled<ReplayMockBackend>(
        fixture.payload, fixture.circuit, verifier,
        fixture.packed_client, std::move(*opened), response, transcript,
        timings);
    CHECK(outputs.has_value());
    CHECK(outputs->size() == 1);
    CHECK(outputs->front() ==
          expected_output(fixture.inputs, fixture.gate_key != nullptr));
    CHECK(Transcript(transcript).challenge_fq2() ==
          Transcript(prover_transcript).challenge_fq2());
}

void check_validated_structure_token_rejects_mutation(
    Fixture &fixture,
    const FoldedResponse<ReplayMockBackend> &response) {
    using Reader = protocol::detail::PackedTranscriptReader;
    using Verifier = gkr::folded_detail::FoldedGkrVerifier<
        ReplayMockBackend, Reader, gkr::CommittedPackedMessage>;

    auto proof = response.proof.gkr;
    const auto validated = Verifier::validate_structure_once(
        proof, TraceProvenance::FheEvaluated, response.trace_id,
        fixture.public_setup, fixture.circuit);
    CHECK(validated.has_value());

    ++proof.header.version;
    std::vector<SlotVector> no_messages;
    Reader reader(no_messages);
    SingleClaim output_claim;
    output_claim.point.resize(
        gkr::base_detail::layer_vars(fixture.circuit, 0), Fpk::zero());
    Transcript transcript(
        "test/delegation/folded/validated-structure-mutation/v1");
    Verifier verifier(
        fixture.payload, fixture.circuit, fixture.inputs, fixture.client,
        TraceProvenance::FheEvaluated, response.trace_id, output_claim,
        proof, reader, transcript, *validated);
    CHECK(!verifier.begin().has_value());
}

void test_request_encryption_timing_boundary() {
    Fixture fixture;
    folded_client_detail::validate_evaluation_start(
        fixture.payload, fixture.circuit, fixture.client);
    ReplayMockBackend::reset_counts(fixture.contexts.eval);
    auto encrypted_inputs =
        payload::prevalidated_input_encryption::
            encrypt_wide_inputs_from_validated_payload<ReplayMockBackend>(
                fixture.client.context, fixture.payload, fixture.inputs);
    const std::size_t encryption_count =
        ReplayMockBackend::counts(fixture.contexts.eval).encrypt;
    CHECK(encryption_count == fixture.inputs.size());
    FoldedClientRequestStart<ReplayMockBackend> started =
        folded_client_detail::
            bind_validated_request_session<ReplayMockBackend>(
                fixture.payload, fixture.circuit, fixture.client,
                fixture.inputs, std::move(encrypted_inputs), test_nonce(1));
    CHECK(ReplayMockBackend::counts(fixture.contexts.eval).encrypt ==
          encryption_count);
    CHECK(started.request.encrypted_inputs.size() == fixture.inputs.size());
}

void test_resident_and_wire(bool outsourced = false) {
    Fixture fixture(outsourced);
    FoldedClientRequestStart<ReplayMockBackend> started =
        delegation::reference::begin_folded_request_resident_reference<ReplayMockBackend>(
            fixture.payload, fixture.circuit, fixture.client,
            fixture.inputs, test_nonce(1));
    const auto encoded_request =
        encode_folded_evaluation_request<ReplayMockBackend>(
            fixture.packed_client.client_context(), started.request);
    CHECK(encode_folded_evaluation_request<ReplayMockBackend>(
              fixture.packed_client.client_context(), started.request,
              encoded_request.size()) == encoded_request);
    CHECK(throws_invalid_argument([&] {
        (void)encode_folded_evaluation_request<ReplayMockBackend>(
            fixture.packed_client.client_context(), started.request,
            encoded_request.size() - 1U);
    }));
    CHECK(encode_folded_evaluation_request<ReplayMockBackend>(
              fixture.contexts.eval, started.request) == encoded_request);
    const FoldedWireDecodeLimits request_limits{
        .max_message_bytes = encoded_request.size(),
        .max_ciphertexts = fixture.inputs.size(),
        .max_ciphertext_bytes = encoded_request.size(),
        .max_total_ciphertext_bytes = encoded_request.size(),
        .max_proof_bytes = 0,
    };
    const auto decoded_request =
        decode_folded_evaluation_request<ReplayMockBackend>(
            fixture.contexts.eval, encoded_request, request_limits);
    CHECK(encode_folded_evaluation_request<ReplayMockBackend>(
              fixture.contexts.eval, decoded_request) == encoded_request);
    auto wrong_request_domain = encoded_request;
    wrong_request_domain.front() ^= 1U;
    CHECK(throws_invalid_argument([&] {
        (void)decode_folded_evaluation_request<ReplayMockBackend>(
            fixture.contexts.eval, wrong_request_domain, request_limits);
    }));
    auto trailing_request = encoded_request;
    trailing_request.push_back(0);
    FoldedWireDecodeLimits trailing_limits = request_limits;
    trailing_limits.max_message_bytes = trailing_request.size();
    CHECK(throws_invalid_argument([&] {
        (void)decode_folded_evaluation_request<ReplayMockBackend>(
            fixture.contexts.eval, trailing_request, trailing_limits);
    }));

    auto evaluated = delegation::reference::evaluate_folded_request_resident_reference<ReplayMockBackend>(
        fixture.payload, fixture.circuit, fixture.server, decoded_request,
        fixture.evaluation);
    Transcript prover("test/delegation/folded/resident/v1");
    FoldedResponse<ReplayMockBackend> response =
        delegation::reference::prove_folded_request_resident_reference<ReplayMockBackend>(
            fixture.payload, fixture.circuit, fixture.server,
            fixture.packing_setup, std::move(evaluated), prover);
    check_validated_structure_token_rejects_mutation(fixture, response);
    CHECK(response.proof.gkr.gate_mle_opening.has_value() == outsourced);
    if (outsourced) {
        CHECK(response.proof.gkr.gate_mle_opening->wide.has_value());
        const auto &wide = *response.proof.gkr.gate_mle_opening->wide;
        CHECK(!wide.adjoint_groups.empty());
        CHECK(!wide.tables.empty());
        CHECK(!wide.public_opening.initial.values.empty());
    }
    auto encoded = encode_folded_response_with_size<ReplayMockBackend>(
        fixture.contexts.eval, response);
    const std::size_t proof_bytes = encoded.proof_size.total_bytes;
    CHECK(proof_bytes ==
          protocol::encode_canonical<ReplayMockBackend>(response.proof)
              .size());
    const auto encoded_response = std::move(encoded.bytes);
    const auto exact_capacity =
        encode_folded_response_with_size<ReplayMockBackend>(
            fixture.contexts.eval, response, encoded_response.size());
    CHECK(exact_capacity.bytes == encoded_response);
    CHECK(exact_capacity.proof_size == encoded.proof_size);
    CHECK(throws_invalid_argument([&] {
        (void)encode_folded_response_with_size<ReplayMockBackend>(
            fixture.contexts.eval, response, encoded_response.size() - 1U);
    }));
    const FoldedWireDecodeLimits wire_limits{
        .max_message_bytes = encoded_response.size(),
        .max_ciphertexts = 1U << 12U,
        .max_ciphertext_bytes = encoded_response.size(),
        .max_total_ciphertext_bytes = encoded_response.size(),
        .max_proof_bytes = proof_bytes,
    };
    const PackedProofDecodeLimits proof_limits{
        .max_proof_bytes = proof_bytes,
        .max_ciphertexts = 1U << 12U,
        .max_ciphertext_bytes = proof_bytes,
        .max_total_ciphertext_bytes = proof_bytes,
        .max_collection_elements = 1U << 16U,
        .max_total_field_elements = 1U << 20U,
        .max_total_digests = 1U << 20U,
    };
    const FoldedVerifierSetup verifier =
        protocol::verifier_setup(fixture.packing_setup);
    const auto decoded_response = decode_folded_response<ReplayMockBackend>(
        fixture.contexts.eval, encoded_response, wire_limits, proof_limits,
        fixture.payload, fixture.circuit, fixture.public_setup, verifier,
        TraceProvenance::FheEvaluated);
    const auto public_decoded_response =
        decode_folded_response<ReplayMockBackend>(
            fixture.packed_client.verifier_context(), encoded_response,
            wire_limits, proof_limits, fixture.payload, fixture.circuit,
            fixture.public_setup, verifier,
            TraceProvenance::FheEvaluated);
    CHECK(encode_folded_response<ReplayMockBackend>(fixture.contexts.eval,
                                                     decoded_response) ==
          encoded_response);
    CHECK(encode_folded_response<ReplayMockBackend>(
              fixture.contexts.eval, public_decoded_response) ==
          encoded_response);
    FoldedWireDecodeLimits short_proof_limit = wire_limits;
    --short_proof_limit.max_proof_bytes;
    CHECK(throws_invalid_argument([&] {
        (void)decode_opaque_folded_response_envelope<ReplayMockBackend>(
            fixture.contexts.eval, encoded_response, short_proof_limit);
    }));

    auto wrong_trace = encoded_response;
    constexpr std::size_t kTraceBindingOffset =
        kFoldedDelegationWireHeaderBytes + 3U * Digest{}.size();
    wrong_trace.at(kTraceBindingOffset) ^= 1U;
    CHECK(throws_invalid_argument([&] {
        (void)decode_folded_response<ReplayMockBackend>(
            fixture.contexts.eval, wrong_trace, wire_limits, proof_limits,
            fixture.payload, fixture.circuit, fixture.public_setup, verifier,
            TraceProvenance::FheEvaluated);
    }));

    FoldedClientRequestStart<ReplayMockBackend> different_session =
        delegation::reference::begin_folded_request_resident_reference<ReplayMockBackend>(
            fixture.payload, fixture.circuit, fixture.client,
            fixture.inputs, test_nonce(2));
    Transcript wrong_session("test/delegation/folded/resident/v1");
    CHECK(!verify_folded_response<ReplayMockBackend>(
        fixture.payload, fixture.circuit, verifier, fixture.packed_client,
        std::move(different_session.state), public_decoded_response,
        wrong_session));

    FoldedClientRequestStart<ReplayMockBackend> tampered_start =
        delegation::reference::begin_folded_request_resident_reference<ReplayMockBackend>(
            fixture.payload, fixture.circuit, fixture.client,
            fixture.inputs, test_nonce(3));
    auto tampered_evaluation = delegation::reference::evaluate_folded_request_resident_reference<ReplayMockBackend>(
        fixture.payload, fixture.circuit, fixture.server,
        tampered_start.request, fixture.evaluation);
    Transcript tampered_prover("test/delegation/folded/tampered/v1");
    auto tampered_response = delegation::reference::prove_folded_request_resident_reference<ReplayMockBackend>(
        fixture.payload, fixture.circuit, fixture.server,
        fixture.packing_setup, std::move(tampered_evaluation),
        tampered_prover);
    corrupt_first_commitment(tampered_response.proof);
    Transcript tampered_verifier("test/delegation/folded/tampered/v1");
    auto opened = open_folded_response<ReplayMockBackend>(
        fixture.payload, fixture.circuit, fixture.packed_client,
        std::move(tampered_start.state), tampered_response,
        tampered_verifier);
    CHECK(opened.has_value());
    const Transcript before_rejected_verification = tampered_verifier;
    CHECK(!verify_opened_folded_response<ReplayMockBackend>(
        fixture.payload, fixture.circuit, verifier, fixture.packed_client,
        std::move(*opened), tampered_response,
        tampered_verifier));
    CHECK(Transcript(tampered_verifier).challenge_fq2() ==
          Transcript(before_rejected_verification).challenge_fq2());

    check_response(fixture, std::move(started.state), public_decoded_response,
                   "test/delegation/folded/resident/v1", prover);
}

void test_file_path() {
    Fixture fixture;
    FoldedClientRequestStart<ReplayMockBackend> started =
        delegation::reference::begin_folded_request_resident_reference<ReplayMockBackend>(
            fixture.payload, fixture.circuit, fixture.client,
            fixture.inputs, test_nonce(17));
    TemporaryDirectory directory;
    const auto trace_root = directory.make_child("trace");
    auto evaluated = delegation::reference::evaluate_folded_request_file_reference<ReplayMockBackend>(
        fixture.payload, fixture.circuit, fixture.server, started.request,
        fixture.evaluation, trace_root,
        FileTraceStoreOptions{
            .max_total_bytes = std::uint64_t{1} << 28U,
            .min_free_bytes = 1,
        });
    auto options =
        make_proof_options(fixture.circuit, directory, "file-scratch-");
    Transcript prover("test/delegation/folded/file/v1");
    auto proved =
        delegation::reference::prove_folded_request_file_irreversible_reference<ReplayMockBackend>(
            fixture.payload, fixture.circuit, fixture.server,
            fixture.packing_setup, std::move(evaluated), prover,
            std::move(options), {});
    CHECK(proved.gkr_report.output_trace_retirement.has_value());
    check_response(fixture, std::move(started.state), proved.response,
                   "test/delegation/folded/file/v1", prover);
}

void test_checkpoint_replay_path() {
    Fixture fixture;
    FoldedClientRequestStart<ReplayMockBackend> started =
        delegation::reference::begin_folded_request_resident_reference<ReplayMockBackend>(
            fixture.payload, fixture.circuit, fixture.client,
            fixture.inputs, test_nonce(33));
    const FheEvaluationPlan checkpoint_evaluation =
        apply_packed_proof_ingress_schedule(
            fixture.circuit,
            FheEvaluationPlan::at_evaluation_levels(
                fixture.circuit, 13, 1, 0),
            fixture.packing_setup);
    FheEvaluationPlan natural = checkpoint_evaluation;
    natural.proof_ingress_mult_depth_by_layer =
        natural.trace.required_mult_depth_by_layer;
    const EncryptedTrace<ReplayMockBackend> resource_trace =
        evaluate_wide_fhe_trace_into<ReplayMockBackend>(
            fixture.contexts.eval, fixture.payload, fixture.circuit,
            started.request.encrypted_inputs, natural,
            InMemoryTraceSink<ReplayMockBackend>{fixture.contexts.eval});
    const auto problem = checkpoint_replay_problem(
        fixture.circuit, checkpoint_evaluation, fixture.contexts.eval,
        resource_trace);
    const auto budgets = checkpoint_budgets();
    const auto plan = plan_payload_checkpoint_replay(problem, budgets);
    const auto storage =
        checkpoint_storage_limits(fixture.circuit, budgets);
    TemporaryDirectory directory;
    const auto replay_root = directory.make_child("replay");
    auto options = make_proof_options(
        fixture.circuit, directory, "checkpoint-scratch-");
    auto evaluated =
        delegation::reference::evaluate_folded_request_with_resident_packing_reference<ReplayMockBackend>(
            fixture.payload, fixture.circuit, fixture.server,
            fixture.packing_setup, started.request, checkpoint_evaluation,
            problem, budgets, plan,
            PayloadCheckpointReplayExecutionOptions{
                .directory = replay_root,
                .min_free_bytes = 1,
                .max_checkpoint_metadata_bytes = 4096,
                .lifecycle =
                    FileTraceSessionLifecycle::IrreversibleNoRetry,
            },
            std::move(options), storage);
    CHECK(evaluated.state.trace.report().checkpoint_set_published);
    CHECK(!evaluated.state.trace.report().all_payload_artifacts_retired);
    Transcript prover("test/delegation/folded/checkpoint/v1");
    auto proved =
        delegation::reference::prove_folded_request_checkpoint_replay_irreversible_reference<
            ReplayMockBackend>(
            fixture.payload, fixture.circuit, fixture.server, evaluated,
            prover);
    CHECK(proved.payload_replay_report.all_payload_artifacts_retired);
    CHECK(proved.payload_replay_report.live_physical_bytes == 0);
    CHECK(proved.storage_admission ==
          evaluated.state.resources().admission());
    check_response(fixture, std::move(started.state), proved.response,
                   "test/delegation/folded/checkpoint/v1", prover);
}

void test_external_checkpoint_replay_path() {
    namespace external = test::packed_external_support;
    constexpr std::size_t kSlots = 32;
    const PayloadCircuit payload = test_payload(kSlots);
    const LayeredCircuit circuit = compile(payload);
    const std::vector<SlotVector> inputs{values(kSlots, 7),
                                         values(kSlots, 31)};
    auto contexts = ReplayMockBackend::create(MockParameters{
        .slot_count = kSlots,
        .fresh_rns_limbs = 14,
        .bits_per_limb = 300,
    });
    ReplayMockBackend::preprocess_fixed_message_cells(contexts.eval);
    const PublicSetup public_setup = make_direct_setup(payload, circuit);
    const EvaluationSetup<ReplayMockBackend> server =
        make_packed_evaluation_setup<ReplayMockBackend>(
            public_setup, contexts.eval);
    const ClientSetup<ReplayMockBackend> client =
        make_client_setup<ReplayMockBackend>(
            public_setup, contexts.client);
    const ConservativePackedProofIngressSchedule ingress =
        derive_conservative_packed_proof_ingress_schedule(
            PackingGkrVariant::Folded, payload, circuit, public_setup);
    auto parameters = packing::selected_lazy_ternary_parameters();
    parameters.repetitions = 1;
    const FoldedSetup resident_setup =
        setup_folded_conservative<ReplayMockBackend>(
            payload, circuit, public_setup, contexts.eval, ingress,
            parameters,
            spartan::BaseFoldPcsParameters{
                .log_rate = 1,
                .query_count = 1,
            });
    external::TemporaryTree external_tree;
    external::ExternalPacking external_packing = external::externalize(
        resident_setup.transcript_packing, external_tree,
        "folded-preprocessed");
    const FoldedVerifierSetup external_verifier{
        .transcript_packing = external_packing.verifier,
    };
    const PackedExternalProverSetup external_setup =
        make_folded_packed_external_prover_setup(
            payload, circuit, public_setup, ingress,
            std::move(external_packing.prover));
    const FheEvaluationPlan evaluation =
        apply_packed_proof_ingress_schedule(
            circuit,
            FheEvaluationPlan::at_evaluation_levels(circuit, 13, 1, 0),
            resident_setup);
    auto started = delegation::reference::begin_folded_request_resident_reference<ReplayMockBackend>(
        payload, circuit, client, inputs, test_nonce(91));
    FheEvaluationPlan natural = evaluation;
    natural.proof_ingress_mult_depth_by_layer =
        natural.trace.required_mult_depth_by_layer;
    const EncryptedTrace<ReplayMockBackend> resource_trace =
        evaluate_wide_fhe_trace_into<ReplayMockBackend>(
            contexts.eval, payload, circuit,
            started.request.encrypted_inputs, natural,
            InMemoryTraceSink<ReplayMockBackend>{contexts.eval});
    const PayloadCheckpointReplayProblem problem = checkpoint_replay_problem(
        circuit, evaluation, contexts.eval, resource_trace);
    const PayloadCheckpointReplayBudgets budgets = checkpoint_budgets();
    const PayloadCheckpointReplayPlan replay_plan =
        plan_payload_checkpoint_replay(problem, budgets);
    const CheckpointReplayServerStorageLimits storage =
        checkpoint_storage_limits(circuit, budgets);
    TemporaryDirectory directory;

    auto resident_evaluated =
        delegation::reference::evaluate_folded_request_with_resident_packing_reference<ReplayMockBackend>(
            payload, circuit, server, resident_setup, started.request,
            evaluation, problem, budgets, replay_plan,
            PayloadCheckpointReplayExecutionOptions{
                .directory = directory.make_child("external-resident-replay"),
                .min_free_bytes = 1,
                .max_checkpoint_metadata_bytes = 4096,
                .lifecycle =
                    FileTraceSessionLifecycle::IrreversibleNoRetry,
            },
            make_proof_options(
                circuit, directory, "external-resident-gkr-"),
            storage);
    external::OnlineRoots roots(
        external_tree, "folded-online", external_packing.tensor_count);
    auto external_evaluated =
        delegation::reference::evaluate_folded_request_with_external_packing_reference<ReplayMockBackend>(
            payload, circuit, server, external_setup, started.request,
            evaluation, problem, budgets, replay_plan,
            PayloadCheckpointReplayExecutionOptions{
                .directory = directory.make_child("external-online-replay"),
                .min_free_bytes = 1,
                .max_checkpoint_metadata_bytes = 4096,
                .lifecycle =
                    FileTraceSessionLifecycle::IrreversibleNoRetry,
            },
            make_proof_options(
                circuit, directory, "external-online-gkr-"),
            admit_transcript_packing_external(
                PackingGkrVariant::Folded,
                external_setup.transcript_packing(),
                external::online_options(roots)),
            storage);
    CHECK(resident_evaluated.state.trace_id ==
          external_evaluated.state.trace_id);

    Transcript resident_transcript(
        "test/delegation/folded/external-checkpoint/v1");
    const auto resident =
        delegation::reference::prove_folded_request_checkpoint_replay_irreversible_reference<
            ReplayMockBackend>(payload, circuit, server,
                               resident_evaluated, resident_transcript);
    Transcript external_transcript(
        "test/delegation/folded/external-checkpoint/v1");
    const Transcript pristine_transcript = external_transcript;
    const std::uint64_t live_before =
        external_evaluated.state.trace.report().live_physical_bytes;
    CHECK(throws_invalid_argument([&] {
        (void)delegation::reference::prove_folded_request_checkpoint_replay_irreversible_reference<
            ReplayMockBackend>(payload, circuit, server,
                               external_evaluated, external_transcript);
    }));
    const PackedExternalProverSetup equivalent_setup = external_setup;
    CHECK(throws_invalid_argument([&] {
        (void)delegation::reference::prove_folded_request_external_checkpoint_replay_irreversible_reference<
            ReplayMockBackend>(
            payload, circuit, server, equivalent_setup,
            external_evaluated, external_transcript);
    }));
    CHECK(!external_evaluated.state.trace.proof_attempt_started());
    const auto rejected_without_writes = [&] {
        CHECK(throws_invalid_argument([&] {
            (void)delegation::reference::prove_folded_request_external_checkpoint_replay_irreversible_reference<
                ReplayMockBackend>(
                payload, circuit, server, external_setup,
                external_evaluated, external_transcript);
        }));
        CHECK(!external_evaluated.state.trace.proof_attempt_started());
        CHECK(external_evaluated.state.trace.report().live_physical_bytes ==
              live_before);
        CHECK(roots.empty());
        CHECK(Transcript(external_transcript).challenge_fq2() ==
              Transcript(pristine_transcript).challenge_fq2());
    };
    for (Digest *binding : {
             &external_evaluated.state.setup_id,
             &external_evaluated.state.session_id,
             &external_evaluated.state.circuit_id,
             &external_evaluated.state.trace_id,
             &external_evaluated.state.request_commitment,
             &external_evaluated.state.statement_digest,
         }) {
        binding->front() ^= 1U;
        rejected_without_writes();
        binding->front() ^= 1U;
    }

    const auto proved =
        delegation::reference::prove_folded_request_external_checkpoint_replay_irreversible_reference<
            ReplayMockBackend>(
            payload, circuit, server, external_setup, external_evaluated,
            external_transcript);
    CHECK(proved.storage_admission ==
          external_evaluated.state.resources().admission());
    CHECK(proved.payload_replay_report.all_payload_artifacts_retired);
    CHECK(proved.payload_replay_report.live_physical_bytes == 0);
    CHECK(proved.transcript_packing_report.storage
              .preprocessing_validation_bytes > 0);
    CHECK(roots.empty());
    CHECK(encode_folded_response<ReplayMockBackend>(
              contexts.eval, proved.response) ==
          encode_folded_response<ReplayMockBackend>(
              contexts.eval, resident.response));
    CHECK(Transcript(external_transcript).challenge_fq2() ==
          Transcript(resident_transcript).challenge_fq2());

    const std::vector<std::uint8_t> response_bytes =
        encode_folded_response<ReplayMockBackend>(
            contexts.eval, proved.response);
    const std::size_t proof_bytes =
        protocol::encode_canonical<ReplayMockBackend>(
            proved.response.proof)
            .size();
    const FoldedWireDecodeLimits wire_limits{
        .max_message_bytes = response_bytes.size(),
        .max_ciphertexts = 1U << 12U,
        .max_ciphertext_bytes = response_bytes.size(),
        .max_total_ciphertext_bytes = response_bytes.size(),
        .max_proof_bytes = proof_bytes,
    };
    const PackedProofDecodeLimits proof_limits{
        .max_proof_bytes = proof_bytes,
        .max_ciphertexts = 1U << 12U,
        .max_ciphertext_bytes = proof_bytes,
        .max_total_ciphertext_bytes = proof_bytes,
        .max_collection_elements = 1U << 16U,
        .max_total_field_elements = 1U << 20U,
        .max_total_digests = 1U << 20U,
    };
    const FoldedResponse<ReplayMockBackend> decoded =
        decode_folded_response<ReplayMockBackend>(
            contexts.eval, response_bytes, wire_limits, proof_limits,
            payload, circuit, public_setup, external_verifier,
            TraceProvenance::FheEvaluated);
    CHECK(encode_folded_response<ReplayMockBackend>(contexts.eval, decoded) ==
          response_bytes);
    Transcript verifier_transcript(
        "test/delegation/folded/external-checkpoint/v1");
    const auto opened = delegation::reference::verify_folded_response_resident_reference<ReplayMockBackend>(
        payload, circuit, contexts.eval, external_verifier, client,
        std::move(started.state), decoded, verifier_transcript);
    CHECK(opened.has_value());
    CHECK(opened->size() == 1);
    CHECK(opened->front() == expected_output(inputs));
    CHECK(Transcript(verifier_transcript).challenge_fq2() ==
          Transcript(external_transcript).challenge_fq2());

    auto failure_options = make_proof_options(
        circuit, directory, "external-failure-gkr-");
    external::OnlineRoots failure_roots(
        external_tree, "folded-failure", external_packing.tensor_count);
    bool reached_witness_opening = false;
    failure_options.proof.progress =
        [&](const RuntimeProgressEvent &event) {
            if (event.stage == RuntimeProgressStage::
                                   TranscriptPackingSpartanWitnessOpening &&
                event.boundary == RuntimeProgressBoundary::Begin) {
                reached_witness_opening = true;
                std::ofstream blocker(
                    failure_roots.witness_opening_scratch /
                    "injected-delegation-failure");
                blocker << "fail after GKR retired its trace";
            }
        };
    auto failure_evaluated =
        delegation::reference::evaluate_folded_request_with_external_packing_reference<ReplayMockBackend>(
            payload, circuit, server, external_setup, started.request,
            evaluation, problem, budgets, replay_plan,
            PayloadCheckpointReplayExecutionOptions{
                .directory = directory.make_child("external-failure-replay"),
                .min_free_bytes = 1,
                .max_checkpoint_metadata_bytes = 4096,
                .lifecycle =
                    FileTraceSessionLifecycle::IrreversibleNoRetry,
            },
            std::move(failure_options),
            admit_transcript_packing_external(
                PackingGkrVariant::Folded,
                external_setup.transcript_packing(),
                external::online_options(failure_roots)),
            storage);
    Transcript failure_transcript(
        "test/delegation/folded/external-checkpoint/v1");
    const Transcript pristine_failure_transcript = failure_transcript;
    bool failed_after_gkr = false;
    try {
        (void)delegation::reference::prove_folded_request_external_checkpoint_replay_irreversible_reference<
            ReplayMockBackend>(
            payload, circuit, server, external_setup, failure_evaluated,
            failure_transcript);
    } catch (const std::exception &) {
        failed_after_gkr = true;
    }
    CHECK(failed_after_gkr);
    CHECK(reached_witness_opening);
    CHECK(failure_evaluated.state.trace.proof_attempt_started());
    CHECK(failure_evaluated.state.trace.report()
              .all_payload_artifacts_retired);
    CHECK(failure_evaluated.state.trace.report().live_physical_bytes == 0);
    CHECK(failure_roots.empty());
    CHECK(Transcript(failure_transcript).challenge_fq2() ==
          Transcript(pristine_failure_transcript).challenge_fq2());
    CHECK(throws_invalid_argument([&] {
        (void)delegation::reference::prove_folded_request_external_checkpoint_replay_irreversible_reference<
            ReplayMockBackend>(
            payload, circuit, server, external_setup, failure_evaluated,
            failure_transcript);
    }));
}

} // namespace

int main() {
    test::Runner runner("test_folded_delegation");
    runner.run("request timing isolates input encryption",
               test_request_encryption_timing_boundary);
    runner.run("resident request response and strict wire",
               [] { test_resident_and_wire(); });
    runner.run("outsourced Wide request response and strict wire",
               [] { test_resident_and_wire(true); });
    runner.run("destructive file trace", test_file_path);
    runner.run("checkpoint replay", test_checkpoint_replay_path);
    runner.run("external checkpoint replay is one request and one response",
               test_external_checkpoint_replay_path);
    return runner.summary();
}
