/// @file test_laned_delegation.cpp
/// @brief Role-separated in-process Laned evaluation and proof flow.

#include "test_helpers.hpp"
#include "packed_setup_fixture.hpp"

#include "laminate/delegation/laned/client.hpp"
#include "laminate/delegation/laned/profiling/client.hpp"
#include "laminate/delegation/laned/reference/client.hpp"
#include "laminate/delegation/laned/wire/codec.hpp"
#include "laminate/delegation/laned/reference/server.hpp"
#include "laminate/fhe/mock_backend.hpp"
#include "laminate/gkr/detail/laned/verifier.hpp"
#include "laminate/payload/compiler.hpp"
#include "laminate/protocol/detail/packing/transcript_reader.hpp"
#include "laminate/protocol/metrics/proof_size.hpp"
#include "delegation/packed_external_test_support.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <numeric>
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

/// Match the chain-index interpretation used by the production SEAL backend
/// while retaining Mock's deterministic arithmetic and storage codec.
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

static_assert(!std::is_copy_constructible_v<LanedClientAwaitingResponse>);
static_assert(!std::is_copy_constructible_v<LanedClientOpenedResponse>);
static_assert(!std::is_default_constructible_v<LanedClientNonce>);
static_assert(!std::is_constructible_v<LanedClientNonce, Digest>);
static_assert(
    !std::is_copy_constructible_v<LanedServerReadyToProve<MockBackend>>);
static_assert(std::is_move_constructible_v<LanedClientAwaitingResponse>);
static_assert(std::is_move_constructible_v<LanedClientOpenedResponse>);
static_assert(
    std::is_move_constructible_v<LanedServerReadyToProve<MockBackend>>);
static_assert(!std::is_copy_constructible_v<FileLanedServerReadyToProve>);
static_assert(std::is_move_constructible_v<FileLanedServerReadyToProve>);
static_assert(!std::is_copy_constructible_v<
              CheckpointReplayLanedServerReadyToProve<MockBackend>>);
static_assert(std::is_move_constructible_v<
              CheckpointReplayLanedServerReadyToProve<MockBackend>>);

class TemporaryDirectory {
  public:
    TemporaryDirectory() {
        const auto stamp = std::chrono::steady_clock::now()
                               .time_since_epoch()
                               .count();
        for (std::size_t attempt = 0; attempt < 100; ++attempt) {
            path_ = std::filesystem::temp_directory_path() /
                    ("laminate-file-delegation-" +
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

    const std::filesystem::path &path() const { return path_; }

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

LanedClientNonce test_nonce(std::uint8_t seed) {
    std::array<std::uint8_t, 32> bytes{};
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        bytes[index] = static_cast<std::uint8_t>(seed + index);
    }
    return make_laned_client_nonce(bytes);
}

SlotVector values(std::size_t count, std::uint64_t seed) {
    SlotVector result;
    result.reserve(count);
    for (std::size_t lane = 0; lane < count; ++lane) {
        result.emplace_back(seed + 5 * lane + lane * lane);
    }
    return result;
}

std::vector<std::size_t>
multiplication_layers(const LayeredCircuit &circuit) {
    std::vector<std::size_t> result;
    for (std::size_t layer = 0; layer + 1U < circuit.layers.size(); ++layer) {
        if (layer_kind(circuit.layers[layer]) ==
            LayerKind::Multiplication) {
            result.push_back(layer);
        }
    }
    return result;
}

std::size_t progress_event_count(
    std::span<const RuntimeProgressEvent> events,
    RuntimeProgressStage stage, RuntimeProgressBoundary boundary) {
    return static_cast<std::size_t>(std::count_if(
        events.begin(), events.end(),
        [stage, boundary](const RuntimeProgressEvent &event) {
            return event.stage == stage && event.boundary == boundary;
        }));
}

std::size_t first_progress_event(
    std::span<const RuntimeProgressEvent> events,
    RuntimeProgressStage stage, RuntimeProgressBoundary boundary) {
    const auto found = std::find_if(
        events.begin(), events.end(),
        [stage, boundary](const RuntimeProgressEvent &event) {
            return event.stage == stage && event.boundary == boundary;
        });
    CHECK(found != events.end());
    return static_cast<std::size_t>(found - events.begin());
}

void check_balanced_progress(
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

std::uint64_t regular_file_bytes(const std::filesystem::path &root) {
    std::uint64_t bytes = 0;
    for (const auto &entry :
         std::filesystem::recursive_directory_iterator(root)) {
        if (entry.is_regular_file()) {
            bytes += entry.file_size();
        }
    }
    return bytes;
}

bool transcripts_match(Transcript left, Transcript right) {
    return left.challenge_fpk() == right.challenge_fpk();
}

std::array<std::uint64_t, 16>
operation_counts(const OperationCounts &counts) {
    return {
        counts.encrypt,
        counts.decrypt,
        counts.negate,
        counts.add,
        counts.sub,
        counts.mul_no_relin,
        counts.relinearize,
        counts.add_plain,
        counts.mul_plain_scalar,
        counts.mul_plain_vector,
        counts.rotate,
        counts.mod_switch,
        counts.logical_ext_add,
        counts.logical_ext_sub,
        counts.logical_ext_mul,
        counts.logical_ext_mul_plain,
    };
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
                fhe::encode_fhe_value_record<ReplayMockBackend>(eval,
                                                                 wire)
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
        const bool ingress_aliases_natural =
            ReplayMockBackend::rns_limb_count(eval, proof_ingress) ==
            ReplayMockBackend::rns_limb_count(
                eval, encrypted->ciphertext());
        resources.push_back(PayloadLayerResourceEstimate{
            .rns_limb_count =
                ReplayMockBackend::rns_limb_count(
                    eval, encrypted->ciphertext()),
            .checkpoint_bytes =
                standalone_checkpoint_layer_artifact_bytes(
                    canonical_layer_storage_layout(circuit, layer)
                        .stored_wire_count,
                    encoded_bound),
            .serialized_ciphertext_bytes = encoded_bound,
            .resident_ciphertext_bytes = encoded_bound + 4096U,
            .replay_work_units = work[layer],
            .proof_ingress_serialized_ciphertext_bytes =
                ingress_aliases_natural ? 0 : proof_ingress_encoded,
            .proof_ingress_resident_ciphertext_bytes =
                ingress_aliases_natural ? 0
                                        : proof_ingress_encoded + 4096U,
        });
    }
    return make_payload_checkpoint_replay_problem(
        circuit, evaluation, resources, 512, 0);
}

PayloadCheckpointReplayBudgets checkpoint_replay_budgets() {
    return PayloadCheckpointReplayBudgets{
        .max_live_scratch_bytes = std::uint64_t{1} << 30U,
        .max_resident_ciphertext_bytes = std::uint64_t{1} << 30U,
        .max_ciphertexts_per_chunk = 8,
        .max_recomputation_factor = {100, 1},
        .reserved_live_scratch_bytes = 4096,
        .reserved_resident_bytes = 2048,
    };
}

CheckpointReplayServerStorageLimits checkpoint_replay_server_limits(
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

LanedSetup make_test_packing_setup(
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

void test_request_encryption_timing_boundary() {
    constexpr std::size_t kLanes = 4;
    constexpr std::size_t kSlots = 32;
    PayloadBuilder builder(PayloadShape::laned(kLanes, kSlots), 2);
    builder.set_outputs({builder.mul(0, 1)});
    const PayloadCircuit payload = builder.finish();
    const LayeredCircuit circuit = compile(payload);
    const std::vector<SlotVector> inputs{values(kLanes, 7),
                                         values(kLanes, 37)};
    auto contexts = MockBackend::create(MockParameters{
        .slot_count = kSlots,
        .fresh_rns_limbs = 14,
        .bits_per_limb = 300,
    });
    const PublicSetup public_setup = make_direct_setup(payload, circuit);
    const ClientSetup<MockBackend> client =
        make_client_setup<MockBackend>(public_setup, contexts.client);

    laned_client_detail::validate_evaluation_start(payload, circuit, client);
    MockBackend::reset_counts(contexts.eval);
    auto encrypted_inputs =
        payload::prevalidated_input_encryption::
            encrypt_laned_inputs_from_validated_payload<MockBackend>(
                client.context, payload, inputs);
    const std::size_t encryption_count =
        MockBackend::counts(contexts.eval).encrypt;
    CHECK(encryption_count == inputs.size());
    LanedClientRequestStart<MockBackend> started =
        laned_client_detail::bind_validated_request_session<MockBackend>(
            payload, circuit, client, inputs, std::move(encrypted_inputs),
            test_nonce(1));
    CHECK(MockBackend::counts(contexts.eval).encrypt == encryption_count);
    CHECK(started.request.encrypted_inputs.size() == inputs.size());
}

void test_resident_laned_keeps_structural_padding_public() {
    constexpr std::size_t kLanes = 4;
    constexpr std::size_t kSlots = 32;
    PayloadBuilder builder(PayloadShape::laned(kLanes, kSlots), 2);
    const WireId product = builder.mul(0, 1);
    builder.set_outputs({product});
    const PayloadCircuit payload = builder.finish();
    const LayeredCircuit circuit = compile(payload);
    const std::vector<SlotVector> inputs{values(kLanes, 7),
                                         values(kLanes, 37)};

    auto contexts = MockBackend::create(MockParameters{
        .slot_count = kSlots,
        .fresh_rns_limbs = 14,
        .bits_per_limb = 300,
    });
    const PublicSetup public_setup = make_direct_setup(payload, circuit);
    const EvaluationSetup<MockBackend> server =
        make_packed_evaluation_setup<MockBackend>(public_setup,
                                                  contexts.eval);
    const ClientSetup<MockBackend> client =
        make_client_setup<MockBackend>(public_setup, contexts.client);
    LanedClientRequestStart<MockBackend> client_start =
        delegation::reference::begin_laned_request_resident_reference<MockBackend>(payload, circuit, client, inputs,
                                         test_nonce(1));
    CHECK(client_start.request.encrypted_inputs.size() == inputs.size());

    MockBackend::reset_counts(contexts.eval);
    const LanedServerEvaluationResult<MockBackend> evaluated =
        delegation::reference::evaluate_laned_request_resident_reference<MockBackend>(
            payload, circuit, server, client_start.request,
            FheEvaluationPlan::without_payload_switches(circuit, 9));
    CHECK(evaluated.output.values.size() == 1);
    CHECK(evaluated.output.values.front().is_encrypted());
    const OperationCounts counts = MockBackend::counts(contexts.eval);
    CHECK(counts.encrypt == 0);
    CHECK(counts.decrypt == 0);
    CHECK(counts.add == 0);
    CHECK(counts.sub == 0);
    CHECK(counts.mul_no_relin == 1);
    CHECK(counts.mul_plain_scalar == 0);
    CHECK(counts.mul_plain_vector == 0);
}

void test_resident_laned_full_live_end_to_end() {
    constexpr std::size_t kLanes = 4;
    constexpr std::size_t kSlots = 32;
    constexpr std::size_t kOutputs = kSlots / kLanes;
    PayloadBuilder builder(PayloadShape::laned(kLanes, kSlots),
                           2 * kOutputs);
    std::vector<WireId> outputs;
    std::vector<SlotVector> inputs;
    for (std::size_t output = 0; output < kOutputs; ++output) {
        outputs.push_back(builder.mul(2 * output, 2 * output + 1));
        inputs.push_back(values(kLanes, 7 + 32 * output));
        inputs.push_back(values(kLanes, 19 + 32 * output));
    }
    builder.set_outputs(outputs);
    const PayloadCircuit payload = builder.finish();
    const LayeredCircuit circuit = compile(payload);

    auto contexts = MockBackend::create(MockParameters{
        .slot_count = kSlots,
        .fresh_rns_limbs = 14,
        .bits_per_limb = 300,
    });
    const PublicSetup public_setup = make_direct_setup(payload, circuit);
    const EvaluationSetup<MockBackend> server =
        make_packed_evaluation_setup<MockBackend>(public_setup,
                                                  contexts.eval);
    const ClientSetup<MockBackend> client =
        make_client_setup<MockBackend>(public_setup, contexts.client);
    const PackedClientSetup<MockBackend> packed_client =
        make_packed_client_setup_from_verifier_context<MockBackend>(
            client, MockBackend::make_public_verifier_context(
                        contexts.eval));
    const LanedSetup packing_setup =
        make_test_packing_setup(contexts.eval, circuit);
    const FheEvaluationPlan evaluation =
        apply_packed_proof_ingress_schedule(
            circuit,
            FheEvaluationPlan::without_payload_switches(circuit, 9),
            packing_setup);

    LanedClientRequestStart<MockBackend> started =
        begin_laned_request<MockBackend>(payload, circuit, packed_client,
                                         inputs, test_nonce(17));
    const std::vector<std::uint8_t> encoded_request =
        encode_laned_evaluation_request<MockBackend>(
            packed_client.client_context(), started.request);
    CHECK(encode_laned_evaluation_request<MockBackend>(
              packed_client.client_context(), started.request,
              encoded_request.size()) == encoded_request);
    bool request_capacity_rejected = false;
    try {
        (void)encode_laned_evaluation_request<MockBackend>(
            packed_client.client_context(), started.request,
            encoded_request.size() - 1U);
    } catch (const std::invalid_argument &) {
        request_capacity_rejected = true;
    }
    CHECK(request_capacity_rejected);
    const LanedWireDecodeLimits request_limits{
        .max_message_bytes = encoded_request.size(),
        .max_ciphertexts = inputs.size(),
        .max_ciphertext_bytes = encoded_request.size(),
        .max_total_ciphertext_bytes = encoded_request.size(),
        .max_proof_bytes = 0,
    };
    const LanedEvaluationRequest<MockBackend> decoded_request =
        decode_laned_evaluation_request<MockBackend>(
            contexts.eval, encoded_request, request_limits);
    CHECK(encode_laned_evaluation_request<MockBackend>(
              contexts.eval, decoded_request) == encoded_request);
    LanedServerEvaluationResult<MockBackend> evaluated =
        delegation::reference::evaluate_laned_request_resident_reference<MockBackend>(
            payload, circuit, server, decoded_request, evaluation);
    Transcript prover_transcript("test/delegation/laned/resident/v1");
    const LanedResponse<MockBackend> response =
        delegation::reference::prove_laned_request_resident_reference<MockBackend>(
            payload, circuit, server, packing_setup,
            std::move(evaluated), prover_transcript);
    {
        using Reader = protocol::detail::PackedTranscriptReader;
        using Verifier = gkr::laned_detail::LanedGkrVerifier<
            MockBackend, Reader, gkr::CommittedPackedMessage>;
        auto proof = response.proof.gkr;
        const auto validated = Verifier::validate_structure_once(
            proof, TraceProvenance::FheEvaluated, response.trace_id,
            public_setup, circuit);
        CHECK(validated.has_value());

        ++proof.header.version;
        std::vector<SlotVector> no_messages;
        Reader reader(no_messages);
        SingleClaim output_claim;
        output_claim.point.resize(
            gkr::laned_layer_variables(circuit, 0), Fpk::zero());
        Transcript mutation_transcript(
            "test/delegation/laned/validated-structure-mutation/v1");
        Verifier mutation_verifier(
            payload, circuit, inputs, client,
            TraceProvenance::FheEvaluated, response.trace_id, output_claim,
            proof, reader, mutation_transcript, *validated);
        CHECK(!mutation_verifier.begin().has_value());
    }
    const LanedVerifierSetup verifier_setup =
        protocol::verifier_setup(packing_setup);
    auto encoded = encode_laned_response_with_size<MockBackend>(
        contexts.eval, response);
    const std::size_t encoded_proof_bytes =
        encoded.proof_size.total_bytes;
    CHECK(encoded_proof_bytes ==
          protocol::encode_canonical<MockBackend>(response.proof).size());
    const std::vector<std::uint8_t> encoded_response =
        std::move(encoded.bytes);
    const auto exact_capacity = encode_laned_response_with_size<MockBackend>(
        contexts.eval, response, encoded_response.size());
    CHECK(exact_capacity.bytes == encoded_response);
    CHECK(exact_capacity.proof_size == encoded.proof_size);
    bool response_capacity_rejected = false;
    try {
        (void)encode_laned_response_with_size<MockBackend>(
            contexts.eval, response, encoded_response.size() - 1U);
    } catch (const std::invalid_argument &) {
        response_capacity_rejected = true;
    }
    CHECK(response_capacity_rejected);
    const LanedWireDecodeLimits wire_limits{
        .max_message_bytes = encoded_response.size(),
        .max_ciphertexts = 1U << 16U,
        .max_ciphertext_bytes = encoded_response.size(),
        .max_total_ciphertext_bytes = encoded_response.size(),
        .max_proof_bytes = encoded_proof_bytes,
    };
    const PackedProofDecodeLimits proof_limits{
        .max_proof_bytes = encoded_proof_bytes,
        .max_ciphertexts = 1U << 16U,
        .max_ciphertext_bytes = encoded_proof_bytes,
        .max_total_ciphertext_bytes = encoded_proof_bytes,
        .max_collection_elements = 1U << 16U,
        .max_total_field_elements = 1U << 20U,
        .max_total_digests = 1U << 20U,
    };
    const LanedResponse<MockBackend> decoded_response =
        decode_laned_response<MockBackend>(
            contexts.eval, encoded_response, wire_limits, proof_limits,
            payload, circuit, public_setup, verifier_setup,
            TraceProvenance::FheEvaluated);
    const LanedResponse<MockBackend> public_decoded_response =
        decode_laned_response<MockBackend>(
            packed_client.verifier_context(), encoded_response, wire_limits,
            proof_limits, payload, circuit, public_setup, verifier_setup,
            TraceProvenance::FheEvaluated);
    CHECK(encode_laned_response<MockBackend>(contexts.eval,
                                              decoded_response) ==
          encoded_response);
    CHECK(encode_laned_response<MockBackend>(
              contexts.eval, public_decoded_response) == encoded_response);

    auto wrong_trace = encoded_response;
    constexpr std::size_t kTraceBindingOffset =
        kLanedDelegationWireHeaderBytes + 3U * Digest{}.size();
    wrong_trace.at(kTraceBindingOffset) ^= 1U;
    bool trace_binding_rejected = false;
    try {
        (void)decode_laned_response<MockBackend>(
            contexts.eval, wrong_trace, wire_limits, proof_limits, payload,
            circuit, public_setup, verifier_setup,
            TraceProvenance::FheEvaluated);
    } catch (const std::invalid_argument &) {
        trace_binding_rejected = true;
    }
    CHECK(trace_binding_rejected);

    LanedClientRequestStart<MockBackend> replayed =
        delegation::reference::begin_laned_request_resident_reference<MockBackend>(payload, circuit, client, inputs,
                                         test_nonce(18));
    Transcript replay_transcript("test/delegation/laned/resident/v1");
    CHECK(!verify_laned_response<MockBackend>(
        payload, circuit, verifier_setup, packed_client,
        std::move(replayed.state), public_decoded_response,
        replay_transcript));

    Transcript verifier_transcript("test/delegation/laned/resident/v1");
    auto opened = open_laned_response<MockBackend>(
        payload, circuit, packed_client, std::move(started.state),
        public_decoded_response, verifier_transcript);
    CHECK(opened.has_value());
    LanedVerifierTimings timings;
    const auto decrypted = verify_opened_laned_response_profiled<MockBackend>(
        payload, circuit, verifier_setup, packed_client,
        std::move(*opened), public_decoded_response, verifier_transcript,
        timings);
    CHECK(decrypted.has_value());
    CHECK(decrypted->size() == kOutputs);
    CHECK(transcripts_match(verifier_transcript, prover_transcript));
    for (std::size_t output = 0; output < kOutputs; ++output) {
        SlotVector expected(kLanes);
        for (std::size_t lane = 0; lane < kLanes; ++lane) {
            expected[lane] =
                inputs[2 * output][lane] * inputs[2 * output + 1][lane];
        }
        CHECK((*decrypted)[output] == expected);
    }
}

void test_response_owns_only_output_batch() {
    constexpr std::size_t kLanes = 4;
    constexpr std::size_t kSlots = 32;
    PayloadBuilder builder(PayloadShape::laned(kLanes, kSlots), 1);
    builder.set_outputs({builder.add_plain(0, builder.add_scalar_plaintext(
                                                 Fp(9)))});
    const PayloadCircuit payload = builder.finish();
    const LayeredCircuit circuit = compile(payload);
    const std::vector<SlotVector> inputs{values(kLanes, 17)};
    auto contexts = MockBackend::create(MockParameters{
        .slot_count = kSlots,
        .fresh_rns_limbs = 8,
        .bits_per_limb = 300,
    });
    const PublicSetup public_setup = make_direct_setup(payload, circuit);
    const EvaluationSetup<MockBackend> server =
        make_packed_evaluation_setup<MockBackend>(public_setup,
                                                  contexts.eval);
    const ClientSetup<MockBackend> client =
        make_client_setup<MockBackend>(public_setup, contexts.client);

    LanedClientRequestStart<MockBackend> started =
        delegation::reference::begin_laned_request_resident_reference<MockBackend>(payload, circuit, client, inputs,
                                         test_nonce(33));
    LanedServerEvaluationResult<MockBackend> evaluated =
        delegation::reference::evaluate_laned_request_resident_reference<MockBackend>(
            payload, circuit, server, started.request,
            FheEvaluationPlan::without_payload_switches(circuit, 4));
    CHECK(!evaluated.output.values.empty());
    CHECK(evaluated.output.values.size() ==
          evaluated.state.trace->layers.front().wires.size());
}

void test_file_backed_server_evaluation_handoff() {
    constexpr std::size_t kLanes = 4;
    constexpr std::size_t kSlots = 32;
    PayloadBuilder builder(PayloadShape::laned(kLanes, kSlots), 2);
    const WireId product = builder.mul(0, 1);
    builder.set_outputs({builder.add(product, 0)});
    const PayloadCircuit payload = builder.finish();
    const LayeredCircuit circuit = compile(payload);
    const std::vector<SlotVector> inputs{values(kLanes, 7),
                                         values(kLanes, 31)};
    auto contexts = MockBackend::create(MockParameters{
        .slot_count = kSlots,
        .fresh_rns_limbs = 12,
        .bits_per_limb = 300,
    });
    const PublicSetup public_setup = make_direct_setup(payload, circuit);
    const EvaluationSetup<MockBackend> server =
        make_packed_evaluation_setup<MockBackend>(public_setup,
                                                  contexts.eval);
    const ClientSetup<MockBackend> client =
        make_client_setup<MockBackend>(public_setup, contexts.client);
    const LanedSetup packing_setup =
        make_test_packing_setup(contexts.eval, circuit);
    LanedClientRequestStart<MockBackend> started =
        delegation::reference::begin_laned_request_resident_reference<MockBackend>(payload, circuit, client, inputs,
                                         test_nonce(71));
    const FheEvaluationPlan plan =
        apply_packed_proof_ingress_schedule(
            circuit,
            FheEvaluationPlan::without_payload_switches(circuit, 7),
            packing_setup);

    TemporaryDirectory directory;
    const std::filesystem::path trace_directory =
        directory.make_child("trace");
    FileLanedServerEvaluationResult<MockBackend> file_result =
        delegation::reference::evaluate_laned_request_file_reference<MockBackend>(
            payload, circuit, server, started.request, plan,
            trace_directory,
            FileTraceStoreOptions{
                .max_total_bytes = std::uint64_t{1} << 30U,
                .min_free_bytes = 1,
            });
    CHECK(file_result.state.trace_store.directory == trace_directory);
    CHECK(file_result.state.trace_store.report.physical_bytes > 0);
    CHECK(file_result.state.trace_store.descriptor.layers.size() ==
          circuit.layers.size());
    CHECK(file_result.output.values.size() ==
          file_result.state.trace_store.descriptor.layers.front()
              .record_count);

    {
        const auto reopened = delegation::reference::open_laned_server_trace_reference<MockBackend>(
            payload, circuit, server, file_result.state, {});
        CHECK(reopened.descriptor() ==
              file_result.state.trace_store.descriptor);
        auto output_reader = reopened.active_layer_reader(0);
        for (const auto &returned : file_result.output.values) {
            const auto stored = output_reader.next();
            CHECK(stored.has_value());
            CHECK(fhe::encode_fhe_value_record<MockBackend>(
                          contexts.eval, stored->value) ==
                  fhe::encode_fhe_value_record<MockBackend>(
                          contexts.eval, returned));
        }
        CHECK(!output_reader.next().has_value());
    }

    const std::uint64_t original_trace_bytes =
        file_result.state.trace_store.report.physical_bytes;
    const std::size_t trace_layer_count =
        file_result.state.trace_store.descriptor.layers.size();
    const std::vector<std::size_t> multiplication =
        multiplication_layers(circuit);
    CHECK(multiplication.size() == 1);
    std::vector<std::filesystem::path> scratch_directories;
    LanedServerProofOptions options;
    options.lifecycle = FileTraceSessionLifecycle::IrreversibleNoRetry;
    options.reclaim_completed_multiplication_scratch = true;
    std::vector<RuntimeProgressEvent> file_progress_events;
    options.proof.progress =
        [&file_progress_events](const RuntimeProgressEvent &event) {
            file_progress_events.push_back(event);
        };
    for (const std::size_t layer : multiplication) {
        const std::filesystem::path scratch = directory.make_child(
            "multiplication-" + std::to_string(layer));
        scratch_directories.push_back(scratch);
        options.proof.multiplication_scratch.push_back(
            laned_detail::FileLanedMultiplicationScratch{
                layer,
                scratch,
                FileTraceStoreOptions{
                    .max_total_bytes = std::uint64_t{1} << 30U,
                    .min_free_bytes = 1,
                },
            });
    }

    const auto clone_file_result = [&] {
        return FileLanedServerEvaluationResult<MockBackend>{
            file_result.output,
            FileLanedServerReadyToProve{
                file_result.state.setup_id,
                file_result.state.session_id,
                file_result.state.circuit_id,
                file_result.state.trace_id,
                file_result.state.request_commitment,
                file_result.state.statement_digest,
                file_result.state.trace_store}};
    };
    const auto require_retryable_store = [&] {
        CHECK(std::filesystem::is_regular_file(
            trace_directory / "manifest.bin"));
        CHECK(!std::filesystem::exists(
            trace_directory / "retirement-session.bin"));
        const auto reopened = delegation::reference::open_laned_server_trace_reference<MockBackend>(
            payload, circuit, server, file_result.state, {});
        CHECK(reopened.descriptor() ==
              file_result.state.trace_store.descriptor);
        for (const auto &scratch : scratch_directories) {
            CHECK(std::filesystem::is_empty(scratch));
        }
    };
    const auto expect_preflight_rejection =
        [&](const LanedSetup &candidate_setup,
            FileLanedServerEvaluationResult<MockBackend> candidate,
            LanedServerProofOptions candidate_options,
            const std::string &domain) {
            bool rejected = false;
            try {
                Transcript rejected_transcript(domain);
                (void)delegation::reference::prove_laned_request_file_irreversible_reference<MockBackend>(
                    payload, circuit, server, candidate_setup,
                    std::move(candidate),
                    rejected_transcript, std::move(candidate_options), {});
            } catch (const std::invalid_argument &) {
                rejected = true;
            }
            CHECK(rejected);
            require_retryable_store();
        };

    // Setup and retained-statement errors are rejected before publishing
    // the no-retry marker. The trace remains reopenable after each rejection.
    expect_preflight_rejection(
        packing_setup, clone_file_result(), LanedServerProofOptions{},
        "test/delegation/laned/file/fail-closed");
    LanedSetup wrong_packing_setup = packing_setup;
    ++wrong_packing_setup.transcript_packing.bhip_round_count;
    expect_preflight_rejection(
        wrong_packing_setup, clone_file_result(), options,
        "test/delegation/laned/file/wrong-packing");
    LanedSetup wrong_layout = packing_setup;
    ++wrong_layout.transcript_packing.alignment_layout.placements.front()
          .rotation_steps;
    expect_preflight_rejection(
        wrong_layout, clone_file_result(), options,
        "test/delegation/laned/file/wrong-layout");
    LanedSetup wrong_parameters = packing_setup;
    wrong_parameters.transcript_packing.parameters.repetitions = 0;
    expect_preflight_rejection(
        wrong_parameters, clone_file_result(), options,
        "test/delegation/laned/file/wrong-parameters");
    LanedSetup wrong_spartan = packing_setup;
    wrong_spartan.transcript_packing.spartan.prover_key.pcs_scheme = 0;
    expect_preflight_rejection(
        wrong_spartan, clone_file_result(), options,
        "test/delegation/laned/file/wrong-spartan");
    auto changed_output = clone_file_result();
    changed_output.output.values.front() =
        fhe::FheValue<MockBackend>::public_zero();
    expect_preflight_rejection(
        packing_setup, std::move(changed_output), options,
        "test/delegation/laned/file/changed-output");
    auto wrong_binding = clone_file_result();
    wrong_binding.state.trace_id.front() ^= 1U;
    expect_preflight_rejection(
        packing_setup, std::move(wrong_binding), options,
        "test/delegation/laned/file/wrong-binding");
    LanedServerProofOptions invalid_scratch = options;
    invalid_scratch.proof.multiplication_scratch.front()
        .storage_limits.max_total_bytes = 0;
    expect_preflight_rejection(
        packing_setup, clone_file_result(), std::move(invalid_scratch),
        "test/delegation/laned/file/invalid-scratch");

    MockBackend::reset_counts(contexts.eval);
    Transcript file_transcript("test/delegation/laned/file/v1");
    FileLanedServerProofResult<MockBackend> file_proved =
        delegation::reference::prove_laned_request_file_irreversible_reference<MockBackend>(
            payload, circuit, server, packing_setup,
            std::move(file_result), file_transcript,
            std::move(options), {});
    CHECK(MockBackend::counts(contexts.eval).decrypt == 0);
    check_balanced_progress(file_progress_events);
    CHECK(progress_event_count(
              file_progress_events,
              RuntimeProgressStage::TranscriptPackingRevealEvaluation,
              RuntimeProgressBoundary::Begin) == 1U);
    CHECK(progress_event_count(
              file_progress_events,
              RuntimeProgressStage::TranscriptPackingAssignment,
              RuntimeProgressBoundary::Begin) == 1U);
    CHECK(progress_event_count(
              file_progress_events,
              RuntimeProgressStage::TranscriptPackingSpartanProve,
              RuntimeProgressBoundary::Begin) == 1U);
    CHECK(first_progress_event(
              file_progress_events,
              RuntimeProgressStage::LanedGateMleFinish,
              RuntimeProgressBoundary::End) <
          first_progress_event(
              file_progress_events,
              RuntimeProgressStage::TranscriptPackingRevealEvaluation,
              RuntimeProgressBoundary::Begin));

    const auto &report = file_proved.gkr_report;
    CHECK(report.output_trace_retirement.has_value());
    CHECK(report.output_trace_retirement->layer_index == 0);
    CHECK(report.reductions.size() == trace_layer_count - 1U);
    std::uint64_t trace_bytes_reclaimed =
        report.output_trace_retirement->reclaimed_physical_bytes;
    std::size_t multiplication_index = 0;
    for (std::size_t layer = 0; layer < report.reductions.size(); ++layer) {
        const auto &reduction = report.reductions[layer];
        CHECK(reduction.reduction_layer == layer);
        CHECK(reduction.trace_retirement.has_value());
        CHECK(reduction.trace_retirement->layer_index == layer + 1U);
        trace_bytes_reclaimed +=
            reduction.trace_retirement->reclaimed_physical_bytes;
        if (reduction.kind == LayerKind::Multiplication) {
            CHECK(reduction.multiplication_artifact.has_value());
            CHECK(reduction.scratch_reclaimed_physical_bytes ==
                  reduction.multiplication_artifact->report.physical_bytes);
            CHECK(std::filesystem::is_empty(
                scratch_directories.at(multiplication_index)));
            ++multiplication_index;
        } else {
            CHECK(reduction.scratch_reclaimed_physical_bytes == 0);
        }
    }
    CHECK(multiplication_index == scratch_directories.size());

    const auto journal = inspect_file_trace_retirement_journal(
        trace_directory);
    std::vector<std::size_t> expected_order(trace_layer_count);
    std::iota(expected_order.begin(), expected_order.end(), std::size_t{0});
    CHECK(journal.generation == trace_layer_count);
    CHECK(journal.retirement_order == expected_order);
    CHECK(journal.retired_layers ==
          std::vector<bool>(trace_layer_count, true));
    CHECK(journal.reclaimed_physical_bytes == trace_bytes_reclaimed);
    CHECK(journal.remaining_trace_physical_bytes ==
          original_trace_bytes - trace_bytes_reclaimed);

    const LanedVerifierSetup verifier_setup =
        protocol::verifier_setup(packing_setup);
    Transcript verifier_transcript("test/delegation/laned/file/v1");
    const auto outputs = delegation::reference::verify_laned_response_resident_reference<MockBackend>(
        payload, circuit, contexts.eval, verifier_setup, client,
        std::move(started.state), file_proved.response,
        verifier_transcript);
    CHECK(outputs.has_value());
    CHECK(outputs->size() == 1);
    SlotVector expected(kLanes);
    for (std::size_t lane = 0; lane < kLanes; ++lane) {
        expected[lane] = inputs[0][lane] * inputs[1][lane] + inputs[0][lane];
    }
    CHECK(outputs->front() == expected);
}

void test_checkpoint_replay_server_lifecycle() {
    constexpr std::size_t kLanes = 4;
    constexpr std::size_t kSlots = 32;
    PayloadBuilder builder(PayloadShape::laned(kLanes, kSlots), 2);
    const WireId product = builder.mul(0, 1);
    builder.set_outputs({builder.add(product, 0)});
    const PayloadCircuit payload = builder.finish();
    const LayeredCircuit circuit = compile(payload);
    const std::vector<SlotVector> inputs{values(kLanes, 11),
                                         values(kLanes, 43)};
    auto contexts = ReplayMockBackend::create(MockParameters{
        .slot_count = kSlots,
        .fresh_rns_limbs = 12,
        .bits_per_limb = 300,
    });
    const PublicSetup public_setup = make_direct_setup(payload, circuit);
    const EvaluationSetup<ReplayMockBackend> server =
        make_packed_evaluation_setup<ReplayMockBackend>(public_setup,
                                                        contexts.eval);
    const ClientSetup<ReplayMockBackend> client =
        make_client_setup<ReplayMockBackend>(public_setup, contexts.client);
    LanedSetup packing_setup =
        make_test_packing_setup(contexts.eval, circuit);
    const FheEvaluationPlan evaluation =
        apply_packed_proof_ingress_schedule(
            circuit,
            FheEvaluationPlan::at_evaluation_levels(circuit, 11, 1, 0),
            packing_setup);

    LanedClientRequestStart<ReplayMockBackend> started =
        delegation::reference::begin_laned_request_resident_reference<ReplayMockBackend>(
            payload, circuit, client, inputs, test_nonce(91));
    FheEvaluationPlan natural_resource_evaluation = evaluation;
    natural_resource_evaluation.proof_ingress_mult_depth_by_layer =
        natural_resource_evaluation.trace.required_mult_depth_by_layer;
    const EncryptedTrace<ReplayMockBackend> resource_trace =
        evaluate_laned_fhe_trace<ReplayMockBackend>(
            contexts.eval, payload, circuit,
            started.request.encrypted_inputs, natural_resource_evaluation);
    const PayloadCheckpointReplayProblem problem =
        checkpoint_replay_problem(circuit, evaluation, contexts.eval,
                                  resource_trace);
    const PayloadCheckpointReplayBudgets limits =
        checkpoint_replay_budgets();
    const PayloadCheckpointReplayPlan replay_plan =
        plan_payload_checkpoint_replay(problem, limits);

    TemporaryDirectory directory;
    const std::filesystem::path replay_directory =
        directory.make_child("checkpoint-replay");
    std::vector<std::filesystem::path> scratch_directories;
    LanedServerProofOptions proof_options;
    proof_options.lifecycle =
        FileTraceSessionLifecycle::IrreversibleNoRetry;
    proof_options.reclaim_completed_multiplication_scratch = true;
    std::vector<RuntimeProgressEvent> progress_events;
    proof_options.proof.progress =
        [&progress_events](const RuntimeProgressEvent &event) {
            progress_events.push_back(event);
            throw std::runtime_error("injected progress callback failure");
        };
    for (std::size_t layer : multiplication_layers(circuit)) {
        const std::filesystem::path scratch = directory.make_child(
            "checkpoint-replay-backup-" + std::to_string(layer));
        scratch_directories.push_back(scratch);
        proof_options.proof.multiplication_scratch.push_back(
            laned_detail::FileLanedMultiplicationScratch{
                layer,
                scratch / ".",
                FileTraceStoreOptions{
                    .max_total_bytes = std::uint64_t{1} << 20U,
                    .min_free_bytes = 1,
                },
            });
    }
    const CheckpointReplayServerStorageLimits storage_limits =
        checkpoint_replay_server_limits(circuit, limits);
    const auto counts_before_rejected_preflights =
        operation_counts(*contexts.eval.counters);

    const std::filesystem::path rejected_setup_replay =
        directory.make_child("rejected-setup-replay");
    packing_setup.transcript_packing.variant =
        PackingGkrVariant::Folded;
    bool setup_rejected_before_publication = false;
    try {
        (void)delegation::reference::evaluate_laned_request_with_resident_packing_reference<
            ReplayMockBackend>(
            payload, circuit, server, packing_setup, started.request,
            evaluation, problem, limits, replay_plan,
            PayloadCheckpointReplayExecutionOptions{
                .directory = rejected_setup_replay,
                .min_free_bytes = 1,
                .max_checkpoint_metadata_bytes = 4096,
                .lifecycle =
                    FileTraceSessionLifecycle::IrreversibleNoRetry,
            },
            proof_options, storage_limits);
    } catch (const std::invalid_argument &) {
        setup_rejected_before_publication = true;
    }
    packing_setup.transcript_packing.variant =
        PackingGkrVariant::Laned;
    CHECK(setup_rejected_before_publication);
    CHECK(std::filesystem::is_empty(rejected_setup_replay));

    const std::filesystem::path rejected_cap_replay =
        directory.make_child("rejected-cap-replay");
    CheckpointReplayServerStorageLimits rejected_cap = storage_limits;
    rejected_cap.caps.max_phase_combined_bytes = 1;
    bool cap_rejected_before_publication = false;
    try {
        (void)delegation::reference::evaluate_laned_request_with_resident_packing_reference<
            ReplayMockBackend>(
            payload, circuit, server, packing_setup, started.request,
            evaluation, problem, limits, replay_plan,
            PayloadCheckpointReplayExecutionOptions{
                .directory = rejected_cap_replay,
                .min_free_bytes = 1,
                .max_checkpoint_metadata_bytes = 4096,
                .lifecycle =
                    FileTraceSessionLifecycle::IrreversibleNoRetry,
            },
            proof_options, rejected_cap);
    } catch (const std::invalid_argument &) {
        cap_rejected_before_publication = true;
    }
    CHECK(cap_rejected_before_publication);
    CHECK(std::filesystem::is_empty(rejected_cap_replay));
    for (const auto &scratch : scratch_directories) {
        CHECK(std::filesystem::is_empty(scratch));
    }

    const auto check_path_rejected_before_publication =
        [&](const std::string &root_name,
            const std::filesystem::path &overlapping_scratch) {
            const std::filesystem::path rejected_replay =
                directory.make_child(root_name);
            LanedServerProofOptions rejected_options = proof_options;
            rejected_options.proof.multiplication_scratch.front()
                .directory = overlapping_scratch.empty()
                                 ? rejected_replay
                                 : overlapping_scratch;
            bool rejected = false;
            try {
                (void)delegation::reference::evaluate_laned_request_with_resident_packing_reference<
                    ReplayMockBackend>(
                    payload, circuit, server, packing_setup,
                    started.request, evaluation, problem, limits,
                    replay_plan,
                    PayloadCheckpointReplayExecutionOptions{
                        .directory = rejected_replay,
                        .min_free_bytes = 1,
                        .max_checkpoint_metadata_bytes = 4096,
                        .lifecycle =
                            FileTraceSessionLifecycle::
                                IrreversibleNoRetry,
                    },
                    rejected_options, storage_limits);
            } catch (const std::invalid_argument &) {
                rejected = true;
            }
            CHECK(rejected);
            CHECK(std::filesystem::is_empty(rejected_replay));
        };
    check_path_rejected_before_publication("rejected-equal-path", {});
    check_path_rejected_before_publication("rejected-ancestor-path",
                                           directory.path());

    const std::filesystem::path rejected_descendant_replay =
        directory.make_child("rejected-descendant-path");
    const std::filesystem::path nonexistent_descendant =
        rejected_descendant_replay / "not-created-scratch";
    LanedServerProofOptions descendant_options = proof_options;
    descendant_options.proof.multiplication_scratch.front().directory =
        nonexistent_descendant;
    bool descendant_rejected_before_publication = false;
    try {
        (void)delegation::reference::evaluate_laned_request_with_resident_packing_reference<
            ReplayMockBackend>(
            payload, circuit, server, packing_setup, started.request,
            evaluation, problem, limits, replay_plan,
            PayloadCheckpointReplayExecutionOptions{
                .directory = rejected_descendant_replay,
                .min_free_bytes = 1,
                .max_checkpoint_metadata_bytes = 4096,
                .lifecycle =
                    FileTraceSessionLifecycle::IrreversibleNoRetry,
            },
            descendant_options, storage_limits);
    } catch (const std::invalid_argument &) {
        descendant_rejected_before_publication = true;
    }
    CHECK(descendant_rejected_before_publication);
    CHECK(!std::filesystem::exists(nonexistent_descendant));
    CHECK(std::filesystem::is_empty(rejected_descendant_replay));

    const std::filesystem::path rejected_reclaim_replay =
        directory.make_child("rejected-no-reclamation");
    LanedServerProofOptions no_reclamation = proof_options;
    no_reclamation.reclaim_completed_multiplication_scratch = false;
    bool reclamation_rejected_before_publication = false;
    try {
        (void)delegation::reference::evaluate_laned_request_with_resident_packing_reference<
            ReplayMockBackend>(
            payload, circuit, server, packing_setup, started.request,
            evaluation, problem, limits, replay_plan,
            PayloadCheckpointReplayExecutionOptions{
                .directory = rejected_reclaim_replay,
                .min_free_bytes = 1,
                .max_checkpoint_metadata_bytes = 4096,
                .lifecycle =
                    FileTraceSessionLifecycle::IrreversibleNoRetry,
            },
            no_reclamation, storage_limits);
    } catch (const std::invalid_argument &) {
        reclamation_rejected_before_publication = true;
    }
    CHECK(reclamation_rejected_before_publication);
    CHECK(std::filesystem::is_empty(rejected_reclaim_replay));
    CHECK(operation_counts(*contexts.eval.counters) ==
          counts_before_rejected_preflights);

    CheckpointReplayLanedServerEvaluationResult<ReplayMockBackend> evaluated =
        delegation::reference::evaluate_laned_request_with_resident_packing_reference<ReplayMockBackend>(
            payload, circuit, server, packing_setup, started.request,
            evaluation, problem, limits, replay_plan,
            PayloadCheckpointReplayExecutionOptions{
                .directory = replay_directory,
                .min_free_bytes = 1,
                .max_checkpoint_metadata_bytes = 4096,
                .lifecycle =
                    FileTraceSessionLifecycle::IrreversibleNoRetry,
            },
            proof_options, storage_limits);
    CHECK(evaluated.output.values.size() ==
          layer_dimensions(circuit.layers.front()).logical_size);
    CHECK(evaluated.state.trace.report().checkpoint_set_published);
    CHECK(!evaluated.state.trace.report().all_payload_artifacts_retired);
    CHECK(regular_file_bytes(replay_directory) ==
          evaluated.state.trace.report().live_physical_bytes);
    const auto &retained_scratch =
        evaluated.state.resources().proof_options()
            .proof.multiplication_scratch;
    CHECK(retained_scratch.size() == scratch_directories.size());
    for (std::size_t index = 0; index < retained_scratch.size(); ++index) {
        CHECK(retained_scratch[index].directory.is_absolute());
        CHECK(retained_scratch[index].directory ==
              std::filesystem::weakly_canonical(
                  scratch_directories[index]));
    }
    const CheckpointReplayServerStorageAdmission retained_admission =
        evaluated.state.resources().admission();
    CHECK(retained_admission ==
          admit_checkpoint_replay_server_storage(
              problem, limits, replay_plan,
              evaluated.state.resources().proof_options().proof, true,
              storage_limits));

    const std::uint64_t bytes_before_preflight =
        regular_file_bytes(replay_directory);
    Transcript replay_transcript(
        "test/delegation/laned/checkpoint-replay/v1");
    const Transcript pristine_transcript = replay_transcript;
    const auto check_replay_state_is_pristine = [&] {
        CHECK(regular_file_bytes(replay_directory) ==
              bytes_before_preflight);
        CHECK(evaluated.state.trace.report()
                  .checkpoint_retirement_order.empty());
        CHECK(!evaluated.state.trace.report()
                   .all_payload_artifacts_retired);
        CHECK(!evaluated.state.trace.proof_attempt_started());
        CHECK(transcripts_match(replay_transcript,
                                pristine_transcript));
        for (const auto &scratch : scratch_directories) {
            CHECK(std::filesystem::is_empty(scratch));
        }
    };

    const Digest retained_packing_digest =
        evaluated.state.resources().packing_setup().transcript_packing
            .spartan.prover_key.setup_digest;
    const auto retained_factored_computation =
        packing_setup.transcript_packing.spartan.prover_key
            .factored_computation;
    CHECK(retained_factored_computation != nullptr);
    packing_setup.transcript_packing.spartan.prover_key.setup_digest
        .front() ^= 1U;
    packing_setup.transcript_packing.spartan.prover_key
        .factored_computation.reset();
    packing_setup.transcript_packing.spartan_options.matrix_evaluation =
        spartan::MatrixEvaluationMode::Direct;
    packing_setup.transcript_packing.spartan.prover_key.options =
        packing_setup.transcript_packing.spartan_options;
    packing_setup.transcript_packing.spartan.verifier_key.options =
        packing_setup.transcript_packing.spartan_options;
    const auto &retained_packing =
        evaluated.state.resources().packing_setup().transcript_packing;
    CHECK(retained_packing.spartan.prover_key.setup_digest ==
          retained_packing_digest);
    CHECK(retained_packing.spartan.prover_key.factored_computation ==
          retained_factored_computation);
    CHECK(retained_packing.spartan_options.matrix_evaluation ==
          spartan::MatrixEvaluationMode::CommittedFactored);
    packing_setup.transcript_packing.spartan.prover_key.setup_digest
        .front() ^= 1U;
    packing_setup.transcript_packing.spartan.prover_key
        .factored_computation = retained_factored_computation;
    packing_setup.transcript_packing.spartan_options.matrix_evaluation =
        spartan::MatrixEvaluationMode::CommittedFactored;
    packing_setup.transcript_packing.spartan.prover_key.options =
        packing_setup.transcript_packing.spartan_options;
    packing_setup.transcript_packing.spartan.verifier_key.options =
        packing_setup.transcript_packing.spartan_options;
    check_replay_state_is_pristine();

    evaluated.state.trace_id.front() ^= 1U;
    bool binding_rejected = false;
    try {
        (void)delegation::reference::prove_laned_request_checkpoint_replay_irreversible_reference<
            ReplayMockBackend>(payload, circuit, server, evaluated,
                               replay_transcript);
    } catch (const std::invalid_argument &) {
        binding_rejected = true;
    }
    evaluated.state.trace_id.front() ^= 1U;
    CHECK(binding_rejected);
    check_replay_state_is_pristine();

    const std::filesystem::path dirty_entry =
        scratch_directories.front() / "unexpected-entry";
    CHECK(std::filesystem::create_directory(dirty_entry));
    bool dirty_scratch_rejected = false;
    try {
        (void)delegation::reference::prove_laned_request_checkpoint_replay_irreversible_reference<
            ReplayMockBackend>(payload, circuit, server, evaluated,
                               replay_transcript);
    } catch (const std::invalid_argument &) {
        dirty_scratch_rejected = true;
    }
    CHECK(dirty_scratch_rejected);
    CHECK(!evaluated.state.trace.proof_attempt_started());
    CHECK(transcripts_match(replay_transcript, pristine_transcript));
    CHECK(std::filesystem::remove(dirty_entry));
    check_replay_state_is_pristine();

    const std::filesystem::path terminal_replay_directory =
        directory.make_child("terminal-checkpoint-replay");
    LanedServerProofOptions forced_failure_options;
    forced_failure_options.lifecycle =
        FileTraceSessionLifecycle::IrreversibleNoRetry;
    forced_failure_options.reclaim_completed_multiplication_scratch = true;
    const CanonicalTraceLayout terminal_trace_layout =
        canonical_trace_layout(circuit);
    const EncryptedTraceDescriptor terminal_trace_template =
        descriptor_of(resource_trace);
    for (std::size_t layer : multiplication_layers(circuit)) {
        const std::filesystem::path scratch = directory.make_child(
            "terminal-multiplication-" + std::to_string(layer));
        const auto artifact_plan =
            gkr::detail::make_dense_multiplication_source_plan(
                circuit, terminal_trace_template, payload::digest(circuit),
                *resource_trace.backend_context_id, layer,
                terminal_trace_layout.wire_support.at(layer + 1U),
                terminal_trace_layout.storage.at(layer + 1U),
                setup_digest(public_setup),
                packing_setup.proof_ingress_rns_limbs_by_layer.at(
                    layer + 1U));
        forced_failure_options.proof.multiplication_scratch.push_back(
            laned_detail::FileLanedMultiplicationScratch{
                layer,
                scratch,
                FileTraceStoreOptions{
                    // Admit the artifact framing, then fail on its first
                    // ciphertext record. This deliberately crosses the
                    // no-retry boundary and tests terminal-session behavior;
                    // a one-byte quota would be rejected during admission.
                    .max_total_bytes =
                        artifact_plan.minimum_artifact_framing_bytes,
                    .min_free_bytes = 1,
                },
            });
    }
    CheckpointReplayLanedServerEvaluationResult<ReplayMockBackend>
        terminal_evaluated =
            delegation::reference::evaluate_laned_request_with_resident_packing_reference<ReplayMockBackend>(
                payload, circuit, server, packing_setup, started.request,
                evaluation, problem, limits, replay_plan,
                PayloadCheckpointReplayExecutionOptions{
                    .directory = terminal_replay_directory,
                    .min_free_bytes = 1,
                    .max_checkpoint_metadata_bytes = 4096,
                    .lifecycle =
                        FileTraceSessionLifecycle::IrreversibleNoRetry,
                },
                forced_failure_options, storage_limits);
    Transcript terminal_transcript(
        "test/delegation/laned/checkpoint-replay/v1");
    const Transcript terminal_pristine_transcript = terminal_transcript;
    bool failed_after_start = false;
    try {
        (void)delegation::reference::prove_laned_request_checkpoint_replay_irreversible_reference<
            ReplayMockBackend>(
            payload, circuit, server, terminal_evaluated,
            terminal_transcript);
    } catch (const std::exception &) {
        failed_after_start = true;
    }
    CHECK(failed_after_start);
    CHECK(terminal_evaluated.state.trace.proof_attempt_started());
    CHECK(!terminal_evaluated.state.trace.report()
               .all_payload_artifacts_retired);
    CHECK(transcripts_match(terminal_transcript,
                            terminal_pristine_transcript));

    const auto retirement_order_after_failure =
        terminal_evaluated.state.trace.report()
            .checkpoint_retirement_order;
    const std::uint64_t bytes_after_failure =
        regular_file_bytes(terminal_replay_directory);
    bool retry_rejected = false;
    try {
        (void)delegation::reference::prove_laned_request_checkpoint_replay_irreversible_reference<
            ReplayMockBackend>(payload, circuit, server,
                               terminal_evaluated,
                               terminal_transcript);
    } catch (const std::invalid_argument &) {
        retry_rejected = true;
    }
    CHECK(retry_rejected);
    CHECK(terminal_evaluated.state.trace.report()
              .checkpoint_retirement_order ==
          retirement_order_after_failure);
    CHECK(regular_file_bytes(terminal_replay_directory) ==
          bytes_after_failure);
    CHECK(transcripts_match(terminal_transcript,
                            terminal_pristine_transcript));

    CheckpointReplayLanedServerProofResult<ReplayMockBackend> replay_proved =
        delegation::reference::prove_laned_request_checkpoint_replay_irreversible_reference<
            ReplayMockBackend>(
            payload, circuit, server, evaluated, replay_transcript);
    CHECK(replay_proved.storage_admission == retained_admission);
    check_balanced_progress(progress_events);
    CHECK(progress_event_count(
              progress_events, RuntimeProgressStage::LanedReduction,
              RuntimeProgressBoundary::Begin) ==
          circuit.layers.size() - 1U);
    CHECK(progress_event_count(
              progress_events, RuntimeProgressStage::LanedGateMleFinish,
              RuntimeProgressBoundary::Begin) == 1U);
    for (const RuntimeProgressStage stage : {
             RuntimeProgressStage::TranscriptPackingRevealEvaluation,
             RuntimeProgressStage::TranscriptPackingAssignment,
             RuntimeProgressStage::TranscriptPackingSpartanProve}) {
        CHECK(progress_event_count(
                  progress_events, stage,
                  RuntimeProgressBoundary::Begin) == 1U);
        CHECK(progress_event_count(
                  progress_events, stage,
                  RuntimeProgressBoundary::End) == 1U);
    }
    CHECK(first_progress_event(
              progress_events, RuntimeProgressStage::LanedGateMleFinish,
              RuntimeProgressBoundary::End) <
          first_progress_event(
              progress_events,
              RuntimeProgressStage::TranscriptPackingRevealEvaluation,
              RuntimeProgressBoundary::Begin));

    const auto &replay_report = replay_proved.payload_replay_report;
    CHECK(replay_report.all_payload_artifacts_retired);
    CHECK(replay_report.live_physical_bytes == 0);
    CHECK(replay_report.checkpoint_metadata_bytes_retired ==
          replay_plan.selected.checkpoint_metadata_bytes);
    CHECK(replay_report.checkpoint_retirement_order ==
          replay_plan.selected.checkpoint_layers);
    CHECK(replay_report.total_reclaimed_physical_bytes ==
          replay_report.forward.physical_bytes_written +
              replay_report.reverse_replay.physical_bytes_written);
    CHECK(regular_file_bytes(replay_directory) == 0);
    for (const auto &scratch : scratch_directories) {
        CHECK(std::filesystem::is_empty(scratch));
    }
    CHECK(replay_proved.gkr_report.output_trace_retirement.has_value());
    CHECK(replay_proved.gkr_report.reductions.size() ==
          circuit.layers.size() - 1U);
    for (std::size_t layer = 0;
         layer < replay_proved.gkr_report.reductions.size(); ++layer) {
        const auto &reduction =
            replay_proved.gkr_report.reductions[layer];
        CHECK(reduction.reduction_layer == layer);
        CHECK(reduction.trace_retirement.has_value());
        CHECK(reduction.trace_retirement->layer_index == layer + 1U);
    }

    const LanedVerifierSetup verifier_setup =
        protocol::verifier_setup(packing_setup);
    Transcript verifier_transcript(
        "test/delegation/laned/checkpoint-replay/v1");
    const auto outputs = delegation::reference::verify_laned_response_resident_reference<ReplayMockBackend>(
        payload, circuit, contexts.eval, verifier_setup, client,
        std::move(started.state), replay_proved.response,
        verifier_transcript);
    CHECK(outputs.has_value());
    CHECK(outputs->size() == 1);
    SlotVector expected(kLanes);
    for (std::size_t lane = 0; lane < kLanes; ++lane) {
        expected[lane] = inputs[0][lane] * inputs[1][lane] + inputs[0][lane];
    }
    CHECK(outputs->front() == expected);
}

void test_external_checkpoint_replay_server() {
    namespace external = test::packed_external_support;
    constexpr std::size_t kLanes = 4;
    constexpr std::size_t kSlots = 32;
    PayloadBuilder builder(PayloadShape::laned(kLanes, kSlots), 2);
    const WireId product = builder.mul(0, 1);
    builder.set_outputs({builder.add(product, 0)});
    const PayloadCircuit payload = builder.finish();
    const LayeredCircuit circuit = compile(payload);
    const std::vector<SlotVector> inputs{values(kLanes, 11),
                                         values(kLanes, 43)};
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
            PackingGkrVariant::Laned, payload, circuit, public_setup);
    auto parameters = packing::selected_lazy_ternary_parameters();
    parameters.repetitions = 1;
    const LanedSetup resident_setup =
        setup_laned_conservative<ReplayMockBackend>(
            payload, circuit, public_setup, contexts.eval, ingress,
            parameters,
            spartan::BaseFoldPcsParameters{
                .log_rate = 1,
                .query_count = 1,
            });
    external::TemporaryTree external_tree;
    external::ExternalPacking external_packing = external::externalize(
        resident_setup.transcript_packing, external_tree,
        "laned-preprocessed");
    const LanedVerifierSetup external_verifier{
        .transcript_packing = external_packing.verifier,
    };
    const PackedExternalProverSetup external_setup =
        make_laned_packed_external_prover_setup(
            payload, circuit, public_setup, ingress,
            std::move(external_packing.prover));
    const FheEvaluationPlan evaluation =
        apply_packed_proof_ingress_schedule(
            circuit,
            FheEvaluationPlan::at_evaluation_levels(circuit, 13, 1, 0),
            resident_setup);
    auto started = delegation::reference::begin_laned_request_resident_reference<ReplayMockBackend>(
        payload, circuit, client, inputs, test_nonce(137));
    FheEvaluationPlan natural = evaluation;
    natural.proof_ingress_mult_depth_by_layer =
        natural.trace.required_mult_depth_by_layer;
    const EncryptedTrace<ReplayMockBackend> resource_trace =
        evaluate_laned_fhe_trace<ReplayMockBackend>(
            contexts.eval, payload, circuit,
            started.request.encrypted_inputs, natural);
    const PayloadCheckpointReplayProblem problem =
        checkpoint_replay_problem(
            circuit, evaluation, contexts.eval, resource_trace);
    const PayloadCheckpointReplayBudgets budgets =
        checkpoint_replay_budgets();
    const PayloadCheckpointReplayPlan replay_plan =
        plan_payload_checkpoint_replay(problem, budgets);
    const CheckpointReplayServerStorageLimits storage =
        checkpoint_replay_server_limits(circuit, budgets);
    TemporaryDirectory directory;
    const auto proof_options = [&](std::string_view prefix) {
        LanedServerProofOptions result;
        result.lifecycle = FileTraceSessionLifecycle::IrreversibleNoRetry;
        result.reclaim_completed_multiplication_scratch = true;
        for (const std::size_t layer : multiplication_layers(circuit)) {
            result.proof.multiplication_scratch.push_back(
                laned_detail::FileLanedMultiplicationScratch{
                    .reduction_layer = layer,
                    .directory = directory.make_child(
                        std::string(prefix) + std::to_string(layer)),
                    .storage_limits = {
                        .max_total_bytes = 1ULL << 26U,
                        .min_free_bytes = 1,
                    },
                });
        }
        return result;
    };

    auto resident_evaluated =
        delegation::reference::evaluate_laned_request_with_resident_packing_reference<ReplayMockBackend>(
            payload, circuit, server, resident_setup, started.request,
            evaluation, problem, budgets, replay_plan,
            PayloadCheckpointReplayExecutionOptions{
                .directory = directory.make_child("external-resident-replay"),
                .min_free_bytes = 1,
                .max_checkpoint_metadata_bytes = 4096,
                .lifecycle =
                    FileTraceSessionLifecycle::IrreversibleNoRetry,
            },
            proof_options("external-resident-gkr-"), storage);
    external::OnlineRoots roots(
        external_tree, "laned-online", external_packing.tensor_count);
    auto external_evaluated =
        delegation::reference::evaluate_laned_request_with_external_packing_reference<ReplayMockBackend>(
            payload, circuit, server, external_setup, started.request,
            evaluation, problem, budgets, replay_plan,
            PayloadCheckpointReplayExecutionOptions{
                .directory = directory.make_child("external-online-replay"),
                .min_free_bytes = 1,
                .max_checkpoint_metadata_bytes = 4096,
                .lifecycle =
                    FileTraceSessionLifecycle::IrreversibleNoRetry,
            },
            proof_options("external-online-gkr-"),
            admit_transcript_packing_external(
                PackingGkrVariant::Laned,
                external_setup.transcript_packing(),
                external::online_options(roots)),
            storage);
    CHECK(resident_evaluated.state.trace_id ==
          external_evaluated.state.trace_id);

    Transcript resident_transcript(
        "test/delegation/laned/external-checkpoint/v1");
    const auto resident =
        delegation::reference::prove_laned_request_checkpoint_replay_irreversible_reference<
            ReplayMockBackend>(payload, circuit, server,
                               resident_evaluated, resident_transcript);
    Transcript external_transcript(
        "test/delegation/laned/external-checkpoint/v1");
    const Transcript pristine_transcript = external_transcript;
    const std::uint64_t live_before =
        external_evaluated.state.trace.report().live_physical_bytes;
    bool resident_rejected_external_resources = false;
    try {
        (void)delegation::reference::prove_laned_request_checkpoint_replay_irreversible_reference<
            ReplayMockBackend>(payload, circuit, server,
                               external_evaluated, external_transcript);
    } catch (const std::invalid_argument &) {
        resident_rejected_external_resources = true;
    }
    CHECK(resident_rejected_external_resources);
    const PackedExternalProverSetup equivalent_setup = external_setup;
    bool equivalent_setup_rejected = false;
    try {
        (void)delegation::reference::prove_laned_request_external_checkpoint_replay_irreversible_reference<
            ReplayMockBackend>(
            payload, circuit, server, equivalent_setup,
            external_evaluated, external_transcript);
    } catch (const std::invalid_argument &) {
        equivalent_setup_rejected = true;
    }
    CHECK(equivalent_setup_rejected);
    CHECK(!external_evaluated.state.trace.proof_attempt_started());
    const auto rejected_without_writes = [&] {
        bool binding_rejected = false;
        try {
            (void)delegation::reference::prove_laned_request_external_checkpoint_replay_irreversible_reference<
                ReplayMockBackend>(
                payload, circuit, server, external_setup,
                external_evaluated, external_transcript);
        } catch (const std::invalid_argument &) {
            binding_rejected = true;
        }
        CHECK(binding_rejected);
        CHECK(!external_evaluated.state.trace.proof_attempt_started());
        CHECK(external_evaluated.state.trace.report().live_physical_bytes ==
              live_before);
        CHECK(roots.empty());
        CHECK(transcripts_match(external_transcript, pristine_transcript));
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
        delegation::reference::prove_laned_request_external_checkpoint_replay_irreversible_reference<
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
    CHECK(encode_laned_response<ReplayMockBackend>(
              contexts.eval, proved.response) ==
          encode_laned_response<ReplayMockBackend>(
              contexts.eval, resident.response));
    CHECK(transcripts_match(external_transcript, resident_transcript));

    const std::vector<std::uint8_t> response_bytes =
        encode_laned_response<ReplayMockBackend>(
            contexts.eval, proved.response);
    const std::size_t proof_bytes =
        protocol::encode_canonical<ReplayMockBackend>(
            proved.response.proof)
            .size();
    const LanedWireDecodeLimits wire_limits{
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
    const LanedResponse<ReplayMockBackend> decoded =
        decode_laned_response<ReplayMockBackend>(
            contexts.eval, response_bytes, wire_limits, proof_limits,
            payload, circuit, public_setup, external_verifier,
            TraceProvenance::FheEvaluated);
    CHECK(encode_laned_response<ReplayMockBackend>(contexts.eval, decoded) ==
          response_bytes);
    Transcript verifier_transcript(
        "test/delegation/laned/external-checkpoint/v1");
    const auto outputs = delegation::reference::verify_laned_response_resident_reference<ReplayMockBackend>(
        payload, circuit, contexts.eval, external_verifier, client,
        std::move(started.state), decoded, verifier_transcript);
    CHECK(outputs.has_value());
    CHECK(outputs->size() == 1);
    SlotVector expected(kLanes);
    for (std::size_t lane = 0; lane < kLanes; ++lane) {
        expected[lane] =
            inputs[0][lane] * inputs[1][lane] + inputs[0][lane];
    }
    CHECK(outputs->front() == expected);
    CHECK(transcripts_match(verifier_transcript, external_transcript));

    external::OnlineRoots failure_roots(
        external_tree, "laned-failure", external_packing.tensor_count);
    auto failure_proof_options = proof_options("external-failure-gkr-");
    bool reached_witness_opening = false;
    failure_proof_options.proof.progress =
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
        delegation::reference::evaluate_laned_request_with_external_packing_reference<ReplayMockBackend>(
            payload, circuit, server, external_setup, started.request,
            evaluation, problem, budgets, replay_plan,
            PayloadCheckpointReplayExecutionOptions{
                .directory = directory.make_child("external-failure-replay"),
                .min_free_bytes = 1,
                .max_checkpoint_metadata_bytes = 4096,
                .lifecycle =
                    FileTraceSessionLifecycle::IrreversibleNoRetry,
            },
            std::move(failure_proof_options),
            admit_transcript_packing_external(
                PackingGkrVariant::Laned,
                external_setup.transcript_packing(),
                external::online_options(failure_roots)),
            storage);
    Transcript failure_transcript(
        "test/delegation/laned/external-checkpoint/v1");
    const Transcript pristine_failure_transcript = failure_transcript;
    bool failed_after_gkr = false;
    try {
        (void)delegation::reference::prove_laned_request_external_checkpoint_replay_irreversible_reference<
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
    CHECK(transcripts_match(failure_transcript,
                            pristine_failure_transcript));
    bool retry_rejected = false;
    try {
        (void)delegation::reference::prove_laned_request_external_checkpoint_replay_irreversible_reference<
            ReplayMockBackend>(
            payload, circuit, server, external_setup, failure_evaluated,
            failure_transcript);
    } catch (const std::invalid_argument &) {
        retry_rejected = true;
    }
    CHECK(retry_rejected);
}

} // namespace

int main() {
    test::Runner runner("test_laned_delegation");
    runner.run("request timing isolates input encryption",
               test_request_encryption_timing_boundary);
    runner.run("resident evaluation keeps structural padding public",
               test_resident_laned_keeps_structural_padding_public);
    runner.run("full-live resident delegation proves and verifies",
               test_resident_laned_full_live_end_to_end);
    runner.run("output response owns only its bounded batch",
               test_response_owns_only_output_batch);
    runner.run("server evaluation hands off a durable private trace",
               test_file_backed_server_evaluation_handoff);
    runner.run("server checkpoint replay preserves proof and retires artifacts",
               test_checkpoint_replay_server_lifecycle);
    runner.run("external checkpoint replay is one request and one response",
               test_external_checkpoint_replay_server);
    return runner.summary();
}
