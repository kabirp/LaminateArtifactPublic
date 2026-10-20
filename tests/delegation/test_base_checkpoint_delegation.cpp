/// @file test_base_checkpoint_delegation.cpp
/// @brief Role-separated Base execution over compact Wide checkpoints.

#include "test_helpers.hpp"
#include "base_checkpoint_test_helpers.hpp"

#include "laminate/delegation/base/client.hpp"
#include "laminate/delegation/base/reference/client.hpp"
#include "laminate/delegation/base/server.hpp"
#include "laminate/fhe/mock_backend.hpp"
#include "laminate/payload/checkpoint/session_engine.hpp"
#include "laminate/payload/compiler.hpp"
#include "laminate/payload/evaluator.hpp"
#include "laminate/payload/noise/honest_base_proof_noise.hpp"
#include "laminate/payload/noise/honest_noise_schedule.hpp"
#include "laminate/payload/trace/trace_sink.hpp"
#include "laminate/payload/wide_fhe_evaluator.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <set>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace {

using namespace laminate;
using namespace laminate::delegation;
using namespace laminate::fhe;
using namespace laminate::payload;

constexpr std::size_t kSlots = 8;

struct ReplayMockBackend : MockBackend {
    static std::size_t remaining_mult_depth(
        const EvalContext &, const Ciphertext &ciphertext) {
        return ciphertext.rns_limbs - 1U;
    }
};

static_assert(fhe::PersistableFheBackend<ReplayMockBackend>);

class TemporaryDirectory {
  public:
    TemporaryDirectory() {
        const auto stamp = std::chrono::steady_clock::now()
                               .time_since_epoch()
                               .count();
        for (std::size_t attempt = 0; attempt < 100; ++attempt) {
            root_ = std::filesystem::temp_directory_path() /
                    ("laminate-base-checkpoint-delegation-" +
                     std::to_string(stamp) + "-" +
                     std::to_string(attempt));
            std::error_code error;
            if (std::filesystem::create_directory(root_, error)) {
                return;
            }
        }
        throw std::runtime_error("failed to create temporary directory");
    }

    ~TemporaryDirectory() {
        std::error_code ignored;
        std::filesystem::remove_all(root_, ignored);
    }

    std::filesystem::path make_child(const std::string &name) const {
        const std::filesystem::path child = root_ / name;
        if (!std::filesystem::create_directory(child)) {
            throw std::runtime_error("failed to create test directory");
        }
        return child;
    }

  private:
    std::filesystem::path root_;
};

fhe::SlotVector values(std::uint64_t seed) {
    fhe::SlotVector result;
    result.reserve(kSlots);
    for (std::size_t slot = 0; slot < kSlots; ++slot) {
        result.emplace_back(seed + 5U * slot + slot * slot);
    }
    return result;
}

PayloadCircuit payload_circuit() {
    PayloadBuilder builder(PayloadShape::wide(kSlots), 3);
    const std::size_t mask = builder.add_plaintext(values(9));
    const WireId product = builder.mul(0, 1);
    const WireId masked = builder.mul_plain(2, mask);
    const WireId mixed = builder.add(product, masked);
    const WireId square = builder.mul(mixed, mixed);
    const WireId rotated = builder.rotate(0, 3);
    const WireId fanin_three =
        builder.add(builder.add(square, product), masked);
    builder.set_outputs({builder.add(fanin_three, rotated)});
    return builder.finish();
}

BaseClientNonce nonce() {
    std::array<std::uint8_t, 32> bytes{};
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        bytes[index] = static_cast<std::uint8_t>(31U + index);
    }
    return make_base_client_nonce(bytes);
}

FileTraceStoreOptions scratch_limits() {
    return FileTraceStoreOptions{
        .max_total_bytes = std::uint64_t{1} << 28U,
        .min_free_bytes = 1,
    };
}

std::vector<PayloadLayerResourceEstimate> replay_resources(
    const ReplayMockBackend::EvalContext &eval,
    const LayeredCircuit &circuit,
    const FheEvaluationPlan &evaluation,
    const EncryptedTrace<ReplayMockBackend> &compact) {
    const std::vector<LayerStorageLayout> storage =
        canonical_trace_storage_layout(circuit);
    const std::vector<std::uint64_t> work =
        payload_replay_work_units(circuit);
    std::vector<PayloadLayerResourceEstimate> result;
    result.reserve(circuit.layers.size());
    for (std::size_t layer = 0; layer < circuit.layers.size(); ++layer) {
        std::uint64_t encoded_bound = 0;
        for (const auto &value : compact.layers[layer].wires) {
            encoded_bound = std::max<std::uint64_t>(
                encoded_bound,
                fhe::encode_fhe_value_record<
                    ReplayMockBackend>(eval, value)
                    .size());
        }
        const auto encrypted = std::find_if(
            compact.layers[layer].wires.begin(),
            compact.layers[layer].wires.end(),
            [](const auto &value) { return value.is_encrypted(); });
        CHECK(encrypted != compact.layers[layer].wires.end());
        ReplayMockBackend::Ciphertext ingress_probe =
            encrypted->ciphertext();
        normalize_ciphertext_for_proof<
            ReplayMockBackend>(
            eval, ingress_probe,
            evaluation.proof_ingress_mult_depth_by_layer[layer]);
        const std::uint64_t ingress_encoded =
            fhe::encode_fhe_value_record<
                ReplayMockBackend>(
                eval, fhe::FheValue<ReplayMockBackend>::from_ciphertext(
                          ingress_probe))
                .size();
        result.push_back(PayloadLayerResourceEstimate{
            .rns_limb_count = ReplayMockBackend::rns_limb_count(
                eval, encrypted->ciphertext()),
            .checkpoint_bytes = standalone_checkpoint_layer_artifact_bytes(
                storage[layer].stored_wire_count, encoded_bound),
            .serialized_ciphertext_bytes = encoded_bound,
            .resident_ciphertext_bytes = encoded_bound + 4096U,
            .replay_work_units = work[layer],
            .proof_ingress_serialized_ciphertext_bytes = ingress_encoded,
            .proof_ingress_resident_ciphertext_bytes =
                ingress_encoded + 4096U,
        });
    }
    return result;
}

PayloadCheckpointReplayBudgets replay_budgets() {
    return PayloadCheckpointReplayBudgets{
        .max_live_scratch_bytes = std::uint64_t{1} << 30U,
        .max_resident_ciphertext_bytes = std::uint64_t{1} << 30U,
        .max_ciphertexts_per_chunk = 2,
        .max_recomputation_factor = {100, 1},
        .reserved_live_scratch_bytes = std::uint64_t{1} << 20U,
        .reserved_resident_bytes = std::uint64_t{1} << 29U,
    };
}

std::vector<std::uint64_t> honest_payload_chain() {
    return {
        kOuterFieldOrder,
        1'152'921'497'895'862'273ULL,
        53'687'910'401ULL,
        96'638'238'721ULL,
        98'785'755'137ULL,
    };
}

HonestPayloadNoiseCalibration honest_payload_calibration(
    std::size_t maximum_switch_tax_bits = 10) {
    return HonestPayloadNoiseCalibration{
        .fresh_canonical_error_bound = 64,
        .ctct_relinearized_debit_bits = 40,
        .plaintext_multiplication_debit_bits = 3,
        .rotation_debit_bits = 2,
        .maximum_switch_tax_bits = maximum_switch_tax_bits,
        .switch_rounding_error_bound = 649,
        .modeled_switch_events_upper_bound = 10'000,
        .switch_model_failure_budget_bits = 40,
        .proof_suffix_level_reserve = 2,
    };
}

HonestBaseProofNoiseCalibration honest_base_proof_calibration() {
    return HonestBaseProofNoiseCalibration{
        .ctct_relinearized_debit_bits = 40,
        .plaintext_multiplication_debit_bits = 3,
        .rotation_debit_bits = 2,
    };
}

HonestPayloadNoiseSchedule assessed_schedule(
    const LayeredCircuit &circuit,
    std::size_t maximum_switch_tax_bits = 10) {
    return select_minimal_honest_base_proof_ingress(
        circuit, honest_payload_chain(),
        honest_payload_calibration(maximum_switch_tax_bits),
        honest_base_proof_calibration());
}

bool no_server_fhe_work(const OperationCounts &counts) {
    return counts.negate == 0 && counts.add == 0 && counts.sub == 0 &&
           counts.mul_no_relin == 0 && counts.relinearize == 0 &&
           counts.add_plain == 0 && counts.mul_plain_scalar == 0 &&
           counts.mul_plain_vector == 0 && counts.rotate == 0 &&
           counts.mod_switch == 0 && counts.logical_ext_add == 0 &&
           counts.logical_ext_sub == 0 && counts.logical_ext_mul == 0 &&
           counts.logical_ext_mul_plain == 0;
}

protocol::BaseProverOptions proof_options(
    const LayeredCircuit &circuit, const TemporaryDirectory &root) {
    protocol::BaseProverOptions result;
    for (std::size_t layer = 0; layer + 1U < circuit.layers.size(); ++layer) {
        if (layer_kind(circuit.layers[layer]) == LayerKind::Multiplication) {
            result.multiplication_scratch.push_back(
                gkr::base_detail::FileBaseMultiplicationScratch{
                    layer,
                    root.make_child("scratch-" + std::to_string(layer)),
                    scratch_limits()});
        }
    }
    return result;
}

template <typename Body> bool throws_invalid(Body &&body) {
    try {
        std::forward<Body>(body)();
    } catch (const std::invalid_argument &) {
        return true;
    }
    return false;
}

void check_ingress_record_metadata_counts_both_source_copies() {
    PayloadCheckpointReplayProblem problem;
    problem.layers = {
        PayloadReplayLayer{
            .layer = 0,
            .kind = LayerKind::Affine,
            .stored_value_count = 1,
            .virtual_wire_count = 1,
            .rns_limb_count = 2,
            .required_proof_depth = 1,
            .checkpoint_bytes = 10,
            .serialized_ciphertext_bytes = 10,
            .resident_ciphertext_bytes = 10,
            .replay_work_units = 1,
        },
        PayloadReplayLayer{
            .layer = 1,
            .kind = LayerKind::Affine,
            .stored_value_count = 1'000,
            .virtual_wire_count = 1'000,
            .rns_limb_count = 2,
            .required_proof_depth = 0,
            .checkpoint_bytes = 10'000,
            .serialized_ciphertext_bytes = 10,
            .resident_ciphertext_bytes = 10,
            .replay_work_units = 1,
            .proof_ingress_serialized_ciphertext_bytes = 5,
            .proof_ingress_resident_ciphertext_bytes = 5,
        },
        PayloadReplayLayer{
            .layer = 2,
            .kind = LayerKind::Input,
            .stored_value_count = 1,
            .virtual_wire_count = 1,
            .rns_limb_count = 2,
            .required_proof_depth = 1,
            .checkpoint_bytes = 10,
            .serialized_ciphertext_bytes = 10,
            .resident_ciphertext_bytes = 10,
        },
    };
    problem.validate();
    const PayloadCheckpointReplayBudgets budgets{
        .max_live_scratch_bytes = 1'000'000,
        .max_resident_ciphertext_bytes = 1'000'000,
        .max_ciphertexts_per_chunk = 1,
        .max_recomputation_factor = {100, 1},
    };
    const PayloadCheckpointReplayPlan plan =
        plan_payload_checkpoint_replay(problem, budgets);
    CHECK(plan.selected.checkpoint_layers ==
          std::vector<std::size_t>{2});
    CHECK(plan.reverse_gkr_segments.front()
              .proof_ingress_artifact_bytes_upper_bound == 5'000);
    constexpr std::uint64_t kExpectedRecords =
        1U + 2U * 1'000U;
    CHECK(base_server_detail::compact_replay_record_metadata_ram(
              problem, plan) ==
          kExpectedRecords *
              (sizeof(std::uint64_t) + sizeof(Digest)));
}

void check_uniform_schedule_publishes_without_assessment() {
    PayloadBuilder builder(PayloadShape::wide(kSlots), 1);
    builder.set_outputs({builder.add(0, 0)});
    const PayloadCircuit payload = builder.finish();
    const LayeredCircuit circuit = compile(payload);
    const CertifiedHonestPayloadSchedule certificate =
        derive_certified_uniform_honest_base_proof_schedule(
            circuit, honest_payload_chain(), honest_payload_calibration(), 3);
    CHECK(!certificate.proof_assessment_digest().has_value());

    auto contexts = ReplayMockBackend::create(MockParameters{
        .slot_count = kSlots,
        .fresh_rns_limbs = honest_payload_chain().size(),
        .bits_per_limb = 256,
        .initial_noise_margin_bits = 4,
    });
    const PublicSetup setup =
        bind_certified_uniform_honest_base_proof_schedule(
            make_direct_setup(payload, circuit), payload, circuit,
            certificate);
    const auto client = make_client_setup<ReplayMockBackend>(
        setup, contexts.client);
    const std::vector<fhe::SlotVector> inputs{values(17)};
    const BaseClientRequestStart<ReplayMockBackend> request =
        reference::begin_base_request_resident_reference<ReplayMockBackend>(
            payload, circuit, client, inputs, nonce());
    const HonestPayloadNoiseSchedule &schedule = certificate.schedule();
    FheEvaluationPlan natural_level_calibration = schedule.evaluation_plan;
    natural_level_calibration.proof_ingress_mult_depth_by_layer =
        natural_level_calibration.trace.required_mult_depth_by_layer;
    const EncryptedTrace<ReplayMockBackend> calibration =
        evaluate_wide_fhe_trace_into<ReplayMockBackend>(
            contexts.eval, payload, circuit,
            request.request.encrypted_inputs, natural_level_calibration,
            InMemoryTraceSink<ReplayMockBackend>{contexts.eval});
    const std::vector<PayloadLayerResourceEstimate> resources =
        replay_resources(contexts.eval, circuit,
                         schedule.evaluation_plan, calibration);
    const PayloadCheckpointReplayProblem problem =
        make_payload_checkpoint_replay_problem(
            circuit, schedule.evaluation_plan, resources, 512, 0);
    const PayloadCheckpointReplayBudgets limits = replay_budgets();
    const PayloadCheckpointReplayPlan plan =
        plan_payload_checkpoint_replay(problem, limits);
    TemporaryDirectory root;
    std::vector<fhe::FheValue<ReplayMockBackend>> output;
    auto replay =
        PayloadCheckpointReplayTrace<ReplayMockBackend>::
            publish_authenticated(
                contexts.eval, payload, circuit,
                request.request.encrypted_inputs, certificate, problem,
                limits, plan,
                PayloadCheckpointReplayExecutionOptions{
                    .directory = root.make_child("replay"),
                    .min_free_bytes = 1,
                    .max_checkpoint_metadata_bytes = 4096,
                    .lifecycle =
                        FileTraceSessionLifecycle::IrreversibleNoRetry},
                output);

    CHECK(replay.authenticated_honest_payload_noise_schedule_digest() ==
          std::optional<Digest>(certificate.digest()));
    CHECK(!replay
               .authenticated_honest_base_proof_noise_assessment_digest()
               .has_value());
    CHECK(output.size() == calibration.layers.front().wires.size());

    PayloadBuilder other_builder(PayloadShape::wide(kSlots), 1);
    other_builder.set_outputs({other_builder.mul(0, 0)});
    const PayloadCircuit other_payload = other_builder.finish();
    const LayeredCircuit other_circuit = compile(other_payload);
    std::vector<fhe::FheValue<ReplayMockBackend>> other_output;
    CHECK(throws_invalid([&] {
        (void)PayloadCheckpointReplayTrace<ReplayMockBackend>::
            publish_authenticated(
                contexts.eval, other_payload, other_circuit,
                request.request.encrypted_inputs, certificate, problem,
                limits, plan,
                PayloadCheckpointReplayExecutionOptions{
                    .directory = root.make_child("cross-circuit"),
                    .min_free_bytes = 1,
                    .max_checkpoint_metadata_bytes = 4096,
                    .lifecycle =
                        FileTraceSessionLifecycle::IrreversibleNoRetry},
                other_output);
    }));
}

void check_complete_checkpoint_exchange() {
    const PayloadCircuit payload = payload_circuit();
    const LayeredCircuit circuit = compile(payload);
    const std::vector<fhe::SlotVector> inputs{
        values(3), values(43), values(101)};
    const PlainTrace expected = synthesize_trace(payload, circuit, inputs);
    auto contexts = ReplayMockBackend::create(MockParameters{
        .slot_count = kSlots,
        .fresh_rns_limbs = 5,
        .bits_per_limb = 256,
        .initial_noise_margin_bits = 4,
    });
    const HonestPayloadNoiseSchedule schedule =
        assessed_schedule(circuit);
    CHECK(schedule.payload_model_accepts());
    CHECK(schedule.base_proof_noise_assessment.has_value());
    const PublicSetup unbound_public_setup =
        make_direct_setup(payload, circuit);
    const auto proof_parameters = derive_honest_base_proof_noise_parameters(
        circuit, schedule, honest_base_proof_calibration());
    const PublicSetup public_setup =
        bind_honest_base_proof_noise_assessment(
            unbound_public_setup, payload, circuit, schedule,
            proof_parameters);
    const auto server = make_evaluation_setup<ReplayMockBackend>(
        public_setup, contexts.eval);
    const auto client = make_client_setup<ReplayMockBackend>(
        public_setup, contexts.client);
    const FheEvaluationPlan &evaluation = schedule.evaluation_plan;

    BaseClientRequestStart<ReplayMockBackend> started =
        reference::begin_base_request_resident_reference<ReplayMockBackend>(
            payload, circuit, client, inputs, nonce());
    FheEvaluationPlan natural_level_calibration = evaluation;
    natural_level_calibration.proof_ingress_mult_depth_by_layer =
        natural_level_calibration.trace.required_mult_depth_by_layer;
    const EncryptedTrace<ReplayMockBackend> calibration =
        evaluate_wide_fhe_trace_into<ReplayMockBackend>(
            contexts.eval, payload, circuit,
            started.request.encrypted_inputs, natural_level_calibration,
            InMemoryTraceSink<ReplayMockBackend>{
                contexts.eval});
    const PayloadCheckpointReplayProblem problem =
        make_payload_checkpoint_replay_problem(
            circuit, evaluation,
            replay_resources(contexts.eval, circuit, evaluation,
                             calibration),
            512, 0);
    const PayloadCheckpointReplayBudgets budgets = replay_budgets();
    const PayloadCheckpointReplayPlan replay_plan =
        plan_payload_checkpoint_replay(problem, budgets);
    CHECK(replay_plan.selected.chunk_ciphertexts == 2);
    CHECK(minimum_payload_checkpoint_relation_chunk_ciphertexts(circuit) ==
          2);
    const auto &output_affine =
        std::get<AffineLayer>(circuit.layers.front());
    const LayerWireSupport output_source_support =
        canonical_layer_wire_support(circuit, 1);
    // The complete output expression still spans multiple source chunks,
    // while its retained primitive nodes each have bounded fan-in. Internal
    // node references are not addresses in the preceding trace layer.
    std::set<std::size_t> sources, visited;
    std::vector<std::size_t> pending;
    for (const auto &term : output_affine.gates.front().terms)
        if (!term.coefficient.is_zero()) pending.push_back(term.source);
    while (!pending.empty()) {
        const auto source = pending.back();
        pending.pop_back();
        if (source < output_source_support.padded_wire_count) {
            if (output_source_support.is_live(source)) sources.insert(source);
        } else if (visited.insert(source).second) {
            const auto &node = output_affine.intermediate_gates.at(
                source - output_source_support.padded_wire_count);
            for (const auto &term : node.terms)
                if (!term.coefficient.is_zero()) pending.push_back(term.source);
        }
    }
    CHECK(sources.size() > replay_plan.selected.chunk_ciphertexts);
    TemporaryDirectory root;
    const std::filesystem::path replay_directory =
        root.make_child("replay");

    protocol::BaseServerCapacityComponents capacity;
    capacity.operational_reserve = {1, 1};
    capacity.preprocessed_keys = {1, 1};
    capacity.payload_replay_workspace = {0, std::uint64_t{1} << 26U};
    capacity.encrypted_input_request = {0, std::uint64_t{1} << 26U};
    capacity.encrypted_output_response = {0, std::uint64_t{1} << 26U};
    capacity.affine_reduction_workspace = {0, std::uint64_t{1} << 26U};
    capacity.multiplication_builder_workspace = {
        0, std::uint64_t{1} << 26U};
    capacity.multiplication_reduction_workspace = {
        0, std::uint64_t{1} << 26U};
    capacity.accumulated_proof = {0, std::uint64_t{1} << 26U};
    capacity.proof_encoding = {0, std::uint64_t{1} << 26U};
    capacity.transport_framing = {0, std::uint64_t{1} << 26U};
    const protocol::BaseServerCapacityCaps caps{
        .max_live_local_disk_bytes = std::uint64_t{1} << 34U,
        .max_resident_ram_bytes = std::uint64_t{1} << 34U,
    };

    const CertifiedHonestPayloadSchedule fixed_certificate =
        derive_certified_uniform_honest_base_proof_schedule(
            circuit, honest_payload_chain(), honest_payload_calibration(), 3);
    const PublicSetup fixed_setup =
        bind_certified_uniform_honest_base_proof_schedule(
            make_direct_setup(payload, circuit), payload, circuit,
            fixed_certificate);
    const auto fixed_server = make_evaluation_setup<ReplayMockBackend>(
        fixed_setup, contexts.eval);
    const auto fixed_client = make_client_setup<ReplayMockBackend>(
        fixed_setup, contexts.client);
    const BaseClientRequestStart<ReplayMockBackend> fixed_started =
        reference::begin_base_request_resident_reference<ReplayMockBackend>(
            payload, circuit, fixed_client, inputs, nonce());
    base_server_detail::validate_checkpoint_replay_schedule(
        payload, circuit, fixed_server, fixed_started.request,
        fixed_certificate);

    HonestPayloadNoiseSchedule payload_only_schedule = schedule;
    payload_only_schedule.base_proof_noise_assessment.reset();
    const PublicSetup payload_only_setup =
        bind_honest_payload_noise_schedule(
            make_direct_setup(payload, circuit), payload, circuit,
            payload_only_schedule);
    const auto payload_only_server =
        make_evaluation_setup<ReplayMockBackend>(payload_only_setup,
                                                 contexts.eval);
    const auto payload_only_client =
        make_client_setup<ReplayMockBackend>(payload_only_setup,
                                             contexts.client);
    const BaseClientRequestStart<ReplayMockBackend> payload_only_started =
        reference::begin_base_request_resident_reference<ReplayMockBackend>(
            payload, circuit, payload_only_client, inputs, nonce());
    TemporaryDirectory payload_only_root;
    const std::filesystem::path payload_only_replay =
        payload_only_root.make_child("replay");
    ReplayMockBackend::reset_counts(contexts.eval);
    CHECK(throws_invalid([&] {
        (void)laminate::test::evaluate_base_request_with_schedule<
            ReplayMockBackend>(
            payload, circuit, payload_only_server,
            payload_only_started.request, payload_only_schedule, problem,
            budgets, replay_plan,
            PayloadCheckpointReplayExecutionOptions{
                .directory = payload_only_replay,
                .min_free_bytes = 1,
                .max_checkpoint_metadata_bytes = 4096,
                .lifecycle =
                    FileTraceSessionLifecycle::IrreversibleNoRetry},
            proof_options(circuit, payload_only_root), caps, capacity);
    }));
    CHECK(no_server_fhe_work(ReplayMockBackend::counts(contexts.eval)));
    CHECK(std::filesystem::is_empty(payload_only_replay));

    const auto unbound_server = make_evaluation_setup<ReplayMockBackend>(
        unbound_public_setup, contexts.eval);
    TemporaryDirectory unbound_root;
    const std::filesystem::path unbound_replay =
        unbound_root.make_child("replay");
    ReplayMockBackend::reset_counts(contexts.eval);
    CHECK(throws_invalid([&] {
        (void)laminate::test::evaluate_base_request_with_schedule<
            ReplayMockBackend>(
            payload, circuit, unbound_server, started.request, schedule,
            problem, budgets, replay_plan,
            PayloadCheckpointReplayExecutionOptions{
                .directory = unbound_replay,
                .min_free_bytes = 1,
                .max_checkpoint_metadata_bytes = 4096,
                .lifecycle =
                    FileTraceSessionLifecycle::IrreversibleNoRetry},
            proof_options(circuit, unbound_root), caps, capacity);
    }));
    CHECK(no_server_fhe_work(ReplayMockBackend::counts(contexts.eval)));
    CHECK(std::filesystem::is_empty(unbound_replay));

    const HonestPayloadNoiseSchedule mismatched_schedule =
        assessed_schedule(circuit, 11);
    CHECK(mismatched_schedule.payload_model_accepts());
    TemporaryDirectory mismatch_root;
    const std::filesystem::path mismatch_replay =
        mismatch_root.make_child("replay");
    ReplayMockBackend::reset_counts(contexts.eval);
    CHECK(throws_invalid([&] {
        (void)laminate::test::evaluate_base_request_with_schedule<
            ReplayMockBackend>(
            payload, circuit, server, started.request,
            mismatched_schedule, problem, budgets, replay_plan,
            PayloadCheckpointReplayExecutionOptions{
                .directory = mismatch_replay,
                .min_free_bytes = 1,
                .max_checkpoint_metadata_bytes = 4096,
                .lifecycle =
                    FileTraceSessionLifecycle::IrreversibleNoRetry},
            proof_options(circuit, mismatch_root), caps, capacity);
    }));
    CHECK(no_server_fhe_work(ReplayMockBackend::counts(contexts.eval)));
    CHECK(std::filesystem::is_empty(mismatch_replay));

    BaseRequest<ReplayMockBackend> wrong_level_request =
        started.request;
    --wrong_level_request.encrypted_inputs.front().rns_limbs;
    wrong_level_request.trace_id =
        fhe_evaluated_trace_id<ReplayMockBackend>(
            payload, circuit, wrong_level_request.encrypted_inputs);
    TemporaryDirectory wrong_level_root;
    const std::filesystem::path wrong_level_replay =
        wrong_level_root.make_child("replay");
    ReplayMockBackend::reset_counts(contexts.eval);
    CHECK(throws_invalid([&] {
        (void)laminate::test::evaluate_base_request_with_schedule<
            ReplayMockBackend>(
            payload, circuit, server, wrong_level_request, schedule,
            problem, budgets, replay_plan,
            PayloadCheckpointReplayExecutionOptions{
                .directory = wrong_level_replay,
                .min_free_bytes = 1,
                .max_checkpoint_metadata_bytes = 4096,
                .lifecycle =
                    FileTraceSessionLifecycle::IrreversibleNoRetry},
            proof_options(circuit, wrong_level_root), caps, capacity);
    }));
    CHECK(no_server_fhe_work(ReplayMockBackend::counts(contexts.eval)));
    CHECK(std::filesystem::is_empty(wrong_level_replay));

    TemporaryDirectory rejected_root;
    const std::filesystem::path rejected_replay =
        rejected_root.make_child("replay");
    ReplayMockBackend::reset_counts(contexts.eval);
    CHECK(throws_invalid([&] {
        (void)laminate::test::evaluate_base_request_with_schedule<
            ReplayMockBackend>(
            payload, circuit, server, started.request, schedule, problem,
            budgets, replay_plan,
            PayloadCheckpointReplayExecutionOptions{
                .directory = rejected_replay,
                .min_free_bytes = 1,
                .max_checkpoint_metadata_bytes = 4096,
                .lifecycle =
                    FileTraceSessionLifecycle::IrreversibleNoRetry},
            proof_options(circuit, rejected_root), caps,
            protocol::BaseServerCapacityComponents{});
    }));
    CHECK(ReplayMockBackend::counts(contexts.eval).add == 0);
    CHECK(ReplayMockBackend::counts(contexts.eval).mul_no_relin == 0);
    CHECK(std::filesystem::is_empty(rejected_replay));

    TemporaryDirectory stale_root;
    const std::filesystem::path stale_replay =
        stale_root.make_child("replay");
    protocol::BaseServerCapacityComponents stale = capacity;
    stale.compact_replay_trace.local_disk_bytes =
        replay_plan.selected.peak_live_scratch_bytes;
    CHECK(throws_invalid([&] {
        (void)laminate::test::evaluate_base_request_with_schedule<
            ReplayMockBackend>(
            payload, circuit, server, started.request, schedule, problem,
            budgets, replay_plan,
            PayloadCheckpointReplayExecutionOptions{
                .directory = stale_replay,
                .min_free_bytes = 1,
                .max_checkpoint_metadata_bytes = 4096,
                .lifecycle =
                    FileTraceSessionLifecycle::IrreversibleNoRetry},
            proof_options(circuit, stale_root), caps, stale);
    }));
    CHECK(std::filesystem::is_empty(stale_replay));

    TemporaryDirectory stale_floor_root;
    const std::filesystem::path stale_floor_replay =
        stale_floor_root.make_child("replay");
    protocol::BaseServerCapacityComponents stale_floor = capacity;
    stale_floor.payload_replay_phase_floor = {1, 1};
    CHECK(throws_invalid([&] {
        (void)laminate::test::evaluate_base_request_with_schedule<
            ReplayMockBackend>(
            payload, circuit, server, started.request, schedule, problem,
            budgets, replay_plan,
            PayloadCheckpointReplayExecutionOptions{
                .directory = stale_floor_replay,
                .min_free_bytes = 1,
                .max_checkpoint_metadata_bytes = 4096,
                .lifecycle =
                    FileTraceSessionLifecycle::IrreversibleNoRetry},
            proof_options(circuit, stale_floor_root), caps, stale_floor);
    }));
    CHECK(std::filesystem::is_empty(stale_floor_replay));

    PayloadCheckpointReplayBudgets underreserved = budgets;
    underreserved.reserved_live_scratch_bytes = 1;
    underreserved.reserved_resident_bytes = 1;
    const PayloadCheckpointReplayPlan underreserved_plan =
        plan_payload_checkpoint_replay(problem, underreserved);
    TemporaryDirectory underreserved_root;
    const std::filesystem::path underreserved_replay =
        underreserved_root.make_child("replay");
    CHECK(throws_invalid([&] {
        (void)laminate::test::evaluate_base_request_with_schedule<
            ReplayMockBackend>(
            payload, circuit, server, started.request, schedule, problem,
            underreserved, underreserved_plan,
            PayloadCheckpointReplayExecutionOptions{
                .directory = underreserved_replay,
                .min_free_bytes = 1,
                .max_checkpoint_metadata_bytes = 4096,
                .lifecycle =
                    FileTraceSessionLifecycle::IrreversibleNoRetry},
            proof_options(circuit, underreserved_root), caps, capacity);
    }));
    CHECK(std::filesystem::is_empty(underreserved_replay));

    ReplayMockBackend::reset_counts(contexts.eval);
    auto evaluated =
        laminate::test::evaluate_base_request_with_schedule<ReplayMockBackend>(
            payload, circuit, server, started.request, schedule, problem,
            budgets, replay_plan,
            PayloadCheckpointReplayExecutionOptions{
                .directory = replay_directory,
                .min_free_bytes = 1,
                .max_checkpoint_metadata_bytes = 4096,
                .lifecycle =
                    FileTraceSessionLifecycle::IrreversibleNoRetry},
            proof_options(circuit, root), caps, capacity);
    CHECK(ReplayMockBackend::counts(contexts.eval).encrypt == 0);
    CHECK(ReplayMockBackend::counts(contexts.eval).sub == 0);
    CHECK(evaluated.output.values.size() == 1);
    CHECK(ReplayMockBackend::serialize_for_storage(
              contexts.eval,
              evaluated.output.values.front().ciphertext()) ==
          ReplayMockBackend::serialize_for_storage(
              contexts.eval,
              calibration.layers.front().wires.front().ciphertext()));
    const protocol::BaseServerCapacityComponents &bound_capacity =
        evaluated.state.resources().capacity_components();
    CHECK(bound_capacity.payload_replay_phase_floor.local_disk_bytes ==
          replay_plan.selected.peak_live_scratch_bytes);
    CHECK(bound_capacity.payload_replay_phase_floor.resident_ram_bytes ==
          replay_plan.selected.peak_resident_bytes);
    std::uint64_t expected_post_replay_disk =
        replay_plan.selected.checkpoint_bytes;
    bool saw_transient_source = false;
    for (const PayloadReplaySegment &segment :
         replay_plan.reverse_gkr_segments) {
        const std::uint64_t transient =
            segment.checkpoint_layer == segment.required_source_layer
                ? 0
                : problem.layers[segment.required_source_layer]
                      .checkpoint_bytes;
        saw_transient_source = saw_transient_source || transient != 0;
        expected_post_replay_disk = std::max(
            expected_post_replay_disk,
            segment.artifact_peak.live_checkpoint_bytes + transient +
                segment.proof_ingress_artifact_bytes_upper_bound);
    }
    CHECK(saw_transient_source);
    CHECK(bound_capacity.compact_replay_trace.local_disk_bytes ==
          expected_post_replay_disk);
    std::uint64_t checkpoint_records = 0;
    for (const PayloadReplayLayer &layer : problem.layers) {
        if (std::binary_search(replay_plan.selected.checkpoint_layers.begin(),
                               replay_plan.selected.checkpoint_layers.end(),
                               layer.layer)) {
            checkpoint_records += layer.stored_value_count;
        }
    }
    std::uint64_t transient_records = 0;
    for (std::size_t output_layer = 0;
         output_layer + 1U < problem.layers.size(); ++output_layer) {
        const std::size_t input_layer = output_layer + 1U;
        const bool input_checkpoint = std::binary_search(
            replay_plan.selected.checkpoint_layers.begin(),
            replay_plan.selected.checkpoint_layers.end(), input_layer);
        const bool output_checkpoint = std::binary_search(
            replay_plan.selected.checkpoint_layers.begin(),
            replay_plan.selected.checkpoint_layers.end(), output_layer);
        transient_records = std::max<std::uint64_t>(
            transient_records,
            (input_checkpoint
                 ? 0
                 : problem.layers[input_layer].stored_value_count) +
                (output_checkpoint
                     ? 0
                     : problem.layers[output_layer]
                           .stored_value_count));
    }
    for (const PayloadReplaySegment &segment :
         replay_plan.reverse_gkr_segments) {
        const std::uint64_t source_records =
            problem.layers[segment.required_source_layer]
                .stored_value_count;
        transient_records = std::max<std::uint64_t>(
            transient_records,
            (segment.checkpoint_layer == segment.required_source_layer
                 ? 0
                 : source_records) +
                (segment.proof_ingress_artifact_bytes_upper_bound == 0
                     ? 0
                     : source_records));
    }
    const std::uint64_t expected_record_metadata =
        (checkpoint_records + transient_records) *
        (sizeof(std::uint64_t) + sizeof(Digest));
    CHECK(bound_capacity.compact_replay_trace.resident_ram_bytes ==
          expected_record_metadata);
    const auto &multiplication_build =
        evaluated.state.resources().capacity_admission().phase(
            protocol::BaseServerCapacityPhase::
                MultiplicationScratchBuild);
    CHECK(multiplication_build.live_local_disk_bytes ==
          capacity.operational_reserve.local_disk_bytes +
              capacity.preprocessed_keys.local_disk_bytes +
              expected_post_replay_disk +
              bound_capacity.multiplication_build_scratch
                  .local_disk_bytes);
    CHECK(bound_capacity.multiplication_artifact.local_disk_bytes <=
          bound_capacity.multiplication_build_scratch.local_disk_bytes);

    BaseFheOutput<ReplayMockBackend> honest_output = evaluated.output;
    CHECK(!evaluated.output.values.empty());
    CHECK(evaluated.output.values.front().is_encrypted());
    evaluated.output.values.front().ciphertext().slots.front() += Fp::one();
    Transcript rejected_transcript(
        "test/delegation/base/checkpoint/rejected/v1");
    CHECK(throws_invalid([&] {
        (void)prove_base_response_irreversible<
            ReplayMockBackend>(payload, circuit, server, evaluated,
                               rejected_transcript);
    }));
    evaluated.output = std::move(honest_output);
    Transcript untouched_transcript(
        "test/delegation/base/checkpoint/rejected/v1");
    CHECK(rejected_transcript.challenge_fpk() ==
          untouched_transcript.challenge_fpk());
    CHECK(!BaseServerStateAccess<ReplayMockBackend>::trace(evaluated.state)
               .proof_attempt_started());

    ReplayMockBackend::reset_counts(contexts.eval);
    Transcript prover_transcript(
        "test/delegation/base/checkpoint/v1");
    const auto proved =
        prove_base_response_irreversible<
            ReplayMockBackend>(payload, circuit, server, evaluated,
                               prover_transcript);
    CHECK(ReplayMockBackend::counts(contexts.eval).encrypt == 0);
    CHECK(proved.payload_replay_report.all_payload_artifacts_retired);
    CHECK(proved.payload_replay_report.live_physical_bytes == 0);
    CHECK(proved.payload_replay_report.peak_controlled_resident_bytes <=
          replay_plan.selected.peak_resident_bytes);
    CHECK(proved.gkr_report.output_trace_retirement.has_value());

    Transcript verifier_transcript(
        "test/delegation/base/checkpoint/v1");
    const auto outputs =
        reference::verify_base_response_resident_reference<
            ReplayMockBackend>(payload, circuit, client,
                               std::move(started.state), proved.response,
                               verifier_transcript);
    CHECK(outputs.has_value());
    CHECK(outputs->size() == 1);
    CHECK(outputs->front() == expected.layers.front().front());

    const std::vector<LayerWireSupport> support =
        canonical_trace_wire_support(circuit);
    CHECK(std::any_of(support.begin(), support.end(), [](const auto &layer) {
        return layer.live_wire_count < layer.padded_wire_count;
    }));
    for (const auto &scratch :
         evaluated.state.resources()
             .proof_options()
             .multiplication_scratch) {
        CHECK(std::filesystem::is_empty(scratch.directory));
    }
}

} // namespace

int main() {
    laminate::test::Runner runner("Base checkpoint delegation");
    runner.run("proof ingress indexes both large source copies",
               check_ingress_record_metadata_counts_both_source_copies);
    runner.run("fixed uniform schedule publishes without an assessment",
               check_uniform_schedule_publishes_without_assessment);
    runner.run("complete compact Wide exchange verifies",
               check_complete_checkpoint_exchange);
    return runner.summary();
}
