/// @file test_base_prover_file_backed.cpp
/// @brief Full-proof parity and no-retry tests for file-backed LaminateBase.

#include "test_helpers.hpp"

#include "laminate/fhe/mock_backend.hpp"
#include "laminate/gkr/detail/base/reference/prover.hpp"
#include "laminate/gkr/detail/base/testing/file_trace_prover.hpp"
#include "laminate/gkr/detail/base/verifier.hpp"
#include "laminate/payload/checkpoint/session_engine.hpp"
#include "laminate/payload/compiler.hpp"
#include "laminate/payload/evaluator.hpp"
#include "laminate/payload/noise/honest_noise_schedule.hpp"
#include "laminate/payload/input_encryption.hpp"
#include "laminate/payload/trace/trace_sink.hpp"
#include "laminate/payload/wide_fhe_evaluator.hpp"
#include "laminate/protocol/base.hpp"
#include "laminate/protocol/metrics/proof_size.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace {

using namespace laminate;
using namespace laminate::fhe;
using namespace laminate::gkr;
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
                    ("laminate-base-prover-stream-" +
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
            throw std::runtime_error("failed to create child directory");
        }
        return child;
    }

  private:
    std::filesystem::path root_;
};

SlotVector values(std::uint64_t seed) {
    SlotVector result;
    result.reserve(kSlots);
    for (std::size_t slot = 0; slot < kSlots; ++slot) {
        result.emplace_back(seed + 5U * slot + slot * slot);
    }
    return result;
}

PayloadCircuit mixed_payload() {
    PayloadBuilder builder(PayloadShape::wide(kSlots), 1);
    const std::size_t bias = builder.add_scalar_plaintext(Fp(7));
    const WireId square = builder.mul(0, 0);
    builder.set_outputs({builder.add_plain(square, bias)});
    return builder.finish();
}

PayloadCircuit aliased_padded_multiplication_payload() {
    PayloadBuilder builder(PayloadShape::wide(kSlots), 2);
    const WireId first = builder.mul(0, 1);
    const WireId second = builder.mul(0, 1);
    const WireId third = builder.mul(0, 1);
    builder.set_outputs({first, second, third});
    return builder.finish();
}

PayloadCircuit padded_payload() {
    PayloadBuilder builder(PayloadShape::wide(kSlots), 3);
    const std::size_t mask = builder.add_plaintext(values(9));
    const WireId first = builder.mul(0, 1);
    const WireId diagonal = builder.mul_plain(2, mask);
    const WireId mixed = builder.add(first, diagonal);
    const WireId second = builder.mul(mixed, first);
    builder.set_outputs({builder.add(second, 2)});
    return builder.finish();
}

std::vector<std::uint64_t> correction_preserving_chain() {
    return {
        kOuterFieldOrder,
        1'152'921'497'895'862'273ULL,
        53'687'910'401ULL,
    };
}

HonestPayloadNoiseCalibration honest_calibration() {
    return HonestPayloadNoiseCalibration{
        .fresh_canonical_error_bound = 64,
        .ctct_relinearized_debit_bits = 40,
        .plaintext_multiplication_debit_bits = 3,
        .rotation_debit_bits = 2,
        .maximum_switch_tax_bits = 10,
        .switch_rounding_error_bound = 649,
        .modeled_switch_events_upper_bound = 10'000,
        .switch_model_failure_budget_bits = 40,
        .proof_suffix_level_reserve = 2,
    };
}

std::uint64_t counted_fhe_operations(const OperationCounts &counts) {
    return counts.encrypt + counts.decrypt + counts.negate + counts.add +
           counts.sub + counts.mul_no_relin + counts.relinearize +
           counts.add_plain + counts.mul_plain_scalar +
           counts.mul_plain_vector + counts.rotate + counts.mod_switch +
           counts.logical_ext_add + counts.logical_ext_sub +
           counts.logical_ext_mul + counts.logical_ext_mul_plain;
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

FileTraceStoreOptions store_limits() {
    return FileTraceStoreOptions{
        .max_total_bytes = std::uint64_t{1} << 28U,
        .min_free_bytes = 1,
    };
}

base_detail::FileEncryptedBaseGkrOptions scratch_options(
    const LayeredCircuit &circuit, const TemporaryDirectory &root,
    const std::string &prefix,
    std::vector<std::filesystem::path> *directories = nullptr) {
    base_detail::FileEncryptedBaseGkrOptions result;
    for (const std::size_t layer : multiplication_layers(circuit)) {
        const std::filesystem::path directory =
            root.make_child(prefix + std::to_string(layer));
        if (directories != nullptr) {
            directories->push_back(directory);
        }
        result.multiplication_scratch.push_back(
            base_detail::FileBaseMultiplicationScratch{
                layer, directory, store_limits()});
    }
    return result;
}

HonestPayloadNoiseSchedule replay_schedule(
    const LayeredCircuit &circuit) {
    HonestPayloadNoiseSchedule schedule =
        derive_honest_payload_noise_schedule(
            circuit, correction_preserving_chain(), honest_calibration());
    std::vector<std::size_t> ingress =
        schedule.evaluation_plan.trace.required_mult_depth_by_layer;
    for (std::size_t layer = 1; layer < ingress.size(); ++layer) {
        ingress[layer] = 0;
    }
    return apply_honest_base_proof_ingress_depths(
        circuit, std::move(schedule), ingress);
}

SingleClaim output_claim(const PlainTrace &plain,
                         const LayeredCircuit &circuit,
                         std::uint64_t seed) {
    Transcript coin("test/base/prover-file-backed/output/" +
                    std::to_string(seed));
    return make_layer_claim(
        plain.layers.front(),
        coin.challenge_vector(base_detail::layer_vars(circuit, 0)));
}

std::vector<PayloadLayerResourceEstimate> replay_resources(
    const ReplayMockBackend::EvalContext &eval,
    const LayeredCircuit &circuit,
    const EncryptedTrace<ReplayMockBackend> &compact) {
    const std::vector<LayerWireSupport> support =
        canonical_trace_wire_support(circuit);
    const std::vector<LayerStorageLayout> storage =
        canonical_trace_storage_layout(circuit);
    const std::vector<std::uint64_t> work =
        payload_replay_work_units(circuit);
    std::vector<PayloadLayerResourceEstimate> result;
    result.reserve(circuit.layers.size());
    for (std::size_t layer = 0; layer < circuit.layers.size(); ++layer) {
        const auto &wires = compact.layers[layer].wires;
        if (wires.empty()) {
            throw std::logic_error("test replay layer is empty");
        }
        std::uint64_t encoded_bound = 0;
        std::size_t rns_limb_count = 0;
        for (const auto &value : wires) {
            encoded_bound = std::max<std::uint64_t>(
                encoded_bound,
                fhe::encode_fhe_value_record<
                    ReplayMockBackend>(eval, value).size());
            if (value.is_encrypted()) {
                rns_limb_count = std::max(
                    rns_limb_count,
                    ReplayMockBackend::rns_limb_count(
                        eval, value.ciphertext()));
            }
        }
        result.push_back(PayloadLayerResourceEstimate{
            .rns_limb_count = rns_limb_count,
            .checkpoint_bytes = standalone_checkpoint_layer_artifact_bytes(
                storage[layer].stored_wire_count, encoded_bound),
            .serialized_ciphertext_bytes = encoded_bound,
            .resident_ciphertext_bytes = encoded_bound + 4096U,
            .replay_work_units = work[layer],
        });
    }
    return result;
}

PayloadCheckpointReplayBudgets replay_budgets() {
    return PayloadCheckpointReplayBudgets{
        .max_live_scratch_bytes = std::uint64_t{1} << 30U,
        .max_resident_ciphertext_bytes = std::uint64_t{1} << 30U,
        .max_ciphertexts_per_chunk = 8,
        .max_recomputation_factor = {100, 1},
        .reserved_live_scratch_bytes = 4096,
        .reserved_resident_bytes = 2048,
    };
}

PayloadCheckpointReplayExecutionOptions replay_options(
    const std::filesystem::path &directory) {
    return PayloadCheckpointReplayExecutionOptions{
        .directory = directory,
        .min_free_bytes = 1,
        .max_checkpoint_metadata_bytes = 4096,
        .lifecycle = FileTraceSessionLifecycle::IrreversibleNoRetry,
    };
}

template <typename Body> bool throws_exception(Body &&body) {
    try {
        std::forward<Body>(body)();
    } catch (const std::exception &) {
        return true;
    }
    return false;
}

template <typename Body> bool throws_invalid(Body &&body) {
    try {
        std::forward<Body>(body)();
    } catch (const std::invalid_argument &) {
        return true;
    }
    return false;
}

void test_file_full_proof_matches_reference() {
    const PayloadCircuit payload = mixed_payload();
    const LayeredCircuit circuit = compile(payload);
    const std::vector<SlotVector> inputs{values(3)};
    const PlainTrace plain = synthesize_trace(payload, circuit, inputs);
    auto contexts = ReplayMockBackend::create(MockParameters{
        .slot_count = kSlots,
        .fresh_rns_limbs = 14,
        .bits_per_limb = 80,
    });
    const auto encrypted_inputs =
        encrypt_wide_payload_inputs<ReplayMockBackend>(
            contexts.client, payload, inputs);
    const FheEvaluationPlan plan =
        FheEvaluationPlan::at_evaluation_levels(circuit, 13);
    const EncryptedTrace<ReplayMockBackend> reference_trace =
        evaluate_wide_fhe_trace_into<ReplayMockBackend>(
            contexts.eval, payload, circuit, encrypted_inputs, plan,
            InMemoryTraceSink<ReplayMockBackend>{
                contexts.eval});
    const auto support = canonical_trace_wire_support(circuit);
    const auto storage = canonical_trace_storage_layout(circuit);
    for (std::size_t layer = 0; layer < circuit.layers.size(); ++layer) {
        CHECK(support[layer].live_wire_count ==
              support[layer].padded_wire_count);
        CHECK(reference_trace.layers[layer].wires.size() ==
              storage[layer].stored_wire_count);
    }

    const PublicSetup public_setup = make_direct_setup(payload, circuit);
    const auto setup = make_evaluation_setup<ReplayMockBackend>(
        public_setup, contexts.eval);
    const ClientSetup<ReplayMockBackend> client =
        make_client_setup<ReplayMockBackend>(public_setup, contexts.client);
    const SingleClaim claim = output_claim(plain, circuit, 17);

    TemporaryDirectory root;
    const std::filesystem::path trace_directory = root.make_child("trace");
    (void)write_file_encrypted_trace(
        contexts.eval, trace_directory, store_limits(), circuit, reference_trace);
    const auto trace = FileEncryptedTraceStore<ReplayMockBackend>::open(
        contexts.eval, trace_directory, payload, circuit,
        reference_trace.provenance, reference_trace.trace_id);
    std::vector<std::filesystem::path> scratch;
    auto options = scratch_options(circuit, root, "scratch-", &scratch);

    const std::string domain = "test/base/prover-file-backed/parity/v1";
    Transcript reference_transcript(domain);
    const auto reference_proof = base_detail::
        prove_resident_test_reference<ReplayMockBackend>(
            payload, circuit, reference_trace, setup, claim.point,
            reference_transcript);
    Transcript production_transcript(domain);
    const auto production =
        base_detail::prove_base_gkr_for_testing<ReplayMockBackend>(
            payload, circuit, trace, setup, claim.point, production_transcript,
            std::move(options));

    CHECK(protocol::encode_canonical<ReplayMockBackend>(production.proof) ==
          protocol::encode_canonical<ReplayMockBackend>(reference_proof));
    CHECK(production_transcript.challenge_fpk() ==
          reference_transcript.challenge_fpk());
    Transcript verifier_transcript(domain);
    CHECK(base_detail::verify_base_gkr_reference<ReplayMockBackend>(
        payload, circuit, inputs, client, reference_trace.provenance,
        reference_trace.trace_id, claim, production.proof, verifier_transcript));
    CHECK(!production.report.output_trace_retirement.has_value());
    CHECK(production.report.reductions.size() == circuit.layers.size() - 1U);
    for (const auto &directory : scratch) {
        CHECK(std::filesystem::is_empty(directory));
    }
    for (const auto &reduction : production.report.reductions) {
        CHECK(!reduction.trace_retirement.has_value());
        if (reduction.kind == LayerKind::Multiplication) {
            CHECK(reduction.multiplication_artifact.has_value());
            CHECK(reduction.multiplication.has_value());
            CHECK(reduction.scratch_reclaimed_physical_bytes ==
                  reduction.multiplication_artifact->storage.physical_bytes);
        } else {
            CHECK(reduction.affine.has_value());
        }
    }

    auto gate_key = std::make_shared<gates::GateTableProverKey>(
        gates::preprocess_gate_tables(circuit, gates::GateTableSet::Wide));
    const PublicSetup outsourced_public = make_outsourced_gate_setup(
        payload, circuit, gate_key->verifier);
    const auto outsourced_setup =
        make_evaluation_setup<ReplayMockBackend>(
            outsourced_public, contexts.eval, gate_key);
    const auto outsourced_client =
        make_client_setup<ReplayMockBackend>(
            outsourced_public, contexts.client);
    std::vector<std::filesystem::path> outsourced_scratch;
    auto outsourced_options = scratch_options(
        circuit, root, "outsourced-scratch-", &outsourced_scratch);
    const std::string outsourced_domain =
        "test/base/prover-file-backed/outsourced/v1";
    Transcript outsourced_reference_transcript(outsourced_domain);
    const auto outsourced_reference =
        base_detail::
            prove_resident_test_reference<ReplayMockBackend>(
            payload, circuit, reference_trace, outsourced_setup, claim.point,
            outsourced_reference_transcript);
    Transcript outsourced_file_transcript(outsourced_domain);
    const auto outsourced_file_backed =
        base_detail::prove_base_gkr_for_testing<ReplayMockBackend>(
            payload, circuit, trace, outsourced_setup, claim.point,
            outsourced_file_transcript,
            std::move(outsourced_options));
    CHECK(outsourced_file_backed.proof.gate_mle_opening.has_value());
    CHECK(protocol::encode_canonical<ReplayMockBackend>(
              outsourced_file_backed.proof) ==
          protocol::encode_canonical<ReplayMockBackend>(
              outsourced_reference));
    CHECK(outsourced_file_transcript.challenge_fpk() ==
          outsourced_reference_transcript.challenge_fpk());
    Transcript outsourced_verifier_transcript(outsourced_domain);
    CHECK(base_detail::verify_base_gkr_reference<ReplayMockBackend>(
        payload, circuit, inputs, outsourced_client,
        reference_trace.provenance, reference_trace.trace_id, claim,
        outsourced_file_backed.proof, outsourced_verifier_transcript));
    for (const auto &directory : outsourced_scratch) {
        CHECK(std::filesystem::is_empty(directory));
    }
}

void test_aliased_padded_dense_unit_gamma_parity() {
    const PayloadCircuit payload =
        aliased_padded_multiplication_payload();
    const LayeredCircuit circuit = compile(payload);
    const std::vector<SlotVector> inputs{values(3), values(29)};
    const PlainTrace plain = synthesize_trace(payload, circuit, inputs);
    const std::vector<std::size_t> dense_layers =
        multiplication_layers(circuit);
    CHECK(dense_layers.size() == 1U);
    const std::size_t layer = dense_layers.front();
    CHECK(base_detail::ciphertext_index_variables(circuit, layer) > 0U);

    const std::vector<LayerWireSupport> support =
        canonical_trace_wire_support(circuit);
    const std::vector<LayerStorageLayout> storage =
        canonical_trace_storage_layout(circuit);
    CHECK(support[layer + 1U].live_wire_count <
          support[layer + 1U].padded_wire_count);
    CHECK(storage[layer + 1U].stored_wire_count <
          support[layer + 1U].live_wire_count);

    auto contexts = ReplayMockBackend::create(MockParameters{
        .slot_count = kSlots,
        .fresh_rns_limbs = 14,
        .bits_per_limb = 80,
    });
    const auto encrypted_inputs =
        encrypt_wide_payload_inputs<ReplayMockBackend>(
            contexts.client, payload, inputs);
    const EncryptedTrace<ReplayMockBackend> reference_trace =
        evaluate_wide_fhe_trace_into<ReplayMockBackend>(
            contexts.eval, payload, circuit, encrypted_inputs,
            FheEvaluationPlan::at_evaluation_levels(circuit, 13),
            InMemoryTraceSink<ReplayMockBackend>{contexts.eval});

    std::vector<Fpk> claim_point =
        output_claim(plain, circuit, 23).point;
    claim_point.front() = Fpk::one();
    const SingleClaim claim =
        make_layer_claim(plain.layers.front(), claim_point);
    const PublicSetup public_setup = make_direct_setup(payload, circuit);
    const auto setup = make_evaluation_setup<ReplayMockBackend>(
        public_setup, contexts.eval);
    const ClientSetup<ReplayMockBackend> client =
        make_client_setup<ReplayMockBackend>(public_setup,
                                             contexts.client);

    TemporaryDirectory root;
    const std::filesystem::path trace_directory =
        root.make_child("unit-gamma-trace");
    (void)write_file_encrypted_trace(
        contexts.eval, trace_directory, store_limits(), circuit, reference_trace);
    const auto trace = FileEncryptedTraceStore<ReplayMockBackend>::open(
        contexts.eval, trace_directory, payload, circuit,
        reference_trace.provenance, reference_trace.trace_id);
    auto options = scratch_options(circuit, root, "unit-gamma-scratch-");

    const std::string domain =
        "test/base/prover-file-backed/unit-gamma-parity/v1";
    Transcript reference_transcript(domain);
    const auto reference_proof = base_detail::
        prove_resident_test_reference<ReplayMockBackend>(
            payload, circuit, reference_trace, setup, claim.point,
            reference_transcript);
    Transcript production_transcript(domain);
    const auto production =
        base_detail::prove_base_gkr_for_testing<ReplayMockBackend>(
            payload, circuit, trace, setup, claim.point,
            production_transcript, std::move(options));

    CHECK(protocol::encode_canonical<ReplayMockBackend>(production.proof) ==
          protocol::encode_canonical<ReplayMockBackend>(reference_proof));
    CHECK(production_transcript.challenge_fpk() ==
          reference_transcript.challenge_fpk());
    Transcript verifier_transcript(domain);
    CHECK(base_detail::verify_base_gkr_reference<ReplayMockBackend>(
        payload, circuit, inputs, client, reference_trace.provenance,
        reference_trace.trace_id, claim, production.proof, verifier_transcript));
}

struct ReplayFixture {
    PayloadCircuit payload = padded_payload();
    LayeredCircuit circuit = compile(payload);
    HonestPayloadNoiseSchedule schedule =
        replay_schedule(circuit);
    ReplayMockBackend::Contexts contexts =
        ReplayMockBackend::create(MockParameters{
            .slot_count = kSlots,
            .fresh_rns_limbs = schedule.data_moduli_low_to_high.size(),
            .bits_per_limb = 256,
            .initial_noise_margin_bits = 4,
        });
    FheEvaluationPlan evaluation = schedule.evaluation_plan;
    std::vector<SlotVector> inputs{values(7), values(71), values(149)};
    std::vector<ReplayMockBackend::Ciphertext> encrypted_inputs =
        encrypt_wide_payload_inputs<ReplayMockBackend>(
            contexts.client, payload, inputs);
    PlainTrace plain = synthesize_trace(payload, circuit, inputs);
    FheEvaluationPlan natural_level_evaluation = [&] {
        FheEvaluationPlan result = evaluation;
        result.proof_ingress_mult_depth_by_layer =
            result.trace.required_mult_depth_by_layer;
        return result;
    }();
    EncryptedTrace<ReplayMockBackend> compact =
        evaluate_wide_fhe_trace_into<ReplayMockBackend>(
            contexts.eval, payload, circuit, encrypted_inputs,
            natural_level_evaluation,
            InMemoryTraceSink<ReplayMockBackend>{
                contexts.eval});
    PayloadCheckpointReplayProblem problem =
        make_payload_checkpoint_replay_problem(
            circuit, evaluation,
            replay_resources(contexts.eval, circuit, compact), 512, 0);
    PayloadCheckpointReplayBudgets budgets = replay_budgets();
    PayloadCheckpointReplayPlan plan =
        plan_payload_checkpoint_replay(problem, budgets);
};

void test_padded_checkpoint_replay_proof_verifies() {
    ReplayFixture fixture;
    const auto support = canonical_trace_wire_support(fixture.circuit);
    CHECK(std::any_of(support.begin(), support.end(), [](const auto &layer) {
        return layer.live_wire_count < layer.padded_wire_count;
    }));
    const PublicSetup public_setup =
        make_direct_setup(fixture.payload, fixture.circuit);
    const auto setup = make_evaluation_setup<ReplayMockBackend>(
        public_setup, fixture.contexts.eval);
    const auto client = make_client_setup<ReplayMockBackend>(
        public_setup, fixture.contexts.client);
    const SingleClaim claim = output_claim(fixture.plain, fixture.circuit, 29);

    TemporaryDirectory root;
    const std::filesystem::path replay_directory =
        root.make_child("replay");
    std::vector<RuntimeProgressEvent> progress_events;
    PayloadCheckpointReplayTrace<ReplayMockBackend> *observed_replay =
        nullptr;
    std::size_t scratch_builds_after_natural_retirement = 0;
    bool lifecycle_overlap_observed = false;
    const RuntimeProgressCallback progress =
        [&](const RuntimeProgressEvent &event) {
            progress_events.push_back(event);
            if (observed_replay != nullptr &&
                event.stage ==
                    RuntimeProgressStage::BaseMultiplicationSourceBuild &&
                event.boundary == RuntimeProgressBoundary::End) {
                const auto &planned =
                    fixture.plan.reverse_gkr_segments.at(
                        event.source_layer - 1U);
                if (planned.proof_ingress_artifact_bytes_upper_bound != 0) {
                    const auto &executed = observed_replay->report()
                                               .segments.at(
                                                   event.source_layer - 1U);
                    const std::uint64_t natural_retired =
                        executed.checkpoint_bytes_retired_after_use +
                        executed.transient_source_bytes_retired_after_use;
                    ++scratch_builds_after_natural_retirement;
                    lifecycle_overlap_observed =
                        lifecycle_overlap_observed ||
                        natural_retired == 0 ||
                        executed.proof_ingress_bytes_retired_after_use != 0;
                }
            }
            // Callback failures are diagnostics failures, not protocol
            // failures. Every integration event deliberately exercises that
            // boundary here.
            throw std::runtime_error("injected progress callback failure");
        };
    PayloadCheckpointReplayExecutionOptions execution_options =
        replay_options(replay_directory);
    execution_options.progress = progress;
    std::vector<fhe::FheValue<ReplayMockBackend>> output;
    auto replay = PayloadCheckpointReplayTrace<ReplayMockBackend>::publish(
        fixture.contexts.eval, fixture.payload, fixture.circuit,
        fixture.encrypted_inputs, fixture.evaluation, fixture.problem,
        fixture.budgets, fixture.plan, std::move(execution_options),
        output);
    observed_replay = &replay;
    const Digest trace_id = replay.descriptor().trace_id;
    std::vector<std::filesystem::path> scratch;
    base_detail::FileEncryptedBaseGkrOptions options =
        scratch_options(fixture.circuit, root, "replay-scratch-", &scratch);
    options.progress = progress;

    ReplayMockBackend::reset_counts(fixture.contexts.eval);
    const std::string domain = "test/base/prover-file-backed/replay/v1";
    Transcript prover_transcript(domain);
    const auto proved =
        base_detail::prove_base_gkr_irreversible<ReplayMockBackend>(
            fixture.payload, fixture.circuit, replay, setup, claim.point,
            prover_transcript, std::move(options));
    CHECK(ReplayMockBackend::counts(fixture.contexts.eval).encrypt == 0);
    CHECK(fixture.schedule.modeled_payload_switch_events == 0);
    const std::uint64_t observed_proof_switches =
        ReplayMockBackend::counts(fixture.contexts.eval).mod_switch;
    if (observed_proof_switches !=
        fixture.schedule.modeled_base_proof_switch_events) {
        throw test::CheckFailure(
            "Base proof switch-count mismatch: observed " +
            std::to_string(observed_proof_switches) + ", modeled " +
            std::to_string(
                fixture.schedule.modeled_base_proof_switch_events) +
            " (ingress " +
            std::to_string(fixture.schedule
                               .modeled_base_proof_ingress_switch_events) +
            ", messages " +
            std::to_string(fixture.schedule
                               .modeled_base_proof_message_switch_events) +
            ")");
    }

    Transcript verifier_transcript(domain);
    base_detail::ProofReader<ReplayMockBackend> proof_reader(
        fixture.contexts.client);
    base_detail::BaseGkrVerifier<ReplayMockBackend,
                                  decltype(proof_reader)>
        verifier(fixture.payload, fixture.circuit,
                 fixture.plain.layers.back(), client,
                 TraceProvenance::FheEvaluated, trace_id, claim,
                 proved.proof, proof_reader, verifier_transcript);
    auto verifier_state = verifier.begin();
    CHECK(verifier_state.has_value());
    while (verifier.has_next_layer(*verifier_state)) {
        const std::size_t layer = verifier_state->next_layer;
        if (!verifier.verify_next_layer(*verifier_state)) {
            throw std::runtime_error("replay proof failed at layer " +
                                     std::to_string(layer));
        }
    }
    if (!verifier.terminal_claim_is_valid(*verifier_state)) {
        throw std::runtime_error("replay proof terminal claim failed");
    }
    CHECK(verifier.verify_gate_opening());
    CHECK(replay.proof_attempt_started());
    CHECK(replay.report().all_payload_artifacts_retired);
    CHECK(replay.report().live_physical_bytes == 0);
    CHECK(proved.report.output_trace_retirement.has_value());
    CHECK(proved.report.output_trace_retirement->layer_index == 0);
    CHECK(proved.report.reductions.size() == fixture.circuit.layers.size() - 1U);
    for (std::size_t layer = 0; layer < proved.report.reductions.size();
         ++layer) {
        CHECK(proved.report.reductions[layer].trace_retirement.has_value());
        CHECK(proved.report.reductions[layer].trace_retirement->layer_index ==
              layer + 1U);
    }
    for (const auto &directory : scratch) {
        CHECK(std::filesystem::is_empty(directory));
    }

    std::vector<RuntimeProgressEvent> active;
    std::size_t forward_relations = 0;
    std::size_t replay_segments = 0;
    std::size_t proof_ingresses = 0;
    std::size_t reductions = 0;
    std::size_t sumcheck_rounds = 0;
    std::size_t multiplication_layers = 0;
    std::size_t scratch_builds = 0;
    std::size_t scratch_reclaims = 0;
    std::size_t trace_retires = 0;
    std::size_t gate_finishes = 0;
    std::vector<std::uint64_t> completed_steps;
    std::vector<std::uint64_t> completed_work_units;
    const auto same_span = [](const RuntimeProgressEvent &left,
                              const RuntimeProgressEvent &right) {
        return left.stage == right.stage &&
               left.layer_kind == right.layer_kind &&
               left.side == right.side &&
               left.coordinate_domain == right.coordinate_domain &&
               left.reduction_layer == right.reduction_layer &&
               left.source_layer == right.source_layer &&
               left.output_layer == right.output_layer &&
               left.checkpoint_layer == right.checkpoint_layer &&
               left.round == right.round &&
               left.round_count == right.round_count &&
               left.work_units == right.work_units;
    };
    for (const RuntimeProgressEvent &event : progress_events) {
        if (event.boundary == RuntimeProgressBoundary::Begin) {
            active.push_back(event);
            completed_steps.push_back(0);
            completed_work_units.push_back(0);
            switch (event.stage) {
            case RuntimeProgressStage::PayloadForwardRelation:
                ++forward_relations;
                break;
            case RuntimeProgressStage::PayloadReplaySegment:
                ++replay_segments;
                break;
            case RuntimeProgressStage::PayloadProofIngress:
                ++proof_ingresses;
                break;
            case RuntimeProgressStage::BaseReduction:
                ++reductions;
                if (event.layer_kind ==
                    RuntimeProgressLayerKind::Multiplication) {
                    ++multiplication_layers;
                }
                break;
            case RuntimeProgressStage::BaseAffineSumcheckRound:
            case RuntimeProgressStage::BaseMultiplicationSumcheckRound:
                ++sumcheck_rounds;
                break;
            case RuntimeProgressStage::BaseMultiplicationSourceBuild:
                ++scratch_builds;
                break;
            case RuntimeProgressStage::BaseMultiplicationSourceReclaim:
                ++scratch_reclaims;
                break;
            case RuntimeProgressStage::BaseTraceLayerRetirement:
                ++trace_retires;
                break;
            case RuntimeProgressStage::BaseGateMleFinish:
                ++gate_finishes;
                break;
            default:
                break;
            }
            continue;
        }
        CHECK(!active.empty());
        CHECK(same_span(event, active.back()));
        if (event.boundary == RuntimeProgressBoundary::Update) {
            if (event.total_steps != 0) {
                CHECK(event.completed_steps > completed_steps.back());
                CHECK(event.completed_steps <= event.total_steps);
                completed_steps.back() = event.completed_steps;
            }
            if (event.total_work_units != 0) {
                CHECK(event.completed_work_units >
                      completed_work_units.back());
                CHECK(event.completed_work_units <=
                      event.total_work_units);
                completed_work_units.back() =
                    event.completed_work_units;
            }
            if (event.column_count != 0) {
                CHECK(event.column_index < event.column_count);
            }
            continue;
        }
        CHECK(event.boundary == RuntimeProgressBoundary::End);
        if (event.total_steps != 0) {
            CHECK(event.completed_steps == event.total_steps);
            CHECK(completed_steps.back() == event.total_steps);
        }
        active.pop_back();
        completed_steps.pop_back();
        completed_work_units.pop_back();
    }
    CHECK(active.empty());
    CHECK(completed_steps.empty());
    CHECK(completed_work_units.empty());
    CHECK(forward_relations == fixture.circuit.layers.size() - 1U);
    CHECK(replay_segments == fixture.circuit.layers.size() - 1U);
    CHECK(proof_ingresses == fixture.circuit.layers.size() - 1U);
    CHECK(reductions == fixture.circuit.layers.size() - 1U);
    CHECK(sumcheck_rounds > 0);
    CHECK(scratch_builds == multiplication_layers);
    CHECK(scratch_reclaims == multiplication_layers);
    CHECK(trace_retires == fixture.circuit.layers.size());
    CHECK(gate_finishes == 1);
    CHECK(scratch_builds_after_natural_retirement > 0);
    CHECK(!lifecycle_overlap_observed);
}

void test_bound_setup_rejects_unbound_checkpoint_trace() {
    ReplayFixture fixture;
    PublicSetup public_setup =
        make_direct_setup(fixture.payload, fixture.circuit);
    Digest schedule_digest{};
    schedule_digest.front() = 1U;
    Digest assessment_digest{};
    assessment_digest.front() = 2U;
    public_setup.honest_payload_noise_schedule_digest = schedule_digest;
    public_setup.honest_base_proof_noise_assessment_digest =
        assessment_digest;
    const auto setup = make_evaluation_setup<ReplayMockBackend>(
        public_setup, fixture.contexts.eval);
    const SingleClaim claim = output_claim(fixture.plain, fixture.circuit, 41);

    TemporaryDirectory root;
    std::vector<fhe::FheValue<ReplayMockBackend>> output;
    auto replay = PayloadCheckpointReplayTrace<ReplayMockBackend>::publish(
        fixture.contexts.eval, fixture.payload, fixture.circuit,
        fixture.encrypted_inputs, fixture.evaluation, fixture.problem,
        fixture.budgets, fixture.plan,
        replay_options(root.make_child("unbound-replay")), output);
    protocol::BaseProverOptions options =
        scratch_options(fixture.circuit, root, "unbound-scratch-");

    ReplayMockBackend::reset_counts(fixture.contexts.eval);
    Transcript attempted("test/base/bound-checkpoint-rejection/v1");
    CHECK(throws_invalid([&] {
        (void)protocol::prove_base<
            ReplayMockBackend>(
            fixture.payload, fixture.circuit, replay, setup, claim.point,
            attempted, std::move(options));
    }));
    CHECK(counted_fhe_operations(
              ReplayMockBackend::counts(fixture.contexts.eval)) == 0);
    CHECK(!replay.proof_attempt_started());
    Transcript pristine("test/base/bound-checkpoint-rejection/v1");
    CHECK(attempted.challenge_fpk() == pristine.challenge_fpk());
}

template <typename Replay> class FailingReplaySource {
  public:
    explicit FailingReplaySource(Replay &replay) : replay_(&replay) {}

    const auto &descriptor() const { return replay_->descriptor(); }
    const auto &backend_context_id() const {
        return replay_->backend_context_id();
    }
    template <typename EvalContext>
    bool matches_backend_context(const EvalContext &eval) const {
        return replay_->matches_backend_context(eval);
    }
    const auto &layered_circuit_id() const {
        return replay_->layered_circuit_id();
    }
    const auto &directory() const { return replay_->directory(); }
    const auto &layer_support(std::size_t layer) const {
        return replay_->layer_support(layer);
    }
    auto active_layer_reader(std::size_t layer) const
        -> decltype(std::declval<const Replay &>().active_layer_reader(
            layer)) {
        throw std::runtime_error("injected Base source-reader failure");
    }
    auto active_layer_reader(std::size_t layer, std::size_t begin,
                             std::size_t end) const
        -> decltype(std::declval<const Replay &>().active_layer_reader(
            layer, begin, end)) {
        return replay_->active_layer_reader(layer, begin, end);
    }
    auto retire_layer(std::size_t layer) {
        return replay_->retire_layer(layer);
    }

  private:
    Replay *replay_;
};

void test_preflight_and_terminal_failure_boundaries() {
    ReplayFixture fixture;
    const PublicSetup public_setup =
        make_direct_setup(fixture.payload, fixture.circuit);
    const auto setup = make_evaluation_setup<ReplayMockBackend>(
        public_setup, fixture.contexts.eval);
    const SingleClaim claim = output_claim(fixture.plain, fixture.circuit, 37);
    TemporaryDirectory root;
    const std::filesystem::path replay_directory =
        root.make_child("preflight-replay");
    std::vector<fhe::FheValue<ReplayMockBackend>> output;
    auto replay = PayloadCheckpointReplayTrace<ReplayMockBackend>::publish(
        fixture.contexts.eval, fixture.payload, fixture.circuit,
        fixture.encrypted_inputs, fixture.evaluation, fixture.problem,
        fixture.budgets, fixture.plan, replay_options(replay_directory),
        output);

    const auto pristine_attempt = [&](auto options,
                                      const SingleClaim &attempted_claim,
                                      const std::string &domain) {
        Transcript attempted(domain);
        CHECK(throws_invalid([&] {
            (void)base_detail::
                prove_base_gkr_irreversible<ReplayMockBackend>(
                    fixture.payload, fixture.circuit, replay, setup,
                    attempted_claim.point, attempted, std::move(options));
        }));
        Transcript fresh(domain);
        CHECK(attempted.challenge_fpk() == fresh.challenge_fpk());
        CHECK(!replay.proof_attempt_started());
    };

    {
        auto bad_claim = claim;
        bad_claim.point.pop_back();
        base_detail::FileEncryptedBaseGkrOptions options =
            scratch_options(fixture.circuit, root, "claim-");
        pristine_attempt(std::move(options), bad_claim,
                         "test/base/preflight/claim");
    }
    {
        base_detail::FileEncryptedBaseGkrOptions options =
            scratch_options(fixture.circuit, root, "quota-");
        options.multiplication_scratch.front()
            .storage_limits.max_total_bytes = 1;
        pristine_attempt(std::move(options), claim,
                         "test/base/preflight/quota");
    }
    {
        base_detail::FileEncryptedBaseGkrOptions options =
            scratch_options(fixture.circuit, root, "ancestry-");
        const std::filesystem::path nested =
            replay_directory / "foreign-empty-scratch";
        CHECK(std::filesystem::create_directory(nested));
        options.multiplication_scratch.front().directory = nested;
        pristine_attempt(std::move(options), claim,
                         "test/base/preflight/ancestry");
    }

    std::vector<std::filesystem::path> failure_scratch;
    base_detail::FileEncryptedBaseGkrOptions failure_options = scratch_options(
        fixture.circuit, root, "terminal-", &failure_scratch);
    FailingReplaySource failure_source(replay);
    Transcript failed("test/base/terminal-failure/v1");
    CHECK(throws_exception([&] {
        (void)base_detail::
            prove_base_gkr_irreversible<ReplayMockBackend>(
                fixture.payload, fixture.circuit, failure_source, setup,
                claim.point, failed, std::move(failure_options));
    }));
    CHECK(replay.proof_attempt_started());
    Transcript fresh("test/base/terminal-failure/v1");
    CHECK(failed.challenge_fpk() != fresh.challenge_fpk());
    for (const auto &directory : failure_scratch) {
        CHECK(std::filesystem::is_empty(directory));
    }
}

} // namespace

int main() {
    laminate::test::Runner runner("Base file-backed top-level prover");
    runner.run("file proof and transcript match reference proof",
               test_file_full_proof_matches_reference);
    runner.run("aliased padded dense proof matches at unit gamma",
               test_aliased_padded_dense_unit_gamma_parity);
    runner.run("padded checkpoint replay proof verifies and retires",
               test_padded_checkpoint_replay_proof_verifies);
    runner.run("bound setup rejects an unauthenticated replay trace",
               test_bound_setup_rejects_unbound_checkpoint_trace);
    runner.run("preflight is pristine and late failure is terminal",
               test_preflight_and_terminal_failure_boundaries);
    return runner.summary();
}
