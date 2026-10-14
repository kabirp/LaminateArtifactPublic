/// @file test_base_prover_file_backed_seal.cpp
/// @brief Small real-BGV full proof for file-backed LaminateBase.

#include "test_helpers.hpp"
#include "base_checkpoint_test_helpers.hpp"

#include "laminate/bench/base_pyramid_parameters.hpp"
#include "laminate/bench/payload_profile.hpp"
#include "laminate/bench/packed_process_profile.hpp"
#include "laminate/delegation/base/client.hpp"
#include "laminate/delegation/base/reference/client.hpp"
#include "laminate/delegation/base/server.hpp"
#include "laminate/fhe/seal_backend.hpp"
#include "laminate/fhe/storage/value_codec.hpp"
#include "laminate/gkr/detail/base/testing/file_trace_prover.hpp"
#include "laminate/gkr/detail/base/verifier.hpp"
#include "laminate/gkr/detail/base/verification/diagnostic.hpp"
#include "laminate/payload/checkpoint/session_engine.hpp"
#include "laminate/payload/compiler.hpp"
#include "laminate/payload/evaluator.hpp"
#include "laminate/payload/fixtures/workloads.hpp"
#include "laminate/payload/noise/honest_base_proof_noise.hpp"
#include "laminate/payload/noise/honest_noise_schedule.hpp"
#include "laminate/payload/input_encryption.hpp"
#include "laminate/payload/trace/trace_sink.hpp"
#include "laminate/payload/wide_fhe_evaluator.hpp"
#include "laminate/protocol/packed/setup/proof_ingress.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <chrono>
#include <cstddef>
#include <cstdio>
#include <cstdint>
#include <filesystem>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace {

using namespace laminate;
using namespace laminate::fhe;
using namespace laminate::gkr;
using namespace laminate::payload;
using namespace laminate::delegation;

constexpr std::size_t kSlots = 1024;

class TemporaryDirectory {
  public:
    TemporaryDirectory() {
        const auto stamp = std::chrono::steady_clock::now()
                               .time_since_epoch()
                               .count();
        for (std::size_t attempt = 0; attempt < 100; ++attempt) {
            root_ = std::filesystem::temp_directory_path() /
                    ("laminate-base-prover-stream-seal-" +
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
        result.emplace_back(seed + 3U * slot + slot * slot);
    }
    return result;
}

BaseClientNonce nonce() {
    std::array<std::uint8_t, 32> bytes{};
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        bytes[index] = static_cast<std::uint8_t>(73U + index);
    }
    return make_base_client_nonce(bytes);
}

PayloadCheckpointReplayProblem make_problem(
    const LayeredCircuit &circuit, const FheEvaluationPlan &evaluation,
    const SealBackend::EvalContext &eval,
    const EncryptedTrace<SealBackend> &compact) {
    const auto storage = canonical_trace_storage_layout(circuit);
    const std::vector<std::uint64_t> work =
        payload_replay_work_units(circuit);
    std::vector<PayloadLayerResourceEstimate> resources;
    resources.reserve(circuit.layers.size());
    for (std::size_t layer = 0; layer < circuit.layers.size(); ++layer) {
        const auto &wires = compact.layers[layer].wires;
        CHECK(wires.size() == storage[layer].stored_wire_count);
        std::uint64_t encoded_bound = 0;
        std::size_t rns_limbs = 0;
        for (const auto &value : wires) {
            encoded_bound = std::max<std::uint64_t>(
                encoded_bound,
                encode_fhe_value_record<SealBackend>(
                    eval, value,
                    "file-backed SEAL checkpoint fixture")
                    .size());
            if (!value.is_encrypted()) {
                continue;
            }
            rns_limbs = SealBackend::rns_limb_count(
                eval, value.ciphertext());
        }
        if (rns_limbs == 0) {
            throw std::logic_error(
                "file-backed SEAL fixture requires a private live wire");
        }
        resources.push_back(PayloadLayerResourceEstimate{
            .rns_limb_count = rns_limbs,
            .checkpoint_bytes = standalone_checkpoint_layer_artifact_bytes(
                storage[layer].stored_wire_count, encoded_bound),
            .serialized_ciphertext_bytes = encoded_bound,
            .resident_ciphertext_bytes =
                encoded_bound + (std::uint64_t{1} << 20U),
            .replay_work_units = work[layer],
        });
    }
    return make_payload_checkpoint_replay_problem(
        circuit, evaluation, resources, 512, 0);
}

HonestPayloadNoiseCalibration honest_payload_calibration() {
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

HonestBaseProofNoiseCalibration honest_base_proof_calibration() {
    return HonestBaseProofNoiseCalibration{
        .ctct_relinearized_debit_bits = 40,
        // Base proof masks are full-slot F_q plaintexts. Account for the
        // field coefficient, the worst-case N-slot accumulation, and a small
        // fixture margin. Proof-message admission needs this full-slot
        // bound rather than the payload's 3-bit scalar charge.
        .plaintext_multiplication_debit_bits =
            std::bit_width(kBaseFieldOrder - 1U) +
            std::bit_width(kSlots - 1U) + 8U,
        .rotation_debit_bits = 2,
    };
}

protocol::BaseProverOptions role_proof_options(
    const LayeredCircuit &circuit, const TemporaryDirectory &root,
    const FileTraceStoreOptions &limits, std::string_view prefix) {
    protocol::BaseProverOptions result;
    for (std::size_t layer = 0; layer + 1U < circuit.layers.size();
         ++layer) {
        if (layer_kind(circuit.layers[layer]) ==
            LayerKind::Multiplication) {
            result.multiplication_scratch.push_back(
                base_detail::FileBaseMultiplicationScratch{
                    layer,
                    root.make_child(std::string(prefix) +
                                    std::to_string(layer)),
                    limits});
        }
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

bool no_seal_fhe_work(const SealBackend::OperationCounts &counts) {
    for (std::size_t kind = 0;
         kind < static_cast<std::size_t>(SealBackend::OperationKind::Count);
         ++kind) {
        if (counts.calls(static_cast<SealBackend::OperationKind>(kind)) !=
            0) {
            return false;
        }
    }
    return true;
}

// Fixed diagnostic chain with nine data primes and a 34-bit special prime.
// The ring degree matches the target, but this fixture independently probes
// modulus exhaustion and does not select the benchmark's parameter schedule.
SealParameters diagnostic_base_chain() {
    return SealParameters{
        .poly_modulus_degree = 16384,
        .fresh_rns_limbs = 9,
        .exact_data_primes =
            {1'053'858'393'162'252'289ULL, 15'032'614'913ULL,
             53'687'910'401ULL, 96'638'238'721ULL, 98'785'755'137ULL,
             118'113'402'881ULL, 122'408'435'713ULL, 246'964'387'841ULL,
             272'734'584'833ULL},
        .exact_special_prime = 8'590'163'969ULL,
        .special_prime_bits = 34,
        .security_level = seal::sec_level_type::none,
        .max_fresh_ciphertext_modulus_bits = 352,
        .max_key_modulus_bits = 385,
    };
}

SealParameters diagnostic_target_chain(std::uint64_t added_top_prime) {
    auto parameters = diagnostic_base_chain();
    parameters.fresh_rns_limbs = 10;
    parameters.exact_data_primes.push_back(292'062'232'577ULL);
    parameters.max_fresh_ciphertext_modulus_bits = 392;
    parameters.max_key_modulus_bits = 426;
    parameters.generate_galois_keys = false;
    if (added_top_prime) {
        ++parameters.fresh_rns_limbs;
        parameters.exact_data_primes.push_back(added_top_prime);
        parameters.max_fresh_ciphertext_modulus_bits += std::bit_width(added_top_prime);
        parameters.max_key_modulus_bits += std::bit_width(added_top_prime);
    }
    return parameters;
}

SealParameters diagnostic_pyramid_chain(std::uint64_t special_prime, int head_bits) {
    auto parameters = diagnostic_target_chain(1'095'233'372'161ULL);
    if (head_bits != 0) {
        parameters.exact_data_primes.resize(3);
        for (const auto &prime : seal::CoeffModulus::Create(16384,
                 seal::Modulus(kBaseFieldOrder), std::vector<int>(8, head_bits)))
            parameters.exact_data_primes.push_back(prime.value());
        parameters.max_fresh_ciphertext_modulus_bits = 130U + 8U * head_bits;
    }
    if (special_prime != 0) {
        parameters.exact_special_prime = special_prime;
        parameters.special_prime_bits = std::bit_width(special_prime);
    }
    parameters.max_key_modulus_bits = parameters.max_fresh_ciphertext_modulus_bits +
                                      parameters.special_prime_bits;
    return parameters;
}

SealParameters production_pyramid_chain() {
    return SealParameters{
        .poly_modulus_degree = 16384,
        .fresh_rns_limbs = bench::kBasePyramidDataPrimes.size(),
        .exact_data_primes = std::vector<std::uint64_t>(
            bench::kBasePyramidDataPrimes.begin(), bench::kBasePyramidDataPrimes.end()),
        .exact_special_prime = bench::kBasePyramidSpecialPrime,
        .special_prime_bits = static_cast<int>(std::bit_width(bench::kBasePyramidSpecialPrime)),
        .security_level = seal::sec_level_type::none,
        .max_fresh_ciphertext_modulus_bits = bench::kBasePyramidDataModulusBits,
        .max_key_modulus_bits = bench::kBasePyramidKeyModulusBits,
        .generate_galois_keys = true};
}

int diagnostic_head_bits(std::string_view argument) {
    if (!argument.starts_with("heads") || argument.size() == 5)
        throw std::invalid_argument("expected a payload-head option such as heads45");
    std::size_t consumed = 0;
    const auto bits = std::stoi(std::string(argument.substr(5)), &consumed);
    if (consumed != argument.size() - 5 || bits < 34 || bits > 60)
        throw std::invalid_argument("diagnostic payload-head width must be between 34 and 60 bits");
    return bits;
}

HonestPayloadNoiseCalibration diagnostic_target_calibration(bool revised_chain) {
    const std::uint64_t events = revised_chain ? 16'000'000 : 12'000'000;
    return HonestPayloadNoiseCalibration{
        .fresh_canonical_error_bound = 59'904,
        .ctct_relinearized_debit_bits = 36,
        .plaintext_multiplication_debit_bits = 24,
        .rotation_debit_bits = 34,
        .maximum_switch_tax_bits = 10,
        .switch_rounding_error_bound = revised_chain
            ? randomized_mod_switch_rounding_heuristic_bound(16384, events, 110) : 921,
        .modeled_switch_events_upper_bound = events,
        .switch_model_failure_budget_bits = 110,
        .proof_suffix_level_reserve = 0};
}

// Measure a repeated-squaring fixture, then report its remaining invariant
// noise budget at each lower modulus level. These observations characterize
// this input and key sample; they do not bound a complete target workload.
void measure_output_noise_budget_over_depth() {
    // The payload slot width must equal the ring degree, and the noise budget
    // depends on that degree, so use the target's N=16384 throughout.
    constexpr std::size_t kTargetDegree = 16384;
    const auto wide_values = [](std::uint64_t seed) {
        SlotVector result;
        result.reserve(kTargetDegree);
        for (std::size_t slot = 0; slot < kTargetDegree; ++slot) {
            result.emplace_back(seed + 3U * slot + slot * slot);
        }
        return result;
    };
    std::printf(
        "\n=== output invariant noise budget vs remaining RNS limbs "
        "(diagnostic chain, N=16384; deep CT-CT chain) ===\n");
    // Seven multiplications and level drops leave two limbs. The final probe
    // switches to one limb to expose the cost of that additional drop.
    constexpr std::size_t kChainDepth = 7;
    PayloadBuilder builder(PayloadShape::wide(kTargetDegree), 2);
    WireId accumulator = builder.mul(0, 1);
    for (std::size_t level = 1; level < kChainDepth; ++level) {
        accumulator = builder.mul(accumulator, accumulator);
    }
    builder.set_outputs({accumulator});
    const PayloadCircuit payload = builder.finish();
    const LayeredCircuit circuit = compile(payload);
    const std::vector<SlotVector> inputs{wide_values(3), wide_values(5)};
    auto contexts = SealBackend::create(diagnostic_base_chain());
    const auto encrypted_inputs = encrypt_wide_payload_inputs<SealBackend>(
        contexts.client, payload, inputs);
    const auto trace = evaluate_wide_fhe_trace_into<SealBackend>(
        contexts.eval, payload, circuit, encrypted_inputs,
        FheEvaluationPlan::switch_after_multiplication_layers(circuit, 1),
        InMemoryTraceSink<SealBackend>{contexts.eval});
    SealBackend::Ciphertext output =
        trace.layers.front().wires.front().ciphertext();
    while (true) {
        const std::size_t limbs =
            SealBackend::rns_limb_count(contexts.eval, output);
        const int budget =
            SealBackend::invariant_noise_budget(contexts.client, output);
        std::printf(
            "  output_rns_limbs=%zu  noise_budget_bits=%d%s\n", limbs, budget,
            budget == 0 ? "   <-- noise budget exhausted" : "");
        if (limbs <= 1) {
            break;
        }
        SealBackend::mod_switch_to_next(contexts.eval, output);
    }
    std::printf("\n");
}

void check_fixed_three_limb_file_backed_proof(
    bool target_depth_sum = false, const Workload *exact_workload = nullptr,
    const SealParameters *parameter_override = nullptr) {
    // Keep the target ring, complete modulus chain, and payload calibration.
    // Only the circuit is bounded. This exercises encrypted proof arithmetic
    // at the committed ingress policy; it is not target-scale calibration.
    constexpr std::size_t degree = 16384;
    auto parameters = parameter_override != nullptr
        ? *parameter_override : diagnostic_target_chain(1'095'233'372'161ULL);
    parameters.generate_galois_keys = exact_workload != nullptr;
    const auto calibration = diagnostic_target_calibration(true);
    std::vector<SlotVector> inputs(4, SlotVector(degree));
    SlotVector mask(degree), bias(degree);
    for (std::size_t slot = 0; slot < degree; ++slot) {
        mask[slot] = Fp(11U + 5U * slot + slot * slot);
        bias[slot] = Fp(17U + 7U * slot);
        for (std::size_t input = 0; input < inputs.size(); ++input)
            inputs[input][slot] = Fp(3U + 13U * input + slot * slot);
    }
    PayloadBuilder builder(PayloadShape::wide(degree), inputs.size());
    const auto mask_id = builder.add_plaintext(mask);
    const auto bias_id = builder.add_plaintext(bias);
    const std::size_t depth = target_depth_sum ? 8 : 2;
    if (target_depth_sum) {
        // BalancedLaned uses only additions and plaintext biases between
        // CT-CT layers. Retain that depth and a final sum at bounded width.
        const auto scalar_bias = builder.add_scalar_plaintext(Fp(7));
        std::array<WireId, 4> state{0, 1, 2, 3};
        for (std::size_t level = 0; level < depth; ++level) {
            std::array<WireId, 4> mixed{}, next{};
            for (std::size_t i = 0; i < state.size(); ++i)
                mixed[i] = builder.add_plain(
                    builder.add(state[i], state[(i + 1U) % state.size()]), scalar_bias);
            for (std::size_t i = 0; i < state.size(); ++i)
                next[i] = builder.mul(mixed[i], mixed[(i + 1U) % state.size()]);
            state = next;
        }
        builder.set_outputs({builder.add(builder.add(state[0], state[1]),
                                         builder.add(state[2], state[3]))});
    } else {
        std::array<WireId, 4> first{}, middle{}, outputs{};
        for (std::size_t i = 0; i < first.size(); ++i)
            first[i] = builder.mul(i, (i + 1U) % first.size());
        for (std::size_t i = 0; i < middle.size(); ++i)
            middle[i] = builder.add_plain(builder.add(
                builder.mul_plain(first[i], mask_id),
                first[(i + 1U) % first.size()]), bias_id);
        for (std::size_t i = 0; i < outputs.size(); ++i)
            outputs[i] = builder.add_plain(builder.mul(
                middle[i], middle[(i + 1U) % middle.size()]), bias_id);
        builder.set_outputs({outputs.begin(), outputs.end()});
    }
    auto payload = builder.finish();
    if (exact_workload != nullptr) {
        payload = exact_workload->circuit;
        inputs = exact_workload->inputs;
        // Put the 3766-copy coherent noise stress inside the actual proof.
        // It preserves one exact target dependency cone and all eight CTCT
        // stages; it does not stand in for 3766 distinct target products.
        const auto add = [&](WireId left, WireId right) {
            const auto output = payload.wire_count();
            payload.gates.push_back(Gate{GateOp::Add, left, right, 0});
            return output;
        };
        WireId term = payload.outputs.front(), output = kNoWire;
        for (std::size_t remaining = 3766; remaining != 0; remaining >>= 1U) {
            if ((remaining & 1U) != 0U)
                output = output == kNoWire ? term : add(output, term);
            if (remaining > 1U) term = add(term, term);
        }
        payload.outputs = {output};
        payload.validate();
        std::printf("full_proof_final_affine=3766_correlated_copies\n");
    }
    const auto circuit = compile(payload);
    const auto plain = synthesize_trace(payload, circuit, inputs);
    const auto schedule = derive_uniform_honest_base_proof_schedule(
        circuit, parameters.exact_data_primes, calibration, 3);
    CHECK(schedule.payload_model_accepts());
    CHECK(!schedule.base_proof_noise_assessment.has_value());
    for (std::size_t layer = 1; layer < circuit.layers.size(); ++layer)
        CHECK(schedule.evaluation_plan.proof_ingress_mult_depth_by_layer[layer] == 2);
    const auto public_setup = bind_uniform_honest_base_proof_schedule(
        make_direct_setup(payload, circuit), payload, circuit, schedule);
    std::printf("full_proof_phase=creating_context special_prime=%llu gates=%zu\n",
        static_cast<unsigned long long>(parameters.exact_special_prime), payload.gates.size());
    std::fflush(stdout);
    auto contexts = SealBackend::create(parameters);
    const auto server = make_evaluation_setup<SealBackend>(public_setup, contexts.eval);
    const auto client = make_client_setup<SealBackend>(public_setup, contexts.client);
    std::printf("full_proof_phase=encrypting_inputs\n"); std::fflush(stdout);
    auto started = reference::begin_base_request_resident_reference<SealBackend>(
        payload, circuit, client, inputs, nonce());
    auto natural_plan = schedule.evaluation_plan;
    natural_plan.proof_ingress_mult_depth_by_layer =
        natural_plan.trace.required_mult_depth_by_layer;
    std::printf("full_proof_phase=evaluating_natural_trace\n"); std::fflush(stdout);
    const auto natural_trace = evaluate_wide_fhe_trace_into<SealBackend>(
        contexts.eval, payload, circuit, started.request.encrypted_inputs, natural_plan,
        InMemoryTraceSink<SealBackend>{contexts.eval});
    const auto problem = make_problem(
        circuit, schedule.evaluation_plan, contexts.eval, natural_trace);
    const PayloadCheckpointReplayBudgets budgets{
        .max_live_scratch_bytes = std::uint64_t{1} << 32U,
        .max_resident_ciphertext_bytes = std::uint64_t{1} << 31U,
        .max_ciphertexts_per_chunk = 2,
        .max_recomputation_factor = {100, 1},
        .reserved_live_scratch_bytes = std::uint64_t{1} << 20U,
        .reserved_resident_bytes = std::uint64_t{3} << 29U};
    const auto replay_plan = plan_payload_checkpoint_replay(problem, budgets);
    TemporaryDirectory root;
    const auto replay_directory = root.make_child("fixed-ingress-replay");
    const FileTraceStoreOptions limits{
        .max_total_bytes = std::uint64_t{1} << 32U, .min_free_bytes = 1};
    auto options = role_proof_options(circuit, root, limits, "fixed-ingress-mul-");
    CHECK(options.multiplication_scratch.size() == depth);
    protocol::BaseServerCapacityComponents capacity;
    capacity.operational_reserve = {1, 1};
    capacity.preprocessed_keys = {1, 1};
    capacity.payload_replay_workspace = {0, std::uint64_t{1} << 29U};
    capacity.encrypted_input_request = {0, std::uint64_t{1} << 29U};
    capacity.encrypted_output_response = {0, std::uint64_t{1} << 29U};
    capacity.affine_reduction_workspace = {0, std::uint64_t{1} << 29U};
    capacity.multiplication_builder_workspace = {0, std::uint64_t{1} << 29U};
    capacity.multiplication_reduction_workspace = {0, std::uint64_t{1} << 29U};
    capacity.accumulated_proof = {0, std::uint64_t{1} << 29U};
    capacity.proof_encoding = {0, std::uint64_t{1} << 29U};
    capacity.transport_framing = {0, std::uint64_t{1} << 29U};
    const protocol::BaseServerCapacityCaps caps{
        .max_live_local_disk_bytes = std::uint64_t{1} << 34U,
        .max_resident_ram_bytes = std::uint64_t{1} << 34U};
    std::printf("full_proof_phase=evaluating_checkpoint_request\n"); std::fflush(stdout);
    auto evaluated = laminate::test::evaluate_base_request_with_schedule<SealBackend>(
        payload, circuit, server, started.request, schedule, problem, budgets, replay_plan,
        PayloadCheckpointReplayExecutionOptions{
            .directory = replay_directory, .min_free_bytes = 1,
            .max_checkpoint_metadata_bytes = exact_workload != nullptr ? (1U << 20U) : 4096U,
            .lifecycle = FileTraceSessionLifecycle::IrreversibleNoRetry},
        std::move(options), caps, capacity);
    constexpr auto domain = "test/base/fixed-three-limb/proof/v1";
    Transcript prover_transcript(domain);
    SealBackend::reset_counts(contexts.eval);
    SealBackend::set_counting(contexts.eval, true);
    std::printf("full_proof_phase=proving\n"); std::fflush(stdout);
    const auto proved = prove_base_response_irreversible<SealBackend>(
        payload, circuit, server, evaluated, prover_transcript);
    SealBackend::set_counting(contexts.eval, false);
    const auto counts = SealBackend::counts(contexts.eval);
    CHECK(counts.calls(SealBackend::OperationKind::MulNoRelin) > 0);
    CHECK(counts.calls(SealBackend::OperationKind::Relinearize) > 0);
    CHECK(counts.calls(SealBackend::OperationKind::Decrypt) == 0);
    int minimum_noise = std::numeric_limits<int>::max();
    std::size_t message_ciphertexts = 0;
    const auto inspect = [&](const ExtensionValue<SealBackend> &value) {
        for (const auto &coefficient : value) {
            if (!coefficient.is_encrypted()) continue;
            const auto &ciphertext = coefficient.ciphertext();
            CHECK(SealBackend::rns_limb_count(contexts.eval, ciphertext) == 1);
            minimum_noise = std::min(minimum_noise,
                SealBackend::invariant_noise_budget(contexts.client, ciphertext));
            ++message_ciphertexts;
        }
    };
    for (const auto &reduction : proved.response.proof.reductions) {
        std::visit([&](const auto &layer) {
            for (const auto &round : layer.rounds)
                for (const auto &value : round.evaluations) inspect(value);
            if constexpr (requires { layer.source_vector; })
                inspect(layer.source_vector);
            else
                for (const auto &value : layer.source_vectors) inspect(value);
        }, reduction);
    }
    CHECK(message_ciphertexts > 0);
    int output_noise = std::numeric_limits<int>::max();
    for (const auto &value : proved.response.output.values)
        if (value.is_encrypted())
            output_noise = std::min(output_noise,
                SealBackend::invariant_noise_budget(contexts.client, value.ciphertext()));
    std::printf("  fixed target chain: depth=%zu, 3-limb ingress, %zu one-limb proof ciphertexts, "
                "minimum observed proof/output noise budgets=%d/%d bits\n",
                depth, message_ciphertexts, minimum_noise, output_noise);
    CHECK(minimum_noise > 0);
    CHECK(output_noise > 0);
    std::printf("full_proof_phase=verifying\n"); std::fflush(stdout);
    Transcript verifier_transcript(domain);
    const auto recovered = reference::verify_base_response_resident_reference<SealBackend>(
        payload, circuit, client, std::move(started.state), proved.response, verifier_transcript);
    if (!recovered)
        std::fprintf(stderr, "  fixed-ingress verification failed: %s\n",
            base_detail::base_verifier_diagnostic().to_string().c_str());
    CHECK(recovered.has_value());
    CHECK(recovered->size() == payload.outputs.size());
    for (std::size_t output = 0; output < recovered->size(); ++output)
        CHECK((*recovered)[output] == plain.layers.front()[output]);
    CHECK(prover_transcript.challenge_fpk() == verifier_transcript.challenge_fpk());
    CHECK(proved.payload_replay_report.all_payload_artifacts_retired);
    CHECK(proved.payload_replay_report.live_physical_bytes == 0);
    for (const auto &scratch : evaluated.state.resources().proof_options().multiplication_scratch)
        CHECK(std::filesystem::is_empty(scratch.directory));
}

int probe_payload_noise(const Workload &workload, SealParameters parameters,
                        std::size_t ingress, bool stress_repeated_sum = false,
                        std::size_t expected_peak_stored = 0,
                        std::size_t repeated_sum_terms = 65536,
                        bool require_target_drop_sequence = false,
                        bool use_folded_target = false) {
    const auto degree = parameters.poly_modulus_degree;
    const auto calibration = diagnostic_target_calibration(parameters.fresh_rns_limbs == 11);
    const auto circuit = compile(workload.circuit);
    const auto storage = canonical_trace_storage_layout(circuit);
    std::size_t peak_stored = 0;
    for (const auto &layer : storage) peak_stored = std::max(peak_stored, layer.stored_wire_count);
    if (expected_peak_stored != 0 && peak_stored != expected_peak_stored)
        throw std::logic_error("target cone stored ciphertext geometry changed");
    if (peak_stored > 1024)
        throw std::invalid_argument("diagnostic payload exceeds 1024 stored ciphertexts per layer: " +
                                    std::to_string(peak_stored));
    const auto plain = synthesize_trace(workload.circuit, circuit, workload.inputs);
    HonestPayloadNoiseSchedule schedule;
    FheEvaluationPlan evaluation_plan;
    std::vector<std::size_t> folded_proof_source_limbs;
    if (use_folded_target) {
        const auto profile = bench::packed_process_profile(
            bench::PackedProcessVariant::Folded, bench::PackedProcessTier::TargetMulHeavy, 0);
        const auto proof = protocol::derive_conservative_packed_proof_ingress_schedule(
            protocol::PackingGkrVariant::Folded, workload.circuit, circuit,
            make_direct_setup(workload.circuit, circuit),
            bench::packed_process_proof_ingress_policy(profile));
        folded_proof_source_limbs.assign(proof.rns_limbs_by_layer().begin(),
                                         proof.rns_limbs_by_layer().end());
        std::vector<std::size_t> proof_depths;
        for (const auto limbs : proof.rns_limbs_by_layer()) proof_depths.push_back(limbs - 1U);
        evaluation_plan = bench::packed_process_evaluation_plan(profile, circuit, proof_depths);
        if (proof.policy() != protocol::kConservativePackedProofIngressPolicyV4 ||
            folded_proof_source_limbs != (std::vector<std::size_t>{
                1,4,6,4,6,4,6,4,6,4,6,4,6,4,6,4,6,4}) ||
            evaluation_plan.trace.required_mult_depth_by_layer !=
                (std::vector<std::size_t>{
                    0,3,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13}))
            throw std::logic_error("Folded cone differs from the production source levels");
    } else {
        schedule = derive_uniform_honest_base_proof_schedule(
            circuit, parameters.exact_data_primes, calibration, ingress);
        evaluation_plan = schedule.evaluation_plan;
    }
    if (require_target_drop_sequence) {
        if (circuit.layers.size() != 18 || parameters.fresh_rns_limbs != (use_folded_target ? 14U : 11U))
            throw std::logic_error("target-cone probe requires depth eight and the selected target chain");
        for (std::size_t layer = 0; layer < circuit.layers.size(); ++layer) {
            const auto expected = use_folded_target && layer <= 1 ? 3U :
                (layer < 17 && (layer % 2U) != 0U ? 1U : 0U);
            if (evaluation_plan.modulus_switches_after_layer[layer] != expected)
                throw std::logic_error("cone schedule differs from the complete target switch vector");
        }
    }
    std::printf("diagnostic_only=true width=%zu inputs=%zu gates=%zu peak_stored=%zu slots=%zu data_limbs=%zu "
                "ingress=%zu seed=1 model_accepts=%d\n", workload.spec.width,
                workload.circuit.input_count, workload.circuit.gates.size(), peak_stored, degree,
                parameters.fresh_rns_limbs, ingress, use_folded_target ? -1 : schedule.payload_model_accepts());
    std::fflush(stdout);
    auto contexts = SealBackend::create(parameters);
    if (use_folded_target) {
        auto expected_moduli = parameters.exact_data_primes;
        expected_moduli.push_back(parameters.exact_special_prime);
        if (SealBackend::coefficient_moduli(contexts.eval) != expected_moduli)
            throw std::logic_error("Folded cone differs from the exact production modulus chain");
    }
    auto encrypted = encrypt_wide_payload_inputs<SealBackend>(
        contexts.client, workload.circuit, workload.inputs);
    std::vector<FheValue<SealBackend>> working;
    for (auto &value : encrypted)
        working.push_back(FheValue<SealBackend>::from_ciphertext(std::move(value)));
    encrypted.clear();
    struct Observation { int minimum = std::numeric_limits<int>::max();
        std::size_t zero = 0, mismatches = 0, limbs = 0; };
    const auto measure = [&](std::size_t layer, bool compare_plaintext) {
        Observation result;
        for (std::size_t ordinal = 0; ordinal < working.size(); ++ordinal) {
            const auto &value = working[ordinal];
            const auto padded = storage[layer].representative_padded_index_of(ordinal);
            if (value.is_encrypted()) {
                const auto &ciphertext = value.ciphertext();
                result.limbs = SealBackend::rns_limb_count(contexts.eval, ciphertext);
                const auto budget = SealBackend::invariant_noise_budget(contexts.client, ciphertext);
                result.minimum = std::min(result.minimum, budget);
                result.zero += budget == 0;
                if (compare_plaintext)
                    result.mismatches += SealBackend::decrypt(contexts.client, ciphertext) !=
                                         plain.layers[layer][padded];
            } else if (compare_plaintext) {
                result.mismatches += value.plaintext().materialize(degree) !=
                                     plain.layers[layer][padded];
            }
        }
        return result;
    };
    const auto input = measure(circuit.layers.size() - 1U, true);
    std::printf("input minimum_noise=%d mismatches=%zu\n", input.minimum, input.mismatches);
    bool failed = input.mismatches != 0;
    for (std::size_t source = circuit.layers.size() - 1U; source > 0; --source) {
        const auto layer = source - 1U;
        working = fhe_evaluation_detail::evaluate_layer<
            SealBackend, fhe_evaluation_detail::WideLayout>(
                contexts.eval, circuit, layer, working, storage[source], storage[layer]);
        const auto before = measure(layer, true);
        for (std::size_t drop = 0; drop < evaluation_plan.modulus_switches_after_layer[layer]; ++drop)
            for (auto &value : working) value_mod_switch_to_next<SealBackend>(contexts.eval, value);
        const auto after = measure(layer, true);
        std::printf("layer=%zu kind=%s stored=%zu limbs=%zu->%zu min_noise=%d->%d "
                    "zero_noise=%zu->%zu mismatches=%zu->%zu",
            layer, layer_kind(circuit.layers[layer]) == LayerKind::Affine ? "affine" : "mul",
            working.size(), before.limbs, after.limbs, before.minimum, after.minimum,
            before.zero, after.zero, before.mismatches, after.mismatches);
        if (!use_folded_target) {
            const auto &modeled = schedule.layers_in_evaluation_order[circuit.layers.size() - 2U - layer];
            std::printf(" modeled_doubled_phase_bits=%zu->%zu",
                NaturalMagnitude::multiply(modeled.evaluated_phase_bound, 2U).bit_count(),
                NaturalMagnitude::multiply(modeled.output_phase_bound, 2U).bit_count());
        }
        std::printf("\n");
        std::fflush(stdout);
        failed |= before.mismatches != 0 || after.mismatches != 0 ||
                  before.zero != 0 || after.zero != 0;
        if (use_folded_target && layer == 1) {
            auto natural = working;
            const auto proof_limbs = folded_proof_source_limbs.at(layer);
            for (std::size_t drop = proof_limbs; drop < after.limbs; ++drop)
                for (auto &value : working) value_mod_switch_to_next<SealBackend>(contexts.eval, value);
            const auto proof_copy = measure(layer, true);
            std::printf("first_affine_proof_source limbs=%zu noise=%d zero=%zu mismatches=%zu\n",
                proof_copy.limbs, proof_copy.minimum, proof_copy.zero, proof_copy.mismatches);
            working = std::move(natural);
            failed |= proof_copy.limbs != proof_limbs || proof_copy.zero != 0 ||
                      proof_copy.mismatches != 0;
        }
    }
    if (stress_repeated_sum) {
        for (std::size_t ordinal = 0; ordinal < working.size(); ++ordinal) {
            auto stress = FheValue<SealBackend>::public_zero();
            auto term = working[ordinal];
            for (std::size_t remaining = repeated_sum_terms; remaining != 0; remaining >>= 1U) {
                if ((remaining & 1U) != 0U)
                    stress = value_add<SealBackend>(contexts.eval, stress, term);
                if (remaining > 1U)
                    term = value_add<SealBackend>(contexts.eval, term, term);
            }
            auto expected = plain.layers.front()[storage.front().representative_padded_index_of(ordinal)];
            for (auto &value : expected) value *= Fp(repeated_sum_terms);
            const auto budget = SealBackend::invariant_noise_budget(contexts.client, stress.ciphertext());
            const bool matches = SealBackend::decrypt(contexts.client, stress.ciphertext()) == expected;
            std::printf("coherent_sum_stress output=%zu repeated_terms=%zu noise=%d plaintext_matches=%d\n",
                        ordinal, repeated_sum_terms, budget, matches);
            failed |= budget == 0 || !matches;
        }
    }
    return failed ? 2 : 0;
}

int probe_balanced_payload_noise(std::size_t width, std::size_t input_count,
                                std::size_t ingress, std::uint64_t added_top_prime) {
    if (width < 64 || width > 256 || input_count < 8 || input_count > 64)
        throw std::invalid_argument("balanced noise probe requires width64..256 and inputs8..64");
    WorkloadSpec spec{WorkloadKind::BalancedLaned, PayloadShape::wide(16384), 8, width, 1};
    spec.input_count = input_count;
    spec.operation_count = 16U * width;
    spec.multiplication_widths.assign(8, width);
    return probe_payload_noise(make_workload(spec), diagnostic_target_chain(added_top_prime), ingress);
}

Workload make_target_balanced_noise_cones() {
    const auto spec = bench::benchmark_payload_workload_spec(
        bench::benchmark_payload_profile("target-balancedLaned"), PayloadShape::wide(16384), 1);
    const auto target = make_payload_circuit(spec);
    // Use a fixed target wire and its complete dependency cone. Selection
    // is independent of platform floating-point behavior.
    constexpr WireId root = 921483;
    if (root < target.input_count || root >= target.wire_count() ||
        target.gates[root - target.input_count].op != GateOp::Mul)
        throw std::logic_error("target cone root is no longer a multiplication");
    std::vector<bool> retained(target.wire_count());
    std::vector<WireId> pending{root};
    std::size_t retained_count = 0;
    while (!pending.empty()) {
        const auto wire = pending.back(); pending.pop_back();
        if (wire < target.input_count || retained[wire]) continue;
        retained[wire] = true;
        if (++retained_count > 3153)
            throw std::logic_error("target cone exceeds its retained gate count");
        const auto &gate = target.gates[wire - target.input_count];
        pending.push_back(gate.left);
        if (gate.right != kNoWire) pending.push_back(gate.right);
    }
    PayloadCircuit payload{.shape = target.shape, .input_count = target.input_count,
                           .plaintexts = target.plaintexts};
    std::vector<WireId> remap(target.wire_count(), kNoWire);
    std::vector<std::size_t> depths(target.wire_count());
    for (std::size_t input = 0; input < target.input_count; ++input) remap[input] = input;
    std::size_t multiplication_count = 0;
    for (std::size_t index = 0; index < target.gates.size(); ++index) {
        const auto wire = target.input_count + index;
        if (!retained[wire]) continue;
        auto gate = target.gates[index];
        if (gate.op == GateOp::AddPlain) {
            depths[wire] = depths[gate.left];
        } else if (gate.op == GateOp::Add || gate.op == GateOp::Mul) {
            depths[wire] = std::max(depths[gate.left], depths[gate.right]) +
                           (gate.op == GateOp::Mul);
        } else {
            throw std::logic_error("target cone encountered an unexpected operator");
        }
        gate.left = remap[gate.left];
        if (gate.right != kNoWire) gate.right = remap[gate.right];
        remap[wire] = payload.input_count + payload.gates.size();
        payload.gates.push_back(gate);
        multiplication_count += gate.op == GateOp::Mul;
    }
    if (payload.gates.size() != 3153 || multiplication_count != 755 || depths[root] != 8)
        throw std::logic_error("target cone gate counts or multiplicative depth changed");
    payload.outputs.push_back(remap[root]);
    payload.validate();
    std::printf("selected_target_product=%zu target_cones_total_gates=%zu "
                "target_cones_ctct_gates=%zu outputs=%zu\n",
                root, payload.gates.size(), multiplication_count, payload.outputs.size());
    std::fflush(stdout);
    return {spec, std::move(payload), make_workload_inputs(spec)};
}

// Preserve the exact target's input values, public masks, grid rotations,
// and every ancestor of one final product. This is an opt-in diagnostic,
// not a replacement for the complete target's final sum and proof.
Workload make_target_pyramid_noise_cone(WireId root) {
    const auto spec = bench::benchmark_payload_workload_spec(
        bench::benchmark_payload_profile("target-mulHeavyPyramid"),
        PayloadShape::wide(16384), 1);
    const auto target = make_payload_circuit(spec);
    std::vector<WireId> final_products, pending = target.outputs;
    while (!pending.empty()) {
        const auto wire = pending.back(); pending.pop_back();
        const auto &gate = target.gates.at(wire - target.input_count);
        if (gate.op == GateOp::Add) {
            pending.push_back(gate.left); pending.push_back(gate.right);
        } else if (gate.op == GateOp::Mul) {
            final_products.push_back(wire);
        } else {
            throw std::logic_error("target pyramid final affine layer is no longer a product sum");
        }
    }
    if (final_products.size() != 3766 ||
        std::find(final_products.begin(), final_products.end(), root) == final_products.end())
        throw std::invalid_argument("pyramid cone root must be one of the 3766 final products");
    std::vector<bool> retained(target.wire_count());
    pending = {root};
    std::size_t retained_count = 0;
    while (!pending.empty()) {
        const auto wire = pending.back(); pending.pop_back();
        if (wire < target.input_count || retained[wire]) continue;
        retained[wire] = true;
        if (++retained_count > 4096)
            throw std::invalid_argument("pyramid cone exceeds 4096 retained gates");
        const auto &gate = target.gates[wire - target.input_count];
        pending.push_back(gate.left);
        if (gate.right != kNoWire) pending.push_back(gate.right);
    }
    PayloadCircuit payload{.shape = target.shape, .input_count = target.input_count,
                           .plaintexts = target.plaintexts};
    std::vector<WireId> remap(target.wire_count(), kNoWire);
    for (std::size_t input = 0; input < target.input_count; ++input) remap[input] = input;
    std::array<std::size_t, 5> operations{};
    for (std::size_t index = 0; index < target.gates.size(); ++index) {
        const auto wire = target.input_count + index;
        if (!retained[wire]) continue;
        auto gate = target.gates[index];
        ++operations[static_cast<std::size_t>(gate.op)];
        gate.left = remap[gate.left];
        if (gate.right != kNoWire) gate.right = remap[gate.right];
        remap[wire] = payload.input_count + payload.gates.size();
        payload.gates.push_back(gate);
    }
    payload.outputs = {remap[root]};
    payload.validate();
    std::printf("selected_target_product=%zu target_cone_gates=%zu add=%zu mul=%zu masks=%zu "
                "rotations=%zu final_target_affine=3766_product_sum\n", root,
                payload.gates.size(), operations[0], operations[2], operations[3], operations[4]);
    std::fflush(stdout);
    return {spec, std::move(payload), make_workload_inputs(spec)};
}

} // namespace

int main(int argc, char **argv) {
    if (argc == 2 && std::string_view(argv[1]) == "--target-pyramid-production-proof") {
        const auto workload = make_target_pyramid_noise_cone(WireId{1042862});
        const auto parameters = production_pyramid_chain();
        test::Runner runner("Production target pyramid dependency-cone proof");
        runner.run("file-backed Base response verifies", [&] {
            check_fixed_three_limb_file_backed_proof(true, &workload, &parameters);
        });
        return runner.summary();
    }
    if ((argc >= 2 && argc <= 5) && std::string_view(argv[1]) == "--target-pyramid-proof") {
        const auto workload = make_target_pyramid_noise_cone(
            argc >= 3 ? std::stoull(argv[2]) : WireId{1041858});
        const auto parameters = diagnostic_pyramid_chain(
            argc >= 4 ? std::stoull(argv[3]) : 0,
            argc == 5 ? diagnostic_head_bits(argv[4]) : 0);
        test::Runner runner("Exact target pyramid dependency-cone proof");
        runner.run("file-backed Base response verifies", [&] {
            check_fixed_three_limb_file_backed_proof(true, &workload, &parameters);
        });
        return runner.summary();
    }
    if ((argc == 2 || argc == 3) && std::string_view(argv[1]) == "--target-folded-pyramid-cone") {
        const auto profile = bench::packed_process_profile(
            bench::PackedProcessVariant::Folded, bench::PackedProcessTier::TargetMulHeavy, 0);
        SealParameters parameters{
            .poly_modulus_degree = profile.slots,
            .fresh_rns_limbs = profile.fresh_rns_limbs(),
            .data_prime_bit_sizes = {},
            .exact_data_primes = profile.exact_data_primes,
            .exact_special_prime = profile.exact_special_prime,
            .special_prime_bits = profile.special_prime_bits,
            .security_level = seal::sec_level_type::none,
            .generate_galois_keys = true};
        return probe_payload_noise(make_target_pyramid_noise_cone(
            argc == 3 ? std::stoull(argv[2]) : WireId{1041858}), parameters,
            4, false, 0, 3766, true, true);
    }
    if ((argc >= 2 && argc <= 5) && std::string_view(argv[1]) == "--target-pyramid-cone") {
        auto parameters = diagnostic_pyramid_chain(
            argc >= 4 ? std::stoull(argv[3]) : 0,
            argc == 5 ? diagnostic_head_bits(argv[4]) : 0);
        parameters.generate_galois_keys = true;
        std::printf("diagnostic_data_primes=");
        for (const auto prime : parameters.exact_data_primes)
            std::printf("%llu,", static_cast<unsigned long long>(prime));
        std::printf(" special_prime=%llu\n",
                    static_cast<unsigned long long>(parameters.exact_special_prime));
        return probe_payload_noise(make_target_pyramid_noise_cone(
            argc >= 3 ? std::stoull(argv[2]) : WireId{1041858}), parameters,
            3, true, 0, 3766, true);
    }
    if ((argc == 5 || argc == 6) && std::string_view(argv[1]) == "--balanced-noise-probe")
        return probe_balanced_payload_noise(std::stoull(argv[2]), std::stoull(argv[3]),
            std::stoull(argv[4]), argc == 6 ? std::stoull(argv[5]) : 0);
    if ((argc == 2 || argc == 3) && std::string_view(argv[1]) == "--target-balanced-cones")
        return probe_payload_noise(make_target_balanced_noise_cones(),
            diagnostic_target_chain(argc == 3 ? std::stoull(argv[2]) : 0), 3, true, 974);
    if (argc != 1) {
        std::fprintf(stderr, "unrecognized diagnostic option or argument count\n");
        return 2;
    }
    test::Runner runner("Base file-backed full proof with SEAL");
    runner.run("output noise budget over a fixed diagnostic chain",
               measure_output_noise_budget_over_depth);
    runner.run("fixed three-limb target ingress verifies a bounded full proof",
               [] { check_fixed_three_limb_file_backed_proof(); });
    runner.run("fixed three-limb target ingress verifies depth-eight branches and a final sum",
               [] { check_fixed_three_limb_file_backed_proof(true); });
    runner.run("revised target chain decrypts the actual balanced generator at bounded width",
               [] { CHECK(probe_balanced_payload_noise(64, 64, 3, 1'095'233'372'161ULL) == 0); });
    runner.run("padded compact Wide proof verifies over real BGV", [] {
        PayloadBuilder builder(PayloadShape::wide(kSlots), 3);
        const std::size_t diagonal = builder.add_plaintext(values(11));
        const WireId product = builder.mul(0, 1);
        const WireId scaled = builder.mul_plain(2, diagonal);
        builder.set_outputs({builder.add(product, scaled)});
        const PayloadCircuit payload = builder.finish();
        const LayeredCircuit circuit = compile(payload);
        const std::vector<SlotVector> inputs{
            values(3), values(47), values(101)};
        const PlainTrace plain = synthesize_trace(payload, circuit, inputs);
        auto contexts = SealBackend::create(SealParameters{
            .poly_modulus_degree = kSlots,
            .fresh_rns_limbs = 10,
            .bits_per_data_prime = 40,
            .special_prime_bits = 40,
            .security_level = seal::sec_level_type::none,
        });
        const auto encrypted_inputs =
            encrypt_wide_payload_inputs<SealBackend>(
                contexts.client, payload, inputs);
        const PublicSetup public_setup = make_direct_setup(payload, circuit);
        const auto setup = make_evaluation_setup<SealBackend>(
            public_setup, contexts.eval);
        const auto client = make_client_setup<SealBackend>(
            public_setup, contexts.client);

        TemporaryDirectory root;
        const std::filesystem::path trace_directory =
            root.make_child("trace");
        const FileTraceStoreOptions limits{
            .max_total_bytes = std::uint64_t{1} << 32U,
            .min_free_bytes = 1,
        };
        const FileTraceStoreWriteResult written =
            evaluate_wide_fhe_trace_into<SealBackend>(
                contexts.eval, payload, circuit, encrypted_inputs,
                FheEvaluationPlan::without_payload_switches(circuit, 7),
                FileEncryptedTraceSink<SealBackend>(
                    contexts.eval, trace_directory, limits));
        const auto trace = FileEncryptedTraceStore<SealBackend>::open(
            contexts.eval, trace_directory, payload, circuit,
            TraceProvenance::FheEvaluated,
            written.descriptor.trace_id);
        CHECK(trace.layer_support(circuit.layers.size() - 1U)
                  .live_wire_count == 3);
        CHECK(trace.layer_support(circuit.layers.size() - 1U)
                  .padded_wire_count == 4);

        base_detail::FileEncryptedBaseGkrOptions options;
        std::vector<std::filesystem::path> scratch;
        for (std::size_t layer = 0; layer + 1U < circuit.layers.size();
             ++layer) {
            if (layer_kind(circuit.layers[layer]) !=
                LayerKind::Multiplication) {
                continue;
            }
            const std::filesystem::path directory = root.make_child(
                "multiplication-" + std::to_string(layer));
            scratch.push_back(directory);
            options.multiplication_scratch.push_back(
                base_detail::FileBaseMultiplicationScratch{
                    layer, directory, limits});
        }

        Transcript output_coin(
            "test/base/prover-file-backed-seal/output/v1");
        const SingleClaim claim = make_layer_claim(
            plain.layers.front(), output_coin.challenge_vector(
                base_detail::layer_vars(circuit, 0)));
        const std::string domain =
            "test/base/prover-file-backed-seal/v1";
        Transcript prover_transcript(domain);
        const auto proved =
            base_detail::prove_base_gkr_for_testing<SealBackend>(
                payload, circuit, trace, setup, claim.point,
                prover_transcript, std::move(options));
        Transcript verifier_transcript(domain);
        CHECK(base_detail::verify_base_gkr_reference<SealBackend>(
            payload, circuit, plain.layers.back(), client,
            TraceProvenance::FheEvaluated,
            written.descriptor.trace_id, claim, proved.proof,
            verifier_transcript));
        for (const auto &directory : scratch) {
            CHECK(std::filesystem::is_empty(directory));
        }
    });
    runner.run("role-separated checkpoint replay verifies over real BGV",
               [] {
        PayloadBuilder builder(PayloadShape::wide(kSlots), 3);
        const std::size_t diagonal = builder.add_plaintext(values(17));
        const std::size_t zero =
            builder.add_scalar_plaintext(Fp::zero());
        const std::size_t constant =
            builder.add_scalar_plaintext(Fp(29));
        const WireId product = builder.mul(0, 1);
        const WireId scaled = builder.mul_plain(2, diagonal);
        const WireId public_zero = builder.mul_plain(0, zero);
        const WireId public_constant =
            builder.add_plain(public_zero, constant);
        builder.set_outputs(
            {builder.add(product, scaled), public_zero, public_constant});
        const PayloadCircuit payload = builder.finish();
        const LayeredCircuit circuit = compile(payload);
        const std::vector<SlotVector> inputs{
            values(5), values(59), values(127)};
        const PlainTrace plain = synthesize_trace(payload, circuit, inputs);
        const auto support = canonical_trace_wire_support(circuit);
        CHECK(std::any_of(support.begin(), support.end(), [](const auto &s) {
            return s.live_wire_count < s.padded_wire_count;
        }));
        const auto storage = canonical_trace_storage_layout(circuit);
        bool has_shared_records = false;
        for (std::size_t layer = 0; layer < storage.size(); ++layer)
            has_shared_records |= storage[layer].stored_wire_count <
                                  support[layer].live_wire_count;
        CHECK(has_shared_records);

        auto contexts = SealBackend::create(SealParameters{
            .poly_modulus_degree = kSlots,
            .fresh_rns_limbs = 10,
            .bits_per_data_prime = 40,
            .special_prime_bits = 40,
            .security_level = seal::sec_level_type::none,
        });
        std::vector<std::uint64_t> data_moduli =
            SealBackend::coefficient_moduli(contexts.eval);
        CHECK(data_moduli.size() == 11);
        data_moduli.pop_back();
        const HonestPayloadNoiseSchedule schedule =
            select_minimal_honest_base_proof_ingress(
                circuit, data_moduli, honest_payload_calibration(),
                honest_base_proof_calibration());
        CHECK(schedule.payload_model_accepts());
        CHECK(schedule.base_proof_noise_assessment.has_value());
        const PublicSetup unbound_public_setup =
            make_direct_setup(payload, circuit);
        const auto proof_parameters =
            derive_honest_base_proof_noise_parameters(
                circuit, schedule, honest_base_proof_calibration());
        const PublicSetup public_setup =
            bind_honest_base_proof_noise_assessment(
                unbound_public_setup, payload, circuit, schedule,
                proof_parameters);
        const auto server = make_evaluation_setup<SealBackend>(
            public_setup, contexts.eval);
        const auto client = make_client_setup<SealBackend>(
            public_setup, contexts.client);
        BaseClientRequestStart<SealBackend> started =
            reference::begin_base_request_resident_reference<SealBackend>(
                payload, circuit, client, inputs, nonce());
        const FheEvaluationPlan &evaluation = schedule.evaluation_plan;
        FheEvaluationPlan natural_level_calibration = evaluation;
        natural_level_calibration.proof_ingress_mult_depth_by_layer =
            natural_level_calibration.trace.required_mult_depth_by_layer;
        const EncryptedTrace<SealBackend> calibration =
            evaluate_wide_fhe_trace_into<SealBackend>(
                contexts.eval, payload, circuit,
                started.request.encrypted_inputs,
                natural_level_calibration,
                InMemoryTraceSink<SealBackend>{
                    contexts.eval});
        const PayloadCheckpointReplayProblem problem = make_problem(
            circuit, evaluation, contexts.eval, calibration);
        const PayloadCheckpointReplayBudgets budgets{
            .max_live_scratch_bytes = std::uint64_t{1} << 32U,
            .max_resident_ciphertext_bytes = std::uint64_t{1} << 31U,
            .max_ciphertexts_per_chunk = 2,
            .max_recomputation_factor = {100, 1},
            .reserved_live_scratch_bytes = std::uint64_t{1} << 20U,
            .reserved_resident_bytes = std::uint64_t{3} << 29U,
        };
        const PayloadCheckpointReplayPlan replay_plan =
            plan_payload_checkpoint_replay(problem, budgets);

        TemporaryDirectory root;
        const std::filesystem::path replay_directory =
            root.make_child("role-replay");
        const FileTraceStoreOptions limits{
            .max_total_bytes = std::uint64_t{1} << 32U,
            .min_free_bytes = 1,
        };
        protocol::BaseProverOptions proof_options =
            role_proof_options(circuit, root, limits, "role-scratch-");
        protocol::BaseServerCapacityComponents capacity;
        capacity.operational_reserve = {1, 1};
        capacity.preprocessed_keys = {1, 1};
        capacity.payload_replay_workspace = {
            0, std::uint64_t{1} << 29U};
        capacity.encrypted_input_request = {
            0, std::uint64_t{1} << 29U};
        capacity.encrypted_output_response = {
            0, std::uint64_t{1} << 29U};
        capacity.affine_reduction_workspace = {
            0, std::uint64_t{1} << 29U};
        capacity.multiplication_builder_workspace = {
            0, std::uint64_t{1} << 29U};
        capacity.multiplication_reduction_workspace = {
            0, std::uint64_t{1} << 29U};
        capacity.accumulated_proof = {
            0, std::uint64_t{1} << 29U};
        capacity.proof_encoding = {
            0, std::uint64_t{1} << 29U};
        capacity.transport_framing = {
            0, std::uint64_t{1} << 29U};
        const protocol::BaseServerCapacityCaps caps{
            .max_live_local_disk_bytes = std::uint64_t{1} << 34U,
            .max_resident_ram_bytes = std::uint64_t{1} << 34U,
        };

        HonestPayloadNoiseSchedule payload_only_schedule = schedule;
        payload_only_schedule.base_proof_noise_assessment.reset();
        const PublicSetup payload_only_setup =
            bind_honest_payload_noise_schedule(
                make_direct_setup(payload, circuit), payload, circuit,
                payload_only_schedule);
        const auto payload_only_server =
            make_evaluation_setup<SealBackend>(payload_only_setup,
                                               contexts.eval);
        const auto payload_only_client =
            make_client_setup<SealBackend>(payload_only_setup,
                                           contexts.client);
        const BaseClientRequestStart<SealBackend> payload_only_started =
            reference::begin_base_request_resident_reference<SealBackend>(
                payload, circuit, payload_only_client, inputs, nonce());
        TemporaryDirectory payload_only_root;
        const std::filesystem::path payload_only_replay =
            payload_only_root.make_child("role-replay");
        SealBackend::reset_counts(contexts.eval);
        SealBackend::set_counting(contexts.eval, true);
        CHECK(throws_invalid_argument([&] {
            (void)laminate::test::evaluate_base_request_with_schedule<SealBackend>(
                payload, circuit, payload_only_server,
                payload_only_started.request, payload_only_schedule,
                problem, budgets, replay_plan,
                PayloadCheckpointReplayExecutionOptions{
                    .directory = payload_only_replay,
                    .min_free_bytes = 1,
                    .max_checkpoint_metadata_bytes = 4096,
                    .lifecycle =
                        FileTraceSessionLifecycle::IrreversibleNoRetry},
                role_proof_options(circuit, payload_only_root, limits,
                                   "role-scratch-"),
                caps, capacity);
        }));
        SealBackend::set_counting(contexts.eval, false);
        CHECK(no_seal_fhe_work(SealBackend::counts(contexts.eval)));
        CHECK(std::filesystem::is_empty(payload_only_replay));

        const auto unbound_server = make_evaluation_setup<SealBackend>(
            unbound_public_setup, contexts.eval);
        TemporaryDirectory unbound_root;
        const std::filesystem::path unbound_replay =
            unbound_root.make_child("role-replay");
        SealBackend::reset_counts(contexts.eval);
        SealBackend::set_counting(contexts.eval, true);
        CHECK(throws_invalid_argument([&] {
            (void)laminate::test::evaluate_base_request_with_schedule<SealBackend>(
                payload, circuit, unbound_server, started.request, schedule,
                problem, budgets, replay_plan,
                PayloadCheckpointReplayExecutionOptions{
                    .directory = unbound_replay,
                    .min_free_bytes = 1,
                    .max_checkpoint_metadata_bytes = 4096,
                    .lifecycle =
                        FileTraceSessionLifecycle::IrreversibleNoRetry},
                role_proof_options(circuit, unbound_root, limits,
                                   "role-scratch-"),
                caps, capacity);
        }));
        SealBackend::set_counting(contexts.eval, false);
        CHECK(no_seal_fhe_work(SealBackend::counts(contexts.eval)));
        CHECK(std::filesystem::is_empty(unbound_replay));

        std::vector<std::uint64_t> mismatched_chain = data_moduli;
        std::swap(mismatched_chain[mismatched_chain.size() - 1U],
                  mismatched_chain[mismatched_chain.size() - 2U]);
        const HonestPayloadNoiseSchedule mismatched_schedule =
            select_minimal_honest_base_proof_ingress(
                circuit, mismatched_chain, honest_payload_calibration(),
                honest_base_proof_calibration());
        CHECK(mismatched_schedule.payload_model_accepts());
        const PublicSetup mismatched_public_setup =
            bind_honest_base_proof_noise_assessment(
                make_direct_setup(payload, circuit), payload, circuit,
                mismatched_schedule,
                derive_honest_base_proof_noise_parameters(
                    circuit, mismatched_schedule,
                    honest_base_proof_calibration()));
        const auto mismatched_server = make_evaluation_setup<SealBackend>(
            mismatched_public_setup, contexts.eval);
        const auto mismatched_client = make_client_setup<SealBackend>(
            mismatched_public_setup, contexts.client);
        const BaseClientRequestStart<SealBackend> mismatched_started =
            reference::begin_base_request_resident_reference<SealBackend>(
                payload, circuit, mismatched_client, inputs, nonce());
        TemporaryDirectory mismatch_root;
        const std::filesystem::path mismatch_replay =
            mismatch_root.make_child("role-replay");
        SealBackend::reset_counts(contexts.eval);
        SealBackend::set_counting(contexts.eval, true);
        CHECK(throws_invalid_argument([&] {
            (void)laminate::test::evaluate_base_request_with_schedule<SealBackend>(
                payload, circuit, mismatched_server,
                mismatched_started.request, mismatched_schedule, problem,
                budgets, replay_plan,
                PayloadCheckpointReplayExecutionOptions{
                    .directory = mismatch_replay,
                    .min_free_bytes = 1,
                    .max_checkpoint_metadata_bytes = 4096,
                    .lifecycle =
                        FileTraceSessionLifecycle::IrreversibleNoRetry},
                role_proof_options(circuit, mismatch_root, limits,
                                   "role-scratch-"),
                caps, capacity);
        }));
        SealBackend::set_counting(contexts.eval, false);
        CHECK(no_seal_fhe_work(SealBackend::counts(contexts.eval)));
        CHECK(std::filesystem::is_empty(mismatch_replay));

        SealBackend::reset_counts(contexts.eval);
        SealBackend::set_counting(contexts.eval, true);
        auto evaluated =
            laminate::test::evaluate_base_request_with_schedule<SealBackend>(
                payload, circuit, server, started.request, schedule,
                problem, budgets, replay_plan,
                PayloadCheckpointReplayExecutionOptions{
                    .directory = replay_directory,
                    .min_free_bytes = 1,
                    .max_checkpoint_metadata_bytes = 4096,
                    .lifecycle =
                        FileTraceSessionLifecycle::IrreversibleNoRetry},
                std::move(proof_options), caps, capacity);
        SealBackend::set_counting(contexts.eval, false);
        const auto evaluation_counts = SealBackend::counts(contexts.eval);
        CHECK(evaluation_counts.calls(
                  SealBackend::OperationKind::Encrypt) == 0);
        CHECK(evaluation_counts.calls(SealBackend::OperationKind::Sub) == 0);

        Transcript prover_transcript(
            "test/base/checkpoint-delegation-seal/v1");
        const auto proved =
            prove_base_response_irreversible<
                SealBackend>(payload, circuit, server, evaluated,
                             prover_transcript);
        CHECK(SealBackend::counts(contexts.eval).calls(
                  SealBackend::OperationKind::Encrypt) == 0);
        CHECK(proved.payload_replay_report.all_payload_artifacts_retired);
        CHECK(proved.payload_replay_report.live_physical_bytes == 0);

        Transcript verifier_transcript(
            "test/base/checkpoint-delegation-seal/v1");
        const auto outputs =
            reference::verify_base_response_resident_reference<SealBackend>(
                payload, circuit, client, std::move(started.state),
                proved.response, verifier_transcript);
        CHECK(outputs.has_value());
        CHECK(outputs->size() == 3);
        for (std::size_t output = 0; output < outputs->size(); ++output) {
            CHECK((*outputs)[output] == plain.layers.front()[output]);
        }
        for (const auto &scratch :
             evaluated.state.resources()
                 .proof_options()
                 .multiplication_scratch) {
            CHECK(std::filesystem::is_empty(scratch.directory));
        }
    });
    return runner.summary();
}
