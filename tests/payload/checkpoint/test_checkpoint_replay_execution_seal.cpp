/// @file test_checkpoint_replay_execution_seal.cpp
/// @brief Real-BGV smoke test for sparse checkpoint replay and Laned GKR.

#include "test_helpers.hpp"
#include "no_integrity_target_noise.hpp"

#include "laminate/bench/no_integrity_parameters.hpp"
#include "laminate/fhe/seal_backend.hpp"
#include "laminate/gkr/detail/laned/prover.hpp"
#include "laminate/gkr/detail/laned/verifier.hpp"
#include "laminate/payload/checkpoint/session_engine.hpp"
#include "laminate/payload/compiler.hpp"
#include "laminate/payload/laned_fhe_evaluator.hpp"
#include "laminate/payload/input_encryption.hpp"
#include "laminate/payload/trace.hpp"
#include "laminate/payload/wide_fhe_evaluator.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace {

using namespace laminate;
using namespace laminate::fhe;
using namespace laminate::gkr;
using namespace laminate::payload;

constexpr std::size_t kSlots = 1024;
constexpr std::size_t kLanes = 8;
constexpr std::size_t kTargetSlots = std::size_t{1} << 14U;

class TemporaryDirectory {
  public:
    TemporaryDirectory() {
        const auto stamp = std::chrono::steady_clock::now()
                               .time_since_epoch()
                               .count();
        for (std::size_t attempt = 0; attempt < 100; ++attempt) {
            path_ = std::filesystem::temp_directory_path() /
                    ("laminate-checkpoint-replay-seal-" +
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

SlotVector lanes(std::uint64_t seed) {
    SlotVector result;
    result.reserve(kLanes);
    for (std::size_t lane = 0; lane < kLanes; ++lane) {
        result.emplace_back(seed + 3U * lane + lane * lane);
    }
    return result;
}
SlotVector wide_values(std::uint64_t seed) {
    SlotVector result;
    result.reserve(kSlots);
    for (std::size_t slot = 0; slot < kSlots; ++slot) {
        result.emplace_back(seed + 5U * slot + slot * slot);
    }
    return result;
}

PayloadCircuit mixed_payload() {
    PayloadBuilder builder(PayloadShape::laned(kLanes, kSlots), 1);
    const std::size_t weight = builder.add_scalar_plaintext(Fp(3));
    const std::size_t bias = builder.add_plaintext(
        {Fp(1), Fp(4), Fp(9), Fp(16), Fp(25), Fp(36), Fp(49), Fp(64)});
    const WireId weighted = builder.mul_plain(0, weight);
    const WireId squared = builder.mul(weighted, weighted);
    builder.set_outputs({builder.add_plain(squared, bias)});
    return builder.finish();
}

PayloadCircuit alias_heavy_multiplication_payload(
    std::size_t pair_count, std::size_t input_count = 2) {
    PayloadBuilder builder(PayloadShape::laned(kLanes, kSlots),
                           input_count);
    const std::size_t bias = builder.add_scalar_plaintext(Fp(7));
    std::vector<WireId> outputs;
    outputs.reserve(pair_count);
    for (std::size_t pair = 0; pair < pair_count; ++pair) {
        const WireId right = builder.add_plain(
            (pair + 1U) % input_count, bias);
        outputs.push_back(builder.mul(pair % input_count, right));
    }
    builder.set_outputs(std::move(outputs));
    return builder.finish();
}

PayloadCircuit strict_identity_affine_payload() {
    constexpr std::size_t kFirstWidth = 16;
    PayloadBuilder builder(
        PayloadShape::laned(kLanes, kSlots), 2U * kFirstWidth);
    std::vector<WireId> first;
    first.reserve(kFirstWidth);
    for (std::size_t gate = 0; gate < kFirstWidth; ++gate) {
        first.push_back(builder.mul(2U * gate, 2U * gate + 1U));
    }
    constexpr std::array<std::size_t, kFirstWidth> kPermutation{
        13, 0, 7, 10, 15, 4, 2, 9,
        6, 12, 1, 14, 8, 3, 11, 5};
    std::vector<WireId> upper;
    upper.reserve(kFirstWidth / 2U);
    for (std::size_t gate = 0; gate < kFirstWidth / 2U; ++gate) {
        upper.push_back(builder.mul(
            first[kPermutation[2U * gate]],
            first[kPermutation[2U * gate + 1U]]));
    }
    WireId output = upper.front();
    for (std::size_t gate = 1; gate < upper.size(); ++gate) {
        output = builder.add(output, upper[gate]);
    }
    builder.set_outputs({output});
    return builder.finish();
}

PayloadCircuit mixed_wide_payload() {
    PayloadBuilder builder(PayloadShape::wide(kSlots), 3);
    const std::size_t scalar = builder.add_scalar_plaintext(Fp(3));
    SlotVector mask(kSlots);
    SlotVector bias(kSlots);
    for (std::size_t slot = 0; slot < kSlots; ++slot) {
        mask[slot] = Fp(2 + slot % 251);
        bias[slot] = Fp(263 + 3 * slot);
    }
    const std::size_t mask_id = builder.add_plaintext(std::move(mask));
    const std::size_t bias_id = builder.add_plaintext(std::move(bias));
    const WireId rotated = builder.rotate(0, kSlots / 2 + 3);
    const WireId scaled = builder.mul_plain(rotated, scalar);
    const WireId shifted = builder.add_plain(1, bias_id);
    const WireId product = builder.mul(scaled, shifted);
    const WireId masked = builder.mul_plain(2, mask_id);
    const WireId mixed = builder.add(product, masked);
    const WireId second_product = builder.mul(mixed, product);
    const WireId fanin_three = builder.add(second_product, product);
    const WireId fanin_four = builder.add(fanin_three, masked);
    const WireId fanin_five = builder.add(fanin_four, rotated);
    builder.set_outputs({fanin_five,
                         builder.add_plain(second_product, bias_id),
                         builder.rotate(product, 5), masked});
    return builder.finish();
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

const FheValue<SealBackend> &first_encrypted_value(
    const std::vector<FheValue<SealBackend>> &values) {
    const auto encrypted = std::find_if(
        values.begin(), values.end(),
        [](const FheValue<SealBackend> &value) {
            return value.is_encrypted();
        });
    CHECK(encrypted != values.end());
    return *encrypted;
}

PayloadCheckpointReplayProblem make_problem(
    const LayeredCircuit &circuit, const FheEvaluationPlan &evaluation,
    const SealBackend::EvalContext &eval,
    const EncryptedTrace<SealBackend> &resident) {
    const std::vector<std::uint64_t> work =
        payload_replay_work_units(circuit);
    const CanonicalTraceLayout trace_layout =
        canonical_trace_layout(circuit);
    std::vector<PayloadLayerResourceEstimate> resources;
    resources.reserve(circuit.layers.size());
    for (std::size_t layer = 0; layer < circuit.layers.size(); ++layer) {
        const auto &wires = resident.layers[layer].wires;
        const LayerTraceValueCounts &counts =
            trace_layout.value_counts[layer];
        CHECK(wires.size() == counts.stored_values);
        CHECK(!wires.empty());
        const FheValue<SealBackend> &representative =
            first_encrypted_value(wires);
        const std::size_t limbs =
            SealBackend::rns_limb_count(eval,
                                        representative.ciphertext());
        std::uint64_t encoded = 0;
        std::uint64_t ingress_encoded = 0;
        std::size_t encrypted_values = 0;
        for (std::size_t stored = 0; stored < wires.size(); ++stored) {
            const FheValue<SealBackend> &value = wires[stored];
            const ClassifiedTraceValue &classification =
                trace_layout.stored_value_classifications[layer][stored];
            CHECK(value.is_public() == classification.has_value());
            if (classification) {
                CHECK(value.plaintext() == *classification);
            } else {
                ++encrypted_values;
            }
            encoded = std::max<std::uint64_t>(
                encoded,
                encode_fhe_value_record<SealBackend>(eval, value).size());
            FheValue<SealBackend> ingress_value = value;
            if (value.is_public()) {
                value.plaintext().validate_slot_count(
                    SealBackend::slot_count(eval),
                    "checkpoint replay SEAL resource fixture");
            } else {
                const SealBackend::Ciphertext &ciphertext =
                    value.ciphertext();
                CHECK(SealBackend::rns_limb_count(eval, ciphertext) ==
                      limbs);
                normalize_ciphertext_for_proof<
                    SealBackend>(
                    eval, ingress_value.ciphertext(),
                    evaluation
                        .proof_ingress_mult_depth_by_layer[layer]);
            }
            ingress_encoded = std::max<std::uint64_t>(
                ingress_encoded,
                encode_fhe_value_record<SealBackend>(eval, ingress_value)
                    .size());
        }
        CHECK(encrypted_values == counts.encrypted_ciphertexts);
        resources.push_back(PayloadLayerResourceEstimate{
            .rns_limb_count = limbs,
            .checkpoint_bytes = standalone_checkpoint_layer_artifact_bytes(
                counts.stored_values, encoded),
            .serialized_ciphertext_bytes = encoded,
            // A conservative deterministic bound for this smoke test. The
            // replay ledger intentionally excludes allocator/backend
            // temporaries from its controlled-residency counter.
            .resident_ciphertext_bytes = encoded + (std::uint64_t{1} << 20U),
            .replay_work_units = work[layer],
            .proof_ingress_serialized_ciphertext_bytes = ingress_encoded,
            .proof_ingress_resident_ciphertext_bytes =
                ingress_encoded + (std::uint64_t{1} << 20U),
        });
    }
    return make_payload_checkpoint_replay_problem(
        circuit, evaluation, resources, 512, 0);
}

std::uint64_t regular_file_bytes(const std::filesystem::path &root) {
    std::uint64_t result = 0;
    for (const auto &entry :
         std::filesystem::recursive_directory_iterator(root)) {
        if (entry.is_regular_file()) {
            result += entry.file_size();
        }
    }
    return result;
}

} // namespace

int main(int argc, char **argv) {
    test::Runner runner("payload checkpoint replay execution with SEAL");
    if (argc == 3 && std::string_view(argv[1]) ==
                         "--no-integrity-target-noise") {
        runner.run("payload-only target dependency cone", [&] {
            test::check_no_integrity_target_noise(argv[2]);
        });
        return runner.summary();
    }
    if (argc != 1) {
        std::cerr << "usage: " << argv[0]
                  << " [--no-integrity-target-noise PROFILE]\n";
        return 1;
    }
    runner.run("quick payload-only chain and noise acceptance", [] {
        const auto selected = bench::benchmark_payload_profile("quick");
        const auto parameters = bench::no_integrity_seal_parameters(selected);
        const auto &data_primes = parameters.exact_data_primes;
        auto contexts = SealBackend::create(parameters);
        std::vector<std::uint64_t> key_moduli =
            SealBackend::coefficient_moduli(contexts.eval);
        CHECK(key_moduli.back() == parameters.exact_special_prime);
        key_moduli.pop_back();
        CHECK(key_moduli == data_primes);
        CHECK(SealBackend::fresh_ciphertext_modulus_bits(contexts.eval) ==
              bench::no_integrity_data_modulus_bits(parameters));
        CHECK(SealBackend::key_modulus_bits(contexts.eval) ==
              bench::no_integrity_key_modulus_bits(parameters));
        CHECK(SealBackend::fresh_ciphertext_modulus_bits(contexts.eval) == 271U);
        CHECK(SealBackend::key_modulus_bits(contexts.eval) == 304U);
        CHECK(data_primes.front() != kOuterFieldOrder);
        CHECK(std::bit_width(data_primes.front()) == 54U);
        CHECK(data_primes.front() % kBaseFieldOrder == 1U);
        const auto restored_eval =
            SealBackend::deserialize_evaluation_context_bundle(
                SealBackend::serialize_evaluation_context_bundle(
                    contexts.eval));
        const auto restored_client =
            SealBackend::deserialize_client_context_bundle(
                SealBackend::serialize_client_context_bundle(
                    contexts.client));
        CHECK(restored_eval.parameters == contexts.eval.parameters);
        CHECK(restored_client.parameters == contexts.client.parameters);
        CHECK(SealBackend::coefficient_moduli(restored_eval) ==
              SealBackend::coefficient_moduli(contexts.eval));
        const SlotVector clear(kTargetSlots, Fp(12345));
        auto ciphertext = SealBackend::encrypt(contexts.client, clear);
        SealBackend::mod_switch_to_lowest(contexts.eval, ciphertext);
        CHECK(SealBackend::rns_limb_count(contexts.eval, ciphertext) == 1U);
        CHECK(SealBackend::decrypt(contexts.client, ciphertext) == clear);

        // Exercise the complete multiplicative depth, then pessimistically
        // align the quick profile's terminal reduction noise by doubling one
        // branch ten times (1,024 equal terms).
        PayloadBuilder builder(PayloadShape::wide(kTargetSlots), 2);
        const std::size_t bias = builder.add_scalar_plaintext(Fp(17));
        WireId left = 0;
        WireId right = 1;
        for (std::size_t depth = 0; depth < selected.depth; ++depth) {
            const WireId next_left =
                builder.mul(left, builder.add_plain(right, bias));
            const WireId next_right =
                builder.mul(right, builder.add_plain(left, bias));
            left = next_left;
            right = next_right;
        }
        builder.set_outputs({left});
        const PayloadCircuit payload = builder.finish();
        const LayeredCircuit layered = compile(payload);
        const std::vector<SlotVector> inputs{
            SlotVector(kTargetSlots, Fp(3)),
            SlotVector(kTargetSlots, Fp(5)),
        };
        const PlainTrace plain =
            synthesize_trace(payload, layered, inputs);
        const auto encrypted_inputs =
            encrypt_wide_payload_inputs<SealBackend>(
                contexts.client, payload, inputs);
        const EncryptedTrace<SealBackend> evaluated =
            evaluate_wide_fhe_trace_into<SealBackend>(
                contexts.eval, payload, layered, encrypted_inputs,
                FheEvaluationPlan::at_evaluation_levels(layered, selected.depth),
                InMemoryTraceSink<SealBackend>{contexts.eval});
        SealBackend::Ciphertext terminal =
            evaluated.layers.front().wires.front().ciphertext();
        SlotVector expected = plain.layers.front().front();
        const auto double_terminal = [&] {
            terminal = SealBackend::add(contexts.eval, terminal, terminal);
            for (Fp &value : expected) {
                value += value;
            }
        };
        for (std::size_t level = 0; level < 10; ++level) {
            double_terminal();
        }
        CHECK(SealBackend::rns_limb_count(contexts.eval, terminal) == 1U);
        const auto check_terminal_output = [&] {
            const int noise_budget = SealBackend::invariant_noise_budget(
                contexts.client, terminal);
            std::cout << "[INFO] payload-only terminal noise budget: "
                      << noise_budget << " bits\n";
            // Keys and encryption are randomized. The observed margin can
            // fall below ten bits while decryption remains correct.
            CHECK(noise_budget > 0);
            bench::require_no_integrity_output_noise_budget(noise_budget);
            CHECK(SealBackend::decrypt(contexts.client, terminal) == expected);
            return noise_budget;
        };
        int terminal_noise_budget = check_terminal_output();

        // Exercise a positive single-digit margin on every run, including
        // when the original stress computation has more headroom. At a
        // positive margin each doubling consumes about one noise-budget bit.
        for (std::size_t extra = 0;
             terminal_noise_budget >= 10 &&
             extra < static_cast<std::size_t>(std::bit_width(data_primes.front()));
             ++extra) {
            double_terminal();
            terminal_noise_budget = SealBackend::invariant_noise_budget(
                contexts.client, terminal);
        }
        CHECK(terminal_noise_budget < 10);
        (void)check_terminal_output();

        for (std::size_t extra = 0;
             terminal_noise_budget > 0 &&
             extra < static_cast<std::size_t>(std::bit_width(data_primes.front())); ++extra) {
            double_terminal();
            terminal_noise_budget = SealBackend::invariant_noise_budget(
                contexts.client, terminal);
        }
        CHECK(terminal_noise_budget == 0);
        bool rejected = false;
        try {
            bench::require_no_integrity_output_noise_budget(terminal_noise_budget);
        } catch (const std::runtime_error &) {
            rejected = true;
        }
        CHECK(rejected);
    });
    runner.run("real BGV output-only replay matches resident evaluation",
               [] {
        const PayloadCircuit payload = mixed_wide_payload();
        const LayeredCircuit circuit = compile(payload);
        const std::vector<SlotVector> clear_inputs{
            wide_values(7), wide_values(71), wide_values(137)};
        const PlainTrace plain =
            synthesize_trace(payload, circuit, clear_inputs);

        auto contexts = SealBackend::create(SealParameters{
            .poly_modulus_degree = kSlots,
            .fresh_rns_limbs = 3,
            .bits_per_data_prime = 45,
            .special_prime_bits = 45,
            .security_level = seal::sec_level_type::none,
        });
        const auto encrypted_inputs =
            encrypt_wide_payload_inputs<SealBackend>(
                contexts.client, payload, clear_inputs);
        const FheEvaluationPlan evaluation =
            FheEvaluationPlan::at_evaluation_levels(circuit, 2);
        const EncryptedTrace<SealBackend> resident =
            evaluate_wide_fhe_trace_into<SealBackend>(
                contexts.eval, payload, circuit, encrypted_inputs,
                evaluation,
                InMemoryTraceSink<SealBackend>{contexts.eval});
        const PayloadCheckpointReplayProblem problem = make_problem(
            circuit, evaluation, contexts.eval, resident);
        const PayloadCheckpointReplayBudgets budgets{
            .max_live_scratch_bytes = std::uint64_t{1} << 32U,
            .max_resident_ciphertext_bytes = std::uint64_t{1} << 31U,
            .max_ciphertexts_per_chunk = 2,
            .max_recomputation_factor = {100, 1},
            .reserved_live_scratch_bytes = 4096,
            .reserved_resident_bytes = 4096,
            .selection_objective =
                PayloadCheckpointSelectionObjective::
                    OutputOnlyAdjacentLayers,
        };
        const PayloadCheckpointReplayPlan plan =
            plan_payload_checkpoint_replay(problem, budgets);
        const CertifiedPayloadCheckpointReplayStatic certified =
            certify_payload_checkpoint_replay_static(
                payload,
                derive_certified_canonical_trace_layout(circuit),
                evaluation, problem, budgets, plan);

        TemporaryDirectory root;
        const std::filesystem::path output_directory =
            root.make_child("output-only");
        std::vector<FheValue<SealBackend>> output;
        SealBackend::reset_counts(contexts.eval);
        SealBackend::set_counting(contexts.eval, true);
        auto evaluated = PayloadCheckpointReplayTrace<
            SealBackend>::publish_output_only_certified(
            contexts.eval, certified, encrypted_inputs,
            PayloadCheckpointReplayExecutionOptions{
                .directory = output_directory,
                .min_free_bytes = 1,
                .max_checkpoint_metadata_bytes = 1,
                .lifecycle =
                    FileTraceSessionLifecycle::IrreversibleNoRetry,
            },
            output);
        SealBackend::set_counting(contexts.eval, false);

        CHECK(output.size() == 4U);
        for (std::size_t stored = 0; stored < output.size(); ++stored) {
            CHECK(materialize_or_decrypt<SealBackend>(
                      contexts.client, output[stored]) ==
                  plain.layers.front()[stored]);
            CHECK(output[stored].is_encrypted() ==
                  resident.layers.front().wires[stored].is_encrypted());
            if (output[stored].is_encrypted()) {
                CHECK(SealBackend::rns_limb_count(
                          contexts.eval, output[stored].ciphertext()) == 1U);
            }
        }
        const SealBackend::OperationCounts counts =
            SealBackend::counts(contexts.eval);
        CHECK(counts.calls(SealBackend::OperationKind::Encrypt) == 0);
        CHECK(evaluated.is_output_only());
        CHECK(!evaluated.report().checkpoint_set_published);
        CHECK(plan.selected.checkpoint_layers.empty());
        CHECK(plan.selected.checkpoint_bytes == 0);
        CHECK(evaluated.report().checkpoint_metadata_physical_bytes == 0);
        CHECK(evaluated.report().checkpoint_layer_physical_bytes == 0);
        CHECK(evaluated.report().replay_work_units == 0);
        CHECK(evaluated.report().segments.empty());
        CHECK(evaluated.report().all_payload_artifacts_retired);
        CHECK(evaluated.report().live_physical_bytes == 0);
        CHECK(evaluated.report().peak_live_layer_artifacts <= 2);
        CHECK(regular_file_bytes(output_directory) == 0);
    });
    runner.run("real BGV identity affine layer reuses its private inode", [] {
        const PayloadCircuit payload = strict_identity_affine_payload();
        const LayeredCircuit circuit = compile(payload);
        std::vector<SlotVector> clear_inputs;
        for (std::size_t input = 0; input < payload.input_count; ++input) {
            clear_inputs.push_back(lanes(11U + 13U * input));
        }
        const PlainTrace plain =
            synthesize_trace(payload, circuit, clear_inputs);
        auto contexts = SealBackend::create(SealParameters{
            .poly_modulus_degree = kSlots,
            .fresh_rns_limbs = 3,
            .bits_per_data_prime = 45,
            .special_prime_bits = 45,
            .security_level = seal::sec_level_type::none,
        });
        const auto encrypted_inputs =
            encrypt_laned_payload_inputs<SealBackend>(
                contexts.client, payload, clear_inputs);
        const FheEvaluationPlan evaluation =
            FheEvaluationPlan::at_evaluation_levels(circuit, 2);
        const EncryptedTrace<SealBackend> resident =
            evaluate_laned_fhe_trace<SealBackend>(
                contexts.eval, payload, circuit, encrypted_inputs,
                evaluation);
        const PayloadCheckpointReplayProblem problem = make_problem(
            circuit, evaluation, contexts.eval, resident);
        const CanonicalTraceLayout alias_layout =
            canonical_trace_layout(circuit);
        constexpr std::size_t kAliasOutputLayer = 2;
        constexpr std::size_t kAliasSourceLayer = 3;
        CHECK(layer_kind(circuit.layers[kAliasOutputLayer]) ==
              LayerKind::Affine);
        CHECK(layer_dimensions(circuit.layers[kAliasSourceLayer])
                  .logical_size ==
              layer_dimensions(circuit.layers[kAliasOutputLayer])
                  .logical_size);
        // The layer-file format binds record order and count, not the
        // descriptor's virtual padding geometry. This fixture deliberately
        // exercises an exact stored identity across distinct padded sizes.
        CHECK(layer_dimensions(circuit.layers[kAliasSourceLayer])
                  .padded_size !=
              layer_dimensions(circuit.layers[kAliasOutputLayer])
                  .padded_size);
        CHECK(evaluation.trace.required_mult_depth_by_layer
                  [kAliasSourceLayer] ==
              evaluation.trace.required_mult_depth_by_layer
                  [kAliasOutputLayer]);
        CHECK(alias_layout.storage[kAliasSourceLayer].stored_wire_count ==
              alias_layout.storage[kAliasOutputLayer].stored_wire_count);
        CHECK(alias_layout.stored_value_classifications[kAliasSourceLayer] ==
              alias_layout.stored_value_classifications[kAliasOutputLayer]);
        CHECK(problem.layers[kAliasSourceLayer].rns_limb_count ==
              problem.layers[kAliasOutputLayer].rns_limb_count);
        CHECK(problem.layers[kAliasSourceLayer]
                  .serialized_ciphertext_bytes ==
              problem.layers[kAliasOutputLayer]
                  .serialized_ciphertext_bytes);
        CHECK(problem.layers[kAliasOutputLayer]
                  .modulus_switches_after_layer == 0U);
        for (std::size_t stored = 0;
             stored < alias_layout.storage[kAliasOutputLayer]
                          .stored_wire_count;
             ++stored) {
            CHECK(materialize_or_decrypt<SealBackend>(
                      contexts.client,
                      resident.layers[kAliasSourceLayer].wires[stored]) ==
                  materialize_or_decrypt<SealBackend>(
                      contexts.client,
                      resident.layers[kAliasOutputLayer].wires[stored]));
        }
        const PayloadCheckpointReplayBudgets budgets{
            .max_live_scratch_bytes = std::uint64_t{1} << 32U,
            .max_resident_ciphertext_bytes = std::uint64_t{1} << 31U,
            .max_ciphertexts_per_chunk = 4,
            .max_recomputation_factor = {100, 1},
            .reserved_live_scratch_bytes = 4096,
            .reserved_resident_bytes = 4096,
            .selection_objective =
                PayloadCheckpointSelectionObjective::
                    OutputOnlyAdjacentLayers,
        };
        const PayloadCheckpointReplayPlan plan =
            plan_payload_checkpoint_replay(problem, budgets);
        const CertifiedPayloadCheckpointReplayStatic certified =
            certify_payload_checkpoint_replay_static(
                payload, derive_certified_canonical_trace_layout(circuit),
                evaluation, problem, budgets, plan);
        TemporaryDirectory root;
        const std::filesystem::path output_directory =
            root.make_child("identity-affine-output-only");
        std::vector<FheValue<SealBackend>> output;
        auto replay = PayloadCheckpointReplayTrace<SealBackend>::
            publish_output_only_certified(
                contexts.eval, certified, encrypted_inputs,
                PayloadCheckpointReplayExecutionOptions{
                    .directory = output_directory,
                    .min_free_bytes = 1,
                    .max_checkpoint_metadata_bytes = 1,
                    .lifecycle =
                        FileTraceSessionLifecycle::IrreversibleNoRetry,
                },
                output);

#ifdef _WIN32
        CHECK(replay.report().forward.identity_affine_alias_relations == 0U);
        CHECK(replay.report().forward.identity_affine_alias_fallbacks == 1U);
        CHECK(replay.report().forward.identity_affine_alias_records_reused ==
              0U);
#else
        CHECK(replay.report().forward.identity_affine_alias_relations == 1U);
        CHECK(replay.report().forward.identity_affine_alias_fallbacks == 0U);
        CHECK(replay.report().forward.identity_affine_alias_records_reused ==
              16U);
        CHECK(replay.report()
                  .forward.identity_affine_alias_unique_bytes_written ==
              file_trace_manifest_bytes(1));
#endif
        CHECK(output.size() == 1U);
        CHECK(materialize_or_decrypt<SealBackend>(
                  contexts.client, output.front()) ==
              expand_for_encryption(payload.shape,
                                    plain.layers.front().front()));
        CHECK(replay.report().all_payload_artifacts_retired);
        CHECK(replay.report().live_physical_bytes == 0);
        CHECK(replay.report().total_reclaimed_physical_bytes ==
              replay.report().forward.physical_bytes_written);
        CHECK(regular_file_bytes(output_directory) == 0);
    });
    runner.run("real BGV alias-heavy replay decodes each source once", [] {
        constexpr std::size_t kPairCount = 40;
        constexpr std::size_t kInputCount = 5;
        const PayloadCircuit payload =
            alias_heavy_multiplication_payload(kPairCount, kInputCount);
        const LayeredCircuit circuit = compile(payload);
        std::vector<SlotVector> clear_inputs;
        clear_inputs.reserve(kInputCount);
        for (std::size_t input = 0; input < kInputCount; ++input) {
            clear_inputs.push_back(lanes(5U + 11U * input));
        }
        const PlainTrace plain =
            synthesize_trace(payload, circuit, clear_inputs);
        const CanonicalTraceLayout trace_layout =
            canonical_trace_layout(circuit);

        auto contexts = SealBackend::create(SealParameters{
            .poly_modulus_degree = kSlots,
            .fresh_rns_limbs = 4,
            .bits_per_data_prime = 45,
            .special_prime_bits = 45,
            .security_level = seal::sec_level_type::none,
        });
        const auto encrypted_inputs =
            encrypt_laned_payload_inputs<SealBackend>(
                contexts.client, payload, clear_inputs);
        const std::size_t fresh_level =
            SealBackend::remaining_mult_depth(contexts.eval,
                                               encrypted_inputs.front());
        const FheEvaluationPlan evaluation =
            FheEvaluationPlan::at_evaluation_levels(circuit, fresh_level);
        const EncryptedTrace<SealBackend> resident =
            evaluate_laned_fhe_trace<SealBackend>(
                contexts.eval, payload, circuit, encrypted_inputs,
                evaluation);
        const PayloadCheckpointReplayProblem problem = make_problem(
            circuit, evaluation, contexts.eval, resident);
        const PayloadCheckpointReplayBudgets budgets{
            .max_live_scratch_bytes = std::uint64_t{1} << 32U,
            .max_resident_ciphertext_bytes = std::uint64_t{1} << 31U,
            .max_ciphertexts_per_chunk = 4,
            .max_recomputation_factor = {100, 1},
            .reserved_live_scratch_bytes = 4096,
            .reserved_resident_bytes = 4096,
        };
        const PayloadCheckpointReplayPlan plan =
            plan_payload_checkpoint_replay(problem, budgets);

        TemporaryDirectory root;
        const std::filesystem::path replay_directory =
            root.make_child("alias-cached-replay");
        std::vector<FheValue<SealBackend>> output;
        auto replay = PayloadCheckpointReplayTrace<SealBackend>::publish(
            contexts.eval, payload, circuit, encrypted_inputs, evaluation,
            problem, budgets, plan,
            PayloadCheckpointReplayExecutionOptions{
                .directory = replay_directory,
                .min_free_bytes = 1,
                .max_checkpoint_metadata_bytes = 4096,
                .lifecycle =
                    FileTraceSessionLifecycle::IrreversibleNoRetry,
            },
            output);

        const std::vector<std::size_t> multiplications =
            multiplication_layers(circuit);
        CHECK(multiplications.size() == 1U);
        const std::size_t source_layer = multiplications.front() + 1U;
        const std::size_t distinct =
            trace_layout.storage[source_layer].stored_wire_count;
        CHECK(distinct > 2U * plan.selected.chunk_ciphertexts);
        CHECK(plan.selected
                  .dense_multiplication_alias_cache_peak_resident_bytes >
              0);
        const PayloadCheckpointReplayIoReport &io = replay.report().forward;
        CHECK(io.alias_cached_dense_multiplication_relations == 1U);
        CHECK(io.alias_cached_dense_multiplication_range_readers_opened ==
              1U);
        CHECK(io.alias_cached_dense_multiplication_distinct_source_records_read ==
              distinct);
        CHECK(io.alias_cached_dense_multiplication_fallback_source_records >=
              4U * distinct);
        CHECK(replay.report().peak_controlled_resident_bytes <=
              plan.selected.peak_resident_bytes);
        CHECK(output.size() ==
              trace_layout.storage.front().stored_wire_count);
        for (std::size_t stored = 0; stored < output.size(); ++stored) {
            const std::size_t padded =
                trace_layout.storage.front()
                    .representative_padded_index_of(stored);
            CHECK(materialize_or_decrypt<SealBackend>(
                      contexts.client, output[stored]) ==
                  expand_for_encryption(payload.shape,
                                        plain.layers.front()[padded]));
        }

        (void)replay.retire_layer(0);
        for (std::size_t layer = 1; layer < circuit.layers.size(); ++layer) {
            {
                auto reader = replay.active_layer_reader(layer);
                while (reader.next()) {
                }
            }
            (void)replay.retire_layer(layer);
        }
        CHECK(replay.report().all_payload_artifacts_retired);
        CHECK(replay.report().live_physical_bytes == 0);
    });
    runner.run("real BGV replay preserves payload and verifies Laned GKR", [] {
        const PayloadCircuit payload = mixed_payload();
        // Rotate is intentionally absent because Laned circuits have
        // independent lanes and the IR therefore rejects rotations.
        const LayeredCircuit circuit = compile(payload);
        const std::vector<SlotVector> clear_inputs{lanes(5)};
        const PlainTrace plain =
            synthesize_trace(payload, circuit, clear_inputs);

        auto contexts = SealBackend::create(SealParameters{
            .poly_modulus_degree = kSlots,
            .fresh_rns_limbs = 8,
            .bits_per_data_prime = 45,
            .special_prime_bits = 45,
            .security_level = seal::sec_level_type::none,
        });
        const auto encrypted_inputs =
            encrypt_laned_payload_inputs<SealBackend>(
                contexts.client, payload, clear_inputs);
        const std::size_t fresh_level =
            SealBackend::remaining_mult_depth(contexts.eval,
                                               encrypted_inputs.front());
        FheEvaluationPlan evaluation =
            FheEvaluationPlan::at_evaluation_levels(circuit, fresh_level);
        CHECK(std::count_if(
                  evaluation.modulus_switches_after_layer.begin(),
                  evaluation.modulus_switches_after_layer.end(),
                  [](std::size_t count) { return count != 0; }) == 1);

        const EncryptedTrace<SealBackend> resident =
            evaluate_laned_fhe_trace<SealBackend>(
                contexts.eval, payload, circuit, encrypted_inputs,
                evaluation);
        std::fill(
            evaluation.proof_ingress_mult_depth_by_layer.begin(),
            evaluation.proof_ingress_mult_depth_by_layer.end(), 5U);
        evaluation.proof_ingress_mult_depth_by_layer.front() =
            evaluation.trace.required_mult_depth_by_layer.front();
        evaluation.validate(circuit);
        const PayloadCheckpointReplayProblem problem = make_problem(
            circuit, evaluation, contexts.eval, resident);
        PayloadCheckpointReplayBudgets budgets{
            .max_live_scratch_bytes = std::uint64_t{1} << 32U,
            .max_resident_ciphertext_bytes = std::uint64_t{1} << 31U,
            .max_ciphertexts_per_chunk = 4,
            .max_recomputation_factor = {100, 1},
            .reserved_live_scratch_bytes = 4096,
            .reserved_resident_bytes = 4096,
        };
        budgets.reserved_resident_bytes +=
            eager_laned_witness_packing_resources(circuit, problem)
                .resident_workspace_bytes;
        const PayloadCheckpointReplayPlan plan =
            plan_payload_checkpoint_replay(problem, budgets);
        CHECK(plan.selected.checkpoint_layers ==
              std::vector<std::size_t>{circuit.layers.size() - 1U});

        TemporaryDirectory root;
        const std::filesystem::path replay_directory =
            root.make_child("replay");
        std::vector<FheValue<SealBackend>> output;
        std::vector<RuntimeProgressEvent> progress_events;
        SealBackend::reset_counts(contexts.eval);
        SealBackend::set_counting(contexts.eval, true);
        auto replay = PayloadCheckpointReplayTrace<SealBackend>::publish(
            contexts.eval, payload, circuit, encrypted_inputs, evaluation,
            problem, budgets, plan,
            PayloadCheckpointReplayExecutionOptions{
                .directory = replay_directory,
                .min_free_bytes = 1,
                .max_checkpoint_metadata_bytes = 4096,
                .lifecycle =
                    FileTraceSessionLifecycle::IrreversibleNoRetry,
                .eager_laned_witness_packing = true,
                .progress = [&](const RuntimeProgressEvent &event) {
                    progress_events.push_back(event);
                },
            },
            output);
        SealBackend::set_counting(contexts.eval, false);
        const SealBackend::OperationCounts forward_counts =
            SealBackend::counts(contexts.eval);
        CHECK(forward_counts.calls(
                  SealBackend::OperationKind::MulPlainScalar) > 0);
        CHECK(forward_counts.calls(
                  SealBackend::OperationKind::MulPlainVector) > 0);
        CHECK(forward_counts.calls(
                  SealBackend::OperationKind::MulNoRelin) > 0);
        CHECK(forward_counts.calls(
                  SealBackend::OperationKind::Relinearize) > 0);
        CHECK(forward_counts.calls(SealBackend::OperationKind::AddPlain) > 0);
        CHECK(forward_counts.calls(SealBackend::OperationKind::ModSwitch) > 0);
        CHECK(forward_counts.calls(SealBackend::OperationKind::Rotate) == 0);

        std::size_t witness_phase_count = 0;
        for (std::size_t index = 0; index < progress_events.size(); ++index) {
            const RuntimeProgressEvent &event = progress_events[index];
            if (event.stage != RuntimeProgressStage::LanedWitnessPacking) {
                continue;
            }
            if (event.boundary == RuntimeProgressBoundary::Begin) {
                ++witness_phase_count;
                if (event.source_layer != circuit.layers.size() - 1U) {
                    CHECK(index != 0);
                    const RuntimeProgressEvent &preceding =
                        progress_events[index - 1U];
                    CHECK(preceding.stage ==
                          RuntimeProgressStage::PayloadForwardRelation);
                    CHECK(preceding.boundary ==
                          RuntimeProgressBoundary::End);
                    CHECK(preceding.output_layer == event.source_layer);
                }
            } else if (event.boundary == RuntimeProgressBoundary::End) {
                CHECK(index + 1U < progress_events.size());
                const RuntimeProgressEvent &following =
                    progress_events[index + 1U];
                CHECK(following.stage ==
                      RuntimeProgressStage::PayloadForwardRelation);
                CHECK(following.boundary ==
                      RuntimeProgressBoundary::Begin);
                CHECK(following.source_layer == event.source_layer);
            }
        }
        CHECK(witness_phase_count == circuit.layers.size() - 1U);

        CHECK(output.size() == plain.layers.front().size());
        for (std::size_t wire = 0; wire < output.size(); ++wire) {
            CHECK(materialize_or_decrypt<SealBackend>(
                      contexts.client, output[wire]) ==
                  expand_for_encryption(payload.shape,
                                        plain.layers.front()[wire]));
            const FheValue<SealBackend> &resident_output =
                resident.layers.front().wires[wire];
            CHECK(output[wire].is_public() ==
                  resident_output.is_public());
            if (output[wire].is_encrypted()) {
                CHECK(SealBackend::rns_limb_count(
                          contexts.eval, output[wire].ciphertext()) ==
                      SealBackend::rns_limb_count(
                          contexts.eval,
                          resident_output.ciphertext()));
            } else {
                CHECK(output[wire].plaintext() ==
                      resident_output.plaintext());
            }
        }

        const PublicSetup public_setup =
            make_direct_setup(payload, circuit);
        const EvaluationSetup<SealBackend> server =
            make_packed_evaluation_setup<SealBackend>(public_setup,
                                                      contexts.eval);
        const ClientSetup<SealBackend> client =
            make_client_setup<SealBackend>(public_setup, contexts.client);
        const std::vector<Fpk> point(
            laned_layer_variables(circuit, 0),
            Fpk::from_base(Fp(23)));
        const SingleClaim output_claim = make_packed_laned_claim(
            plain.layers.front(), laned_layout(circuit, 0), point);

        laned_detail::FileLanedGkrOptions streamed_options;
        std::vector<std::filesystem::path> scratch_directories;
        for (std::size_t layer : multiplication_layers(circuit)) {
            const std::filesystem::path scratch = root.make_child(
                "multiplication-" + std::to_string(layer));
            scratch_directories.push_back(scratch);
            streamed_options.multiplication_scratch.push_back(
                laned_detail::FileLanedMultiplicationScratch{
                    layer,
                    scratch,
                    FileTraceStoreOptions{
                        .max_total_bytes = std::uint64_t{1} << 32U,
                        .min_free_bytes = 1,
                    },
                });
        }

        constexpr std::string_view kDomain =
            "test/checkpoint-replay/execution-seal/v1";
        Transcript prover_transcript(kDomain);
        const auto proved =
            laned_detail::LanedProver<
                SealBackend, PayloadCheckpointReplayTrace<SealBackend>>(
                payload, circuit, replay, server,
                [&] {
                    std::vector<std::size_t> limbs;
                    for (const std::size_t depth :
                         evaluation.proof_ingress_mult_depth_by_layer) {
                        limbs.push_back(depth + 1U);
                    }
                    return limbs;
                }(),
                output_claim.point,
                prover_transcript, std::move(streamed_options), {}, {}, true)
                .run();
        CHECK(replay.report().all_payload_artifacts_retired);
        CHECK(replay.report().live_physical_bytes == 0);
        CHECK(replay.uses_eager_laned_witness_packing());
        CHECK(replay.report().replay_work_units == 0);
        CHECK(replay.report().proof_ingress_ciphertexts == 0);
        CHECK(replay.report().proof_ingress_modulus_switches == 0);
        CHECK(replay.report().laned_witness_source_values > 0);
        CHECK(replay.report().laned_witness_packed_ciphertexts > 0);
        CHECK(replay.report().laned_witness_rotations == 0);
        CHECK(replay.report().laned_witness_modulus_switches <=
              replay.report().laned_witness_packed_ciphertexts *
                  fresh_level);
        CHECK(replay.report().laned_witness_physical_bytes_written ==
              replay.report().laned_witness_physical_bytes_retired);
        for (const auto &scratch : scratch_directories) {
            CHECK(std::filesystem::is_empty(scratch));
        }

        Transcript verifier_transcript(kDomain);
        CHECK(laned_detail::verify_encrypted_gkr<SealBackend>(
            payload, circuit, plain.layers.back(), client,
            resident.provenance, resident.trace_id, output_claim,
            proved.proof, verifier_transcript));
    });
    runner.run("real BGV Wide replay stores only canonical distinct values",
               [] {
        const PayloadCircuit payload = mixed_wide_payload();
        const LayeredCircuit circuit = compile(payload);
        const std::vector<SlotVector> clear_inputs{
            wide_values(7), wide_values(71), wide_values(137)};
        const PlainTrace plain =
            synthesize_trace(payload, circuit, clear_inputs);
        const CanonicalTraceLayout trace_layout =
            canonical_trace_layout(circuit);
        const auto &support = trace_layout.wire_support;
        const auto &storage = trace_layout.storage;
        const auto &value_counts = trace_layout.value_counts;
        CHECK(std::any_of(support.begin(), support.end(),
                          [](const LayerWireSupport &layer) {
                              return layer.live_wire_count <
                                     layer.padded_wire_count;
                          }));
        bool has_stored_aliases = false;
        bool has_public_stored_values = false;
        for (std::size_t layer = 0; layer < support.size(); ++layer) {
            has_stored_aliases =
                has_stored_aliases ||
                value_counts[layer].stored_values <
                    value_counts[layer].logical_live_wires;
            has_public_stored_values =
                has_public_stored_values ||
                value_counts[layer].encrypted_ciphertexts <
                    value_counts[layer].stored_values;
        }
        CHECK(has_stored_aliases);
        CHECK(has_public_stored_values);

        auto contexts = SealBackend::create(SealParameters{
            .poly_modulus_degree = kSlots,
            .fresh_rns_limbs = 8,
            .bits_per_data_prime = 45,
            .special_prime_bits = 45,
            .security_level = seal::sec_level_type::none,
        });
        const auto encrypted_inputs =
            encrypt_wide_payload_inputs<SealBackend>(
                contexts.client, payload, clear_inputs);
        const std::size_t fresh_level =
            SealBackend::remaining_mult_depth(contexts.eval,
                                               encrypted_inputs.front());
        FheEvaluationPlan evaluation =
            FheEvaluationPlan::at_evaluation_levels(circuit, fresh_level);
        const EncryptedTrace<SealBackend> resident =
            evaluate_wide_fhe_trace_into<SealBackend>(
                contexts.eval, payload, circuit, encrypted_inputs,
                evaluation,
                InMemoryTraceSink<SealBackend>{
                    contexts.eval});
        std::fill(
            evaluation.proof_ingress_mult_depth_by_layer.begin(),
            evaluation.proof_ingress_mult_depth_by_layer.end(), 0U);
        evaluation.proof_ingress_mult_depth_by_layer.front() =
            evaluation.trace.required_mult_depth_by_layer.front();
        evaluation.validate(circuit);
        const PayloadCheckpointReplayProblem problem = make_problem(
            circuit, evaluation, contexts.eval, resident);
        const PayloadCheckpointReplayBudgets budgets{
            .max_live_scratch_bytes = std::uint64_t{1} << 32U,
            .max_resident_ciphertext_bytes = std::uint64_t{1} << 31U,
            .max_ciphertexts_per_chunk = 2,
            .max_recomputation_factor = {100, 1},
            .reserved_live_scratch_bytes = 4096,
            .reserved_resident_bytes = 4096,
        };
        const PayloadCheckpointReplayPlan plan =
            plan_payload_checkpoint_replay(problem, budgets);
        CHECK(plan.selected.chunk_ciphertexts == 2);
        CHECK(minimum_payload_checkpoint_relation_chunk_ciphertexts(
                  circuit) == 2);
        const auto &output_affine =
            std::get<AffineLayer>(circuit.layers.front());
        CHECK(!output_affine.intermediate_gates.empty());
        CHECK(problem.layers.front().affine_workspace_bytes > 0);
        CHECK(std::all_of(output_affine.intermediate_gates.begin(),
                         output_affine.intermediate_gates.end(),
                         [](const AffineGate &gate) { return gate.terms.size() <= 2; }));

        TemporaryDirectory root;
        const std::filesystem::path replay_directory =
            root.make_child("wide-replay");
        std::vector<FheValue<SealBackend>> output;
        SealBackend::reset_counts(contexts.eval);
        SealBackend::set_counting(contexts.eval, true);
        auto replay = PayloadCheckpointReplayTrace<SealBackend>::publish(
            contexts.eval, payload, circuit, encrypted_inputs, evaluation,
            problem, budgets, plan,
            PayloadCheckpointReplayExecutionOptions{
                .directory = replay_directory,
                .min_free_bytes = 1,
                .max_checkpoint_metadata_bytes = 4096,
                .lifecycle =
                    FileTraceSessionLifecycle::IrreversibleNoRetry,
            },
            output);
        const SealBackend::OperationCounts forward_counts =
            SealBackend::counts(contexts.eval);
        CHECK(forward_counts.calls(SealBackend::OperationKind::Sub) == 0);
        CHECK(forward_counts.calls(SealBackend::OperationKind::Encrypt) ==
              0);
        std::uint64_t expected_forward_switches = 0;
        for (std::size_t layer = 0; layer + 1U < support.size(); ++layer) {
            expected_forward_switches +=
                value_counts[layer].encrypted_ciphertexts *
                evaluation.modulus_switches_after_layer[layer];
        }
        CHECK(forward_counts.calls(SealBackend::OperationKind::ModSwitch) ==
              expected_forward_switches);

        CHECK(output.size() == storage.front().stored_wire_count);
        for (std::size_t stored = 0; stored < output.size(); ++stored) {
            const std::size_t padded =
                storage.front().representative_padded_index_of(stored);
            CHECK(materialize_or_decrypt<SealBackend>(
                      contexts.client, output[stored]) ==
                  plain.layers.front()[padded]);
            const FheValue<SealBackend> &resident_output =
                resident.layers.front().wires[stored];
            CHECK(output[stored].is_public() ==
                  resident_output.is_public());
            if (output[stored].is_encrypted()) {
                CHECK(SealBackend::rns_limb_count(
                          contexts.eval, output[stored].ciphertext()) ==
                      SealBackend::rns_limb_count(
                          contexts.eval,
                          resident_output.ciphertext()));
            } else {
                CHECK(output[stored].plaintext() ==
                      resident_output.plaintext());
            }
        }
        for (std::size_t layer = 0; layer < support.size(); ++layer) {
            CHECK(replay.descriptor().layers[layer].layout ==
                  TraceLayerLayout::Wide);
            CHECK(replay.descriptor().layers[layer].record_count ==
                  storage[layer].stored_wire_count);
            CHECK(problem.layers[layer].stored_value_count ==
                  value_counts[layer].stored_values);
        }

        (void)replay.retire_layer(0);
        SealBackend::reset_counts(contexts.eval);
        std::size_t public_zeros_read = 0;
        for (std::size_t layer = 1; layer < support.size(); ++layer) {
            CHECK(replay.layer_support(layer) == support[layer]);
            {
                auto reader = replay.layer_reader(layer);
                std::size_t padded = 0;
                std::size_t live = 0;
                while (std::optional<fhe::FheValue<SealBackend>> value =
                           reader.next()) {
                    if (support[layer].is_live(padded)) {
                        CHECK(!value->is_public_zero());
                        CHECK(materialize_or_decrypt<SealBackend>(
                                  contexts.client, *value) ==
                              plain.layers[layer][padded]);
                        ++live;
                    } else {
                        CHECK(value->is_public_zero());
                        ++public_zeros_read;
                    }
                    ++padded;
                }
                CHECK(padded == support[layer].padded_wire_count);
                CHECK(live == support[layer].live_wire_count);
                CHECK(reader.serialized_records_read() == live);
                CHECK(reader.resident_ciphertexts_held() == 0);
            }

            const std::uint64_t aggregate_encoded_before =
                replay.report()
                    .gkr_source_reads.encoded_ciphertext_bytes_read;
            const std::uint64_t aggregate_framed_before =
                replay.report()
                    .gkr_source_reads.framed_record_bytes_read;
            const std::uint64_t aggregate_readers_before =
                replay.report().gkr_source_reads.range_readers_opened;
            std::uint64_t active_encoded = 0;
            std::uint64_t active_records = 0;
            {
                auto reader = replay.active_layer_reader(layer);
                CHECK(reader.begin() == 0);
                CHECK(reader.end() == storage[layer].stored_wire_count);
                const SealBackend::OperationCounts before =
                    SealBackend::counts(contexts.eval);
                std::size_t stored = 0;
                std::size_t encrypted = 0;
                while (auto record = reader.next()) {
                    CHECK(record->padded_index ==
                          storage[layer]
                              .representative_padded_index_of(stored));
                    CHECK(materialize_or_decrypt<SealBackend>(
                              contexts.client, record->value) ==
                          plain.layers[layer][record->padded_index]);
                    if (record->value.is_encrypted()) {
                        ++encrypted;
                        CHECK(SealBackend::remaining_mult_depth(
                                  contexts.eval,
                                  record->value.ciphertext()) ==
                              evaluation
                                  .proof_ingress_mult_depth_by_layer[layer]);
                        CHECK(SealBackend::rns_limb_count(
                                  contexts.eval,
                                  record->value.ciphertext()) == 1U);
                    } else {
                        record->value.plaintext().validate_slot_count(
                            SealBackend::slot_count(contexts.eval),
                            "checkpoint replay active SEAL reader");
                    }
                    ++stored;
                }
                CHECK(stored == storage[layer].stored_wire_count);
                CHECK(encrypted ==
                      value_counts[layer].encrypted_ciphertexts);
                CHECK(reader.position() == reader.end());
                CHECK(reader.serialized_records_read() == stored);
                CHECK(reader.resident_ciphertexts_held() == 0);
                const SealBackend::OperationCounts after =
                    SealBackend::counts(contexts.eval);
                CHECK(after.calls(SealBackend::OperationKind::Sub) ==
                      before.calls(SealBackend::OperationKind::Sub));
                CHECK(after.calls(SealBackend::OperationKind::ModSwitch) ==
                      before.calls(
                          SealBackend::OperationKind::ModSwitch));
                active_encoded = reader.encoded_bytes_read();
                active_records = reader.serialized_records_read();
            }
            CHECK(replay.report()
                          .gkr_source_reads.encoded_ciphertext_bytes_read -
                      aggregate_encoded_before ==
                  active_encoded);
            CHECK(replay.report()
                          .gkr_source_reads.framed_record_bytes_read -
                      aggregate_framed_before ==
                  active_encoded +
                      active_records * sizeof(std::uint64_t));
            CHECK(replay.report().gkr_source_reads.range_readers_opened ==
                  aggregate_readers_before + 1U);
            (void)replay.retire_layer(layer);
        }
        CHECK(public_zeros_read > 0);

        std::uint64_t expected_replay_switches = 0;
        for (const PayloadReplaySegment &segment :
             plan.reverse_gkr_segments) {
            for (std::size_t output_layer = segment.checkpoint_layer;
                 output_layer-- > segment.required_source_layer;) {
                expected_replay_switches +=
                    value_counts[output_layer].encrypted_ciphertexts *
                    evaluation.modulus_switches_after_layer[output_layer];
            }
        }
        std::uint64_t expected_ingress_switches = 0;
        for (std::size_t layer = 1; layer < support.size(); ++layer) {
            const std::size_t natural_limbs =
                SealBackend::rns_limb_count(
                    contexts.eval,
                    first_encrypted_value(
                        resident.layers[layer].wires).ciphertext());
            const std::size_t ingress_limbs =
                evaluation.proof_ingress_mult_depth_by_layer[layer] + 1U;
            expected_ingress_switches +=
                value_counts[layer].encrypted_ciphertexts *
                (natural_limbs - ingress_limbs);
        }
        const SealBackend::OperationCounts replay_counts =
            SealBackend::counts(contexts.eval);
        SealBackend::set_counting(contexts.eval, false);
        CHECK(replay_counts.calls(SealBackend::OperationKind::Sub) == 0);
        CHECK(replay_counts.calls(SealBackend::OperationKind::Encrypt) == 0);
        CHECK(replay_counts.calls(SealBackend::OperationKind::ModSwitch) ==
              expected_replay_switches + expected_ingress_switches);
        CHECK(replay.report().proof_ingress_modulus_switches ==
              expected_ingress_switches);
        CHECK(replay.report().peak_live_scratch_bytes <=
              budgets.max_live_scratch_bytes);
        CHECK(replay.report().peak_controlled_resident_bytes <=
              budgets.max_resident_ciphertext_bytes);
        CHECK(replay.report().peak_controlled_resident_bytes <=
              plan.selected.peak_resident_bytes);
        CHECK(replay.report().all_payload_artifacts_retired);
        CHECK(replay.report().live_physical_bytes == 0);
    });
    return runner.summary();
}
