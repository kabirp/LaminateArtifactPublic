/// @file test_checkpoint_replay_execution.cpp
/// @brief Mock execution and GKR parity for sparse payload checkpoints.

#include "test_helpers.hpp"

#include "laminate/fhe/mock_backend.hpp"
#include "laminate/gkr/detail/laned/affine/source/scan.hpp"
#include "laminate/gkr/detail/laned/reference/prover.hpp"
#include "laminate/gkr/detail/laned/prover.hpp"
#include "laminate/gkr/detail/laned/verifier.hpp"
#include "laminate/payload/checkpoint/session_engine.hpp"
#include "laminate/payload/compiler.hpp"
#include "laminate/payload/evaluator.hpp"
#include "laminate/payload/input_encryption.hpp"
#include "laminate/payload/laned_fhe_evaluator.hpp"
#include "laminate/payload/wide_fhe_evaluator.hpp"
#include "laminate/protocol/metrics/proof_size.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <limits>
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

constexpr std::size_t kSlots = 16;

/// The production SEAL backend's public remaining-depth value follows its
/// chain index. This tiny test adapter gives Mock the same level semantics
/// while retaining Mock's exact slot arithmetic, operation counters, and
/// persistent ciphertext codec.
struct ReplayMockBackend : MockBackend {
    static std::size_t remaining_mult_depth(
        const EvalContext &context, const Ciphertext &ciphertext) {
        (void)context;
        return ciphertext.rns_limbs - 1U;
    }
};

static_assert(fhe::PersistableFheBackend<ReplayMockBackend>);

struct CountingReplayMockBackend : ReplayMockBackend {
    static inline std::size_t storage_deserialize_calls = 0;

    static Ciphertext deserialize_from_storage(
        const EvalContext &context, std::span<const std::uint8_t> bytes) {
        ++storage_deserialize_calls;
        return ReplayMockBackend::deserialize_from_storage(context, bytes);
    }
};

static_assert(fhe::PersistableFheBackend<CountingReplayMockBackend>);

class TemporaryDirectory {
  public:
    TemporaryDirectory() {
        const auto stamp = std::chrono::steady_clock::now()
                               .time_since_epoch()
                               .count();
        for (std::size_t attempt = 0; attempt < 100; ++attempt) {
            path_ = std::filesystem::temp_directory_path() /
                    ("laminate-checkpoint-replay-execution-" +
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

bool throws_invalid_argument(const auto &body) {
    try {
        body();
    } catch (const std::invalid_argument &) {
        return true;
    }
    return false;
}
bool throws_exception(const auto &body) {
    try {
        body();
    } catch (const std::exception &) {
        return true;
    }
    return false;
}

PayloadCircuit make_payload(std::size_t output_count = 1) {
    PayloadBuilder builder(PayloadShape::laned(4, kSlots), 1);
    const WireId product = builder.mul(0, 0);
    const WireId mixed = builder.add(product, product);
    const WireId squared = builder.mul(mixed, mixed);
    const std::vector<WireId> candidates = {squared, mixed, product, 0};
    if (output_count == 0 || output_count > candidates.size()) {
        throw std::invalid_argument("unsupported replay-test output count");
    }
    builder.set_outputs(std::vector<WireId>(
        candidates.begin(),
        candidates.begin() + static_cast<std::ptrdiff_t>(output_count)));
    return builder.finish();
}

PayloadCircuit make_full_width_laned_payload() {
    PayloadBuilder builder(PayloadShape::laned(kSlots, kSlots), 1);
    const WireId product = builder.mul(0, 0);
    builder.set_outputs({builder.add(product, 0)});
    return builder.finish();
}

PayloadCircuit make_identity_dense_payload(std::size_t pair_count) {
    PayloadBuilder builder(
        PayloadShape::laned(4, kSlots), 2U * pair_count);
    std::vector<WireId> outputs;
    outputs.reserve(pair_count);
    for (std::size_t pair = 0; pair < pair_count; ++pair) {
        outputs.push_back(builder.mul(2U * pair, 2U * pair + 1U));
    }
    builder.set_outputs(std::move(outputs));
    return builder.finish();
}

PayloadCircuit make_alias_heavy_dense_payload(
    std::size_t pair_count, std::size_t input_count = 2,
    std::size_t lane_count = 4, bool reduce_outputs = false) {
    PayloadBuilder builder(
        PayloadShape::laned(lane_count, kSlots), input_count);
    const std::size_t bias = builder.add_scalar_plaintext(Fp(7));
    std::vector<WireId> outputs;
    outputs.reserve(pair_count);
    for (std::size_t pair = 0; pair < pair_count; ++pair) {
        const WireId left = pair % input_count;
        const WireId right = builder.add_plain(
            (pair + 1U) % input_count, bias);
        outputs.push_back(builder.mul(left, right));
    }
    while (reduce_outputs && outputs.size() > 1U) {
        std::vector<WireId> reduced;
        for (std::size_t i = 0; i < outputs.size(); i += 2U) {
            reduced.push_back(i + 1U < outputs.size()
                ? builder.mul(outputs[i], outputs[i + 1U]) : outputs[i]);
        }
        outputs = std::move(reduced);
    }
    builder.set_outputs(std::move(outputs));
    return builder.finish();
}

PayloadCircuit make_two_stage_alias_heavy_dense_payload(
    std::size_t pair_count) {
    PayloadBuilder builder(PayloadShape::laned(4, kSlots), 2);
    const std::size_t bias = builder.add_scalar_plaintext(Fp(7));
    std::vector<WireId> first_products;
    first_products.reserve(pair_count);
    for (std::size_t pair = 0; pair < pair_count; ++pair) {
        const WireId right = builder.add_plain((pair + 1U) % 2U, bias);
        first_products.push_back(builder.mul(pair % 2U, right));
    }

    std::vector<WireId> outputs;
    outputs.reserve(pair_count);
    for (std::size_t pair = 0; pair < pair_count; ++pair) {
        outputs.push_back(builder.mul(
            first_products[pair],
            first_products[(pair + 1U) % pair_count]));
    }
    builder.set_outputs(std::move(outputs));
    return builder.finish();
}

PayloadCircuit make_strict_identity_affine_payload() {
    PayloadBuilder builder(PayloadShape::laned(4, kSlots), 16);
    const std::array<WireId, 8> first{
        builder.mul(0, 1), builder.mul(2, 3),
        builder.mul(4, 5), builder.mul(6, 7),
        builder.mul(8, 9), builder.mul(10, 11),
        builder.mul(12, 13), builder.mul(14, 15)};
    const std::array<WireId, 4> upper{
        builder.mul(first[6], first[0]),
        builder.mul(first[3], first[5]),
        builder.mul(first[7], first[2]),
        builder.mul(first[4], first[1])};
    builder.set_outputs(
        {builder.add(builder.add(upper[0], upper[1]),
                     builder.add(upper[2], upper[3]))});
    return builder.finish();
}

struct IdentityAffineAliasPredicateFixture {
    Layer relation;
    EncryptedTraceLayerDescriptor source_descriptor;
    EncryptedTraceLayerDescriptor output_descriptor;
    PayloadReplayLayer source_resources;
    PayloadReplayLayer output_resources;
    LayerStorageLayout source_storage;
    LayerStorageLayout output_storage;
    std::vector<ClassifiedTraceValue> source_classifications;
    std::vector<ClassifiedTraceValue> output_classifications;

    checkpoint_replay_execution_detail::
        StoredIdentityAffineAliasCandidate candidate() const {
        return {
            .relation = relation,
            .source_descriptor = source_descriptor,
            .output_descriptor = output_descriptor,
            .source_resources = source_resources,
            .output_resources = output_resources,
            .source_storage = source_storage,
            .output_storage = output_storage,
            .source_classifications = source_classifications,
            .output_classifications = output_classifications,
        };
    }
};

IdentityAffineAliasPredicateFixture identity_affine_alias_candidate() {
    AffineLayer affine{
        .dimensions =
            LayerDimensions{
                .logical_size = 2,
                .padded_size = 4,
                .payload_size = 2,
                .forward_size = 0,
            },
        .gates = std::vector<AffineGate>(4),
    };
    affine.gates[0] = AffineGate{
        .terms = {{.source = 0,
                   .rotation = 0,
                   .coefficient = Fp::one()}},
        .constant = Fp::zero(),
        .origin = GateOrigin::Payload,
    };
    affine.gates[1] = AffineGate{
        .terms = {{.source = 1,
                   .rotation = 0,
                   .coefficient = Fp::one()}},
        .constant = Fp::zero(),
        .origin = GateOrigin::Forward,
    };

    return {
        .relation = std::move(affine),
        .source_descriptor =
            EncryptedTraceLayerDescriptor{
                .layout = TraceLayerLayout::BPeriodic,
                .dimensions =
                    LayerDimensions{
                        .logical_size = 2,
                        .padded_size = 2,
                        .payload_size = 2,
                        .forward_size = 0,
                    },
                .required_mult_depth = 3,
                .record_count = 2,
            },
        .output_descriptor =
            EncryptedTraceLayerDescriptor{
                .layout = TraceLayerLayout::BPeriodic,
                .dimensions =
                    LayerDimensions{
                        .logical_size = 2,
                        .padded_size = 4,
                        .payload_size = 2,
                        .forward_size = 0,
                    },
                .required_mult_depth = 3,
                .record_count = 2,
            },
        .source_resources =
            PayloadReplayLayer{
                .rns_limb_count = 4,
                .serialized_ciphertext_bytes = 128,
            },
        .output_resources =
            PayloadReplayLayer{
                .rns_limb_count = 4,
                .modulus_switches_after_layer = 0,
                .serialized_ciphertext_bytes = 128,
            },
        .source_storage =
            LayerStorageLayout{
                .padded_wire_count = 2,
                .stored_wire_count = 2,
                .padded_to_stored = {0U, 1U},
                .representative_padded_indices = {0U, 1U},
            },
        .output_storage =
            LayerStorageLayout{
                .padded_wire_count = 4,
                .stored_wire_count = 2,
                .padded_to_stored = {0U, 1U, std::nullopt, std::nullopt},
                .representative_padded_indices = {0U, 1U},
            },
        .source_classifications = {std::nullopt, std::nullopt},
        .output_classifications = {std::nullopt, std::nullopt},
    };
}

PayloadCircuit make_wide_payload() {
    PayloadBuilder builder(PayloadShape::wide(kSlots), 3);
    const std::size_t scalar = builder.add_scalar_plaintext(Fp(3));
    const std::size_t zero_scalar =
        builder.add_scalar_plaintext(Fp::zero());
    fhe::SlotVector mask(kSlots);
    fhe::SlotVector bias(kSlots);
    for (std::size_t slot = 0; slot < kSlots; ++slot) {
        mask[slot] = Fp(2 + slot);
        bias[slot] = Fp(41 + 3 * slot);
    }
    const std::size_t mask_id = builder.add_plaintext(std::move(mask));
    const std::size_t bias_id = builder.add_plaintext(std::move(bias));

    const WireId rotated = builder.rotate(0, 5);
    const WireId scaled = builder.mul_plain(rotated, scalar);
    const WireId shifted = builder.add_plain(1, bias_id);
    const WireId product = builder.mul(scaled, shifted);
    const WireId masked = builder.mul_plain(2, mask_id);
    const WireId mixed = builder.add(product, masked);
    const WireId second_product = builder.mul(mixed, product);
    const WireId fanin_three = builder.add(second_product, product);
    const WireId fanin_four = builder.add(fanin_three, masked);
    const WireId fanin_five = builder.add(fanin_four, scaled);
    const WireId live_zero = builder.mul_plain(0, zero_scalar);
    builder.set_outputs({fanin_five,
                         builder.add_plain(second_product, bias_id),
                         builder.rotate(product, 3), masked, live_zero});
    return builder.finish();
}

fhe::SlotVector values(std::size_t lane_count, std::size_t seed) {
    fhe::SlotVector result;
    for (std::size_t lane = 0; lane < lane_count; ++lane) {
        result.emplace_back(seed + 7U * lane + lane * lane);
    }
    return result;
}

fhe::SlotVector wide_values(std::size_t seed) {
    fhe::SlotVector result;
    result.reserve(kSlots);
    for (std::size_t slot = 0; slot < kSlots; ++slot) {
        result.emplace_back(seed + 5U * slot + slot * slot);
    }
    return result;
}

template <fhe::PersistableFheBackend Backend>
std::vector<std::uint8_t> encode_value(
    const typename Backend::EvalContext &eval,
    const fhe::FheValue<Backend> &value) {
    return fhe::encode_fhe_value_record<Backend>(
        eval, value);
}

struct Fixture {
    PayloadCircuit payload;
    LayeredCircuit circuit;
    ReplayMockBackend::Contexts contexts;
    FheEvaluationPlan evaluation;
    std::vector<fhe::SlotVector> clear_inputs;
    std::vector<ReplayMockBackend::Ciphertext> encrypted_inputs;
    PlainTrace plain;
    EncryptedTrace<ReplayMockBackend> compact_reference;
    PayloadCheckpointReplayProblem problem;
};

Fixture make_fixture_for_payload(PayloadCircuit payload) {
    Fixture result;
    result.payload = std::move(payload);
    result.circuit = compile(result.payload);
    result.contexts = ReplayMockBackend::create(MockParameters{
        .slot_count = kSlots,
        .fresh_rns_limbs = 14,
        .bits_per_limb = 60,
    });
    result.evaluation = FheEvaluationPlan::at_evaluation_levels(
        result.circuit, 13, 1, 2);
    result.clear_inputs.reserve(result.payload.input_count);
    for (std::size_t input = 0; input < result.payload.input_count; ++input) {
        result.clear_inputs.push_back(values(
            result.payload.shape.lane_count, 5U + 17U * input));
    }
    result.encrypted_inputs =
        encrypt_laned_payload_inputs<ReplayMockBackend>(
        result.contexts.client, result.payload, result.clear_inputs);
    result.plain = synthesize_trace(result.payload, result.circuit,
                                    result.clear_inputs);
    const std::vector<std::uint64_t> work =
        payload_replay_work_units(result.circuit);
    const std::vector<LayerStorageLayout> storage =
        canonical_trace_storage_layout(result.circuit);
    std::vector<std::size_t> working_limbs(result.circuit.layers.size());
    std::size_t current_limbs =
        result.contexts.eval.parameters.fresh_rns_limbs;
    working_limbs.back() = current_limbs;
    for (std::size_t source = result.circuit.layers.size(); source-- > 1;) {
        const std::size_t output = source - 1U;
        current_limbs -=
            result.evaluation.modulus_switches_after_layer[output];
        working_limbs[output] = current_limbs;
    }

    result.compact_reference =
        evaluate_laned_fhe_trace<ReplayMockBackend>(
        result.contexts.eval, result.payload, result.circuit,
        result.encrypted_inputs, result.evaluation);
    for (std::size_t layer = 0;
         layer < result.compact_reference.layers.size();
         ++layer) {
        for (const auto &value :
             result.compact_reference.layers[layer].wires) {
            if (value.is_encrypted()) {
                CHECK(ReplayMockBackend::rns_limb_count(
                          result.contexts.eval, value.ciphertext()) ==
                      working_limbs[layer]);
            }
        }
    }
    std::vector<PayloadLayerResourceEstimate> resources;
    resources.reserve(result.circuit.layers.size());
    for (std::size_t layer = 0; layer < result.circuit.layers.size();
         ++layer) {
        const auto &reference_layer =
            result.compact_reference.layers[layer];
        const std::size_t limbs = working_limbs[layer];
        std::uint64_t encoded = 0;
        for (const auto &value : reference_layer.wires) {
            encoded = std::max<std::uint64_t>(
                encoded, encode_value<ReplayMockBackend>(
                             result.contexts.eval, value)
                             .size());
        }
        resources.push_back(PayloadLayerResourceEstimate{
            .rns_limb_count = limbs,
            .checkpoint_bytes =
                standalone_checkpoint_layer_artifact_bytes(
                    storage[layer].stored_wire_count,
                    encoded),
            .serialized_ciphertext_bytes = encoded,
            .resident_ciphertext_bytes = encoded + 4096U,
            .replay_work_units = work[layer],
        });
    }
    result.problem = make_payload_checkpoint_replay_problem(
        result.circuit, result.evaluation, resources, 512, 0);
    return result;
}

Fixture make_fixture(std::size_t output_count = 1) {
    return make_fixture_for_payload(make_payload(output_count));
}

struct WideFixture {
    PayloadCircuit payload;
    LayeredCircuit circuit;
    ReplayMockBackend::Contexts contexts;
    FheEvaluationPlan evaluation;
    std::vector<fhe::SlotVector> clear_inputs;
    std::vector<ReplayMockBackend::Ciphertext> encrypted_inputs;
    PlainTrace plain;
    EncryptedTrace<ReplayMockBackend> compact_reference;
    PayloadCheckpointReplayProblem problem;
};

WideFixture make_wide_fixture() {
    WideFixture result;
    result.payload = make_wide_payload();
    result.circuit = compile(result.payload);
    result.contexts = ReplayMockBackend::create(MockParameters{
        .slot_count = kSlots,
        .fresh_rns_limbs = 14,
        .bits_per_limb = 60,
    });
    result.evaluation = FheEvaluationPlan::at_evaluation_levels(
        result.circuit, 13);
    result.clear_inputs = {
        wide_values(7), wide_values(73), wide_values(137)};
    result.encrypted_inputs =
        encrypt_wide_payload_inputs<ReplayMockBackend>(
            result.contexts.client, result.payload, result.clear_inputs);
    result.plain = synthesize_trace(result.payload, result.circuit,
                                    result.clear_inputs);
    result.compact_reference =
        evaluate_wide_fhe_trace_into<ReplayMockBackend>(
        result.contexts.eval, result.payload, result.circuit,
        result.encrypted_inputs, result.evaluation,
        InMemoryTraceSink<ReplayMockBackend>{
            result.contexts.eval});

    const std::vector<std::uint64_t> work =
        payload_replay_work_units(result.circuit);
    const std::vector<LayerWireSupport> support =
        canonical_trace_wire_support(result.circuit);
    const std::vector<LayerStorageLayout> storage =
        canonical_trace_storage_layout(result.circuit);
    std::vector<PayloadLayerResourceEstimate> resources;
    resources.reserve(result.circuit.layers.size());
    for (std::size_t layer = 0; layer < result.circuit.layers.size();
         ++layer) {
        const auto &wires = result.compact_reference.layers[layer].wires;
        CHECK(wires.size() == storage[layer].stored_wire_count);
        CHECK(!wires.empty());
        const auto encrypted = std::find_if(
            wires.begin(), wires.end(),
            [](const auto &value) { return value.is_encrypted(); });
        CHECK(encrypted != wires.end());
        const std::size_t limbs = ReplayMockBackend::rns_limb_count(
            result.contexts.eval, encrypted->ciphertext());
        std::uint64_t encoded = 0;
        for (const auto &value : wires) {
            if (value.is_encrypted()) {
                CHECK(ReplayMockBackend::rns_limb_count(
                          result.contexts.eval, value.ciphertext()) ==
                      limbs);
            }
            encoded = std::max<std::uint64_t>(
                encoded, encode_value<ReplayMockBackend>(
                             result.contexts.eval, value)
                             .size());
        }
        resources.push_back(PayloadLayerResourceEstimate{
            .rns_limb_count = limbs,
            .checkpoint_bytes = standalone_checkpoint_layer_artifact_bytes(
                storage[layer].stored_wire_count, encoded),
            .serialized_ciphertext_bytes = encoded,
            .resident_ciphertext_bytes = encoded + 4096U,
            .replay_work_units = work[layer],
        });
    }
    result.problem = make_payload_checkpoint_replay_problem(
        result.circuit, result.evaluation, resources, 512, 0);
    return result;
}

PayloadCheckpointReplayBudgets budgets(
    PayloadRecomputationFactorLimit recomputation = {100, 1}) {
    return PayloadCheckpointReplayBudgets{
        .max_live_scratch_bytes = std::uint64_t{1} << 30U,
        .max_resident_ciphertext_bytes = std::uint64_t{1} << 30U,
        .max_ciphertexts_per_chunk = 8,
        .max_recomputation_factor = recomputation,
        .reserved_live_scratch_bytes = 4096,
        .reserved_resident_bytes = 2048,
    };
}

PayloadCheckpointReplayExecutionOptions options(
    const std::filesystem::path &directory) {
    return PayloadCheckpointReplayExecutionOptions{
        .directory = directory,
        .min_free_bytes = 1,
        .max_checkpoint_metadata_bytes = 4096,
        .lifecycle = FileTraceSessionLifecycle::IrreversibleNoRetry,
    };
}

std::uint64_t counted_fhe_operations(const OperationCounts &counts) {
    return counts.negate + counts.add + counts.sub + counts.mul_no_relin +
           counts.relinearize + counts.add_plain +
           counts.mul_plain_scalar + counts.mul_plain_vector +
           counts.rotate + counts.mod_switch + counts.logical_ext_add +
           counts.logical_ext_sub + counts.logical_ext_mul +
           counts.logical_ext_mul_plain;
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

laned_detail::FileLanedGkrOptions gkr_options(
    const LayeredCircuit &circuit, const TemporaryDirectory &root,
    const std::string &prefix) {
    laned_detail::FileLanedGkrOptions result;
    for (std::size_t layer : multiplication_layers(circuit)) {
        result.multiplication_scratch.push_back(
            laned_detail::FileLanedMultiplicationScratch{
                layer,
                root.make_child(prefix + std::to_string(layer)),
                FileTraceStoreOptions{
                    .max_total_bytes = std::uint64_t{1} << 30U,
                    .min_free_bytes = 1,
                },
            });
    }
    return result;
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

void test_full_width_laned_bypasses_eager_witness_packing() {
    Fixture fixture =
        make_fixture_for_payload(make_full_width_laned_payload());
    CHECK(fixture.circuit.shape.lane_count ==
          fixture.circuit.shape.slot_count);
    for (std::size_t layer = 1; layer < fixture.circuit.layers.size();
         ++layer) {
        CHECK(laned_witness_packing_layout(fixture.circuit, layer)
                  .logical_ciphertext_count <=
              kEagerLanedPackedCiphertextLimit);
    }
    CHECK(!supports_eager_laned_witness_packing(fixture.circuit));
    const std::vector<LayerStorageLayout> storage =
        canonical_trace_storage_layout(fixture.circuit);
    LanedWitnessMaskCache<ReplayMockBackend> mask_cache(
        fixture.circuit.shape.slot_count,
        fixture.circuit.shape.lane_count);
    CHECK(throws_invalid_argument([&] {
        EagerLanedWitnessLayerBuilder<ReplayMockBackend> builder(
            fixture.contexts.eval, fixture.circuit, 1U, storage.at(1U),
            fixture.problem.layers.at(1U).required_proof_depth + 1U,
            mask_cache);
        (void)builder;
    }));

    const PayloadCheckpointReplayBudgets limits = budgets();
    const PayloadCheckpointReplayPlan plan =
        plan_payload_checkpoint_replay(fixture.problem, limits);
    TemporaryDirectory root;
    PayloadCheckpointReplayExecutionOptions execution =
        options(root.make_child("full-width-replay"));
    execution.eager_laned_witness_packing = true;
    std::vector<fhe::FheValue<ReplayMockBackend>> output;
    const auto replay =
        PayloadCheckpointReplayTrace<ReplayMockBackend>::publish(
            fixture.contexts.eval, fixture.payload, fixture.circuit,
            fixture.encrypted_inputs, fixture.evaluation, fixture.problem,
            limits, plan, std::move(execution), output);

    CHECK(!replay.uses_eager_laned_witness_packing());
    CHECK(replay.report().laned_witness_source_values == 0);
    CHECK(replay.report().laned_witness_logical_values_packed == 0);
    CHECK(replay.report().laned_witness_mask_preparations == 0);
    CHECK(replay.report().laned_witness_mask_cache_hits == 0);
    CHECK(replay.report().laned_witness_prepared_mask_ntt_bytes == 0);
    CHECK(replay.report().laned_witness_peak_mask_cache_ntt_bytes == 0);
    CHECK(replay.report().laned_witness_modulus_switches == 0);
    CHECK(replay.report().laned_witness_plain_multiplications == 0);
    CHECK(replay.report().laned_witness_additions == 0);
    CHECK(replay.report().laned_witness_rotations == 0);
    CHECK(replay.report().laned_witness_packed_ciphertexts == 0);
    CHECK(replay.report().laned_witness_physical_bytes_written == 0);
    CHECK(replay.report().laned_witness_packing_wall_ms == 0.0);
    CHECK(replay.report().laned_witness_packing_cpu_ms == 0.0);
}

void test_laned_witness_packing_reuses_masks_without_rotations() {
    constexpr std::size_t kLanes = 2;
    constexpr std::size_t kChunks = kSlots / kLanes;
    PayloadBuilder payload_builder(
        PayloadShape::laned(kLanes, kSlots), 2U * kChunks);
    std::vector<WireId> outputs;
    outputs.reserve(kChunks);
    for (std::size_t pair = 0; pair < kChunks; ++pair) {
        outputs.push_back(
            payload_builder.mul(2U * pair, 2U * pair + 1U));
    }
    payload_builder.set_outputs(std::move(outputs));
    const PayloadCircuit payload = payload_builder.finish();
    const LayeredCircuit circuit = compile(payload);
    const std::size_t source_layer = circuit.layers.size() - 1U;
    const std::vector<LayerStorageLayout> storage =
        canonical_trace_storage_layout(circuit);
    CHECK(storage.at(source_layer).stored_wire_count == 2U * kChunks);

    auto contexts = ReplayMockBackend::create(MockParameters{
        .slot_count = kSlots,
        .fresh_rns_limbs = 6,
        .bits_per_limb = 60,
    });
    LanedWitnessMaskCache<ReplayMockBackend> mask_cache(kSlots, kLanes);
    EagerLanedWitnessLayerBuilder<ReplayMockBackend> builder(
        contexts.eval, circuit, source_layer, storage.at(source_layer), 3,
        mask_cache);
    const std::size_t packed_rns_limbs = builder.packed_rns_limbs();
    ReplayMockBackend::reset_counts(contexts.eval);
    for (std::size_t source = 0; source < 2U * kChunks; ++source) {
        SlotVector repeated(kSlots, Fp::zero());
        for (std::size_t chunk = 0; chunk < kChunks; ++chunk) {
            for (std::size_t lane = 0; lane < kLanes; ++lane) {
                repeated[chunk * kLanes + lane] =
                    Fp(kLanes * source + lane + 1U);
            }
        }
        builder.append_stored_value(
            FheValue<ReplayMockBackend>::from_ciphertext(
                ReplayMockBackend::encrypt(contexts.client, repeated)));
    }
    std::vector<FheValue<ReplayMockBackend>> packed =
        std::move(builder).finish();
    const LanedWitnessPackingStatistics statistics = builder.statistics();

    CHECK(packed.size() == 2);
    CHECK(statistics.source_values == 2U * kChunks);
    CHECK(statistics.logical_values_packed == 2U * kChunks);
    CHECK(statistics.mask_preparations == kChunks);
    CHECK(statistics.mask_cache_hits == kChunks);
    CHECK(statistics.plain_multiplications == 2U * kChunks);
    CHECK(statistics.additions == 2U * (kChunks - 1U));
    CHECK(statistics.rotations == 0);
    CHECK(statistics.packed_ciphertexts == 2);
    CHECK(statistics.modulus_switches ==
          packed.size() * (6U - packed_rns_limbs));
    CHECK(ReplayMockBackend::counts(contexts.eval).rotate == 0);
    for (std::size_t destination = 0; destination < packed.size();
         ++destination) {
        CHECK(packed[destination].is_encrypted());
        const SlotVector decrypted = ReplayMockBackend::decrypt(
            contexts.client, packed[destination].ciphertext());
        for (std::size_t chunk = 0; chunk < kChunks; ++chunk) {
            const std::size_t source = destination * kChunks + chunk;
            for (std::size_t lane = 0; lane < kLanes; ++lane) {
                CHECK(decrypted[chunk * kLanes + lane] ==
                      Fp(kLanes * source + lane + 1U));
            }
        }
    }
}

void test_sparse_execution_verifies() {
    Fixture fixture = make_fixture();
    const PayloadCheckpointReplayBudgets limits = budgets();
    const PayloadCheckpointReplayPlan plan =
        plan_payload_checkpoint_replay(fixture.problem, limits);
    CHECK(plan.selected.checkpoint_layers ==
          std::vector<std::size_t>({fixture.circuit.layers.size() - 1U}));

    TemporaryDirectory root;
    const std::filesystem::path replay_directory =
        root.make_child("replay");
    std::vector<fhe::FheValue<ReplayMockBackend>> sparse_output;
    auto replay = PayloadCheckpointReplayTrace<ReplayMockBackend>::publish(
        fixture.contexts.eval, fixture.payload, fixture.circuit,
        fixture.encrypted_inputs, fixture.evaluation, fixture.problem,
        limits, plan, options(replay_directory), sparse_output);

    const std::vector<LayerWireSupport> support =
        canonical_trace_wire_support(fixture.circuit);
    const std::vector<LayerStorageLayout> storage =
        canonical_trace_storage_layout(fixture.circuit);
    CHECK(std::any_of(support.begin(), support.end(), [](const auto &layer) {
        return layer.live_wire_count < layer.padded_wire_count;
    }));
    bool has_aliases = false;
    for (std::size_t layer = 0; layer < storage.size(); ++layer) {
        has_aliases = has_aliases ||
                      storage[layer].stored_wire_count <
                          support[layer].live_wire_count;
    }
    CHECK(has_aliases);
    CHECK(support[1].live_wire_count < support[1].padded_wire_count);
    const std::uint64_t framed_before =
        replay.report().gkr_source_reads.framed_record_bytes_read;
    const std::uint64_t encoded_before =
        replay.report().gkr_source_reads.encoded_ciphertext_bytes_read;
    {
        auto reader = replay.active_layer_reader(1);
        laned_detail::LanedAffineStatistics scan;
        laned_detail::affine_detail::scan_source_layer<
            ReplayMockBackend>(
            reader, support[1].padded_wire_count,
            storage[1].stored_wire_count, &scan,
            [](std::size_t, const auto &) {});
        CHECK(reader.serialized_records_read() ==
              storage[1].stored_wire_count);
        CHECK(scan.source_ciphertexts_read ==
              storage[1].stored_wire_count);
        CHECK(scan.source_logical_bytes_read == reader.encoded_bytes_read());
        CHECK(scan.source_framed_record_bytes_read ==
              scan.source_logical_bytes_read +
                  sizeof(std::uint64_t) *
                      reader.serialized_records_read());
        CHECK(scan.peak_live_source_ciphertexts == 1);
    }
    CHECK(replay.report().gkr_source_reads.encoded_ciphertext_bytes_read -
              encoded_before ==
          replay.report().gkr_source_reads.framed_record_bytes_read -
              framed_before -
              sizeof(std::uint64_t) * storage[1].stored_wire_count);
    CHECK(sparse_output.size() == storage.front().stored_wire_count);
    for (std::size_t wire = 0; wire < sparse_output.size(); ++wire) {
        CHECK(encode_value<ReplayMockBackend>(
                  fixture.contexts.eval, sparse_output[wire]) ==
              encode_value<ReplayMockBackend>(
                  fixture.contexts.eval,
                  fixture.compact_reference.layers.front().wires[wire]));
    }
    for (std::size_t layer = 0; layer < support.size(); ++layer) {
        CHECK(fixture.problem.layers[layer].stored_value_count ==
              storage[layer].stored_wire_count);
        CHECK(fixture.problem.layers[layer].virtual_wire_count ==
              support[layer].padded_wire_count);
        CHECK(replay.descriptor().layers[layer].record_count ==
              storage[layer].stored_wire_count);
    }
    CHECK(replay.report().checkpoint_set_published);
    CHECK(replay.report().checkpoint_metadata_physical_bytes == 512);
    const std::uint64_t metadata_identity_bytes =
        127U + 8U * plan.selected.checkpoint_layers.size();
    CHECK(replay.report().peak_checkpoint_metadata_buffer_bytes ==
          512U + metadata_identity_bytes);
    CHECK(replay.report().peak_checkpoint_metadata_buffer_bytes ==
          plan.selected.checkpoint_metadata_validation_buffer_bytes);
    CHECK(replay.report().peak_controlled_resident_bytes >=
          plan.selected.retained_output_peak_resident_bytes +
              replay.report().peak_checkpoint_metadata_buffer_bytes);
    CHECK(replay.report().peak_live_scratch_bytes <=
          limits.max_live_scratch_bytes);
    CHECK(replay.report().peak_controlled_resident_bytes <=
          limits.max_resident_ciphertext_bytes);
    CHECK(replay.report().peak_controlled_resident_bytes <=
          plan.selected.peak_resident_bytes);
    CHECK(replay.report().peak_live_layer_artifacts <= 3);
    CHECK(replay.report().peak_live_layer_artifacts <
          fixture.circuit.layers.size());

    const PublicSetup public_setup =
        make_direct_setup(fixture.payload, fixture.circuit);
    const EvaluationSetup<ReplayMockBackend> evaluation =
        make_packed_evaluation_setup<ReplayMockBackend>(
            public_setup, fixture.contexts.eval);
    const ClientSetup<ReplayMockBackend> client =
        make_client_setup<ReplayMockBackend>(public_setup,
                                             fixture.contexts.client);
    const std::vector<Fpk> point(
        laned_layer_variables(fixture.circuit, 0),
        Fpk::from_base(Fp(17)));
    const SingleClaim claim = make_packed_laned_claim(
        fixture.plain.layers.front(),
        laned_layout(fixture.circuit, 0), point);

    const std::string domain = "test/checkpoint-replay/gkr-parity";
    Transcript replay_transcript(domain);
    laned_detail::FileLanedGkrResult<ReplayMockBackend> sparse_proof;
    try {
        sparse_proof =
            laned_detail::LanedProver<
                ReplayMockBackend,
                PayloadCheckpointReplayTrace<ReplayMockBackend>>(
                fixture.payload, fixture.circuit, replay, evaluation,
                [&] {
                    std::vector<std::size_t> limbs;
                    for (const std::size_t depth :
                         fixture.evaluation
                             .proof_ingress_mult_depth_by_layer) {
                        limbs.push_back(depth + 1U);
                    }
                    return limbs;
                }(),
                claim.point,
                replay_transcript,
                gkr_options(fixture.circuit, root, "multiplication-"))
                .run();
    } catch (const std::exception &error) {
        throw std::runtime_error(std::string("sparse proof: ") +
                                 error.what());
    }

    Transcript verifier_transcript(domain);
    CHECK(laned_detail::verify_encrypted_gkr<ReplayMockBackend>(
        fixture.payload, fixture.circuit, fixture.plain.layers.back(), client,
        TraceProvenance::FheEvaluated, fixture.compact_reference.trace_id,
        claim,
        sparse_proof.proof, verifier_transcript));
    CHECK(replay.report().replay_work_units ==
          plan.selected.replay_work_units);
    CHECK(replay.report().all_payload_artifacts_retired);
    CHECK(replay.report().live_physical_bytes == 0);
    CHECK(replay.report().checkpoint_metadata_bytes_retired == 512);
    CHECK(replay.report().checkpoint_retirement_order ==
          plan.selected.checkpoint_layers);
    CHECK(replay.report().checkpoint_layer_bytes_retired ==
          replay.report().checkpoint_layer_physical_bytes);
    CHECK(replay.report().total_reclaimed_physical_bytes ==
          replay.report().forward.physical_bytes_written +
              replay.report().reverse_replay.physical_bytes_written);
    CHECK(replay.report().forward.physical_validation_bytes_read ==
          replay.report().checkpoint_metadata_physical_bytes);
    CHECK(replay.report().reverse_replay.physical_validation_bytes_read ==
          2U * replay.report().checkpoint_metadata_physical_bytes);
    CHECK(replay.report().reverse_replay.framed_record_bytes_read >=
          replay.report().reverse_replay.encoded_ciphertext_bytes_read);
    CHECK(replay.report().gkr_source_reads.framed_record_bytes_read >
          replay.report().gkr_source_reads.encoded_ciphertext_bytes_read);
    CHECK(regular_file_bytes(replay_directory) == 0);
}

void test_identity_affine_alias_preserves_eager_laned_proof() {
    Fixture fixture =
        make_fixture_for_payload(make_strict_identity_affine_payload());
    PayloadCheckpointReplayBudgets limits = budgets();
    limits.reserved_resident_bytes +=
        eager_laned_witness_packing_resources(fixture.circuit, fixture.problem)
            .resident_workspace_bytes;
    const PayloadCheckpointReplayPlan plan =
        plan_payload_checkpoint_replay(fixture.problem, limits);
    TemporaryDirectory root;
    const std::filesystem::path replay_directory =
        root.make_child("identity-affine-alias");
    PayloadCheckpointReplayExecutionOptions execution =
        options(replay_directory);
    execution.eager_laned_witness_packing = true;
    std::vector<RuntimeProgressEvent> diagnostic_progress_events;
    execution.progress = [&](const RuntimeProgressEvent &event) {
        diagnostic_progress_events.push_back(event);
    };
    std::vector<fhe::FheValue<ReplayMockBackend>> output;
    auto replay = PayloadCheckpointReplayTrace<ReplayMockBackend>::publish(
        fixture.contexts.eval, fixture.payload, fixture.circuit,
        fixture.encrypted_inputs, fixture.evaluation, fixture.problem,
        limits, plan, std::move(execution), output);

    CHECK(replay.uses_eager_laned_witness_packing());
#ifdef _WIN32
    CHECK(replay.report().forward.identity_affine_alias_relations == 0U);
    CHECK(replay.report().forward.identity_affine_alias_fallbacks == 1U);
    CHECK(replay.report().forward.identity_affine_alias_records_reused ==
          0U);
#else
    CHECK(replay.report().forward.identity_affine_alias_relations == 1U);
    CHECK(replay.report().forward.identity_affine_alias_fallbacks == 0U);
    CHECK(replay.report().forward.identity_affine_alias_records_reused ==
          8U);
    CHECK(replay.report()
              .forward.identity_affine_alias_layer_bytes_reused >
          replay.report()
              .forward.identity_affine_alias_unique_bytes_written);
    CHECK(replay.report()
              .forward.identity_affine_alias_unique_bytes_written ==
          file_trace_manifest_bytes(1));
#endif
    std::vector<const RuntimeProgressEvent *> relation_ends;
    for (const RuntimeProgressEvent &event : diagnostic_progress_events) {
        if (event.stage == RuntimeProgressStage::PayloadForwardRelation &&
            event.boundary == RuntimeProgressBoundary::End) {
            relation_ends.push_back(&event);
        }
    }
    CHECK(relation_ends.size() == 5U);
    CHECK(relation_ends[0]->total_steps == 16U);
    CHECK(relation_ends[1]->total_steps == 8U);
    const RuntimeProgressEvent &second_relation = *relation_ends[1];
    CHECK(second_relation.application_read_bytes == 2864U);
    CHECK(second_relation.read_batches == 2U);
    CHECK(second_relation.read_syscalls == 2U);
    CHECK(second_relation.maximum_read_batch_bytes == 1432U);
    CHECK(second_relation.application_write_bytes ==
          1568U + file_trace_manifest_bytes(1));
    CHECK(second_relation.write_batches == 3U);
    CHECK(second_relation.write_syscalls == 3U);
    CHECK(second_relation.maximum_write_batch_bytes == 1560U);
    CHECK(second_relation.prefetch_requests == 0U);
    CHECK(second_relation.prefetch_bytes_requested == 0U);
    CHECK(second_relation.maximum_prefetch_request_bytes == 0U);
    CHECK(second_relation.identity_affine_alias_relations == 0U);

    const RuntimeProgressEvent *alias_relation = nullptr;
    for (const RuntimeProgressEvent *event : relation_ends) {
        if (event->identity_affine_alias_relations != 0U) {
            CHECK(alias_relation == nullptr);
            alias_relation = event;
        }
    }
#ifdef _WIN32
    CHECK(alias_relation == nullptr);
#else
    CHECK(alias_relation != nullptr);
    const std::uint64_t alias_manifest_bytes = file_trace_manifest_bytes(1);
    CHECK(alias_relation->application_read_bytes == 0U);
    CHECK(alias_relation->read_batches == 0U);
    CHECK(alias_relation->read_syscalls == 0U);
    CHECK(alias_relation->maximum_read_batch_bytes == 0U);
    CHECK(alias_relation->prefetch_requests == 0U);
    CHECK(alias_relation->prefetch_bytes_requested == 0U);
    CHECK(alias_relation->prefetch_fallbacks == 0U);
    CHECK(alias_relation->prefetch_seek_disables == 0U);
    CHECK(alias_relation->prefetch_window_bytes == 0U);
    CHECK(alias_relation->maximum_prefetch_request_bytes == 0U);
    CHECK(alias_relation->application_write_bytes == alias_manifest_bytes);
    CHECK(alias_relation->write_batches == 1U);
    CHECK(alias_relation->write_syscalls == 1U);
    CHECK(alias_relation->maximum_write_batch_bytes == alias_manifest_bytes);
    CHECK(alias_relation->capacity_probes == 1U);
    CHECK(alias_relation->authenticated_record_bytes == 0U);
    CHECK(alias_relation->same_process_unhashed_record_bytes == 0U);
    CHECK(alias_relation->record_copy_bytes == 0U);
    CHECK(alias_relation->writeback_submission_attempts == 0U);
    CHECK(alias_relation->writeback_submission_successes == 0U);
    CHECK(alias_relation->writeback_wait_attempts == 0U);
    CHECK(alias_relation->writeback_wait_successes == 0U);
    CHECK(alias_relation->writeback_range_bytes_submitted == 0U);
    CHECK(alias_relation->writeback_range_bytes_waited == 0U);
    CHECK(alias_relation->maximum_writeback_submission_bytes == 0U);
    CHECK(alias_relation->writeback_window_bytes == 0U);
    CHECK(alias_relation->maximum_unwaited_writeback_range_bytes == 0U);
    CHECK(alias_relation->writeback_files_submit_only == 0U);
    CHECK(alias_relation->writeback_drains == 0U);
    CHECK(alias_relation->writeback_drain_range_bytes == 0U);
    CHECK(alias_relation->writeback_drains_skipped == 0U);
    CHECK(alias_relation->writeback_range_bytes_without_explicit_wait == 0U);
    CHECK(alias_relation->positional_write_calls == 0U);
    CHECK(alias_relation->positional_write_bytes == 0U);
    CHECK(alias_relation->identity_affine_alias_fallbacks == 0U);
    CHECK(alias_relation->identity_affine_alias_records_reused == 8U);
    CHECK(alias_relation->identity_affine_alias_unique_bytes_written ==
          alias_manifest_bytes);
#endif
    CHECK(output.size() ==
          fixture.compact_reference.layers.front().wires.size());
    for (std::size_t wire = 0; wire < output.size(); ++wire) {
        CHECK(encode_value<ReplayMockBackend>(
                  fixture.contexts.eval, output[wire]) ==
              encode_value<ReplayMockBackend>(
                  fixture.contexts.eval,
                  fixture.compact_reference.layers.front().wires[wire]));
    }

    const PublicSetup public_setup =
        make_direct_setup(fixture.payload, fixture.circuit);
    const EvaluationSetup<ReplayMockBackend> evaluation =
        make_packed_evaluation_setup<ReplayMockBackend>(
            public_setup, fixture.contexts.eval);
    const ClientSetup<ReplayMockBackend> client =
        make_client_setup<ReplayMockBackend>(public_setup,
                                             fixture.contexts.client);
    const std::vector<Fpk> point(
        laned_layer_variables(fixture.circuit, 0),
        Fpk::from_base(Fp(23)));
    const SingleClaim claim = make_packed_laned_claim(
        fixture.plain.layers.front(),
        laned_layout(fixture.circuit, 0), point);
    const std::string domain =
        "test/checkpoint-replay/identity-affine-alias";
    Transcript prover_transcript(domain);
    const auto proof =
        laned_detail::LanedProver<
            ReplayMockBackend,
            PayloadCheckpointReplayTrace<ReplayMockBackend>>(
            fixture.payload, fixture.circuit, replay, evaluation,
            [&] {
                std::vector<std::size_t> limbs;
                for (const std::size_t depth :
                     fixture.evaluation
                         .proof_ingress_mult_depth_by_layer) {
                    limbs.push_back(depth + 1U);
                }
                return limbs;
            }(),
            claim.point, prover_transcript,
            gkr_options(fixture.circuit, root, "identity-multiplication-"))
            .run();
    Transcript verifier_transcript(domain);
    CHECK(laned_detail::verify_encrypted_gkr<ReplayMockBackend>(
        fixture.payload, fixture.circuit, fixture.plain.layers.back(), client,
        TraceProvenance::FheEvaluated, fixture.compact_reference.trace_id,
        claim, proof.proof, verifier_transcript));
    CHECK(replay.report().all_payload_artifacts_retired);
    CHECK(replay.report().live_physical_bytes == 0);
    CHECK(replay.report().total_reclaimed_physical_bytes ==
          replay.report().forward.physical_bytes_written);
    CHECK(regular_file_bytes(replay_directory) == 0);
}

void test_identity_affine_alias_predicate_rejects_semantic_changes() {
    const auto qualifies = [](const auto &fixture) {
        return checkpoint_replay_execution_detail::
            qualifies_stored_identity_affine_alias(fixture.candidate());
    };
    const IdentityAffineAliasPredicateFixture identity =
        identity_affine_alias_candidate();
    CHECK(identity.source_descriptor.dimensions.padded_size !=
          identity.output_descriptor.dimensions.padded_size);
    CHECK(qualifies(identity));

    {
        auto changed = identity;
        std::get<AffineLayer>(changed.relation).gates[0].constant = Fp(9);
        CHECK(!qualifies(changed));
    }
    {
        auto changed = identity;
        std::get<AffineLayer>(changed.relation)
            .gates[0]
            .terms[0]
            .coefficient = Fp(2);
        CHECK(!qualifies(changed));
    }
    {
        auto changed = identity;
        std::get<AffineLayer>(changed.relation)
            .gates[0]
            .terms[0]
            .rotation = 1;
        CHECK(!qualifies(changed));
    }
    {
        auto changed = identity;
        changed.output_classifications[0] =
            fhe::PublicPlaintext::from_scalar(Fp::one());
        CHECK(!qualifies(changed));
    }
    {
        auto changed = identity;
        ++changed.output_descriptor.required_mult_depth;
        CHECK(!qualifies(changed));
    }
    {
        auto changed = identity;
        ++changed.output_resources.rns_limb_count;
        CHECK(!qualifies(changed));
    }
    {
        auto changed = identity;
        changed.output_resources.modulus_switches_after_layer = 1;
        CHECK(!qualifies(changed));
    }
}

void test_output_only_execution_retires_every_layer() {
    WideFixture fixture = make_wide_fixture();
    PayloadCheckpointReplayBudgets limits = budgets();
    limits.selection_objective =
        PayloadCheckpointSelectionObjective::OutputOnlyAdjacentLayers;
    const PayloadCheckpointReplayPlan plan =
        plan_payload_checkpoint_replay(fixture.problem, limits);
    const CertifiedPayloadCheckpointReplayStatic certified =
        certify_payload_checkpoint_replay_static(
            fixture.payload,
            derive_certified_canonical_trace_layout(fixture.circuit),
            fixture.evaluation, fixture.problem, limits, plan);

    TemporaryDirectory root;
    const std::filesystem::path output_directory =
        root.make_child("output-only");
    std::vector<fhe::FheValue<ReplayMockBackend>> output;
    auto evaluated = PayloadCheckpointReplayTrace<
        ReplayMockBackend>::publish_output_only_certified(
        fixture.contexts.eval, certified, fixture.encrypted_inputs,
        options(output_directory), output);

    CHECK(evaluated.is_output_only());
    CHECK(!evaluated.uses_eager_laned_witness_packing());
    CHECK(!evaluated.report().checkpoint_set_published);
    CHECK(plan.selected.checkpoint_layers.empty());
    CHECK(plan.selected.checkpoint_bytes == 0);
    CHECK(evaluated.report().checkpoint_metadata_physical_bytes == 0);
    CHECK(evaluated.report().checkpoint_layer_physical_bytes == 0);
    CHECK(evaluated.report().replay_work_units == 0);
    CHECK(evaluated.report().reverse_replay.physical_bytes_written == 0);
    CHECK(evaluated.report().segments.empty());
    CHECK(evaluated.report().all_payload_artifacts_retired);
    CHECK(evaluated.report().live_physical_bytes == 0);
    CHECK(evaluated.report().peak_live_layer_artifacts <= 2);
    CHECK(regular_file_bytes(output_directory) == 0);

    CHECK(output.size() ==
          fixture.compact_reference.layers.front().wires.size());
    for (std::size_t wire = 0; wire < output.size(); ++wire) {
        CHECK(encode_value<ReplayMockBackend>(
                  fixture.contexts.eval, output[wire]) ==
              encode_value<ReplayMockBackend>(
                  fixture.contexts.eval,
                  fixture.compact_reference.layers.front().wires[wire]));
    }
    CHECK(throws_exception([&] { (void)evaluated.layer_reader(1); }));
}

void test_proof_ingress_is_published_once() {
    Fixture fixture = make_fixture();
    std::fill(
        fixture.evaluation.proof_ingress_mult_depth_by_layer.begin(),
        fixture.evaluation.proof_ingress_mult_depth_by_layer.end(), 1U);
    fixture.evaluation.proof_ingress_mult_depth_by_layer.front() =
        fixture.evaluation.trace.required_mult_depth_by_layer.front();
    fixture.evaluation.validate(fixture.circuit);
    fixture.problem = make_payload_checkpoint_replay_problem(
        fixture.circuit, fixture.evaluation,
        [&]() {
            std::vector<PayloadLayerResourceEstimate> resources;
            resources.reserve(fixture.problem.layers.size());
            for (const PayloadReplayLayer &layer : fixture.problem.layers) {
                resources.push_back(PayloadLayerResourceEstimate{
                    .rns_limb_count = layer.rns_limb_count,
                    .checkpoint_bytes = layer.checkpoint_bytes,
                    .serialized_ciphertext_bytes =
                        layer.serialized_ciphertext_bytes,
                    .resident_ciphertext_bytes =
                        layer.resident_ciphertext_bytes,
                    .replay_work_units = layer.replay_work_units,
                    .prefer_post_modulus_switch_checkpoint =
                        layer.preferred_checkpoint,
                });
            }
            return resources;
        }(),
        512, 0);
    const PayloadCheckpointReplayBudgets limits = budgets();
    const PayloadCheckpointReplayPlan plan =
        plan_payload_checkpoint_replay(fixture.problem, limits);

    TemporaryDirectory root;
    const std::filesystem::path replay_directory =
        root.make_child("proof-ingress-once");
    std::vector<RuntimeProgressEvent> progress_events;
    PayloadCheckpointReplayExecutionOptions replay_options =
        options(replay_directory);
    replay_options.progress = [&](const RuntimeProgressEvent &event) {
        progress_events.push_back(event);
    };
    std::vector<fhe::FheValue<ReplayMockBackend>> output;
    auto replay = PayloadCheckpointReplayTrace<ReplayMockBackend>::publish(
        fixture.contexts.eval, fixture.payload, fixture.circuit,
        fixture.encrypted_inputs, fixture.evaluation, fixture.problem,
        limits, plan, std::move(replay_options), output);
    for (std::size_t layer = 0;
         layer < replay.descriptor().layers.size(); ++layer) {
        CHECK(replay.descriptor().layers[layer].required_mult_depth ==
              (layer == 0
                   ? fixture.evaluation.trace
                         .required_mult_depth_by_layer.front()
                   : 1U));
    }
    (void)replay.retire_layer(0);

    const std::vector<LayerWireSupport> support =
        canonical_trace_wire_support(fixture.circuit);
    const std::vector<LayerStorageLayout> storage =
        canonical_trace_storage_layout(fixture.circuit);
    std::uint64_t expected_ciphertexts = 0;
    std::uint64_t expected_switches = 0;
    std::size_t public_zeros = 0;
    ReplayMockBackend::reset_counts(fixture.contexts.eval);
    for (std::size_t layer = 1; layer < support.size(); ++layer) {
        const std::size_t encrypted_count = static_cast<std::size_t>(
            std::count_if(
                fixture.compact_reference.layers[layer].wires.begin(),
                fixture.compact_reference.layers[layer].wires.end(),
                [](const auto &value) { return value.is_encrypted(); }));
        expected_ciphertexts += encrypted_count;
        expected_switches +=
            encrypted_count *
            (fixture.problem.layers[layer].rns_limb_count - 2U);

        {
            auto active = replay.active_layer_reader(layer);
            const std::uint64_t switches_after_publication =
                ReplayMockBackend::counts(fixture.contexts.eval).mod_switch;
            std::size_t live = 0;
            while (auto record = active.next()) {
                CHECK(record->padded_index ==
                      storage[layer]
                          .representative_padded_index_of(live));
                const fhe::SlotVector expected = expand_for_encryption(
                    fixture.payload.shape,
                    fixture.plain.layers[layer][record->padded_index]);
                if (record->value.is_encrypted()) {
                    CHECK(ReplayMockBackend::remaining_mult_depth(
                              fixture.contexts.eval,
                              record->value.ciphertext()) == 1);
                    CHECK(record->value.ciphertext().slots == expected);
                } else {
                    CHECK(record->value.plaintext().materialize(kSlots) ==
                          expected);
                }
                ++live;
            }
            CHECK(live == storage[layer].stored_wire_count);

            active.rewind();
            while (active.next()) {
            }
            CHECK(ReplayMockBackend::counts(fixture.contexts.eval)
                      .mod_switch == switches_after_publication);
        }

        const std::uint64_t operations_before_padded_scan =
            counted_fhe_operations(
                ReplayMockBackend::counts(fixture.contexts.eval));
        {
            auto padded = replay.layer_reader(layer);
            while (auto value = padded.next()) {
                if (value->is_public_zero()) {
                    ++public_zeros;
                }
            }
        }
        CHECK(counted_fhe_operations(
                  ReplayMockBackend::counts(fixture.contexts.eval)) ==
              operations_before_padded_scan);
        const FileTraceLayerRetirementReport retired =
            replay.retire_layer(layer);
        CHECK(retired.reclaimed_physical_bytes > 0);
        CHECK(replay.report()
                  .segments[layer - 1U]
                  .proof_ingress_bytes_retired_after_use > 0);
    }
    CHECK(public_zeros > 0);
    CHECK(replay.report().proof_ingress_ciphertexts ==
          expected_ciphertexts);
    CHECK(replay.report().proof_ingress_modulus_switches ==
          expected_switches);
    std::uint64_t ingress_progress_work = 0;
    std::size_t ingress_progress_begins = 0;
    std::size_t ingress_progress_ends = 0;
    for (const RuntimeProgressEvent &event : progress_events) {
        if (event.stage != RuntimeProgressStage::PayloadProofIngress) {
            continue;
        }
        if (event.boundary == RuntimeProgressBoundary::Begin) {
            ++ingress_progress_begins;
            ingress_progress_work += event.work_units;
        } else {
            ++ingress_progress_ends;
        }
    }
    CHECK(ingress_progress_begins == support.size() - 1U);
    CHECK(ingress_progress_ends == ingress_progress_begins);
    CHECK(ingress_progress_work == expected_switches);
    std::optional<std::size_t> active_relation_total;
    std::size_t relation_updates = 0;
    std::size_t last_relation_progress = 0;
    double last_relation_wall_ms = 0.0;
    std::uint64_t last_relation_read_bytes = 0;
    std::uint64_t last_relation_write_bytes = 0;
    bool saw_live_relation_attribution = false;
    bool saw_identity_alias_publication_attribution = false;
    for (const RuntimeProgressEvent &event : progress_events) {
        if (event.stage != RuntimeProgressStage::PayloadForwardRelation &&
            event.stage != RuntimeProgressStage::PayloadReplayRelation) {
            continue;
        }
        if (event.boundary == RuntimeProgressBoundary::Begin) {
            CHECK(!active_relation_total);
            CHECK(event.total_steps > 0);
            active_relation_total = event.total_steps;
            relation_updates = 0;
            last_relation_progress = 0;
            last_relation_wall_ms = 0.0;
            last_relation_read_bytes = 0;
            last_relation_write_bytes = 0;
        } else if (event.boundary == RuntimeProgressBoundary::Update) {
            CHECK(active_relation_total);
            CHECK(event.total_steps == *active_relation_total);
            CHECK(event.completed_steps > last_relation_progress);
            CHECK(event.completed_steps <= *active_relation_total);
            last_relation_progress = event.completed_steps;
            ++relation_updates;
            CHECK(relation_updates <= 16);
            CHECK(event.phase_wall_ms > 0.0);
            CHECK(event.phase_wall_ms >= last_relation_wall_ms);
            CHECK(event.application_read_bytes >= last_relation_read_bytes);
            CHECK(event.application_write_bytes >= last_relation_write_bytes);
            CHECK(event.storage_wait_wall_ms + 1e-6 >=
                  event.storage_read_wall_ms +
                      event.storage_write_wall_ms +
                      event.prefetch_wall_ms +
                      event.writeback_submission_wall_ms +
                      event.writeback_wait_wall_ms);
            if (event.fhe_wall_ms > 0.0 &&
                event.deserialization_wall_ms > 0.0 &&
                event.read_batches > 0 && event.read_syscalls > 0 &&
                event.application_read_bytes > 0 &&
                event.serialization_wall_ms > 0.0) {
                saw_live_relation_attribution = true;
            }
            last_relation_wall_ms = event.phase_wall_ms;
            last_relation_read_bytes = event.application_read_bytes;
            last_relation_write_bytes = event.application_write_bytes;
        } else if (event.boundary == RuntimeProgressBoundary::End) {
            CHECK(active_relation_total);
            CHECK(event.completed_steps == *active_relation_total);
            // Updates are rate-limited snapshots rather than a required final
            // boundary.  In particular, an identity alias can complete without
            // entering the record loop at all; the End event is authoritative.
            CHECK(last_relation_progress <= *active_relation_total);
            CHECK(event.phase_wall_ms >= last_relation_wall_ms);
            CHECK(event.application_read_bytes >= last_relation_read_bytes);
            CHECK(event.application_write_bytes >= last_relation_write_bytes);
            if (event.identity_affine_alias_relations != 0) {
                CHECK(event.application_write_bytes > 0);
                CHECK(event.write_batches > 0);
                CHECK(event.write_syscalls > 0);
                CHECK(event.storage_write_wall_ms > 0.0);
                CHECK(event.identity_affine_alias_unique_bytes_written ==
                      event.application_write_bytes);
                saw_identity_alias_publication_attribution = true;
            }
            active_relation_total.reset();
        }
    }
    CHECK(!active_relation_total);
    CHECK(saw_live_relation_attribution);
    CHECK(saw_identity_alias_publication_attribution);
    std::uint64_t expected_replay_switches = 0;
    for (const PayloadReplaySegment &segment :
         plan.reverse_gkr_segments) {
        for (std::size_t output = segment.checkpoint_layer;
             output-- > segment.required_source_layer;) {
            expected_replay_switches +=
                storage[output].stored_wire_count *
                fixture.evaluation.modulus_switches_after_layer[output];
        }
    }
    CHECK(ReplayMockBackend::counts(fixture.contexts.eval).mod_switch ==
          expected_switches + expected_replay_switches);
    CHECK(replay.report().proof_ingress_physical_bytes_written ==
          replay.report().proof_ingress_physical_bytes_retired);
    CHECK(replay.report().all_payload_artifacts_retired);
    CHECK(replay.report().live_physical_bytes == 0);
    CHECK(regular_file_bytes(replay_directory) == 0);
}

void test_same_writer_handoff_avoids_artifact_rescans() {
    Fixture fixture = make_fixture();
    const PayloadCheckpointReplayBudgets limits = budgets();
    const PayloadCheckpointReplayPlan plan =
        plan_payload_checkpoint_replay(fixture.problem, limits);
    CHECK(plan.selected.feasible());

    TemporaryDirectory root;
    const std::filesystem::path replay_directory =
        root.make_child("fresh-open-validation");
    std::vector<fhe::FheValue<CountingReplayMockBackend>> output;
    CountingReplayMockBackend::storage_deserialize_calls = 0;
    auto replay =
        PayloadCheckpointReplayTrace<CountingReplayMockBackend>::publish(
            fixture.contexts.eval, fixture.payload, fixture.circuit,
            fixture.encrypted_inputs, fixture.evaluation, fixture.problem,
            limits, plan, options(replay_directory), output);

    const PayloadCheckpointReplayIoReport &io = replay.report().forward;
    CHECK(io.physical_validation_bytes_read ==
          replay.report().checkpoint_metadata_physical_bytes);
    CHECK(io.framed_record_bytes_read >=
          io.encoded_ciphertext_bytes_read);
    const std::uint64_t framing_bytes =
        io.framed_record_bytes_read - io.encoded_ciphertext_bytes_read;
    CHECK(framing_bytes % sizeof(std::uint64_t) == 0);
    const std::uint64_t records_read =
        framing_bytes / sizeof(std::uint64_t);
    CHECK(records_read > 0);
    // Every decode corresponds to a ciphertext the evaluator actually read.
    // The same-writer handoff transfers exact offsets and file identities and
    // performs no immediate full-artifact scan.
    CHECK(CountingReplayMockBackend::storage_deserialize_calls ==
          records_read);

    (void)replay.retire_layer(0);
    {
        auto source = replay.active_layer_reader(1);
        while (source.next()) {
        }
    }
    CountingReplayMockBackend::storage_deserialize_calls = 0;
    (void)replay.retire_layer(1);
    CHECK(CountingReplayMockBackend::storage_deserialize_calls == 0);
}

void test_proof_ingress_transient_peak_fails_closed() {
    Fixture fixture = make_fixture();
    std::fill(
        fixture.evaluation.proof_ingress_mult_depth_by_layer.begin(),
        fixture.evaluation.proof_ingress_mult_depth_by_layer.end(), 1U);
    fixture.evaluation.proof_ingress_mult_depth_by_layer.front() =
        fixture.evaluation.trace.required_mult_depth_by_layer.front();
    fixture.problem = make_payload_checkpoint_replay_problem(
        fixture.circuit, fixture.evaluation,
        [&]() {
            std::vector<PayloadLayerResourceEstimate> resources;
            resources.reserve(fixture.problem.layers.size());
            for (const PayloadReplayLayer &layer : fixture.problem.layers) {
                resources.push_back(PayloadLayerResourceEstimate{
                    .rns_limb_count = layer.rns_limb_count,
                    .checkpoint_bytes = layer.checkpoint_bytes,
                    .serialized_ciphertext_bytes =
                        layer.serialized_ciphertext_bytes,
                    .resident_ciphertext_bytes =
                        layer.resident_ciphertext_bytes,
                    .replay_work_units = layer.replay_work_units,
                    .prefer_post_modulus_switch_checkpoint =
                        layer.preferred_checkpoint,
                });
            }
            return resources;
        }(),
        512, 0);
    PayloadCheckpointReplayBudgets limits = budgets();
    const PayloadCheckpointReplayPlan admitted =
        plan_payload_checkpoint_replay(fixture.problem, limits);
    CHECK(admitted.selected.proof_ingress_artifact_bytes_upper_bound > 0);
    CHECK(admitted.selected.proof_ingress_peak_live_scratch_bytes <=
          admitted.selected.peak_live_scratch_bytes);
    limits.max_live_scratch_bytes =
        admitted.selected.proof_ingress_peak_live_scratch_bytes - 1U;
    CHECK(throws_invalid_argument([&] {
        (void)plan_payload_checkpoint_replay(fixture.problem, limits);
    }));
}

void test_natural_level_proof_ingress_aliases() {
    Fixture fixture = make_fixture();
    const PayloadCheckpointReplayBudgets limits = budgets();
    const PayloadCheckpointReplayPlan plan =
        plan_payload_checkpoint_replay(fixture.problem, limits);
    CHECK(plan.selected.proof_ingress_artifact_bytes_upper_bound == 0);

    TemporaryDirectory root;
    const std::filesystem::path replay_directory =
        root.make_child("proof-ingress-alias");
    std::vector<RuntimeProgressEvent> progress_events;
    PayloadCheckpointReplayExecutionOptions replay_options =
        options(replay_directory);
    replay_options.progress = [&](const RuntimeProgressEvent &event) {
        progress_events.push_back(event);
    };
    std::vector<fhe::FheValue<ReplayMockBackend>> output;
    auto replay = PayloadCheckpointReplayTrace<ReplayMockBackend>::publish(
        fixture.contexts.eval, fixture.payload, fixture.circuit,
        fixture.encrypted_inputs, fixture.evaluation, fixture.problem,
        limits, plan, std::move(replay_options), output);
    (void)replay.retire_layer(0);
    ReplayMockBackend::reset_counts(fixture.contexts.eval);
    for (std::size_t layer = 1; layer < fixture.circuit.layers.size();
         ++layer) {
        {
            auto reader = replay.active_layer_reader(layer);
            while (reader.next()) {
            }
            reader.rewind();
            while (reader.next()) {
            }
        }
        const FileTraceLayerRetirementReport retired =
            replay.retire_layer(layer);
        CHECK(replay.report()
                  .segments[layer - 1U]
                  .proof_ingress_bytes_retired_after_use == 0);
        CHECK(retired.reclaimed_physical_bytes > 0);
    }
    CHECK(replay.report().proof_ingress_ciphertexts == 0);
    CHECK(replay.report().proof_ingress_physical_bytes_written == 0);
    CHECK(replay.report().proof_ingress_physical_bytes_retired == 0);
    CHECK(replay.report().all_payload_artifacts_retired);

    std::size_t ingress_begins = 0;
    std::size_t ingress_ends = 0;
    for (std::size_t index = 0; index < progress_events.size(); ++index) {
        const RuntimeProgressEvent &event = progress_events[index];
        if (event.stage != RuntimeProgressStage::PayloadProofIngress) {
            continue;
        }
        CHECK(event.work_units == 0);
        if (event.boundary == RuntimeProgressBoundary::Begin) {
            ++ingress_begins;
            CHECK(index > 0);
            CHECK(progress_events[index - 1U].stage ==
                  RuntimeProgressStage::PayloadReplaySegment);
            CHECK(progress_events[index - 1U].boundary ==
                  RuntimeProgressBoundary::End);
        } else {
            ++ingress_ends;
        }
    }
    CHECK(ingress_begins == fixture.circuit.layers.size() - 1U);
    CHECK(ingress_ends == ingress_begins);
}

void test_failed_publication_cleans_owned_root() {
    Fixture fixture = make_fixture();
    const PayloadCheckpointReplayBudgets limits = budgets();
    const PayloadCheckpointReplayPlan plan =
        plan_payload_checkpoint_replay(fixture.problem, limits);

    TemporaryDirectory root;
    const std::filesystem::path replay_directory =
        root.make_child("failed-publication");
    PayloadCheckpointReplayExecutionOptions failed =
        options(replay_directory);
    failed.min_free_bytes = std::numeric_limits<std::uint64_t>::max();
    std::vector<fhe::FheValue<ReplayMockBackend>> output;
    CHECK(throws_exception([&] {
        (void)PayloadCheckpointReplayTrace<ReplayMockBackend>::publish(
            fixture.contexts.eval, fixture.payload, fixture.circuit,
            fixture.encrypted_inputs, fixture.evaluation, fixture.problem,
            limits, plan, failed, output);
    }));
    CHECK(std::filesystem::is_empty(replay_directory));
    CHECK(output.empty());
}

void test_complete_output_can_exceed_relation_chunk() {
    Fixture fixture = make_fixture(4);
    PayloadCheckpointReplayBudgets limits = budgets();
    limits.max_ciphertexts_per_chunk = 2;
    const PayloadCheckpointReplayPlan plan =
        plan_payload_checkpoint_replay(fixture.problem, limits);
    CHECK(plan.selected.chunk_ciphertexts == 2);
    CHECK(fixture.problem.layers.front().stored_value_count >
          plan.selected.chunk_ciphertexts);

    TemporaryDirectory root;
    const std::filesystem::path replay_directory =
        root.make_child("output-larger-than-chunk");
    std::vector<fhe::FheValue<ReplayMockBackend>> output;
    auto replay = PayloadCheckpointReplayTrace<ReplayMockBackend>::publish(
        fixture.contexts.eval, fixture.payload, fixture.circuit,
        fixture.encrypted_inputs, fixture.evaluation, fixture.problem,
        limits, plan, options(replay_directory), output);
    CHECK(output.size() ==
          fixture.problem.layers.front().stored_value_count);
    CHECK(replay.report().peak_controlled_resident_bytes >=
          plan.selected.retained_output_peak_resident_bytes);
}

void test_metadata_preflight_is_pristine_and_does_no_fhe_work() {
    Fixture fixture = make_fixture();
    const PayloadCheckpointReplayBudgets limits = budgets();

    const auto attempt = [&](const std::string &name,
                             PayloadCheckpointReplayProblem problem,
                             std::uint64_t metadata_cap) {
        const PayloadCheckpointReplayPlan plan =
            plan_payload_checkpoint_replay(problem, limits);
        TemporaryDirectory root;
        const std::filesystem::path replay_directory =
            root.make_child(name);
        PayloadCheckpointReplayExecutionOptions invalid =
            options(replay_directory);
        invalid.max_checkpoint_metadata_bytes = metadata_cap;
        std::vector<fhe::FheValue<ReplayMockBackend>> output;
        ReplayMockBackend::reset_counts(fixture.contexts.eval);
        CHECK(throws_invalid_argument([&] {
            (void)PayloadCheckpointReplayTrace<ReplayMockBackend>::publish(
                fixture.contexts.eval, fixture.payload, fixture.circuit,
                fixture.encrypted_inputs, fixture.evaluation, problem,
                limits, plan, invalid, output);
        }));
        CHECK(counted_fhe_operations(
                  ReplayMockBackend::counts(fixture.contexts.eval)) == 0);
        CHECK(std::filesystem::is_empty(replay_directory));
        CHECK(output.empty());
    };

    attempt("metadata-cap", fixture.problem, 511);
    PayloadCheckpointReplayProblem undersized = fixture.problem;
    undersized.checkpoint_set_fixed_bytes = 1;
    undersized.checkpoint_set_bytes_per_layer = 0;
    attempt("metadata-identity", std::move(undersized), 4096);
}

void test_destructive_lifecycle_must_be_explicit() {
    Fixture fixture = make_fixture();
    const PayloadCheckpointReplayBudgets limits = budgets();
    const PayloadCheckpointReplayPlan plan =
        plan_payload_checkpoint_replay(fixture.problem, limits);
    TemporaryDirectory root;
    const std::filesystem::path replay_directory =
        root.make_child("lifecycle");
    PayloadCheckpointReplayExecutionOptions invalid =
        options(replay_directory);
    invalid.lifecycle = FileTraceSessionLifecycle::PreserveForRetry;
    std::vector<fhe::FheValue<ReplayMockBackend>> output;
    CHECK(throws_invalid_argument([&] {
        (void)PayloadCheckpointReplayTrace<ReplayMockBackend>::publish(
            fixture.contexts.eval, fixture.payload, fixture.circuit,
            fixture.encrypted_inputs, fixture.evaluation, fixture.problem,
            limits, plan, invalid, output);
    }));
    CHECK(std::filesystem::is_empty(replay_directory));
    CHECK(output.empty());
}

void test_metadata_corruption_rejects_before_replay() {
    Fixture fixture = make_fixture();
    const PayloadCheckpointReplayBudgets limits = budgets();
    const PayloadCheckpointReplayPlan plan =
        plan_payload_checkpoint_replay(fixture.problem, limits);

    TemporaryDirectory root;
    const std::filesystem::path replay_directory =
        root.make_child("metadata-corruption");
    std::vector<fhe::FheValue<ReplayMockBackend>> output;
    auto replay =
        PayloadCheckpointReplayTrace<ReplayMockBackend>::publish(
            fixture.contexts.eval, fixture.payload, fixture.circuit,
            fixture.encrypted_inputs, fixture.evaluation, fixture.problem,
            limits, plan, options(replay_directory), output);

    const std::filesystem::path metadata =
        replay_directory / "checkpoint-set.bin";
    std::fstream file(metadata,
                      std::ios::binary | std::ios::in | std::ios::out);
    char byte = 0;
    file.read(&byte, 1);
    byte ^= 1;
    file.seekp(0);
    file.write(&byte, 1);
    file.close();
    CHECK(file.good());

    const std::uint64_t live_before = replay.report().live_physical_bytes;
    CHECK(throws_exception([&] { (void)replay.layer_reader(1); }));
    CHECK(replay.report().live_physical_bytes == live_before);
    CHECK(replay.report().checkpoint_retirement_order.empty());
}

void test_plan_mismatch_is_pristine() {
    Fixture fixture = make_fixture();
    const PayloadCheckpointReplayBudgets limits = budgets();
    const PayloadCheckpointReplayPlan admitted =
        plan_payload_checkpoint_replay(fixture.problem, limits);
    TemporaryDirectory root;
    const auto attempt = [&](std::string_view name,
                             PayloadCheckpointReplayPlan plan) {
        const std::filesystem::path replay_directory =
            root.make_child(std::string(name));
        std::vector<fhe::FheValue<ReplayMockBackend>> output;
        CHECK(throws_invalid_argument([&] {
            (void)PayloadCheckpointReplayTrace<ReplayMockBackend>::publish(
                fixture.contexts.eval, fixture.payload, fixture.circuit,
                fixture.encrypted_inputs, fixture.evaluation,
                fixture.problem, limits, plan, options(replay_directory),
                output);
        }));
        CHECK(std::filesystem::is_empty(replay_directory));
        CHECK(output.empty());
    };

    PayloadCheckpointReplayPlan chunk = admitted;
    --chunk.selected.chunk_ciphertexts;
    attempt("pristine-chunk", std::move(chunk));

    PayloadCheckpointReplayPlan metadata = admitted;
    ++metadata.selected.checkpoint_metadata_validation_buffer_bytes;
    attempt("pristine-metadata", std::move(metadata));
}

void test_execution_rejects_unbound_natural_rns_levels() {
    Fixture fixture = make_fixture();
    for (PayloadReplayLayer &layer : fixture.problem.layers) {
        ++layer.rns_limb_count;
    }
    fixture.problem.validate();
    const PayloadCheckpointReplayBudgets limits = budgets();
    const PayloadCheckpointReplayPlan plan =
        plan_payload_checkpoint_replay(fixture.problem, limits);

    TemporaryDirectory root;
    const std::filesystem::path replay_directory =
        root.make_child("unbound-natural-rns");
    std::vector<fhe::FheValue<ReplayMockBackend>> output;
    ReplayMockBackend::reset_counts(fixture.contexts.eval);
    CHECK(throws_invalid_argument([&] {
        (void)PayloadCheckpointReplayTrace<ReplayMockBackend>::publish(
            fixture.contexts.eval, fixture.payload, fixture.circuit,
            fixture.encrypted_inputs, fixture.evaluation, fixture.problem,
            limits, plan, options(replay_directory), output);
    }));
    CHECK(counted_fhe_operations(
              ReplayMockBackend::counts(fixture.contexts.eval)) == 0);
    CHECK(std::filesystem::is_empty(replay_directory));
    CHECK(output.empty());
}

void test_cached_relation_chunk_geometry_matches_and_validates() {
    WideFixture fixture = make_wide_fixture();
    const CertifiedCanonicalTraceLayout trace_layout =
        derive_certified_canonical_trace_layout(fixture.circuit);
    const std::size_t derived =
        minimum_payload_checkpoint_relation_chunk_ciphertexts(
            fixture.circuit);
    const std::size_t cached =
        minimum_payload_checkpoint_relation_chunk_ciphertexts(
            trace_layout);
    CHECK(cached == derived);
    validate_payload_checkpoint_relation_chunk_capacity(
        trace_layout, cached);
    CHECK(throws_invalid_argument([&] {
        validate_payload_checkpoint_relation_chunk_capacity(
            trace_layout, cached - 1U);
    }));
}

void test_relation_chunk_preflight_is_pristine() {
    WideFixture fixture = make_wide_fixture();
    PayloadCheckpointReplayBudgets limits = budgets();
    limits.max_ciphertexts_per_chunk = 1;
    const PayloadCheckpointReplayPlan plan =
        plan_payload_checkpoint_replay(fixture.problem, limits);
    CHECK(plan.selected.feasible());
    CHECK(plan.selected.chunk_ciphertexts == 1);
    CHECK(minimum_payload_checkpoint_relation_chunk_ciphertexts(
              fixture.circuit) == 2);

    TemporaryDirectory root;
    const std::filesystem::path replay_directory =
        root.make_child("undersized-relation-chunk");
    std::vector<fhe::FheValue<ReplayMockBackend>> output;
    ReplayMockBackend::reset_counts(fixture.contexts.eval);
    CHECK(throws_invalid_argument([&] {
        (void)PayloadCheckpointReplayTrace<ReplayMockBackend>::publish(
            fixture.contexts.eval, fixture.payload, fixture.circuit,
            fixture.encrypted_inputs, fixture.evaluation, fixture.problem,
            limits, plan, options(replay_directory), output);
    }));
    CHECK(counted_fhe_operations(
              ReplayMockBackend::counts(fixture.contexts.eval)) == 0);
    CHECK(std::filesystem::is_empty(replay_directory));
    CHECK(output.empty());
}

void test_wrong_layer_swap_rejects_before_retirement() {
    Fixture fixture = make_fixture();
    const PayloadCheckpointReplayBudgets limits = budgets({1, 1});
    const PayloadCheckpointReplayPlan plan =
        plan_payload_checkpoint_replay(fixture.problem, limits);
    CHECK(plan.selected.checkpoint_layers.size() >= 2);
    CHECK(plan.selected.checkpoint_layers[0] == 1);
    CHECK(plan.selected.checkpoint_layers[1] == 2);

    TemporaryDirectory root;
    const std::filesystem::path replay_directory =
        root.make_child("wrong-layer");
    std::vector<fhe::FheValue<ReplayMockBackend>> output;
    auto replay =
        PayloadCheckpointReplayTrace<ReplayMockBackend>::publish(
        fixture.contexts.eval, fixture.payload, fixture.circuit,
        fixture.encrypted_inputs, fixture.evaluation, fixture.problem,
        limits, plan, options(replay_directory), output);

    const std::filesystem::path first =
        replay_directory / "layer-0000000000000001";
    const std::filesystem::path second =
        replay_directory / "layer-0000000000000002";
    const std::filesystem::path staging = replay_directory / "swapped";
    std::filesystem::rename(first, staging);
    std::filesystem::rename(second, first);
    std::filesystem::rename(staging, second);

    const std::uint64_t live_before = replay.report().live_physical_bytes;
    CHECK(throws_exception([&] {
        auto reader = replay.layer_reader(1);
        while (reader.next()) {
        }
    }));
    CHECK(replay.report().live_physical_bytes == live_before);
    CHECK(replay.report().checkpoint_retirement_order.empty());
    CHECK(regular_file_bytes(first) != 0);
    CHECK(regular_file_bytes(second) != 0);
}

void test_identity_dense_multiplication_uses_two_monotone_readers() {
    constexpr std::size_t kPairCount = 20;
    Fixture fixture = make_fixture_for_payload(
        make_identity_dense_payload(kPairCount));
    const std::vector<std::size_t> multiplications =
        multiplication_layers(fixture.circuit);
    CHECK(multiplications.size() == 1U);
    const std::size_t multiplication = multiplications.front();
    const std::size_t source_layer = multiplication + 1U;
    const CanonicalTraceLayout layout =
        canonical_trace_layout(fixture.circuit);
    CHECK(layout.storage[source_layer].stored_wire_count ==
          layout.wire_support[source_layer].live_wire_count);

    const PayloadCheckpointReplayBudgets limits = budgets();
    CHECK(layout.storage[source_layer].stored_wire_count >
          limits.max_ciphertexts_per_chunk);
    const PayloadCheckpointReplayPlan plan =
        plan_payload_checkpoint_replay(fixture.problem, limits);
    TemporaryDirectory root;
    const std::filesystem::path replay_directory =
        root.make_child("identity-dense-replay");
    const OperationCounts before =
        ReplayMockBackend::counts(fixture.contexts.eval);
    std::vector<fhe::FheValue<ReplayMockBackend>> output;
    auto replay = PayloadCheckpointReplayTrace<ReplayMockBackend>::publish(
        fixture.contexts.eval, fixture.payload, fixture.circuit,
        fixture.encrypted_inputs, fixture.evaluation, fixture.problem,
        limits, plan, options(replay_directory), output);

    const PayloadCheckpointReplayIoReport &io = replay.report().forward;
    CHECK(io.monotone_dense_multiplication_relations == 1U);
    CHECK(io.monotone_dense_multiplication_range_readers_opened == 2U);
    CHECK(io.monotone_dense_multiplication_source_records_read ==
          layout.storage[source_layer].stored_wire_count);
    CHECK(output.size() ==
          fixture.compact_reference.layers.front().wires.size());
    for (std::size_t wire = 0; wire < output.size(); ++wire) {
        CHECK(encode_value<ReplayMockBackend>(
                  fixture.contexts.eval, output[wire]) ==
              encode_value<ReplayMockBackend>(
                  fixture.contexts.eval,
                  fixture.compact_reference.layers.front().wires[wire]));
    }
    const OperationCounts after =
        ReplayMockBackend::counts(fixture.contexts.eval);
    CHECK(after.mul_no_relin - before.mul_no_relin == kPairCount);
    CHECK(after.relinearize - before.relinearize == kPairCount);
    CHECK(after.mod_switch - before.mod_switch == kPairCount);
}

void test_alias_heavy_dense_multiplication_decodes_distinct_source_once() {
    constexpr std::size_t kPairCount = 40;
    Fixture fixture = make_fixture_for_payload(
        make_alias_heavy_dense_payload(kPairCount));
    const std::vector<std::size_t> multiplications =
        multiplication_layers(fixture.circuit);
    CHECK(multiplications.size() == 1U);
    const std::size_t multiplication = multiplications.front();
    const std::size_t source_layer = multiplication + 1U;
    const CanonicalTraceLayout layout =
        canonical_trace_layout(fixture.circuit);
    const std::size_t distinct =
        layout.storage[source_layer].stored_wire_count;
    CHECK(distinct < layout.wire_support[source_layer].live_wire_count);

    PayloadCheckpointReplayBudgets limits = budgets();
    limits.max_ciphertexts_per_chunk = 8;
    CHECK(distinct <= 2U * limits.max_ciphertexts_per_chunk);
    CHECK(distinct <=
          layout.wire_support[source_layer].live_wire_count / 4U);
    const PayloadCheckpointReplayPlan plan =
        plan_payload_checkpoint_replay(fixture.problem, limits);
    TemporaryDirectory root;
    const std::filesystem::path replay_directory =
        root.make_child("alias-cached-dense-replay");
    const OperationCounts before =
        ReplayMockBackend::counts(fixture.contexts.eval);
    std::vector<fhe::FheValue<ReplayMockBackend>> output;
    auto replay = PayloadCheckpointReplayTrace<ReplayMockBackend>::publish(
        fixture.contexts.eval, fixture.payload, fixture.circuit,
        fixture.encrypted_inputs, fixture.evaluation, fixture.problem,
        limits, plan, options(replay_directory), output);

    const PayloadCheckpointReplayIoReport &io = replay.report().forward;
    CHECK(io.alias_cached_dense_multiplication_relations == 1U);
    CHECK(io.alias_cached_dense_multiplication_range_readers_opened == 1U);
    CHECK(io.alias_cached_dense_multiplication_distinct_source_records_read ==
          distinct);
    CHECK(io.alias_cached_dense_multiplication_logical_source_uses ==
          layout.wire_support[source_layer].live_wire_count);
    CHECK(io.alias_cached_dense_multiplication_logical_source_uses >
          io.alias_cached_dense_multiplication_distinct_source_records_read);
    CHECK(io.alias_cached_dense_multiplication_fallback_source_records >=
          4U * distinct);
    CHECK(io.alias_cached_dense_multiplication_fallback_source_records >
          io.alias_cached_dense_multiplication_distinct_source_records_read);
    CHECK(replay.report().peak_controlled_resident_bytes <=
          plan.selected.peak_resident_bytes);
    CHECK(output.size() ==
          fixture.compact_reference.layers.front().wires.size());
    for (std::size_t wire = 0; wire < output.size(); ++wire) {
        CHECK(encode_value<ReplayMockBackend>(
                  fixture.contexts.eval, output[wire]) ==
              encode_value<ReplayMockBackend>(
                  fixture.contexts.eval,
                  fixture.compact_reference.layers.front().wires[wire]));
    }
    const OperationCounts after =
        ReplayMockBackend::counts(fixture.contexts.eval);
    CHECK(after.mul_no_relin - before.mul_no_relin == kPairCount);
    CHECK(after.relinearize - before.relinearize == kPairCount);
    CHECK(after.mod_switch - before.mod_switch == kPairCount);
}

void test_alias_cache_uses_global_resident_cap_beyond_chunk_peak() {
    constexpr std::size_t kPairCount = 40;
    constexpr std::size_t kInputCount = 3;
    Fixture fixture = make_fixture_for_payload(
        make_alias_heavy_dense_payload(kPairCount, kInputCount));
    const std::size_t multiplication =
        multiplication_layers(fixture.circuit).front();
    const std::size_t source_layer = multiplication + 1U;
    const CanonicalTraceLayout layout =
        canonical_trace_layout(fixture.circuit);
    const std::size_t distinct =
        layout.storage[source_layer].stored_wire_count;

    PayloadCheckpointReplayBudgets limits = budgets();
    limits.max_ciphertexts_per_chunk = 2;
    CHECK(distinct > 2U * limits.max_ciphertexts_per_chunk);
    const PayloadCheckpointReplayPlan plan =
        plan_payload_checkpoint_replay(fixture.problem, limits);
    CHECK(plan.selected
              .dense_multiplication_alias_cache_peak_resident_bytes > 0);
    CHECK(plan.selected.peak_resident_bytes >=
          plan.selected
              .dense_multiplication_alias_cache_peak_resident_bytes);
    TemporaryDirectory root;
    std::vector<fhe::FheValue<ReplayMockBackend>> output;
    auto replay = PayloadCheckpointReplayTrace<ReplayMockBackend>::publish(
        fixture.contexts.eval, fixture.payload, fixture.circuit,
        fixture.encrypted_inputs, fixture.evaluation, fixture.problem,
        limits, plan, options(root.make_child("alias-cache-global-cap")),
        output);
    CHECK(replay.report()
              .forward.alias_cached_dense_multiplication_relations == 1U);
    CHECK(replay.report()
              .forward.monotone_dense_multiplication_relations == 0);
    CHECK(replay.report().peak_controlled_resident_bytes <=
          plan.selected.peak_resident_bytes);
    CHECK(output.size() ==
          fixture.compact_reference.layers.front().wires.size());
}

void test_eager_laned_admission_reserves_workspace_before_publication() {
    Fixture fixture = make_fixture_for_payload(
        make_alias_heavy_dense_payload(40, 3, 1));
    const auto resources = eager_laned_witness_packing_resources(
        fixture.circuit, fixture.problem);
    CHECK(resources.eligible);
    CHECK(resources.maximum_builder_resident_bytes > 0);
    CHECK(resources.maximum_mask_cache_resident_bytes > 0);
    CHECK(resources.artifact_bytes_by_layer.size() ==
          fixture.circuit.layers.size());

    auto limits = budgets();
    limits.max_ciphertexts_per_chunk = 2;
    const auto unreserved = plan_payload_checkpoint_replay(
        fixture.problem, limits);
    CHECK(unreserved.selected.peak_resident_bytes <=
          limits.max_resident_ciphertext_bytes);
    CHECK(limits.reserved_resident_bytes < resources.resident_workspace_bytes);
    CHECK(throws_invalid_argument([&] {
        (void)admit_eager_laned_witness_packing(
            fixture.circuit, fixture.problem, limits, unreserved);
    }));

    TemporaryDirectory root;
    const auto rejected_directory = root.make_child("eager-unreserved");
    auto rejected_options = options(rejected_directory);
    rejected_options.eager_laned_witness_packing = true;
    std::vector<FheValue<ReplayMockBackend>> output;
    ReplayMockBackend::reset_counts(fixture.contexts.eval);
    CHECK(throws_invalid_argument([&] {
        (void)PayloadCheckpointReplayTrace<ReplayMockBackend>::publish(
            fixture.contexts.eval, fixture.payload, fixture.circuit,
            fixture.encrypted_inputs, fixture.evaluation, fixture.problem,
            limits, unreserved, rejected_options, output);
    }));
    CHECK(output.empty());
    CHECK(std::filesystem::is_empty(rejected_directory));
    CHECK(counted_fhe_operations(
              ReplayMockBackend::counts(fixture.contexts.eval)) == 0);

    limits.reserved_resident_bytes += resources.resident_workspace_bytes;
    const auto plan = plan_payload_checkpoint_replay(fixture.problem, limits);
    const auto admission = admit_eager_laned_witness_packing(
        fixture.circuit, fixture.problem, limits, plan);
    CHECK(admission.resources.eligible);
    CHECK(admission.peak_resident_bytes == plan.selected.peak_resident_bytes);
    CHECK(admission.peak_live_scratch_bytes <= limits.max_live_scratch_bytes);
    auto boundary = limits;
    boundary.max_resident_ciphertext_bytes = admission.peak_resident_bytes;
    boundary.max_live_scratch_bytes = admission.peak_live_scratch_bytes;
    (void)admit_eager_laned_witness_packing(
        fixture.circuit, fixture.problem, boundary, plan);
    --boundary.max_resident_ciphertext_bytes;
    CHECK(throws_invalid_argument([&] {
        (void)admit_eager_laned_witness_packing(
            fixture.circuit, fixture.problem, boundary, plan);
    }));
    ++boundary.max_resident_ciphertext_bytes;
    --boundary.max_live_scratch_bytes;
    CHECK(throws_invalid_argument([&] {
        (void)admit_eager_laned_witness_packing(
            fixture.circuit, fixture.problem, boundary, plan);
    }));

    auto execution = options(root.make_child("eager-reserved"));
    execution.eager_laned_witness_packing = true;
    auto replay = PayloadCheckpointReplayTrace<ReplayMockBackend>::publish(
        fixture.contexts.eval, fixture.payload, fixture.circuit,
        fixture.encrypted_inputs, fixture.evaluation, fixture.problem,
        limits, plan, std::move(execution), output);
    CHECK(replay.uses_eager_laned_witness_packing());
    CHECK(replay.report().peak_controlled_resident_bytes <=
          admission.peak_resident_bytes);
    CHECK(output.size() == fixture.compact_reference.layers.front().wires.size());
    for (std::size_t wire = 0; wire < output.size(); ++wire) {
        CHECK(materialize_or_decrypt<ReplayMockBackend>(
                  fixture.contexts.client, output[wire]) ==
              materialize_or_decrypt<ReplayMockBackend>(fixture.contexts.client,
                  fixture.compact_reference.layers.front().wires[wire]));
    }
}

void test_eager_workspace_precedes_optional_alias_cache_selection() {
    Fixture fixture = make_fixture_for_payload(
        make_alias_heavy_dense_payload(32, 3, 1, true));
    const auto resources = eager_laned_witness_packing_resources(
        fixture.circuit, fixture.problem);
    CHECK(resources.eligible);
    auto limits = budgets();
    limits.max_ciphertexts_per_chunk = 2;
    const auto unreserved = plan_payload_checkpoint_replay(fixture.problem, limits);
    CHECK(unreserved.selected.dense_multiplication_alias_cache_peak_resident_bytes > 0);

    // This cap fits the generic cache, but not that cache together with the
    // eager workspace. The optional cache must yield to the fixed workspace.
    limits.max_resident_ciphertext_bytes =
        unreserved.selected.dense_multiplication_alias_cache_peak_resident_bytes +
        resources.resident_workspace_bytes - 1;
    CHECK(unreserved.selected.peak_resident_bytes <=
          limits.max_resident_ciphertext_bytes);
    limits.reserved_resident_bytes += resources.resident_workspace_bytes;
    const auto plan = plan_payload_checkpoint_replay(fixture.problem, limits);
    CHECK(plan.selected.dense_multiplication_alias_cache_peak_resident_bytes == 0);
    const auto admission = admit_eager_laned_witness_packing(
        fixture.circuit, fixture.problem, limits, plan);
    CHECK(admission.peak_resident_bytes <= limits.max_resident_ciphertext_bytes);

    TemporaryDirectory root;
    auto execution = options(root.make_child("eager-cache-fallback"));
    execution.eager_laned_witness_packing = true;
    std::vector<FheValue<ReplayMockBackend>> output;
    auto replay = PayloadCheckpointReplayTrace<ReplayMockBackend>::publish(
        fixture.contexts.eval, fixture.payload, fixture.circuit,
        fixture.encrypted_inputs, fixture.evaluation, fixture.problem,
        limits, plan, std::move(execution), output);
    CHECK(replay.uses_eager_laned_witness_packing());
    CHECK(replay.report().forward.alias_cached_dense_multiplication_relations == 0);
    CHECK(replay.report().peak_controlled_resident_bytes <= admission.peak_resident_bytes);
    CHECK(output.size() == fixture.compact_reference.layers.front().wires.size());
}

void test_alias_cache_requires_material_read_savings() {
    constexpr std::size_t kPairCount = 12;
    Fixture fixture = make_fixture_for_payload(
        make_alias_heavy_dense_payload(kPairCount));
    const std::size_t multiplication =
        multiplication_layers(fixture.circuit).front();
    const std::size_t source_layer = multiplication + 1U;
    const CanonicalTraceLayout layout =
        canonical_trace_layout(fixture.circuit);

    PayloadCheckpointReplayBudgets limits = budgets();
    limits.max_ciphertexts_per_chunk = 8;
    CHECK(layout.storage[source_layer].stored_wire_count <
          layout.wire_support[source_layer].live_wire_count);
    CHECK(layout.storage[source_layer].stored_wire_count <=
          2U * limits.max_ciphertexts_per_chunk);
    const PayloadCheckpointReplayPlan plan =
        plan_payload_checkpoint_replay(fixture.problem, limits);
    TemporaryDirectory root;
    std::vector<fhe::FheValue<ReplayMockBackend>> output;
    auto replay = PayloadCheckpointReplayTrace<ReplayMockBackend>::publish(
        fixture.contexts.eval, fixture.payload, fixture.circuit,
        fixture.encrypted_inputs, fixture.evaluation, fixture.problem,
        limits, plan,
        options(root.make_child("alias-cache-low-reuse-fallback")), output);
    CHECK(replay.report()
              .forward.alias_cached_dense_multiplication_relations == 0);
    CHECK(replay.report()
              .forward.monotone_dense_multiplication_relations == 0);
    CHECK(output.size() ==
          fixture.compact_reference.layers.front().wires.size());
}

void test_alias_cache_falls_back_when_global_resident_cap_is_too_small() {
    constexpr std::size_t kPairCount = 80;
    constexpr std::size_t kInputCount = 6;
    Fixture fixture = make_fixture_for_payload(
        make_alias_heavy_dense_payload(kPairCount, kInputCount));
    const std::size_t multiplication =
        multiplication_layers(fixture.circuit).front();
    const std::size_t source_layer = multiplication + 1U;
    const CanonicalTraceLayout layout =
        canonical_trace_layout(fixture.circuit);

    PayloadCheckpointReplayBudgets limits = budgets();
    limits.max_ciphertexts_per_chunk = 8;
    const std::size_t distinct =
        layout.storage[source_layer].stored_wire_count;
    CHECK(distinct > limits.max_ciphertexts_per_chunk);
    CHECK(distinct <= 2U * limits.max_ciphertexts_per_chunk);
    fixture.problem.layers[source_layer].resident_ciphertext_bytes =
        std::uint64_t{1} << 27U;
    const PayloadCheckpointReplayPlan plan =
        plan_payload_checkpoint_replay(fixture.problem, limits);
    CHECK(plan.selected.chunk_ciphertexts > 0);
    CHECK(plan.selected
              .dense_multiplication_alias_cache_peak_resident_bytes == 0);

    TemporaryDirectory root;
    std::vector<fhe::FheValue<ReplayMockBackend>> output;
    auto replay = PayloadCheckpointReplayTrace<ReplayMockBackend>::publish(
        fixture.contexts.eval, fixture.payload, fixture.circuit,
        fixture.encrypted_inputs, fixture.evaluation, fixture.problem,
        limits, plan,
        options(root.make_child("alias-cache-global-memory-fallback")),
        output);
    CHECK(replay.report()
              .forward.alias_cached_dense_multiplication_relations == 0);
    CHECK(replay.report()
              .forward.monotone_dense_multiplication_relations == 0);
    CHECK(replay.report().peak_controlled_resident_bytes <=
          plan.selected.peak_resident_bytes);
    CHECK(output.size() ==
          fixture.compact_reference.layers.front().wires.size());
}

void test_alias_cache_is_used_during_reverse_replay() {
    constexpr std::size_t kPairCount = 40;
    Fixture fixture = make_fixture_for_payload(
        make_two_stage_alias_heavy_dense_payload(kPairCount));
    PayloadCheckpointReplayBudgets limits = budgets();
    limits.max_ciphertexts_per_chunk = 8;
    const PayloadCheckpointReplayPlan plan =
        plan_payload_checkpoint_replay(fixture.problem, limits);
    CHECK(plan.selected.checkpoint_layers ==
          std::vector<std::size_t>({fixture.circuit.layers.size() - 1U}));

    TemporaryDirectory root;
    const std::filesystem::path replay_directory =
        root.make_child("reverse-alias-cached-dense-replay");
    std::vector<fhe::FheValue<ReplayMockBackend>> output;
    auto replay = PayloadCheckpointReplayTrace<ReplayMockBackend>::publish(
        fixture.contexts.eval, fixture.payload, fixture.circuit,
        fixture.encrypted_inputs, fixture.evaluation, fixture.problem,
        limits, plan, options(replay_directory), output);
    CHECK(replay.report()
              .forward.alias_cached_dense_multiplication_relations > 0);

    (void)replay.retire_layer(0);
    for (std::size_t layer = 1; layer < fixture.circuit.layers.size();
         ++layer) {
        {
            auto reader = replay.active_layer_reader(layer);
            std::size_t stored = 0;
            while (auto record = reader.next()) {
                CHECK(record->padded_index ==
                      replay.layer_storage_layout(layer)
                          .representative_padded_index_of(stored));
                CHECK(encode_value<ReplayMockBackend>(
                          fixture.contexts.eval, record->value) ==
                      encode_value<ReplayMockBackend>(
                          fixture.contexts.eval,
                          fixture.compact_reference.layers[layer]
                              .wires[stored]));
                ++stored;
            }
            CHECK(stored ==
                  replay.layer_storage_layout(layer).stored_wire_count);
        }
        (void)replay.retire_layer(layer);
    }

    const PayloadCheckpointReplayIoReport &reverse =
        replay.report().reverse_replay;
    CHECK(reverse.alias_cached_dense_multiplication_relations > 0);
    CHECK(reverse.alias_cached_dense_multiplication_range_readers_opened ==
          reverse.alias_cached_dense_multiplication_relations);
    CHECK(reverse.alias_cached_dense_multiplication_distinct_source_records_read >
          0);
    CHECK(reverse.alias_cached_dense_multiplication_fallback_source_records >=
          4U *
              reverse
                  .alias_cached_dense_multiplication_distinct_source_records_read);
    CHECK(replay.report().all_payload_artifacts_retired);
    CHECK(replay.report().live_physical_bytes == 0);
    CHECK(regular_file_bytes(replay_directory) == 0);
}

void test_wide_checkpoint_replay_is_compact_and_exact() {
    WideFixture fixture = make_wide_fixture();
    PayloadCheckpointReplayBudgets limits = budgets();
    limits.max_ciphertexts_per_chunk = 2;
    const PayloadCheckpointReplayPlan plan =
        plan_payload_checkpoint_replay(fixture.problem, limits);
    CHECK(plan.selected.chunk_ciphertexts == 2);
    CHECK(minimum_payload_checkpoint_relation_chunk_ciphertexts(
              fixture.circuit) == 2);

    const auto &output_affine =
        std::get<AffineLayer>(fixture.circuit.layers.front());
    CHECK(!output_affine.intermediate_gates.empty());
    CHECK(fixture.problem.layers.front().affine_workspace_bytes > 0);
    CHECK(std::all_of(output_affine.intermediate_gates.begin(),
                     output_affine.intermediate_gates.end(),
                     [](const AffineGate &gate) { return gate.terms.size() <= 2; }));
    CHECK(std::any_of(output_affine.intermediate_gates.begin(),
                     output_affine.intermediate_gates.end(),
                     [](const AffineGate &gate) {
                         return std::any_of(gate.terms.begin(), gate.terms.end(),
                             [](const AffineTerm &term) { return term.coefficient != Fp::one(); });
                     }));

    const std::vector<LayerWireSupport> support =
        canonical_trace_wire_support(fixture.circuit);
    const std::vector<LayerStorageLayout> storage =
        canonical_trace_storage_layout(fixture.circuit);
    CHECK(std::any_of(support.begin(), support.end(), [](const auto &layer) {
        return layer.live_wire_count < layer.padded_wire_count;
    }));

    TemporaryDirectory root;
    const std::filesystem::path replay_directory =
        root.make_child("wide-replay");
    std::vector<fhe::FheValue<ReplayMockBackend>> output;
    ReplayMockBackend::reset_counts(fixture.contexts.eval);
    auto replay = PayloadCheckpointReplayTrace<ReplayMockBackend>::publish(
        fixture.contexts.eval, fixture.payload, fixture.circuit,
        fixture.encrypted_inputs, fixture.evaluation, fixture.problem,
        limits, plan, options(replay_directory), output);
    const OperationCounts forward_counts =
        ReplayMockBackend::counts(fixture.contexts.eval);

    // The server evaluates and stores only canonical live wires. Public
    // padding causes neither subtraction-based zero construction nor fresh
    // encryption.
    CHECK(forward_counts.sub == 0);
    CHECK(forward_counts.encrypt == 0);
    // The fixture has one semantically live zero output. It remains a public
    // scalar and therefore causes no backend multiplication or encryption.
    CHECK(forward_counts.mul_plain_scalar_api_calls > 0);
    // The mask is evaluated once in each of the two affine stages that
    // consume it; final aliases within a stage share that local node.
    CHECK(forward_counts.mul_plain_vector_api_calls == 2);
    CHECK(forward_counts.mul_plain_vector_api_elements == 2 * kSlots);
    CHECK(forward_counts.mul_plain_vector_api_elements <
          output_affine.intermediate_gates.size() * kSlots);
    std::uint64_t expected_forward_switches = 0;
    for (std::size_t layer = 0; layer + 1U < support.size(); ++layer) {
        const std::size_t encrypted = static_cast<std::size_t>(
            std::count_if(
                fixture.compact_reference.layers[layer].wires.begin(),
                fixture.compact_reference.layers[layer].wires.end(),
                [](const auto &value) { return value.is_encrypted(); }));
        expected_forward_switches +=
            encrypted *
            fixture.evaluation.modulus_switches_after_layer[layer];
    }
    CHECK(forward_counts.mod_switch == expected_forward_switches);

    CHECK(output.size() == storage.front().stored_wire_count);
    CHECK(replay.descriptor().shape.kind == PayloadKind::Wide);
    for (std::size_t layer = 0; layer < support.size(); ++layer) {
        CHECK(replay.descriptor().layers[layer].layout ==
              TraceLayerLayout::Wide);
        CHECK(replay.descriptor().layers[layer].record_count ==
              storage[layer].stored_wire_count);
    }
    for (std::size_t live = 0; live < output.size(); ++live) {
        CHECK(encode_value<ReplayMockBackend>(
                  fixture.contexts.eval, output[live]) ==
              encode_value<ReplayMockBackend>(
                  fixture.contexts.eval,
                  fixture.compact_reference.layers.front().wires[live]));
    }
    CHECK(replay.report().peak_live_scratch_bytes <=
          limits.max_live_scratch_bytes);
    CHECK(replay.report().peak_controlled_resident_bytes <=
          limits.max_resident_ciphertext_bytes);
    CHECK(replay.report().peak_controlled_resident_bytes <=
          plan.selected.peak_resident_bytes);
    CHECK(replay.report().peak_live_layer_artifacts <= 3);

    (void)replay.retire_layer(0);
    ReplayMockBackend::reset_counts(fixture.contexts.eval);
    std::size_t public_zeros_read = 0;
    for (std::size_t layer = 1; layer < support.size(); ++layer) {
        CHECK(replay.layer_support(layer) == support[layer]);
        {
            auto reader = replay.layer_reader(layer);
            const std::uint64_t operations_before_read =
                counted_fhe_operations(
                    ReplayMockBackend::counts(fixture.contexts.eval));
            std::size_t padded = 0;
            std::size_t live = 0;
            while (std::optional<fhe::FheValue<ReplayMockBackend>> value =
                       reader.next()) {
                if (support[layer].is_live(padded)) {
                    const std::size_t stored =
                        *storage[layer].stored_ordinal_of(padded);
                    CHECK(encode_value<ReplayMockBackend>(
                              fixture.contexts.eval, *value) ==
                          encode_value<ReplayMockBackend>(
                              fixture.contexts.eval,
                              fixture.compact_reference.layers[layer]
                                  .wires[stored]));
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
            CHECK(counted_fhe_operations(
                      ReplayMockBackend::counts(fixture.contexts.eval)) ==
                  operations_before_read);
        }

        const std::uint64_t aggregate_encoded_before =
            replay.report()
                .gkr_source_reads.encoded_ciphertext_bytes_read;
        const std::uint64_t aggregate_framed_before =
            replay.report().gkr_source_reads.framed_record_bytes_read;
        const std::uint64_t aggregate_readers_before =
            replay.report().gkr_source_reads.range_readers_opened;
        std::uint64_t active_encoded = 0;
        std::uint64_t active_records = 0;
        {
            auto reader = replay.active_layer_reader(layer);
            CHECK(reader.begin() == 0);
            CHECK(reader.end() == storage[layer].stored_wire_count);
            const std::uint64_t operations_before_read =
                counted_fhe_operations(
                    ReplayMockBackend::counts(fixture.contexts.eval));
            std::size_t live = 0;
            while (auto record = reader.next()) {
                CHECK(record->padded_index ==
                      storage[layer]
                          .representative_padded_index_of(live));
                CHECK(encode_value<ReplayMockBackend>(
                          fixture.contexts.eval, record->value) ==
                      encode_value<ReplayMockBackend>(
                          fixture.contexts.eval,
                          fixture.compact_reference.layers[layer]
                              .wires[live]));
                ++live;
            }
            CHECK(live == storage[layer].stored_wire_count);
            CHECK(reader.position() == reader.end());
            CHECK(reader.serialized_records_read() == live);
            CHECK(reader.resident_ciphertexts_held() == 0);
            CHECK(counted_fhe_operations(
                      ReplayMockBackend::counts(fixture.contexts.eval)) ==
                  operations_before_read);
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
              active_encoded + active_records * sizeof(std::uint64_t));
        CHECK(replay.report().gkr_source_reads.range_readers_opened ==
              aggregate_readers_before + 1U);
        (void)replay.retire_layer(layer);
    }
    CHECK(public_zeros_read > 0);

    std::uint64_t expected_replay_switches = 0;
    for (const PayloadReplaySegment &segment :
         plan.reverse_gkr_segments) {
        for (std::size_t output = segment.checkpoint_layer;
             output-- > segment.required_source_layer;) {
            expected_replay_switches +=
                storage[output].stored_wire_count *
                fixture.evaluation.modulus_switches_after_layer[output];
        }
    }
    const OperationCounts replay_counts =
        ReplayMockBackend::counts(fixture.contexts.eval);
    CHECK(replay_counts.sub == 0);
    CHECK(replay_counts.encrypt == 0);
    CHECK(replay_counts.mod_switch == expected_replay_switches);
    CHECK(replay.report().all_payload_artifacts_retired);
    CHECK(replay.report().live_physical_bytes == 0);
    CHECK(regular_file_bytes(replay_directory) == 0);
}

void test_affine_dag_workspace_is_admitted_before_execution() {
    auto fixture = make_wide_fixture();
    auto limits = budgets();
    const auto largest = std::max_element(fixture.problem.layers.begin(), fixture.problem.layers.end(),
        [](const auto &a, const auto &b) { return a.affine_workspace_bytes < b.affine_workspace_bytes; });
    CHECK(largest->affine_workspace_bytes > 0);
    limits.max_resident_ciphertext_bytes = largest->affine_workspace_bytes - 1;
    CHECK(throws_exception([&] { (void)plan_payload_checkpoint_replay(fixture.problem, limits); }));
    limits = budgets();
    auto damaged = fixture.problem;
    damaged.layers[largest - fixture.problem.layers.begin()].affine_workspace_bytes = 0;
    const auto plan = plan_payload_checkpoint_replay(damaged, limits);
    TemporaryDirectory root;
    const auto destination = root.make_child("dag-understated-workspace");
    std::vector<fhe::FheValue<ReplayMockBackend>> output;
    ReplayMockBackend::reset_counts(fixture.contexts.eval);
    CHECK(throws_invalid_argument([&] {
        (void)PayloadCheckpointReplayTrace<ReplayMockBackend>::publish(
            fixture.contexts.eval, fixture.payload, fixture.circuit,
            fixture.encrypted_inputs, fixture.evaluation, damaged,
            limits, plan, options(destination), output);
    }));
    CHECK(std::filesystem::is_empty(destination));
    CHECK(counted_fhe_operations(ReplayMockBackend::counts(fixture.contexts.eval)) == 0);
}

} // namespace

int main() {
    laminate::test::Runner runner("Payload checkpoint replay execution");
    runner.run("B=N bypasses eager Laned witness packing",
               test_full_width_laned_bypasses_eager_witness_packing);
    runner.run("Laned witness packing caches masks and never rotates",
               test_laned_witness_packing_reuses_masks_without_rotations);
    runner.run("sparse Mock replay produces a valid Laned GKR proof",
               test_sparse_execution_verifies);
    runner.run("identity affine alias preserves eager Laned proof",
               test_identity_affine_alias_preserves_eager_laned_proof);
    runner.run("identity affine alias rejects semantic changes",
               test_identity_affine_alias_predicate_rejects_semantic_changes);
    runner.run("output-only execution retires every file-backed layer",
               test_output_only_execution_retires_every_layer);
    runner.run("proof ingress is normalized and persisted exactly once",
               test_proof_ingress_is_published_once);
    runner.run("same-writer handoff skips complete artifact rescans",
               test_same_writer_handoff_avoids_artifact_rescans);
    runner.run("proof-ingress transient disk peak fails closed",
               test_proof_ingress_transient_peak_fails_closed);
    runner.run("natural-level proof ingress aliases replay artifacts",
               test_natural_level_proof_ingress_aliases);
    runner.run("plan mismatch leaves destination pristine",
               test_plan_mismatch_is_pristine);
    runner.run("execution binds natural RNS levels exactly",
               test_execution_rejects_unbound_natural_rns_levels);
    runner.run("cached relation chunk geometry matches and validates",
               test_cached_relation_chunk_geometry_matches_and_validates);
    runner.run("relation chunk preflight precedes paths and FHE work",
               test_relation_chunk_preflight_is_pristine);
    runner.run("failed publication cleans session-owned files",
               test_failed_publication_cleans_owned_root);
    runner.run("complete output may exceed the relation chunk",
               test_complete_output_can_exceed_relation_chunk);
    runner.run("metadata failures precede directories and FHE work",
               test_metadata_preflight_is_pristine_and_does_no_fhe_work);
    runner.run("destructive lifecycle requires explicit opt-in",
               test_destructive_lifecycle_must_be_explicit);
    runner.run("checkpoint metadata corruption fails before replay",
               test_metadata_corruption_rejects_before_replay);
    runner.run("wrong-layer swap is rejected before retirement",
               test_wrong_layer_swap_rejects_before_retirement);
    runner.run("identity dense replay keeps two monotone source readers",
               test_identity_dense_multiplication_uses_two_monotone_readers);
    runner.run("alias-heavy dense replay decodes each distinct source once",
               test_alias_heavy_dense_multiplication_decodes_distinct_source_once);
    runner.run("alias cache may use admitted RAM beyond the chunk peak",
               test_alias_cache_uses_global_resident_cap_beyond_chunk_peak);
    runner.run("eager Laned workspace is admitted before payload publication",
               test_eager_laned_admission_reserves_workspace_before_publication);
    runner.run("eager workspace takes priority over the optional alias cache",
               test_eager_workspace_precedes_optional_alias_cache_selection);
    runner.run("alias cache requires material record-read savings",
               test_alias_cache_requires_material_read_savings);
    runner.run("alias cache falls back above the global resident cap",
               test_alias_cache_falls_back_when_global_resident_cap_is_too_small);
    runner.run("alias cache is reused by reverse checkpoint replay",
               test_alias_cache_is_used_during_reverse_replay);
    runner.run("Wide replay stays compact and follows exact switches",
               test_wide_checkpoint_replay_is_compact_and_exact);
    runner.run("affine DAG workspace is admitted before execution",
               test_affine_dag_workspace_is_admitted_before_execution);
    return runner.summary();
}
