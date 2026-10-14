/// @file test_packed_server_online.cpp
/// @brief Authenticated recurring Folded/Laned server lifecycle regression.

#include "test_helpers.hpp"

#include "laminate/delegation/folded/server.hpp"
#include "laminate/delegation/laned/server.hpp"
#include "laminate/fhe/mock_backend.hpp"
#include "laminate/payload/compiler.hpp"
#include "laminate/payload/laned_fhe_evaluator.hpp"
#include "laminate/payload/input_encryption.hpp"
#include "laminate/payload/wide_fhe_evaluator.hpp"
#include "laminate/protocol/packed/preprocessing/roles.hpp"
#include "laminate/diagnostics/setup_validation.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <type_traits>
#include <utility>
#include <vector>

using namespace laminate;
using namespace laminate::delegation;
using namespace laminate::fhe;
using namespace laminate::gkr;
using namespace laminate::packing;
using namespace laminate::payload;
using namespace laminate::protocol;

namespace {

/// Give checkpoint planning the exact RNS interpretation used by these
/// lifecycle tests. The ordinary Mock noise estimator is intentionally more
/// abstract than the persisted checkpoint format.
struct ReplayMockBackend : MockBackend {
    static std::size_t remaining_mult_depth(
        const EvalContext &, const Ciphertext &ciphertext) {
        return ciphertext.rns_limbs - 1U;
    }
};

static_assert(PackedRolePreprocessingBackend<ReplayMockBackend>);
static_assert(!std::is_aggregate_v<
              OpenedPackedServerEvaluation<ReplayMockBackend>>);
static_assert(!std::is_copy_constructible_v<
              OpenedPackedServerEvaluation<ReplayMockBackend>>);
static_assert(std::is_move_constructible_v<
              OpenedPackedServerEvaluation<ReplayMockBackend>>);

template <typename Action>
bool rejects(Action &&action) {
    try {
        std::forward<Action>(action)();
        return false;
    } catch (const std::exception &) {
        return true;
    }
}

class TemporaryTree {
  public:
    TemporaryTree() {
        const auto stamp = std::chrono::steady_clock::now()
                               .time_since_epoch()
                               .count();
        for (std::size_t attempt = 0; attempt < 100; ++attempt) {
            root_ = std::filesystem::temp_directory_path() /
                    ("laminate-packed-server-online-" +
                     std::to_string(stamp) + "-" +
                     std::to_string(attempt));
            if (std::filesystem::create_directory(root_)) {
                make_private(root_);
                return;
            }
        }
        throw std::runtime_error("failed to create temporary test tree");
    }

    ~TemporaryTree() {
        std::error_code ignored;
        std::filesystem::remove_all(root_, ignored);
    }

    std::filesystem::path make(std::string_view name) const {
        const std::filesystem::path result = root_ / name;
        if (!std::filesystem::create_directory(result)) {
            throw std::runtime_error("failed to create test directory");
        }
        make_private(result);
        return result;
    }

    static void make_private(const std::filesystem::path &path) {
        std::filesystem::permissions(
            path, std::filesystem::perms::owner_all,
            std::filesystem::perm_options::replace);
    }

  private:
    std::filesystem::path root_;
};

struct PublicationPaths {
    std::filesystem::path container;
    std::filesystem::path shared;
    std::filesystem::path server;
    std::filesystem::path client;
    std::filesystem::path work;

    PackedRolePreprocessingDirectories directories() const {
        return {shared, server, client, work};
    }
};

PublicationPaths publication_paths(const TemporaryTree &tree,
                                   std::string_view prefix) {
    PublicationPaths result;
    result.container = tree.make(prefix);
    for (const auto &entry : std::array{
             std::pair{"shared", &result.shared},
             std::pair{"server", &result.server},
             std::pair{"client", &result.client},
             std::pair{"work", &result.work},
         }) {
        *entry.second = result.container / entry.first;
        if (!std::filesystem::create_directory(*entry.second)) {
            throw std::runtime_error(
                "failed to create role-publication directory");
        }
        TemporaryTree::make_private(*entry.second);
    }
    return result;
}

PayloadCircuit make_payload(PackingGkrVariant variant) {
    PayloadBuilder builder(
        variant == PackingGkrVariant::Folded
            ? PayloadShape::wide(32)
            : PayloadShape::laned(4, 32),
        2);
    const WireId product = builder.mul(0, 1);
    builder.set_outputs({builder.add(product, 0)});
    return builder.finish();
}

CertifiedPackedWorkloadStatic make_workload(PackingGkrVariant variant) {
    PayloadCircuit payload = make_payload(variant);
    LayeredCircuit circuit = compile(payload);
    OutsourcedGateMleSetupArtifacts gate_mle =
        preprocess_outsourced_gate_mle_setup(
            payload, circuit,
            variant == PackingGkrVariant::Laned
                ? gates::GateTableSet::Laned
                : gates::GateTableSet::Wide);
    return certify_packed_workload_static(
        std::move(payload), std::move(circuit),
        std::move(gate_mle.public_setup));
}

TranscriptPackingExternalPreprocessingSpecification specification(
    PackingGkrVariant variant,
    const CertifiedPackedWorkloadStatic &workload) {
    LazyTernaryParameters parameters =
        selected_lazy_ternary_parameters();
    parameters.repetitions = 1;
    return {
        .variant = variant,
        .ring_degree = 32,
        .bhip_round_count =
            variant == PackingGkrVariant::Folded
                ? folded_bhip_round_count(workload.circuit())
                : laned_bhip_round_count(workload.circuit()),
        .parameters = parameters,
        .basefold_parameters = {.log_rate = 1, .query_count = 1},
        .staging_block_elements = 7,
        .canonical_copy_block_elements = 7,
        .basefold_block_elements = 7,
    };
}

TranscriptPackingExternalPreprocessingLimits external_limits(
    const TranscriptPackingExternalPreprocessingPlan &plan) {
    TranscriptPackingExternalPreprocessingLimits result{
        .staging_artifact = {
            .max_total_bytes = plan.staging.artifact_physical_bytes,
            .min_free_bytes = 1,
        },
        .max_staging_working_bytes = plan.staging.peak_working_bytes,
        .canonical_tensor_artifact = {
            .max_total_bytes =
                plan.factored.canonical_artifact_physical_bytes,
            .min_free_bytes = 1,
        },
        .max_live_physical_bytes =
            plan.factored.conservative_peak_live_physical_bytes,
        .max_copy_working_field_bytes =
            plan.factored.peak_copy_working_field_bytes,
    };
    for (const auto &tensor : plan.factored.tensors) {
        result.tensors.push_back({
            .max_final_physical_bytes =
                tensor.commitment.final_physical_bytes,
            .max_scratch_physical_bytes =
                tensor.commitment.scratch_peak_physical_bytes,
            .min_free_bytes = 1,
            .max_working_field_bytes =
                tensor.commitment.peak_working_field_bytes,
        });
    }
    return result;
}

PackedRolePreprocessingPublishLimits publication_limits(
    const CertifiedPackedWorkloadStatic &workload,
    const PackedRolePreprocessingPublicationPlan &plan) {
    const std::uint64_t role_bytes = std::max(
        plan.server_role_static_bytes, plan.client_role_static_bytes);
    return {
        .storage = {
            .max_workload_bytes = 1ULL << 22U,
            .max_role_artifact_bytes = role_bytes,
            .max_manifest_bytes = 1ULL << 20U,
            .min_free_bytes = 1,
            .max_artifact_tree_files = plan.server_artifacts.file_count,
            .max_artifact_tree_directories =
                plan.server_artifacts.directory_count,
            .max_artifact_tree_depth = 2,
            .max_artifact_tree_relative_path_bytes = 256,
            .max_artifact_tree_file_bytes =
                plan.server_artifacts.serialized_bytes,
            .max_artifact_tree_bytes =
                plan.server_artifacts.serialized_bytes,
            .workload_decode = {
                .max_artifact_bytes = 1ULL << 22U,
                .max_slots = 64,
                .max_payload_plaintexts = 64,
                .max_payload_gates = 256,
                .max_payload_outputs = 64,
                .max_layers = 64,
                .max_layer_gates = 1024,
                .max_affine_terms = 4096,
                .max_storage_entries = 8192,
                .max_gate_tables = 128,
            },
        },
        .role_static = {
            .max_encoded_bytes = role_bytes,
            .max_ingress_layers = workload.circuit().layers.size(),
            .max_factored_tensors =
                plan.transcript_packing.factored.tensors.size(),
            .max_relative_path_bytes = 64,
        },
        .transcript_packing = external_limits(plan.transcript_packing),
    };
}

SlotVector sequence(std::size_t count, std::uint64_t seed) {
    SlotVector result;
    result.reserve(count);
    for (std::size_t index = 0; index < count; ++index) {
        result.emplace_back(seed + 5U * index + index * index);
    }
    return result;
}

std::vector<std::size_t> multiplication_layers(
    const LayeredCircuit &circuit) {
    std::vector<std::size_t> result;
    for (std::size_t layer = 0; layer + 1U < circuit.layers.size();
         ++layer) {
        if (layer_kind(circuit.layers[layer]) ==
            LayerKind::Multiplication) {
            result.push_back(layer);
        }
    }
    return result;
}

class PackingRoots {
  public:
    PackingRoots(const TemporaryTree &tree, std::string_view prefix,
                 std::size_t tensor_count)
        : outer_(tree.make(std::string(prefix) + "-outer")),
          assignment_(tree.make(std::string(prefix) + "-assignment")),
          products_(tree.make(std::string(prefix) + "-products")),
          witness_state_(tree.make(
              std::string(prefix) + "-witness-state")),
          witness_commit_scratch_(tree.make(
              std::string(prefix) + "-witness-commit-scratch")),
          constraint_scratch_(tree.make(
              std::string(prefix) + "-constraint-scratch")),
          wiring_matrix_(tree.make(
              std::string(prefix) + "-wiring-matrix")),
          wiring_scratch_(tree.make(
              std::string(prefix) + "-wiring-scratch")),
          witness_opening_scratch_(tree.make(
              std::string(prefix) + "-witness-opening-scratch")) {
        for (std::size_t index = 0; index < tensor_count; ++index) {
            factored_opening_scratch_.push_back(tree.make(
                std::string(prefix) + "-factored-opening-" +
                std::to_string(index)));
        }
    }

    TranscriptPackingExternalProverOptions options() const {
        TranscriptPackingExternalProverOptions result{
            .outer_assignment = {
                .directory = outer_,
                .storage_limits = {.max_total_bytes = 1ULL << 30U,
                                   .min_free_bytes = 1},
                .max_working_field_bytes = 1ULL << 22U,
                .block_elements = 11,
            },
            .spartan = {
                .max_live_storage_bytes = 1ULL << 34U,
                .assignment = {
                    .directory = assignment_,
                    .storage_limits = {
                        .max_total_bytes = 1ULL << 30U,
                        .min_free_bytes = 1,
                    },
                    .max_working_bytes = 1ULL << 24U,
                    .block_elements = 13,
                },
                .matrix_products = {
                    .directory = products_,
                    .storage_limits = {
                        .max_total_bytes = 1ULL << 30U,
                        .min_free_bytes = 1,
                    },
                    .max_working_field_bytes = 1ULL << 22U,
                    .block_elements = 7,
                },
                .witness_commitment = {
                    .destination_directory = witness_state_,
                    .scratch_directory = witness_commit_scratch_,
                    .max_final_bytes = 1ULL << 30U,
                    .max_scratch_bytes = 1ULL << 30U,
                    .min_free_bytes = 1,
                    .max_working_field_bytes = 1ULL << 24U,
                    .block_elements = 7,
                },
                .constraint_sumcheck = {
                    .scratch_directory = constraint_scratch_,
                    .max_live_storage_bytes = 1,
                    .max_total_scratch_bytes = 1ULL << 30U,
                    .min_free_bytes = 1,
                    .max_working_field_bytes = 1ULL << 24U,
                    .block_elements = 7,
                    .source_rounds = 4,
                },
                .wiring_matrix = {
                    .directory = wiring_matrix_,
                    .storage_limits = {
                        .max_total_bytes = 1ULL << 30U,
                        .min_free_bytes = 1,
                    },
                    .max_live_storage_bytes = 1,
                    .max_working_field_bytes = 1ULL << 24U,
                    .block_elements = 7,
                },
                .wiring_sumcheck = {
                    .scratch_directory = wiring_scratch_,
                    .max_live_storage_bytes = 1,
                    .max_total_scratch_bytes = 1ULL << 30U,
                    .min_free_bytes = 1,
                    .max_working_field_bytes = 1ULL << 24U,
                    .block_elements = 7,
                    .source_rounds = 4,
                },
                .factored_evaluation = {
                    .tensor_openings = {},
                    .max_live_storage_bytes = 1,
                    .reserved_live_storage_bytes = 0,
                    .max_working_field_bytes = 1ULL << 28U,
                },
                .witness_opening = {
                    .scratch_directory = witness_opening_scratch_,
                    .max_live_storage_bytes = 1,
                    .max_total_scratch_bytes = 1ULL << 30U,
                    .min_free_bytes = 1,
                    .max_working_field_bytes = 1ULL << 24U,
                    .fold_chunk_elements = 128,
                },
            },
        };
        for (const auto &scratch : factored_opening_scratch_) {
            result.spartan.factored_evaluation.tensor_openings.push_back({
                .scratch_directory = scratch,
                .max_live_storage_bytes = 1,
                .max_total_scratch_bytes = 1ULL << 30U,
                .min_free_bytes = 1,
                .max_working_field_bytes = 1ULL << 24U,
                .fold_chunk_elements = 128,
            });
        }
        return result;
    }

    bool empty() const {
        for (const auto *root : {
                 &outer_, &assignment_, &products_, &witness_state_,
                 &witness_commit_scratch_, &constraint_scratch_,
                 &wiring_matrix_, &wiring_scratch_,
                 &witness_opening_scratch_,
             }) {
            if (!std::filesystem::is_directory(*root) ||
                !std::filesystem::is_empty(*root)) {
                return false;
            }
        }
        return std::ranges::all_of(
            factored_opening_scratch_,
            [](const auto &root) {
                return std::filesystem::is_directory(root) &&
                       std::filesystem::is_empty(root);
            });
    }

  private:
    std::filesystem::path outer_;
    std::filesystem::path assignment_;
    std::filesystem::path products_;
    std::filesystem::path witness_state_;
    std::filesystem::path witness_commit_scratch_;
    std::filesystem::path constraint_scratch_;
    std::filesystem::path wiring_matrix_;
    std::filesystem::path wiring_scratch_;
    std::vector<std::filesystem::path> factored_opening_scratch_;
    std::filesystem::path witness_opening_scratch_;
};

struct RequestRoots {
    RequestRoots(const TemporaryTree &tree, std::string_view prefix,
                 const LayeredCircuit &circuit,
                 std::size_t tensor_count)
        : replay(tree.make(std::string(prefix) + "-replay")),
          packing(tree, std::string(prefix) + "-packing",
                  tensor_count) {
        for (const std::size_t layer : multiplication_layers(circuit)) {
            gkr.push_back(tree.make(
                std::string(prefix) + "-gkr-" +
                std::to_string(layer)));
        }
    }

    bool empty_before_writes() const {
        if (!std::filesystem::is_empty(replay) || !packing.empty()) {
            return false;
        }
        return std::ranges::all_of(gkr, [](const auto &root) {
            return std::filesystem::is_empty(root);
        });
    }

    std::filesystem::path replay;
    std::vector<std::filesystem::path> gkr;
    PackingRoots packing;
};

FoldedServerProofOptions folded_options(
    const LayeredCircuit &circuit, const RequestRoots &roots) {
    FoldedServerProofOptions result;
    result.lifecycle = FileTraceSessionLifecycle::IrreversibleNoRetry;
    result.reclaim_completed_multiplication_scratch = true;
    const auto layers = multiplication_layers(circuit);
    for (std::size_t index = 0; index < layers.size(); ++index) {
        result.proof.multiplication_scratch.push_back({
            .reduction_layer = layers[index],
            .directory = roots.gkr[index],
            .storage_limits = {.max_total_bytes = 1ULL << 27U,
                               .min_free_bytes = 1},
        });
    }
    return result;
}

LanedServerProofOptions laned_options(
    const LayeredCircuit &circuit, const RequestRoots &roots) {
    LanedServerProofOptions result;
    result.lifecycle = FileTraceSessionLifecycle::IrreversibleNoRetry;
    result.reclaim_completed_multiplication_scratch = true;
    const auto layers = multiplication_layers(circuit);
    for (std::size_t index = 0; index < layers.size(); ++index) {
        result.proof.multiplication_scratch.push_back({
            .reduction_layer = layers[index],
            .directory = roots.gkr[index],
            .storage_limits = {.max_total_bytes = 1ULL << 27U,
                               .min_free_bytes = 1},
        });
    }
    return result;
}

PayloadCheckpointReplayExecutionOptions replay_options(
    const RequestRoots &roots) {
    return {
        .directory = roots.replay,
        .min_free_bytes = 1,
        .max_checkpoint_metadata_bytes = 4096,
        .lifecycle = FileTraceSessionLifecycle::IrreversibleNoRetry,
    };
}

PayloadCheckpointReplayProblem checkpoint_problem(
    const LayeredCircuit &circuit, const FheEvaluationPlan &evaluation,
    const ReplayMockBackend::EvalContext &eval,
    const EncryptedTrace<ReplayMockBackend> &trace) {
    const std::vector<std::uint64_t> work =
        payload_replay_work_units(circuit);
    std::vector<PayloadLayerResourceEstimate> resources;
    resources.reserve(trace.layers.size());
    for (std::size_t layer = 0; layer < trace.layers.size(); ++layer) {
        const auto &wires = trace.layers[layer].wires;
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
        if (encrypted == wires.end()) {
            throw std::logic_error("resource trace has no encrypted wire");
        }
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
    return {
        .max_live_scratch_bytes = 1ULL << 30U,
        .max_resident_ciphertext_bytes = 1ULL << 30U,
        .max_ciphertexts_per_chunk = 8,
        .max_recomputation_factor = {100, 1},
        .reserved_live_scratch_bytes = 4096,
        .reserved_resident_bytes = 2048,
    };
}

CheckpointReplayServerStorageLimits storage_limits(
    const LayeredCircuit &circuit,
    const PayloadCheckpointReplayBudgets &budgets) {
    CheckpointReplayServerStorageLimits result{
        .caps = {
            .max_total_local_disk_bytes =
                budgets.max_live_scratch_bytes,
            .max_resident_ram_bytes =
                budgets.max_resident_ciphertext_bytes,
            .max_phase_combined_bytes = 2ULL << 30U,
        },
        .common = {
            .local_disk_bytes = budgets.reserved_live_scratch_bytes,
            .resident_ram_bytes = budgets.reserved_resident_bytes,
        },
        .payload_gkr_only = {},
        .transcript_packing_only = {
            .local_disk_bytes = 1ULL << 28U,
            .resident_ram_bytes = 1ULL << 28U,
        },
    };
    for (std::size_t layer = 0; layer + 1U < circuit.layers.size();
         ++layer) {
        const LayerKind kind = layer_kind(circuit.layers[layer]);
        result.reduction_workspaces.push_back({
            .reduction_layer = layer,
            .kind = kind,
            .multiplication_builder_phase_bytes =
                kind == LayerKind::Multiplication ? 1ULL << 28U : 0,
            .reduction_phase_bytes = 1ULL << 28U,
        });
    }
    return result;
}

Digest session_id(std::uint8_t seed) {
    Digest result{};
    result[0] = seed;
    result[7] = static_cast<std::uint8_t>(seed + 1U);
    return result;
}

std::size_t tensor_count(
    const AuthenticatedPackedServerOnlineState<ReplayMockBackend> &server) {
    const auto &factored = server.prover_setup()
                               .transcript_packing()
                               .spartan_key()
                               .factored_computation;
    if (!factored || factored->tensors.empty()) {
        throw std::logic_error(
            "authenticated server has no factored transcript setup");
    }
    return factored->tensors.size();
}

void check_folded_online_lifecycle(
    const TemporaryTree &tree,
    AuthenticatedPackedServerOnlineState<ReplayMockBackend> &server,
    const std::vector<ReplayMockBackend::Ciphertext> &encrypted_inputs,
    const PayloadCheckpointReplayBudgets &budgets) {
    const LayeredCircuit &circuit = server.checkpoint_replay().circuit();
    const auto limits = storage_limits(circuit, budgets);

    RequestRoots rejected_roots(
        tree, "folded-rejected", circuit, tensor_count(server));
    auto rejected_packing = admit_transcript_packing_external(
        PackingGkrVariant::Folded,
        server.prover_setup().transcript_packing(),
        rejected_roots.packing.options());
    auto rejected_resources =
        prepare_folded_request_resources(
            server, replay_options(rejected_roots),
            folded_options(circuit, rejected_roots),
            std::move(rejected_packing), limits);

    RequestRoots accepted_roots(
        tree, "folded-accepted", circuit, tensor_count(server));
    auto accepted_packing = admit_transcript_packing_external(
        PackingGkrVariant::Folded,
        server.prover_setup().transcript_packing(),
        accepted_roots.packing.options());
    auto accepted_resources =
        prepare_folded_request_resources(
            server, replay_options(accepted_roots),
            folded_options(circuit, accepted_roots),
            std::move(accepted_packing), limits);
    const CheckpointReplayServerStorageAdmission accepted_admission =
        accepted_resources.storage_admission();

    FoldedEvaluationRequest<ReplayMockBackend> request{
        .setup_id = server.setup_id(),
        .session_id = session_id(17),
        .circuit_id = server.circuit_id(),
        .trace_id =
            prevalidated_trace_identity::validated_fhe_evaluated_trace_id<
                ReplayMockBackend>(
                server.circuit_id(), server.checkpoint_replay().input_count(),
                encrypted_inputs),
        .encrypted_inputs = encrypted_inputs,
    };
    FoldedEvaluationRequest<ReplayMockBackend> malformed = request;
    malformed.trace_id[0] ^= 1U;

    diagnostics::PublicSetupValidationCounter setup_scans;
    diagnostics::LayeredCircuitValidationCounter circuit_scans;
    {
        diagnostics::ObservePublicSetupValidation observe_setup(setup_scans);
        diagnostics::ObserveLayeredCircuitValidation observe_circuit(
            circuit_scans);
        CHECK(rejects([&] {
            (void)evaluate_folded_request<
                ReplayMockBackend>(server, malformed,
                                   std::move(rejected_resources));
        }));
        CHECK(rejected_roots.empty_before_writes());
        CHECK(setup_scans.scans == 0);
        CHECK(circuit_scans.scans == 0);

        auto evaluated =
            evaluate_folded_request<
                ReplayMockBackend>(server, request,
                                   std::move(accepted_resources));
        CHECK(setup_scans.scans == 0);
        CHECK(circuit_scans.scans == 0);
        Transcript transcript("test/packed-server-online/folded/v1");
        auto proved =
            prove_folded_response_irreversible<
                ReplayMockBackend>(server, evaluated, transcript);
        CHECK(proved.response.setup_id == request.setup_id);
        CHECK(proved.response.session_id == request.session_id);
        CHECK(proved.response.circuit_id == request.circuit_id);
        CHECK(proved.response.trace_id == request.trace_id);
        CHECK(proved.payload_replay_report.all_payload_artifacts_retired);
        CHECK(proved.payload_replay_report.live_physical_bytes == 0);
        CHECK(proved.storage_admission == accepted_admission);
        CHECK(accepted_roots.packing.empty());
    }
    CHECK(setup_scans.scans == 0);
    CHECK(circuit_scans.scans == 0);
}

void check_laned_online_lifecycle(
    const TemporaryTree &tree,
    AuthenticatedPackedServerOnlineState<ReplayMockBackend> &server,
    const std::vector<ReplayMockBackend::Ciphertext> &encrypted_inputs,
    const PayloadCheckpointReplayBudgets &budgets) {
    const LayeredCircuit &circuit = server.checkpoint_replay().circuit();
    const auto limits = storage_limits(circuit, budgets);

    RequestRoots rejected_roots(
        tree, "laned-rejected", circuit, tensor_count(server));
    auto rejected_packing = admit_transcript_packing_external(
        PackingGkrVariant::Laned,
        server.prover_setup().transcript_packing(),
        rejected_roots.packing.options());
    auto rejected_resources =
        prepare_laned_request_resources(
            server, replay_options(rejected_roots),
            laned_options(circuit, rejected_roots),
            std::move(rejected_packing), limits);

    RequestRoots accepted_roots(
        tree, "laned-accepted", circuit, tensor_count(server));
    auto accepted_packing = admit_transcript_packing_external(
        PackingGkrVariant::Laned,
        server.prover_setup().transcript_packing(),
        accepted_roots.packing.options());
    auto accepted_resources =
        prepare_laned_request_resources(
            server, replay_options(accepted_roots),
            laned_options(circuit, accepted_roots),
            std::move(accepted_packing), limits);
    const CheckpointReplayServerStorageAdmission accepted_admission =
        accepted_resources.storage_admission();

    LanedEvaluationRequest<ReplayMockBackend> request{
        .setup_id = server.setup_id(),
        .session_id = session_id(29),
        .circuit_id = server.circuit_id(),
        .trace_id =
            prevalidated_trace_identity::validated_fhe_evaluated_trace_id<
                ReplayMockBackend>(
                server.circuit_id(), server.checkpoint_replay().input_count(),
                encrypted_inputs),
        .encrypted_inputs = encrypted_inputs,
    };
    LanedEvaluationRequest<ReplayMockBackend> malformed = request;
    malformed.trace_id[0] ^= 1U;

    diagnostics::PublicSetupValidationCounter setup_scans;
    diagnostics::LayeredCircuitValidationCounter circuit_scans;
    {
        diagnostics::ObservePublicSetupValidation observe_setup(setup_scans);
        diagnostics::ObserveLayeredCircuitValidation observe_circuit(
            circuit_scans);
        CHECK(rejects([&] {
            (void)evaluate_laned_request<
                ReplayMockBackend>(server, malformed,
                                   std::move(rejected_resources));
        }));
        CHECK(rejected_roots.empty_before_writes());
        CHECK(setup_scans.scans == 0);
        CHECK(circuit_scans.scans == 0);

        auto evaluated =
            evaluate_laned_request<
                ReplayMockBackend>(server, request,
                                   std::move(accepted_resources));
        CHECK(setup_scans.scans == 0);
        CHECK(circuit_scans.scans == 0);
        Transcript transcript("test/packed-server-online/laned/v1");
        auto proved =
            prove_laned_response_irreversible<
                ReplayMockBackend>(server, evaluated, transcript);
        CHECK(proved.response.setup_id == request.setup_id);
        CHECK(proved.response.session_id == request.session_id);
        CHECK(proved.response.circuit_id == request.circuit_id);
        CHECK(proved.response.trace_id == request.trace_id);
        CHECK(proved.payload_replay_report.all_payload_artifacts_retired);
        CHECK(proved.payload_replay_report.live_physical_bytes == 0);
        CHECK(proved.storage_admission == accepted_admission);
        CHECK(accepted_roots.packing.empty());
    }
    CHECK(setup_scans.scans == 0);
    CHECK(circuit_scans.scans == 0);
}

void run_variant(PackingGkrVariant variant) {
    TemporaryTree tree;
    CertifiedPackedWorkloadStatic workload = make_workload(variant);
    auto contexts = ReplayMockBackend::create({
        .slot_count = 32,
        .fresh_rns_limbs = 14,
        .bits_per_limb = 300,
    });
    const auto verifier_context =
        ReplayMockBackend::make_public_verifier_context(contexts.client);
    ReplayMockBackend::preprocess_fixed_message_cells(contexts.eval);

    const auto spec = specification(variant, workload);
    const auto publication_plan =
        plan_packed_role_preprocessing_publication(
            workload, spec,
            ReplayMockBackend::storage_context_id(contexts.eval));
    const auto limits = publication_limits(workload, publication_plan);
    const PublicationPaths paths = publication_paths(
        tree, variant == PackingGkrVariant::Folded
                  ? "folded-preprocessing"
                  : "laned-preprocessing");
    const auto published = publish_packed_role_preprocessing<
        ReplayMockBackend>(
        workload, spec, contexts.eval, contexts.client,
        verifier_context, paths.directories(), limits);
    auto restored = open_packed_server_evaluation<ReplayMockBackend>(
        paths.shared, paths.server, published.root.storage_identity,
        std::move(contexts.eval),
        packed_role_preprocessing_open_limits(limits));
    const ReplayMockBackend::EvalContext *const evaluation_context_address =
        &restored.evaluation_context();
    CHECK(&restored.role().evaluation_context() ==
          evaluation_context_address);
    CHECK(setup_digest(restored.public_setup()) ==
          restored.role().workload().setup_digest());
    CHECK(restored.public_setup().shape ==
          restored.role().workload().public_setup().shape);
    CHECK(ReplayMockBackend::slot_count(
              restored.evaluation_context()) == 32);
    CHECK(restored.public_setup().shape.slot_count == 32);
    CHECK(restored.public_setup().shape.kind ==
          (variant == PackingGkrVariant::Folded
               ? PayloadKind::Wide
               : PayloadKind::Laned));
    CHECK(restored.public_setup().shape.lane_count ==
          (variant == PackingGkrVariant::Folded ? 0 : 4));

    FheEvaluationPlan evaluation_plan =
        protocol::detail::apply_packed_proof_ingress_schedule(
            workload.circuit(),
            FheEvaluationPlan::at_evaluation_levels(
                workload.circuit(), 13, 1, 0),
            restored.role().prover_setup()
                .proof_ingress_rns_limbs_by_layer());
    const std::vector<SlotVector> inputs{
        sequence(variant == PackingGkrVariant::Folded ? 32 : 4, 7),
        sequence(variant == PackingGkrVariant::Folded ? 32 : 4, 31),
    };
    const std::vector<ReplayMockBackend::Ciphertext> encrypted_inputs =
        variant == PackingGkrVariant::Folded
            ? encrypt_wide_payload_inputs<ReplayMockBackend>(
                  contexts.client, workload.payload(), inputs)
            : encrypt_laned_payload_inputs<ReplayMockBackend>(
                  contexts.client, workload.payload(), inputs);

    FheEvaluationPlan natural = evaluation_plan;
    natural.proof_ingress_mult_depth_by_layer =
        natural.trace.required_mult_depth_by_layer;
    const EncryptedTrace<ReplayMockBackend> resource_trace =
        variant == PackingGkrVariant::Folded
            ? evaluate_wide_fhe_trace_into<ReplayMockBackend>(
                  restored.evaluation_context(), workload.payload(),
                  workload.circuit(), encrypted_inputs, natural,
                  InMemoryTraceSink<ReplayMockBackend>{
                      restored.evaluation_context()})
            : evaluate_laned_fhe_trace_into<ReplayMockBackend>(
                  restored.evaluation_context(), workload.payload(),
                  workload.circuit(), encrypted_inputs, natural,
                  InMemoryTraceSink<ReplayMockBackend>{
                      restored.evaluation_context()});
    const PayloadCheckpointReplayProblem problem = checkpoint_problem(
        workload.circuit(), evaluation_plan,
        restored.evaluation_context(),
        resource_trace);
    const PayloadCheckpointReplayBudgets budgets = checkpoint_budgets();
    const PayloadCheckpointReplayPlan replay_plan =
        plan_payload_checkpoint_replay(problem, budgets);

    diagnostics::PublicSetupValidationCounter startup_setup_scans;
    diagnostics::LayeredCircuitValidationCounter startup_circuit_scans;
    auto server = [&] {
        diagnostics::ObservePublicSetupValidation observe_setup(
            startup_setup_scans);
        diagnostics::ObserveLayeredCircuitValidation observe_circuit(
            startup_circuit_scans);
        return make_authenticated_packed_server_online_state<
            ReplayMockBackend>(
            std::move(restored), evaluation_plan, problem, budgets,
            replay_plan);
    }();
    CHECK(startup_setup_scans.scans > 0);
    CHECK(startup_circuit_scans.scans > 0);
    CHECK(&server.evaluation_context() == evaluation_context_address);

    if (variant == PackingGkrVariant::Folded) {
        check_folded_online_lifecycle(
            tree, server, encrypted_inputs, budgets);
    } else {
        check_laned_online_lifecycle(
            tree, server, encrypted_inputs, budgets);
    }
}

} // namespace

int main() {
    test::Runner runner("authenticated packed server online");
    runner.run("Folded recurring path has no static validation scans", [] {
        run_variant(PackingGkrVariant::Folded);
    });
    runner.run("Laned recurring path has no static validation scans", [] {
        run_variant(PackingGkrVariant::Laned);
    });
    return runner.summary();
}
