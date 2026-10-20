/// @file test_packed_external.cpp
/// @brief Folded/Laned checkpoint replay with external transcript packing.

#include "test_helpers.hpp"

#include "laminate/fhe/mock_backend.hpp"
#include "laminate/payload/compiler.hpp"
#include "laminate/payload/laned_fhe_evaluator.hpp"
#include "laminate/payload/input_encryption.hpp"
#include "laminate/payload/wide_fhe_evaluator.hpp"
#include "laminate/protocol/packed/external/prover.hpp"
#include "laminate/protocol/detail/packing/gkr_transcript_replay.hpp"
#include "laminate/protocol/packed/reference/materialized_external_setup.hpp"
#include "laminate/protocol/reference/folded.hpp"
#include "laminate/protocol/reference/laned.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
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
using namespace laminate::fhe;
using namespace laminate::gkr;
using namespace laminate::packing;
using namespace laminate::payload;
using namespace laminate::protocol;

namespace {

struct ReplayMockBackend : MockBackend {
    static std::size_t remaining_mult_depth(
        const EvalContext &, const Ciphertext &ciphertext) {
        return ciphertext.rns_limbs - 1U;
    }
};

static_assert(fhe::PersistableFheBackend<ReplayMockBackend>);
static_assert(!std::is_copy_constructible_v<
              TranscriptPackingExternalAdmission>);
static_assert(!std::is_copy_constructible_v<
              FoldedCheckpointReplayExternalAdmission<ReplayMockBackend>>);
static_assert(!std::is_copy_constructible_v<
              LanedCheckpointReplayExternalAdmission<ReplayMockBackend>>);

class TemporaryTree {
  public:
    TemporaryTree() {
        const auto stamp = std::chrono::steady_clock::now()
                               .time_since_epoch()
                               .count();
        for (std::size_t attempt = 0; attempt < 100; ++attempt) {
            root_ = std::filesystem::temp_directory_path() /
                    ("laminate-packed-external-" +
                     std::to_string(stamp) + "-" +
                     std::to_string(attempt));
            if (std::filesystem::create_directory(root_)) {
                return;
            }
        }
        throw std::runtime_error("failed to create temporary tree");
    }

    ~TemporaryTree() {
        std::error_code ignored;
        std::filesystem::remove_all(root_, ignored);
    }

    std::filesystem::path make(std::string_view name) const {
        const std::filesystem::path path = root_ / name;
        if (!std::filesystem::create_directory(path)) {
            throw std::runtime_error("failed to create temporary child");
        }
        return path;
    }

  private:
    std::filesystem::path root_;
};

struct OnlineRoots {
    OnlineRoots(const TemporaryTree &tree, std::string_view prefix,
                std::size_t tensor_count)
        : outer(tree.make(std::string(prefix) + "-outer")),
          assignment(tree.make(std::string(prefix) + "-assignment")),
          products(tree.make(std::string(prefix) + "-products")),
          witness_state(tree.make(
              std::string(prefix) + "-witness-state")),
          witness_commit_scratch(tree.make(
              std::string(prefix) + "-witness-commit-scratch")),
          constraint_scratch(tree.make(
              std::string(prefix) + "-constraint-scratch")),
          wiring_matrix(tree.make(
              std::string(prefix) + "-wiring-matrix")),
          wiring_scratch(tree.make(
              std::string(prefix) + "-wiring-scratch")),
          witness_opening_scratch(tree.make(
              std::string(prefix) + "-witness-opening-scratch")) {
        for (std::size_t index = 0; index < tensor_count; ++index) {
            factored_opening_scratch.push_back(tree.make(
                std::string(prefix) + "-factored-opening-scratch-" +
                std::to_string(index)));
        }
    }

    bool empty() const {
        for (const auto *root : {
                 &outer,
                 &assignment,
                 &products,
                 &witness_state,
                 &witness_commit_scratch,
                 &constraint_scratch,
                 &wiring_matrix,
                 &wiring_scratch,
                 &witness_opening_scratch,
             }) {
            if (!std::filesystem::is_directory(*root) ||
                !std::filesystem::is_empty(*root)) {
                return false;
            }
        }
        for (const auto &root : factored_opening_scratch) {
            if (!std::filesystem::is_directory(root) ||
                !std::filesystem::is_empty(root)) {
                return false;
            }
        }
        return true;
    }

    std::filesystem::path outer;
    std::filesystem::path assignment;
    std::filesystem::path products;
    std::filesystem::path witness_state;
    std::filesystem::path witness_commit_scratch;
    std::filesystem::path constraint_scratch;
    std::filesystem::path wiring_matrix;
    std::filesystem::path wiring_scratch;
    std::vector<std::filesystem::path> factored_opening_scratch;
    std::filesystem::path witness_opening_scratch;
};

TranscriptPackingExternalProverOptions packing_options(
    const OnlineRoots &roots) {
    TranscriptPackingExternalProverOptions result{
        .outer_assignment = {
            .directory = roots.outer,
            .storage_limits = {.max_total_bytes = 1ULL << 30U,
                               .min_free_bytes = 1},
            .max_working_field_bytes = 1ULL << 22U,
            .block_elements = 11,
        },
        .spartan = {
            .max_live_storage_bytes = 1ULL << 34U,
            .assignment = {
                .directory = roots.assignment,
                .storage_limits = {.max_total_bytes = 1ULL << 30U,
                                   .min_free_bytes = 1},
                .max_working_bytes = 1ULL << 24U,
                .block_elements = 13,
            },
            .matrix_products = {
                .directory = roots.products,
                .storage_limits = {.max_total_bytes = 1ULL << 30U,
                                   .min_free_bytes = 1},
                .max_working_field_bytes = 1ULL << 22U,
                .block_elements = 7,
            },
            .witness_commitment = {
                .destination_directory = roots.witness_state,
                .scratch_directory = roots.witness_commit_scratch,
                .max_final_bytes = 1ULL << 30U,
                .max_scratch_bytes = 1ULL << 30U,
                .min_free_bytes = 1,
                .max_working_field_bytes = 1ULL << 24U,
                .block_elements = 7,
            },
            .constraint_sumcheck = {
                .scratch_directory = roots.constraint_scratch,
                .max_live_storage_bytes = 1,
                .max_total_scratch_bytes = 1ULL << 30U,
                .min_free_bytes = 1,
                .max_working_field_bytes = 1ULL << 24U,
                .block_elements = 7,
                .source_rounds = 4,
            },
            .wiring_matrix = {
                .directory = roots.wiring_matrix,
                .storage_limits = {.max_total_bytes = 1ULL << 30U,
                                   .min_free_bytes = 1},
                .max_live_storage_bytes = 1,
                .max_working_field_bytes = 1ULL << 24U,
                .block_elements = 7,
            },
            .wiring_sumcheck = {
                .scratch_directory = roots.wiring_scratch,
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
                .scratch_directory = roots.witness_opening_scratch,
                .max_live_storage_bytes = 1,
                .max_total_scratch_bytes = 1ULL << 30U,
                .min_free_bytes = 1,
                .max_working_field_bytes = 1ULL << 24U,
                .fold_chunk_elements = 128,
            },
        },
    };
    for (const auto &scratch : roots.factored_opening_scratch) {
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

struct ExternalPacking {
    TranscriptPackingExternalProverSetup prover;
    TranscriptPackingSpartanVerifierSetup verifier;
    std::size_t tensor_count = 0;
};

ExternalPacking externalize_packing(
    const TranscriptPackingSpartanSetup &resident,
    const TemporaryTree &tree, std::string_view prefix) {
    const auto pcs = std::make_shared<const spartan::BaseFoldPcs>(
        resident.basefold_parameters);
    const auto &resident_factored =
        resident.spartan.prover_key.factored_computation;
    if (resident_factored == nullptr ||
        resident_factored->tensors.empty()) {
        throw std::logic_error("test packing setup has no tensors");
    }
    std::vector<std::vector<std::vector<Fq>>> columns;
    for (const auto &tensor : resident_factored->tensors) {
        columns.push_back(tensor.columns);
    }
    const ProofOfPackingStructuredMetadata relation =
        make_proof_of_packing_structured_metadata(
            resident.alignment_layout, resident.parameters);
    const auto structure = make_proof_of_packing_factored_structure(
        relation.relation_plan, relation.r1cs_layout,
        relation.tensor_mappings,
        resident.spartan.prover_key.circuit->metadata());
    spartan::FactoredMatrixSetup factored =
        spartan::preprocess_factored_matrix_to_artifact(
            structure, std::move(columns), *pcs,
            {.directory = tree.make(
                 std::string(prefix) + "-tensor-columns"),
             .limits = {.max_total_bytes = 1ULL << 30U,
                        .min_free_bytes = 1}});
    for (std::size_t index = 0;
         index < factored.prover_key.tensors.size(); ++index) {
        const spartan::BaseFoldExternalization externalized =
            pcs->externalize_prover_state(
                factored.prover_key.tensors[index].opening_state,
                {.directory = tree.make(
                     std::string(prefix) + "-tensor-state-" +
                     std::to_string(index)),
                 .limits = {.max_total_bytes = 1ULL << 30U,
                            .min_free_bytes = 1}});
        factored.prover_key.tensors[index].opening_state =
            externalized.prover_state;
        factored.prover_key.tensors[index].opening_state_source =
            spartan::FactoredTensorProverKey::OpeningStateSource::External;
    }
    spartan::ExternalSetup external =
        spartan::setup_external_committed_factored(
            resident.spartan.prover_key.circuit->metadata(), *pcs,
            std::make_shared<const spartan::FactoredMatrixProverKey>(
                std::move(factored.prover_key)),
            std::make_shared<const spartan::FactoredMatrixVerifierKey>(
                std::move(factored.verifier_key)));
    TranscriptPackingExternalProverSetup prover =
        reference::make_materialized_reference_external_prover_setup(
            resident, pcs, external.prover_key);
    const auto &bound = prover.relation();
    TranscriptPackingSpartanVerifierSetup verifier{
        .variant = resident.variant,
        .bhip_round_count = resident.bhip_round_count,
        .alignment_layout = bound.alignment_layout,
        .relation_plan = bound.relation_plan,
        .parameters = bound.parameters,
        .radix = bound.parameters.packing_radix,
        .basefold_parameters = resident.basefold_parameters,
        .spartan = std::move(external.verifier_key),
    };
    return {
        .prover = std::move(prover),
        .verifier = std::move(verifier),
        .tensor_count = resident_factored->tensors.size(),
    };
}

SlotVector values(std::size_t count, std::uint64_t seed) {
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

FoldedExternalGkrProofOptions folded_gkr_options(
    const LayeredCircuit &circuit, const TemporaryTree &tree,
    std::string_view prefix) {
    FoldedExternalGkrProofOptions options;
    options.lifecycle = FileTraceSessionLifecycle::IrreversibleNoRetry;
    options.reclaim_completed_multiplication_scratch = true;
    for (const std::size_t layer : multiplication_layers(circuit)) {
        options.proof.multiplication_scratch.push_back(
            gkr::folded_detail::FileFoldedMultiplicationScratch{
                .reduction_layer = layer,
                .directory = tree.make(
                    std::string(prefix) + "-" +
                    std::to_string(layer)),
                .storage_limits = {.max_total_bytes = 1ULL << 27U,
                                   .min_free_bytes = 1},
            });
    }
    return options;
}

LanedExternalGkrProofOptions laned_gkr_options(
    const LayeredCircuit &circuit, const TemporaryTree &tree,
    std::string_view prefix) {
    LanedExternalGkrProofOptions options;
    options.lifecycle = FileTraceSessionLifecycle::IrreversibleNoRetry;
    options.reclaim_completed_multiplication_scratch = true;
    for (const std::size_t layer : multiplication_layers(circuit)) {
        options.proof.multiplication_scratch.push_back(
            gkr::laned_detail::FileLanedMultiplicationScratch{
                .reduction_layer = layer,
                .directory = tree.make(
                    std::string(prefix) + "-" +
                    std::to_string(layer)),
                .storage_limits = {.max_total_bytes = 1ULL << 27U,
                                   .min_free_bytes = 1},
            });
    }
    return options;
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

PayloadCheckpointReplayTrace<ReplayMockBackend> publish_replay(
    const ReplayMockBackend::EvalContext &eval,
    const PayloadCircuit &payload, const LayeredCircuit &circuit,
    std::span<const ReplayMockBackend::Ciphertext> encrypted_inputs,
    const FheEvaluationPlan &evaluation,
    const PayloadCheckpointReplayProblem &problem,
    const PayloadCheckpointReplayBudgets &budgets,
    const PayloadCheckpointReplayPlan &plan,
    const std::filesystem::path &directory,
    bool eager_laned_witness_packing = false) {
    std::vector<fhe::FheValue<ReplayMockBackend>> output;
    return PayloadCheckpointReplayTrace<ReplayMockBackend>::publish(
        eval, payload, circuit, encrypted_inputs, evaluation, problem,
        budgets, plan,
        {.directory = directory,
         .min_free_bytes = 1,
         .max_checkpoint_metadata_bytes = 4096,
         .lifecycle = FileTraceSessionLifecycle::IrreversibleNoRetry,
         .eager_laned_witness_packing = eager_laned_witness_packing},
        output);
}

template <typename Action>
bool rejects(Action action) {
    try {
        action();
    } catch (const std::exception &) {
        return true;
    }
    return false;
}

std::vector<std::optional<std::vector<std::uint8_t>>> encoded_reveals(
    std::span<const std::optional<ReplayMockBackend::Ciphertext>> values) {
    std::vector<std::optional<std::vector<std::uint8_t>>> result;
    for (const auto &value : values) {
        result.push_back(
            value ? std::optional(ReplayMockBackend::serialize(*value))
                  : std::nullopt);
    }
    return result;
}

} // namespace

int main() {
    test::Runner runner("packed external checkpoint replay");

    runner.run("Folded admission, parity, verification, and retirement", [] {
        constexpr std::size_t kSlots = 32;
        TemporaryTree tree;
        PayloadBuilder builder(PayloadShape::wide(kSlots), 2);
        const WireId product = builder.mul(0, 1);
        builder.set_outputs({builder.add(product, 0)});
        const PayloadCircuit payload = builder.finish();
        const LayeredCircuit circuit = compile(payload);
        const std::vector<SlotVector> inputs{values(kSlots, 7),
                                             values(kSlots, 31)};
        const PlainTrace plain = synthesize_trace(payload, circuit, inputs);
        auto contexts = ReplayMockBackend::create(MockParameters{
            .slot_count = kSlots,
            .fresh_rns_limbs = 14,
            .bits_per_limb = 300,
        });
        ReplayMockBackend::preprocess_fixed_message_cells(contexts.eval);
        const PublicSetup public_setup = make_direct_setup(payload, circuit);
        const EvaluationSetup<ReplayMockBackend> evaluation_setup =
            make_packed_evaluation_setup<ReplayMockBackend>(
                public_setup, contexts.eval);
        const ClientSetup<ReplayMockBackend> client_setup =
            make_client_setup<ReplayMockBackend>(
                public_setup, contexts.client);
        const ConservativePackedProofIngressSchedule ingress =
            derive_conservative_packed_proof_ingress_schedule(
                PackingGkrVariant::Folded, payload, circuit,
                public_setup);
        auto parameters = selected_lazy_ternary_parameters();
        parameters.repetitions = 1;
        const spartan::BaseFoldPcsParameters basefold{
            .log_rate = 1,
            .query_count = 1,
        };
        const FoldedSetup resident_setup =
            setup_folded_conservative<ReplayMockBackend>(
                payload, circuit, public_setup, contexts.eval, ingress,
                parameters, basefold);
        ExternalPacking external = externalize_packing(
            resident_setup.transcript_packing, tree, "folded-preprocessed");
        const FoldedVerifierSetup external_verifier{
            .transcript_packing = external.verifier,
        };
        const FoldedVerifierSetup resident_verifier =
            verifier_setup(resident_setup);
        CHECK(external_verifier.transcript_packing.spartan.setup_digest ==
              resident_verifier.transcript_packing.spartan.setup_digest);
        CHECK(external_verifier.transcript_packing.spartan
                  .circuit_metadata ==
              resident_verifier.transcript_packing.spartan
                  .circuit_metadata);
        CHECK(external_verifier.transcript_packing.spartan
                  .factored_computation->commitment ==
              resident_verifier.transcript_packing.spartan
                  .factored_computation->commitment);
        const PackedExternalProverSetup packed_setup =
            make_folded_packed_external_prover_setup(
                payload, circuit, public_setup, ingress,
                std::move(external.prover));

        const FheEvaluationPlan evaluation =
            apply_packed_proof_ingress_schedule(
                circuit,
                FheEvaluationPlan::at_evaluation_levels(
                    circuit, 13, 1, 0),
                resident_setup);
        const std::vector<ReplayMockBackend::Ciphertext> encrypted_inputs =
            encrypt_wide_payload_inputs<ReplayMockBackend>(
                contexts.client, payload, inputs);
        FheEvaluationPlan natural = evaluation;
        natural.proof_ingress_mult_depth_by_layer =
            natural.trace.required_mult_depth_by_layer;
        const EncryptedTrace<ReplayMockBackend> resource_trace =
            evaluate_wide_fhe_trace_into<ReplayMockBackend>(
                contexts.eval, payload, circuit, encrypted_inputs, natural,
                InMemoryTraceSink<ReplayMockBackend>{contexts.eval});
        const PayloadCheckpointReplayProblem problem = checkpoint_problem(
            circuit, evaluation, contexts.eval, resource_trace);
        const PayloadCheckpointReplayBudgets budgets =
            checkpoint_budgets();
        const PayloadCheckpointReplayPlan plan =
            plan_payload_checkpoint_replay(problem, budgets);
        auto resident_trace = publish_replay(
            contexts.eval, payload, circuit, encrypted_inputs, evaluation,
            problem, budgets, plan, tree.make("folded-resident-replay"));
        auto external_trace = publish_replay(
            contexts.eval, payload, circuit, encrypted_inputs, evaluation,
            problem, budgets, plan, tree.make("folded-external-replay"));
        const Digest trace_id = external_trace.descriptor().trace_id;
        CHECK(resident_trace.descriptor().trace_id == trace_id);

        const std::vector<Fpk> output_point(
            gkr::base_detail::layer_vars(circuit, 0),
            Fpk::from_base(Fp(19)));
        const SingleClaim output_claim = make_layer_claim(
            plain.layers.front(), output_point);
        Transcript resident_transcript(
            "test/packed-external/folded/v1");
        const auto resident =
            reference::prove_folded_checkpoint_replay_irreversible_reference<ReplayMockBackend>(
                payload, circuit, resident_trace, evaluation_setup,
                resident_setup, output_point, resident_transcript,
                folded_gkr_options(
                    circuit, tree, "folded-resident-gkr"));

        OnlineRoots roots(
            tree, "folded-external-online", external.tensor_count);
        FoldedCheckpointReplayExternalOptions options{
            .gkr = folded_gkr_options(
                circuit, tree, "folded-external-gkr"),
            .transcript_packing = packing_options(roots),
        };
        const std::uint64_t live_before =
            external_trace.report().live_physical_bytes;
        auto admission =
            admit_folded_checkpoint_replay_external_irreversible<
                ReplayMockBackend>(
                payload, circuit, external_trace, evaluation_setup,
                packed_setup, output_point, options);
        CHECK(!external_trace.proof_attempt_started());
        CHECK(external_trace.report().live_physical_bytes == live_before);
        CHECK(roots.empty());
        CHECK(admission.packing_report().spartan_storage
                  .preprocessing_validation_bytes > 0);

        Transcript external_transcript(
            "test/packed-external/folded/v1");
        const auto proved =
            prove_folded_checkpoint_replay_external_irreversible<
                ReplayMockBackend>(
                std::move(admission), external_transcript);
        CHECK(roots.empty());
        CHECK(proved.payload_replay_report.all_payload_artifacts_retired);
        CHECK(proved.payload_replay_report.live_physical_bytes == 0);
        CHECK(proved.transcript_packing_report.storage
                  .preprocessing_validation_bytes > 0);
        CHECK(protocol::detail::encode_committed_gkr(
                  proved.proof.gkr) ==
              protocol::detail::encode_committed_gkr(
                  resident.proof.gkr));
        CHECK(encoded_reveals(
                  proved.proof.transcript_packing
                      .well_formedness_reveals) ==
              encoded_reveals(
                  resident.proof.transcript_packing
                      .well_formedness_reveals));
        CHECK(encoded_reveals(
                  proved.proof.transcript_packing
                      .digit_decomposed_packed_values) ==
              encoded_reveals(
                  resident.proof.transcript_packing
                      .digit_decomposed_packed_values));
        CHECK(spartan::encode_proof(
                  proved.proof.transcript_packing.proof_of_packing) ==
              spartan::encode_proof(
                  resident.proof.transcript_packing.proof_of_packing));
        CHECK(external_transcript.challenge_fq2() ==
              resident_transcript.challenge_fq2());
        const std::vector<SlotVector> input_layer =
            make_plain_input_layer(circuit, inputs);
        Transcript packing_verifier_transcript(
            "test/packed-external/folded/v1");
        const auto public_gkr =
            protocol::detail::replay_packed_gkr_transcript<
                ProtocolVariant::LaminateFolded, ReplayMockBackend>(
                circuit, public_setup, proved.proof.gkr,
                output_claim.point, packing_verifier_transcript);
        CHECK(public_gkr.has_value());
        protocol::detail::bind_committed_gkr_for_packing(
            proved.proof.gkr, packing_verifier_transcript);
        const auto committed_messages =
            collect_transcript_packing_committed_messages(
                proved.proof.gkr);
        if (committed_messages.size() !=
            external_verifier.transcript_packing.alignment_layout
                .placements.size()) {
            throw std::runtime_error(
                "committed/layout sizes " +
                std::to_string(committed_messages.size()) + "/" +
                std::to_string(
                    external_verifier.transcript_packing.alignment_layout
                        .placements.size()));
        }
        const auto packing_verified =
            protocol::detail::verify_transcript_packing<ReplayMockBackend>(
                contexts.eval, contexts.client,
                external_verifier.transcript_packing,
                committed_messages,
                proved.proof.transcript_packing,
                packing_verifier_transcript);
        CHECK(packing_verified.spartan_proof);
        CHECK(packing_verified.threshold_checks);
        Transcript resident_verifier_transcript(
            "test/packed-external/folded/v1");
        CHECK(verify_folded<ReplayMockBackend>(
            payload, circuit, input_layer, contexts.eval,
            resident_verifier, client_setup,
            TraceProvenance::FheEvaluated, trace_id, output_claim,
            resident.proof, resident_verifier_transcript));
        Transcript verifier_transcript(
            "test/packed-external/folded/v1");
        CHECK(verify_folded<ReplayMockBackend>(
            payload, circuit, input_layer, contexts.eval,
            external_verifier, client_setup,
            TraceProvenance::FheEvaluated, trace_id, output_claim,
            proved.proof, verifier_transcript));
    });

    runner.run("Laned admission, parity, verification, and retirement", [] {
        constexpr std::size_t kLanes = 4;
        constexpr std::size_t kSlots = 32;
        TemporaryTree tree;
        PayloadBuilder builder(PayloadShape::laned(kLanes, kSlots), 2);
        const WireId product = builder.mul(0, 1);
        builder.set_outputs({builder.add(product, 0)});
        const PayloadCircuit payload = builder.finish();
        const LayeredCircuit circuit = compile(payload);
        const std::vector<SlotVector> inputs{values(kLanes, 7),
                                             values(kLanes, 31)};
        const PlainTrace plain = synthesize_trace(payload, circuit, inputs);
        auto contexts = ReplayMockBackend::create(MockParameters{
            .slot_count = kSlots,
            .fresh_rns_limbs = 14,
            .bits_per_limb = 300,
        });
        ReplayMockBackend::preprocess_fixed_message_cells(contexts.eval);
        const PublicSetup public_setup = make_direct_setup(payload, circuit);
        const EvaluationSetup<ReplayMockBackend> evaluation_setup =
            make_packed_evaluation_setup<ReplayMockBackend>(
                public_setup, contexts.eval);
        const ClientSetup<ReplayMockBackend> client_setup =
            make_client_setup<ReplayMockBackend>(
                public_setup, contexts.client);
        const ConservativePackedProofIngressSchedule ingress =
            derive_conservative_packed_proof_ingress_schedule(
                PackingGkrVariant::Laned, payload, circuit,
                public_setup);
        auto parameters = selected_lazy_ternary_parameters();
        parameters.repetitions = 1;
        const spartan::BaseFoldPcsParameters basefold{
            .log_rate = 1,
            .query_count = 1,
        };
        const LanedSetup resident_setup =
            setup_laned_conservative<ReplayMockBackend>(
                payload, circuit, public_setup, contexts.eval, ingress,
                parameters, basefold);
        ExternalPacking external = externalize_packing(
            resident_setup.transcript_packing, tree, "laned-preprocessed");
        const LanedVerifierSetup external_verifier{
            .transcript_packing = external.verifier,
        };
        const LanedVerifierSetup resident_verifier =
            verifier_setup(resident_setup);
        CHECK(external_verifier.transcript_packing.spartan.setup_digest ==
              resident_verifier.transcript_packing.spartan.setup_digest);
        CHECK(external_verifier.transcript_packing.spartan
                  .circuit_metadata ==
              resident_verifier.transcript_packing.spartan
                  .circuit_metadata);
        CHECK(external_verifier.transcript_packing.spartan
                  .factored_computation->commitment ==
              resident_verifier.transcript_packing.spartan
                  .factored_computation->commitment);
        const PackedExternalProverSetup packed_setup =
            make_laned_packed_external_prover_setup(
                payload, circuit, public_setup, ingress,
                std::move(external.prover));

        const FheEvaluationPlan evaluation =
            apply_packed_proof_ingress_schedule(
                circuit,
                FheEvaluationPlan::at_evaluation_levels(
                    circuit, 13, 1, 0),
                resident_setup);
        const std::vector<ReplayMockBackend::Ciphertext> encrypted_inputs =
            encrypt_laned_payload_inputs<ReplayMockBackend>(
                contexts.client, payload, inputs);
        FheEvaluationPlan natural = evaluation;
        natural.proof_ingress_mult_depth_by_layer =
            natural.trace.required_mult_depth_by_layer;
        const EncryptedTrace<ReplayMockBackend> resource_trace =
            evaluate_laned_fhe_trace_into<ReplayMockBackend>(
                contexts.eval, payload, circuit, encrypted_inputs, natural,
                InMemoryTraceSink<ReplayMockBackend>{contexts.eval});
        const PayloadCheckpointReplayProblem problem = checkpoint_problem(
            circuit, evaluation, contexts.eval, resource_trace);
        PayloadCheckpointReplayBudgets budgets = checkpoint_budgets();
        budgets.reserved_resident_bytes +=
            eager_laned_witness_packing_resources(circuit, problem)
                .resident_workspace_bytes;
        const PayloadCheckpointReplayPlan plan =
            plan_payload_checkpoint_replay(problem, budgets);
        auto resident_trace = publish_replay(
            contexts.eval, payload, circuit, encrypted_inputs, evaluation,
            problem, budgets, plan, tree.make("laned-resident-replay"));
        auto external_trace = publish_replay(
            contexts.eval, payload, circuit, encrypted_inputs, evaluation,
            problem, budgets, plan, tree.make("laned-external-replay"),
            true);
        const Digest trace_id = external_trace.descriptor().trace_id;
        CHECK(resident_trace.descriptor().trace_id == trace_id);
        CHECK(external_trace.uses_eager_laned_witness_packing());
        CHECK(external_trace.report().replay_work_units == 0);
        CHECK(external_trace.report().proof_ingress_ciphertexts == 0);
        CHECK(external_trace.report().proof_ingress_modulus_switches == 0);
        CHECK(external_trace.report().laned_witness_source_values > 0);
        CHECK(external_trace.report().laned_witness_packed_ciphertexts > 0);
        CHECK(external_trace.report().laned_witness_physical_bytes_written >
              0);

        const std::vector<Fpk> output_point(
            laned_layer_variables(circuit, 0),
            Fpk::from_base(Fp(19)));
        const SingleClaim output_claim = make_packed_laned_claim(
            plain.layers.front(), laned_layout(circuit, 0), output_point);
        Transcript resident_transcript(
            "test/packed-external/laned/v1");
        const auto resident =
            reference::prove_laned_checkpoint_replay_irreversible_reference<ReplayMockBackend>(
                payload, circuit, resident_trace, evaluation_setup,
                resident_setup, output_point, resident_transcript,
                laned_gkr_options(circuit, tree, "laned-resident-gkr"));

        OnlineRoots roots(
            tree, "laned-external-online", external.tensor_count);
        LanedCheckpointReplayExternalOptions options{
            .gkr = laned_gkr_options(
                circuit, tree, "laned-external-gkr"),
            .transcript_packing = packing_options(roots),
        };
        const std::uint64_t live_before =
            external_trace.report().live_physical_bytes;
        auto admission =
            admit_laned_checkpoint_replay_external_irreversible<
                ReplayMockBackend>(
                payload, circuit, external_trace, evaluation_setup,
                packed_setup, output_point, options);
        CHECK(!external_trace.proof_attempt_started());
        CHECK(external_trace.report().live_physical_bytes == live_before);
        CHECK(roots.empty());
        CHECK(admission.packing_report().spartan_storage
                  .preprocessing_validation_bytes > 0);

        Transcript external_transcript(
            "test/packed-external/laned/v1");
        const auto proved =
            prove_laned_checkpoint_replay_external_irreversible<
                ReplayMockBackend>(
                std::move(admission), external_transcript);
        CHECK(roots.empty());
        CHECK(proved.payload_replay_report.all_payload_artifacts_retired);
        CHECK(proved.payload_replay_report.live_physical_bytes == 0);
        CHECK(proved.payload_replay_report
                  .laned_witness_physical_bytes_retired ==
              proved.payload_replay_report
                  .laned_witness_physical_bytes_written);
        CHECK(proved.payload_replay_report
                  .laned_witness_packing_wall_ms > 0.0);
        CHECK(proved.phase_timings.gkr_wall_ms > 0.0);
        CHECK(proved.phase_timings.transcript_packing_wall_ms > 0.0);
        CHECK(proved.transcript_packing_report.storage
                  .preprocessing_validation_bytes > 0);
        CHECK(protocol::detail::encode_committed_gkr(proved.proof.gkr) ==
              protocol::detail::encode_committed_gkr(resident.proof.gkr));
        CHECK(encoded_reveals(
                  proved.proof.transcript_packing
                      .well_formedness_reveals) ==
              encoded_reveals(
                  resident.proof.transcript_packing
                      .well_formedness_reveals));
        const std::vector<SlotVector> input_layer =
            make_plain_input_layer(circuit, inputs);
        Transcript resident_verifier_transcript(
            "test/packed-external/laned/v1");
        CHECK(verify_laned<ReplayMockBackend>(
            payload, circuit, input_layer, contexts.eval,
            resident_verifier, client_setup,
            TraceProvenance::FheEvaluated, trace_id, output_claim,
            resident.proof, resident_verifier_transcript));
        Transcript verifier_transcript(
            "test/packed-external/laned/v1");
        CHECK(verify_laned<ReplayMockBackend>(
            payload, circuit, input_layer, contexts.eval,
            external_verifier, client_setup,
            TraceProvenance::FheEvaluated, trace_id, output_claim,
            proved.proof, verifier_transcript));
    });

    return runner.summary();
}
