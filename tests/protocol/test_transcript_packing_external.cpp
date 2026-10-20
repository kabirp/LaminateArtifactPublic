/// @file test_transcript_packing_external.cpp
/// @brief End-to-end lifecycle tests for external transcript packing.

#include "test_helpers.hpp"

#include "laminate/fhe/mock_backend.hpp"
#include "laminate/protocol/detail/packing/aligned_commitments.hpp"
#include "laminate/protocol/packed/external/transcript_packing.hpp"
#include "laminate/protocol/packed/reference/materialized_external_setup.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
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
using namespace laminate::packing;
using namespace laminate::protocol;

namespace {

class TemporaryTree {
  public:
    TemporaryTree() {
        const auto stamp = std::chrono::steady_clock::now()
                               .time_since_epoch()
                               .count();
        for (std::size_t attempt = 0; attempt < 100; ++attempt) {
            root_ = std::filesystem::temp_directory_path() /
                    ("laminate-external-packing-" +
                     std::to_string(stamp) + "-" +
                     std::to_string(attempt));
            if (std::filesystem::create_directory(root_)) {
                return;
            }
        }
        throw std::runtime_error(
            "failed to create external transcript-packing test root");
    }

    ~TemporaryTree() {
        std::error_code ignored;
        std::filesystem::remove_all(root_, ignored);
    }

    std::filesystem::path make_directory(std::string_view name) const {
        const std::filesystem::path result = root_ / name;
        if (!std::filesystem::create_directory(result)) {
            throw std::runtime_error(
                "failed to create external transcript-packing test "
                "directory");
        }
        return result;
    }

  private:
    std::filesystem::path root_;
};

struct OnlineRoots {
    OnlineRoots(const TemporaryTree &tree, std::string_view prefix)
        : outer(tree.make_directory(std::string(prefix) + "-outer")),
          assignment(tree.make_directory(
              std::string(prefix) + "-spartan-assignment")),
          products(tree.make_directory(
              std::string(prefix) + "-products")),
          witness_state(tree.make_directory(
              std::string(prefix) + "-witness-state")),
          witness_commit_scratch(tree.make_directory(
              std::string(prefix) + "-witness-commit-scratch")),
          constraint_scratch(tree.make_directory(
              std::string(prefix) + "-constraint-scratch")),
          wiring_matrix(tree.make_directory(
              std::string(prefix) + "-wiring-matrix")),
          wiring_scratch(tree.make_directory(
              std::string(prefix) + "-wiring-scratch")),
          factored_opening_scratch(tree.make_directory(
              std::string(prefix) + "-factored-opening-scratch")),
          witness_opening_scratch(tree.make_directory(
              std::string(prefix) + "-witness-opening-scratch")) {}

    bool empty() const {
        for (const std::filesystem::path *path : {
                 &outer,
                 &assignment,
                 &products,
                 &witness_state,
                 &witness_commit_scratch,
                 &constraint_scratch,
                 &wiring_matrix,
                 &wiring_scratch,
                 &factored_opening_scratch,
                 &witness_opening_scratch,
             }) {
            if (!std::filesystem::is_directory(*path) ||
                !std::filesystem::is_empty(*path)) {
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
    std::filesystem::path factored_opening_scratch;
    std::filesystem::path witness_opening_scratch;
};

LazyTernaryParameters test_parameters() {
    LazyTernaryParameters result =
        selected_lazy_ternary_parameters();
    result.repetitions = 2;
    return result;
}

TranscriptPackingSpartanSetup make_resident_setup(
    const MockBackend::EvalContext &eval,
    const LazyTernaryParameters &parameters,
    spartan::BaseFoldPcsParameters basefold_parameters,
    std::size_t message_count) {
    return make_transcript_packing_spartan_setup(
        PackingGkrVariant::Folded, MockBackend::slot_count(eval),
        message_count,
        {.centered_coefficients =
             [&eval](const SlotVector &slots) {
                 return MockBackend::
                     encode_centered_plaintext_coefficients(eval, slots);
             },
         .native_ntt =
             [&eval](std::span<const std::int64_t> coefficients) {
                 return MockBackend::
                     encode_lowest_plaintext_ntt_coordinates(
                         eval, coefficients);
             }},
        parameters, basefold_parameters,
        {.matrix_evaluation =
             spartan::MatrixEvaluationMode::CommittedFactored});
}

spartan::FactoredMatrixArtifactOptions factored_artifact_options(
    const std::filesystem::path &directory) {
    return {
        .directory = directory,
        .limits = {
            .max_total_bytes = 1ULL << 28U,
            .min_free_bytes = 1,
        },
    };
}

struct Fixture {
    static constexpr std::size_t kMessageCount = 2;

    TemporaryTree tree;
    MockBackend::Contexts contexts = MockBackend::create(
        MockParameters{.slot_count = 32, .fresh_rns_limbs = 4,
                       .bits_per_limb = 120});
    LazyTernaryParameters parameters = test_parameters();
    spartan::BaseFoldPcsParameters basefold_parameters{
        .log_rate = 1,
        .query_count = 1,
    };
    std::shared_ptr<const spartan::BaseFoldPcs> pcs =
        std::make_shared<const spartan::BaseFoldPcs>(
            basefold_parameters);
    TranscriptPackingSpartanSetup resident = make_resident_setup(
        contexts.eval, parameters, basefold_parameters, kMessageCount);
    spartan::ExternalSetup external;
    std::optional<TranscriptPackingExternalProverSetup> certified;
    TranscriptPackingSpartanVerifierSetup external_verifier;

    Fixture() {
        ProofOfPackingStructuredMetadata relation =
            make_proof_of_packing_structured_metadata(
                resident.alignment_layout, resident.parameters);
        const auto &resident_factored =
            resident.spartan.prover_key.factored_computation;
        if (resident_factored == nullptr ||
            resident_factored->tensors.size() != 1 ||
            resident_factored->tensors.front().columns.empty()) {
            throw std::logic_error(
                "resident packing fixture lacks one coefficient tensor");
        }
        std::vector<std::vector<std::vector<Fq>>> columns;
        columns.reserve(resident_factored->tensors.size());
        for (const spartan::FactoredTensorProverKey &tensor :
             resident_factored->tensors) {
            columns.push_back(tensor.columns);
        }
        const auto structure =
            make_proof_of_packing_factored_structure(
                relation.relation_plan, relation.r1cs_layout,
                relation.tensor_mappings,
                resident.spartan.prover_key.circuit->metadata());
        spartan::FactoredMatrixSetup factored =
            spartan::preprocess_factored_matrix_to_artifact(
                structure, std::move(columns), *pcs,
                factored_artifact_options(
                    tree.make_directory("preprocessed-columns")));
        for (std::size_t tensor = 0;
             tensor < factored.prover_key.tensors.size(); ++tensor) {
            const spartan::BaseFoldExternalization externalized =
                pcs->externalize_prover_state(
                    factored.prover_key.tensors[tensor].opening_state,
                    {.directory = tree.make_directory(
                         "preprocessed-state-" +
                         std::to_string(tensor)),
                     .limits = {.max_total_bytes = 1ULL << 30U,
                                .min_free_bytes = 1}});
            factored.prover_key.tensors[tensor].opening_state =
                externalized.prover_state;
            factored.prover_key.tensors[tensor].opening_state_source =
                spartan::FactoredTensorProverKey::OpeningStateSource::
                    External;
        }
        external = spartan::setup_external_committed_factored(
            resident.spartan.prover_key.circuit->metadata(), *pcs,
            std::make_shared<const spartan::FactoredMatrixProverKey>(
                std::move(factored.prover_key)),
            std::make_shared<const spartan::FactoredMatrixVerifierKey>(
                std::move(factored.verifier_key)));
        certified.emplace(
            reference::make_materialized_reference_external_prover_setup(
                resident, pcs,
                external.prover_key));
        const auto &bound = certified->relation();
        external_verifier = TranscriptPackingSpartanVerifierSetup{
            .variant = PackingGkrVariant::Folded,
            .bhip_round_count = kMessageCount,
            .alignment_layout = bound.alignment_layout,
            .relation_plan = bound.relation_plan,
            .parameters = bound.parameters,
            .radix = bound.parameters.packing_radix,
            .basefold_parameters = basefold_parameters,
            .spartan = external.verifier_key,
        };
    }

    protocol::detail::CollectedAlignedCommitments<MockBackend>
    make_input_for_layout(const PackingLayout &layout) const {
        protocol::detail::AlignedCommitmentCollector<MockBackend>
            collector(contexts.eval, layout);
        for (std::size_t message = 0; message < kMessageCount;
             ++message) {
            SlotVector slots(32);
            for (std::size_t slot = 0; slot < slots.size(); ++slot) {
                slots[slot] = Fp(17 + 13 * message + 5 * slot);
            }
            const auto ciphertext =
                MockBackend::encrypt(contexts.client, slots);
            (void)collector.commit(
                FheValue<MockBackend>::from_ciphertext(ciphertext));
        }
        return std::move(collector).finish();
    }

    protocol::detail::CollectedAlignedCommitments<MockBackend>
    make_input() const {
        return make_input_for_layout(resident.alignment_layout);
    }

    std::vector<gkr::CommittedPackedMessage> messages(
        std::span<const gkr::HashCommitCT> commitments) const {
        std::vector<gkr::CommittedPackedMessage> result;
        result.reserve(commitments.size());
        for (const auto &commitment : commitments) {
            result.push_back(
                gkr::CommittedPackedMessage::encrypted_message(
                    commitment));
        }
        return result;
    }
};

OuterRelationAssignmentArtifactOptions outer_options(
    const std::filesystem::path &directory) {
    return {
        .directory = directory,
        .storage_limits = {.max_total_bytes = 1ULL << 28U,
                           .min_free_bytes = 1},
        .max_working_field_bytes = 1ULL << 20U,
        .block_elements = 11,
    };
}

ProofOfPackingAssignmentArtifactOptions complete_options(
    const std::filesystem::path &directory) {
    return {
        .directory = directory,
        .storage_limits = {.max_total_bytes = 1ULL << 30U,
                           .min_free_bytes = 1},
        .max_working_bytes = 1ULL << 24U,
        .block_elements = 13,
    };
}

ProofOfPackingMatrixProductArtifactOptions product_options(
    const std::filesystem::path &directory) {
    return {
        .directory = directory,
        .storage_limits = {.max_total_bytes = 1ULL << 30U,
                           .min_free_bytes = 1},
        .max_working_field_bytes = 1ULL << 20U,
        .block_elements = 7,
    };
}

TranscriptPackingExternalProverOptions online_options(
    const OnlineRoots &roots, std::uint64_t max_live_storage) {
    return {
        .outer_assignment = outer_options(roots.outer),
        .spartan = {
            .max_live_storage_bytes = max_live_storage,
            .assignment = complete_options(roots.assignment),
            .matrix_products = product_options(roots.products),
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
                .tensor_openings = {{
                    .scratch_directory =
                        roots.factored_opening_scratch,
                    .max_live_storage_bytes = 1,
                    .max_total_scratch_bytes = 1ULL << 30U,
                    .min_free_bytes = 1,
                    .max_working_field_bytes = 1ULL << 24U,
                    .fold_chunk_elements = 128,
                }},
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
    std::span<const std::optional<MockBackend::Ciphertext>> values) {
    std::vector<std::optional<std::vector<std::uint8_t>>> result;
    result.reserve(values.size());
    for (const auto &value : values) {
        result.push_back(value ? std::optional(MockBackend::serialize(*value))
                               : std::nullopt);
    }
    return result;
}

std::size_t event_index(
    std::span<const RuntimeProgressEvent> events,
    RuntimeProgressStage stage, RuntimeProgressBoundary boundary) {
    const auto selected = std::find_if(
        events.begin(), events.end(), [&](const RuntimeProgressEvent &event) {
            return event.stage == stage && event.boundary == boundary;
        });
    if (selected == events.end()) {
        throw std::logic_error("expected runtime progress event is absent");
    }
    return static_cast<std::size_t>(selected - events.begin());
}

} // namespace

int main() {
    test::Runner runner("external transcript packing");

    runner.run(
        "external transcript packing matches resident semantics and owns "
        "its lifecycle",
        [] {
            static_assert(!std::is_aggregate_v<
                          protocol::detail::
                              CollectedAlignedCommitments<MockBackend>>);
            static_assert(!std::is_constructible_v<
                          protocol::detail::
                              CollectedAlignedCommitments<MockBackend>,
                          NormalizedAlignedTranscript<MockBackend>,
                          std::vector<gkr::HashCommitCT>>);
            static_assert(!std::is_constructible_v<
                          TranscriptPackingExternalProverInput<MockBackend>,
                          NormalizedAlignedTranscript<MockBackend>,
                          std::vector<gkr::HashCommitCT>>);
            Fixture fixture;
            spartan::ExternalProverKey mismatched_key =
                fixture.external.prover_key;
            mismatched_key.setup_digest.front() ^= 1U;
            CHECK(rejects([&] {
                (void)reference::
                    make_materialized_reference_external_prover_setup(
                    fixture.resident, fixture.pcs,
                    std::move(mismatched_key));
            }));

            auto resident_input = fixture.make_input();
            Transcript resident_coin(
                "laminate/test/external-transcript-packing/v1");
            const TranscriptPackingProof<MockBackend> resident =
                protocol::detail::prove_transcript_packing<MockBackend>(
                    fixture.contexts.eval, fixture.resident,
                    resident_input.aligned(),
                    resident_input.commitments(),
                    resident_coin);

            OnlineRoots broad_roots(fixture.tree, "broad");
            auto external_input = fixture.make_input();
            const std::vector<gkr::CommittedPackedMessage> messages =
                fixture.messages(external_input.commitments());
            std::vector<RuntimeProgressEvent> events;
            Transcript external_coin(
                "laminate/test/external-transcript-packing/v1");
            const auto external =
                prove_transcript_packing_external<MockBackend>(
                    fixture.contexts.eval, PackingGkrVariant::Folded,
                    *fixture.certified,
                    TranscriptPackingExternalProverInput<MockBackend>(
                        std::move(external_input)),
                    external_coin,
                    online_options(broad_roots, 1ULL << 34U),
                    [&](const RuntimeProgressEvent &event) {
                        events.push_back(event);
                    });
            CHECK(broad_roots.empty());
            CHECK(encoded_reveals(
                      external.proof.well_formedness_reveals) ==
                  encoded_reveals(resident.well_formedness_reveals));
            CHECK(encoded_reveals(
                      external.proof.digit_decomposed_packed_values) ==
                  encoded_reveals(
                      resident.digit_decomposed_packed_values));
            CHECK(spartan::encode_proof(
                      external.proof.proof_of_packing) ==
                  spartan::encode_proof(
                      resident.proof_of_packing));
            CHECK(external_coin.challenge_fq2() ==
                  resident_coin.challenge_fq2());
            CHECK(external.report.outer_assignment.physical_bytes ==
                  external.report.storage
                      .outer_assignment_physical_bytes);
            CHECK(external.report.prefix_storage
                      .outer_assignment_physical_bytes ==
                  external.report.outer_assignment.physical_bytes);
            CHECK(external.report.prefix_storage
                      .outer_assignment_peak_working_field_bytes ==
                  external.report.outer_assignment
                      .peak_working_field_bytes);
            CHECK(external.report.prefix_storage
                      .outer_assignment_construction_peak_live_storage_bytes ==
                  external.report.storage
                      .persistent_input_physical_bytes);
            CHECK(external.report.storage.peak_live_storage_bytes <=
                  external.report.storage.admitted_live_storage_bytes);
            CHECK(spartan::proof_size_bytes(
                      external.proof.proof_of_packing) ==
                  spartan::encode_proof(
                      external.proof.proof_of_packing)
                      .size());

            Transcript resident_verifier_coin(
                "laminate/test/external-transcript-packing/v1");
            const auto resident_verified =
                protocol::detail::verify_transcript_packing<MockBackend>(
                    fixture.contexts.eval, fixture.contexts.client,
                    verifier_setup(fixture.resident), messages, resident,
                    resident_verifier_coin);
            Transcript external_verifier_coin(
                "laminate/test/external-transcript-packing/v1");
            const auto external_verified =
                protocol::detail::verify_transcript_packing<MockBackend>(
                    fixture.contexts.eval, fixture.contexts.client,
                    fixture.external_verifier, messages, external.proof,
                    external_verifier_coin);
            CHECK(resident_verified.accepts());
            CHECK(external_verified.accepts());
            CHECK(external_verified.logical_messages ==
                  resident_verified.logical_messages);

            const std::size_t source_retirement_begin = event_index(
                events,
                RuntimeProgressStage::
                    TranscriptPackingAlignedSourceRetirement,
                RuntimeProgressBoundary::Begin);
            const std::size_t source_retired = event_index(
                events,
                RuntimeProgressStage::
                    TranscriptPackingAlignedSourceRetirement,
                RuntimeProgressBoundary::End);
            const std::size_t spartan_begin = event_index(
                events,
                RuntimeProgressStage::TranscriptPackingSpartanProve,
                RuntimeProgressBoundary::Begin);
            const std::size_t spartan_assignment = event_index(
                events,
                RuntimeProgressStage::TranscriptPackingSpartanAssignment,
                RuntimeProgressBoundary::Begin);
            const std::size_t outer_retirement = event_index(
                events,
                RuntimeProgressStage::
                    TranscriptPackingOuterAssignmentRetirement,
                RuntimeProgressBoundary::Begin);
            CHECK(source_retirement_begin < source_retired);
            CHECK(source_retired < spartan_begin);
            CHECK(spartan_begin < spartan_assignment);
            CHECK(spartan_assignment < outer_retirement);

            OnlineRoots variant_roots(fixture.tree, "variant-mismatch");
            auto variant_input = fixture.make_input();
            Transcript variant_coin(
                "laminate/test/external-transcript-packing/v1");
            CHECK(rejects([&] {
                (void)prove_transcript_packing_external<MockBackend>(
                    fixture.contexts.eval,
                    PackingGkrVariant::Laned,
                    *fixture.certified,
                    TranscriptPackingExternalProverInput<MockBackend>(
                        std::move(variant_input)),
                    variant_coin,
                    online_options(variant_roots, 1ULL << 34U));
            }));
            Transcript fresh_variant_coin(
                "laminate/test/external-transcript-packing/v1");
            CHECK(variant_coin.challenge_fq2() ==
                  fresh_variant_coin.challenge_fq2());
            CHECK(variant_roots.empty());

            OnlineRoots layout_roots(fixture.tree, "layout-mismatch");
            const PackingLayout mismatched_layout =
                make_prefix_packing_layout(
                    MockBackend::slot_count(fixture.contexts.eval),
                    std::vector<std::size_t>{4, 4});
            auto layout_input =
                fixture.make_input_for_layout(mismatched_layout);
            Transcript layout_coin(
                "laminate/test/external-transcript-packing/v1");
            CHECK(rejects([&] {
                (void)prove_transcript_packing_external<MockBackend>(
                    fixture.contexts.eval,
                    PackingGkrVariant::Folded,
                    *fixture.certified,
                    TranscriptPackingExternalProverInput<MockBackend>(
                        std::move(layout_input)),
                    layout_coin,
                    online_options(layout_roots, 1ULL << 34U));
            }));
            Transcript fresh_layout_coin(
                "laminate/test/external-transcript-packing/v1");
            CHECK(layout_coin.challenge_fq2() ==
                  fresh_layout_coin.challenge_fq2());
            CHECK(layout_roots.empty());

            const std::uint64_t exact_cap =
                external.report.storage.peak_live_storage_bytes;
            CHECK(exact_cap > 0);
            OnlineRoots exact_roots(fixture.tree, "exact");
            auto exact_input = fixture.make_input();
            Transcript exact_coin(
                "laminate/test/external-transcript-packing/v1");
            const auto exact =
                prove_transcript_packing_external<MockBackend>(
                    fixture.contexts.eval, PackingGkrVariant::Folded,
                    *fixture.certified,
                    TranscriptPackingExternalProverInput<MockBackend>(
                        std::move(exact_input)),
                    exact_coin, online_options(exact_roots, exact_cap));
            CHECK(exact_roots.empty());
            CHECK(exact.report.storage.admitted_live_storage_bytes ==
                  exact_cap);
            CHECK(exact.report.storage.peak_live_storage_bytes ==
                  exact_cap);
            CHECK(spartan::encode_proof(exact.proof.proof_of_packing) ==
                  spartan::encode_proof(
                      external.proof.proof_of_packing));

            OnlineRoots exact_prefix_roots(
                fixture.tree, "exact-prefix");
            auto exact_prefix_input = fixture.make_input();
            Transcript exact_prefix_coin(
                "laminate/test/external-transcript-packing/v1");
            auto exact_prefix_options =
                online_options(exact_prefix_roots, exact_cap);
            exact_prefix_options.outer_assignment.storage_limits
                .max_total_bytes = external.report.prefix_storage
                                       .outer_assignment_physical_bytes;
            exact_prefix_options.outer_assignment
                .max_working_field_bytes = sizeof(Fq);
            const auto exact_prefix =
                prove_transcript_packing_external<MockBackend>(
                    fixture.contexts.eval,
                    PackingGkrVariant::Folded,
                    *fixture.certified,
                    TranscriptPackingExternalProverInput<MockBackend>(
                        std::move(exact_prefix_input)),
                    exact_prefix_coin,
                    std::move(exact_prefix_options));
            CHECK(exact_prefix_roots.empty());
            CHECK(exact_prefix.report.prefix_storage
                      .outer_assignment_peak_working_field_bytes ==
                  sizeof(Fq));
            CHECK(spartan::encode_proof(
                      exact_prefix.proof.proof_of_packing) ==
                  spartan::encode_proof(
                      external.proof.proof_of_packing));

            OnlineRoots outer_short_roots(
                fixture.tree, "outer-short");
            auto outer_short_input = fixture.make_input();
            Transcript outer_short_coin(
                "laminate/test/external-transcript-packing/v1");
            auto outer_short_options =
                online_options(outer_short_roots, exact_cap);
            outer_short_options.outer_assignment.storage_limits
                .max_total_bytes =
                external.report.prefix_storage
                    .outer_assignment_physical_bytes -
                1U;
            CHECK(rejects([&] {
                (void)prove_transcript_packing_external<MockBackend>(
                    fixture.contexts.eval,
                    PackingGkrVariant::Folded,
                    *fixture.certified,
                    TranscriptPackingExternalProverInput<MockBackend>(
                        std::move(outer_short_input)),
                    outer_short_coin,
                    std::move(outer_short_options));
            }));
            Transcript fresh_outer_short_coin(
                "laminate/test/external-transcript-packing/v1");
            CHECK(outer_short_coin.challenge_fq2() ==
                  fresh_outer_short_coin.challenge_fq2());
            CHECK(outer_short_roots.empty());

            OnlineRoots working_short_roots(
                fixture.tree, "working-short");
            auto working_short_input = fixture.make_input();
            Transcript working_short_coin(
                "laminate/test/external-transcript-packing/v1");
            auto working_short_options =
                online_options(working_short_roots, exact_cap);
            working_short_options.outer_assignment
                .max_working_field_bytes = sizeof(Fq) - 1U;
            CHECK(rejects([&] {
                (void)prove_transcript_packing_external<MockBackend>(
                    fixture.contexts.eval,
                    PackingGkrVariant::Folded,
                    *fixture.certified,
                    TranscriptPackingExternalProverInput<MockBackend>(
                        std::move(working_short_input)),
                    working_short_coin,
                    std::move(working_short_options));
            }));
            Transcript fresh_working_short_coin(
                "laminate/test/external-transcript-packing/v1");
            CHECK(working_short_coin.challenge_fq2() ==
                  fresh_working_short_coin.challenge_fq2());
            CHECK(working_short_roots.empty());

            OnlineRoots free_short_roots(
                fixture.tree, "free-short");
            auto free_short_input = fixture.make_input();
            Transcript free_short_coin(
                "laminate/test/external-transcript-packing/v1");
            auto free_short_options =
                online_options(free_short_roots, exact_cap);
            free_short_options.outer_assignment.storage_limits
                .min_free_bytes = std::filesystem::space(
                                      free_short_roots.outer)
                                      .available;
            CHECK(rejects([&] {
                (void)prove_transcript_packing_external<MockBackend>(
                    fixture.contexts.eval,
                    PackingGkrVariant::Folded,
                    *fixture.certified,
                    TranscriptPackingExternalProverInput<MockBackend>(
                        std::move(free_short_input)),
                    free_short_coin,
                    std::move(free_short_options));
            }));
            Transcript fresh_free_short_coin(
                "laminate/test/external-transcript-packing/v1");
            CHECK(free_short_coin.challenge_fq2() ==
                  fresh_free_short_coin.challenge_fq2());
            CHECK(free_short_roots.empty());

            OnlineRoots short_roots(fixture.tree, "short");
            auto short_input = fixture.make_input();
            Transcript short_coin(
                "laminate/test/external-transcript-packing/v1");
            std::vector<RuntimeProgressEvent> short_events;
            CHECK(rejects([&] {
                (void)prove_transcript_packing_external<MockBackend>(
                    fixture.contexts.eval, PackingGkrVariant::Folded,
                    *fixture.certified,
                    TranscriptPackingExternalProverInput<MockBackend>(
                        std::move(short_input)),
                    short_coin,
                    online_options(short_roots, exact_cap - 1U),
                    [&](const RuntimeProgressEvent &event) {
                        short_events.push_back(event);
                    });
            }));
            Transcript fresh_short_coin(
                "laminate/test/external-transcript-packing/v1");
            CHECK(short_coin.challenge_fq2() ==
                  fresh_short_coin.challenge_fq2());
            CHECK(short_events.empty());
            CHECK(short_roots.empty());

            OnlineRoots failure_roots(fixture.tree, "late-failure");
            auto failure_input = fixture.make_input();
            Transcript failure_coin(
                "laminate/test/external-transcript-packing/v1");
            bool reached_witness_opening = false;
            CHECK(rejects([&] {
                (void)prove_transcript_packing_external<MockBackend>(
                    fixture.contexts.eval, PackingGkrVariant::Folded,
                    *fixture.certified,
                    TranscriptPackingExternalProverInput<MockBackend>(
                        std::move(failure_input)),
                    failure_coin,
                    online_options(failure_roots, 1ULL << 34U),
                    [&](const RuntimeProgressEvent &event) {
                        if (event.stage == RuntimeProgressStage::
                                               TranscriptPackingSpartanWitnessOpening &&
                            event.boundary ==
                                RuntimeProgressBoundary::Begin) {
                            reached_witness_opening = true;
                            std::ofstream blocker(
                                failure_roots.witness_opening_scratch /
                                    "injected-late-failure");
                            blocker << "fail after the outer artifact exists";
                        }
                    });
            }));
            CHECK(reached_witness_opening);
            CHECK(failure_roots.empty());

#ifndef _WIN32
            OnlineRoots replaced_roots(fixture.tree, "replaced-outer");
            auto replaced_input = fixture.make_input();
            Transcript replaced_coin(
                "laminate/test/external-transcript-packing/v1");
            const std::filesystem::path admitted_outer =
                replaced_roots.outer.parent_path() /
                "replaced-outer-admitted";
            const std::filesystem::path replacement_sentinel =
                replaced_roots.outer / "must-not-delete";
            bool replaced_outer = false;
            CHECK(rejects([&] {
                (void)prove_transcript_packing_external<MockBackend>(
                    fixture.contexts.eval, PackingGkrVariant::Folded,
                    *fixture.certified,
                    TranscriptPackingExternalProverInput<MockBackend>(
                        std::move(replaced_input)),
                    replaced_coin,
                    online_options(replaced_roots, 1ULL << 34U),
                    [&](const RuntimeProgressEvent &event) {
                        if (!replaced_outer &&
                            event.stage == RuntimeProgressStage::
                                               TranscriptPackingAssignment &&
                            event.boundary ==
                                RuntimeProgressBoundary::End) {
                            std::filesystem::rename(replaced_roots.outer,
                                                    admitted_outer);
                            std::filesystem::create_directory(
                                replaced_roots.outer);
                            std::ofstream marker(replacement_sentinel);
                            marker << "replacement root";
                            if (!marker) {
                                throw std::runtime_error(
                                    "failed to write replacement sentinel");
                            }
                            replaced_outer = true;
                        }
                    });
            }));
            CHECK(replaced_outer);
            CHECK(std::filesystem::is_regular_file(
                replacement_sentinel));
            CHECK(std::filesystem::is_directory(admitted_outer));
#endif
        });

    return runner.summary();
}
