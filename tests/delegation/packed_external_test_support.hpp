#ifndef LAMINATE_TESTS_DELEGATION_PACKED_EXTERNAL_TEST_SUPPORT_HPP
#define LAMINATE_TESTS_DELEGATION_PACKED_EXTERNAL_TEST_SUPPORT_HPP

/// @file packed_external_test_support.hpp
/// @brief Artifact-backed transcript-packing fixtures for delegation tests.

#include "laminate/packing/proof/matrix/metadata.hpp"
#include "laminate/protocol/packed/setup.hpp"
#include "laminate/protocol/packed/external/transcript_packing.hpp"
#include "laminate/protocol/packed/reference/materialized_external_setup.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace laminate::test::packed_external_support {

class TemporaryTree {
  public:
    TemporaryTree() {
        const auto stamp = std::chrono::steady_clock::now()
                               .time_since_epoch()
                               .count();
        for (std::size_t attempt = 0; attempt < 100; ++attempt) {
            root_ = std::filesystem::temp_directory_path() /
                    ("laminate-external-delegation-" +
                     std::to_string(stamp) + "-" +
                     std::to_string(attempt));
            if (std::filesystem::create_directory(root_)) {
                return;
            }
        }
        throw std::runtime_error(
            "failed to create external delegation temporary tree");
    }

    ~TemporaryTree() {
        std::error_code ignored;
        std::filesystem::remove_all(root_, ignored);
    }

    std::filesystem::path make(std::string_view name) const {
        const std::filesystem::path path = root_ / name;
        if (!std::filesystem::create_directory(path)) {
            throw std::runtime_error(
                "failed to create external delegation test directory");
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
          witness_state(
              tree.make(std::string(prefix) + "-witness-state")),
          witness_commit_scratch(tree.make(
              std::string(prefix) + "-witness-commit-scratch")),
          constraint_scratch(tree.make(
              std::string(prefix) + "-constraint-scratch")),
          wiring_matrix(
              tree.make(std::string(prefix) + "-wiring-matrix")),
          wiring_scratch(
              tree.make(std::string(prefix) + "-wiring-scratch")),
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

inline protocol::TranscriptPackingExternalProverOptions online_options(
    const OnlineRoots &roots) {
    protocol::TranscriptPackingExternalProverOptions result{
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
    protocol::TranscriptPackingExternalProverSetup prover;
    protocol::TranscriptPackingSpartanVerifierSetup verifier;
    std::size_t tensor_count = 0;
};

inline ExternalPacking externalize(
    const protocol::TranscriptPackingSpartanSetup &resident,
    const TemporaryTree &tree, std::string_view prefix) {
    const auto pcs = std::make_shared<const spartan::BaseFoldPcs>(
        resident.basefold_parameters);
    const auto &resident_factored =
        resident.spartan.prover_key.factored_computation;
    if (resident_factored == nullptr || resident_factored->tensors.empty()) {
        throw std::logic_error(
            "external delegation setup has no factored tensors");
    }
    std::vector<std::vector<std::vector<Fq>>> columns;
    for (const auto &tensor : resident_factored->tensors) {
        columns.push_back(tensor.columns);
    }
    const packing::ProofOfPackingStructuredMetadata relation =
        packing::make_proof_of_packing_structured_metadata(
            resident.alignment_layout, resident.parameters);
    const auto structure = packing::make_proof_of_packing_factored_structure(
        relation.relation_plan, relation.r1cs_layout,
        relation.tensor_mappings,
        resident.spartan.prover_key.circuit->metadata());
    spartan::FactoredMatrixSetup factored =
        spartan::preprocess_factored_matrix_to_artifact(
            structure, std::move(columns), *pcs,
            {.directory =
                 tree.make(std::string(prefix) + "-tensor-columns"),
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
    protocol::TranscriptPackingExternalProverSetup prover =
        protocol::reference::make_materialized_reference_external_prover_setup(
            resident, pcs, external.prover_key);
    const auto &bound = prover.relation();
    protocol::TranscriptPackingSpartanVerifierSetup verifier{
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

} // namespace laminate::test::packed_external_support

#endif // LAMINATE_TESTS_DELEGATION_PACKED_EXTERNAL_TEST_SUPPORT_HPP
