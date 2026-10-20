/// @file test_transcript_packing_external_preprocessing.cpp
/// @brief Formula admission and lifecycle tests for external packing setup.

#include "test_helpers.hpp"

#include "laminate/fhe/mock_backend.hpp"
#include "laminate/protocol/packed/external/preprocessing.hpp"

#include <algorithm>
#include <bit>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <limits>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
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
                    ("laminate-external-packing-setup-" +
                     std::to_string(stamp) + "-" +
                     std::to_string(attempt));
            if (std::filesystem::create_directory(root_)) {
                std::filesystem::permissions(
                    root_, std::filesystem::perms::owner_all,
                    std::filesystem::perm_options::replace);
                return;
            }
        }
        throw std::runtime_error(
            "failed to create external packing setup test tree");
    }

    ~TemporaryTree() {
        std::error_code ignored;
        std::filesystem::remove_all(root_, ignored);
    }

    std::filesystem::path make_directory(std::string_view label) const {
        const std::filesystem::path result = root_ / label;
        if (!std::filesystem::create_directory(result)) {
            throw std::runtime_error(
                "failed to create external packing setup test directory");
        }
        std::filesystem::permissions(
            result, std::filesystem::perms::owner_all,
            std::filesystem::perm_options::replace);
        return result;
    }

  private:
    std::filesystem::path root_;
};

struct SetupRoots {
    SetupRoots(const TemporaryTree &tree, std::string_view prefix,
               std::size_t tensor_count)
        : staging(tree.make_directory(std::string(prefix) + "-staging")),
          canonical(tree.make_directory(std::string(prefix) +
                                        "-canonical")),
          quarantine(tree.make_directory(std::string(prefix) +
                                         "-quarantine")) {
        for (std::size_t tensor = 0; tensor < tensor_count; ++tensor) {
            states.push_back(tree.make_directory(
                std::string(prefix) + "-state-" +
                std::to_string(tensor)));
            scratches.push_back(tree.make_directory(
                std::string(prefix) + "-scratch-" +
                std::to_string(tensor)));
        }
    }

    TranscriptPackingExternalPreprocessingResources resources() const {
        TranscriptPackingExternalPreprocessingResources result{
            .staging_directory = staging,
            .canonical_tensor_directory = canonical,
            .staging_quarantine_directory = quarantine,
        };
        for (std::size_t tensor = 0; tensor < states.size(); ++tensor) {
            result.tensors.push_back({
                .state_directory = states[tensor],
                .scratch_directory = scratches[tensor],
            });
        }
        return result;
    }

    bool all_empty() const {
        for (const std::filesystem::path *path : {
                 &staging,
                 &canonical,
                 &quarantine,
             }) {
            if (!std::filesystem::is_directory(*path) ||
                !std::filesystem::is_empty(*path)) {
                return false;
            }
        }
        for (std::size_t tensor = 0; tensor < states.size(); ++tensor) {
            if (!std::filesystem::is_directory(states[tensor]) ||
                !std::filesystem::is_empty(states[tensor]) ||
                !std::filesystem::is_directory(scratches[tensor]) ||
                !std::filesystem::is_empty(scratches[tensor])) {
                return false;
            }
        }
        return true;
    }

    bool transients_empty() const {
        if (!std::filesystem::is_directory(staging) ||
            !std::filesystem::is_empty(staging) ||
            !std::filesystem::is_directory(quarantine) ||
            !std::filesystem::is_empty(quarantine)) {
            return false;
        }
        return std::ranges::all_of(
            scratches, [](const std::filesystem::path &path) {
                return std::filesystem::is_directory(path) &&
                       std::filesystem::is_empty(path);
            });
    }

    std::filesystem::path staging;
    std::filesystem::path canonical;
    std::filesystem::path quarantine;
    std::vector<std::filesystem::path> states;
    std::vector<std::filesystem::path> scratches;
};

LazyTernaryParameters test_parameters() {
    LazyTernaryParameters result =
        selected_lazy_ternary_parameters();
    result.repetitions = 2;
    return result;
}

TranscriptPackingExternalPreprocessingSpecification small_specification(
    PackingGkrVariant variant = PackingGkrVariant::Folded) {
    return {
        .variant = variant,
        .ring_degree = 32,
        .bhip_round_count = 2,
        .parameters = test_parameters(),
        .basefold_parameters = {.log_rate = 1, .query_count = 1},
        .staging_block_elements = 7,
        .canonical_copy_block_elements = 7,
        .basefold_block_elements = 7,
    };
}

TranscriptPackingExternalPreprocessingLimits exact_limits(
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
    for (const spartan::FactoredTensorExternalPreprocessingPlan &tensor :
         plan.factored.tensors) {
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

ProofOfPackingR1csEncoders mock_encoders(
    const MockBackend::EvalContext &eval) {
    return {
        .centered_coefficients =
            [&eval](const SlotVector &slots) {
                return MockBackend::encode_centered_plaintext_coefficients(
                    eval, slots);
            },
        .native_ntt =
            [&eval](std::span<const std::int64_t> coefficients) {
                return MockBackend::
                    encode_lowest_plaintext_ntt_coordinates(
                        eval, coefficients);
            },
    };
}

TranscriptPackingSpartanSetup resident_setup(
    const MockBackend::EvalContext &eval,
    const TranscriptPackingExternalPreprocessingSpecification &specification) {
    return make_transcript_packing_spartan_setup(
        specification.variant, specification.ring_degree,
        specification.bhip_round_count, mock_encoders(eval),
        specification.parameters, specification.basefold_parameters,
        {.matrix_evaluation =
             spartan::MatrixEvaluationMode::CommittedFactored});
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

Fq2 evaluate_msb(std::span<const Fq> values,
                 std::span<const Fq2> point) {
    Fq2 result = Fq2::zero();
    for (std::size_t index = 0; index < values.size(); ++index) {
        Fq2 weight = Fq2::one();
        for (std::size_t variable = 0; variable < point.size(); ++variable) {
            const bool bit =
                ((index >> (point.size() - 1U - variable)) & 1U) != 0;
            weight *= bit ? point[variable]
                          : Fq2::one() - point[variable];
        }
        result += weight * values[index];
    }
    return result;
}

Fq2 evaluate_linear_combination(
    const std::vector<std::vector<Fq>> &columns,
    std::span<const Fq2> weights, std::span<const Fq2> point) {
    Fq2 result = Fq2::zero();
    for (std::size_t column = 0; column < columns.size(); ++column) {
        result += weights[column] * evaluate_msb(columns[column], point);
    }
    return result;
}

void bind_commitment(const spartan::PcsCommitment &commitment,
                     Transcript &transcript) {
    transcript.observe(
        "test/external-packing-setup/commitment",
        spartan::encode_pcs_commitment(commitment));
}

} // namespace

int main() {
    test::Runner runner("external transcript-packing preprocessing");

    runner.run("target setup plan is formula only", [] {
        const TranscriptPackingExternalPreprocessingSpecification target{
            .variant = PackingGkrVariant::Folded,
            .ring_degree = std::size_t{1} << 14U,
            .bhip_round_count = 517,
            .parameters = selected_lazy_ternary_parameters(),
            .basefold_parameters = {.log_rate = 1, .query_count = 128},
            .staging_block_elements = 4'096,
            .canonical_copy_block_elements = 4'096,
            .basefold_block_elements = 4'096,
        };
        // No path and no encoder exists in this interface. The target plan
        // can therefore only use compact geometry and public formulas.
        const auto plan =
            plan_transcript_packing_external_preprocessing(target);
        CHECK(plan.variant == PackingGkrVariant::Folded);
        CHECK(plan.bhip_round_count == 517);
        CHECK(plan.relation.parameters.repetitions == 120);
        CHECK(plan.relation.r1cs_ledger.total_constraints ==
              3'167'501'480ULL);
        CHECK(plan.relation.circuit_metadata.padded_constraints() ==
              (std::size_t{1} << 32U));
        CHECK(plan.staging.artifact_physical_bytes == 536'871'816ULL);
        CHECK(plan.factored.canonical_artifact_physical_bytes ==
              plan.staging.artifact_physical_bytes);
        CHECK(plan.factored.tensors.size() == 1);
        CHECK(plan.factored.tensors.front().shape.column_count == 4);
        CHECK(plan.factored.tensors.front().shape.evaluation_count ==
              16'777'216ULL);
        CHECK(plan.factored.tensors.front()
                  .commitment.final_physical_bytes ==
              1'652'557'646ULL);
        CHECK(plan.factored.tensors.front()
                  .commitment.scratch_peak_physical_bytes ==
              1'342'178'660ULL);
        CHECK(plan.factored.tensors.front()
                  .commitment.peak_working_field_bytes == 65'536ULL);
        CHECK(plan.factored.external_states_physical_bytes ==
              1'652'557'646ULL);
        CHECK(plan.factored.persistent_output_physical_bytes ==
              2'189'429'462ULL);
        CHECK(plan.factored.conservative_peak_live_physical_bytes ==
              3'531'608'122ULL);
        CHECK(plan.factored.peak_copy_working_field_bytes == 65'536ULL);
        CHECK(plan.factored.peak_working_field_bytes == 65'536ULL);
        CHECK(plan.peak_working_bytes == 688'128ULL);

        auto laned = target;
        laned.variant = PackingGkrVariant::Laned;
        const auto laned_plan =
            plan_transcript_packing_external_preprocessing(laned);
        CHECK(laned_plan.variant == PackingGkrVariant::Laned);
        CHECK(laned_plan.relation.semantic_circuit_digest ==
              plan.relation.semantic_circuit_digest);
    });

    runner.run("every cap minus one rejects before encoders or files", [] {
        const auto specification = small_specification();
        const auto plan =
            plan_transcript_packing_external_preprocessing(specification);
        using Limits =
            TranscriptPackingExternalPreprocessingLimits;
        const std::vector<std::pair<
            std::string, std::function<void(Limits &)>>> cases{
            {"staging-artifact", [](Limits &limits) {
                 --limits.staging_artifact.max_total_bytes;
             }},
            {"staging-working", [](Limits &limits) {
                 --limits.max_staging_working_bytes;
             }},
            {"canonical-artifact", [](Limits &limits) {
                 --limits.canonical_tensor_artifact.max_total_bytes;
             }},
            {"aggregate-live", [](Limits &limits) {
                 --limits.max_live_physical_bytes;
             }},
            {"canonical-copy-working", [](Limits &limits) {
                 --limits.max_copy_working_field_bytes;
             }},
            {"tensor-final", [](Limits &limits) {
                 --limits.tensors.front().max_final_physical_bytes;
             }},
            {"tensor-scratch", [](Limits &limits) {
                 --limits.tensors.front().max_scratch_physical_bytes;
             }},
            {"tensor-working", [](Limits &limits) {
                 --limits.tensors.front().max_working_field_bytes;
             }},
        };
        for (const auto &[label, weaken] : cases) {
            TemporaryTree tree;
            SetupRoots roots(tree, "cap-" + label,
                             plan.factored.tensors.size());
            auto limits = exact_limits(plan);
            weaken(limits);
            auto calls = std::make_shared<std::size_t>(0);
            ProofOfPackingR1csEncoders encoders{
                .centered_coefficients =
                    [calls](const SlotVector &slots) {
                        ++*calls;
                        return SignedCoefficientMask(slots.size(), 0);
                    },
                .native_ntt =
                    [calls](
                        std::span<const std::int64_t> coefficients) {
                        ++*calls;
                        return std::vector<std::uint64_t>(
                            coefficients.size(), 0);
                    },
            };
            CHECK(rejects([&] {
                (void)preprocess_transcript_packing_external(
                    specification, encoders, roots.resources(),
                    limits);
            }));
            CHECK(*calls == 0);
            CHECK(roots.all_empty());
        }
    });

    runner.run("selected-profile quota rejection precedes mask encoding", [] {
        auto specification = small_specification();
        specification.parameters = selected_lazy_ternary_parameters();
        const auto plan =
            plan_transcript_packing_external_preprocessing(specification);
        TemporaryTree tree;
        SetupRoots roots(tree, "selected-quota", plan.factored.tensors.size());
        auto limits = exact_limits(plan);
        --limits.max_staging_working_bytes;

        const auto contexts = MockBackend::create(
            MockParameters{.slot_count = specification.ring_degree,
                           .fresh_rns_limbs = 4, .bits_per_limb = 120});
        const auto base_encoders = mock_encoders(contexts.eval);
        std::size_t calls = 0;
        const ProofOfPackingR1csEncoders encoders{
            .centered_coefficients = [&calls, &base_encoders](const SlotVector &slots) {
                ++calls;
                return base_encoders.centered_coefficients(slots);
            },
            .native_ntt = [&calls, &base_encoders](std::span<const std::int64_t> coefficients) {
                ++calls;
                return base_encoders.native_ntt(coefficients);
            },
        };
        validate_selected_packing_well_formedness(
            plan.relation.packing_operator, encoders.centered_coefficients,
            specification.parameters, specification.ciphertext_commitment_policy);
        CHECK(calls > 0);
        calls = 0;
        CHECK(rejects([&] {
            (void)preprocess_transcript_packing_external(
                specification, encoders, roots.resources(), limits);
        }));
        CHECK(calls == 0);
        CHECK(roots.all_empty());
    });

    runner.run("free-space preflight rejects before encoders or files", [] {
        const auto specification = small_specification();
        const auto plan =
            plan_transcript_packing_external_preprocessing(specification);
        TemporaryTree tree;
        SetupRoots roots(tree, "free-space",
                         plan.factored.tensors.size());
        auto limits = exact_limits(plan);
        limits.staging_artifact.min_free_bytes =
            std::numeric_limits<std::uint64_t>::max() / 2U;
        auto calls = std::make_shared<std::size_t>(0);
        ProofOfPackingR1csEncoders encoders{
            .centered_coefficients =
                [calls](const SlotVector &slots) {
                    ++*calls;
                    return SignedCoefficientMask(slots.size(), 0);
                },
            .native_ntt =
                [calls](std::span<const std::int64_t> coefficients) {
                    ++*calls;
                    return std::vector<std::uint64_t>(
                        coefficients.size(), 0);
                },
        };
        CHECK(rejects([&] {
            (void)preprocess_transcript_packing_external(
                specification, encoders, roots.resources(), limits);
        }));
        CHECK(*calls == 0);
        CHECK(roots.all_empty());
    });

    runner.run("resource roots reject aliases symlinks and shared access",
               [] {
        const auto specification = small_specification();
        const auto plan =
            plan_transcript_packing_external_preprocessing(specification);
        auto counted_encoders = [](std::shared_ptr<std::size_t> calls) {
            return ProofOfPackingR1csEncoders{
                .centered_coefficients =
                    [calls](const SlotVector &slots) {
                        ++*calls;
                        return SignedCoefficientMask(slots.size(), 0);
                    },
                .native_ntt =
                    [calls](
                        std::span<const std::int64_t> coefficients) {
                        ++*calls;
                        return std::vector<std::uint64_t>(
                            coefficients.size(), 0);
                    },
            };
        };

        {
            TemporaryTree tree;
            SetupRoots roots(tree, "alias",
                             plan.factored.tensors.size());
            auto resources = roots.resources();
            resources.canonical_tensor_directory =
                resources.staging_directory;
            auto calls = std::make_shared<std::size_t>(0);
            CHECK(rejects([&] {
                (void)preprocess_transcript_packing_external(
                    specification, counted_encoders(calls),
                    resources, exact_limits(plan));
            }));
            CHECK(*calls == 0);
            CHECK(roots.all_empty());
        }

        {
            TemporaryTree tree;
            SetupRoots roots(tree, "symlink",
                             plan.factored.tensors.size());
            const std::filesystem::path alias =
                roots.staging.parent_path() / "symlink-alias";
            std::filesystem::create_directory_symlink(
                roots.staging, alias);
            auto resources = roots.resources();
            resources.staging_directory = alias;
            auto calls = std::make_shared<std::size_t>(0);
            CHECK(rejects([&] {
                (void)preprocess_transcript_packing_external(
                    specification, counted_encoders(calls),
                    resources, exact_limits(plan));
            }));
            CHECK(*calls == 0);
            CHECK(roots.all_empty());
        }

#ifndef _WIN32
        {
            TemporaryTree tree;
            SetupRoots roots(tree, "permissions",
                             plan.factored.tensors.size());
            std::filesystem::permissions(
                roots.canonical,
                std::filesystem::perms::owner_all |
                    std::filesystem::perms::group_read,
                std::filesystem::perm_options::replace);
            auto calls = std::make_shared<std::size_t>(0);
            CHECK(rejects([&] {
                (void)preprocess_transcript_packing_external(
                    specification, counted_encoders(calls),
                    roots.resources(), exact_limits(plan));
            }));
            CHECK(*calls == 0);
            CHECK(roots.all_empty());
        }
#endif
    });

    runner.run("encoder failure rolls back every setup root", [] {
        const auto specification = small_specification();
        const auto plan =
            plan_transcript_packing_external_preprocessing(specification);
        TemporaryTree tree;
        SetupRoots roots(tree, "failure",
                         plan.factored.tensors.size());
        const auto contexts = MockBackend::create(
            MockParameters{.slot_count = specification.ring_degree,
                           .fresh_rns_limbs = 4,
                           .bits_per_limb = 120});
        auto native_calls = std::make_shared<std::size_t>(0);
        ProofOfPackingR1csEncoders encoders{
            .centered_coefficients =
                [&eval = contexts.eval](const SlotVector &slots) {
                    return MockBackend::
                        encode_centered_plaintext_coefficients(eval, slots);
                },
            .native_ntt =
                [&eval = contexts.eval, native_calls](
                    std::span<const std::int64_t> coefficients) {
                    ++*native_calls;
                    if (*native_calls == 2) {
                        throw std::runtime_error(
                            "injected packing setup encoder failure");
                    }
                    return MockBackend::
                        encode_lowest_plaintext_ntt_coordinates(
                            eval, coefficients);
                },
        };
        CHECK(rejects([&] {
            (void)preprocess_transcript_packing_external(
                specification, encoders, roots.resources(),
                exact_limits(plan));
        }));
        CHECK(*native_calls == 2);
        CHECK(roots.all_empty());
    });

    runner.run("post-staging failure rolls back every admitted root", [] {
        const auto specification = small_specification();
        const auto plan =
            plan_transcript_packing_external_preprocessing(specification);
        TemporaryTree tree;
        SetupRoots roots(tree, "late-failure",
                         plan.factored.tensors.size());
        const auto contexts = MockBackend::create(
            MockParameters{.slot_count = specification.ring_degree,
                           .fresh_rns_limbs = 4,
                           .bits_per_limb = 120});
        auto native_calls = std::make_shared<std::uint64_t>(0);
        ProofOfPackingR1csEncoders encoders{
            .centered_coefficients =
                [&eval = contexts.eval](const SlotVector &slots) {
                    return MockBackend::
                        encode_centered_plaintext_coefficients(eval, slots);
                },
            .native_ntt =
                [&eval = contexts.eval, native_calls, &roots, &plan](
                    std::span<const std::int64_t> coefficients) {
                    ++*native_calls;
                    if (*native_calls ==
                        plan.staging.encoder_invocations) {
                        const std::filesystem::path occupied =
                            roots.quarantine / "staging-artifact";
                        if (!std::filesystem::create_directory(occupied)) {
                            throw std::runtime_error(
                                "failed to inject late setup failure");
                        }
                    }
                    return MockBackend::
                        encode_lowest_plaintext_ntt_coordinates(
                            eval, coefficients);
                },
        };
        CHECK(rejects([&] {
            (void)preprocess_transcript_packing_external(
                specification, encoders, roots.resources(),
                exact_limits(plan));
        }));
        CHECK(*native_calls == plan.staging.encoder_invocations);
        CHECK(roots.all_empty());
    });

    runner.run("rollback refuses to erase a replaced setup root", [] {
        const auto specification = small_specification();
        const auto plan =
            plan_transcript_packing_external_preprocessing(specification);
        TemporaryTree tree;
        SetupRoots roots(tree, "replacement",
                         plan.factored.tensors.size());
        const auto contexts = MockBackend::create(
            MockParameters{.slot_count = specification.ring_degree,
                           .fresh_rns_limbs = 4,
                           .bits_per_limb = 120});
        const std::filesystem::path admitted_copy =
            roots.canonical.parent_path() / "replacement-admitted-copy";
        const std::filesystem::path sentinel =
            roots.canonical / "must-not-delete";
        auto native_calls = std::make_shared<std::uint64_t>(0);
        ProofOfPackingR1csEncoders encoders{
            .centered_coefficients =
                [&eval = contexts.eval](const SlotVector &slots) {
                    return MockBackend::
                        encode_centered_plaintext_coefficients(eval, slots);
                },
            .native_ntt =
                [&eval = contexts.eval, native_calls, &roots, &plan,
                 &admitted_copy, &sentinel](
                    std::span<const std::int64_t> coefficients) {
                    ++*native_calls;
                    if (*native_calls ==
                        plan.staging.encoder_invocations) {
                        std::filesystem::rename(roots.canonical,
                                                admitted_copy);
                        if (!std::filesystem::create_directory(
                                roots.canonical)) {
                            throw std::runtime_error(
                                "failed to inject root replacement");
                        }
                        std::filesystem::permissions(
                            roots.canonical,
                            std::filesystem::perms::owner_all,
                            std::filesystem::perm_options::replace);
                        std::ofstream marker(sentinel);
                        marker << "replacement root";
                        if (!marker) {
                            throw std::runtime_error(
                                "failed to write replacement sentinel");
                        }
                    }
                    return MockBackend::
                        encode_lowest_plaintext_ntt_coordinates(
                            eval, coefficients);
                },
        };
        CHECK(rejects([&] {
            (void)preprocess_transcript_packing_external(
                specification, encoders, roots.resources(),
                exact_limits(plan));
        }));
        CHECK(*native_calls == plan.staging.encoder_invocations);
        CHECK(std::filesystem::is_regular_file(sentinel));
        CHECK(std::filesystem::is_directory(admitted_copy));
        CHECK(std::filesystem::is_empty(admitted_copy));
    });

    runner.run("streamed setup matches resident tensor roots and verifies an opening",
               [] {
        const auto specification = small_specification();
        const auto plan =
            plan_transcript_packing_external_preprocessing(specification);
        const auto contexts = MockBackend::create(
            MockParameters{.slot_count = specification.ring_degree,
                           .fresh_rns_limbs = 4,
                           .bits_per_limb = 120});
        const TranscriptPackingSpartanSetup resident =
            resident_setup(contexts.eval, specification);
        TemporaryTree tree;
        SetupRoots roots(tree, "success",
                         plan.factored.tensors.size());
        TranscriptPackingExternalPreprocessing external =
            preprocess_transcript_packing_external(
                specification, mock_encoders(contexts.eval),
                roots.resources(), exact_limits(plan));

        CHECK(roots.transients_empty());
        CHECK(external.report.plan.factored == plan.factored);
        CHECK(external.report.retired_staging_physical_bytes ==
              plan.staging.artifact_physical_bytes);
        CHECK(external.report.final_persistent_physical_bytes ==
              plan.factored.persistent_output_physical_bytes);
        CHECK(external.prover.variant() == PackingGkrVariant::Folded);
        CHECK(external.verifier.variant == PackingGkrVariant::Folded);
        CHECK(external.prover.bhip_round_count() ==
              specification.bhip_round_count);
        CHECK(external.prover.basefold_pcs() != nullptr);
        CHECK(external.prover.basefold_parameters() ==
              specification.basefold_parameters);
        CHECK(external.prover.spartan_key().setup_digest ==
              external.verifier.spartan.setup_digest);
        CHECK(external.verifier.spartan.direct_matrix == nullptr);
        CHECK(external.verifier.spartan.matrix_oracle == nullptr);
        CHECK(external.verifier.spartan.factored_computation != nullptr);

        const auto &resident_factored =
            resident.spartan.prover_key.factored_computation;
        const auto &external_factored =
            external.prover.spartan_key().factored_computation;
        CHECK(resident_factored != nullptr);
        CHECK(external_factored != nullptr);
        CHECK(external_factored->tensor_column_source ==
              spartan::FactoredTensorColumnSource::Artifact);
        CHECK(external_factored->tensor_columns_artifact != nullptr);
        CHECK(resident_factored->tensors.size() ==
              external_factored->tensors.size());
        CHECK(resident_factored->commitment.tensors.size() ==
              external_factored->commitment.tensors.size());
        for (std::size_t tensor = 0;
             tensor < external_factored->tensors.size(); ++tensor) {
            // The formula metadata deliberately has a different circuit
            // digest from a sparse-matrix serialization. Coefficient PCS
            // roots nevertheless agree exactly.
            CHECK(resident_factored->commitment.tensors[tensor].shape ==
                  external_factored->commitment.tensors[tensor].shape);
            CHECK(resident_factored->commitment.tensors[tensor].columns ==
                  external_factored->commitment.tensors[tensor].columns);
            CHECK(external_factored->tensors[tensor].columns.empty());
            CHECK(external_factored->tensors[tensor].opening_state_source ==
                  spartan::FactoredTensorProverKey::OpeningStateSource::
                      External);
            CHECK(external_factored->tensors[tensor].opening_state !=
                  nullptr);
        }

        const std::size_t tensor = 0;
        const auto &columns = resident_factored->tensors[tensor].columns;
        const auto &commitment =
            external_factored->commitment.tensors[tensor].columns;
        std::vector<Fq2> weights;
        for (std::size_t column = 0; column < columns.size(); ++column) {
            weights.push_back(Fq2(
                {Fq(3U * column + 5U), Fq(7U * column + 11U)}));
        }
        std::vector<Fq2> point;
        const std::size_t variables =
            std::bit_width(columns.front().size()) - 1U;
        for (std::size_t variable = 0; variable < variables; ++variable) {
            point.push_back(Fq2(
                {Fq(13U * variable + 17U),
                 Fq(19U * variable + 23U)}));
        }
        const Fq2 value =
            evaluate_linear_combination(columns, weights, point);
        const std::filesystem::path opening_scratch =
            tree.make_directory("opening-scratch");
        Transcript prover_coin(
            "laminate/test/external-packing-setup-opening/v1");
        bind_commitment(commitment, prover_coin);
        const spartan::BaseFoldExternalOpening opening =
            external.prover.basefold_pcs()
                ->open_linear_combination_external(
                    external_factored->tensors[tensor].opening_state,
                    weights, point, value,
                    {
                        .scratch_directory = opening_scratch,
                        .max_live_storage_bytes = 1ULL << 28U,
                        .max_total_scratch_bytes = 1ULL << 24U,
                        .min_free_bytes = 1,
                        .max_working_field_bytes = 1ULL << 20U,
                        .fold_chunk_elements = 128,
                    },
                    prover_coin);
        CHECK(std::filesystem::is_empty(opening_scratch));
        Transcript verifier_coin(
            "laminate/test/external-packing-setup-opening/v1");
        bind_commitment(commitment, verifier_coin);
        CHECK(external.prover.basefold_pcs()
                  ->verify_linear_combination(
                      commitment, weights, point, value, opening.proof,
                      verifier_coin));
        CHECK(prover_coin.challenge_fq2() ==
              verifier_coin.challenge_fq2());
    });

    runner.run("Laned setup uses the same bounded preprocessing lifecycle",
               [] {
        const auto specification =
            small_specification(PackingGkrVariant::Laned);
        const auto plan =
            plan_transcript_packing_external_preprocessing(specification);
        const auto contexts = MockBackend::create(
            MockParameters{.slot_count = specification.ring_degree,
                           .fresh_rns_limbs = 4,
                           .bits_per_limb = 120});
        TemporaryTree tree;
        SetupRoots roots(tree, "laned-success",
                         plan.factored.tensors.size());
        TranscriptPackingExternalPreprocessing external =
            preprocess_transcript_packing_external(
                specification, mock_encoders(contexts.eval),
                roots.resources(), exact_limits(plan));
        CHECK(roots.transients_empty());
        CHECK(external.prover.variant() == PackingGkrVariant::Laned);
        CHECK(external.verifier.variant == PackingGkrVariant::Laned);
        CHECK(external.report.plan.factored == plan.factored);
        CHECK(external.report.final_persistent_physical_bytes ==
              plan.factored.persistent_output_physical_bytes);
    });

    runner.run("selected packing setup checks public geometry and encoded mask norms", [] {
        const auto contexts = MockBackend::create(
            MockParameters{.slot_count = 32, .fresh_rns_limbs = 4,
                           .bits_per_limb = 120});
        const auto layout = make_fixed_message_coset_packing_layout(32, 1, 2);
        const auto packing_operator = make_packing_linear_operator(layout);
        const auto encoders = mock_encoders(contexts.eval);
        auto parameters = selected_lazy_ternary_parameters();
        const auto poseidon = gkr::CiphertextCommitmentPolicy::poseidon_v2();
        validate_selected_packing_well_formedness(
            packing_operator, encoders.centered_coefficients, parameters, poseidon);

        const auto rejects = [&](const PackingLinearOperator &candidate) {
            bool rejected = false;
            try {
                validate_selected_packing_well_formedness(
                    candidate, encoders.centered_coefficients, parameters,
                    poseidon);
            } catch (const std::invalid_argument &) {
                rejected = true;
            }
            CHECK(rejected);
        };
        auto unsupported = packing_operator;
        unsupported.slot_count = std::size_t{1} << 16U;
        rejects(unsupported);
        unsupported = packing_operator;
        unsupported.aligned_ciphertext_count = (std::size_t{1} << 20U) + 1U;
        rejects(unsupported);
        unsupported = packing_operator;
        unsupported.rows.front().contributions.clear();
        rejects(unsupported);
        parameters.packing_radix.plaintext_modulus = 257;
        rejects(packing_operator);
        parameters = selected_lazy_ternary_parameters();

        // This P satisfies detection for r=1; the actual dense mask norm
        // violates the independent packing inequality.
        parameters.honest_error_bound = kOuterFieldOrder / 200U / kBaseFieldOrder;
        rejects(packing_operator);
        // The same bounded setup remains available only as a reduced-test
        // diagnostic, for which this helper makes no theorem claim.
        parameters.repetitions = 4;
        validate_selected_packing_well_formedness(
            packing_operator, encoders.centered_coefficients, parameters, poseidon);
    });

    return runner.summary();
}
