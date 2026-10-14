/// @file test_matrix_products.cpp
/// @brief External-memory product parity and failure tests.

#include "test_helpers.hpp"

#include "laminate/packing/alignment/layout.hpp"
#include "laminate/packing/proof/matrix/products.hpp"
#include "laminate/packing/proof/reference/materialized_assignment.hpp"
#include "laminate/packing/proof/spartan_external.hpp"
#include "laminate/packing/proof/matrix/metadata.hpp"
#include "laminate/spartan/basefold_pcs.hpp"
#include "laminate/transcript/transcript.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iterator>
#include <limits>
#include <memory>
#include <set>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

using namespace laminate;
using namespace laminate::packing;

namespace {

template <typename Key>
concept HasExpandedCircuit = requires(Key key) { key.circuit; };

template <typename Key>
concept HasMatrixOracle = requires(Key key) { key.matrix_oracle; };

static_assert(!HasExpandedCircuit<spartan::ExternalProverKey>);
static_assert(!HasMatrixOracle<spartan::ExternalProverKey>);

class TemporaryDirectory {
  public:
    explicit TemporaryDirectory(std::string_view label) {
        const auto stamp = std::chrono::steady_clock::now()
                               .time_since_epoch()
                               .count();
        for (std::size_t attempt = 0; attempt < 100; ++attempt) {
            path_ = std::filesystem::temp_directory_path() /
                    ("laminate-matrix-products-" + std::string(label) +
                     "-" + std::to_string(stamp) + "-" +
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

    const std::filesystem::path &path() const { return path_; }

    TemporaryDirectory(const TemporaryDirectory &) = delete;
    TemporaryDirectory &operator=(const TemporaryDirectory &) = delete;

  private:
    std::filesystem::path path_;
};

class ThrowingObserveCoin final : public PublicCoin {
  public:
    ThrowingObserveCoin(std::string_view domain, std::string_view label)
        : transcript_(domain), label_(label) {}

    void observe(std::string_view label,
                 std::span<const std::uint8_t> bytes) override {
        if (label == label_) {
            throw std::runtime_error("injected public-coin failure");
        }
        transcript_.observe(label, bytes);
    }

    void observe(std::string_view label, std::uint64_t value) override {
        if (label == label_) {
            throw std::runtime_error("injected public-coin failure");
        }
        transcript_.observe(label, value);
    }

    Fpk challenge_fpk() override { return transcript_.challenge_fpk(); }
    Fq challenge_fq() override { return transcript_.challenge_fq(); }
    Fq2 challenge_fq2() override { return transcript_.challenge_fq2(); }
    std::vector<Fq2> challenge_fq2_vector(std::size_t count) override {
        return transcript_.challenge_fq2_vector(count);
    }
    std::vector<Fpk> challenge_vector(std::size_t count) override {
        return transcript_.challenge_vector(count);
    }
    std::vector<bool> challenge_bits(std::size_t count) override {
        return transcript_.challenge_bits(count);
    }

  private:
    Transcript transcript_;
    std::string label_;
};

struct ExternalSpartanRoots {
    explicit ExternalSpartanRoots(std::string_view prefix)
        : assignment(std::string(prefix) + "-assignment"),
          products(std::string(prefix) + "-products"),
          witness_state(std::string(prefix) + "-witness-state"),
          witness_commit_scratch(
              std::string(prefix) + "-witness-commit-scratch"),
          constraint_scratch(
              std::string(prefix) + "-constraint-scratch"),
          wiring_matrix(std::string(prefix) + "-wiring-matrix"),
          wiring_scratch(std::string(prefix) + "-wiring-scratch"),
          factored_opening_scratch(
              std::string(prefix) + "-factored-opening-scratch"),
          witness_opening_scratch(
              std::string(prefix) + "-witness-opening-scratch") {}

    bool empty() const {
        return std::filesystem::is_empty(assignment.path()) &&
               std::filesystem::is_empty(products.path()) &&
               std::filesystem::is_empty(witness_state.path()) &&
               std::filesystem::is_empty(witness_commit_scratch.path()) &&
               std::filesystem::is_empty(constraint_scratch.path()) &&
               std::filesystem::is_empty(wiring_matrix.path()) &&
               std::filesystem::is_empty(wiring_scratch.path()) &&
               std::filesystem::is_empty(factored_opening_scratch.path()) &&
               std::filesystem::is_empty(witness_opening_scratch.path());
    }

    TemporaryDirectory assignment;
    TemporaryDirectory products;
    TemporaryDirectory witness_state;
    TemporaryDirectory witness_commit_scratch;
    TemporaryDirectory constraint_scratch;
    TemporaryDirectory wiring_matrix;
    TemporaryDirectory wiring_scratch;
    TemporaryDirectory factored_opening_scratch;
    TemporaryDirectory witness_opening_scratch;
};

template <typename Exception = std::exception, typename Action>
bool rejects_as(Action action) {
    try {
        action();
    } catch (const Exception &) {
        return true;
    }
    return false;
}

SignedCoefficientMask identity_coefficients(const fhe::SlotVector &slots) {
    SignedCoefficientMask result;
    result.reserve(slots.size());
    for (const Fp value : slots) {
        result.push_back(static_cast<std::int64_t>(value.value()));
    }
    return result;
}

std::vector<std::uint64_t> identity_native_ntt(
    std::span<const std::int64_t> coefficients) {
    std::vector<std::uint64_t> result;
    result.reserve(coefficients.size());
    for (const std::int64_t coefficient : coefficients) {
        const std::uint64_t magnitude =
            coefficient >= 0
                ? static_cast<std::uint64_t>(coefficient)
                : std::uint64_t{0} -
                      static_cast<std::uint64_t>(coefficient);
        result.push_back(
            coefficient >= 0 || magnitude == 0
                ? magnitude % kOuterFieldOrder
                : (kOuterFieldOrder - magnitude % kOuterFieldOrder) %
                      kOuterFieldOrder);
    }
    return result;
}

LazyTernaryChallengeMatrix challenges() {
    return {
        {{false, false}, {true, true}, {true, false}},
        {{false, true}, {true, false}, {true, true}},
    };
}

OuterRelationPlan make_test_plan(
    const NativePackingOperator &native,
    gkr::CiphertextCommitmentPolicy policy) {
    OuterRelationPlan result = make_outer_relation_plan(native, 2, 2, 5);
    result.shape.ciphertext_commitment_policy = policy;
    return result;
}

OuterRelationAssignmentArtifactOptions outer_options(
    const std::filesystem::path &directory) {
    return {
        .directory = directory,
        .storage_limits = {
            .max_total_bytes = 1ULL << 24U,
            .min_free_bytes = 1,
        },
        .max_working_field_bytes = 256,
        .block_elements = 11,
    };
}

ProofOfPackingAssignmentArtifactOptions complete_options(
    const std::filesystem::path &directory) {
    return {
        .directory = directory,
        .storage_limits = {
            .max_total_bytes = 1ULL << 28U,
            .min_free_bytes = 1,
        },
        .max_working_bytes = 1ULL << 24U,
        .block_elements = 13,
    };
}

spartan::FactoredMatrixArtifactOptions factored_options(
    const std::filesystem::path &directory) {
    return {
        .directory = directory,
        .limits = {
            .max_total_bytes = 1ULL << 24U,
            .min_free_bytes = 1,
        },
    };
}

ProofOfPackingMatrixProductArtifactOptions product_options(
    const std::filesystem::path &directory,
    std::uint64_t max_total_bytes = 1ULL << 28U,
    std::uint64_t max_working_field_bytes = 1ULL << 16U,
    std::size_t block_elements = 7) {
    return {
        .directory = directory,
        .storage_limits = {
            .max_total_bytes = max_total_bytes,
            .min_free_bytes = 1,
        },
        .max_working_field_bytes = max_working_field_bytes,
        .block_elements = block_elements,
    };
}

ProofOfPackingExternalSpartanOptions external_spartan_options(
    const ExternalSpartanRoots &roots, std::uint64_t max_live_storage) {
    return {
        .max_live_storage_bytes = max_live_storage,
        .assignment = complete_options(roots.assignment.path()),
        .matrix_products = product_options(roots.products.path()),
        .witness_commitment = {
            .destination_directory = roots.witness_state.path(),
            .scratch_directory = roots.witness_commit_scratch.path(),
            .max_final_bytes = 1ULL << 30U,
            .max_scratch_bytes = 1ULL << 30U,
            .min_free_bytes = 1,
            .max_working_field_bytes = 1ULL << 24U,
            .block_elements = 7,
        },
        .constraint_sumcheck = {
            .scratch_directory = roots.constraint_scratch.path(),
            .max_live_storage_bytes = 1,
            .max_total_scratch_bytes = 1ULL << 30U,
            .min_free_bytes = 1,
            .max_working_field_bytes = 1ULL << 24U,
            .block_elements = 7,
            .source_rounds = 4,
        },
        .wiring_matrix = {
            .directory = roots.wiring_matrix.path(),
            .storage_limits = {.max_total_bytes = 1ULL << 30U,
                               .min_free_bytes = 1},
            .max_live_storage_bytes = 1,
            .max_working_field_bytes = 1ULL << 24U,
            .block_elements = 7,
        },
        .wiring_sumcheck = {
            .scratch_directory = roots.wiring_scratch.path(),
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
                    roots.factored_opening_scratch.path(),
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
            .scratch_directory = roots.witness_opening_scratch.path(),
            .max_live_storage_bytes = 1,
            .max_total_scratch_bytes = 1ULL << 30U,
            .min_free_bytes = 1,
            .max_working_field_bytes = 1ULL << 24U,
            .fold_chunk_elements = 128,
        },
    };
}

struct Fixture {
    BalancedRadix radix =
        make_minimal_balanced_radix(kBaseFieldOrder, 17);
    PackingLinearOperator logical = make_packing_linear_operator(
        make_prefix_packing_layout(
            16, std::vector<std::size_t>{4, 4, 4}));
    NativePackingOperator native =
        make_native_signed_digit_packing_operator(
            logical, identity_coefficients, identity_native_ntt,
            kOuterFieldOrder, radix);
    OuterRelationPlan plan;
    OuterRelationWitnessInputs witness_inputs;
    OuterRelationPublicInputs public_inputs;
    OuterRelationR1csAssignment outer_assignment;
    std::vector<gkr::HashCommitCT> commitments;
    CompiledProofOfPackingR1cs compiled;
    spartan::R1csAssignment complete_assignment;

    explicit Fixture(
        gkr::CiphertextCommitmentPolicy commitment_policy =
            gkr::CiphertextCommitmentPolicy::poseidon_v2())
        : plan(make_test_plan(native, commitment_policy)),
          compiled(compile_proof_of_packing_r1cs(
              plan, logical,
              {.centered_coefficients = identity_coefficients,
               .native_ntt = identity_native_ntt},
              radix)) {
        witness_inputs.aligned_ciphertext_coordinates.resize(
            plan.variables.witness.aligned_ciphertext_coordinates.count);
        for (std::size_t index = 0;
             index < witness_inputs.aligned_ciphertext_coordinates.size();
             ++index) {
            witness_inputs.aligned_ciphertext_coordinates[index] =
                3 + 7 * index;
        }
        public_inputs.packed_challenge_words =
            pack_outer_relation_challenge_bits(plan, challenges());
        const OuterRelationExpectedOutputs expected =
            compute_outer_relation_expected_outputs(
                plan, public_inputs.packed_challenge_words,
                witness_inputs, native);
        public_inputs.revealed_test_coordinates =
            expected.revealed_test_coordinates;
        public_inputs.revealed_packing_coordinates =
            expected.revealed_packing_coordinates;
        const OuterRelationAuxiliaryWitness auxiliary =
            build_outer_relation_auxiliary_witness(
                plan, public_inputs.packed_challenge_words,
                witness_inputs);
        outer_assignment = make_outer_relation_r1cs_assignment(
            plan, public_inputs, witness_inputs, auxiliary);

        const std::size_t coordinates_per_ciphertext =
            plan.coordinates_per_ciphertext();
        for (std::size_t ciphertext = 0;
             ciphertext < plan.shape.aligned_ciphertexts; ++ciphertext) {
            const auto coordinates = std::span(
                witness_inputs.aligned_ciphertext_coordinates)
                                         .subspan(
                                             ciphertext *
                                                 coordinates_per_ciphertext,
                                             coordinates_per_ciphertext);
            commitments.push_back(
                gkr::hash_commit_normalized_ciphertext_coordinates(
                    plan.shape.ring_degree, coordinates,
                    plan.shape.ciphertext_commitment_policy));
        }
        complete_assignment =
            reference::make_materialized_proof_of_packing_assignment(
            plan, commitments, outer_assignment);
    }

    OuterRelationR1csAssignmentView outer_view() const {
        return OuterRelationR1csAssignmentView(
            plan, public_inputs, witness_inputs);
    }
};

struct Sources {
    OuterRelationAssignmentArtifact outer;
    ProofOfPackingAssignmentArtifact complete;
    spartan::FactoredMatrixSetup factored;
};

Sources write_sources(const Fixture &fixture,
                      const std::filesystem::path &outer_directory,
                      const std::filesystem::path &complete_directory,
                      const std::filesystem::path &factored_directory) {
    Sources result;
    result.outer = write_outer_relation_assignment_artifact(
        fixture.outer_view(), outer_options(outer_directory));
    result.complete = write_proof_of_packing_assignment_artifact(
        fixture.plan, fixture.compiled.circuit.metadata(),
        *result.outer.artifact, fixture.commitments,
        complete_options(complete_directory));

    std::vector<PackingTensor> tensors = compile_packing_tensors(
        fixture.plan, fixture.native);
    const auto structure = make_proof_of_packing_factored_structure(
        fixture.plan, fixture.compiled.layout, tensors,
        fixture.compiled.circuit.metadata());
    std::vector<std::vector<std::vector<Fq>>> columns;
    columns.reserve(tensors.size());
    for (PackingTensor &tensor : tensors) {
        columns.push_back(std::move(tensor.digit_columns));
    }
    const spartan::BaseFoldPcs pcs(
        {.log_rate = 1, .query_count = 1});
    result.factored = spartan::preprocess_factored_matrix_to_artifact(
        structure, std::move(columns), pcs,
        factored_options(factored_directory));
    return result;
}

std::vector<Fq> read_array(
    const storage::NativeFieldArtifact &artifact,
    std::string_view name) {
    auto reader = artifact.open_array(name);
    std::vector<Fq> result(
        static_cast<std::size_t>(reader.size()));
    CHECK(reader.read(result) == result.size());
    return result;
}

void flip_last_byte(const std::filesystem::path &path) {
    std::fstream file(path, std::ios::in | std::ios::out | std::ios::binary);
    if (!file) {
        throw std::runtime_error("failed to open artifact for corruption");
    }
    file.seekg(-1, std::ios::end);
    char value = 0;
    file.read(&value, 1);
    value ^= 1;
    file.seekp(-1, std::ios::end);
    file.write(&value, 1);
}

} // namespace

int main() {
    test::Runner runner("test_proof_of_packing_matrix_products");

    runner.run("disk products match direct A B C exactly", [] {
        const Fixture fixture;
        CHECK(fixture.plan.shape.aligned_ciphertexts == 3);
        CHECK(fixture.compiled.layout.ciphertext_segments.size() > 1);
        CHECK(fixture.compiled.layout.rows.well_formedness_products.begin >
              fixture.compiled.layout.rows
                  .challenge_word_recomposition.end());

        TemporaryDirectory outer_directory("outer");
        TemporaryDirectory complete_directory("complete");
        TemporaryDirectory factored_directory("factored");
        TemporaryDirectory product_directory("products");
        const Sources sources = write_sources(
            fixture, outer_directory.path(), complete_directory.path(),
            factored_directory.path());
        const auto mappings = proof_of_packing_factored_tensor_mappings(
            *sources.factored.prover_key.structure);
        CHECK(mappings.size() == 1);
        CHECK(mappings.front().global_owners.size() == 3);

        const ProofOfPackingMatrixProductArtifact products =
            write_proof_of_packing_matrix_product_artifact(
                fixture.plan, fixture.compiled.layout,
                fixture.compiled.circuit.metadata(),
                *sources.complete.artifact, *sources.outer.artifact,
                sources.factored.prover_key,
                product_options(product_directory.path()));
        const std::vector<Fq> z =
            fixture.compiled.circuit.padded_assignment(
                fixture.complete_assignment);
        const std::array<spartan::Matrix, 3> matrices{
            spartan::Matrix::A, spartan::Matrix::B,
            spartan::Matrix::C};
        const std::array<std::string_view, 3> names{
            "az", "bz", "cz"};
        std::array<std::vector<Fq>, 3> values;
        for (std::size_t matrix = 0; matrix < matrices.size(); ++matrix) {
            values[matrix] = read_array(*products.artifact, names[matrix]);
            const std::vector<Fq> direct =
                fixture.compiled.circuit.multiply(matrices[matrix], z);
            CHECK(values[matrix].size() ==
                  fixture.compiled.circuit.shape().constraints);
            CHECK(std::equal(values[matrix].begin(), values[matrix].end(),
                             direct.begin()));
            CHECK(std::all_of(
                direct.begin() +
                    static_cast<std::ptrdiff_t>(values[matrix].size()),
                direct.end(), [](const Fq &value) {
                    return value.is_zero();
                }));
        }
        for (std::size_t row = 0; row < values[0].size(); ++row) {
            CHECK(values[0][row] * values[1][row] == values[2][row]);
        }

        const auto &report = products.report;
        CHECK(report.stored_constraint_elements ==
              fixture.compiled.circuit.shape().constraints);
        CHECK(report.logical_padded_constraint_elements ==
              fixture.compiled.circuit.padded_constraints());
        CHECK(report.ciphertext_commitment_rows ==
              fixture.compiled.layout.rows.ciphertext_poseidon.live);
        CHECK(report.fixed_packing_rows ==
              fixture.plan.constraints.revealed_packing_equalities.count);
        CHECK(report.structural_zero_rows_per_matrix ==
              fixture.compiled.circuit.shape().constraints -
                  fixture.compiled.ledger.total_constraints);
        CHECK(report.virtual_zero_rows_per_matrix ==
              fixture.compiled.circuit.padded_constraints() -
                  fixture.compiled.circuit.shape().constraints);
        CHECK(report.product_payload_bytes ==
              3 * report.stored_constraint_elements * sizeof(Fq));
        CHECK(report.sequential_output_payload_bytes ==
              report.product_payload_bytes);
        CHECK(report.physical_bytes == products.artifact->physical_bytes());
        CHECK(report.output_artifact_validation_bytes ==
              report.physical_bytes);
        CHECK(report.source_artifact_validation_bytes ==
              report.source_artifact_physical_bytes);
        CHECK(report.complete_assignment_io.payload_bytes > 0);
        CHECK(report.outer_assignment_io.payload_bytes > 0);
        CHECK(report.factored_tensor_io.payload_bytes > 0);
        CHECK(report.revealed_test_product_elements_read ==
              fixture.plan.variables.witness
                  .well_formedness_products.count);
        CHECK(report.revealed_test_product_payload_bytes ==
              report.revealed_test_product_elements_read * sizeof(Fq));
        const std::uint64_t product_blocks_per_owner =
            fixture.plan.shape.ring_degree /
                report.effective_block_elements +
            (fixture.plan.shape.ring_degree %
                     report.effective_block_elements !=
                 0
             ? 1
             : 0);
        CHECK(report.revealed_test_product_read_operations ==
              fixture.plan.shape.repetitions *
                  fixture.plan.shape.ciphertext_components *
                  fixture.plan.shape.aligned_ciphertexts *
                  product_blocks_per_owner);
        CHECK(report.revealed_test_product_seek_operations ==
              fixture.plan.shape.repetitions *
                      (2 * fixture.plan.shape.aligned_ciphertexts - 1) +
                  1);
        CHECK(report.fixed_accumulator_elements ==
              fixture.plan.shape.ring_degree);
        CHECK(report.peak_working_field_bytes <=
              product_options(product_directory.path())
                  .max_working_field_bytes);
        CHECK(report.maximum_regular_row_terms ==
              std::max(fixture.plan.shape.aligned_ciphertexts,
                       fixture.plan.shape.public_input_capacity_bits));

        const auto reopened =
            open_proof_of_packing_matrix_product_artifact(
                product_directory.path(), fixture.plan,
                fixture.compiled.layout,
                fixture.compiled.circuit.metadata(),
                *sources.complete.artifact, *sources.outer.artifact,
                sources.factored.prover_key.commitment,
                *sources.factored.prover_key.tensor_columns_artifact);
        CHECK(reopened->identity() == products.artifact->identity());
        CHECK(reopened->arrays() == products.artifact->arrays());
    });

    runner.run("diagnostic simpleCTHash disk products match direct A B C",
               [] {
                   const Fixture fixture(
                       gkr::CiphertextCommitmentPolicy::
                           diagnostic_simple_ct_hash_v2());
                   TemporaryDirectory outer_directory("simple-outer");
                   TemporaryDirectory complete_directory("simple-complete");
                   TemporaryDirectory factored_directory("simple-factored");
                   TemporaryDirectory product_directory("simple-products");
                   const Sources sources = write_sources(
                       fixture, outer_directory.path(),
                       complete_directory.path(), factored_directory.path());
                   const auto products =
                       write_proof_of_packing_matrix_product_artifact(
                           fixture.plan, fixture.compiled.layout,
                           fixture.compiled.circuit.metadata(),
                           *sources.complete.artifact,
                           *sources.outer.artifact,
                           sources.factored.prover_key,
                           product_options(product_directory.path()));
                   const std::vector<Fq> assignment =
                       fixture.compiled.circuit.padded_assignment(
                           fixture.complete_assignment);
                   const std::array<spartan::Matrix, 3> matrices{
                       spartan::Matrix::A, spartan::Matrix::B,
                       spartan::Matrix::C};
                   const std::array<std::string_view, 3> names{
                       "az", "bz", "cz"};
                   for (std::size_t index = 0; index < matrices.size();
                        ++index) {
                       const auto external =
                           read_array(*products.artifact, names[index]);
                       const auto resident =
                           fixture.compiled.circuit.multiply(
                               matrices[index], assignment);
                       CHECK(std::equal(external.begin(), external.end(),
                                        resident.begin()));
                   }
               });

    runner.run("product identity report and output are deterministic", [] {
        const Fixture fixture;
        TemporaryDirectory outer_directory("det-outer");
        TemporaryDirectory complete_directory("det-complete");
        TemporaryDirectory factored_directory("det-factored");
        TemporaryDirectory first_directory("det-first");
        TemporaryDirectory second_directory("det-second");
        const Sources sources = write_sources(
            fixture, outer_directory.path(), complete_directory.path(),
            factored_directory.path());
        const auto first = write_proof_of_packing_matrix_product_artifact(
            fixture.plan, fixture.compiled.layout,
            fixture.compiled.circuit.metadata(),
            *sources.complete.artifact, *sources.outer.artifact,
            sources.factored.prover_key,
            product_options(first_directory.path()));
        const auto second = write_proof_of_packing_matrix_product_artifact(
            fixture.plan, fixture.compiled.layout,
            fixture.compiled.circuit.metadata(),
            *sources.complete.artifact, *sources.outer.artifact,
            sources.factored.prover_key,
            product_options(second_directory.path()));
        CHECK(first.report == second.report);
        CHECK(first.artifact->identity() == second.artifact->identity());
        CHECK(first.artifact->arrays() == second.artifact->arrays());
    });

    runner.run("product limits and source types fail closed", [] {
        const Fixture fixture;
        TemporaryDirectory outer_directory("limit-outer");
        TemporaryDirectory complete_directory("limit-complete");
        TemporaryDirectory factored_directory("limit-factored");
        TemporaryDirectory baseline_directory("limit-baseline");
        const Sources sources = write_sources(
            fixture, outer_directory.path(), complete_directory.path(),
            factored_directory.path());
        const auto baseline =
            write_proof_of_packing_matrix_product_artifact(
                fixture.plan, fixture.compiled.layout,
                fixture.compiled.circuit.metadata(),
                *sources.complete.artifact, *sources.outer.artifact,
                sources.factored.prover_key,
                product_options(baseline_directory.path()));

        TemporaryDirectory quota_directory("limit-quota");
        CHECK(rejects_as<std::invalid_argument>([&] {
            (void)write_proof_of_packing_matrix_product_artifact(
                fixture.plan, fixture.compiled.layout,
                fixture.compiled.circuit.metadata(),
                *sources.complete.artifact, *sources.outer.artifact,
                sources.factored.prover_key,
                product_options(quota_directory.path(),
                                baseline.report.physical_bytes - 1));
        }));
        CHECK(std::filesystem::is_empty(quota_directory.path()));

        TemporaryDirectory memory_directory("limit-memory");
        CHECK(rejects_as<std::invalid_argument>([&] {
            (void)write_proof_of_packing_matrix_product_artifact(
                fixture.plan, fixture.compiled.layout,
                fixture.compiled.circuit.metadata(),
                *sources.complete.artifact, *sources.outer.artifact,
                sources.factored.prover_key,
                product_options(
                    memory_directory.path(), 1ULL << 28U,
                    fixture.plan.shape.ring_degree * sizeof(Fq)));
        }));
        CHECK(std::filesystem::is_empty(memory_directory.path()));

        TemporaryDirectory occupied_directory("limit-occupied");
        const std::filesystem::path marker =
            occupied_directory.path() / "keep";
        std::ofstream(marker) << "keep";
        CHECK(rejects_as<std::invalid_argument>([&] {
            (void)write_proof_of_packing_matrix_product_artifact(
                fixture.plan, fixture.compiled.layout,
                fixture.compiled.circuit.metadata(),
                *sources.complete.artifact, *sources.outer.artifact,
                sources.factored.prover_key,
                product_options(occupied_directory.path()));
        }));
        CHECK(std::filesystem::exists(marker));

        spartan::FactoredMatrixProverKey resident =
            sources.factored.prover_key;
        resident.tensor_column_source =
            spartan::FactoredTensorColumnSource::Resident;
        resident.tensor_columns_artifact.reset();
        TemporaryDirectory type_directory("limit-type");
        CHECK(rejects_as<std::invalid_argument>([&] {
            (void)write_proof_of_packing_matrix_product_artifact(
                fixture.plan, fixture.compiled.layout,
                fixture.compiled.circuit.metadata(),
                *sources.complete.artifact, *sources.outer.artifact,
                resident, product_options(type_directory.path()));
        }));
        CHECK(std::filesystem::is_empty(type_directory.path()));

        TemporaryDirectory changed_outer_directory("limit-changed-outer");
        auto changed_witness = fixture.witness_inputs;
        ++changed_witness.aligned_ciphertext_coordinates.front();
        const OuterRelationR1csAssignmentView changed_view(
            fixture.plan, fixture.public_inputs, changed_witness);
        const OuterRelationAssignmentArtifact changed_outer =
            write_outer_relation_assignment_artifact(
                changed_view,
                outer_options(changed_outer_directory.path()));
        TemporaryDirectory identity_directory("limit-identity");
        CHECK(rejects_as<std::invalid_argument>([&] {
            (void)write_proof_of_packing_matrix_product_artifact(
                fixture.plan, fixture.compiled.layout,
                fixture.compiled.circuit.metadata(),
                *sources.complete.artifact, *changed_outer.artifact,
                sources.factored.prover_key,
                product_options(identity_directory.path()));
        }));
        CHECK(std::filesystem::is_empty(identity_directory.path()));

        const std::filesystem::path nested_destination =
            outer_directory.path() / "nested-output";
        std::filesystem::create_directory(nested_destination);
        CHECK(rejects_as<std::invalid_argument>([&] {
            (void)write_proof_of_packing_matrix_product_artifact(
                fixture.plan, fixture.compiled.layout,
                fixture.compiled.circuit.metadata(),
                *sources.complete.artifact, *sources.outer.artifact,
                sources.factored.prover_key,
                product_options(nested_destination));
        }));
        CHECK(std::filesystem::is_empty(nested_destination));

        spartan::FactoredMatrixCommitment wrong =
            sources.factored.prover_key.commitment;
        wrong.structure_digest.front() ^= 1U;
        CHECK(rejects_as<std::invalid_argument>([&] {
            (void)open_proof_of_packing_matrix_product_artifact(
                baseline_directory.path(), fixture.plan,
                fixture.compiled.layout,
                fixture.compiled.circuit.metadata(),
                *sources.complete.artifact, *sources.outer.artifact,
                wrong,
                *sources.factored.prover_key.tensor_columns_artifact);
        }));
    });

    runner.run("changed tensor payload is revalidated before publication", [] {
        const Fixture fixture;
        TemporaryDirectory outer_directory("late-outer");
        TemporaryDirectory complete_directory("late-complete");
        TemporaryDirectory factored_directory("late-factored");
        TemporaryDirectory product_directory("late-products");
        const Sources sources = write_sources(
            fixture, outer_directory.path(), complete_directory.path(),
            factored_directory.path());
        const std::filesystem::path first_tensor =
            factored_directory.path() /
            "array-0000000000000000.bin";
        // The FactoredMatrixSetup still holds an already-open artifact object.
        // Mutating an unused padded-owner payload byte proves the product
        // writer performs a fresh full-file validation rather than trusting
        // that cached descriptor.
        flip_last_byte(first_tensor);
        CHECK(rejects_as([&] {
            (void)write_proof_of_packing_matrix_product_artifact(
                fixture.plan, fixture.compiled.layout,
                fixture.compiled.circuit.metadata(),
                *sources.complete.artifact, *sources.outer.artifact,
                sources.factored.prover_key,
                product_options(product_directory.path()));
        }));
        CHECK(std::filesystem::is_empty(product_directory.path()));
        CHECK(std::filesystem::exists(first_tensor));
        CHECK(std::filesystem::exists(outer_directory.path() /
                                      "manifest.bin"));
        CHECK(std::filesystem::exists(complete_directory.path() /
                                      "manifest.bin"));
    });

    runner.run("corrupted completed product is rejected", [] {
        const Fixture fixture;
        TemporaryDirectory outer_directory("corrupt-outer");
        TemporaryDirectory complete_directory("corrupt-complete");
        TemporaryDirectory factored_directory("corrupt-factored");
        TemporaryDirectory product_directory("corrupt-products");
        const Sources sources = write_sources(
            fixture, outer_directory.path(), complete_directory.path(),
            factored_directory.path());
        (void)write_proof_of_packing_matrix_product_artifact(
            fixture.plan, fixture.compiled.layout,
            fixture.compiled.circuit.metadata(),
            *sources.complete.artifact, *sources.outer.artifact,
            sources.factored.prover_key,
            product_options(product_directory.path()));
        flip_last_byte(product_directory.path() /
                       "array-0000000000000000.bin");
        CHECK(rejects_as([&] {
            (void)open_proof_of_packing_matrix_product_artifact(
                product_directory.path(), fixture.plan,
                fixture.compiled.layout,
                fixture.compiled.circuit.metadata(),
                *sources.complete.artifact, *sources.outer.artifact,
                sources.factored.prover_key.commitment,
                *sources.factored.prover_key.tensor_columns_artifact);
        }));
    });

    runner.run("formula-only metadata constructs compact external setup",
               [] {
        const BalancedRadix radix =
            make_minimal_balanced_radix(kBaseFieldOrder, 17);
        const PackingLayout alignment_layout =
            make_prefix_packing_layout(
                16, std::vector<std::size_t>{4, 4, 4});
        const PackingLinearOperator logical =
            make_packing_linear_operator(alignment_layout);
        const LazyTernaryParameters parameters{
            .repetitions = 2,
            .honest_error_bound = 23,
            .packing_radix = radix,
        };
        const ProofOfPackingStructuredMetadata structured =
            make_proof_of_packing_structured_metadata(
                alignment_layout, parameters);
        structured.validate();
        const NativePackingOperator native =
            make_native_signed_digit_packing_operator(
                logical, identity_coefficients, identity_native_ntt,
                kOuterFieldOrder, radix);
        std::vector<PackingTensor> tensors = compile_packing_tensors(
            structured.relation_plan, native);
        const auto structure = make_proof_of_packing_factored_structure(
            structured.relation_plan, structured.r1cs_layout,
            structured.tensor_mappings, structured.circuit_metadata);
        std::vector<std::vector<std::vector<Fq>>> columns;
        columns.reserve(tensors.size());
        for (PackingTensor &tensor : tensors) {
            columns.push_back(std::move(tensor.digit_columns));
        }
        const spartan::BaseFoldPcs pcs(
            {.log_rate = 1, .query_count = 1});
        TemporaryDirectory factored_directory("formula-factored");
        spartan::FactoredMatrixSetup factored =
            spartan::preprocess_factored_matrix_to_artifact(
                structure, std::move(columns), pcs,
                factored_options(factored_directory.path()));
        const spartan::ExternalSetup setup =
            spartan::setup_external_committed_factored(
                structured.circuit_metadata, pcs,
                std::make_shared<const spartan::FactoredMatrixProverKey>(
                    factored.prover_key),
                std::make_shared<const spartan::FactoredMatrixVerifierKey>(
                    factored.verifier_key));
        spartan::validate_external_prover_key(setup.prover_key, pcs);
        CHECK(setup.prover_key.circuit_metadata ==
              structured.circuit_metadata);
        CHECK(setup.verifier_key.circuit_metadata ==
              structured.circuit_metadata);
        CHECK(setup.prover_key.setup_digest ==
              setup.verifier_key.setup_digest);
        CHECK(setup.verifier_key.direct_matrix == nullptr);
        CHECK(setup.verifier_key.matrix_oracle == nullptr);

        auto mismatched_verifier = factored.verifier_key;
        mismatched_verifier.commitment.structure_digest.front() ^= 1U;
        CHECK(rejects_as<std::invalid_argument>([&] {
            (void)spartan::setup_external_committed_factored(
                structured.circuit_metadata, pcs,
                std::make_shared<const spartan::FactoredMatrixProverKey>(
                    factored.prover_key),
                std::make_shared<
                    const spartan::FactoredMatrixVerifierKey>(
                    mismatched_verifier));
        }));
    });

    runner.run("composed external Spartan matches resident proof bytes", [] {
        const Fixture fixture;
        TemporaryDirectory outer_directory("spartan-outer");
        TemporaryDirectory unused_complete_directory(
            "spartan-source-complete");
        TemporaryDirectory factored_directory("spartan-factored");
        const Sources sources = write_sources(
            fixture, outer_directory.path(),
            unused_complete_directory.path(), factored_directory.path());
        const spartan::BaseFoldPcs pcs(
            {.log_rate = 1, .query_count = 1});
        auto circuit = std::make_shared<const spartan::R1csInstance>(
            fixture.compiled.circuit);
        const auto oracle = make_proof_of_packing_factored_prover_oracle(
            fixture.plan, fixture.compiled.layout, circuit);
        spartan::Setup keys = spartan::setup(
            circuit, pcs,
            {.matrix_evaluation =
                 spartan::MatrixEvaluationMode::CommittedFactored},
            oracle,
            std::make_shared<const spartan::FactoredMatrixProverKey>(
                sources.factored.prover_key),
            std::make_shared<const spartan::FactoredMatrixVerifierKey>(
                sources.factored.verifier_key));

        Transcript resident_coin(
            "laminate/test/packing-external-spartan-parity/v1");
        const spartan::Proof resident = spartan::prove(
            keys.prover_key, fixture.complete_assignment, pcs,
            resident_coin);
        const Fq2 resident_next = resident_coin.challenge_fq2();

        CHECK(sources.factored.prover_key.tensors.size() == 1);
        TemporaryDirectory factored_state("spartan-factored-state");
        auto external_factored = sources.factored.prover_key;
        const auto externalized_tensor = pcs.externalize_prover_state(
            external_factored.tensors.front().opening_state,
            {.directory = factored_state.path(),
             .limits = {.max_total_bytes = 1ULL << 28U,
                        .min_free_bytes = 1}});
        external_factored.tensors.front().opening_state =
            externalized_tensor.prover_state;
        external_factored.tensors.front().opening_state_source =
            spartan::FactoredTensorProverKey::OpeningStateSource::External;
        const auto external_factored_key =
            std::make_shared<const spartan::FactoredMatrixProverKey>(
                std::move(external_factored));
        const spartan::ExternalSetup external_keys =
            spartan::setup_external_committed_factored(
                fixture.compiled.circuit.metadata(), pcs,
                external_factored_key,
                keys.verifier_key.factored_computation);
        const spartan::ExternalProverKey &external_key =
            external_keys.prover_key;
        const auto retained_pcs =
            std::make_shared<const spartan::BaseFoldPcs>(pcs);
        CHECK(external_key.setup_digest == keys.prover_key.setup_digest);
        CHECK(external_keys.verifier_key.circuit_metadata ==
              keys.verifier_key.circuit_metadata);
        CHECK(external_keys.verifier_key.setup_digest ==
              keys.verifier_key.setup_digest);
        CHECK(external_keys.verifier_key.pcs_scheme ==
              keys.verifier_key.pcs_scheme);
        CHECK(external_keys.verifier_key.options ==
              keys.verifier_key.options);
        CHECK(external_keys.verifier_key.factored_computation->commitment ==
              keys.verifier_key.factored_computation->commitment);

        {
            ExternalSpartanRoots nonempty_future_roots(
                "spartan-nonempty-future");
            CHECK(rejects_as<std::invalid_argument>([&] {
                (void)admit_proof_of_packing_spartan_external(
                    fixture.plan, fixture.compiled.layout, external_key,
                    sources.outer.artifact->directory(),
                    fixture.commitments, retained_pcs,
                    external_spartan_options(
                        nonempty_future_roots, 1ULL << 32U));
            }));
            CHECK(nonempty_future_roots.empty());
        }

        {
            ExternalSpartanRoots planner_roots("spartan-planner-caps");
            ProofOfPackingExternalSpartanOptions planner_options =
                external_spartan_options(
                    planner_roots, 1ULL << 32U);
            const spartan::R1csMetadata &metadata =
                fixture.compiled.circuit.metadata();

            const auto assignment_plan =
                plan_proof_of_packing_assignment_artifact(
                    fixture.plan, fixture.compiled.layout, metadata,
                    1ULL << 30U,
                    planner_options.assignment.block_elements);
            CHECK(rejects_as<std::invalid_argument>([&] {
                (void)plan_proof_of_packing_assignment_artifact(
                    fixture.plan, fixture.compiled.layout, metadata,
                    assignment_plan.minimum_working_bytes - 1U,
                    planner_options.assignment.block_elements);
            }));

            const auto product_plan =
                plan_proof_of_packing_matrix_product_artifact(
                    fixture.plan, metadata, 1ULL << 30U,
                    planner_options.matrix_products.block_elements);
            CHECK(rejects_as<std::invalid_argument>([&] {
                (void)plan_proof_of_packing_matrix_product_artifact(
                    fixture.plan, metadata,
                    product_plan.minimum_working_field_bytes - 1U,
                    planner_options.matrix_products.block_elements);
            }));

            const auto commit_plan = pcs.plan_external_commit_storage(
                metadata.assignment_half_size(), 1, true,
                1ULL << 30U,
                planner_options.witness_commitment.block_elements);
            CHECK(rejects_as<std::invalid_argument>([&] {
                (void)pcs.plan_external_commit_storage(
                    metadata.assignment_half_size(), 1, true,
                    commit_plan.minimum_working_field_bytes - 1U,
                    planner_options.witness_commitment.block_elements);
            }));

            const auto constraint_plan =
                spartan::plan_constraint_sumcheck_artifact(
                    metadata.padded_constraints(),
                    planner_options.constraint_sumcheck.source_rounds,
                    1ULL << 30U,
                    planner_options.constraint_sumcheck.block_elements);
            CHECK(rejects_as<std::invalid_argument>([&] {
                (void)spartan::plan_constraint_sumcheck_artifact(
                    metadata.padded_constraints(),
                    planner_options.constraint_sumcheck.source_rounds,
                    constraint_plan.minimum_working_field_bytes - 1U,
                    planner_options.constraint_sumcheck.block_elements);
            }));

            const auto wiring_plan =
                plan_proof_of_packing_wiring_matrix_artifact(
                    fixture.plan, fixture.compiled.layout, metadata,
                    *external_key.factored_computation, 1ULL << 30U,
                    planner_options.wiring_matrix.block_elements);
            CHECK(rejects_as<std::invalid_argument>([&] {
                (void)plan_proof_of_packing_wiring_matrix_artifact(
                    fixture.plan, fixture.compiled.layout, metadata,
                    *external_key.factored_computation,
                    wiring_plan.minimum_working_field_bytes - 1U,
                    planner_options.wiring_matrix.block_elements);
            }));

            const auto wiring_sumcheck_plan =
                spartan::plan_wiring_sumcheck_artifact(
                    metadata.assignment_half_size(),
                    planner_options.wiring_sumcheck.source_rounds,
                    1ULL << 30U,
                    planner_options.wiring_sumcheck.block_elements);
            CHECK(rejects_as<std::invalid_argument>([&] {
                (void)spartan::plan_wiring_sumcheck_artifact(
                    metadata.assignment_half_size(),
                    planner_options.wiring_sumcheck.source_rounds,
                    wiring_sumcheck_plan.minimum_working_field_bytes - 1U,
                    planner_options.wiring_sumcheck.block_elements);
            }));

            const spartan::PcsCommitment witness_commitment{
                .scheme = pcs.scheme_identifier(),
                .evaluation_count = metadata.assignment_half_size(),
                .width = 1,
                .log_rate = static_cast<std::uint32_t>(
                    pcs.parameters().log_rate),
                .query_count = static_cast<std::uint32_t>(
                    pcs.parameters().query_count),
            };
            const auto opening_plan = pcs.plan_external_opening_storage(
                witness_commitment,
                planner_options.witness_opening.fold_chunk_elements,
                1ULL << 30U);
            CHECK(rejects_as<std::runtime_error>([&] {
                (void)pcs.plan_external_opening_storage(
                    witness_commitment,
                    planner_options.witness_opening.fold_chunk_elements,
                    opening_plan.minimum_working_field_bytes - 1U);
            }));

            std::vector<spartan::BaseFoldExternalOpeningPreflight>
                factored_preflights;
            for (std::size_t tensor = 0;
                 tensor < external_key.factored_computation->tensors.size();
                 ++tensor) {
                auto opening = planner_options.factored_evaluation
                                   .tensor_openings[tensor];
                opening.max_live_storage_bytes = 1ULL << 32U;
                factored_preflights.push_back(
                    pcs.preflight_external_opening(
                        external_key.factored_computation->tensors[tensor]
                            .opening_state,
                        external_key.factored_computation->commitment
                            .tensors[tensor]
                            .columns,
                        opening));
            }
            planner_options.factored_evaluation.max_live_storage_bytes =
                1ULL << 32U;
            const auto factored_plan =
                spartan::plan_factored_matrix_evaluation_external_admitted(
                    *external_key.factored_computation,
                    planner_options.factored_evaluation,
                    factored_preflights);
            planner_options.factored_evaluation.max_live_storage_bytes =
                factored_plan.report.peak_live_storage_bytes - 1U;
            CHECK(rejects_as<std::runtime_error>([&] {
                (void)spartan::
                    plan_factored_matrix_evaluation_external_admitted(
                        *external_key.factored_computation,
                        planner_options.factored_evaluation,
                        factored_preflights);
            }));
            planner_options.factored_evaluation.max_live_storage_bytes =
                1ULL << 32U;
            planner_options.factored_evaluation.max_working_field_bytes =
                factored_plan.report.peak_working_field_bytes - 1U;
            CHECK(rejects_as<std::runtime_error>([&] {
                (void)spartan::
                    plan_factored_matrix_evaluation_external_admitted(
                        *external_key.factored_computation,
                        planner_options.factored_evaluation,
                        factored_preflights);
            }));
            CHECK(planner_roots.empty());
        }

        const auto reject_key_before_outputs =
            [&](spartan::ExternalProverKey bad_key,
                std::string_view label) {
                ExternalSpartanRoots bad_roots(label);
                CHECK(rejects_as<std::invalid_argument>([&] {
                    (void)admit_proof_of_packing_spartan_external(
                        fixture.plan, fixture.compiled.layout, bad_key,
                        sources.outer.artifact->directory(),
                        fixture.commitments, retained_pcs,
                        external_spartan_options(
                            bad_roots, 1ULL << 32U));
                }));
                CHECK(bad_roots.empty());
            };
        {
            spartan::ExternalProverKey bad = external_key;
            Digest digest = bad.circuit_metadata.digest();
            digest.front() ^= 1U;
            bad.circuit_metadata = spartan::R1csMetadata(
                bad.circuit_metadata.shape(),
                bad.circuit_metadata.padded_constraints(),
                bad.circuit_metadata.assignment_half_size(), digest);
            reject_key_before_outputs(
                std::move(bad), "spartan-bad-metadata");
        }
        {
            spartan::ExternalProverKey bad = external_key;
            bad.setup_digest.front() ^= 1U;
            reject_key_before_outputs(
                std::move(bad), "spartan-bad-setup-digest");
        }
        {
            spartan::ExternalProverKey bad = external_key;
            ++bad.pcs_scheme;
            reject_key_before_outputs(
                std::move(bad), "spartan-bad-pcs");
        }
        {
            spartan::ExternalProverKey bad = external_key;
            bad.options.matrix_evaluation =
                spartan::MatrixEvaluationMode::Direct;
            reject_key_before_outputs(
                std::move(bad), "spartan-bad-options");
        }
        {
            spartan::ExternalProverKey bad = external_key;
            auto factored =
                std::make_shared<spartan::FactoredMatrixProverKey>(
                    *bad.factored_computation);
            factored->commitment.structure_digest.front() ^= 1U;
            bad.factored_computation = std::move(factored);
            reject_key_before_outputs(
                std::move(bad), "spartan-bad-factored");
        }
        {
            ExternalSpartanRoots bad_roots("spartan-bad-pcs-options");
            const spartan::BaseFoldPcs wrong_pcs(
                {.log_rate = 2, .query_count = 1});
            const auto retained_wrong_pcs =
                std::make_shared<const spartan::BaseFoldPcs>(wrong_pcs);
            CHECK(rejects_as<std::invalid_argument>([&] {
                (void)admit_proof_of_packing_spartan_external(
                    fixture.plan, fixture.compiled.layout, external_key,
                    sources.outer.artifact->directory(),
                    fixture.commitments, retained_wrong_pcs,
                    external_spartan_options(
                        bad_roots, 1ULL << 32U));
            }));
            CHECK(bad_roots.empty());
        }

        ExternalSpartanRoots external_roots("spartan");
        ProofOfPackingExternalSpartanOptions external_options =
            external_spartan_options(external_roots, 1ULL << 32U);
        std::vector<spartan::BaseFoldExternalCommitProgress>
            witness_progress_events;
        external_options.witness_commitment.progress =
            [&](const spartan::BaseFoldExternalCommitProgress &event) {
                witness_progress_events.push_back(event);
            };

        Transcript external_coin(
            "laminate/test/packing-external-spartan-parity/v1");
        std::vector<RuntimeProgressEvent> progress_events;
        const ProofOfPackingExternalSpartanResult external =
            prove_proof_of_packing_spartan_external(
                fixture.plan, fixture.compiled.layout, external_key,
                *sources.outer.artifact, fixture.commitments, pcs,
                std::move(external_options), external_coin,
                [&](const RuntimeProgressEvent &event) {
                    progress_events.push_back(event);
                });
        CHECK(spartan::encode_proof(external.proof) ==
              spartan::encode_proof(resident));
        CHECK(external_coin.challenge_fq2() == resident_next);
        Transcript verifier_coin(
            "laminate/test/packing-external-spartan-parity/v1");
        CHECK(spartan::verify(keys.verifier_key,
                              fixture.complete_assignment.public_inputs,
                              external.proof, pcs, verifier_coin));
        CHECK(external_roots.empty());
        CHECK(external.storage.peak_live_storage_bytes ==
              std::max({
                  external.storage
                      .assignment_construction_peak_live_storage_bytes,
                  external.storage
                      .witness_commitment_peak_live_storage_bytes,
                  external.storage
                      .matrix_product_construction_peak_live_storage_bytes,
                  external.storage
                      .constraint_check_peak_live_storage_bytes,
                  external.storage
                      .wiring_construction_peak_live_storage_bytes,
                  external.storage.wiring_check_peak_live_storage_bytes,
                  external.storage
                      .factored_evaluation_peak_live_storage_bytes,
                  external.storage.witness_opening_peak_live_storage_bytes,
              }));
        CHECK(external.factored_evaluation.reserved_live_storage_bytes ==
              external.storage.outer_assignment_physical_bytes +
                  external.storage.witness_state_physical_bytes);
        CHECK(external.factored_evaluation.basefold_state_integrity_scans ==
              external_key.factored_computation->tensors.size());
        CHECK(external.factored_evaluation
                  .basefold_preflight_validation_bytes ==
              external.storage.factored_external_states_physical_bytes);
        CHECK(external.storage.factored_tensor_columns_validation_bytes ==
              external.storage.factored_tensor_columns_physical_bytes);
        CHECK(external.storage.factored_external_states_validation_bytes ==
              external.storage.factored_external_states_physical_bytes);
        CHECK(external.storage.preprocessing_validation_bytes ==
              external.storage.factored_tensor_columns_validation_bytes +
                  external.storage
                      .factored_external_states_validation_bytes);
        CHECK(external.matrix_products.source_artifact_validation_bytes ==
              0);
        CHECK(external.wiring_matrix.source_artifact_validation_bytes == 0);
        CHECK(std::all_of(
            external.factored_evaluation.tensor_openings.begin(),
            external.factored_evaluation.tensor_openings.end(),
            [](const spartan::BaseFoldExternalOpeningReport &opening) {
                return opening.artifact_validation_passes == 1;
            }));
        CHECK(external.witness_opening.artifact_validation_passes == 1);
        CHECK(external.witness_opening.state_artifact_validation_bytes ==
              external.storage.witness_state_physical_bytes);
        const auto progress_count =
            [&](RuntimeProgressStage stage,
                RuntimeProgressBoundary boundary) {
                return std::count_if(
                    progress_events.begin(), progress_events.end(),
                    [&](const RuntimeProgressEvent &event) {
                        return event.stage == stage &&
                               event.boundary == boundary;
                    });
            };
        for (const RuntimeProgressStage stage : {
                 RuntimeProgressStage::
                     TranscriptPackingSpartanAssignment,
                 RuntimeProgressStage::
                     TranscriptPackingSpartanWitnessCommitment,
                 RuntimeProgressStage::
                     TranscriptPackingSpartanMatrixProducts,
                 RuntimeProgressStage::
                     TranscriptPackingSpartanConstraintCheck,
                 RuntimeProgressStage::
                     TranscriptPackingSpartanWiringMatrix,
                 RuntimeProgressStage::
                     TranscriptPackingSpartanWiringCheck,
                 RuntimeProgressStage::
                     TranscriptPackingSpartanFactoredOpenings,
                 RuntimeProgressStage::
                     TranscriptPackingSpartanWitnessOpening,
             }) {
            CHECK(progress_count(stage, RuntimeProgressBoundary::Begin) == 1);
            CHECK(progress_count(stage, RuntimeProgressBoundary::End) == 1);
        }
        CHECK(progress_count(
                  RuntimeProgressStage::
                      TranscriptPackingSpartanRetirement,
                  RuntimeProgressBoundary::Begin) == 3);
        CHECK(progress_count(
                  RuntimeProgressStage::
                      TranscriptPackingSpartanRetirement,
                  RuntimeProgressBoundary::End) == 3);
        CHECK(!witness_progress_events.empty());
        const std::array witness_progress_stages{
            RuntimeProgressStage::
                TranscriptPackingSpartanWitnessCommitmentMobius,
            RuntimeProgressStage::
                TranscriptPackingSpartanWitnessCommitmentRateExpansion,
            RuntimeProgressStage::
                TranscriptPackingSpartanWitnessCommitmentNtt,
            RuntimeProgressStage::
                TranscriptPackingSpartanWitnessCommitmentMerkleTree,
            RuntimeProgressStage::
                TranscriptPackingSpartanWitnessCommitmentFinalPublication,
        };
        for (const RuntimeProgressStage stage : witness_progress_stages) {
            CHECK(progress_count(stage, RuntimeProgressBoundary::Update) >=
                  1);
        }
        const std::vector<RuntimeProgressEvent> witness_runtime_updates = [&] {
            std::vector<RuntimeProgressEvent> result;
            std::copy_if(
                progress_events.begin(), progress_events.end(),
                std::back_inserter(result),
                [&](const RuntimeProgressEvent &event) {
                    return event.boundary == RuntimeProgressBoundary::Update &&
                           std::find(witness_progress_stages.begin(),
                                     witness_progress_stages.end(),
                                     event.stage) !=
                               witness_progress_stages.end();
                });
            return result;
        }();
        CHECK(witness_runtime_updates.size() ==
              witness_progress_events.size());
        std::set<RuntimeProgressSubpass> witness_subpasses;
        for (const RuntimeProgressEvent &event : witness_runtime_updates) {
            CHECK(event.total_steps != 0);
            CHECK(event.completed_steps <= event.total_steps);
            CHECK(event.total_work_units != 0);
            CHECK(event.completed_work_units <= event.total_work_units);
            CHECK(event.subpass != RuntimeProgressSubpass::Unspecified);
            CHECK(event.progress_work_unit !=
                  RuntimeProgressWorkUnit::Unspecified);
            CHECK(event.phase_total_steps != 0);
            CHECK(event.phase_completed_steps <= event.phase_total_steps);
            CHECK(event.total_read_bytes != 0 ||
                  event.total_write_bytes != 0);
            CHECK(event.completed_read_bytes <= event.total_read_bytes);
            CHECK(event.completed_write_bytes <= event.total_write_bytes);
            CHECK(event.phase_completed_read_bytes <=
                  event.phase_total_read_bytes);
            CHECK(event.phase_completed_write_bytes <=
                  event.phase_total_write_bytes);
            CHECK(event.completed_butterflies <= event.total_butterflies);
            CHECK(event.phase_completed_butterflies <=
                  event.phase_total_butterflies);
            if (event.subpass == RuntimeProgressSubpass::LocalNtt &&
                event.total_butterflies != 0) {
                CHECK(event.progress_work_unit ==
                      RuntimeProgressWorkUnit::NttButterflies);
                CHECK(event.completed_work_units ==
                      event.completed_butterflies);
                CHECK(event.total_work_units == event.total_butterflies);
            }
            witness_subpasses.insert(event.subpass);
            CHECK(event.column_index == 0);
            CHECK(event.column_count == 1);
        }
        CHECK(witness_subpasses.contains(
            RuntimeProgressSubpass::SourceLocalMobius));
        CHECK(witness_subpasses.contains(RuntimeProgressSubpass::Transpose));
        CHECK(witness_subpasses.contains(
            RuntimeProgressSubpass::TwiddleTranspose));
        CHECK(witness_subpasses.contains(RuntimeProgressSubpass::LocalNtt));
        CHECK(witness_subpasses.contains(RuntimeProgressSubpass::MerkleTree));
        CHECK(witness_subpasses.contains(
            RuntimeProgressSubpass::ArtifactPublication));
        CHECK(witness_runtime_updates.back().completed_steps ==
              witness_runtime_updates.back().total_steps);
        CHECK(witness_runtime_updates.back().completed_work_units ==
              witness_runtime_updates.back().total_work_units);

        const auto reject_admission_before_challenges =
            [&](std::string_view label, auto mutate) {
                ExternalSpartanRoots roots(label);
                TemporaryDirectory future_outer(label);
                ProofOfPackingExternalSpartanOptions options =
                    external_spartan_options(roots, 1ULL << 32U);
                mutate(options);
                CHECK(rejects_as([&] {
                    (void)admit_proof_of_packing_spartan_external(
                        fixture.plan, fixture.compiled.layout,
                        external_key, future_outer.path(),
                        fixture.commitments, retained_pcs,
                        std::move(options));
                }));
                CHECK(roots.empty());
                CHECK(std::filesystem::is_empty(future_outer.path()));
            };
        reject_admission_before_challenges(
            "spartan-assignment-cap", [&](auto &options) {
                options.assignment.storage_limits.max_total_bytes =
                    external.assignment.physical_bytes - 1U;
            });
        reject_admission_before_challenges(
            "spartan-product-cap", [&](auto &options) {
                options.matrix_products.storage_limits.max_total_bytes =
                    external.matrix_products.physical_bytes - 1U;
            });
        reject_admission_before_challenges(
            "spartan-witness-final-cap", [&](auto &options) {
                options.witness_commitment.max_final_bytes =
                    external.witness_commitment.final_physical_bytes - 1U;
            });
        reject_admission_before_challenges(
            "spartan-witness-scratch-cap", [&](auto &options) {
                options.witness_commitment.max_scratch_bytes =
                    external.witness_commitment
                            .scratch_peak_physical_bytes -
                    1U;
            });
        reject_admission_before_challenges(
            "spartan-constraint-cap", [&](auto &options) {
                options.constraint_sumcheck.max_total_scratch_bytes =
                    external.constraint_sumcheck
                            .scratch_peak_physical_bytes -
                    1U;
            });
        reject_admission_before_challenges(
            "spartan-wiring-matrix-cap", [&](auto &options) {
                options.wiring_matrix.storage_limits.max_total_bytes =
                    external.wiring_matrix.physical_bytes - 1U;
            });
        reject_admission_before_challenges(
            "spartan-wiring-check-cap", [&](auto &options) {
                options.wiring_sumcheck.max_total_scratch_bytes =
                    external.wiring_sumcheck
                            .scratch_peak_physical_bytes -
                    1U;
            });
        reject_admission_before_challenges(
            "spartan-factored-opening-cap", [&](auto &options) {
                options.factored_evaluation.tensor_openings.front()
                    .max_total_scratch_bytes =
                    external.factored_evaluation.tensor_openings.front()
                            .scratch_peak_physical_bytes -
                    1U;
            });
        reject_admission_before_challenges(
            "spartan-witness-opening-cap", [&](auto &options) {
                options.witness_opening.max_total_scratch_bytes =
                    external.witness_opening
                            .scratch_peak_physical_bytes -
                    1U;
            });

        using AdmissionMutator = std::function<void(
            ProofOfPackingExternalSpartanOptions &)>;
        const std::array<
            std::pair<std::string_view, AdmissionMutator>, 9>
            working_cap_cases{{
                {"spartan-assignment-working-cap", [](auto &options) {
                     options.assignment.max_working_bytes = 1;
                 }},
                {"spartan-product-working-cap", [](auto &options) {
                     options.matrix_products.max_working_field_bytes = 1;
                 }},
                {"spartan-witness-commit-working-cap", [](auto &options) {
                     options.witness_commitment.max_working_field_bytes = 1;
                 }},
                {"spartan-constraint-working-cap", [](auto &options) {
                     options.constraint_sumcheck.max_working_field_bytes = 1;
                 }},
                {"spartan-wiring-build-working-cap", [](auto &options) {
                     options.wiring_matrix.max_working_field_bytes = 1;
                 }},
                {"spartan-wiring-check-working-cap", [](auto &options) {
                     options.wiring_sumcheck.max_working_field_bytes = 1;
                 }},
                {"spartan-factored-working-cap", [](auto &options) {
                     options.factored_evaluation.max_working_field_bytes = 1;
                 }},
                {"spartan-factored-opening-working-cap", [](auto &options) {
                     options.factored_evaluation.tensor_openings.front()
                         .max_working_field_bytes = 1;
                 }},
                {"spartan-witness-opening-working-cap", [](auto &options) {
                     options.witness_opening.max_working_field_bytes = 1;
                 }},
            }};
        for (const auto &[label, mutate] : working_cap_cases) {
            reject_admission_before_challenges(label, mutate);
        }

        reject_admission_before_challenges(
            "spartan-free-space-cap", [](auto &options) {
                options.assignment.storage_limits.min_free_bytes =
                    std::numeric_limits<std::uint64_t>::max();
            });

        ExternalSpartanRoots exact_roots("spartan-exact-envelope");
        TemporaryDirectory exact_outer("spartan-admitted-outer");
        Transcript exact_coin(
            "laminate/test/packing-external-spartan-parity/v1");
        ProofOfPackingExternalSpartanAdmission exact_admission =
            admit_proof_of_packing_spartan_external(
                fixture.plan, fixture.compiled.layout, external_key,
                exact_outer.path(), fixture.commitments, retained_pcs,
                external_spartan_options(
                    exact_roots,
                    external.storage.peak_live_storage_bytes));
        CHECK(std::filesystem::is_empty(exact_outer.path()));
        CHECK(exact_admission.storage_report().peak_live_storage_bytes ==
              external.storage.peak_live_storage_bytes);
        CHECK(exact_admission.storage_report()
                  .preprocessing_validation_bytes ==
              external.storage.preprocessing_validation_bytes);
        const OuterRelationAssignmentArtifact exact_outer_artifact =
            write_outer_relation_assignment_artifact(
                fixture.outer_view(), outer_options(exact_outer.path()));
        const ProofOfPackingExternalSpartanResult exact =
            prove_proof_of_packing_spartan_external_admitted(
                std::move(exact_admission),
                *exact_outer_artifact.artifact, exact_coin);
        CHECK(spartan::encode_proof(exact.proof) ==
              spartan::encode_proof(resident));
        CHECK(exact.storage.admitted_live_storage_bytes ==
              exact.storage.peak_live_storage_bytes);
        CHECK(exact_roots.empty());
        CHECK(!std::filesystem::is_empty(exact_outer.path()));

        ExternalSpartanRoots short_roots("spartan-short-envelope");
        Transcript short_coin(
            "laminate/test/packing-external-spartan-parity/v1");
        CHECK(rejects_as<std::invalid_argument>([&] {
            (void)prove_proof_of_packing_spartan_external(
                fixture.plan, fixture.compiled.layout, external_key,
                *sources.outer.artifact, fixture.commitments, pcs,
                external_spartan_options(
                    short_roots,
                    external.storage.peak_live_storage_bytes - 1U),
                short_coin);
        }));
        Transcript fresh_short_coin(
            "laminate/test/packing-external-spartan-parity/v1");
        CHECK(short_coin.challenge_fq2() ==
              fresh_short_coin.challenge_fq2());
        CHECK(short_roots.empty());

        ExternalSpartanRoots failure_roots("spartan-failure-cleanup");
        ThrowingObserveCoin failure_coin(
            "laminate/test/packing-external-spartan-parity/v1",
            "laminate/spartan/factored/commitment/v1");
        CHECK(rejects_as<std::runtime_error>([&] {
            (void)prove_proof_of_packing_spartan_external(
                fixture.plan, fixture.compiled.layout, external_key,
                *sources.outer.artifact, fixture.commitments, pcs,
                external_spartan_options(failure_roots, 1ULL << 32U),
                failure_coin);
        }));
        CHECK(failure_roots.empty());
    });

    runner.run("current Folded compact product payload is exact", [] {
        const OuterRelationPlan target = make_outer_relation_plan(
            OuterRelationShape{
                .native_modulus = kOuterFieldOrder,
                .ring_degree = 1U << 14U,
                .aligned_ciphertexts = 517,
                .repetitions = kPackingWellFormednessRepetitions,
                .logical_packed_outputs = 1,
                .packing_digit_count = 4,
                .ciphertext_components = 2,
                .public_input_capacity_bits = 59,
            });
        const ProofOfPackingR1csLedger ledger =
            proof_of_packing_r1cs_ledger(target);
        CHECK(ledger.total_constraints == 3'167'501'480ULL);
        CHECK(ledger.matrix_rows == 3'167'518'720ULL);
        CHECK(std::bit_ceil(ledger.matrix_rows) == 4'294'967'296ULL);
        CHECK(3ULL * ledger.matrix_rows * sizeof(Fq) ==
              76'020'449'280ULL);
        CHECK(target.variables.witness.well_formedness_products.count ==
              2'032'926'720ULL);
        CHECK(target.variables.witness.well_formedness_products.count *
                  sizeof(Fq) ==
              16'263'413'760ULL);
    });

    return runner.summary();
}
