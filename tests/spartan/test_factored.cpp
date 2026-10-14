#include "test_helpers.hpp"

#include "laminate/spartan/basefold_pcs.hpp"
#include "laminate/spartan/factored.hpp"
#include "laminate/transcript/transcript.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace {

using laminate::Digest;
using laminate::Fq;
using laminate::Fq2;
using laminate::Transcript;
using laminate::spartan::BaseFoldPcs;
using laminate::spartan::BaseFoldExternalCommitOptions;
using laminate::spartan::BaseFoldExternalOpeningOptions;
using laminate::spartan::FactoredMatrixCommitment;
using laminate::spartan::FactoredMatrixArtifactOptions;
using laminate::spartan::FactoredMatrixEvaluationProof;
using laminate::spartan::FactoredMatrixExternalPreprocessingOptions;
using laminate::spartan::FactoredMatrixExternalProvingOptions;
using laminate::spartan::FactoredMatrixSetup;
using laminate::spartan::FactoredMatrixStagingOwnership;
using laminate::spartan::FactoredMatrixStructure;
using laminate::spartan::FactoredMatrixVerifierKey;
using laminate::spartan::FactoredTensorShape;
using laminate::spartan::FactoredTensorColumnSource;

constexpr const char *kTranscriptDomain =
    "laminate/test/factored-matrix/v1";

class TemporaryDirectory {
  public:
    TemporaryDirectory() {
        const auto stamp = std::chrono::steady_clock::now()
                               .time_since_epoch()
                               .count();
        for (std::size_t attempt = 0; attempt < 100; ++attempt) {
            path_ = std::filesystem::temp_directory_path() /
                    ("laminate-factored-artifact-" +
                     std::to_string(stamp) + "-" +
                     std::to_string(attempt));
            if (std::filesystem::create_directory(path_)) {
                std::filesystem::permissions(
                    path_, std::filesystem::perms::owner_all,
                    std::filesystem::perm_options::replace);
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

  private:
    std::filesystem::path path_;
};

bool throws_exception(const auto &body) {
    try {
        body();
    } catch (const std::exception &) {
        return true;
    }
    return false;
}

FactoredMatrixArtifactOptions artifact_options(
    const std::filesystem::path &directory) {
    return FactoredMatrixArtifactOptions{
        .directory = directory,
        .limits = {
            .max_total_bytes = 1ULL << 20U,
            .min_free_bytes = 1,
        },
    };
}

std::uint64_t recursive_file_bytes(
    const std::filesystem::path &directory) {
    std::uint64_t bytes = 0;
    for (const auto &entry :
         std::filesystem::recursive_directory_iterator(directory)) {
        if (entry.is_regular_file()) {
            bytes += entry.file_size();
        }
    }
    return bytes;
}

class ToyFactoredStructure final : public FactoredMatrixStructure {
  public:
    explicit ToyFactoredStructure(std::uint8_t identity = 7)
        : identity_(identity) {}

    Digest circuit_digest() const override {
        Digest result{};
        result[0] = 0x31;
        result[9] = 0x72;
        return result;
    }

    Digest structure_digest() const override {
        Digest result{};
        result[0] = identity_;
        result[17] = 0xa5;
        return result;
    }

    std::uint64_t row_variables() const override { return 2; }
    std::uint64_t column_variables() const override { return 3; }
    std::size_t tensor_count() const override { return 3; }

    FactoredTensorShape
    tensor_shape(std::size_t tensor_index) const override {
        switch (tensor_index) {
        case 0:
            return {.evaluation_count = 8, .column_count = 2};
        case 1:
            return {.evaluation_count = 4, .column_count = 3};
        case 2:
            return {.evaluation_count = 1, .column_count = 1};
        default:
            throw std::out_of_range("toy tensor index");
        }
    }

    laminate::spartan::FactoredTensorOperandWorkingSet
    tensor_operand_working_set(
        std::size_t tensor_index) const override {
        const FactoredTensorShape shape = tensor_shape(tensor_index);
        const std::uint64_t rounds =
            std::bit_width(shape.evaluation_count) - 1U;
        const std::uint64_t factor_fields = 2U * rounds;
        return {
            .materialization_peak_field_bytes =
                (shape.evaluation_count + factor_fields) * sizeof(Fq2),
            .compact_evaluation_peak_field_bytes =
                factor_fields * sizeof(Fq2),
        };
    }

    std::array<Fq2, 3> regular_matrix_evaluations(
        std::span<const Fq2> row_point,
        std::span<const Fq2> column_point) const override {
        return {
            row_point[0] + column_point[0],
            row_point[1] * column_point[1],
            column_point[2] + Fq(3),
        };
    }

    std::vector<Fq2> tensor_column_weights(
        std::size_t tensor_index, std::span<const Fq2> row_point,
        std::span<const Fq2> column_point,
        const Fq2 &gamma) const override {
        switch (tensor_index) {
        case 0:
            return {row_point[0] + gamma, column_point[2]};
        case 1:
            return {gamma * gamma, row_point[1],
                    column_point[1] + Fq(1)};
        case 2:
            return {column_point[0]};
        default:
            throw std::out_of_range("toy tensor index");
        }
    }

    std::vector<Fq2> materialize_tensor_operand(
        std::size_t tensor_index, std::span<const Fq2> row_point,
        std::span<const Fq2> column_point,
        const Fq2 &gamma) const override {
        ++materialization_count;
        const FactoredTensorShape shape = tensor_shape(tensor_index);
        const auto factors = operand_factors(
            tensor_index, row_point, column_point, gamma);
        std::vector<Fq2> result(shape.evaluation_count, Fq2::zero());
        for (std::size_t index = 0; index < result.size(); ++index) {
            Fq2 value = operand_scale(
                tensor_index, row_point, column_point, gamma);
            for (std::size_t variable = 0; variable < factors.size();
                 ++variable) {
                const bool bit =
                    ((index >> (factors.size() - 1U - variable)) & 1U) != 0;
                value *= factors[variable][bit ? 1U : 0U];
            }
            result[index] = value;
        }
        return result;
    }

    Fq2 evaluate_tensor_operand(
        std::size_t tensor_index, std::span<const Fq2> row_point,
        std::span<const Fq2> column_point, const Fq2 &gamma,
        std::span<const Fq2> tensor_point) const override {
        ++compact_evaluation_count;
        const auto factors = operand_factors(
            tensor_index, row_point, column_point, gamma);
        if (tensor_point.size() != factors.size()) {
            throw std::invalid_argument("toy tensor point length");
        }
        Fq2 result = operand_scale(
            tensor_index, row_point, column_point, gamma);
        for (std::size_t variable = 0; variable < factors.size();
             ++variable) {
            result *= (Fq2::one() - tensor_point[variable]) *
                          factors[variable][0] +
                      tensor_point[variable] * factors[variable][1];
        }
        return result;
    }

    mutable std::size_t materialization_count = 0;
    mutable std::size_t compact_evaluation_count = 0;

  private:
    using Factor = std::array<Fq2, 2>;

    static std::vector<Factor> operand_factors(
        std::size_t tensor_index, std::span<const Fq2> row_point,
        std::span<const Fq2> column_point, const Fq2 &gamma) {
        switch (tensor_index) {
        case 0:
            // Explicit zero factors exercise projective tensor weights;
            // compact evaluation must not divide by either endpoint.
            return {
                Factor{row_point[0], column_point[0]},
                Factor{Fq2::zero(), gamma + row_point[1]},
                Factor{Fq2::one() + column_point[1], column_point[2]},
            };
        case 1:
            return {
                Factor{gamma, row_point[1]},
                Factor{column_point[0], Fq2::zero()},
            };
        case 2:
            return {};
        default:
            throw std::out_of_range("toy tensor index");
        }
    }

    static Fq2 operand_scale(
        std::size_t tensor_index, std::span<const Fq2> row_point,
        std::span<const Fq2> column_point, const Fq2 &gamma) {
        switch (tensor_index) {
        case 0:
            return column_point[2];
        case 1:
            return Fq2::one();
        case 2:
            return gamma + row_point[0];
        default:
            throw std::out_of_range("toy tensor index");
        }
    }

    std::uint8_t identity_;
};

struct Fixture {
    std::shared_ptr<ToyFactoredStructure> structure =
        std::make_shared<ToyFactoredStructure>();
    std::vector<std::vector<std::vector<Fq>>> tensors;
    std::vector<Fq2> row_point{
        Fq2({Fq(2), Fq(3)}),
        Fq2({Fq(5), Fq(7)}),
    };
    std::vector<Fq2> column_point{
        Fq2({Fq(11), Fq(13)}),
        Fq2({Fq(17), Fq(19)}),
        Fq2({Fq(23), Fq(29)}),
    };
    Fq2 gamma{Fq2({Fq(31), Fq(37)})};

    Fixture() {
        tensors.resize(structure->tensor_count());
        for (std::size_t tensor_index = 0;
             tensor_index < tensors.size(); ++tensor_index) {
            const FactoredTensorShape shape =
                structure->tensor_shape(tensor_index);
            tensors[tensor_index].resize(shape.column_count);
            for (std::size_t column = 0;
                 column < tensors[tensor_index].size(); ++column) {
                auto &values = tensors[tensor_index][column];
                values.resize(shape.evaluation_count);
                for (std::size_t index = 0; index < values.size(); ++index) {
                    values[index] = Fq(
                        7U + 13U * tensor_index + 11U * column +
                        5U * index + 3U * column * index);
                }
            }
        }
    }
};

std::shared_ptr<const laminate::storage::NativeFieldArtifact>
write_staging_artifact(const Fixture &fixture,
                       const std::filesystem::path &directory) {
    laminate::storage::NativeFieldArtifactWriter writer(
        directory,
        {.max_total_bytes = 1ULL << 20U, .min_free_bytes = 1},
        laminate::spartan::factored_matrix_staging_artifact_identity(
            *fixture.structure));
    for (std::size_t tensor_index = 0;
         tensor_index < fixture.tensors.size(); ++tensor_index) {
        for (std::size_t column = 0;
             column < fixture.tensors[tensor_index].size(); ++column) {
            const auto &values = fixture.tensors[tensor_index][column];
            writer.begin_array(
                laminate::spartan::
                    factored_matrix_tensor_column_array_name(tensor_index,
                                                              column),
                laminate::storage::NativeFieldElementKind::Fq,
                values.size());
            writer.append(values);
            writer.finish_array();
        }
    }
    (void)writer.finish();
    return laminate::spartan::open_factored_matrix_staging_artifact(
        directory, *fixture.structure);
}

struct ExternalPreprocessingDirectories {
    TemporaryDirectory canonical;
    std::array<TemporaryDirectory, 3> states;
    std::array<TemporaryDirectory, 3> scratches;

    bool empty() const {
        if (!std::filesystem::is_empty(canonical.path())) {
            return false;
        }
        for (std::size_t tensor = 0; tensor < states.size(); ++tensor) {
            if (!std::filesystem::is_empty(states[tensor].path()) ||
                !std::filesystem::is_empty(scratches[tensor].path())) {
                return false;
            }
        }
        return true;
    }
};

BaseFoldExternalCommitOptions external_commit_options(
    const std::filesystem::path &destination,
    const std::filesystem::path &scratch) {
    return {
        .destination_directory = destination,
        .scratch_directory = scratch,
        .max_final_bytes = 1ULL << 20U,
        .max_scratch_bytes = 1ULL << 20U,
        .min_free_bytes = 1,
        .max_working_field_bytes = 1ULL << 16U,
        .block_elements = 3,
    };
}

FactoredMatrixExternalPreprocessingOptions external_options(
    const ExternalPreprocessingDirectories &directories,
    FactoredMatrixStagingOwnership ownership =
        FactoredMatrixStagingOwnership::Retain,
    std::filesystem::path quarantine_directory = {}) {
    FactoredMatrixExternalPreprocessingOptions options{
        .tensor_columns_artifact = artifact_options(
            directories.canonical.path()),
        .staging_ownership = ownership,
        .staging_quarantine_directory =
            std::move(quarantine_directory),
        .max_live_physical_bytes = 1ULL << 24U,
        .max_copy_working_field_bytes = 6U * sizeof(Fq),
        .copy_block_elements = 3,
    };
    for (std::size_t tensor = 0; tensor < directories.states.size();
         ++tensor) {
        options.tensor_commitments.push_back(external_commit_options(
            directories.states[tensor].path(),
            directories.scratches[tensor].path()));
    }
    return options;
}

BaseFoldExternalOpeningOptions external_opening_options(
    const std::filesystem::path &scratch) {
    return {
        .scratch_directory = scratch,
        .max_live_storage_bytes = 1ULL << 25U,
        .max_total_scratch_bytes = 1ULL << 20U,
        .min_free_bytes = 1,
        .max_working_field_bytes = 1ULL << 16U,
    };
}

Fq2 evaluate_msb(std::span<const Fq> evaluations,
                 std::span<const Fq2> point) {
    Fq2 result = Fq2::zero();
    for (std::size_t index = 0; index < evaluations.size(); ++index) {
        Fq2 weight = Fq2::one();
        for (std::size_t variable = 0; variable < point.size(); ++variable) {
            const bool bit =
                ((index >> (point.size() - 1U - variable)) & 1U) != 0;
            weight *= bit ? point[variable]
                          : Fq2::one() - point[variable];
        }
        result += weight * evaluations[index];
    }
    return result;
}

Fq2 evaluate_linear_combination_msb(
    const std::vector<std::vector<Fq>> &columns,
    std::span<const Fq2> weights, std::span<const Fq2> point) {
    Fq2 result = Fq2::zero();
    for (std::size_t column = 0; column < columns.size(); ++column) {
        result += weights[column] * evaluate_msb(columns[column], point);
    }
    return result;
}

void bind_pcs_commitment(
    const laminate::spartan::PcsCommitment &commitment,
    Transcript &transcript) {
    transcript.observe(
        "test/factored-external/basefold-commitment",
        laminate::spartan::encode_pcs_commitment(commitment));
}

Fq2 component_claim(
    const Fixture &fixture, std::size_t tensor_index) {
    const std::vector<Fq2> weights =
        fixture.structure->tensor_column_weights(
            tensor_index, fixture.row_point, fixture.column_point,
            fixture.gamma);
    const std::vector<Fq2> operand =
        fixture.structure->materialize_tensor_operand(
            tensor_index, fixture.row_point, fixture.column_point,
            fixture.gamma);
    Fq2 result = Fq2::zero();
    for (std::size_t index = 0; index < operand.size(); ++index) {
        Fq2 tensor_value = Fq2::zero();
        for (std::size_t column = 0; column < weights.size(); ++column) {
            tensor_value += weights[column] *
                            fixture.tensors[tensor_index][column][index];
        }
        result += tensor_value * operand[index];
    }
    return result;
}

Fq2 direct_claim(const Fixture &fixture) {
    const auto regular = fixture.structure->regular_matrix_evaluations(
        fixture.row_point, fixture.column_point);
    Fq2 result = regular[0] + fixture.gamma * regular[1] +
                 fixture.gamma * fixture.gamma * regular[2];
    for (std::size_t tensor_index = 0;
         tensor_index < fixture.tensors.size(); ++tensor_index) {
        result += component_claim(fixture, tensor_index);
    }
    return result;
}

FactoredMatrixEvaluationProof prove(
    const Fixture &fixture, const FactoredMatrixSetup &setup,
    const BaseFoldPcs &pcs, const Fq2 &claim) {
    Transcript transcript(kTranscriptDomain);
    return laminate::spartan::prove_factored_matrix_evaluation(
        setup.prover_key, fixture.row_point, fixture.column_point,
        fixture.gamma, claim, pcs, transcript);
}

bool accepts(const Fixture &fixture,
             const FactoredMatrixVerifierKey &verifier_key,
             const FactoredMatrixEvaluationProof &proof,
             const BaseFoldPcs &pcs, const Fq2 &claim) {
    Transcript transcript(kTranscriptDomain);
    return laminate::spartan::verify_factored_matrix_evaluation(
        verifier_key, fixture.row_point, fixture.column_point,
        fixture.gamma, claim, proof, pcs, transcript);
}

void test_factored_evaluation_and_transcript_sync() {
    Fixture fixture;
    const Fq2 claim = direct_claim(fixture);
    BaseFoldPcs pcs;
    CHECK(pcs.parameters().log_rate == 3U);
    CHECK(pcs.parameters().query_count ==
          laminate::kTranscriptPackingBaseFoldQueries);
    const FactoredMatrixSetup setup =
        laminate::spartan::preprocess_factored_matrix(
            fixture.structure, fixture.tensors, pcs);
    CHECK(laminate::spartan::valid_factored_matrix_commitment(
        setup.verifier_key.commitment, *fixture.structure, pcs));
    CHECK(setup.verifier_key.commitment.tensors.size() == 3);
    for (const auto &tensor : setup.verifier_key.commitment.tensors) {
        CHECK(tensor.columns.log_rate == 3U);
        CHECK(tensor.columns.query_count == pcs.parameters().query_count);
    }
    CHECK(setup.verifier_key.commitment.tensors[0].shape ==
          (FactoredTensorShape{.evaluation_count = 8,
                               .column_count = 2}));

    Transcript prover(kTranscriptDomain);
    const FactoredMatrixEvaluationProof proof =
        laminate::spartan::prove_factored_matrix_evaluation(
            setup.prover_key, fixture.row_point, fixture.column_point,
            fixture.gamma, claim, pcs, prover);
    CHECK(proof.tensors.size() == 3);
    CHECK(proof.tensors[0].rounds.size() == 3);
    CHECK(proof.tensors[1].rounds.size() == 2);
    CHECK(proof.tensors[2].rounds.empty());
    CHECK(!proof.tensors[0].opening.bytes.empty());

    const std::size_t materializations_before_verify =
        fixture.structure->materialization_count;
    Transcript verifier(kTranscriptDomain);
    CHECK(laminate::spartan::verify_factored_matrix_evaluation(
        setup.verifier_key, fixture.row_point, fixture.column_point,
        fixture.gamma, claim, proof, pcs, verifier));
    CHECK(fixture.structure->materialization_count ==
          materializations_before_verify);
    CHECK(prover.challenge_fq2() == verifier.challenge_fq2());

    const auto encoded =
        laminate::spartan::encode_factored_matrix_evaluation_proof(proof);
    std::vector<std::uint8_t> appended{0x46U, 0x41U, 0x43U};
    const std::size_t prefix = appended.size();
    laminate::spartan::append_factored_matrix_evaluation_proof(
        proof, appended);
    CHECK(std::equal(encoded.begin(), encoded.end(),
                     appended.begin() + static_cast<std::ptrdiff_t>(prefix)));
    CHECK(appended.size() - prefix == encoded.size());
    CHECK(encoded.size() ==
          laminate::spartan::factored_matrix_evaluation_proof_size_bytes(
              proof));
    CHECK(encoded.size() <=
          laminate::spartan::factored_matrix_evaluation_proof_max_size_bytes(
              setup.verifier_key.commitment,
              pcs.parameters()));
}

void test_mutations_and_statement_changes_reject() {
    Fixture fixture;
    const Fq2 claim = direct_claim(fixture);
    BaseFoldPcs pcs;
    const FactoredMatrixSetup setup =
        laminate::spartan::preprocess_factored_matrix(
            fixture.structure, fixture.tensors, pcs);
    const FactoredMatrixEvaluationProof proof =
        prove(fixture, setup, pcs, claim);

    FactoredMatrixEvaluationProof shifted_claims = proof;
    shifted_claims.tensors[0].claim += Fq2::one();
    shifted_claims.tensors[1].claim -= Fq2::one();
    CHECK(!accepts(fixture, setup.verifier_key, shifted_claims, pcs,
                   claim));

    FactoredMatrixEvaluationProof bad_round = proof;
    bad_round.tensors[0].rounds[1].evaluations[1] += Fq2::one();
    CHECK(!accepts(fixture, setup.verifier_key, bad_round, pcs, claim));

    FactoredMatrixEvaluationProof missing_round = proof;
    missing_round.tensors[1].rounds.pop_back();
    CHECK(!accepts(fixture, setup.verifier_key, missing_round, pcs, claim));

    FactoredMatrixEvaluationProof bad_terminal = proof;
    bad_terminal.tensors[2].terminal_tensor_value += Fq2::one();
    CHECK(!accepts(fixture, setup.verifier_key, bad_terminal, pcs, claim));

    FactoredMatrixEvaluationProof bad_opening = proof;
    auto &opening = bad_opening.tensors[0].opening.bytes;
    opening[opening.size() / 2U] ^= 1U;
    CHECK(!accepts(fixture, setup.verifier_key, bad_opening, pcs, claim));

    FactoredMatrixEvaluationProof missing_tensor = proof;
    missing_tensor.tensors.pop_back();
    CHECK(!accepts(fixture, setup.verifier_key, missing_tensor, pcs, claim));
    CHECK(!accepts(fixture, setup.verifier_key, proof, pcs,
                   claim + Fq2::one()));

    FactoredMatrixVerifierKey bad_root = setup.verifier_key;
    bad_root.commitment.tensors[1].columns.root[0] ^= 1U;
    CHECK(!accepts(fixture, bad_root, proof, pcs, claim));

    FactoredMatrixVerifierKey bad_rate = setup.verifier_key;
    --bad_rate.commitment.tensors[0].columns.log_rate;
    CHECK(!accepts(fixture, bad_rate, proof, pcs, claim));
    FactoredMatrixVerifierKey bad_queries = setup.verifier_key;
    --bad_queries.commitment.tensors[0].columns.query_count;
    CHECK(!accepts(fixture, bad_queries, proof, pcs, claim));

    FactoredMatrixVerifierKey wrong_structure = setup.verifier_key;
    wrong_structure.structure =
        std::make_shared<ToyFactoredStructure>(9);
    CHECK(!accepts(fixture, wrong_structure, proof, pcs, claim));

    Fixture changed_point = fixture;
    changed_point.row_point[0] += Fq2::one();
    CHECK(!accepts(changed_point, setup.verifier_key, proof, pcs, claim));

    Fixture changed_gamma = fixture;
    changed_gamma.gamma += Fq2::one();
    CHECK(!accepts(changed_gamma, setup.verifier_key, proof, pcs, claim));

    bool wrong_claim_rejected = false;
    try {
        (void)prove(fixture, setup, pcs, claim + Fq2::one());
    } catch (const std::invalid_argument &) {
        wrong_claim_rejected = true;
    }
    CHECK(wrong_claim_rejected);
}

void test_setup_validation_and_commitment_encoding() {
    Fixture fixture;
    BaseFoldPcs pcs;
    const FactoredMatrixSetup setup =
        laminate::spartan::preprocess_factored_matrix(
            fixture.structure, fixture.tensors, pcs);
    const std::vector<std::uint8_t> encoded =
        laminate::spartan::encode_factored_matrix_commitment(
            setup.verifier_key.commitment);

    FactoredMatrixCommitment changed = setup.verifier_key.commitment;
    changed.structure_digest[2] ^= 1U;
    CHECK(encoded != laminate::spartan::encode_factored_matrix_commitment(
                         changed));
    CHECK(!laminate::spartan::valid_factored_matrix_commitment(
        changed, *fixture.structure, pcs));
    changed = setup.verifier_key.commitment;
    ++changed.tensors[0].shape.column_count;
    CHECK(encoded != laminate::spartan::encode_factored_matrix_commitment(
                         changed));
    CHECK(!laminate::spartan::valid_factored_matrix_commitment(
        changed, *fixture.structure, pcs));
    changed = setup.verifier_key.commitment;
    changed.tensors[0].columns.root[4] ^= 1U;
    CHECK(encoded != laminate::spartan::encode_factored_matrix_commitment(
                         changed));

    BaseFoldPcs wrong_pcs({.log_rate = 2, .query_count = 8});
    CHECK(!laminate::spartan::valid_factored_matrix_commitment(
        setup.verifier_key.commitment, *fixture.structure, wrong_pcs));

    bool bad_columns_rejected = false;
    try {
        auto bad_tensors = fixture.tensors;
        bad_tensors[0].pop_back();
        (void)laminate::spartan::preprocess_factored_matrix(
            fixture.structure, std::move(bad_tensors), pcs);
    } catch (const std::invalid_argument &) {
        bad_columns_rejected = true;
    }
    CHECK(bad_columns_rejected);

    BaseFoldPcs zero_rate({.log_rate = 0, .query_count = 8});
    bool zero_rate_rejected = false;
    try {
        (void)laminate::spartan::preprocess_factored_matrix(
            fixture.structure, fixture.tensors, zero_rate);
    } catch (const std::invalid_argument &) {
        zero_rate_rejected = true;
    }
    CHECK(zero_rate_rejected);

    bool invalid_size_rejected = false;
    try {
        (void)laminate::spartan::
            factored_matrix_evaluation_proof_max_size_bytes(
                setup.verifier_key.commitment,
                {.log_rate = 0, .query_count = 8});
    } catch (const std::invalid_argument &) {
        invalid_size_rejected = true;
    }
    CHECK(invalid_size_rejected);
}

void test_artifact_reopen_matches_resident_proof() {
    Fixture fixture;
    const Fq2 claim = direct_claim(fixture);
    BaseFoldPcs pcs({.log_rate = 1, .query_count = 8});
    const FactoredMatrixSetup resident =
        laminate::spartan::preprocess_factored_matrix(
            fixture.structure, fixture.tensors, pcs);
    TemporaryDirectory directory;
    FactoredMatrixSetup artifact =
        laminate::spartan::preprocess_factored_matrix_to_artifact(
            fixture.structure, fixture.tensors, pcs,
            artifact_options(directory.path()));

    CHECK(artifact.prover_key.commitment == resident.prover_key.commitment);
    CHECK(artifact.prover_key.tensor_column_source ==
          FactoredTensorColumnSource::Artifact);
    CHECK(artifact.prover_key.tensor_columns_artifact != nullptr);
    for (const auto &tensor : artifact.prover_key.tensors) {
        CHECK(tensor.columns.empty());
        CHECK(tensor.opening_state != nullptr);
    }
    const auto &arrays =
        artifact.prover_key.tensor_columns_artifact->arrays();
    CHECK(arrays.size() == 6);
    CHECK(arrays[0].name == "tensor-0-column-0");
    CHECK(arrays[1].name == "tensor-0-column-1");
    CHECK(arrays[2].name == "tensor-1-column-0");
    CHECK(arrays[5].name == "tensor-2-column-0");
    CHECK(arrays[0].element_count == 8);
    CHECK(arrays[2].element_count == 4);
    CHECK(arrays[5].element_count == 1);

    Transcript resident_transcript(kTranscriptDomain);
    const FactoredMatrixEvaluationProof resident_proof =
        laminate::spartan::prove_factored_matrix_evaluation(
            resident.prover_key, fixture.row_point, fixture.column_point,
            fixture.gamma, claim, pcs, resident_transcript);
    const Fq2 resident_next = resident_transcript.challenge_fq2();
    Transcript artifact_transcript(kTranscriptDomain);
    const FactoredMatrixEvaluationProof artifact_proof =
        laminate::spartan::prove_factored_matrix_evaluation(
            artifact.prover_key, fixture.row_point, fixture.column_point,
            fixture.gamma, claim, pcs, artifact_transcript);
    const Fq2 artifact_next = artifact_transcript.challenge_fq2();
    CHECK(artifact_proof == resident_proof);
    CHECK(laminate::spartan::encode_factored_matrix_evaluation_proof(
              artifact_proof) ==
          laminate::spartan::encode_factored_matrix_evaluation_proof(
              resident_proof));
    CHECK(artifact_next == resident_next);
    CHECK(accepts(fixture, artifact.verifier_key, artifact_proof, pcs,
                  claim));

    artifact.prover_key.tensor_columns_artifact.reset();
    CHECK(throws_exception([&] {
        (void)prove(fixture, artifact, pcs, claim);
    }));
    artifact.prover_key.tensor_columns_artifact =
        laminate::spartan::open_factored_matrix_artifact(
            directory.path(), artifact.prover_key.commitment);
    CHECK(prove(fixture, artifact, pcs, claim) == resident_proof);
}

void test_artifact_identity_layout_and_corruption_validation() {
    Fixture fixture;
    BaseFoldPcs pcs({.log_rate = 1, .query_count = 8});
    TemporaryDirectory directory;
    FactoredMatrixSetup setup =
        laminate::spartan::preprocess_factored_matrix_to_artifact(
            fixture.structure, fixture.tensors, pcs,
            artifact_options(directory.path()));
    const Digest identity =
        laminate::spartan::factored_matrix_artifact_identity(
            setup.prover_key.commitment);

    auto changed = setup.prover_key.commitment;
    changed.circuit_digest[0] ^= 1U;
    CHECK(identity != laminate::spartan::factored_matrix_artifact_identity(
                          changed));
    changed = setup.prover_key.commitment;
    changed.structure_digest[0] ^= 1U;
    CHECK(identity != laminate::spartan::factored_matrix_artifact_identity(
                          changed));
    changed = setup.prover_key.commitment;
    ++changed.row_variables;
    CHECK(identity != laminate::spartan::factored_matrix_artifact_identity(
                          changed));
    changed = setup.prover_key.commitment;
    changed.tensors[0].shape.evaluation_count *= 2;
    CHECK(identity != laminate::spartan::factored_matrix_artifact_identity(
                          changed));
    changed = setup.prover_key.commitment;
    ++changed.tensors[0].columns.log_rate;
    CHECK(identity != laminate::spartan::factored_matrix_artifact_identity(
                          changed));
    changed = setup.prover_key.commitment;
    ++changed.tensors[0].columns.query_count;
    CHECK(identity != laminate::spartan::factored_matrix_artifact_identity(
                          changed));
    changed = setup.prover_key.commitment;
    changed.tensors[0].columns.root[0] ^= 1U;
    CHECK(identity != laminate::spartan::factored_matrix_artifact_identity(
                          changed));
    CHECK(throws_exception([&] {
        (void)laminate::spartan::open_factored_matrix_artifact(
            directory.path(), changed);
    }));

    TemporaryDirectory wrong_layout_directory;
    laminate::storage::NativeFieldArtifactWriter wrong_layout(
        wrong_layout_directory.path(),
        artifact_options(wrong_layout_directory.path()).limits, identity);
    std::vector<std::pair<std::string, std::uint64_t>> layout;
    for (std::size_t tensor_index = 0;
         tensor_index < setup.prover_key.commitment.tensors.size();
         ++tensor_index) {
        const FactoredTensorShape shape =
            setup.prover_key.commitment.tensors[tensor_index].shape;
        for (std::size_t column = 0; column < shape.column_count; ++column) {
            layout.emplace_back(
                "tensor-" + std::to_string(tensor_index) + "-column-" +
                    std::to_string(column),
                shape.evaluation_count);
        }
    }
    std::swap(layout[0].first, layout[1].first);
    for (const auto &[name, count] : layout) {
        std::vector<Fq> zeroes(static_cast<std::size_t>(count), Fq::zero());
        wrong_layout.begin_array(
            name, laminate::storage::NativeFieldElementKind::Fq, count);
        wrong_layout.append(zeroes);
        wrong_layout.finish_array();
    }
    (void)wrong_layout.finish();
    CHECK(throws_exception([&] {
        (void)laminate::spartan::open_factored_matrix_artifact(
            wrong_layout_directory.path(), setup.prover_key.commitment);
    }));

    const std::filesystem::path first_array =
        directory.path() / "array-0000000000000000.bin";
    std::fstream file(first_array,
                      std::ios::binary | std::ios::in | std::ios::out);
    file.seekg(-1, std::ios::end);
    char byte = 0;
    file.read(&byte, 1);
    byte ^= 1;
    file.clear();
    file.seekp(-1, std::ios::end);
    file.write(&byte, 1);
    file.close();
    CHECK(throws_exception([&] {
        (void)laminate::spartan::open_factored_matrix_artifact(
            directory.path(), setup.prover_key.commitment);
    }));
}

void test_prover_key_column_sources_are_exclusive() {
    Fixture fixture;
    const Fq2 claim = direct_claim(fixture);
    BaseFoldPcs pcs({.log_rate = 1, .query_count = 8});
    const FactoredMatrixSetup resident =
        laminate::spartan::preprocess_factored_matrix(
            fixture.structure, fixture.tensors, pcs);
    TemporaryDirectory directory;
    const FactoredMatrixSetup artifact =
        laminate::spartan::preprocess_factored_matrix_to_artifact(
            fixture.structure, fixture.tensors, pcs,
            artifact_options(directory.path()));

    FactoredMatrixSetup resident_with_artifact = resident;
    resident_with_artifact.prover_key.tensor_columns_artifact =
        artifact.prover_key.tensor_columns_artifact;
    CHECK(throws_exception([&] {
        (void)prove(fixture, resident_with_artifact, pcs, claim);
    }));

    FactoredMatrixSetup artifact_with_resident = artifact;
    artifact_with_resident.prover_key.tensors[0].columns =
        fixture.tensors[0];
    CHECK(throws_exception([&] {
        (void)prove(fixture, artifact_with_resident, pcs, claim);
    }));

    FactoredMatrixSetup missing_artifact = artifact;
    missing_artifact.prover_key.tensor_columns_artifact.reset();
    CHECK(throws_exception([&] {
        (void)prove(fixture, missing_artifact, pcs, claim);
    }));

    FactoredMatrixSetup externally_tagged = resident;
    externally_tagged.prover_key.tensors[0].opening_state_source =
        laminate::spartan::FactoredTensorProverKey::
            OpeningStateSource::External;
    Transcript tag_attempt(kTranscriptDomain);
    Transcript tag_pristine(kTranscriptDomain);
    CHECK(throws_exception([&] {
        (void)laminate::spartan::prove_factored_matrix_evaluation(
            externally_tagged.prover_key, fixture.row_point,
            fixture.column_point, fixture.gamma, claim, pcs,
            tag_attempt);
    }));
    CHECK(tag_attempt.challenge_fq2() == tag_pristine.challenge_fq2());

    FactoredMatrixSetup wrong_bound_state = resident;
    wrong_bound_state.prover_key.tensors[0].opening_state =
        resident.prover_key.tensors[1].opening_state;
    Transcript binding_attempt(kTranscriptDomain);
    Transcript binding_pristine(kTranscriptDomain);
    CHECK(throws_exception([&] {
        (void)laminate::spartan::prove_factored_matrix_evaluation(
            wrong_bound_state.prover_key, fixture.row_point,
            fixture.column_point, fixture.gamma, claim, pcs,
            binding_attempt);
    }));
    CHECK(binding_attempt.challenge_fq2() ==
          binding_pristine.challenge_fq2());
}

void test_external_preprocessing_matches_resident_and_reopens() {
    Fixture fixture;
    const Fq2 claim = direct_claim(fixture);
    BaseFoldPcs pcs({.log_rate = 1, .query_count = 8});
    const FactoredMatrixSetup resident =
        laminate::spartan::preprocess_factored_matrix(
            fixture.structure, fixture.tensors, pcs);
    TemporaryDirectory staging_directory;
    const auto staging = write_staging_artifact(
        fixture, staging_directory.path());
    const std::uint64_t staging_bytes = staging->physical_bytes();
    ExternalPreprocessingDirectories directories;
    auto external = laminate::spartan::preprocess_factored_matrix_external(
        fixture.structure, staging, pcs, external_options(directories));

    CHECK(external.setup.prover_key.commitment ==
          resident.prover_key.commitment);
    CHECK(external.setup.verifier_key.commitment ==
          resident.verifier_key.commitment);
    CHECK(external.setup.prover_key.tensor_column_source ==
          FactoredTensorColumnSource::Artifact);
    CHECK(external.setup.prover_key.tensor_columns_artifact != nullptr);
    CHECK(external.report.staging_physical_bytes == staging_bytes);
    CHECK(external.report.staging_validation_bytes == staging_bytes);
    CHECK(external.report.tensor_payload_bytes == 29U * sizeof(Fq));
    CHECK(external.report.canonical_copy_read_payload_bytes ==
          external.report.tensor_payload_bytes);
    CHECK(external.report.canonical_copy_write_payload_bytes ==
          external.report.tensor_payload_bytes);
    CHECK(external.report.canonical_copy_read_operations == 13);
    CHECK(external.report.canonical_copy_write_operations == 13);
    CHECK(external.report.peak_copy_working_field_bytes ==
          6U * sizeof(Fq));
    CHECK(external.report.canonical_comparison_read_payload_bytes ==
          2U * external.report.tensor_payload_bytes);
    CHECK(external.report.canonical_comparison_read_operations == 26);
    CHECK(external.report.canonical_artifact_physical_bytes ==
          recursive_file_bytes(directories.canonical.path()));
    CHECK(external.report.canonical_artifact_validation_bytes ==
          external.report.canonical_artifact_physical_bytes);
    CHECK(external.report.retained_staging_physical_bytes == staging_bytes);
    CHECK(external.report.quarantined_staging_physical_bytes == 0);

    std::uint64_t state_bytes = 0;
    std::uint64_t validation_bytes = 0;
    std::uint64_t sequential_read_bytes = 0;
    std::uint64_t indexed_read_bytes = 0;
    std::uint64_t sequential_write_bytes = 0;
    std::uint64_t indexed_write_bytes = 0;
    std::uint64_t scratch_written = 0;
    std::uint64_t scratch_deleted = 0;
    std::uint64_t maximum_scratch = 0;
    for (std::size_t tensor_index = 0;
         tensor_index < fixture.structure->tensor_count();
         ++tensor_index) {
        CHECK(external.setup.prover_key.tensors[tensor_index].columns.empty());
        CHECK(external.setup.prover_key.tensors[tensor_index].opening_state !=
              nullptr);
        CHECK(external.report.tensors[tensor_index].shape ==
              fixture.structure->tensor_shape(tensor_index));
        CHECK(external.report.tensors[tensor_index]
                  .external_state.physical_bytes ==
              recursive_file_bytes(directories.states[tensor_index].path()));
        CHECK(std::filesystem::is_empty(
            directories.scratches[tensor_index].path()));
        state_bytes += recursive_file_bytes(
            directories.states[tensor_index].path());
        validation_bytes += external.report.tensors[tensor_index]
                                .commitment.artifact_validation_bytes;
        sequential_read_bytes += external.report.tensors[tensor_index]
                                     .commitment
                                     .sequential_read_payload_bytes;
        indexed_read_bytes += external.report.tensors[tensor_index]
                                  .commitment.indexed_read_payload_bytes;
        sequential_write_bytes += external.report.tensors[tensor_index]
                                      .commitment
                                      .sequential_write_payload_bytes;
        indexed_write_bytes += external.report.tensors[tensor_index]
                                   .commitment.indexed_write_payload_bytes;
        scratch_written += external.report.tensors[tensor_index]
                               .commitment.scratch_written_physical_bytes;
        scratch_deleted += external.report.tensors[tensor_index]
                               .commitment.scratch_deleted_physical_bytes;
        maximum_scratch = std::max(
            maximum_scratch,
            external.report.tensors[tensor_index]
                .commitment.scratch_peak_physical_bytes);
    }
    CHECK(external.report.external_states_physical_bytes == state_bytes);
    CHECK(external.report.basefold_artifact_validation_bytes ==
          validation_bytes);
    CHECK(external.report.basefold_sequential_read_payload_bytes ==
          sequential_read_bytes);
    CHECK(external.report.basefold_indexed_read_payload_bytes ==
          indexed_read_bytes);
    CHECK(external.report.basefold_sequential_write_payload_bytes ==
          sequential_write_bytes);
    CHECK(external.report.basefold_indexed_write_payload_bytes ==
          indexed_write_bytes);
    CHECK(external.report.basefold_scratch_written_physical_bytes ==
          scratch_written);
    CHECK(external.report.basefold_scratch_deleted_physical_bytes ==
          scratch_deleted);
    CHECK(external.report.basefold_scratch_peak_physical_bytes ==
          maximum_scratch);
    CHECK(scratch_written == scratch_deleted);
    CHECK(external.report.persistent_output_physical_bytes ==
          state_bytes + external.report.canonical_artifact_physical_bytes);
    CHECK(external.report.final_live_physical_bytes ==
          external.report.persistent_output_physical_bytes + staging_bytes);
    CHECK(external.report.max_live_physical_bytes == (1ULL << 24U));
    std::uint64_t expected_conservative_peak = staging_bytes;
    std::uint64_t accumulated_state_bytes = 0;
    for (const auto &tensor_report : external.report.tensors) {
        expected_conservative_peak = std::max(
            expected_conservative_peak,
            staging_bytes + accumulated_state_bytes +
                tensor_report.commitment.final_physical_bytes +
                tensor_report.commitment.scratch_peak_physical_bytes);
        accumulated_state_bytes +=
            tensor_report.commitment.final_physical_bytes;
    }
    expected_conservative_peak = std::max(
        expected_conservative_peak,
        staging_bytes + accumulated_state_bytes +
            external.report.canonical_artifact_physical_bytes);
    CHECK(external.report.conservative_peak_live_physical_bytes ==
          expected_conservative_peak);

    for (std::size_t tensor_index = 0;
         tensor_index < fixture.tensors.size(); ++tensor_index) {
        for (std::size_t column = 0;
             column < fixture.tensors[tensor_index].size(); ++column) {
            auto reader =
                external.setup.prover_key.tensor_columns_artifact->open_array(
                    laminate::spartan::
                        factored_matrix_tensor_column_array_name(
                            tensor_index, column));
            std::vector<Fq> actual(fixture.tensors[tensor_index][column].size());
            CHECK(reader.read(actual) == actual.size());
            CHECK(actual == fixture.tensors[tensor_index][column]);
        }
    }

    std::array<TemporaryDirectory, 3> factored_opening_scratches;
    FactoredMatrixExternalProvingOptions proving_options;
    proving_options.max_live_storage_bytes = 1ULL << 28U;
    proving_options.reserved_live_storage_bytes = 4096;
    proving_options.max_working_field_bytes = 1ULL << 20U;
    for (const TemporaryDirectory &scratch : factored_opening_scratches) {
        proving_options.tensor_openings.push_back(
            external_opening_options(scratch.path()));
    }
    Transcript resident_factored_coin(kTranscriptDomain);
    const FactoredMatrixEvaluationProof resident_factored_proof =
        laminate::spartan::prove_factored_matrix_evaluation(
            resident.prover_key, fixture.row_point, fixture.column_point,
            fixture.gamma, claim, pcs, resident_factored_coin);
    Transcript external_factored_coin(kTranscriptDomain);
    const auto external_factored =
        laminate::spartan::prove_factored_matrix_evaluation_external(
            external.setup.prover_key, fixture.row_point,
            fixture.column_point, fixture.gamma, claim, pcs,
            std::move(proving_options), external_factored_coin);
    CHECK(external_factored.proof == resident_factored_proof);
    CHECK(laminate::spartan::encode_factored_matrix_evaluation_proof(
              external_factored.proof) ==
          laminate::spartan::encode_factored_matrix_evaluation_proof(
              resident_factored_proof));
    CHECK(external_factored_coin.challenge_fq2() ==
          resident_factored_coin.challenge_fq2());
    CHECK(accepts(fixture, external.setup.verifier_key,
                  external_factored.proof, pcs, claim));
    CHECK(external_factored.report.tensor_openings.size() == 3);
    CHECK(external_factored.report.tensor_columns_physical_bytes ==
          external.setup.prover_key.tensor_columns_artifact->physical_bytes());
    CHECK(external_factored.report.external_states_physical_bytes ==
          external.report.external_states_physical_bytes);
    CHECK(external_factored.report.persistent_input_physical_bytes ==
          external_factored.report.tensor_columns_physical_bytes +
              external_factored.report.external_states_physical_bytes);
    CHECK(external_factored.report.reserved_live_storage_bytes == 4096);
    CHECK(external_factored.report.admitted_live_storage_bytes ==
          (1ULL << 28U));
    CHECK(external_factored.report
              .tensor_column_sequential_read_payload_bytes ==
          2U * external.report.tensor_payload_bytes);
    CHECK(external_factored.report
              .tensor_column_sequential_read_operations == 12);
    CHECK(external_factored.report.tensor_column_read_seek_operations == 0);
    CHECK(external_factored.report.scratch_written_physical_bytes ==
          external_factored.report.scratch_deleted_physical_bytes);
    CHECK(external_factored.report.resident_product_sumcheck_field_bytes ==
          2U * 8U * sizeof(Fq2));
    CHECK(external_factored.report.operand_materialization_field_bytes ==
          14U * sizeof(Fq2));
    CHECK(external_factored.report
              .compact_operand_evaluation_field_bytes ==
          6U * sizeof(Fq2));
    CHECK(external_factored.report.retained_column_weight_field_bytes ==
          6U * sizeof(Fq2));
    CHECK(external_factored.report.retained_claim_field_bytes ==
          3U * sizeof(Fq2));
    CHECK(external_factored.report.tensor_column_read_buffer_field_bytes ==
          4096U * sizeof(Fq));
    CHECK(external_factored.report.product_challenge_point_field_bytes ==
          2U * 3U * sizeof(Fq2));
    CHECK(external_factored.report.accumulated_factored_proof_field_bytes ==
          16U * sizeof(Fq2));
    CHECK(external_factored.report.outer_opening_retained_field_bytes ==
          27U * sizeof(Fq2));
    CHECK(external_factored.report.proof_bytes ==
          laminate::spartan::factored_matrix_evaluation_proof_size_bytes(
              external_factored.proof));
    std::uint64_t opening_validation_bytes = 0;
    std::uint64_t opening_sequential_reads = 0;
    std::uint64_t opening_indexed_reads = 0;
    std::uint64_t opening_sequential_writes = 0;
    std::uint64_t opening_scratch_bytes = 0;
    std::uint64_t opening_scratch_peak = 0;
    std::uint64_t opening_scratch_deleted = 0;
    std::uint64_t opening_artifacts_written = 0;
    std::uint64_t opening_artifacts_deleted = 0;
    std::uint64_t opening_files_written = 0;
    std::uint64_t opening_files_deleted = 0;
    std::uint64_t opening_field_peak = 0;
    for (const auto &opening :
         external_factored.report.tensor_openings) {
        opening_validation_bytes += opening.artifact_validation_bytes;
        opening_sequential_reads +=
            opening.sequential_read_payload_bytes;
        opening_indexed_reads += opening.indexed_read_payload_bytes;
        opening_sequential_writes +=
            opening.sequential_write_payload_bytes;
        opening_scratch_bytes +=
            opening.scratch_written_physical_bytes;
        opening_scratch_deleted +=
            opening.scratch_deleted_physical_bytes;
        opening_scratch_peak = std::max(
            opening_scratch_peak,
            opening.scratch_peak_physical_bytes);
        opening_artifacts_written +=
            opening.scratch_chunk_artifacts_written;
        opening_artifacts_deleted +=
            opening.scratch_chunk_artifacts_deleted;
        opening_files_written += opening.scratch_files_written;
        opening_files_deleted += opening.scratch_files_deleted;
        opening_field_peak = std::max(
            opening_field_peak, opening.peak_working_field_bytes);
    }
    CHECK(external_factored.report.artifact_validation_bytes ==
          opening_validation_bytes);
    CHECK(external_factored.report.basefold_preflight_validation_bytes ==
          external.report.external_states_physical_bytes);
    CHECK(external_factored.report.sequential_read_payload_bytes ==
          opening_sequential_reads +
              external_factored.report
                  .tensor_column_sequential_read_payload_bytes);
    CHECK(external_factored.report.indexed_read_payload_bytes ==
          opening_indexed_reads);
    CHECK(external_factored.report.sequential_write_payload_bytes ==
          opening_sequential_writes);
    CHECK(external_factored.report.scratch_written_physical_bytes ==
          opening_scratch_bytes);
    CHECK(external_factored.report.scratch_peak_physical_bytes ==
          opening_scratch_peak);
    CHECK(external_factored.report.scratch_deleted_physical_bytes ==
          opening_scratch_deleted);
    CHECK(external_factored.report.scratch_chunk_artifacts_written ==
          opening_artifacts_written);
    CHECK(external_factored.report.scratch_chunk_artifacts_deleted ==
          opening_artifacts_deleted);
    CHECK(external_factored.report.scratch_files_written ==
          opening_files_written);
    CHECK(external_factored.report.scratch_files_deleted ==
          opening_files_deleted);
    CHECK(external_factored.report.peak_live_storage_bytes ==
          external_factored.report.persistent_input_physical_bytes +
              external_factored.report.reserved_live_storage_bytes +
              opening_scratch_peak);
    CHECK(external_factored.report.basefold_opening_field_bytes ==
          opening_field_peak);
    const std::array<std::uint64_t, 3> outer_opening_bytes{
        24U * sizeof(Fq2), 27U * sizeof(Fq2), 25U * sizeof(Fq2)};
    std::uint64_t expected_complete_field_peak = 33232;
    for (std::size_t tensor = 0; tensor < outer_opening_bytes.size();
         ++tensor) {
        expected_complete_field_peak = std::max(
            expected_complete_field_peak,
            outer_opening_bytes[tensor] +
                external_factored.report.tensor_openings[tensor]
                    .peak_working_field_bytes);
    }
    CHECK(external_factored.report.peak_working_field_bytes ==
          expected_complete_field_peak);
    for (const TemporaryDirectory &scratch : factored_opening_scratches) {
        CHECK(std::filesystem::is_empty(scratch.path()));
    }

    std::array<TemporaryDirectory, 3> late_failure_scratches;
    FactoredMatrixExternalProvingOptions late_failure_options;
    late_failure_options.max_live_storage_bytes = 1ULL << 28U;
    late_failure_options.max_working_field_bytes = 1ULL << 20U;
    for (const TemporaryDirectory &scratch : late_failure_scratches) {
        late_failure_options.tensor_openings.push_back(
            external_opening_options(scratch.path()));
    }
    late_failure_options.tensor_openings[1].max_total_scratch_bytes = 1;
    Transcript late_failure_coin(kTranscriptDomain);
    Transcript late_failure_pristine(kTranscriptDomain);
    CHECK(throws_exception([&] {
        (void)laminate::spartan::prove_factored_matrix_evaluation_external(
            external.setup.prover_key, fixture.row_point,
            fixture.column_point, fixture.gamma, claim, pcs,
            std::move(late_failure_options), late_failure_coin);
    }));
    CHECK(late_failure_coin.challenge_fq2() ==
          late_failure_pristine.challenge_fq2());
    for (const TemporaryDirectory &scratch : late_failure_scratches) {
        CHECK(std::filesystem::is_empty(scratch.path()));
    }

    std::array<TemporaryDirectory, 3> outer_cap_scratches;
    FactoredMatrixExternalProvingOptions outer_cap_options;
    outer_cap_options.max_live_storage_bytes = 1ULL << 28U;
    outer_cap_options.max_working_field_bytes = 1;
    for (const TemporaryDirectory &scratch : outer_cap_scratches) {
        outer_cap_options.tensor_openings.push_back(
            external_opening_options(scratch.path()));
    }
    Transcript outer_cap_coin(kTranscriptDomain);
    Transcript outer_cap_pristine(kTranscriptDomain);
    CHECK(throws_exception([&] {
        (void)laminate::spartan::prove_factored_matrix_evaluation_external(
            external.setup.prover_key, fixture.row_point,
            fixture.column_point, fixture.gamma, claim, pcs,
            std::move(outer_cap_options), outer_cap_coin);
    }));
    CHECK(outer_cap_coin.challenge_fq2() ==
          outer_cap_pristine.challenge_fq2());
    for (const TemporaryDirectory &scratch : outer_cap_scratches) {
        CHECK(std::filesystem::is_empty(scratch.path()));
    }

    std::array<TemporaryDirectory, 3> storage_cap_scratches;
    FactoredMatrixExternalProvingOptions storage_cap_options;
    storage_cap_options.max_live_storage_bytes = 1;
    storage_cap_options.max_working_field_bytes = 1ULL << 20U;
    for (const TemporaryDirectory &scratch : storage_cap_scratches) {
        storage_cap_options.tensor_openings.push_back(
            external_opening_options(scratch.path()));
    }
    Transcript storage_cap_coin(kTranscriptDomain);
    Transcript storage_cap_pristine(kTranscriptDomain);
    CHECK(throws_exception([&] {
        (void)laminate::spartan::prove_factored_matrix_evaluation_external(
            external.setup.prover_key, fixture.row_point,
            fixture.column_point, fixture.gamma, claim, pcs,
            std::move(storage_cap_options), storage_cap_coin);
    }));
    CHECK(storage_cap_coin.challenge_fq2() ==
          storage_cap_pristine.challenge_fq2());
    for (const TemporaryDirectory &scratch : storage_cap_scratches) {
        CHECK(std::filesystem::is_empty(scratch.path()));
    }

    external.setup.prover_key.tensor_columns_artifact.reset();
    external.setup.prover_key.tensor_columns_artifact =
        laminate::spartan::open_factored_matrix_artifact(
            directories.canonical.path(),
            external.setup.prover_key.commitment);
    std::array<TemporaryDirectory, 3> opening_scratches;
    for (std::size_t tensor_index = 0;
         tensor_index < fixture.structure->tensor_count();
         ++tensor_index) {
        const FactoredTensorShape shape =
            fixture.structure->tensor_shape(tensor_index);
        std::vector<Fq2> weights;
        for (std::size_t column = 0; column < shape.column_count; ++column) {
            weights.push_back(Fq2(
                {Fq(3U * column + 5U), Fq(7U * column + 11U)}));
        }
        std::vector<Fq2> point;
        const std::size_t variables =
            std::bit_width(shape.evaluation_count) - 1U;
        for (std::size_t variable = 0; variable < variables; ++variable) {
            point.push_back(Fq2(
                {Fq(13U * variable + 17U),
                 Fq(19U * variable + 23U)}));
        }
        const Fq2 value = evaluate_linear_combination_msb(
            fixture.tensors[tensor_index], weights, point);
        Transcript resident_coin(
            "laminate/test/factored-external-opening/v1");
        bind_pcs_commitment(
            resident.prover_key.commitment.tensors[tensor_index].columns,
            resident_coin);
        const auto resident_proof = pcs.open_linear_combination(
            resident.prover_key.tensors[tensor_index].opening_state,
            weights, point, value, resident_coin);

        external.setup.prover_key.tensors[tensor_index].opening_state =
            pcs.open_external_prover_state(
                directories.states[tensor_index].path(),
                external.setup.prover_key.commitment.tensors[tensor_index]
                    .columns);
        Transcript external_coin(
            "laminate/test/factored-external-opening/v1");
        bind_pcs_commitment(
            external.setup.prover_key.commitment.tensors[tensor_index]
                .columns,
            external_coin);
        const auto external_opening =
            pcs.open_linear_combination_external(
                external.setup.prover_key.tensors[tensor_index]
                    .opening_state,
                weights, point, value,
                external_opening_options(
                    opening_scratches[tensor_index].path()),
                external_coin);
        CHECK(external_opening.proof == resident_proof);
        CHECK(external_coin.challenge_fq2() ==
              resident_coin.challenge_fq2());
        CHECK(external_opening.report.scratch_physical_bytes ==
              recursive_file_bytes(
                  opening_scratches[tensor_index].path()));
        CHECK(external_opening.report.scratch_physical_bytes == 0);
        CHECK(external_opening.report.scratch_written_physical_bytes ==
              external_opening.report.scratch_deleted_physical_bytes);
    }
}

void test_external_preprocessing_rejects_corruption_and_cleans_failures() {
    Fixture fixture;
    BaseFoldPcs pcs({.log_rate = 1, .query_count = 8});

    {
        TemporaryDirectory staging_directory;
        const auto staging = write_staging_artifact(
            fixture, staging_directory.path());
        const std::filesystem::path first_array =
            staging_directory.path() / "array-0000000000000000.bin";
        std::fstream file(first_array,
                          std::ios::binary | std::ios::in | std::ios::out);
        file.seekg(-1, std::ios::end);
        char byte = 0;
        file.read(&byte, 1);
        byte ^= 1;
        file.clear();
        file.seekp(-1, std::ios::end);
        file.write(&byte, 1);
        file.close();
        ExternalPreprocessingDirectories directories;
        CHECK(throws_exception([&] {
            (void)laminate::spartan::
                preprocess_factored_matrix_external(
                    fixture.structure, staging, pcs,
                    external_options(directories));
        }));
        CHECK(directories.empty());
    }

    {
        TemporaryDirectory staging_directory;
        const auto staging = write_staging_artifact(
            fixture, staging_directory.path());
        const std::uint64_t staging_bytes = staging->physical_bytes();
        ExternalPreprocessingDirectories directories;
        auto options = external_options(directories);
        options.tensor_commitments[1].max_final_bytes = 1;
        CHECK(throws_exception([&] {
            (void)laminate::spartan::
                preprocess_factored_matrix_external(
                    fixture.structure, staging, pcs, std::move(options));
        }));
        CHECK(directories.empty());
        CHECK(recursive_file_bytes(staging_directory.path()) ==
              staging_bytes);
    }

    {
        TemporaryDirectory staging_directory;
        const auto staging = write_staging_artifact(
            fixture, staging_directory.path());
        const std::uint64_t staging_bytes = staging->physical_bytes();
        ExternalPreprocessingDirectories directories;
        auto options = external_options(directories);
        options.max_live_physical_bytes = 1;
        CHECK(throws_exception([&] {
            (void)laminate::spartan::
                preprocess_factored_matrix_external(
                    fixture.structure, staging, pcs, std::move(options));
        }));
        CHECK(directories.empty());
        CHECK(recursive_file_bytes(staging_directory.path()) ==
              staging_bytes);
    }

    {
        TemporaryDirectory staging_directory;
        const auto staging = write_staging_artifact(
            fixture, staging_directory.path());
        const std::uint64_t staging_bytes = staging->physical_bytes();
        ExternalPreprocessingDirectories directories;
        auto options = external_options(directories);
        options.tensor_columns_artifact.limits.min_free_bytes =
            std::numeric_limits<std::uint64_t>::max() / 2U;
        CHECK(throws_exception([&] {
            (void)laminate::spartan::
                preprocess_factored_matrix_external(
                    fixture.structure, staging, pcs, std::move(options));
        }));
        CHECK(directories.empty());
        CHECK(recursive_file_bytes(staging_directory.path()) ==
              staging_bytes);
    }

    {
        TemporaryDirectory staging_directory;
        const auto staging = write_staging_artifact(
            fixture, staging_directory.path());
        ExternalPreprocessingDirectories directories;
        auto options = external_options(directories);
        options.tensor_commitments[0].destination_directory =
            directories.canonical.path();
        CHECK(throws_exception([&] {
            (void)laminate::spartan::
                preprocess_factored_matrix_external(
                    fixture.structure, staging, pcs, std::move(options));
        }));
        CHECK(directories.empty());
    }
}

void test_external_proving_rejects_resident_opening_states_before_coin() {
    Fixture fixture;
    const Fq2 claim = direct_claim(fixture);
    BaseFoldPcs pcs({.log_rate = 1, .query_count = 8});
    TemporaryDirectory artifact_directory;
    FactoredMatrixSetup resident_openings =
        laminate::spartan::preprocess_factored_matrix_to_artifact(
            fixture.structure, fixture.tensors, pcs,
            artifact_options(artifact_directory.path()));
    for (auto &tensor : resident_openings.prover_key.tensors) {
        tensor.opening_state_source =
            laminate::spartan::FactoredTensorProverKey::
                OpeningStateSource::External;
    }
    std::array<TemporaryDirectory, 3> opening_scratches;
    FactoredMatrixExternalProvingOptions options;
    options.max_live_storage_bytes = 1ULL << 28U;
    options.max_working_field_bytes = 1ULL << 20U;
    for (const TemporaryDirectory &scratch : opening_scratches) {
        options.tensor_openings.push_back(
            external_opening_options(scratch.path()));
    }
    Transcript attempted(kTranscriptDomain);
    Transcript pristine(kTranscriptDomain);
    CHECK(throws_exception([&] {
        (void)laminate::spartan::
            prove_factored_matrix_evaluation_external(
                resident_openings.prover_key, fixture.row_point,
                fixture.column_point, fixture.gamma, claim, pcs,
                std::move(options), attempted);
    }));
    CHECK(attempted.challenge_fq2() == pristine.challenge_fq2());
    for (const TemporaryDirectory &scratch : opening_scratches) {
        CHECK(std::filesystem::is_empty(scratch.path()));
    }
}

void test_external_preprocessing_staging_ownership_is_explicit() {
    Fixture fixture;
    BaseFoldPcs pcs({.log_rate = 1, .query_count = 8});

    {
        TemporaryDirectory staging_directory;
        auto staging = write_staging_artifact(
            fixture, staging_directory.path());
        const auto alias = staging;
        TemporaryDirectory quarantine;
        ExternalPreprocessingDirectories directories;
        CHECK(throws_exception([&] {
            (void)laminate::spartan::
                preprocess_factored_matrix_external(
                    fixture.structure, std::move(staging), pcs,
                    external_options(
                        directories,
                        FactoredMatrixStagingOwnership::
                            MoveToQuarantineOnSuccess,
                        quarantine.path()));
        }));
        CHECK(alias != nullptr);
        CHECK(std::filesystem::exists(staging_directory.path()));
        CHECK(std::filesystem::is_empty(quarantine.path()));
        CHECK(directories.empty());
    }

#ifndef _WIN32
    {
        TemporaryDirectory staging_directory;
        auto staging = write_staging_artifact(
            fixture, staging_directory.path());
        TemporaryDirectory nonprivate_quarantine;
        std::filesystem::permissions(
            nonprivate_quarantine.path(),
            std::filesystem::perms::owner_all |
                std::filesystem::perms::group_read,
            std::filesystem::perm_options::replace);
        ExternalPreprocessingDirectories directories;
        CHECK(throws_exception([&] {
            (void)laminate::spartan::
                preprocess_factored_matrix_external(
                    fixture.structure, std::move(staging), pcs,
                    external_options(
                        directories,
                        FactoredMatrixStagingOwnership::
                            MoveToQuarantineOnSuccess,
                        nonprivate_quarantine.path()));
        }));
        CHECK(std::filesystem::exists(staging_directory.path()));
        CHECK(std::filesystem::is_empty(
            nonprivate_quarantine.path()));
        CHECK(directories.empty());
    }
#endif

    {
        TemporaryDirectory staging_directory;
        auto staging = write_staging_artifact(
            fixture, staging_directory.path());
        const std::uint64_t staging_bytes = staging->physical_bytes();
        TemporaryDirectory quarantine;
        ExternalPreprocessingDirectories directories;
        const auto external =
            laminate::spartan::preprocess_factored_matrix_external(
                fixture.structure, std::move(staging), pcs,
                external_options(
                    directories,
                    FactoredMatrixStagingOwnership::
                        MoveToQuarantineOnSuccess,
                    quarantine.path()));
        CHECK(staging == nullptr);
        CHECK(!std::filesystem::exists(staging_directory.path()));
        const std::filesystem::path quarantined_artifact =
            quarantine.path() / "staging-artifact";
        CHECK(std::filesystem::exists(quarantined_artifact));
        CHECK(external.report.quarantined_staging_physical_bytes ==
              staging_bytes);
        CHECK(external.report.retained_staging_physical_bytes == 0);
        CHECK(external.report.staging_quarantine_artifact_path ==
              std::filesystem::canonical(quarantined_artifact));
        CHECK(external.report.final_live_physical_bytes ==
              external.report.persistent_output_physical_bytes +
                  staging_bytes);
        const auto reopened =
            laminate::spartan::open_factored_matrix_staging_artifact(
                quarantined_artifact, *fixture.structure);
        CHECK(reopened->physical_bytes() == staging_bytes);
    }
}

void test_external_preprocessing_target_payload_formulas() {
    constexpr std::uint64_t width = 4;
    constexpr std::uint64_t fq_bytes = 8;
    constexpr std::uint64_t digest_bytes = 40;
    constexpr std::uint64_t leaf_elements = 64;
    const auto check_target = [&](std::uint64_t evaluations,
                                  std::uint64_t expected_raw_mebibytes,
                                  std::uint64_t expected_state_mebibytes,
                                  std::uint64_t expected_output_mebibytes,
                                  std::uint64_t expected_quarantine_mebibytes) {
        const std::uint64_t codeword_evaluations = 2U * evaluations;
        const std::uint64_t leaf_count =
            codeword_evaluations / leaf_elements;
        const std::uint64_t tree_nodes = 2U * leaf_count - 1U;
        const std::uint64_t raw_payload =
            width * evaluations * fq_bytes;
        const std::uint64_t external_state_payload =
            raw_payload + width * codeword_evaluations * fq_bytes +
            tree_nodes * digest_bytes;
        const std::uint64_t persistent_output_payload =
            raw_payload + external_state_payload;
        const std::uint64_t quarantine_live_payload =
            raw_payload + persistent_output_payload;
        const std::uint64_t product_rounds =
            std::bit_width(evaluations) - 1U;
        const std::uint64_t tensor_column_read_payload =
            2U * raw_payload;
        const std::uint64_t tensor_column_read_operations =
            2U * width *
            (evaluations / 4096U +
             (evaluations % 4096U != 0 ? 1U : 0U));
        const std::uint64_t product_table_fields = 2U * evaluations;
        const std::uint64_t challenge_point_fields =
            2U * product_rounds;
        const std::uint64_t factored_proof_fields =
            2U + 2U * product_rounds;
        const std::uint64_t outer_opening_fields =
            (width + 1U) + factored_proof_fields + product_rounds;
        constexpr std::uint64_t mebibyte = 1ULL << 20U;
        CHECK(raw_payload == expected_raw_mebibytes * mebibyte);
        CHECK(external_state_payload ==
              expected_state_mebibytes * mebibyte - digest_bytes);
        CHECK(persistent_output_payload ==
              expected_output_mebibytes * mebibyte - digest_bytes);
        CHECK(quarantine_live_payload ==
              expected_quarantine_mebibytes * mebibyte - digest_bytes);
        CHECK(tensor_column_read_payload ==
              2U * width * evaluations * fq_bytes);
        CHECK(tensor_column_read_operations ==
              2U * width * (evaluations / 4096U));
        CHECK(product_table_fields * sizeof(Fq2) ==
              2U * evaluations * sizeof(Fq2));
        CHECK(challenge_point_fields * sizeof(Fq2) ==
              2U * product_rounds * sizeof(Fq2));
        CHECK(factored_proof_fields * sizeof(Fq2) ==
              (2U + 2U * product_rounds) * sizeof(Fq2));
        CHECK(outer_opening_fields * sizeof(Fq2) ==
              (width + 3U + 3U * product_rounds) * sizeof(Fq2));
    };
    check_target(1ULL << 23U, 256, 788, 1044, 1300);
    check_target(1ULL << 24U, 512, 1576, 2088, 2600);
}

} // namespace

int main() {
    laminate::test::Runner runner("test_factored");
    runner.run("factored tensors match direct evaluation",
               test_factored_evaluation_and_transcript_sync);
    runner.run("factored proof mutations reject",
               test_mutations_and_statement_changes_reject);
    runner.run("factored setup and commitment validation",
               test_setup_validation_and_commitment_encoding);
    runner.run("artifact reopen matches resident proof",
               test_artifact_reopen_matches_resident_proof);
    runner.run("artifact identity, layout, and corruption",
               test_artifact_identity_layout_and_corruption_validation);
    runner.run("prover key column sources are exclusive",
               test_prover_key_column_sources_are_exclusive);
    runner.run("external preprocessing matches resident and reopens",
               test_external_preprocessing_matches_resident_and_reopens);
    runner.run("external preprocessing validates and cleans failures",
               test_external_preprocessing_rejects_corruption_and_cleans_failures);
    runner.run("external proving rejects resident opening states before coin",
               test_external_proving_rejects_resident_opening_states_before_coin);
    runner.run("external preprocessing staging ownership is explicit",
               test_external_preprocessing_staging_ownership_is_explicit);
    runner.run("external preprocessing target payload formulas",
               test_external_preprocessing_target_payload_formulas);
    return runner.summary();
}
