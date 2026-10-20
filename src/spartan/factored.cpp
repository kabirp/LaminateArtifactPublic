/// @file factored.cpp
/// @brief Product-sumcheck proofs for factored R1CS matrix evaluations.

#include "laminate/spartan/factored.hpp"

#include "laminate/field/serialization.hpp"

#include <algorithm>
#include <bit>
#include <cerrno>
#include <exception>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

#ifndef _WIN32
#include <sys/stat.h>
#include <unistd.h>
#ifdef __APPLE__
#include <sys/stdio.h>
#elif defined(__linux__)
#include <fcntl.h>
#include <linux/fs.h>
#include <sys/syscall.h>
#endif
#endif

namespace laminate::spartan {
namespace {

constexpr std::string_view kCommitmentLabel =
    "laminate/spartan/factored/commitment/v1";
constexpr std::string_view kStatementLabel =
    "laminate/spartan/factored/evaluation-statement/v1";
constexpr std::string_view kClaimsLabel =
    "laminate/spartan/factored/component-claims/v1";
constexpr std::string_view kRoundLabel =
    "laminate/spartan/factored/product-round/v1";
constexpr std::string_view kTerminalLabel =
    "laminate/spartan/factored/terminal-tensor/v1";
constexpr std::string_view kOpeningLabel =
    "laminate/spartan/factored/component-opening/v1";
constexpr std::string_view kCommitmentEncodingDomain =
    "LaminateImpl/FactoredMatrixCommitment/v1";
constexpr std::string_view kProofEncodingDomain =
    "LaminateImpl/FactoredMatrixEvaluationProof/v1";
constexpr std::string_view kArtifactIdentityDomain =
    "LaminateImpl/FactoredMatrixTensorColumns/v1";
constexpr std::string_view kStagingArtifactIdentityDomain =
    "LaminateImpl/FactoredMatrixTensorStaging/v1";
constexpr std::size_t kArtifactReadElements = 4096;

std::uint64_t storage_add(std::uint64_t left, std::uint64_t right,
                          const char *label);
std::uint64_t storage_multiply(std::uint64_t left,
                               std::uint64_t right,
                               const char *label);

void append_u64(std::vector<std::uint8_t> &output, std::uint64_t value) {
    for (std::size_t byte = 0; byte < 8; ++byte) {
        output.push_back(static_cast<std::uint8_t>(value >> (8U * byte)));
    }
}

void append_size(std::vector<std::uint8_t> &output, std::size_t value) {
    if constexpr (sizeof(std::size_t) > sizeof(std::uint64_t)) {
        if (value > std::numeric_limits<std::uint64_t>::max()) {
            throw std::overflow_error("factored matrix size exceeds u64");
        }
    }
    append_u64(output, static_cast<std::uint64_t>(value));
}

void append_digest(std::vector<std::uint8_t> &output,
                   const Digest &digest) {
    output.insert(output.end(), digest.begin(), digest.end());
}

void append_fq2(std::vector<std::uint8_t> &output, const Fq2 &value) {
    const SerializedFq2 encoded = serialize(value);
    output.insert(output.end(), encoded.begin(), encoded.end());
}

void append_fq2_vector(std::vector<std::uint8_t> &output,
                       std::span<const Fq2> values) {
    append_size(output, values.size());
    for (const Fq2 &value : values) {
        append_fq2(output, value);
    }
}

std::size_t checked_size(std::uint64_t value, const char *label) {
    if (value > std::numeric_limits<std::size_t>::max()) {
        throw std::overflow_error(std::string(label) + " exceeds size_t");
    }
    return static_cast<std::size_t>(value);
}

std::uint64_t checked_u64(std::size_t value, const char *label) {
    if constexpr (sizeof(std::size_t) > sizeof(std::uint64_t)) {
        if (value > std::numeric_limits<std::uint64_t>::max()) {
            throw std::overflow_error(std::string(label) + " exceeds u64");
        }
    }
    return static_cast<std::uint64_t>(value);
}

std::size_t log2_exact(std::uint64_t value) {
    if (value == 0 || !std::has_single_bit(value)) {
        throw std::invalid_argument(
            "factored tensor size is not a power of two");
    }
    return static_cast<std::size_t>(std::bit_width(value) - 1U);
}

bool valid_shape(const FactoredTensorShape &shape) {
    return shape.evaluation_count != 0 &&
           std::has_single_bit(shape.evaluation_count) &&
           shape.column_count != 0 &&
           shape.evaluation_count <=
               std::numeric_limits<std::size_t>::max() &&
           shape.column_count <= std::numeric_limits<std::size_t>::max();
}

bool valid_pcs_commitment(const FactoredTensorCommitment &tensor,
                          const IPCS &pcs) {
    const auto *basefold = dynamic_cast<const BaseFoldPcs *>(&pcs);
    return basefold != nullptr &&
           basefold->parameters().log_rate > 0 &&
           tensor.columns.scheme == BaseFoldPcs::kSchemeIdentifier &&
           tensor.columns.scheme == pcs.scheme_identifier() &&
           tensor.columns.log_rate == basefold->parameters().log_rate &&
           tensor.columns.query_count ==
               basefold->parameters().query_count &&
           tensor.columns.evaluation_count ==
               tensor.shape.evaluation_count &&
           tensor.columns.width == tensor.shape.column_count;
}

bool valid_internal_commitment(
    const FactoredMatrixCommitment &commitment,
    const FactoredMatrixStructure &structure, const IPCS &pcs) {
    if (commitment.profile != kFactoredMatrixProfileIdentifier ||
        commitment.circuit_digest != structure.circuit_digest() ||
        commitment.structure_digest != structure.structure_digest() ||
        commitment.row_variables != structure.row_variables() ||
        commitment.column_variables != structure.column_variables() ||
        commitment.tensors.size() != structure.tensor_count()) {
        return false;
    }
    for (std::size_t tensor_index = 0;
         tensor_index < commitment.tensors.size(); ++tensor_index) {
        const FactoredTensorCommitment &tensor =
            commitment.tensors[tensor_index];
        if (!valid_shape(tensor.shape) ||
            tensor.shape != structure.tensor_shape(tensor_index) ||
            !valid_pcs_commitment(tensor, pcs)) {
            return false;
        }
    }
    return true;
}

void validate_artifact_layout(
    const storage::NativeFieldArtifact &artifact,
    const FactoredMatrixCommitment &commitment) {
    if (artifact.identity() != factored_matrix_artifact_identity(commitment)) {
        throw std::invalid_argument(
            "factored tensor artifact identity mismatch");
    }
    std::size_t expected_array_count = 0;
    for (const FactoredTensorCommitment &tensor : commitment.tensors) {
        const std::size_t width =
            checked_size(tensor.shape.column_count,
                         "factored tensor width");
        if (width > std::numeric_limits<std::size_t>::max() -
                        expected_array_count) {
            throw std::overflow_error(
                "factored artifact array count overflows");
        }
        expected_array_count += width;
    }
    if (artifact.arrays().size() != expected_array_count) {
        throw std::invalid_argument(
            "factored tensor artifact has wrong array count");
    }
    std::size_t array_index = 0;
    for (std::size_t tensor_index = 0;
         tensor_index < commitment.tensors.size(); ++tensor_index) {
        const FactoredTensorShape shape =
            commitment.tensors[tensor_index].shape;
        const std::size_t width =
            checked_size(shape.column_count, "factored tensor width");
        for (std::size_t column = 0; column < width;
             ++column, ++array_index) {
            const storage::NativeFieldArrayDescriptor &array =
                artifact.arrays()[array_index];
            if (array.name != factored_matrix_tensor_column_array_name(
                                  tensor_index, column) ||
                array.kind != storage::NativeFieldElementKind::Fq ||
                array.element_count != shape.evaluation_count ||
                array.encoded_element_bytes != kSerializedFqBytes) {
                throw std::invalid_argument(
                    "factored tensor artifact layout mismatch");
            }
        }
    }
}

void validate_staging_artifact_layout(
    const storage::NativeFieldArtifact &artifact,
    const FactoredMatrixStructure &structure) {
    if (artifact.identity() !=
        factored_matrix_staging_artifact_identity(structure)) {
        throw std::invalid_argument(
            "factored tensor staging artifact identity mismatch");
    }
    std::size_t expected_array_count = 0;
    for (std::size_t tensor_index = 0;
         tensor_index < structure.tensor_count(); ++tensor_index) {
        const FactoredTensorShape shape =
            structure.tensor_shape(tensor_index);
        if (!valid_shape(shape)) {
            throw std::invalid_argument(
                "factored structure has an invalid tensor shape");
        }
        const std::size_t width =
            checked_size(shape.column_count, "factored tensor width");
        if (width > std::numeric_limits<std::size_t>::max() -
                        expected_array_count) {
            throw std::overflow_error(
                "factored staging array count overflows");
        }
        expected_array_count += width;
    }
    if (structure.tensor_count() == 0 ||
        artifact.arrays().size() != expected_array_count) {
        throw std::invalid_argument(
            "factored tensor staging artifact has wrong array count");
    }
    std::size_t array_index = 0;
    for (std::size_t tensor_index = 0;
         tensor_index < structure.tensor_count(); ++tensor_index) {
        const FactoredTensorShape shape =
            structure.tensor_shape(tensor_index);
        const std::size_t width =
            checked_size(shape.column_count, "factored tensor width");
        for (std::size_t column = 0; column < width;
             ++column, ++array_index) {
            const storage::NativeFieldArrayDescriptor &array =
                artifact.arrays()[array_index];
            if (array.name != factored_matrix_tensor_column_array_name(
                                  tensor_index, column) ||
                array.kind != storage::NativeFieldElementKind::Fq ||
                array.element_count != shape.evaluation_count ||
                array.encoded_element_bytes != kSerializedFqBytes) {
                throw std::invalid_argument(
                    "factored tensor staging artifact layout mismatch");
            }
        }
    }
}

void validate_evaluation_inputs(
    const FactoredMatrixCommitment &commitment,
    const std::shared_ptr<const FactoredMatrixStructure> &structure,
    std::span<const Fq2> row_point,
    std::span<const Fq2> column_point, const IPCS &pcs) {
    if (structure == nullptr ||
        !valid_internal_commitment(commitment, *structure, pcs) ||
        row_point.size() != commitment.row_variables ||
        column_point.size() != commitment.column_variables) {
        throw std::invalid_argument(
            "factored commitment, structure, PCS, or point is inconsistent");
    }
}

void validate_prover_key(const FactoredMatrixProverKey &key,
                         std::span<const Fq2> row_point,
                         std::span<const Fq2> column_point,
                         const IPCS &pcs) {
    validate_evaluation_inputs(key.commitment, key.structure, row_point,
                               column_point, pcs);
    if (key.tensors.size() != key.commitment.tensors.size()) {
        throw std::invalid_argument(
            "factored prover key has wrong tensor count");
    }
    const bool artifact_backed =
        key.tensor_column_source == FactoredTensorColumnSource::Artifact;
    if (artifact_backed) {
        if (key.tensor_columns_artifact == nullptr) {
            throw std::invalid_argument(
                "factored artifact-backed key has no artifact");
        }
        validate_artifact_layout(*key.tensor_columns_artifact,
                                 key.commitment);
    } else if (key.tensor_column_source !=
                   FactoredTensorColumnSource::Resident ||
               key.tensor_columns_artifact != nullptr) {
        throw std::invalid_argument(
            "factored prover key has an inconsistent column source");
    }
    for (std::size_t tensor_index = 0;
         tensor_index < key.tensors.size(); ++tensor_index) {
        const FactoredTensorShape shape =
            key.commitment.tensors[tensor_index].shape;
        const std::size_t width =
            checked_size(shape.column_count, "factored tensor width");
        const std::size_t evaluation_count = checked_size(
            shape.evaluation_count, "factored tensor evaluation count");
        const FactoredTensorProverKey &tensor = key.tensors[tensor_index];
        if (tensor.opening_state == nullptr ||
            (artifact_backed && !tensor.columns.empty()) ||
            (!artifact_backed && tensor.columns.size() != width) ||
            (!artifact_backed &&
             tensor.opening_state_source !=
                 FactoredTensorProverKey::OpeningStateSource::Resident) ||
            (tensor.opening_state_source !=
                 FactoredTensorProverKey::OpeningStateSource::Resident &&
             tensor.opening_state_source !=
                 FactoredTensorProverKey::OpeningStateSource::External)) {
            throw std::invalid_argument(
                "factored prover tensor has wrong shape");
        }
        if (!artifact_backed) {
            for (const std::vector<Fq> &column : tensor.columns) {
                if (column.size() != evaluation_count) {
                    throw std::invalid_argument(
                        "factored prover tensor column has wrong length");
                }
            }
        }
    }
}

std::vector<Fq2> checked_column_weights(
    const FactoredMatrixStructure &structure, std::size_t tensor_index,
    const FactoredTensorShape &shape,
    std::span<const Fq2> row_point,
    std::span<const Fq2> column_point, const Fq2 &gamma) {
    std::vector<Fq2> weights = structure.tensor_column_weights(
        tensor_index, row_point, column_point, gamma);
    if (weights.size() != shape.column_count) {
        throw std::invalid_argument(
            "factored tensor column weights have wrong length");
    }
    return weights;
}

std::vector<Fq2> checked_operand(
    const FactoredMatrixStructure &structure, std::size_t tensor_index,
    const FactoredTensorShape &shape,
    std::span<const Fq2> row_point,
    std::span<const Fq2> column_point, const Fq2 &gamma) {
    std::vector<Fq2> operand = structure.materialize_tensor_operand(
        tensor_index, row_point, column_point, gamma);
    if (operand.size() != shape.evaluation_count) {
        throw std::invalid_argument(
            "factored tensor operand has wrong length");
    }
    return operand;
}

template <typename Consume>
void for_each_column_chunk(const FactoredMatrixProverKey &key,
                           std::size_t tensor_index,
                           std::size_t column_index,
                           std::size_t evaluation_count,
                           Consume consume,
                           FactoredMatrixExternalProvingReport *report) {
    if (key.tensor_column_source ==
        FactoredTensorColumnSource::Resident) {
        const std::vector<Fq> &values =
            key.tensors[tensor_index].columns[column_index];
        for (std::size_t offset = 0; offset < evaluation_count;
             offset += kArtifactReadElements) {
            const std::size_t count = std::min(
                kArtifactReadElements, evaluation_count - offset);
            consume(std::span<const Fq>(values).subspan(offset, count),
                    offset);
        }
        return;
    }

    storage::NativeFieldArrayReader reader =
        key.tensor_columns_artifact->open_array(
            factored_matrix_tensor_column_array_name(tensor_index,
                                                      column_index));
    std::array<Fq, kArtifactReadElements> buffer{};
    std::size_t offset = 0;
    while (offset < evaluation_count) {
        const std::size_t requested = std::min(
            buffer.size(), evaluation_count - offset);
        const std::size_t read = reader.read(
            std::span<Fq>(buffer).first(requested));
        if (read != requested) {
            throw std::runtime_error(
                "factored tensor artifact ended early");
        }
        if (report != nullptr) {
            const std::uint64_t bytes = storage_multiply(
                checked_u64(read, "factored tensor-column elements"),
                kSerializedFqBytes,
                "factored tensor-column payload bytes");
            report->tensor_column_sequential_read_payload_bytes =
                storage_add(
                    report
                        ->tensor_column_sequential_read_payload_bytes,
                    bytes,
                    "factored tensor-column payload bytes");
            report->sequential_read_payload_bytes = storage_add(
                report->sequential_read_payload_bytes, bytes,
                "factored total sequential read payload bytes");
            report->tensor_column_sequential_read_operations =
                storage_add(
                    report->tensor_column_sequential_read_operations, 1U,
                    "factored tensor-column read operations");
        }
        consume(std::span<const Fq>(buffer).first(read), offset);
        offset += read;
    }
    if (reader.position() != reader.size()) {
        throw std::runtime_error(
            "factored tensor artifact has trailing elements");
    }
}

Fq2 weighted_dot(const FactoredMatrixProverKey &key,
                 std::size_t tensor_index,
                 std::span<const Fq2> weights,
                 std::span<const Fq2> operand,
                 FactoredMatrixExternalProvingReport *report) {
    Fq2 result = Fq2::zero();
    for (std::size_t column = 0; column < weights.size(); ++column) {
        const Fq2 &weight = weights[column];
        for_each_column_chunk(
            key, tensor_index, column, operand.size(),
            [&](std::span<const Fq> values, std::size_t offset) {
                for (std::size_t index = 0; index < values.size(); ++index) {
                    result += weight * values[index] *
                              operand[offset + index];
                }
            }, report);
    }
    return result;
}

std::vector<Fq2> weighted_tensor_table(
    const FactoredMatrixProverKey &key, std::size_t tensor_index,
    std::span<const Fq2> weights, std::size_t evaluation_count,
    FactoredMatrixExternalProvingReport *report) {
    std::vector<Fq2> result(evaluation_count, Fq2::zero());
    for (std::size_t column = 0; column < weights.size(); ++column) {
        const Fq2 &weight = weights[column];
        if (weight.is_zero()) {
            continue;
        }
        for_each_column_chunk(
            key, tensor_index, column, evaluation_count,
            [&](std::span<const Fq> values, std::size_t offset) {
                for (std::size_t index = 0; index < values.size(); ++index) {
                    result[offset + index] += weight * values[index];
                }
            }, report);
    }
    return result;
}

struct ProductRound {
    Fq2 at_zero{};
    FactoredSumcheckRound transmitted{};
};

ProductRound product_round(std::span<const Fq2> tensor,
                           std::span<const Fq2> operand) {
    if (tensor.size() != operand.size() || tensor.size() < 2 ||
        (tensor.size() & 1U) != 0) {
        throw std::invalid_argument(
            "factored product sumcheck state is malformed");
    }
    ProductRound result;
    for (std::size_t index = 0; index < tensor.size(); index += 2U) {
        const Fq2 &a0 = tensor[index];
        const Fq2 &a1 = tensor[index + 1U];
        const Fq2 &b0 = operand[index];
        const Fq2 &b1 = operand[index + 1U];
        result.at_zero += a0 * b0;
        result.transmitted.evaluations[0] += a1 * b1;
        result.transmitted.evaluations[1] +=
            (a1 + a1 - a0) * (b1 + b1 - b0);
    }
    return result;
}

void fold_adjacent(std::vector<Fq2> &table, const Fq2 &challenge) {
    if (table.size() < 2 || (table.size() & 1U) != 0) {
        throw std::invalid_argument(
            "factored sumcheck table cannot be folded");
    }
    const std::size_t half = table.size() / 2U;
    for (std::size_t index = 0; index < half; ++index) {
        const Fq2 &lo = table[2U * index];
        const Fq2 &hi = table[2U * index + 1U];
        table[index] = lo + challenge * (hi - lo);
    }
    table.resize(half);
}

Fq2 interpolate_quadratic(const Fq2 &at_zero,
                          const std::array<Fq2, 2> &message,
                          const Fq2 &point) {
    const Fq2 one = Fq2::one();
    const Fq2 two = one + one;
    const Fq2 inverse_two = Fq2::from_base(Fq(2).inverse());
    const Fq2 l0 = (point - one) * (point - two) * inverse_two;
    const Fq2 l1 = point * (point - two);
    const Fq2 l2 = point * (point - one) * inverse_two;
    return at_zero * l0 - message[0] * l1 + message[1] * l2;
}

Fq2 batched_regular_evaluation(const FactoredMatrixStructure &structure,
                               std::span<const Fq2> row_point,
                               std::span<const Fq2> column_point,
                               const Fq2 &gamma) {
    const std::array<Fq2, 3> values =
        structure.regular_matrix_evaluations(row_point, column_point);
    return values[0] + gamma * values[1] + gamma * gamma * values[2];
}

Fq2 sum_claims(std::span<const Fq2> claims) {
    Fq2 result = Fq2::zero();
    for (const Fq2 &claim : claims) {
        result += claim;
    }
    return result;
}

void observe_commitment(const FactoredMatrixCommitment &commitment,
                        PublicCoin &public_coin) {
    public_coin.observe(kCommitmentLabel,
                        encode_factored_matrix_commitment(commitment));
}

void observe_statement(std::span<const Fq2> row_point,
                       std::span<const Fq2> column_point,
                       const Fq2 &gamma, const Fq2 &claim,
                       PublicCoin &public_coin) {
    std::vector<std::uint8_t> bytes;
    append_fq2_vector(bytes, row_point);
    append_fq2_vector(bytes, column_point);
    append_fq2(bytes, gamma);
    append_fq2(bytes, claim);
    public_coin.observe(kStatementLabel, bytes);
}

void observe_claims(std::span<const Fq2> claims,
                    PublicCoin &public_coin) {
    std::vector<std::uint8_t> bytes;
    append_fq2_vector(bytes, claims);
    public_coin.observe(kClaimsLabel, bytes);
}

void observe_round(std::size_t tensor_index, std::size_t round_index,
                   const FactoredSumcheckRound &round,
                   PublicCoin &public_coin) {
    std::vector<std::uint8_t> bytes;
    append_size(bytes, tensor_index);
    append_size(bytes, round_index);
    append_fq2(bytes, round.evaluations[0]);
    append_fq2(bytes, round.evaluations[1]);
    public_coin.observe(kRoundLabel, bytes);
}

void observe_terminal(std::size_t tensor_index, const Fq2 &value,
                      PublicCoin &public_coin) {
    std::vector<std::uint8_t> bytes;
    append_size(bytes, tensor_index);
    append_fq2(bytes, value);
    public_coin.observe(kTerminalLabel, bytes);
}

void observe_opening(std::size_t tensor_index,
                     const PcsOpeningProof &opening,
                     PublicCoin &public_coin) {
    std::vector<std::uint8_t> bytes;
    append_size(bytes, tensor_index);
    append_size(bytes, opening.bytes.size());
    bytes.insert(bytes.end(), opening.bytes.begin(), opening.bytes.end());
    public_coin.observe(kOpeningLabel, bytes);
}

std::size_t checked_add(std::size_t left, std::size_t right) {
    if (right > std::numeric_limits<std::size_t>::max() - left) {
        throw std::overflow_error("factored proof size overflows");
    }
    return left + right;
}

std::size_t checked_multiply(std::size_t left, std::size_t right) {
    if (left != 0 &&
        right > std::numeric_limits<std::size_t>::max() / left) {
        throw std::overflow_error("factored proof size overflows");
    }
    return left * right;
}

} // namespace

Digest factored_matrix_artifact_identity(
    const FactoredMatrixCommitment &commitment) {
    std::vector<std::uint8_t> encoding(kArtifactIdentityDomain.begin(),
                                       kArtifactIdentityDomain.end());
    const std::vector<std::uint8_t> commitment_encoding =
        encode_factored_matrix_commitment(commitment);
    encoding.insert(encoding.end(), commitment_encoding.begin(),
                    commitment_encoding.end());
    return sha256(encoding);
}

Digest factored_matrix_staging_artifact_identity(
    const FactoredMatrixStructure &structure) {
    const std::size_t tensor_count = structure.tensor_count();
    if (tensor_count == 0) {
        throw std::invalid_argument(
            "factored staging requires at least one tensor");
    }
    std::vector<std::uint8_t> encoding(
        kStagingArtifactIdentityDomain.begin(),
        kStagingArtifactIdentityDomain.end());
    append_u64(encoding, kFactoredMatrixProfileIdentifier);
    append_digest(encoding, structure.circuit_digest());
    append_digest(encoding, structure.structure_digest());
    append_u64(encoding, structure.row_variables());
    append_u64(encoding, structure.column_variables());
    append_u64(encoding,
               checked_u64(tensor_count, "factored tensor count"));
    for (std::size_t tensor_index = 0; tensor_index < tensor_count;
         ++tensor_index) {
        const FactoredTensorShape shape =
            structure.tensor_shape(tensor_index);
        if (!valid_shape(shape)) {
            throw std::invalid_argument(
                "factored structure has an invalid tensor shape");
        }
        append_u64(encoding, shape.evaluation_count);
        append_u64(encoding, shape.column_count);
    }
    return sha256(encoding);
}

std::string factored_matrix_tensor_column_array_name(
    std::size_t tensor_index, std::size_t column_index) {
    return "tensor-" + std::to_string(tensor_index) + "-column-" +
           std::to_string(column_index);
}

std::shared_ptr<const storage::NativeFieldArtifact>
open_factored_matrix_artifact(
    const std::filesystem::path &directory,
    const FactoredMatrixCommitment &commitment) {
    if (commitment.profile != kFactoredMatrixProfileIdentifier ||
        commitment.tensors.empty() ||
        std::any_of(commitment.tensors.begin(), commitment.tensors.end(),
                    [](const FactoredTensorCommitment &tensor) {
                        return !valid_shape(tensor.shape);
                    })) {
        throw std::invalid_argument(
            "cannot open an artifact for an invalid factored commitment");
    }
    auto artifact = std::make_shared<storage::NativeFieldArtifact>(
        storage::NativeFieldArtifact::open(
            directory, factored_matrix_artifact_identity(commitment)));
    validate_artifact_layout(*artifact, commitment);
    return artifact;
}

std::shared_ptr<const storage::NativeFieldArtifact>
open_factored_matrix_staging_artifact(
    const std::filesystem::path &directory,
    const FactoredMatrixStructure &structure) {
    auto artifact = std::make_shared<storage::NativeFieldArtifact>(
        storage::NativeFieldArtifact::open(
            directory,
            factored_matrix_staging_artifact_identity(structure)));
    validate_staging_artifact_layout(*artifact, structure);
    return artifact;
}

namespace {

FactoredMatrixSetup preprocess_factored_matrix_impl(
    std::shared_ptr<const FactoredMatrixStructure> structure,
    std::vector<std::vector<std::vector<Fq>>> tensors,
    const IPCS &pcs,
    const FactoredMatrixArtifactOptions *artifact_options) {
    const auto *basefold = dynamic_cast<const BaseFoldPcs *>(&pcs);
    if (structure == nullptr || basefold == nullptr ||
        basefold->parameters().log_rate == 0 ||
        tensors.size() != structure->tensor_count()) {
        throw std::invalid_argument(
            "factored preprocessing requires a matching structure and "
            "positive-rate BaseFold");
    }
    (void)checked_u64(tensors.size(), "factored tensor count");

    FactoredMatrixCommitment commitment{
        .profile = kFactoredMatrixProfileIdentifier,
        .circuit_digest = structure->circuit_digest(),
        .structure_digest = structure->structure_digest(),
        .row_variables = structure->row_variables(),
        .column_variables = structure->column_variables(),
    };
    commitment.tensors.reserve(tensors.size());

    std::vector<FactoredTensorProverKey> prover_tensors;
    prover_tensors.reserve(tensors.size());
    for (std::size_t tensor_index = 0; tensor_index < tensors.size();
         ++tensor_index) {
        const FactoredTensorShape shape =
            structure->tensor_shape(tensor_index);
        if (!valid_shape(shape)) {
            throw std::invalid_argument(
                "factored structure has an invalid tensor shape");
        }
        const std::size_t width =
            checked_size(shape.column_count, "factored tensor width");
        const std::size_t evaluation_count = checked_size(
            shape.evaluation_count, "factored tensor evaluation count");
        std::vector<std::vector<Fq>> &columns = tensors[tensor_index];
        if (columns.size() != width) {
            throw std::invalid_argument(
                "factored tensor has the wrong column count");
        }
        for (const std::vector<Fq> &column : columns) {
            if (column.size() != evaluation_count) {
                throw std::invalid_argument(
                    "factored tensor column has the wrong length");
            }
        }

        IPCS::CommitOutput committed = pcs.commit_columns(columns);
        FactoredTensorCommitment tensor_commitment{
            .shape = shape,
            .columns = committed.commitment,
        };
        if (!valid_pcs_commitment(tensor_commitment, pcs)) {
            throw std::logic_error(
                "factored preprocessing produced invalid PCS metadata");
        }
        commitment.tensors.push_back(std::move(tensor_commitment));
        FactoredTensorProverKey prover_tensor{
            .opening_state = std::move(committed.prover_state),
        };
        if (artifact_options == nullptr) {
            prover_tensor.columns = std::move(columns);
        }
        prover_tensors.push_back(std::move(prover_tensor));
    }
    if (!valid_internal_commitment(commitment, *structure, pcs)) {
        throw std::logic_error(
            "factored preprocessing produced inconsistent metadata");
    }

    std::shared_ptr<const storage::NativeFieldArtifact> artifact;
    if (artifact_options != nullptr) {
        storage::NativeFieldArtifactWriter writer(
            artifact_options->directory, artifact_options->limits,
            factored_matrix_artifact_identity(commitment));
        for (std::size_t tensor_index = 0; tensor_index < tensors.size();
             ++tensor_index) {
            for (std::size_t column = 0;
                 column < tensors[tensor_index].size(); ++column) {
                const std::vector<Fq> &values =
                    tensors[tensor_index][column];
                writer.begin_array(
                    factored_matrix_tensor_column_array_name(tensor_index,
                                                              column),
                    storage::NativeFieldElementKind::Fq,
                    checked_u64(values.size(), "factored column length"));
                writer.append(values);
                writer.finish_array();
            }
        }
        (void)writer.finish();
        artifact = open_factored_matrix_artifact(
            artifact_options->directory, commitment);
    }

    FactoredMatrixSetup result;
    result.verifier_key.commitment = commitment;
    result.verifier_key.structure = structure;
    result.prover_key.commitment = std::move(commitment);
    result.prover_key.structure = std::move(structure);
    result.prover_key.tensors = std::move(prover_tensors);
    if (artifact != nullptr) {
        result.prover_key.tensor_column_source =
            FactoredTensorColumnSource::Artifact;
        result.prover_key.tensor_columns_artifact = std::move(artifact);
    }
    return result;
}

} // namespace

FactoredMatrixSetup preprocess_factored_matrix(
    std::shared_ptr<const FactoredMatrixStructure> structure,
    std::vector<std::vector<std::vector<Fq>>> tensors,
    const IPCS &pcs) {
    return preprocess_factored_matrix_impl(
        std::move(structure), std::move(tensors), pcs, nullptr);
}

FactoredMatrixSetup preprocess_factored_matrix_to_artifact(
    std::shared_ptr<const FactoredMatrixStructure> structure,
    std::vector<std::vector<std::vector<Fq>>> tensors,
    const IPCS &pcs, FactoredMatrixArtifactOptions options) {
    return preprocess_factored_matrix_impl(
        std::move(structure), std::move(tensors), pcs, &options);
}

namespace {

std::uint64_t storage_add(std::uint64_t left, std::uint64_t right,
                          const char *label) {
    if (right > std::numeric_limits<std::uint64_t>::max() - left) {
        throw std::overflow_error(std::string(label) + " overflows");
    }
    return left + right;
}

std::uint64_t storage_multiply(std::uint64_t left,
                               std::uint64_t right,
                               const char *label) {
    if (left != 0 &&
        right > std::numeric_limits<std::uint64_t>::max() / left) {
        throw std::overflow_error(std::string(label) + " overflows");
    }
    return left * right;
}

std::filesystem::path external_normalized_path(
    const std::filesystem::path &path, const char *label) {
    if (path.empty()) {
        throw std::invalid_argument(std::string(label) + " path is empty");
    }
    const std::filesystem::file_status status =
        std::filesystem::symlink_status(path);
    if (!std::filesystem::is_directory(status) ||
        std::filesystem::is_symlink(status)) {
        throw std::invalid_argument(std::string(label) +
                                    " must be a real directory");
    }
    return std::filesystem::canonical(path);
}

void validate_empty_external_directory(
    const std::filesystem::path &directory, const char *label) {
    if (!std::filesystem::is_empty(directory)) {
        throw std::invalid_argument(std::string(label) +
                                    " must be empty");
    }
}

bool external_path_prefix(const std::filesystem::path &prefix,
                          const std::filesystem::path &path) {
    auto prefix_part = prefix.begin();
    auto path_part = path.begin();
    while (prefix_part != prefix.end() && path_part != path.end() &&
           *prefix_part == *path_part) {
        ++prefix_part;
        ++path_part;
    }
    return prefix_part == prefix.end();
}

bool existing_paths_equivalent(const std::filesystem::path &left,
                               const std::filesystem::path &right) {
    std::error_code error;
    const bool equivalent =
        std::filesystem::equivalent(left, right, error);
    if (error) {
        throw std::filesystem::filesystem_error(
            "failed to compare factored storage paths", left, right,
            error);
    }
    return equivalent;
}

bool same_storage_device(const std::filesystem::path &left,
                         const std::filesystem::path &right) {
#ifdef _WIN32
    return left.root_name() == right.root_name();
#else
    struct stat left_status {};
    struct stat right_status {};
    if (::stat(left.c_str(), &left_status) != 0) {
        throw std::filesystem::filesystem_error(
            "failed to inspect factored storage device", left,
            std::error_code(errno, std::generic_category()));
    }
    if (::stat(right.c_str(), &right_status) != 0) {
        throw std::filesystem::filesystem_error(
            "failed to inspect factored storage device", right,
            std::error_code(errno, std::generic_category()));
    }
    return left_status.st_dev == right_status.st_dev;
#endif
}

std::filesystem::path validate_quarantine_directory(
    const std::filesystem::path &requested,
    const std::filesystem::path &staging_directory) {
    const std::filesystem::path root = external_normalized_path(
        requested, "factored staging quarantine");
    validate_empty_external_directory(
        root, "factored staging quarantine");
    if (!same_storage_device(root, staging_directory)) {
        throw std::invalid_argument(
            "factored staging quarantine must share the staging device");
    }
#ifndef _WIN32
    struct stat status {};
    if (::stat(root.c_str(), &status) != 0) {
        throw std::filesystem::filesystem_error(
            "failed to inspect factored quarantine ownership", root,
            std::error_code(errno, std::generic_category()));
    }
    if (status.st_uid != ::geteuid() ||
        (status.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
        throw std::invalid_argument(
            "factored staging quarantine must be owner-private");
    }
#endif
    return root / "staging-artifact";
}

void rename_directory_no_replace(const std::filesystem::path &source,
                                 const std::filesystem::path &target) {
#ifdef __APPLE__
    if (::renamex_np(source.c_str(), target.c_str(), RENAME_EXCL) != 0) {
        throw std::filesystem::filesystem_error(
            "failed to quarantine factored staging without replacement",
            source, target,
            std::error_code(errno, std::generic_category()));
    }
#elif defined(__linux__)
    if (::syscall(SYS_renameat2, AT_FDCWD, source.c_str(), AT_FDCWD,
                  target.c_str(), RENAME_NOREPLACE) != 0) {
        throw std::filesystem::filesystem_error(
            "failed to quarantine factored staging without replacement",
            source, target,
            std::error_code(errno, std::generic_category()));
    }
#else
    // Windows rename does not replace an existing directory. Other fallback
    // platforms rely on the documented caller-owned private-namespace
    // noninterference contract, with this final absence check as a guard.
    if (std::filesystem::exists(target)) {
        throw std::filesystem::filesystem_error(
            "factored staging quarantine target already exists", target,
            std::make_error_code(std::errc::file_exists));
    }
    std::filesystem::rename(source, target);
#endif
}

std::uint64_t directory_regular_bytes(
    const std::filesystem::path &directory) {
    std::uint64_t bytes = 0;
    for (const auto &entry :
         std::filesystem::recursive_directory_iterator(directory)) {
        if (entry.is_regular_file()) {
            bytes = storage_add(bytes, entry.file_size(),
                                "factored directory bytes");
        }
    }
    return bytes;
}

class FactoredExternalOutputCleanup {
  public:
    explicit FactoredExternalOutputCleanup(
        std::vector<std::filesystem::path> roots)
        : roots_(std::move(roots)) {}

    FactoredExternalOutputCleanup(
        const FactoredExternalOutputCleanup &) = delete;
    FactoredExternalOutputCleanup &operator=(
        const FactoredExternalOutputCleanup &) = delete;

    ~FactoredExternalOutputCleanup() {
        if (!armed_) {
            return;
        }
        for (const std::filesystem::path &root : roots_) {
            std::error_code iteration_error;
            std::filesystem::directory_iterator entry(root,
                                                       iteration_error);
            const std::filesystem::directory_iterator end;
            while (!iteration_error && entry != end) {
                const std::filesystem::path child = entry->path();
                entry.increment(iteration_error);
                std::error_code ignored;
                std::filesystem::remove_all(child, ignored);
            }
        }
    }

    void clear() {
        for (const std::filesystem::path &root : roots_) {
            for (auto entry = std::filesystem::directory_iterator(root);
                 entry != std::filesystem::directory_iterator();) {
                const std::filesystem::path child = entry->path();
                ++entry;
                std::filesystem::remove_all(child);
            }
            if (!std::filesystem::is_empty(root)) {
                throw std::runtime_error(
                    "factored external output cleanup is incomplete");
            }
        }
        armed_ = false;
    }

    void disarm() { armed_ = false; }

  private:
    std::vector<std::filesystem::path> roots_;
    bool armed_ = true;
};

void add_basefold_report(
    FactoredMatrixExternalPreprocessingReport &aggregate,
    const BaseFoldExternalCommitReport &report) {
    aggregate.external_states_physical_bytes = storage_add(
        aggregate.external_states_physical_bytes,
        report.final_physical_bytes, "external state bytes");
    aggregate.basefold_artifact_validation_bytes = storage_add(
        aggregate.basefold_artifact_validation_bytes,
        report.artifact_validation_bytes,
        "BaseFold artifact validation bytes");
    aggregate.basefold_sequential_read_payload_bytes = storage_add(
        aggregate.basefold_sequential_read_payload_bytes,
        report.sequential_read_payload_bytes,
        "BaseFold sequential read bytes");
    aggregate.basefold_indexed_read_payload_bytes = storage_add(
        aggregate.basefold_indexed_read_payload_bytes,
        report.indexed_read_payload_bytes,
        "BaseFold indexed read bytes");
    aggregate.basefold_sequential_write_payload_bytes = storage_add(
        aggregate.basefold_sequential_write_payload_bytes,
        report.sequential_write_payload_bytes,
        "BaseFold sequential write bytes");
    aggregate.basefold_indexed_write_payload_bytes = storage_add(
        aggregate.basefold_indexed_write_payload_bytes,
        report.indexed_write_payload_bytes,
        "BaseFold indexed write bytes");
    aggregate.basefold_scratch_peak_physical_bytes = std::max(
        aggregate.basefold_scratch_peak_physical_bytes,
        report.scratch_peak_physical_bytes);
    aggregate.basefold_scratch_written_physical_bytes = storage_add(
        aggregate.basefold_scratch_written_physical_bytes,
        report.scratch_written_physical_bytes,
        "BaseFold scratch written bytes");
    aggregate.basefold_scratch_deleted_physical_bytes = storage_add(
        aggregate.basefold_scratch_deleted_physical_bytes,
        report.scratch_deleted_physical_bytes,
        "BaseFold scratch deleted bytes");
    aggregate.peak_working_field_bytes = std::max(
        aggregate.peak_working_field_bytes,
        report.peak_working_field_bytes);
}

} // namespace

FactoredMatrixExternalPreprocessingPlan
plan_factored_matrix_external_preprocessing(
    const FactoredMatrixStructure &structure, const BaseFoldPcs &pcs,
    FactoredMatrixExternalPreprocessingPlanningOptions options) {
    if (pcs.parameters().log_rate == 0 || structure.tensor_count() == 0 ||
        options.staging_physical_bytes == 0 ||
        options.copy_block_elements == 0 ||
        options.tensor_commitment_block_elements.size() !=
            structure.tensor_count() ||
        std::ranges::any_of(
            options.tensor_commitment_block_elements,
            [](std::size_t block) { return block == 0; })) {
        throw std::invalid_argument(
            "factored preprocessing planning needs matching tensors, "
            "positive-rate BaseFold, and nonzero streaming blocks");
    }

    FactoredMatrixExternalPreprocessingPlan result{
        .staging_physical_bytes = options.staging_physical_bytes,
    };
    std::vector<storage::NativeFieldArrayLayout> canonical_layout;
    std::size_t maximum_evaluation_count = 0;
    result.tensors.reserve(structure.tensor_count());
    for (std::size_t tensor_index = 0;
         tensor_index < structure.tensor_count(); ++tensor_index) {
        const FactoredTensorShape shape =
            structure.tensor_shape(tensor_index);
        if (!valid_shape(shape)) {
            throw std::invalid_argument(
                "factored structure has an invalid tensor shape");
        }
        const std::size_t width =
            checked_size(shape.column_count, "factored tensor width");
        const std::size_t evaluation_count = checked_size(
            shape.evaluation_count, "factored tensor evaluation count");
        maximum_evaluation_count =
            std::max(maximum_evaluation_count, evaluation_count);

        FactoredTensorExternalPreprocessingPlan tensor_plan{
            .shape = shape,
        };
        tensor_plan.column_names.reserve(width);
        for (std::size_t column = 0; column < width; ++column) {
            std::string name = factored_matrix_tensor_column_array_name(
                tensor_index, column);
            tensor_plan.column_names.push_back(name);
            canonical_layout.push_back({
                std::move(name),
                storage::NativeFieldElementKind::Fq,
                shape.evaluation_count,
            });
            result.tensor_payload_bytes = storage_add(
                result.tensor_payload_bytes,
                storage_multiply(shape.evaluation_count,
                                 kSerializedFqBytes,
                                 "factored tensor payload"),
                "factored tensor payload");
        }
        tensor_plan.commitment = pcs.plan_external_commit_storage(
            evaluation_count, width, false,
            std::numeric_limits<std::uint64_t>::max(),
            options.tensor_commitment_block_elements[tensor_index]);
        result.external_states_physical_bytes = storage_add(
            result.external_states_physical_bytes,
            tensor_plan.commitment.final_physical_bytes,
            "factored external state bytes");
        result.peak_working_field_bytes = std::max(
            result.peak_working_field_bytes,
            tensor_plan.commitment.peak_working_field_bytes);
        result.tensors.push_back(std::move(tensor_plan));
    }

    result.canonical_artifact_physical_bytes =
        storage::native_field_artifact_physical_bytes(canonical_layout);
    if (result.staging_physical_bytes !=
        result.canonical_artifact_physical_bytes) {
        throw std::invalid_argument(
            "factored staging bytes do not match the canonical tensor "
            "layout");
    }
    result.effective_copy_block_elements = std::min(
        options.copy_block_elements, maximum_evaluation_count);
    result.peak_copy_working_field_bytes = storage_multiply(
        checked_u64(result.effective_copy_block_elements,
                    "factored copy block"),
        2U * sizeof(Fq), "factored copy field bytes");
    result.peak_working_field_bytes = std::max(
        result.peak_working_field_bytes,
        result.peak_copy_working_field_bytes);
    result.persistent_output_physical_bytes = storage_add(
        result.canonical_artifact_physical_bytes,
        result.external_states_physical_bytes,
        "factored persistent output bytes");

    std::uint64_t accumulated_states = 0;
    result.conservative_peak_live_physical_bytes =
        result.staging_physical_bytes;
    for (const FactoredTensorExternalPreprocessingPlan &tensor :
         result.tensors) {
        const std::uint64_t phase_peak = storage_add(
            storage_add(
                storage_add(result.staging_physical_bytes,
                            accumulated_states,
                            "factored live staging and prior states"),
                tensor.commitment.final_physical_bytes,
                "factored live current state"),
            tensor.commitment.scratch_peak_physical_bytes,
            "factored conservative scratch peak");
        result.conservative_peak_live_physical_bytes = std::max(
            result.conservative_peak_live_physical_bytes, phase_peak);
        accumulated_states = storage_add(
            accumulated_states,
            tensor.commitment.final_physical_bytes,
            "factored accumulated states");
    }
    result.conservative_peak_live_physical_bytes = std::max(
        result.conservative_peak_live_physical_bytes,
        storage_add(
            storage_add(result.staging_physical_bytes,
                        accumulated_states,
                        "factored live setup before canonical copy"),
            result.canonical_artifact_physical_bytes,
            "factored live canonical copy"));
    return result;
}

FactoredMatrixExternalPreprocessing preprocess_factored_matrix_external(
    std::shared_ptr<const FactoredMatrixStructure> structure,
    std::shared_ptr<const storage::NativeFieldArtifact> staging_artifact,
    const BaseFoldPcs &pcs,
    FactoredMatrixExternalPreprocessingOptions options) {
    if (structure == nullptr || staging_artifact == nullptr ||
        pcs.parameters().log_rate == 0 ||
        structure->tensor_count() == 0 ||
        options.tensor_commitments.size() != structure->tensor_count() ||
        options.tensor_columns_artifact.limits.max_total_bytes == 0 ||
        options.tensor_columns_artifact.limits.min_free_bytes == 0 ||
        options.max_live_physical_bytes == 0 ||
        options.max_copy_working_field_bytes == 0 ||
        options.copy_block_elements == 0) {
        throw std::invalid_argument(
            "factored external preprocessing needs matching tensors, "
            "positive-rate BaseFold, and explicit nonzero limits");
    }
    const bool quarantine_staging =
        options.staging_ownership ==
        FactoredMatrixStagingOwnership::MoveToQuarantineOnSuccess;
    if (options.staging_ownership !=
            FactoredMatrixStagingOwnership::Retain &&
        !quarantine_staging) {
        throw std::invalid_argument(
            "unknown factored staging ownership mode");
    }
    if (quarantine_staging && staging_artifact.use_count() != 1) {
        throw std::invalid_argument(
            "moving factored staging requires sole shared ownership");
    }
    if (!quarantine_staging &&
        !options.staging_quarantine_directory.empty()) {
        throw std::invalid_argument(
            "retained factored staging must not name a quarantine path");
    }

    const std::filesystem::path staging_directory =
        external_normalized_path(staging_artifact->directory(),
                                 "factored staging");
    // Reopen at the API boundary so corruption after an earlier open is
    // detected before any output is written.
    staging_artifact.reset();
    staging_artifact = open_factored_matrix_staging_artifact(
        staging_directory, *structure);

    std::vector<std::size_t> tensor_blocks;
    tensor_blocks.reserve(options.tensor_commitments.size());
    for (const BaseFoldExternalCommitOptions &tensor :
         options.tensor_commitments) {
        tensor_blocks.push_back(tensor.block_elements);
    }
    const FactoredMatrixExternalPreprocessingPlan plan =
        plan_factored_matrix_external_preprocessing(
            *structure, pcs,
            {
                .staging_physical_bytes =
                    staging_artifact->physical_bytes(),
                .copy_block_elements = options.copy_block_elements,
                .tensor_commitment_block_elements =
                    std::move(tensor_blocks),
            });

    FactoredMatrixExternalPreprocessingReport report{
        .staging_physical_bytes = plan.staging_physical_bytes,
        .staging_validation_bytes = plan.staging_physical_bytes,
        .tensor_payload_bytes = plan.tensor_payload_bytes,
        .canonical_artifact_physical_bytes = 0,
        .external_states_physical_bytes = 0,
        .persistent_output_physical_bytes = 0,
        .max_live_physical_bytes = options.max_live_physical_bytes,
        .conservative_peak_live_physical_bytes =
            plan.conservative_peak_live_physical_bytes,
        .peak_copy_working_field_bytes =
            plan.peak_copy_working_field_bytes,
        .peak_working_field_bytes =
            plan.peak_copy_working_field_bytes,
    };
    const std::uint64_t expected_canonical_physical =
        plan.canonical_artifact_physical_bytes;
    if (options.tensor_columns_artifact.limits.max_total_bytes <
        expected_canonical_physical) {
        throw std::invalid_argument(
            "factored canonical-artifact quota is below its exact size");
    }
    if (options.max_copy_working_field_bytes <
        plan.peak_copy_working_field_bytes) {
        throw std::invalid_argument(
            "factored copy field-memory limit cannot hold two Fq values");
    }
    const std::size_t copy_block_elements =
        plan.effective_copy_block_elements;

    options.tensor_columns_artifact.directory =
        external_normalized_path(
            options.tensor_columns_artifact.directory,
            "factored canonical artifact");
    validate_empty_external_directory(
        options.tensor_columns_artifact.directory,
        "factored canonical artifact");
    const std::filesystem::path quarantine_artifact_path =
        quarantine_staging
            ? validate_quarantine_directory(
                  options.staging_quarantine_directory,
                  staging_directory)
            : std::filesystem::path{};

    std::vector<std::filesystem::path> all_paths;
    std::vector<std::filesystem::path> output_roots;
    all_paths.reserve(3U + 2U * options.tensor_commitments.size());
    output_roots.reserve(1U + 2U * options.tensor_commitments.size());
    all_paths.push_back(staging_directory);
    all_paths.push_back(options.tensor_columns_artifact.directory);
    if (quarantine_staging) {
        all_paths.push_back(quarantine_artifact_path.parent_path());
    }
    output_roots.push_back(options.tensor_columns_artifact.directory);
    for (std::size_t tensor_index = 0;
         tensor_index < options.tensor_commitments.size();
         ++tensor_index) {
        BaseFoldExternalCommitOptions &tensor_options =
            options.tensor_commitments[tensor_index];
        if (tensor_options.max_final_bytes == 0 ||
            tensor_options.max_scratch_bytes == 0 ||
            tensor_options.min_free_bytes == 0 ||
            tensor_options.max_working_field_bytes == 0 ||
            tensor_options.block_elements == 0) {
            throw std::invalid_argument(
                "factored tensor commitment limits must be nonzero");
        }
        const BaseFoldExternalCommitStoragePlan &required =
            plan.tensors[tensor_index].commitment;
        if (tensor_options.max_final_bytes <
                required.final_physical_bytes ||
            tensor_options.max_scratch_bytes <
                required.scratch_peak_physical_bytes ||
            tensor_options.max_working_field_bytes <
                required.peak_working_field_bytes) {
            throw std::invalid_argument(
                "factored tensor BaseFold limits are below the exact plan");
        }
        tensor_options.destination_directory = external_normalized_path(
            tensor_options.destination_directory,
            "factored tensor destination");
        tensor_options.scratch_directory = external_normalized_path(
            tensor_options.scratch_directory,
            "factored tensor scratch");
        validate_empty_external_directory(
            tensor_options.destination_directory,
            "factored tensor destination");
        validate_empty_external_directory(
            tensor_options.scratch_directory,
            "factored tensor scratch");
        all_paths.push_back(tensor_options.destination_directory);
        all_paths.push_back(tensor_options.scratch_directory);
        output_roots.push_back(tensor_options.destination_directory);
        output_roots.push_back(tensor_options.scratch_directory);
    }
    for (std::size_t left = 0; left < all_paths.size(); ++left) {
        for (std::size_t right = left + 1U; right < all_paths.size();
             ++right) {
            if (external_path_prefix(all_paths[left], all_paths[right]) ||
                external_path_prefix(all_paths[right], all_paths[left]) ||
                existing_paths_equivalent(all_paths[left],
                                          all_paths[right])) {
                throw std::invalid_argument(
                    "factored staging, canonical, destination, and scratch "
                    "directories must be disjoint");
            }
        }
    }
    if (options.max_live_physical_bytes <
        plan.conservative_peak_live_physical_bytes) {
        throw std::invalid_argument(
            "factored global live-storage quota is below the conservative "
            "peak");
    }

    std::uint64_t canonical_device_states = 0;
    for (std::size_t tensor_index = 0;
         tensor_index < options.tensor_commitments.size();
         ++tensor_index) {
        if (same_storage_device(
                options.tensor_columns_artifact.directory,
                options.tensor_commitments[tensor_index]
                    .destination_directory)) {
            canonical_device_states = storage_add(
                canonical_device_states,
                plan.tensors[tensor_index]
                    .commitment.final_physical_bytes,
                "canonical-device BaseFold states");
        }
    }
    const std::uint64_t canonical_required_free = storage_add(
        storage_add(expected_canonical_physical,
                    canonical_device_states,
                    "canonical publication and prior states"),
        options.tensor_columns_artifact.limits.min_free_bytes,
        "canonical free-space reserve");
    if (std::filesystem::space(
            options.tensor_columns_artifact.directory).available <
        canonical_required_free) {
        throw std::runtime_error(
            "factored canonical artifact has insufficient preflight free "
            "space");
    }

    FactoredExternalOutputCleanup cleanup(std::move(output_roots));
    try {
        FactoredMatrixCommitment commitment{
            .profile = kFactoredMatrixProfileIdentifier,
            .circuit_digest = structure->circuit_digest(),
            .structure_digest = structure->structure_digest(),
            .row_variables = structure->row_variables(),
            .column_variables = structure->column_variables(),
        };
        commitment.tensors.reserve(structure->tensor_count());
        std::vector<FactoredTensorProverKey> prover_tensors;
        prover_tensors.reserve(structure->tensor_count());
        report.tensors.reserve(structure->tensor_count());

        for (std::size_t tensor_index = 0;
             tensor_index < structure->tensor_count(); ++tensor_index) {
            const FactoredTensorShape shape =
                structure->tensor_shape(tensor_index);
            BaseFoldExternalCommitment committed =
                pcs.commit_artifact_columns(
                    staging_artifact,
                    plan.tensors[tensor_index].column_names,
                    options.tensor_commitments[tensor_index]);
            if (committed.report.final_physical_bytes !=
                    plan.tensors[tensor_index].commitment
                        .final_physical_bytes ||
                committed.report.scratch_peak_physical_bytes !=
                    plan.tensors[tensor_index].commitment
                        .scratch_peak_physical_bytes ||
                committed.report.peak_working_field_bytes !=
                    plan.tensors[tensor_index].commitment
                        .peak_working_field_bytes) {
                throw std::logic_error(
                    "factored BaseFold storage estimate disagrees with "
                    "output");
            }
            FactoredTensorCommitment tensor_commitment{
                .shape = shape,
                .columns = committed.externalization.commitment,
            };
            if (!valid_pcs_commitment(tensor_commitment, pcs)) {
                throw std::logic_error(
                    "external factored preprocessing produced invalid PCS "
                    "metadata");
            }
            commitment.tensors.push_back(std::move(tensor_commitment));
            prover_tensors.push_back({
                .columns = {},
                .opening_state =
                    committed.externalization.prover_state,
                .opening_state_source =
                    FactoredTensorProverKey::OpeningStateSource::External,
            });
            add_basefold_report(report, committed.report);
            report.tensors.push_back({
                .shape = shape,
                .external_state_identity =
                    committed.externalization.artifact_identity,
                .external_state = committed.externalization.report,
                .commitment = std::move(committed.report),
            });
        }
        if (!valid_internal_commitment(commitment, *structure, pcs)) {
            throw std::logic_error(
                "external factored preprocessing produced inconsistent "
                "metadata");
        }

        storage::NativeFieldArtifactWriter canonical_writer(
            options.tensor_columns_artifact.directory,
            options.tensor_columns_artifact.limits,
            factored_matrix_artifact_identity(commitment));
        std::vector<Fq> copy_buffer(copy_block_elements);
        for (std::size_t tensor_index = 0;
             tensor_index < commitment.tensors.size(); ++tensor_index) {
            const FactoredTensorShape shape =
                commitment.tensors[tensor_index].shape;
            const std::size_t width = checked_size(
                shape.column_count, "factored tensor width");
            const std::size_t evaluation_count = checked_size(
                shape.evaluation_count,
                "factored tensor evaluation count");
            for (std::size_t column = 0; column < width; ++column) {
                const std::string &name =
                    plan.tensors[tensor_index].column_names[column];
                storage::NativeFieldArrayReader reader =
                    staging_artifact->open_array(name);
                canonical_writer.begin_array(
                    name, storage::NativeFieldElementKind::Fq,
                    shape.evaluation_count);
                std::size_t copied = 0;
                while (copied < evaluation_count) {
                    const std::size_t requested = std::min(
                        copy_buffer.size(), evaluation_count - copied);
                    const std::size_t count = reader.read(
                        std::span<Fq>(copy_buffer).first(requested));
                    if (count != requested) {
                        throw std::runtime_error(
                            "factored staging array ended early");
                    }
                    canonical_writer.append(
                        std::span<const Fq>(copy_buffer).first(count));
                    const std::uint64_t bytes = storage_multiply(
                        checked_u64(count, "factored copied elements"),
                        kSerializedFqBytes, "factored copied bytes");
                    report.canonical_copy_read_payload_bytes = storage_add(
                        report.canonical_copy_read_payload_bytes, bytes,
                        "factored copy read bytes");
                    report.canonical_copy_write_payload_bytes = storage_add(
                        report.canonical_copy_write_payload_bytes, bytes,
                        "factored copy write bytes");
                    report.canonical_copy_read_operations = storage_add(
                        report.canonical_copy_read_operations, 1U,
                        "factored copy read operations");
                    report.canonical_copy_write_operations = storage_add(
                        report.canonical_copy_write_operations, 1U,
                        "factored copy write operations");
                    copied += count;
                }
                if (reader.position() != reader.size()) {
                    throw std::runtime_error(
                        "factored staging array has trailing elements");
                }
                canonical_writer.finish_array();
            }
        }
        const storage::NativeFieldArtifactWriteResult canonical_written =
            canonical_writer.finish();
        if (canonical_written.physical_bytes !=
            expected_canonical_physical) {
            throw std::logic_error(
                "factored canonical storage preflight disagrees with "
                "output");
        }
        report.canonical_artifact_physical_bytes =
            canonical_written.physical_bytes;
        std::shared_ptr<const storage::NativeFieldArtifact>
            canonical_artifact = open_factored_matrix_artifact(
                options.tensor_columns_artifact.directory, commitment);
        report.canonical_artifact_validation_bytes =
            canonical_artifact->physical_bytes();
        std::vector<Fq> comparison_buffer(copy_block_elements);
        for (std::size_t tensor_index = 0;
             tensor_index < commitment.tensors.size(); ++tensor_index) {
            const FactoredTensorShape shape =
                commitment.tensors[tensor_index].shape;
            const std::size_t width = checked_size(
                shape.column_count, "factored tensor width");
            const std::size_t evaluation_count = checked_size(
                shape.evaluation_count,
                "factored tensor evaluation count");
            for (std::size_t column = 0; column < width; ++column) {
                const std::string &name =
                    plan.tensors[tensor_index].column_names[column];
                storage::NativeFieldArrayReader staging_reader =
                    staging_artifact->open_array(name);
                storage::NativeFieldArrayReader canonical_reader =
                    canonical_artifact->open_array(name);
                std::size_t compared = 0;
                while (compared < evaluation_count) {
                    const std::size_t requested = std::min(
                        copy_buffer.size(), evaluation_count - compared);
                    const std::size_t staging_count = staging_reader.read(
                        std::span<Fq>(copy_buffer).first(requested));
                    const std::size_t canonical_count = canonical_reader.read(
                        std::span<Fq>(comparison_buffer).first(requested));
                    if (staging_count != requested ||
                        canonical_count != requested ||
                        !std::equal(copy_buffer.begin(),
                                    copy_buffer.begin() + requested,
                                    comparison_buffer.begin())) {
                        throw std::runtime_error(
                            "factored canonical tensor content mismatch");
                    }
                    const std::uint64_t bytes = storage_multiply(
                        checked_u64(requested,
                                    "factored compared elements"),
                        2U * kSerializedFqBytes,
                        "factored comparison read bytes");
                    report.canonical_comparison_read_payload_bytes =
                        storage_add(
                            report.canonical_comparison_read_payload_bytes,
                            bytes, "factored comparison read bytes");
                    report.canonical_comparison_read_operations =
                        storage_add(
                            report.canonical_comparison_read_operations, 2U,
                            "factored comparison read operations");
                    compared += requested;
                }
                if (staging_reader.position() != staging_reader.size() ||
                    canonical_reader.position() != canonical_reader.size()) {
                    throw std::runtime_error(
                        "factored canonical comparison has trailing data");
                }
            }
        }

        FactoredMatrixSetup setup;
        setup.verifier_key.commitment = commitment;
        setup.verifier_key.structure = structure;
        setup.prover_key.commitment = commitment;
        setup.prover_key.structure = structure;
        setup.prover_key.tensors = std::move(prover_tensors);
        setup.prover_key.tensor_column_source =
            FactoredTensorColumnSource::Artifact;
        setup.prover_key.tensor_columns_artifact =
            std::move(canonical_artifact);

        report.persistent_output_physical_bytes = storage_add(
            report.canonical_artifact_physical_bytes,
            report.external_states_physical_bytes,
            "factored persistent output bytes");
        if (report.external_states_physical_bytes !=
                plan.external_states_physical_bytes ||
            report.persistent_output_physical_bytes !=
                plan.persistent_output_physical_bytes ||
            report.peak_working_field_bytes !=
                plan.peak_working_field_bytes) {
            throw std::logic_error(
                "factored execution differs from its preprocessing plan");
        }
        for (const BaseFoldExternalCommitOptions &tensor_options :
             options.tensor_commitments) {
            if (!std::filesystem::is_empty(
                    tensor_options.scratch_directory)) {
                throw std::runtime_error(
                    "factored BaseFold scratch cleanup is incomplete");
            }
        }
        const std::uint64_t final_staging_bytes =
            staging_artifact->physical_bytes();
        report.final_live_physical_bytes = storage_add(
            report.persistent_output_physical_bytes, final_staging_bytes,
            "factored final live bytes");
        if (report.final_live_physical_bytes >
                report.conservative_peak_live_physical_bytes ||
            report.conservative_peak_live_physical_bytes >
                report.max_live_physical_bytes) {
            throw std::logic_error(
                "factored live-storage accounting is inconsistent");
        }
        if (quarantine_staging) {
            report.quarantined_staging_physical_bytes =
                final_staging_bytes;
            report.staging_quarantine_artifact_path =
                quarantine_artifact_path;
            staging_artifact.reset();
            // The move is atomic on the required same-device namespace and
            // must fail if the target appeared after preflight. Once it
            // succeeds, deletion belongs to the caller.
            rename_directory_no_replace(staging_directory,
                                        quarantine_artifact_path);
        } else {
            report.retained_staging_physical_bytes = final_staging_bytes;
        }
        cleanup.disarm();
        return {
            .setup = std::move(setup),
            .report = std::move(report),
        };
    } catch (...) {
        const std::exception_ptr failure = std::current_exception();
        cleanup.clear();
        std::rethrow_exception(failure);
    }
}

bool valid_factored_matrix_commitment(
    const FactoredMatrixCommitment &commitment,
    const FactoredMatrixStructure &structure, const IPCS &pcs) {
    try {
        return valid_internal_commitment(commitment, structure, pcs);
    } catch (const std::exception &) {
        return false;
    }
}

namespace {

template <typename Open>
FactoredMatrixEvaluationProof prove_factored_matrix_evaluation_impl(
    const FactoredMatrixProverKey &key,
    std::span<const Fq2> row_point,
    std::span<const Fq2> column_point, const Fq2 &gamma,
    const Fq2 &claimed_matrix_evaluation, const IPCS &pcs,
    PublicCoin &public_coin,
    FactoredMatrixExternalProvingReport *report, Open open) {
    validate_prover_key(key, row_point, column_point, pcs);

    const std::size_t tensor_count = key.commitment.tensors.size();
    std::vector<std::vector<Fq2>> column_weights;
    column_weights.reserve(tensor_count);
    std::vector<Fq2> claims;
    claims.reserve(tensor_count);

    // Compute all component claims before sampling any challenge. Operands
    // are intentionally discarded and rematerialized one component at a
    // time below, keeping peak memory independent of the tensor count.
    for (std::size_t tensor_index = 0; tensor_index < tensor_count;
         ++tensor_index) {
        const FactoredTensorShape shape =
            key.commitment.tensors[tensor_index].shape;
        column_weights.push_back(checked_column_weights(
            *key.structure, tensor_index, shape, row_point, column_point,
            gamma));
        const std::vector<Fq2> operand = checked_operand(
            *key.structure, tensor_index, shape, row_point, column_point,
            gamma);
        claims.push_back(weighted_dot(key, tensor_index,
                                      column_weights.back(), operand,
                                      report));
    }

    const Fq2 regular = batched_regular_evaluation(
        *key.structure, row_point, column_point, gamma);
    if (regular + sum_claims(claims) != claimed_matrix_evaluation) {
        throw std::invalid_argument(
            "factored claimed matrix evaluation is incorrect");
    }

    observe_commitment(key.commitment, public_coin);
    observe_statement(row_point, column_point, gamma,
                      claimed_matrix_evaluation, public_coin);
    observe_claims(claims, public_coin);

    FactoredMatrixEvaluationProof proof;
    proof.tensors.resize(tensor_count);
    for (std::size_t tensor_index = 0; tensor_index < tensor_count;
         ++tensor_index) {
        const FactoredTensorShape shape =
            key.commitment.tensors[tensor_index].shape;
        const std::size_t evaluation_count = checked_size(
            shape.evaluation_count, "factored tensor evaluation count");
        const std::size_t round_count = log2_exact(shape.evaluation_count);
        FactoredTensorEvaluationProof &component =
            proof.tensors[tensor_index];
        component.claim = claims[tensor_index];
        component.rounds.reserve(round_count);
        std::vector<Fq2> tensor_point;
        {
            // Release both dense Fq2 tables before BaseFold allocates its
            // codeword layers. This is the main peak-memory boundary.
            std::vector<Fq2> tensor = weighted_tensor_table(
                key, tensor_index, column_weights[tensor_index],
                evaluation_count, report);
            std::vector<Fq2> operand = checked_operand(
                *key.structure, tensor_index, shape, row_point,
                column_point, gamma);
            std::vector<Fq2> challenges_lsb;
            challenges_lsb.reserve(round_count);
            Fq2 running_claim = component.claim;
            for (std::size_t round_index = 0;
                 round_index < round_count; ++round_index) {
                const ProductRound round = product_round(tensor, operand);
                if (round.at_zero + round.transmitted.evaluations[0] !=
                    running_claim) {
                    throw std::logic_error(
                        "factored product sumcheck claim is inconsistent");
                }
                component.rounds.push_back(round.transmitted);
                observe_round(tensor_index, round_index,
                              component.rounds.back(), public_coin);
                const Fq2 challenge = public_coin.challenge_fq2();
                challenges_lsb.push_back(challenge);
                running_claim = interpolate_quadratic(
                    round.at_zero, round.transmitted.evaluations,
                    challenge);
                fold_adjacent(tensor, challenge);
                fold_adjacent(operand, challenge);
            }

            if (tensor.size() != 1 || operand.size() != 1) {
                throw std::logic_error(
                    "factored product sumcheck did not reach a point");
            }
            tensor_point.assign(challenges_lsb.rbegin(),
                                challenges_lsb.rend());
            const Fq2 compact_operand =
                key.structure->evaluate_tensor_operand(
                    tensor_index, row_point, column_point, gamma,
                    tensor_point);
            component.terminal_tensor_value = tensor.front();
            if (operand.front() != compact_operand ||
                running_claim !=
                    component.terminal_tensor_value * compact_operand) {
                throw std::logic_error(
                    "factored terminal operand evaluation is inconsistent");
            }
        }

        observe_terminal(tensor_index, component.terminal_tensor_value,
                         public_coin);
        component.opening = open(
            tensor_index, key.tensors[tensor_index].opening_state,
            column_weights[tensor_index], tensor_point,
            component.terminal_tensor_value, public_coin);
        observe_opening(tensor_index, component.opening, public_coin);
    }
    return proof;
}

} // namespace

FactoredMatrixEvaluationProof prove_factored_matrix_evaluation(
    const FactoredMatrixProverKey &key,
    std::span<const Fq2> row_point,
    std::span<const Fq2> column_point, const Fq2 &gamma,
    const Fq2 &claimed_matrix_evaluation, const IPCS &pcs,
    PublicCoin &public_coin) {
    validate_prover_key(key, row_point, column_point, pcs);
    const auto *basefold = dynamic_cast<const BaseFoldPcs *>(&pcs);
    if (basefold == nullptr) {
        throw std::invalid_argument(
            "factored proving requires the BaseFold PCS");
    }
    for (std::size_t tensor_index = 0;
         tensor_index < key.tensors.size(); ++tensor_index) {
        if (key.tensors[tensor_index].opening_state_source !=
            FactoredTensorProverKey::OpeningStateSource::Resident) {
            throw std::invalid_argument(
                "ordinary factored proving requires resident opening "
                "states");
        }
        basefold->validate_resident_prover_state(
            key.tensors[tensor_index].opening_state,
            key.commitment.tensors[tensor_index].columns);
    }
    return prove_factored_matrix_evaluation_impl(
        key, row_point, column_point, gamma, claimed_matrix_evaluation,
        pcs, public_coin, nullptr,
        [&](std::size_t,
            const std::shared_ptr<const IPCS::ProverState> &opening_state,
            std::span<const Fq2> column_weights,
            std::span<const Fq2> tensor_point,
            const Fq2 &terminal_tensor_value,
            PublicCoin &opening_coin) {
            return pcs.open_linear_combination(
                opening_state, column_weights, tensor_point,
                terminal_tensor_value, opening_coin);
        });
}

FactoredMatrixExternalProvingPlan
plan_factored_matrix_evaluation_external_admitted(
    const FactoredMatrixProverKey &key,
    const FactoredMatrixExternalProvingOptions &options,
    std::span<const BaseFoldExternalOpeningPreflight> opening_admissions) {
    if (key.structure == nullptr || key.tensor_columns_artifact == nullptr ||
        options.max_live_storage_bytes == 0 ||
        options.reserved_live_storage_bytes >=
            options.max_live_storage_bytes ||
        options.max_working_field_bytes == 0 ||
        opening_admissions.size() != key.commitment.tensors.size()) {
        throw std::invalid_argument(
            "factored resource planning needs complete admitted inputs");
    }

    FactoredMatrixExternalProvingPlan plan;
    FactoredMatrixExternalProvingReport &report = plan.report;
    std::uint64_t scratch_peak_physical_bytes = 0;
    for (const BaseFoldExternalOpeningPreflight &admission :
         opening_admissions) {
        report.external_states_physical_bytes = storage_add(
            report.external_states_physical_bytes,
            admission.state_artifact_physical_bytes,
            "factored external-state physical bytes");
        scratch_peak_physical_bytes = std::max(
            scratch_peak_physical_bytes,
            admission.required_scratch_physical_bytes);
    }
    report.tensor_columns_physical_bytes =
        key.tensor_columns_artifact->physical_bytes();
    report.persistent_input_physical_bytes = storage_add(
        report.tensor_columns_physical_bytes,
        report.external_states_physical_bytes,
        "factored persistent input physical bytes");
    report.reserved_live_storage_bytes =
        options.reserved_live_storage_bytes;
    report.admitted_live_storage_bytes = options.max_live_storage_bytes;
    report.peak_live_storage_bytes = storage_add(
        storage_add(report.persistent_input_physical_bytes,
                    report.reserved_live_storage_bytes,
                    "factored reserved live physical bytes"),
        scratch_peak_physical_bytes,
        "factored peak live physical bytes");
    if (report.peak_live_storage_bytes > options.max_live_storage_bytes) {
        throw std::runtime_error(
            "external factored proving exceeds the complete live-storage "
            "limit");
    }
    report.admitted_working_field_bytes =
        options.max_working_field_bytes;
    report.tensor_openings.reserve(key.tensors.size());

    const std::uint64_t tensor_count = checked_u64(
        key.commitment.tensors.size(), "factored tensor count");
    std::uint64_t total_weight_fields = 0;
    std::uint64_t total_rounds = 0;
    for (const FactoredTensorCommitment &tensor : key.commitment.tensors) {
        total_weight_fields = storage_add(
            total_weight_fields, tensor.shape.column_count,
            "factored retained column weights");
        total_rounds = storage_add(
            total_rounds,
            checked_u64(log2_exact(tensor.shape.evaluation_count),
                        "factored product rounds"),
            "factored product rounds");
    }
    report.retained_column_weight_field_bytes = storage_multiply(
        total_weight_fields, sizeof(Fq2),
        "factored retained column-weight bytes");
    report.retained_claim_field_bytes = storage_multiply(
        tensor_count, sizeof(Fq2), "factored retained claim bytes");
    report.tensor_column_read_buffer_field_bytes = storage_multiply(
        kArtifactReadElements, sizeof(Fq),
        "factored tensor-column read buffer bytes");
    report.accumulated_factored_proof_field_bytes = storage_multiply(
        storage_add(storage_multiply(tensor_count, 2U,
                                     "factored fixed proof fields"),
                    storage_multiply(total_rounds, 2U,
                                     "factored round proof fields"),
                    "factored proof fields"),
        sizeof(Fq2), "factored proof field bytes");

    std::vector<FactoredTensorOperandWorkingSet> operand_working_sets;
    operand_working_sets.reserve(key.commitment.tensors.size());
    for (std::size_t tensor_index = 0;
         tensor_index < key.commitment.tensors.size(); ++tensor_index) {
        const FactoredTensorShape shape =
            key.commitment.tensors[tensor_index].shape;
        const FactoredTensorOperandWorkingSet working_set =
            key.structure->tensor_operand_working_set(tensor_index);
        const std::uint64_t output_bytes = storage_multiply(
            shape.evaluation_count, sizeof(Fq2),
            "factored operand output bytes");
        if (working_set.materialization_peak_field_bytes < output_bytes) {
            throw std::invalid_argument(
                "factored structure underreports operand materialization "
                "memory");
        }
        operand_working_sets.push_back(working_set);
        report.operand_materialization_field_bytes = std::max(
            report.operand_materialization_field_bytes,
            working_set.materialization_peak_field_bytes);
        report.compact_operand_evaluation_field_bytes = std::max(
            report.compact_operand_evaluation_field_bytes,
            working_set.compact_evaluation_peak_field_bytes);
        report.basefold_preflight_validation_bytes = storage_add(
            report.basefold_preflight_validation_bytes,
            opening_admissions[tensor_index]
                .state_artifact_physical_bytes,
            "BaseFold preflight validation bytes");
        report.artifact_validation_bytes = storage_add(
            report.artifact_validation_bytes,
            opening_admissions[tensor_index]
                .state_artifact_physical_bytes,
            "BaseFold admitted validation bytes");
        report.basefold_state_integrity_scans = storage_add(
            report.basefold_state_integrity_scans, 1,
            "BaseFold state integrity scans");
        report.basefold_opening_field_bytes = std::max(
            report.basefold_opening_field_bytes,
            opening_admissions[tensor_index]
                .required_working_field_bytes);
    }

    std::uint64_t weights_so_far = 0;
    for (std::size_t tensor_index = 0;
         tensor_index < key.commitment.tensors.size(); ++tensor_index) {
        const FactoredTensorShape shape =
            key.commitment.tensors[tensor_index].shape;
        weights_so_far = storage_add(
            weights_so_far, shape.column_count,
            "factored claim-phase weights");
        const std::uint64_t retained_claim_fields = storage_add(
            weights_so_far, tensor_count,
            "factored claim retained fields");
        report.peak_working_field_bytes = std::max(
            report.peak_working_field_bytes,
            storage_add(
                storage_multiply(
                    storage_add(retained_claim_fields,
                                shape.evaluation_count,
                                "factored claim operand fields"),
                    sizeof(Fq2), "factored claim scan field bytes"),
                report.tensor_column_read_buffer_field_bytes,
                "factored claim scan working bytes"));
        report.peak_working_field_bytes = std::max(
            report.peak_working_field_bytes,
            storage_add(
                storage_multiply(retained_claim_fields, sizeof(Fq2),
                                 "factored claim retained bytes"),
                operand_working_sets[tensor_index]
                    .materialization_peak_field_bytes,
                "factored claim operand materialization peak"));
    }

    const std::uint64_t retained_core_fields = storage_add(
        total_weight_fields, tensor_count,
        "factored retained proving fields");
    plan.outer_opening_retained_field_bytes.reserve(
        key.commitment.tensors.size());
    std::uint64_t completed_rounds = 0;
    for (std::size_t tensor_index = 0;
         tensor_index < key.commitment.tensors.size(); ++tensor_index) {
        const FactoredTensorCommitment &tensor =
            key.commitment.tensors[tensor_index];
        const std::uint64_t rounds = checked_u64(
            log2_exact(tensor.shape.evaluation_count),
            "factored product rounds");
        completed_rounds = storage_add(
            completed_rounds, rounds, "factored completed rounds");
        const std::uint64_t proof_fields = storage_add(
            storage_multiply(tensor_count, 2U,
                             "factored fixed proof fields"),
            storage_multiply(completed_rounds, 2U,
                             "factored allocated round fields"),
            "factored allocated proof fields");
        const std::uint64_t retained_product_fields = storage_add(
            retained_core_fields, proof_fields,
            "factored retained product fields");
        report.peak_working_field_bytes = std::max(
            report.peak_working_field_bytes,
            storage_add(
                storage_multiply(
                    storage_add(retained_product_fields,
                                tensor.shape.evaluation_count,
                                "factored weighted tensor fields"),
                    sizeof(Fq2), "factored raw-scan field bytes"),
                report.tensor_column_read_buffer_field_bytes,
                "factored raw-scan working bytes"));
        const std::uint64_t retained_product_bytes = storage_multiply(
            retained_product_fields, sizeof(Fq2),
            "factored retained product bytes");
        const std::uint64_t weighted_tensor_bytes = storage_multiply(
            tensor.shape.evaluation_count, sizeof(Fq2),
            "factored weighted tensor bytes");
        report.peak_working_field_bytes = std::max(
            report.peak_working_field_bytes,
            storage_add(
                storage_add(retained_product_bytes,
                            weighted_tensor_bytes,
                            "factored retained weighted tensor bytes"),
                operand_working_sets[tensor_index]
                    .materialization_peak_field_bytes,
                "factored product operand materialization peak"));

        const std::uint64_t table_bytes = storage_multiply(
            storage_multiply(tensor.shape.evaluation_count, 2U,
                             "factored product-sumcheck table entries"),
            sizeof(Fq2), "factored product-sumcheck table bytes");
        report.resident_product_sumcheck_field_bytes = std::max(
            report.resident_product_sumcheck_field_bytes, table_bytes);
        const std::uint64_t challenge_point_bytes = storage_multiply(
            storage_multiply(rounds, 2U,
                             "factored challenge and point fields"),
            sizeof(Fq2), "factored challenge and point bytes");
        report.product_challenge_point_field_bytes = std::max(
            report.product_challenge_point_field_bytes,
            challenge_point_bytes);
        report.peak_working_field_bytes = std::max(
            report.peak_working_field_bytes,
            storage_add(
                storage_add(
                    storage_add(retained_product_bytes, table_bytes,
                                "factored product table peak"),
                    challenge_point_bytes,
                    "factored product challenge-point peak"),
                operand_working_sets[tensor_index]
                    .compact_evaluation_peak_field_bytes,
                "factored compact operand evaluation peak"));

        const std::uint64_t outer_bytes = storage_multiply(
            storage_add(retained_product_fields, rounds,
                        "factored tensor point fields"),
            sizeof(Fq2), "factored outer opening retained bytes");
        plan.outer_opening_retained_field_bytes.push_back(outer_bytes);
        report.outer_opening_retained_field_bytes = std::max(
            report.outer_opening_retained_field_bytes, outer_bytes);
        report.peak_working_field_bytes = std::max(
            report.peak_working_field_bytes,
            storage_add(
                outer_bytes,
                opening_admissions[tensor_index]
                    .required_working_field_bytes,
                "factored admitted external opening fields"));
    }
    if (report.peak_working_field_bytes >
        options.max_working_field_bytes) {
        throw std::runtime_error(
            "external factored proving exceeds the outer field-memory "
            "limit");
    }
    return plan;
}

FactoredMatrixExternalProving prove_factored_matrix_evaluation_external(
    const FactoredMatrixProverKey &key,
    std::span<const Fq2> row_point,
    std::span<const Fq2> column_point, const Fq2 &gamma,
    const Fq2 &claimed_matrix_evaluation, const BaseFoldPcs &pcs,
    FactoredMatrixExternalProvingOptions options,
    PublicCoin &public_coin) {
    if (options.tensor_openings.size() != key.tensors.size()) {
        throw std::invalid_argument(
            "external factored proving needs one opening resource per "
            "tensor");
    }
    std::vector<BaseFoldExternalOpeningAdmission> admissions;
    admissions.reserve(key.tensors.size());
    for (std::size_t tensor_index = 0;
         tensor_index < key.tensors.size(); ++tensor_index) {
        admissions.push_back(pcs.admit_external_opening(
            key.tensors[tensor_index].opening_state,
            key.commitment.tensors[tensor_index].columns,
            options.tensor_openings[tensor_index]));
    }
    return prove_factored_matrix_evaluation_external_admitted(
        key, row_point, column_point, gamma,
        claimed_matrix_evaluation, pcs, std::move(options),
        std::move(admissions), public_coin);
}

FactoredMatrixExternalProving
prove_factored_matrix_evaluation_external_admitted(
    const FactoredMatrixProverKey &key,
    std::span<const Fq2> row_point,
    std::span<const Fq2> column_point, const Fq2 &gamma,
    const Fq2 &claimed_matrix_evaluation, const BaseFoldPcs &pcs,
    FactoredMatrixExternalProvingOptions options,
    std::vector<BaseFoldExternalOpeningAdmission> validated_admissions,
    PublicCoin &public_coin) {
    validate_prover_key(key, row_point, column_point, pcs);
    if (key.tensor_column_source != FactoredTensorColumnSource::Artifact ||
        key.tensor_columns_artifact == nullptr ||
        options.max_live_storage_bytes == 0 ||
        options.reserved_live_storage_bytes >=
            options.max_live_storage_bytes ||
        options.max_working_field_bytes == 0 ||
        options.tensor_openings.size() != key.tensors.size() ||
        validated_admissions.size() != key.tensors.size() ||
        std::any_of(
            key.tensors.begin(), key.tensors.end(),
            [](const FactoredTensorProverKey &tensor) {
                return tensor.opening_state_source !=
                       FactoredTensorProverKey::OpeningStateSource::External;
            })) {
        throw std::invalid_argument(
            "external factored proving needs external opening states and "
            "explicit outer storage and memory limits plus one scratch "
            "configuration per tensor");
    }

    const std::filesystem::path column_artifact_path =
        external_normalized_path(
            key.tensor_columns_artifact->directory(),
            "factored tensor columns");
    std::vector<std::filesystem::path> scratch_roots;
    scratch_roots.reserve(options.tensor_openings.size());
    for (BaseFoldExternalOpeningOptions &opening :
         options.tensor_openings) {
        if (opening.max_live_storage_bytes == 0 ||
            opening.max_total_scratch_bytes == 0 ||
            opening.min_free_bytes == 0 ||
            opening.max_working_field_bytes == 0) {
            throw std::invalid_argument(
                "external factored opening limits must be nonzero");
        }
        opening.scratch_directory = external_normalized_path(
            opening.scratch_directory,
            "external factored opening scratch");
        validate_empty_external_directory(
            opening.scratch_directory,
            "external factored opening scratch");
        if (external_path_prefix(column_artifact_path,
                                 opening.scratch_directory) ||
            external_path_prefix(opening.scratch_directory,
                                 column_artifact_path) ||
            existing_paths_equivalent(column_artifact_path,
                                      opening.scratch_directory)) {
            throw std::invalid_argument(
                "factored column artifact and opening scratch must be "
                "disjoint");
        }
        scratch_roots.push_back(opening.scratch_directory);
    }
    for (std::size_t left = 0; left < scratch_roots.size(); ++left) {
        for (std::size_t right = left + 1U;
             right < scratch_roots.size(); ++right) {
            if (external_path_prefix(scratch_roots[left],
                                     scratch_roots[right]) ||
                external_path_prefix(scratch_roots[right],
                                     scratch_roots[left]) ||
                existing_paths_equivalent(scratch_roots[left],
                                          scratch_roots[right])) {
                throw std::invalid_argument(
                    "factored opening scratch roots must be disjoint");
            }
        }
    }

    // Admit every opaque state, exact commitment, scratch quota, field
    // budget, and free-space reserve before the outer protocol can observe or
    // sample from its public coin.
    std::vector<BaseFoldExternalOpeningPreflight> opening_admissions;
    opening_admissions.reserve(key.tensors.size());
    for (const BaseFoldExternalOpeningAdmission &admission :
         validated_admissions) {
        opening_admissions.push_back(admission.preflight());
    }

    // Persistent tensor columns and every external PCS state remain live for
    // the full factored proof. States must be distinct from one another and
    // from all column/scratch paths; otherwise a path alias could make both
    // accounting and cleanup unsound.
    std::vector<std::filesystem::path> state_roots;
    state_roots.reserve(opening_admissions.size());
    for (const BaseFoldExternalOpeningPreflight &admission :
         opening_admissions) {
        if (external_path_prefix(column_artifact_path,
                                 admission.state_artifact_directory) ||
            external_path_prefix(admission.state_artifact_directory,
                                 column_artifact_path) ||
            existing_paths_equivalent(column_artifact_path,
                                      admission.state_artifact_directory)) {
            throw std::invalid_argument(
                "factored column artifact and BaseFold states must be "
                "disjoint");
        }
        for (const std::filesystem::path &scratch : scratch_roots) {
            if (external_path_prefix(admission.state_artifact_directory,
                                     scratch) ||
                external_path_prefix(scratch,
                                     admission.state_artifact_directory) ||
                existing_paths_equivalent(
                    admission.state_artifact_directory, scratch)) {
                throw std::invalid_argument(
                    "factored BaseFold states and opening scratches must "
                    "be disjoint");
            }
        }
        for (const std::filesystem::path &prior : state_roots) {
            if (external_path_prefix(prior,
                                     admission.state_artifact_directory) ||
                external_path_prefix(admission.state_artifact_directory,
                                     prior) ||
                existing_paths_equivalent(
                    prior, admission.state_artifact_directory)) {
                throw std::invalid_argument(
                    "factored BaseFold states must use distinct artifact "
                    "roots");
            }
        }
        state_roots.push_back(admission.state_artifact_directory);
    }

    FactoredMatrixExternalProvingPlan resource_plan =
        plan_factored_matrix_evaluation_external_admitted(
            key, options, opening_admissions);
    FactoredMatrixExternalProvingReport report =
        std::move(resource_plan.report);
    const std::vector<std::uint64_t> outer_opening_bytes =
        std::move(resource_plan.outer_opening_retained_field_bytes);

    try {
        FactoredMatrixEvaluationProof proof =
            prove_factored_matrix_evaluation_impl(
            key, row_point, column_point, gamma,
            claimed_matrix_evaluation, pcs, public_coin, &report,
            [&](std::size_t tensor_index,
                const std::shared_ptr<const IPCS::ProverState>
                    & /*opening_state*/,
                std::span<const Fq2> column_weights,
                std::span<const Fq2> tensor_point,
                const Fq2 &terminal_tensor_value,
                PublicCoin &opening_coin) {
                BaseFoldExternalOpening opened =
                    pcs.open_linear_combination_external_admitted(
                        std::move(validated_admissions[tensor_index]),
                        column_weights, tensor_point,
                        terminal_tensor_value, opening_coin);
                const std::filesystem::path &scratch =
                    options.tensor_openings[tensor_index]
                        .scratch_directory;
                const std::uint64_t scratch_bytes =
                    directory_regular_bytes(scratch);
                if (scratch_bytes !=
                        opened.report.scratch_physical_bytes ||
                    scratch_bytes != 0 ||
                    opened.report.scratch_peak_physical_bytes !=
                        opening_admissions[tensor_index]
                            .required_scratch_physical_bytes ||
                    opened.report.scratch_written_physical_bytes !=
                        opening_admissions[tensor_index]
                            .required_scratch_written_physical_bytes ||
                    opened.report.sequential_write_payload_bytes !=
                        opening_admissions[tensor_index]
                            .required_sequential_write_payload_bytes ||
                    opened.report.scratch_chunk_artifacts_written !=
                        opening_admissions[tensor_index]
                            .required_chunk_artifacts_written ||
                    opened.report.scratch_files_written !=
                        opening_admissions[tensor_index]
                            .required_scratch_files_written ||
                    opened.report.scratch_deleted_physical_bytes !=
                        opened.report.scratch_written_physical_bytes ||
                    opened.report.scratch_chunk_artifacts_deleted !=
                        opened.report.scratch_chunk_artifacts_written ||
                    opened.report.scratch_files_deleted !=
                        opened.report.scratch_files_written ||
                    opened.report.peak_working_field_bytes !=
                        opening_admissions[tensor_index]
                            .required_working_field_bytes ||
                    opened.report.materialized_sumcheck_entries !=
                        opening_admissions[tensor_index]
                            .materialized_sumcheck_entries) {
                    throw std::logic_error(
                        "external factored opening disagrees with its "
                        "preflight");
                }
                if (opened.report.artifact_validation_passes != 1 ||
                    opened.report.state_artifact_validation_bytes !=
                        opening_admissions[tensor_index]
                            .state_artifact_physical_bytes) {
                    throw std::logic_error(
                        "external factored opening admission accounting "
                        "differs: passes=" +
                        std::to_string(
                            opened.report.artifact_validation_passes) +
                        " bytes=" +
                        std::to_string(
                            opened.report.artifact_validation_bytes) +
                        " state-bytes=" +
                        std::to_string(
                            opened.report.state_artifact_validation_bytes) +
                        " planned=" +
                        std::to_string(
                            opening_admissions[tensor_index]
                                .state_artifact_physical_bytes));
                }
                report.artifact_validation_bytes = storage_add(
                    report.artifact_validation_bytes,
                    opened.report.artifact_validation_bytes -
                        opened.report.state_artifact_validation_bytes,
                    "external factored scratch validation bytes");
                report.sequential_read_payload_bytes = storage_add(
                    report.sequential_read_payload_bytes,
                    opened.report.sequential_read_payload_bytes,
                    "external factored sequential read bytes");
                report.indexed_read_payload_bytes = storage_add(
                    report.indexed_read_payload_bytes,
                    opened.report.indexed_read_payload_bytes,
                    "external factored indexed read bytes");
                report.sequential_write_payload_bytes = storage_add(
                    report.sequential_write_payload_bytes,
                    opened.report.sequential_write_payload_bytes,
                    "external factored sequential write bytes");
                report.scratch_peak_physical_bytes = std::max(
                    report.scratch_peak_physical_bytes,
                    opened.report.scratch_peak_physical_bytes);
                report.scratch_written_physical_bytes = storage_add(
                    report.scratch_written_physical_bytes,
                    opened.report.scratch_written_physical_bytes,
                    "external factored scratch written bytes");
                report.scratch_deleted_physical_bytes = storage_add(
                    report.scratch_deleted_physical_bytes,
                    opened.report.scratch_deleted_physical_bytes,
                    "external factored scratch deleted bytes");
                report.scratch_chunk_artifacts_written = storage_add(
                    report.scratch_chunk_artifacts_written,
                    opened.report.scratch_chunk_artifacts_written,
                    "external factored scratch artifacts written");
                report.scratch_chunk_artifacts_deleted = storage_add(
                    report.scratch_chunk_artifacts_deleted,
                    opened.report.scratch_chunk_artifacts_deleted,
                    "external factored scratch artifacts deleted");
                report.scratch_files_written = storage_add(
                    report.scratch_files_written,
                    opened.report.scratch_files_written,
                    "external factored scratch files written");
                report.scratch_files_deleted = storage_add(
                    report.scratch_files_deleted,
                    opened.report.scratch_files_deleted,
                    "external factored scratch files deleted");
                report.basefold_opening_field_bytes = std::max(
                    report.basefold_opening_field_bytes,
                    opened.report.peak_working_field_bytes);
                report.peak_working_field_bytes = std::max(
                    report.peak_working_field_bytes,
                    storage_add(
                        outer_opening_bytes[tensor_index],
                        opened.report.peak_working_field_bytes,
                        "factored simultaneous external opening fields"));
                report.tensor_openings.push_back(opened.report);
                return std::move(opened.proof);
                });
        if (report.tensor_openings.size() != key.tensors.size() ||
            report.basefold_state_integrity_scans != key.tensors.size() ||
            report.artifact_validation_bytes <
                report.basefold_preflight_validation_bytes ||
            report.scratch_written_physical_bytes !=
                report.scratch_deleted_physical_bytes ||
            report.scratch_chunk_artifacts_written !=
                report.scratch_chunk_artifacts_deleted ||
            report.scratch_files_written !=
                report.scratch_files_deleted) {
            throw std::logic_error(
                "external factored proving resource accounting is "
                "incomplete");
        }
        report.proof_bytes = checked_u64(
            encode_factored_matrix_evaluation_proof(proof).size(),
            "external factored proof bytes");
        return {
            .proof = std::move(proof),
            .report = std::move(report),
        };
    } catch (...) {
        // BaseFold owns and identity-checks every file it creates. If it
        // deliberately retains a substituted or corrupt path, the composing
        // prover must not recursively delete that unowned data.
        throw;
    }
}

bool verify_factored_matrix_evaluation(
    const FactoredMatrixVerifierKey &key,
    std::span<const Fq2> row_point,
    std::span<const Fq2> column_point, const Fq2 &gamma,
    const Fq2 &claimed_matrix_evaluation,
    const FactoredMatrixEvaluationProof &proof, const IPCS &pcs,
    PublicCoin &public_coin) {
    try {
        validate_evaluation_inputs(key.commitment, key.structure, row_point,
                                   column_point, pcs);
        if (proof.tensors.size() != key.commitment.tensors.size()) {
            return false;
        }

        std::vector<std::vector<Fq2>> column_weights;
        column_weights.reserve(proof.tensors.size());
        std::vector<Fq2> claims;
        claims.reserve(proof.tensors.size());
        for (std::size_t tensor_index = 0;
             tensor_index < proof.tensors.size(); ++tensor_index) {
            const FactoredTensorShape shape =
                key.commitment.tensors[tensor_index].shape;
            if (proof.tensors[tensor_index].rounds.size() !=
                log2_exact(shape.evaluation_count)) {
                return false;
            }
            column_weights.push_back(checked_column_weights(
                *key.structure, tensor_index, shape, row_point,
                column_point, gamma));
            claims.push_back(proof.tensors[tensor_index].claim);
        }

        const Fq2 regular = batched_regular_evaluation(
            *key.structure, row_point, column_point, gamma);
        if (regular + sum_claims(claims) != claimed_matrix_evaluation) {
            return false;
        }

        observe_commitment(key.commitment, public_coin);
        observe_statement(row_point, column_point, gamma,
                          claimed_matrix_evaluation, public_coin);
        observe_claims(claims, public_coin);

        for (std::size_t tensor_index = 0;
             tensor_index < proof.tensors.size(); ++tensor_index) {
            const FactoredTensorEvaluationProof &component =
                proof.tensors[tensor_index];
            Fq2 running_claim = component.claim;
            std::vector<Fq2> challenges_lsb;
            challenges_lsb.reserve(component.rounds.size());
            for (std::size_t round_index = 0;
                 round_index < component.rounds.size(); ++round_index) {
                const FactoredSumcheckRound &round =
                    component.rounds[round_index];
                observe_round(tensor_index, round_index, round,
                              public_coin);
                const Fq2 challenge = public_coin.challenge_fq2();
                challenges_lsb.push_back(challenge);
                const Fq2 at_zero =
                    running_claim - round.evaluations[0];
                running_claim = interpolate_quadratic(
                    at_zero, round.evaluations, challenge);
            }

            std::vector<Fq2> tensor_point(challenges_lsb.rbegin(),
                                         challenges_lsb.rend());
            const Fq2 compact_operand =
                key.structure->evaluate_tensor_operand(
                    tensor_index, row_point, column_point, gamma,
                    tensor_point);
            if (running_claim !=
                component.terminal_tensor_value * compact_operand) {
                return false;
            }
            observe_terminal(tensor_index,
                             component.terminal_tensor_value,
                             public_coin);
            if (!pcs.verify_linear_combination(
                    key.commitment.tensors[tensor_index].columns,
                    column_weights[tensor_index], tensor_point,
                    component.terminal_tensor_value, component.opening,
                    public_coin)) {
                return false;
            }
            observe_opening(tensor_index, component.opening, public_coin);
        }
        return true;
    } catch (const std::exception &) {
        return false;
    }
}

std::vector<std::uint8_t> encode_factored_matrix_commitment(
    const FactoredMatrixCommitment &commitment) {
    std::vector<std::uint8_t> output;
    output.insert(output.end(), kCommitmentEncodingDomain.begin(),
                  kCommitmentEncodingDomain.end());
    append_u64(output, commitment.profile);
    output.insert(output.end(), commitment.circuit_digest.begin(),
                  commitment.circuit_digest.end());
    output.insert(output.end(), commitment.structure_digest.begin(),
                  commitment.structure_digest.end());
    append_u64(output, commitment.row_variables);
    append_u64(output, commitment.column_variables);
    append_size(output, commitment.tensors.size());
    for (const FactoredTensorCommitment &tensor : commitment.tensors) {
        append_u64(output, tensor.shape.evaluation_count);
        append_u64(output, tensor.shape.column_count);
        const std::vector<std::uint8_t> pcs =
            encode_pcs_commitment(tensor.columns);
        append_size(output, pcs.size());
        output.insert(output.end(), pcs.begin(), pcs.end());
    }
    return output;
}

void append_factored_matrix_evaluation_proof(
    const FactoredMatrixEvaluationProof &proof,
    std::vector<std::uint8_t> &output) {
    output.insert(output.end(), kProofEncodingDomain.begin(),
                  kProofEncodingDomain.end());
    append_size(output, proof.tensors.size());
    for (const FactoredTensorEvaluationProof &tensor : proof.tensors) {
        append_fq2(output, tensor.claim);
        append_size(output, tensor.rounds.size());
        for (const FactoredSumcheckRound &round : tensor.rounds) {
            append_fq2(output, round.evaluations[0]);
            append_fq2(output, round.evaluations[1]);
        }
        append_fq2(output, tensor.terminal_tensor_value);
        append_size(output, tensor.opening.bytes.size());
        output.insert(output.end(), tensor.opening.bytes.begin(),
                      tensor.opening.bytes.end());
    }
}

std::vector<std::uint8_t> encode_factored_matrix_evaluation_proof(
    const FactoredMatrixEvaluationProof &proof) {
    std::vector<std::uint8_t> output;
    append_factored_matrix_evaluation_proof(proof, output);
    return output;
}

std::size_t factored_matrix_evaluation_proof_size_bytes(
    const FactoredMatrixEvaluationProof &proof) {
    std::size_t size = checked_add(kProofEncodingDomain.size(), 8U);
    for (const FactoredTensorEvaluationProof &tensor : proof.tensors) {
        size = checked_add(size, kSerializedFq2Bytes);
        size = checked_add(size, 8U);
        size = checked_add(
            size, checked_multiply(
                      tensor.rounds.size(), 2U * kSerializedFq2Bytes));
        size = checked_add(size, kSerializedFq2Bytes);
        size = checked_add(size, 8U);
        size = checked_add(size, tensor.opening.bytes.size());
    }
    return size;
}

std::size_t factored_matrix_evaluation_proof_max_size_bytes(
    const FactoredMatrixCommitment &commitment,
    BaseFoldPcsParameters parameters) {
    if (commitment.profile != kFactoredMatrixProfileIdentifier ||
        parameters.log_rate == 0) {
        throw std::invalid_argument(
            "factored maximum proof-size commitment is invalid");
    }
    BaseFoldPcs pcs(parameters);
    std::size_t size = checked_add(kProofEncodingDomain.size(), 8U);
    for (const FactoredTensorCommitment &tensor : commitment.tensors) {
        if (!valid_shape(tensor.shape) ||
            !valid_pcs_commitment(tensor, pcs)) {
            throw std::invalid_argument(
                "factored maximum proof-size tensor is invalid");
        }
        const std::size_t rounds =
            log2_exact(tensor.shape.evaluation_count);
        const std::size_t width =
            checked_size(tensor.shape.column_count,
                         "factored proof width");
        size = checked_add(size, kSerializedFq2Bytes);
        size = checked_add(size, 8U);
        size = checked_add(
            size,
            checked_multiply(rounds, 2U * kSerializedFq2Bytes));
        size = checked_add(size, kSerializedFq2Bytes);
        size = checked_add(size, 8U);
        size = checked_add(
            size, basefold_opening_proof_max_size_bytes(
                      rounds, width, parameters));
    }
    return size;
}

} // namespace laminate::spartan
