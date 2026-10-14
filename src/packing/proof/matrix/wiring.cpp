/// @file wiring.cpp
/// @brief Compact external-memory row-bound matrix for packing Spartan.

#include "laminate/packing/proof/matrix/wiring.hpp"

#include "laminate/crypto/poseidon.hpp"
#include "laminate/packing/proof/detail/poseidon_template.hpp"
#include "laminate/packing/outer_relation/assignment.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <limits>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace laminate::packing {
namespace {

constexpr std::string_view kIdentityDomain =
    "LaminateImpl/ProofOfPackingWiringMatrix/v1";

std::uint64_t checked_u64(std::size_t value, const char *label) {
    if constexpr (sizeof(std::size_t) > sizeof(std::uint64_t)) {
        if (value > std::numeric_limits<std::uint64_t>::max()) {
            throw std::overflow_error(std::string(label) + " exceeds u64");
        }
    }
    return static_cast<std::uint64_t>(value);
}

std::size_t checked_size(std::uint64_t value, const char *label) {
    if (value > std::numeric_limits<std::size_t>::max()) {
        throw std::overflow_error(std::string(label) + " exceeds size_t");
    }
    return static_cast<std::size_t>(value);
}

std::uint64_t checked_add(std::uint64_t left, std::uint64_t right,
                          const char *label) {
    if (right > std::numeric_limits<std::uint64_t>::max() - left) {
        throw std::overflow_error(std::string(label) + " overflows u64");
    }
    return left + right;
}

std::uint64_t checked_mul(std::uint64_t left, std::uint64_t right,
                          const char *label) {
    if (left != 0 &&
        right > std::numeric_limits<std::uint64_t>::max() / left) {
        throw std::overflow_error(std::string(label) + " overflows u64");
    }
    return left * right;
}

std::size_t log2_exact(std::size_t value, const char *label) {
    if (value == 0 || !std::has_single_bit(value)) {
        throw std::invalid_argument(label);
    }
    return std::bit_width(value) - 1U;
}

void append_u64(std::vector<std::uint8_t> &output,
                std::uint64_t value) {
    for (std::size_t byte = 0; byte < 8; ++byte) {
        output.push_back(static_cast<std::uint8_t>(value >> (8U * byte)));
    }
}

void append_bytes(std::vector<std::uint8_t> &output,
                  std::span<const std::uint8_t> bytes) {
    output.insert(output.end(), bytes.begin(), bytes.end());
}

void append_string(std::vector<std::uint8_t> &output,
                   std::string_view value) {
    append_u64(output, checked_u64(value.size(), "identity string"));
    output.insert(output.end(), value.begin(), value.end());
}

void append_range(std::vector<std::uint8_t> &output,
                  const ProofOfPackingR1csRange &range) {
    append_u64(output, range.begin);
    append_u64(output, range.live);
    append_u64(output, range.extent);
}

void append_layout(std::vector<std::uint8_t> &output,
                   const ProofOfPackingR1csLayout &layout) {
    append_range(output, layout.rows.ciphertext_poseidon);
    append_range(output, layout.rows.ciphertext_outputs);
    append_range(output, layout.rows.challenge_bit_booleanity);
    append_range(output, layout.rows.challenge_word_recomposition);
    append_range(output, layout.rows.well_formedness_products);
    append_range(output, layout.rows.revealed_test_equalities);
    append_range(output, layout.rows.revealed_packing_equalities);
    append_u64(output, layout.rows.total);
    append_range(output, layout.witness.challenge_bits);
    append_range(output, layout.witness.aligned_coordinates);
    append_range(output, layout.witness.well_formedness_products);
    append_range(output, layout.witness.ciphertext_poseidon_auxiliary);
    append_u64(output, layout.witness.total);
    append_u64(output, layout.logical_inputs);
    append_u64(output, layout.poseidon_rows_per_permutation);
    append_u64(output, layout.ciphertext_permutations_per_hash);
    append_u64(output, layout.ciphertext_permutations);
    append_u64(output, layout.largest_ciphertext_segment);
    append_u64(output, checked_u64(layout.ciphertext_segments.size(),
                                   "Poseidon segment count"));
    for (const ProofOfPackingPoseidonSegment &segment :
         layout.ciphertext_segments) {
        append_u64(output, segment.permutation_begin);
        append_u64(output, segment.permutations);
        append_u64(output, segment.row_begin);
        append_u64(output, segment.input_witness_begin);
        append_u64(output, segment.auxiliary_witness_begin);
    }
}

void append_metadata(std::vector<std::uint8_t> &output,
                     const spartan::R1csMetadata &metadata) {
    append_u64(output, metadata.shape().constraints);
    append_u64(output, metadata.shape().public_inputs);
    append_u64(output, metadata.shape().witness_variables);
    append_u64(output, checked_u64(metadata.padded_constraints(),
                                   "padded constraints"));
    append_u64(output, checked_u64(metadata.assignment_half_size(),
                                   "assignment half"));
    append_bytes(output, metadata.digest());
}

void append_artifact(std::vector<std::uint8_t> &output,
                     const storage::NativeFieldArtifact &artifact) {
    append_bytes(output, artifact.identity());
    append_u64(output, artifact.physical_bytes());
    append_u64(output,
               checked_u64(artifact.arrays().size(), "artifact arrays"));
    for (const storage::NativeFieldArrayDescriptor &array :
         artifact.arrays()) {
        append_string(output, array.name);
        append_u64(output, static_cast<std::uint64_t>(array.kind));
        append_u64(output, array.element_count);
        append_u64(output, array.encoded_element_bytes);
        append_u64(output, array.physical_bytes);
        append_bytes(output, array.file_digest);
    }
}

void append_fq2(std::vector<std::uint8_t> &output, const Fq2 &value) {
    append_u64(output, value.coefficients()[0].value());
    append_u64(output, value.coefficients()[1].value());
}

bool same_range(const ProofOfPackingR1csRange &left,
                const ProofOfPackingR1csRange &right) {
    return left.begin == right.begin && left.live == right.live &&
           left.extent == right.extent;
}

bool same_layout(const ProofOfPackingR1csLayout &left,
                 const ProofOfPackingR1csLayout &right) {
    const auto same_segment = [](const ProofOfPackingPoseidonSegment &a,
                                 const ProofOfPackingPoseidonSegment &b) {
        return a.permutation_begin == b.permutation_begin &&
               a.permutations == b.permutations &&
               a.row_begin == b.row_begin &&
               a.input_witness_begin == b.input_witness_begin &&
               a.auxiliary_witness_begin == b.auxiliary_witness_begin;
    };
    return same_range(left.rows.ciphertext_poseidon,
                      right.rows.ciphertext_poseidon) &&
           same_range(left.rows.ciphertext_outputs,
                      right.rows.ciphertext_outputs) &&
           same_range(left.rows.challenge_bit_booleanity,
                      right.rows.challenge_bit_booleanity) &&
           same_range(left.rows.challenge_word_recomposition,
                      right.rows.challenge_word_recomposition) &&
           same_range(left.rows.well_formedness_products,
                      right.rows.well_formedness_products) &&
           same_range(left.rows.revealed_test_equalities,
                      right.rows.revealed_test_equalities) &&
           same_range(left.rows.revealed_packing_equalities,
                      right.rows.revealed_packing_equalities) &&
           left.rows.total == right.rows.total &&
           same_range(left.witness.challenge_bits,
                      right.witness.challenge_bits) &&
           same_range(left.witness.aligned_coordinates,
                      right.witness.aligned_coordinates) &&
           same_range(left.witness.well_formedness_products,
                      right.witness.well_formedness_products) &&
           same_range(left.witness.ciphertext_poseidon_auxiliary,
                      right.witness.ciphertext_poseidon_auxiliary) &&
           left.witness.total == right.witness.total &&
           left.logical_inputs == right.logical_inputs &&
           left.poseidon_rows_per_permutation ==
               right.poseidon_rows_per_permutation &&
           left.ciphertext_permutations_per_hash ==
               right.ciphertext_permutations_per_hash &&
           left.ciphertext_permutations == right.ciphertext_permutations &&
           left.largest_ciphertext_segment ==
               right.largest_ciphertext_segment &&
           left.ciphertext_segments.size() ==
               right.ciphertext_segments.size() &&
           std::equal(left.ciphertext_segments.begin(),
                      left.ciphertext_segments.end(),
                      right.ciphertext_segments.begin(), same_segment);
}

void validate_static_inputs(
    const OuterRelationPlan &plan,
    const ProofOfPackingR1csLayout &layout,
    const spartan::R1csMetadata &metadata,
    std::span<const Fq2> row_point) {
    const ProofOfPackingR1csLayout expected =
        make_proof_of_packing_r1cs_layout(plan);
    if (plan.shape.native_modulus != kOuterFieldOrder ||
        !same_layout(layout, expected) || !metadata.is_well_formed() ||
        metadata.shape() != spartan::R1csShape{
                                .constraints = layout.rows.total,
                                .public_inputs = layout.logical_inputs,
                                .witness_variables = layout.witness.total} ||
        metadata.padded_constraints() !=
            std::bit_ceil(checked_size(layout.rows.total,
                                      "Wiring row count")) ||
        row_point.size() != metadata.row_variables()) {
        throw std::invalid_argument(
            "proof-of-packing Wiring inputs are inconsistent");
    }
}

class DestinationCleanup {
  public:
    explicit DestinationCleanup(std::filesystem::path directory)
        : directory_(std::move(directory)) {}
    DestinationCleanup(const DestinationCleanup &) = delete;
    DestinationCleanup &operator=(const DestinationCleanup &) = delete;
    ~DestinationCleanup() {
        if (!armed_) {
            return;
        }
        std::error_code error;
        std::filesystem::directory_iterator entry(directory_, error);
        const std::filesystem::directory_iterator end;
        while (!error && entry != end) {
            const std::filesystem::path child = entry->path();
            entry.increment(error);
            std::error_code ignored;
            std::filesystem::remove_all(child, ignored);
        }
    }
    void disarm() { armed_ = false; }

  private:
    std::filesystem::path directory_;
    bool armed_ = true;
};

void validate_empty_directory(const std::filesystem::path &directory) {
    const std::filesystem::file_status status =
        std::filesystem::symlink_status(directory);
    if (!std::filesystem::is_directory(status) ||
        std::filesystem::is_symlink(status) ||
        !std::filesystem::is_empty(directory)) {
        throw std::invalid_argument(
            "proof-of-packing Wiring destination must be an empty real "
            "directory");
    }
}

bool path_prefix(const std::filesystem::path &prefix,
                 const std::filesystem::path &path) {
    auto left = prefix.begin();
    auto right = path.begin();
    while (left != prefix.end() && right != path.end() &&
           *left == *right) {
        ++left;
        ++right;
    }
    return left == prefix.end();
}

void require_disjoint_directories(
    const std::filesystem::path &destination,
    const std::filesystem::path &source) {
    const std::filesystem::path canonical_destination =
        std::filesystem::canonical(destination);
    const std::filesystem::path canonical_source =
        std::filesystem::canonical(source);
    std::error_code equivalent_error;
    const bool equivalent = std::filesystem::equivalent(
        canonical_destination, canonical_source, equivalent_error);
    if (equivalent_error) {
        throw std::filesystem::filesystem_error(
            "failed to compare Wiring storage directories",
            canonical_destination, canonical_source, equivalent_error);
    }
    if (equivalent ||
        path_prefix(canonical_destination, canonical_source) ||
        path_prefix(canonical_source, canonical_destination)) {
        throw std::invalid_argument(
            "Wiring destination and tensor source must be disjoint");
    }
}

struct ValidatedFactored {
    std::vector<PackingTensorMapping> mappings;
    std::size_t tensor_columns = 0;
};

ValidatedFactored validate_factored_preprocessing(
    const OuterRelationPlan &plan,
    const spartan::R1csMetadata &metadata,
    const spartan::FactoredMatrixProverKey &factored) {
    if (factored.tensor_column_source !=
            spartan::FactoredTensorColumnSource::Artifact ||
        factored.tensor_columns_artifact == nullptr ||
        factored.structure == nullptr ||
        factored.commitment.profile !=
            spartan::kFactoredMatrixProfileIdentifier ||
        factored.commitment.circuit_digest != metadata.digest() ||
        factored.commitment.circuit_digest !=
            factored.structure->circuit_digest() ||
        factored.commitment.structure_digest !=
            factored.structure->structure_digest() ||
        factored.commitment.row_variables != metadata.row_variables() ||
        factored.commitment.column_variables !=
            metadata.column_variables() ||
        factored.commitment.row_variables !=
            factored.structure->row_variables() ||
        factored.commitment.column_variables !=
            factored.structure->column_variables() ||
        factored.commitment.tensors.size() !=
            factored.structure->tensor_count() ||
        factored.tensors.size() != factored.commitment.tensors.size() ||
        factored.tensor_columns_artifact->identity() !=
            spartan::factored_matrix_artifact_identity(
                factored.commitment)) {
        throw std::invalid_argument(
            "Wiring requires artifact-backed committed-factored "
            "preprocessing for the same circuit");
    }

    ValidatedFactored result;
    result.mappings = proof_of_packing_factored_tensor_mappings(
        *factored.structure);
    if (result.mappings.size() !=
        plan.shape.logical_packed_outputs) {
        throw std::invalid_argument(
            "factored packing owner map has the wrong output count");
    }
    std::vector<std::size_t> appearances(
        plan.shape.aligned_ciphertexts, 0);
    for (std::size_t output = 0; output < result.mappings.size();
         ++output) {
        const auto &mapping = result.mappings[output];
        const auto &descriptor = mapping.descriptor;
        const spartan::FactoredTensorShape shape =
            factored.commitment.tensors[output].shape;
        if (descriptor.logical_output != output ||
            descriptor.live_owner_count != mapping.global_owners.size() ||
            descriptor.ring_degree != plan.shape.ring_degree ||
            descriptor.digit_count != plan.shape.packing_digit_count ||
            descriptor.padded_owner_count == 0 ||
            !std::has_single_bit(descriptor.padded_owner_count) ||
            shape.evaluation_count !=
                checked_mul(descriptor.padded_owner_count,
                            descriptor.ring_degree,
                            "factored tensor evaluations") ||
            shape.column_count != descriptor.digit_count ||
            shape != factored.structure->tensor_shape(output)) {
            throw std::invalid_argument(
                "factored packing tensor geometry is inconsistent");
        }
        bool first = true;
        std::size_t previous = 0;
        for (const std::size_t owner : mapping.global_owners) {
            if (owner >= appearances.size() ||
                (!first && owner <= previous)) {
                throw std::invalid_argument(
                    "factored packing owner map is noncanonical");
            }
            first = false;
            previous = owner;
            ++appearances[owner];
        }
        result.tensor_columns = checked_size(
            checked_add(checked_u64(result.tensor_columns,
                                    "factored tensor columns"),
                        checked_u64(descriptor.digit_count,
                                    "factored tensor digits"),
                        "factored tensor columns"),
            "factored tensor columns");
    }
    if (std::any_of(appearances.begin(), appearances.end(),
                    [](std::size_t count) { return count != 1; }) ||
        factored.tensor_columns_artifact->arrays().size() !=
            result.tensor_columns) {
        throw std::invalid_argument(
            "factored packing owners or artifact arrays are incomplete");
    }
    std::size_t array_index = 0;
    for (std::size_t output = 0; output < result.mappings.size();
         ++output) {
        const spartan::FactoredTensorShape shape =
            factored.commitment.tensors[output].shape;
        for (std::size_t digit = 0; digit < shape.column_count;
             ++digit, ++array_index) {
            const storage::NativeFieldArrayDescriptor &array =
                factored.tensor_columns_artifact->arrays()[array_index];
            if (array.name !=
                    spartan::factored_matrix_tensor_column_array_name(
                        output, digit) ||
                array.kind != storage::NativeFieldElementKind::Fq ||
                array.element_count != shape.evaluation_count ||
                array.encoded_element_bytes != sizeof(Fq)) {
                throw std::invalid_argument(
                    "factored tensor-column artifact layout is "
                    "inconsistent");
            }
        }
    }
    return result;
}

std::vector<Fq2> equality_table(std::span<const Fq2> point) {
    if (point.size() >= std::numeric_limits<std::size_t>::digits) {
        throw std::overflow_error("Wiring equality table is too large");
    }
    std::vector<Fq2> result(std::size_t{1} << point.size(), Fq2::zero());
    result[0] = Fq2::one();
    std::size_t active = 1;
    for (const Fq2 &coordinate : point) {
        for (std::size_t index = active; index-- > 0;) {
            const Fq2 previous = result[index];
            const Fq2 high = previous * coordinate;
            result[2 * index] = previous - high;
            result[2 * index + 1] = high;
        }
        active *= 2;
    }
    return result;
}

Fq2 equality_prefix_sum(std::span<const Fq2> point,
                        std::size_t exclusive_limit) {
    if (point.size() >= std::numeric_limits<std::size_t>::digits) {
        throw std::overflow_error("Wiring equality domain is too large");
    }
    const std::size_t domain = std::size_t{1} << point.size();
    if (exclusive_limit > domain) {
        throw std::out_of_range("Wiring equality prefix is out of range");
    }
    if (exclusive_limit == domain) {
        return Fq2::one();
    }
    Fq2 result = Fq2::zero();
    Fq2 equal_prefix = Fq2::one();
    for (std::size_t bit = 0; bit < point.size(); ++bit) {
        const bool one =
            ((exclusive_limit >> (point.size() - 1U - bit)) & 1U) != 0;
        if (one) {
            result += equal_prefix * (Fq2::one() - point[bit]);
            equal_prefix *= point[bit];
        } else {
            equal_prefix *= Fq2::one() - point[bit];
        }
    }
    return result;
}

class BlockedRowWeights {
  public:
    BlockedRowWeights(std::span<const Fq2> point,
                      std::size_t low_bits)
        : point_(point), low_bits_(low_bits) {
        if (low_bits > point.size()) {
            throw std::invalid_argument(
                "Wiring row split exceeds its point");
        }
        high_ = equality_table(point.first(point.size() - low_bits_));
        low_ = equality_table(point.last(low_bits_));
    }

    Fq2 value(std::uint64_t index) const {
        const std::uint64_t domain = checked_mul(
            checked_u64(high_.size(), "row high table"),
            checked_u64(low_.size(), "row low table"),
            "row equality domain");
        if (index >= domain) {
            throw std::out_of_range("Wiring row is out of range");
        }
        const std::uint64_t low_mask = low_.size() - 1U;
        return high_[checked_size(index >> low_bits_, "row high index")] *
               low_[checked_size(index & low_mask, "row low index")];
    }

    Fq2 range_sum(std::uint64_t begin, std::uint64_t end) const {
        if (begin > end) {
            throw std::invalid_argument("Wiring row range is reversed");
        }
        return equality_prefix_sum(point_, checked_size(end, "row end")) -
               equality_prefix_sum(point_,
                                   checked_size(begin, "row begin"));
    }

    Fq2 high_value(std::uint64_t index) const {
        return high_.at(checked_size(index, "row-prefix index"));
    }

    std::span<const Fq2> coordinate_weights() const { return low_; }

    std::uint64_t high_table_elements() const {
        return checked_u64(high_.size(), "row high table");
    }

    std::uint64_t low_table_elements() const {
        return checked_u64(low_.size(), "row low table");
    }

  private:
    std::span<const Fq2> point_;
    std::size_t low_bits_ = 0;
    std::vector<Fq2> high_;
    std::vector<Fq2> low_;
};

class TrackedFqReader {
  public:
    TrackedFqReader(const storage::NativeFieldArtifact &artifact,
                    std::string_view name,
                    ProofOfPackingWiringIoReport &report)
        : reader_(artifact.open_array(name)), report_(&report) {
        if (reader_.kind() != storage::NativeFieldElementKind::Fq) {
            throw std::invalid_argument("Wiring tensor source is not Fq");
        }
    }

    std::uint64_t size() const { return reader_.size(); }

    void seek(std::uint64_t position) {
        if (position > reader_.size()) {
            throw std::out_of_range("Wiring tensor seek is out of range");
        }
        if (reader_.position() != position) {
            reader_.seek(position);
            report_->seek_operations = checked_add(
                report_->seek_operations, 1, "tensor seek operations");
        }
    }

    void read_exact(std::span<Fq> output) {
        std::size_t offset = 0;
        while (offset < output.size()) {
            const std::size_t count = reader_.read(output.subspan(offset));
            if (count == 0) {
                throw std::runtime_error(
                    "Wiring tensor source ended unexpectedly");
            }
            report_->payload_bytes = checked_add(
                report_->payload_bytes,
                checked_mul(checked_u64(count, "tensor read elements"),
                            sizeof(Fq), "tensor read bytes"),
                "tensor read bytes");
            report_->read_operations = checked_add(
                report_->read_operations, 1, "tensor read operations");
            offset += count;
        }
    }

    void read_at(std::uint64_t position, std::span<Fq> output) {
        seek(position);
        read_exact(output);
    }

  private:
    storage::NativeFieldArrayReader reader_;
    ProofOfPackingWiringIoReport *report_ = nullptr;
};

class FqBlockCache {
  public:
    FqBlockCache(const storage::NativeFieldArtifact &artifact,
                 std::string_view name, std::size_t block_elements,
                 ProofOfPackingWiringIoReport &report)
        : reader_(artifact, name, report), buffer_(block_elements) {}

    Fq value(std::uint64_t index) {
        if (index >= reader_.size()) {
            throw std::out_of_range(
                "Wiring cached tensor index is out of range");
        }
        if (!loaded_ || index < begin_ || index >= begin_ + live_) {
            begin_ = (index / buffer_.size()) * buffer_.size();
            live_ = std::min<std::uint64_t>(
                buffer_.size(), reader_.size() - begin_);
            reader_.read_at(begin_, std::span<Fq>(buffer_).first(
                                        checked_size(live_, "cache block")));
            loaded_ = true;
        }
        return buffer_[checked_size(index - begin_, "cache offset")];
    }

  private:
    TrackedFqReader reader_;
    std::vector<Fq> buffer_;
    std::uint64_t begin_ = 0;
    std::uint64_t live_ = 0;
    bool loaded_ = false;
};

class BufferedFq2Output {
  public:
    BufferedFq2Output(storage::NativeFieldArtifactWriter &writer,
                      std::size_t block_elements,
                      ProofOfPackingWiringArtifactReport &report)
        : writer_(&writer), buffer_(block_elements), report_(&report) {}

    void push(const Fq2 &value) {
        buffer_[live_++] = value;
        ++position_;
        if (live_ == buffer_.size()) {
            flush();
        }
    }

    void zeros(std::uint64_t count) {
        for (std::uint64_t index = 0; index < count; ++index) {
            push(Fq2::zero());
        }
    }

    void pad_to(std::uint64_t target) {
        if (position_ > target) {
            throw std::logic_error("Wiring column families overlap");
        }
        zeros(target - position_);
    }

    std::uint64_t position() const { return position_; }
    void finish() { flush(); }

  private:
    void flush() {
        if (live_ == 0) {
            return;
        }
        writer_->append(std::span<const Fq2>(buffer_).first(live_));
        report_->sequential_output_payload_bytes = checked_add(
            report_->sequential_output_payload_bytes,
            checked_mul(checked_u64(live_, "Wiring output elements"),
                        sizeof(Fq2), "Wiring output bytes"),
            "Wiring sequential output bytes");
        report_->sequential_output_operations = checked_add(
            report_->sequential_output_operations, 1,
            "Wiring sequential output operations");
        live_ = 0;
    }

    storage::NativeFieldArtifactWriter *writer_ = nullptr;
    std::vector<Fq2> buffer_;
    ProofOfPackingWiringArtifactReport *report_ = nullptr;
    std::size_t live_ = 0;
    std::uint64_t position_ = 0;
};

struct LocalTerm {
    const spartan::R1csEntry *entry = nullptr;
    spartan::Matrix matrix = spartan::Matrix::A;
};

struct PoseidonAdjacency {
    std::vector<LocalTerm> constant;
    std::array<std::vector<LocalTerm>, kPoseidonWidth> prior;
    std::array<std::vector<LocalTerm>, kPoseidonRate> input;
    std::vector<std::vector<LocalTerm>> auxiliary;
    std::vector<std::vector<std::size_t>> final_words;
};

PoseidonAdjacency make_poseidon_adjacency() {
    const auto &local =
        detail::proof_of_packing_poseidon_permutation_template();
    PoseidonAdjacency result;
    result.auxiliary.resize(checked_size(local.rows,
                                         "Poseidon auxiliary count"));
    result.final_words.resize(result.auxiliary.size());
    for (std::size_t word = 0; word < kPoseidonWidth; ++word) {
        if (local.final_auxiliary[word] >= local.rows) {
            throw std::logic_error(
                "Poseidon final auxiliary is out of range");
        }
        result.final_words[checked_size(local.final_auxiliary[word],
                                        "Poseidon final auxiliary")]
            .push_back(word);
    }
    const std::array<std::span<const spartan::R1csEntry>, 3> matrices{
        std::span<const spartan::R1csEntry>(local.a),
        std::span<const spartan::R1csEntry>(local.b),
        std::span<const spartan::R1csEntry>(local.c)};
    for (std::size_t matrix = 0; matrix < matrices.size(); ++matrix) {
        for (const spartan::R1csEntry &entry : matrices[matrix]) {
            if (entry.row >= local.rows) {
                throw std::logic_error(
                    "Poseidon template row is out of range");
            }
            const LocalTerm term{&entry,
                                 static_cast<spartan::Matrix>(matrix)};
            if (entry.column == 0) {
                result.constant.push_back(term);
            } else if (entry.column <= kPoseidonWidth) {
                result.prior[checked_size(entry.column - 1,
                                          "Poseidon prior word")]
                    .push_back(term);
            } else if (entry.column <=
                       kPoseidonWidth + kPoseidonRate) {
                result.input[checked_size(
                                 entry.column - 1 - kPoseidonWidth,
                                 "Poseidon input word")]
                    .push_back(term);
            } else {
                const std::uint64_t auxiliary =
                    entry.column - 1 - kPoseidonWidth - kPoseidonRate;
                if (auxiliary >= local.rows) {
                    throw std::logic_error(
                        "Poseidon template column is out of range");
                }
                result.auxiliary[checked_size(
                                     auxiliary,
                                     "Poseidon auxiliary column")]
                    .push_back(term);
            }
        }
    }
    return result;
}

Fq2 batching_scale(spartan::Matrix matrix, const Fq2 &gamma,
                   const Fq2 &gamma_squared) {
    switch (matrix) {
    case spartan::Matrix::A:
        return Fq2::one();
    case spartan::Matrix::B:
        return gamma;
    case spartan::Matrix::C:
        return gamma_squared;
    }
    throw std::logic_error("unknown Wiring matrix");
}

Fq2 evaluate_local_terms(
    std::span<const LocalTerm> terms,
    const ProofOfPackingPoseidonSegment &segment,
    std::uint64_t local_permutation,
    const BlockedRowWeights &rows, const Fq2 &gamma,
    const Fq2 &gamma_squared) {
    Fq2 result = Fq2::zero();
    for (const LocalTerm &term : terms) {
        const std::uint64_t row = checked_add(
            segment.row_begin,
            checked_add(
                checked_mul(term.entry->row, segment.permutations,
                            "Poseidon transposed row"),
                local_permutation, "Poseidon transposed row"),
            "Poseidon transposed row");
        result += batching_scale(term.matrix, gamma, gamma_squared) *
                  term.entry->value * rows.value(row);
    }
    return result;
}

Fq2 evaluate_constant_poseidon_column(
    const OuterRelationPlan &plan,
    const ProofOfPackingR1csLayout &layout,
    const PoseidonAdjacency &adjacency,
    const BlockedRowWeights &rows, const Fq2 &gamma,
    const Fq2 &gamma_squared) {
    Fq2 result = Fq2::zero();
    for (const LocalTerm &term : adjacency.constant) {
        const Fq2 coefficient =
            batching_scale(term.matrix, gamma, gamma_squared) *
            term.entry->value;
        for (const ProofOfPackingPoseidonSegment &segment :
             layout.ciphertext_segments) {
            const std::uint64_t begin = checked_add(
                segment.row_begin,
                checked_mul(term.entry->row, segment.permutations,
                            "Poseidon constant row"),
                "Poseidon constant row");
            result += coefficient * rows.range_sum(
                                      begin,
                                      checked_add(begin,
                                                  segment.permutations,
                                                  "Poseidon row range"));
        }
    }

    const std::uint64_t preimage = checked_add(
        gkr::kCiphertextCommitmentMetadataElements,
        checked_mul(plan.shape.ciphertext_components,
                    plan.shape.ring_degree,
                    "ciphertext Poseidon preimage"),
        "ciphertext Poseidon preimage");
    const std::array<Fq, gkr::kCiphertextCommitmentMetadataElements>
        metadata{
            Fq(plan.shape.ring_degree),
            Fq(gkr::kCiphertextCommitmentComponents),
            Fq(gkr::kCiphertextCommitmentNttFlag),
            Fq(gkr::kCiphertextCommitmentCorrectionFactor)};
    std::array<Fq, kPoseidonWidth> initial{};
    initial[kPoseidonRate] = Fq(static_cast<std::uint64_t>(
        PoseidonDomain::CiphertextCommitment));
    initial[kPoseidonRate + 1] = Fq(preimage);
    initial[kPoseidonRate + 2] = Fq(preimage);
    initial[kPoseidonRate + 3] =
        Fq(kPoseidonEncodingVersionDelimiter);

    const std::uint64_t permutations_per_hash =
        layout.ciphertext_permutations_per_hash;
    for (std::size_t ciphertext = 0;
         ciphertext < plan.shape.aligned_ciphertexts; ++ciphertext) {
        const std::uint64_t first_permutation = checked_mul(
            ciphertext, permutations_per_hash,
            "ciphertext first permutation");
        const ProofOfPackingPoseidonSegment &first_segment =
            layout.ciphertext_segment(first_permutation);
        const std::uint64_t first_local =
            first_permutation - first_segment.permutation_begin;
        for (std::size_t word = 0; word < initial.size(); ++word) {
            if (!initial[word].is_zero()) {
                result += evaluate_local_terms(
                              adjacency.prior[word], first_segment,
                              first_local, rows, gamma, gamma_squared) *
                          initial[word];
            }
        }
        for (std::size_t input = 0; input < metadata.size(); ++input) {
            const std::uint64_t permutation = checked_add(
                first_permutation, input / kPoseidonRate,
                "metadata permutation");
            const auto &segment = layout.ciphertext_segment(permutation);
            result += evaluate_local_terms(
                          adjacency.input[input % kPoseidonRate], segment,
                          permutation - segment.permutation_begin, rows,
                          gamma, gamma_squared) *
                      metadata[input];
        }
        const std::uint64_t padding_permutation = checked_add(
            first_permutation, preimage / kPoseidonRate,
            "padding permutation");
        const auto &padding_segment =
            layout.ciphertext_segment(padding_permutation);
        result += evaluate_local_terms(
            adjacency.input[checked_size(preimage % kPoseidonRate,
                                         "padding rate")],
            padding_segment,
            padding_permutation - padding_segment.permutation_begin,
            rows, gamma, gamma_squared) *
                  Fq2::from_base(Fq(kPoseidonRatePaddingDelimiter));
    }
    return result;
}

Fq2 evaluate_constant_simple_hash_column(
    const OuterRelationPlan &plan,
    const ProofOfPackingR1csLayout &layout,
    const BlockedRowWeights &rows) {
    const std::size_t q = plan.coordinates_per_ciphertext();
    const Fq initial =
        gkr::diagnostic_simple_ct_hash_initial_state(
            plan.shape.ring_degree);
    const Fq first_scale =
        Fq(gkr::kDiagnosticSimpleCtHashAlpha) * initial;
    Fq2 result = Fq2::zero();
    for (std::size_t ciphertext = 0;
         ciphertext < plan.shape.aligned_ciphertexts; ++ciphertext) {
        result += rows.value(layout.ciphertext_simple_hash_row(
                      plan, ciphertext, 0)) *
                  first_scale;
        for (std::size_t element = 0;
             element < kPoseidonDigestElements; ++element) {
            result += rows.value(layout.ciphertext_output_row(
                          ciphertext, element)) *
                      Fq(gkr::kDiagnosticSimpleCtHashOutputDomains[
                          element]);
        }
    }
    if (layout.rows.ciphertext_poseidon.live !=
        checked_mul(plan.shape.aligned_ciphertexts, q,
                    "diagnostic hash row count")) {
        throw std::logic_error(
            "diagnostic ciphertext-hash rows have the wrong size");
    }
    return result;
}

struct OwnerAddress {
    std::size_t tensor = 0;
    std::size_t local_owner = 0;
};

std::vector<OwnerAddress> make_owner_addresses(
    const OuterRelationPlan &plan,
    std::span<const PackingTensorMapping> mappings) {
    std::vector<OwnerAddress> result(plan.shape.aligned_ciphertexts);
    std::vector<bool> seen(result.size(), false);
    for (std::size_t tensor = 0; tensor < mappings.size(); ++tensor) {
        for (std::size_t local = 0;
             local < mappings[tensor].global_owners.size(); ++local) {
            const std::size_t owner =
                mappings[tensor].global_owners[local];
            if (owner >= result.size() || seen[owner]) {
                throw std::logic_error("Wiring owner map is inconsistent");
            }
            seen[owner] = true;
            result[owner] = OwnerAddress{tensor, local};
        }
    }
    if (std::any_of(seen.begin(), seen.end(),
                    [](bool value) { return !value; })) {
        throw std::logic_error("Wiring owner map is incomplete");
    }
    return result;
}

struct FamilyWeights {
    std::vector<Fq2> product;
    std::vector<Fq2> owner_product_sum;
    std::vector<Fq2> test;
    std::vector<Fq2> packing;
};

FamilyWeights make_family_weights(
    const OuterRelationPlan &plan,
    const ProofOfPackingR1csLayout &layout,
    const BlockedRowWeights &rows) {
    const std::uint64_t q = checked_u64(
        plan.coordinates_per_ciphertext(), "ciphertext coordinates");
    const auto high = [&](std::uint64_t row) {
        if (row % q != 0) {
            throw std::logic_error(
                "Wiring coordinate family is not q-aligned");
        }
        return rows.high_value(row / q);
    };

    FamilyWeights result;
    const std::size_t pairs =
        plan.shape.repetitions * plan.shape.aligned_ciphertexts;
    result.product.reserve(pairs);
    result.owner_product_sum.assign(plan.shape.aligned_ciphertexts,
                                    Fq2::zero());
    for (std::size_t test = 0; test < plan.shape.repetitions; ++test) {
        for (std::size_t aligned = 0;
             aligned < plan.shape.aligned_ciphertexts; ++aligned) {
            const std::uint64_t local = checked_add(
                checked_mul(test, plan.shape.aligned_ciphertexts,
                            "product row family"),
                aligned, "product row family");
            const Fq2 value = high(checked_add(
                layout.rows.well_formedness_products.begin,
                checked_mul(local, q, "product row family"),
                "product row family"));
            result.product.push_back(value);
            result.owner_product_sum[aligned] += value;
        }
    }
    result.test.reserve(plan.shape.repetitions);
    for (std::size_t test = 0; test < plan.shape.repetitions; ++test) {
        result.test.push_back(high(checked_add(
            layout.rows.revealed_test_equalities.begin,
            checked_mul(test, q, "test row family"),
            "test row family")));
    }
    const std::size_t packing_count =
        plan.shape.logical_packed_outputs *
        plan.shape.packing_digit_count;
    result.packing.reserve(packing_count);
    for (std::size_t physical = 0; physical < packing_count;
         ++physical) {
        result.packing.push_back(high(checked_add(
            layout.rows.revealed_packing_equalities.begin,
            checked_mul(physical, q, "packing row family"),
            "packing row family")));
    }
    return result;
}

std::uint64_t family_weight_elements(const FamilyWeights &weights) {
    return checked_add(
        checked_add(checked_u64(weights.product.size(), "product weights"),
                    checked_u64(weights.owner_product_sum.size(),
                                "owner product weights"),
                    "row-family weights"),
        checked_add(checked_u64(weights.test.size(), "test weights"),
                    checked_u64(weights.packing.size(), "packing weights"),
                    "row-family weights"),
        "row-family weights");
}

} // namespace

std::uint64_t proof_of_packing_wiring_matrix_payload_bytes(
    const spartan::R1csMetadata &circuit_metadata) {
    if (!circuit_metadata.is_well_formed()) {
        throw std::invalid_argument("Wiring metadata is malformed");
    }
    const std::uint64_t elements = checked_add(
        checked_add(circuit_metadata.shape().public_inputs, 1,
                    "Wiring public prefix"),
        circuit_metadata.shape().witness_variables,
        "Wiring compact elements");
    return checked_mul(
        elements,
        storage::encoded_element_bytes(
            storage::NativeFieldElementKind::Fq2),
        "Wiring compact payload");
}

std::uint64_t proof_of_packing_wiring_matrix_artifact_physical_bytes(
    const spartan::R1csMetadata &circuit_metadata) {
    if (!circuit_metadata.is_well_formed()) {
        throw std::invalid_argument("Wiring metadata is malformed");
    }
    const std::array<storage::NativeFieldArrayLayout, 2> arrays{{
        {std::string(kProofOfPackingWiringPublicColumns),
         storage::NativeFieldElementKind::Fq2,
         checked_add(circuit_metadata.shape().public_inputs, 1,
                     "Wiring public columns")},
        {std::string(kProofOfPackingWiringWitnessColumns),
         storage::NativeFieldElementKind::Fq2,
         circuit_metadata.shape().witness_variables},
    }};
    return storage::native_field_artifact_physical_bytes(arrays);
}

ProofOfPackingWiringArtifactPlan
plan_proof_of_packing_wiring_matrix_artifact(
    const OuterRelationPlan &plan,
    const ProofOfPackingR1csLayout &layout,
    const spartan::R1csMetadata &circuit_metadata,
    const spartan::FactoredMatrixProverKey &factored_preprocessing,
    std::uint64_t max_working_field_bytes,
    std::size_t requested_block_elements) {
    if (max_working_field_bytes == 0 || requested_block_elements == 0) {
        throw std::invalid_argument(
            "Wiring planning needs explicit nonzero memory limits");
    }
    if (!same_layout(layout, make_proof_of_packing_r1cs_layout(plan))) {
        throw std::invalid_argument(
            "Wiring planning layout does not match the relation");
    }
    const ValidatedFactored validated = validate_factored_preprocessing(
        plan, circuit_metadata, factored_preprocessing);
    const std::size_t row_variables = circuit_metadata.row_variables();
    const std::size_t q = plan.coordinates_per_ciphertext();
    const std::size_t coordinate_bits = log2_exact(
        q, "ciphertext coordinate count is not a power of two");
    if (coordinate_bits > row_variables) {
        throw std::invalid_argument(
            "ciphertext coordinate domain exceeds Wiring rows");
    }
    const std::uint64_t row_prefix_elements =
        std::uint64_t{1} << (row_variables - coordinate_bits);
    const std::uint64_t coordinate_elements = checked_u64(
        q, "coordinate equality table elements");
    const std::uint64_t family_elements = checked_add(
        checked_add(
            checked_mul(plan.shape.repetitions,
                        plan.shape.aligned_ciphertexts,
                        "product family weights"),
            plan.shape.aligned_ciphertexts,
            "row-family weights"),
        checked_add(
            plan.shape.repetitions,
            checked_mul(plan.shape.logical_packed_outputs,
                        plan.shape.packing_digit_count,
                        "packing family weights"),
            "row-family weights"),
        "row-family weights");
    const std::uint64_t retained_fq2_elements = checked_add(
        checked_add(row_prefix_elements, coordinate_elements,
                    "Wiring retained equality elements"),
        family_elements, "Wiring retained Fq2 elements");
    const std::uint64_t retained_fq2_bytes = checked_mul(
        retained_fq2_elements, sizeof(Fq2),
        "Wiring retained Fq2 bytes");
    const std::uint64_t bytes_per_block_element = checked_add(
        sizeof(Fq2),
        checked_mul(validated.tensor_columns, sizeof(Fq),
                    "Wiring tensor-cache stride"),
        "Wiring live block stride");
    const std::uint64_t minimum_working_field_bytes = checked_add(
        retained_fq2_bytes, bytes_per_block_element,
        "minimum Wiring working bytes");
    if (max_working_field_bytes < minimum_working_field_bytes) {
        throw std::invalid_argument(
            "Wiring memory limit cannot hold its retained tables and one "
            "I/O block");
    }
    const std::uint64_t block_capacity =
        (max_working_field_bytes - retained_fq2_bytes) /
        bytes_per_block_element;
    const std::size_t block_elements = std::min(
        requested_block_elements,
        checked_size(block_capacity, "Wiring block capacity"));
    const std::uint64_t tensor_cache_elements = checked_mul(
        validated.tensor_columns, block_elements,
        "Wiring tensor cache elements");
    const std::uint64_t physical_bytes =
        proof_of_packing_wiring_matrix_artifact_physical_bytes(
            circuit_metadata);
    return {
        .physical_bytes = physical_bytes,
        .source_artifact_physical_bytes =
            factored_preprocessing.tensor_columns_artifact->physical_bytes(),
        .peak_live_storage_bytes = checked_add(
            factored_preprocessing.tensor_columns_artifact->physical_bytes(),
            physical_bytes, "Wiring live source and output bytes"),
        .row_prefix_equality_table_elements = row_prefix_elements,
        .coordinate_equality_table_elements = coordinate_elements,
        .row_family_weight_elements = family_elements,
        .tensor_columns = validated.tensor_columns,
        .retained_working_field_bytes = retained_fq2_bytes,
        .minimum_working_field_bytes = minimum_working_field_bytes,
        .effective_block_elements = block_elements,
        .tensor_cache_elements = tensor_cache_elements,
        .peak_working_field_bytes = checked_add(
            retained_fq2_bytes,
            checked_mul(block_elements, bytes_per_block_element,
                        "Wiring live block bytes"),
            "Wiring peak field bytes"),
    };
}

ProofOfPackingWiringIoReport
estimate_proof_of_packing_wiring_tensor_io(
    const OuterRelationPlan &plan,
    const ProofOfPackingR1csLayout &layout,
    std::span<const PackingTensorMapping> mappings,
    std::size_t block_elements) {
    if (block_elements == 0 ||
        !same_layout(layout, make_proof_of_packing_r1cs_layout(plan)) ||
        mappings.size() != plan.shape.logical_packed_outputs) {
        throw std::invalid_argument(
            "Wiring tensor-I/O estimate has inconsistent geometry");
    }
    for (std::size_t tensor = 0; tensor < mappings.size(); ++tensor) {
        const PackingTensorDescriptor &descriptor =
            mappings[tensor].descriptor;
        if (descriptor.logical_output != tensor ||
            descriptor.live_owner_count !=
                mappings[tensor].global_owners.size() ||
            descriptor.padded_owner_count == 0 ||
            !std::has_single_bit(descriptor.padded_owner_count) ||
            descriptor.ring_degree != plan.shape.ring_degree ||
            descriptor.digit_count != plan.shape.packing_digit_count) {
            throw std::invalid_argument(
                "Wiring tensor-I/O estimate has malformed owner geometry");
        }
    }
    const std::vector<OwnerAddress> owners =
        make_owner_addresses(plan, mappings);

    struct CacheState {
        std::uint64_t begin = 0;
        std::uint64_t live = 0;
        std::uint64_t reader_position = 0;
        bool loaded = false;
    };
    std::vector<CacheState> caches(mappings.size());
    ProofOfPackingWiringIoReport report;
    const std::uint64_t preimage = checked_add(
        gkr::kCiphertextCommitmentMetadataElements,
        checked_mul(plan.shape.ciphertext_components,
                    plan.shape.ring_degree,
                    "Wiring tensor-I/O preimage"),
        "Wiring tensor-I/O preimage");
    const std::uint64_t permutations_per_hash =
        layout.ciphertext_permutations_per_hash;
    const std::uint64_t block = checked_u64(
        block_elements, "Wiring tensor-I/O block");
    const std::uint64_t digit_count = checked_u64(
        plan.shape.packing_digit_count, "Wiring tensor-I/O digits");

    for (const ProofOfPackingPoseidonSegment &segment :
         layout.ciphertext_segments) {
        for (std::size_t rate = 0; rate < kPoseidonRate; ++rate) {
            for (std::uint64_t local = 0;
                 local < segment.permutations; ++local) {
                const std::uint64_t permutation = checked_add(
                    segment.permutation_begin, local,
                    "Wiring tensor-I/O permutation");
                const std::uint64_t input = checked_add(
                    checked_mul(permutation % permutations_per_hash,
                                kPoseidonRate,
                                "Wiring tensor-I/O input"),
                    rate, "Wiring tensor-I/O input");
                if (input < gkr::kCiphertextCommitmentMetadataElements ||
                    input >= preimage) {
                    continue;
                }
                const std::size_t aligned = checked_size(
                    permutation / permutations_per_hash,
                    "Wiring tensor-I/O owner");
                const std::uint64_t coordinate =
                    (input - gkr::kCiphertextCommitmentMetadataElements) %
                    plan.shape.ring_degree;
                const OwnerAddress &owner = owners.at(aligned);
                const PackingTensorDescriptor &descriptor =
                    mappings[owner.tensor].descriptor;
                const std::uint64_t evaluation_count = checked_mul(
                    descriptor.padded_owner_count, descriptor.ring_degree,
                    "Wiring tensor-I/O evaluations");
                const std::uint64_t address = checked_add(
                    checked_mul(owner.local_owner, descriptor.ring_degree,
                                "Wiring tensor-I/O owner address"),
                    coordinate, "Wiring tensor-I/O address");
                CacheState &cache = caches.at(owner.tensor);
                if (cache.loaded && address >= cache.begin &&
                    address - cache.begin < cache.live) {
                    continue;
                }
                const std::uint64_t begin = (address / block) * block;
                const std::uint64_t live =
                    std::min(block, evaluation_count - begin);
                if (cache.reader_position != begin) {
                    report.seek_operations = checked_add(
                        report.seek_operations, digit_count,
                        "Wiring tensor-I/O seeks");
                }
                report.read_operations = checked_add(
                    report.read_operations, digit_count,
                    "Wiring tensor-I/O reads");
                report.payload_bytes = checked_add(
                    report.payload_bytes,
                    checked_mul(
                        checked_mul(live, digit_count,
                                    "Wiring tensor-I/O loaded elements"),
                        sizeof(Fq), "Wiring tensor-I/O bytes"),
                    "Wiring tensor-I/O bytes");
                cache = CacheState{
                    .begin = begin,
                    .live = live,
                    .reader_position = checked_add(
                        begin, live, "Wiring tensor-I/O reader position"),
                    .loaded = true,
                };
            }
        }
    }
    return report;
}

Digest proof_of_packing_wiring_matrix_artifact_identity(
    const OuterRelationPlan &plan,
    const ProofOfPackingR1csLayout &layout,
    const spartan::R1csMetadata &circuit_metadata,
    const spartan::FactoredMatrixProverKey &factored_preprocessing,
    std::span<const Fq2> row_point, const Fq2 &gamma) {
    validate_static_inputs(plan, layout, circuit_metadata, row_point);
    const ValidatedFactored validated = validate_factored_preprocessing(
        plan, circuit_metadata, factored_preprocessing);

    std::vector<std::uint8_t> encoding(kIdentityDomain.begin(),
                                       kIdentityDomain.end());
    append_bytes(encoding,
                 outer_relation_assignment_artifact_identity(plan));
    append_layout(encoding, layout);
    append_metadata(encoding, circuit_metadata);
    append_u64(encoding,
               factored_preprocessing.structure->row_variables());
    append_u64(encoding,
               factored_preprocessing.structure->column_variables());
    append_bytes(encoding,
                 factored_preprocessing.structure->circuit_digest());
    append_bytes(encoding,
                 factored_preprocessing.structure->structure_digest());
    append_u64(encoding,
               checked_u64(validated.mappings.size(),
                           "factored mapping count"));
    for (const auto &mapping : validated.mappings) {
        append_u64(encoding, mapping.descriptor.logical_output);
        append_u64(encoding, mapping.descriptor.live_owner_count);
        append_u64(encoding, mapping.descriptor.padded_owner_count);
        append_u64(encoding, mapping.descriptor.ring_degree);
        append_u64(encoding, mapping.descriptor.digit_count);
        append_u64(encoding,
                   checked_u64(mapping.global_owners.size(),
                               "factored owner count"));
        for (const std::size_t owner : mapping.global_owners) {
            append_u64(encoding, checked_u64(owner, "factored owner"));
        }
    }
    const std::vector<std::uint8_t> commitment =
        spartan::encode_factored_matrix_commitment(
            factored_preprocessing.commitment);
    append_u64(encoding,
               checked_u64(commitment.size(), "factored commitment"));
    append_bytes(encoding, commitment);
    append_artifact(encoding,
                    *factored_preprocessing.tensor_columns_artifact);
    append_u64(encoding, checked_u64(row_point.size(), "row point"));
    for (const Fq2 &coordinate : row_point) {
        append_fq2(encoding, coordinate);
    }
    append_fq2(encoding, gamma);
    append_u64(encoding,
               checked_add(circuit_metadata.shape().public_inputs, 1,
                           "Wiring public prefix"));
    append_u64(encoding,
               circuit_metadata.shape().witness_variables);
    append_u64(encoding,
               checked_u64(circuit_metadata.assignment_half_size(),
                           "Wiring assignment half"));
    return sha256(encoding);
}

std::shared_ptr<const storage::NativeFieldArtifact>
open_proof_of_packing_wiring_matrix_artifact(
    const std::filesystem::path &directory,
    const OuterRelationPlan &plan,
    const ProofOfPackingR1csLayout &layout,
    const spartan::R1csMetadata &circuit_metadata,
    const spartan::FactoredMatrixProverKey &factored_preprocessing,
    std::span<const Fq2> row_point, const Fq2 &gamma) {
    if (factored_preprocessing.tensor_columns_artifact == nullptr) {
        throw std::invalid_argument(
            "Wiring factored tensor artifact is absent");
    }
    spartan::FactoredMatrixProverKey validated_factored =
        factored_preprocessing;
    validated_factored.tensor_columns_artifact =
        spartan::open_factored_matrix_artifact(
            factored_preprocessing.tensor_columns_artifact->directory(),
            factored_preprocessing.commitment);
    auto artifact = std::make_shared<storage::NativeFieldArtifact>(
        storage::NativeFieldArtifact::open(
            directory,
            proof_of_packing_wiring_matrix_artifact_identity(
                plan, layout, circuit_metadata, validated_factored,
                row_point, gamma)));
    const std::uint64_t public_count = checked_add(
        circuit_metadata.shape().public_inputs, 1,
        "Wiring public prefix");
    const std::array<storage::NativeFieldArrayLayout, 2> expected{{
        {std::string(kProofOfPackingWiringPublicColumns),
         storage::NativeFieldElementKind::Fq2, public_count},
        {std::string(kProofOfPackingWiringWitnessColumns),
         storage::NativeFieldElementKind::Fq2,
         circuit_metadata.shape().witness_variables},
    }};
    if (artifact->arrays().size() != expected.size()) {
        throw std::invalid_argument(
            "proof-of-packing Wiring artifact has wrong array count");
    }
    for (std::size_t index = 0; index < expected.size(); ++index) {
        const storage::NativeFieldArrayDescriptor &array =
            artifact->arrays()[index];
        if (array.name != expected[index].name ||
            array.kind != expected[index].kind ||
            array.element_count != expected[index].element_count ||
            array.encoded_element_bytes != sizeof(Fq2)) {
            throw std::invalid_argument(
                "proof-of-packing Wiring artifact has wrong layout");
        }
    }
    return artifact;
}

namespace {

void validate_compact_matrix_layout(
    const storage::NativeFieldArtifact &artifact,
    const spartan::R1csMetadata &metadata) {
    if (!metadata.is_well_formed() || artifact.arrays().size() != 2) {
        throw std::invalid_argument(
            "compact Wiring artifact or metadata is malformed");
    }
    const std::array<storage::NativeFieldArrayLayout, 2> expected{{
        {std::string(kProofOfPackingWiringPublicColumns),
         storage::NativeFieldElementKind::Fq2,
         checked_add(metadata.shape().public_inputs, 1,
                     "Wiring public prefix")},
        {std::string(kProofOfPackingWiringWitnessColumns),
         storage::NativeFieldElementKind::Fq2,
         metadata.shape().witness_variables},
    }};
    for (std::size_t index = 0; index < expected.size(); ++index) {
        const auto &actual = artifact.arrays()[index];
        if (actual.name != expected[index].name ||
            actual.kind != expected[index].kind ||
            actual.element_count != expected[index].element_count ||
            actual.encoded_element_bytes != sizeof(Fq2)) {
            throw std::invalid_argument(
                "compact Wiring artifact has wrong prefixes");
        }
    }
}

void read_fq2_exact(storage::NativeFieldArrayReader &reader,
                    std::span<Fq2> output) {
    std::size_t offset = 0;
    while (offset < output.size()) {
        const std::size_t count = reader.read(output.subspan(offset));
        if (count == 0) {
            throw std::runtime_error(
                "compact Wiring artifact ended unexpectedly");
        }
        offset += count;
    }
}

void read_logical_overlap(
    const storage::NativeFieldArtifact &artifact,
    std::string_view array_name, std::uint64_t logical_begin,
    std::uint64_t logical_end, std::uint64_t request_begin,
    std::span<Fq2> output) {
    const std::uint64_t request_end = checked_add(
        request_begin, checked_u64(output.size(), "Wiring read span"),
        "Wiring read end");
    const std::uint64_t overlap_begin =
        std::max(logical_begin, request_begin);
    const std::uint64_t overlap_end = std::min(logical_end, request_end);
    if (overlap_begin >= overlap_end) {
        return;
    }
    auto reader = artifact.open_array(array_name);
    reader.seek(overlap_begin - logical_begin);
    read_fq2_exact(
        reader,
        output.subspan(
            checked_size(overlap_begin - request_begin,
                         "Wiring output offset"),
            checked_size(overlap_end - overlap_begin,
                         "Wiring overlap length")));
}

} // namespace

void read_proof_of_packing_wiring_matrix_range(
    const storage::NativeFieldArtifact &artifact,
    const spartan::R1csMetadata &circuit_metadata,
    std::uint64_t begin, std::span<Fq2> output) {
    validate_compact_matrix_layout(artifact, circuit_metadata);
    const std::uint64_t logical_size = checked_mul(
        2, checked_u64(circuit_metadata.assignment_half_size(),
                       "Wiring assignment half"),
        "Wiring logical size");
    const std::uint64_t end = checked_add(
        begin, checked_u64(output.size(), "Wiring read length"),
        "Wiring read end");
    if (end > logical_size) {
        throw std::out_of_range(
            "compact Wiring logical read is out of range");
    }
    std::fill(output.begin(), output.end(), Fq2::zero());
    const std::uint64_t public_count = checked_add(
        circuit_metadata.shape().public_inputs, 1,
        "Wiring public prefix");
    const std::uint64_t witness_begin = checked_u64(
        circuit_metadata.assignment_half_size(),
        "Wiring witness begin");
    read_logical_overlap(
        artifact, kProofOfPackingWiringPublicColumns, 0, public_count,
        begin, output);
    read_logical_overlap(
        artifact, kProofOfPackingWiringWitnessColumns, witness_begin,
        checked_add(witness_begin,
                    circuit_metadata.shape().witness_variables,
                    "Wiring witness end"),
        begin, output);
}

namespace {

Fq2 public_column_value(
    const OuterRelationPlan &plan,
    const ProofOfPackingR1csLayout &layout,
    const BlockedRowWeights &rows, std::uint64_t logical_input,
    const Fq2 &gamma_squared) {
    const std::uint64_t commitment_fields = checked_mul(
        plan.shape.aligned_ciphertexts, kPoseidonDigestElements,
        "commitment field count");
    if (logical_input < commitment_fields) {
        const std::size_t ciphertext = checked_size(
            logical_input / kPoseidonDigestElements,
            "commitment ciphertext");
        const std::size_t element = checked_size(
            logical_input % kPoseidonDigestElements,
            "commitment digest element");
        return gamma_squared *
               rows.value(layout.ciphertext_output_row(ciphertext,
                                                       element));
    }
    const std::uint64_t outer = logical_input - commitment_fields;
    std::uint64_t row = 0;
    const auto map = [&](const OuterRelationRange &source,
                         const ProofOfPackingR1csRange &destination) {
        return checked_add(destination.begin, outer - source.begin,
                           "public Wiring row");
    };
    if (outer >= plan.variables.public_inputs.packed_challenge_words.begin &&
        outer < plan.variables.public_inputs.packed_challenge_words.end()) {
        row = map(plan.variables.public_inputs.packed_challenge_words,
                  layout.rows.challenge_word_recomposition);
    } else if (
        outer >= plan.variables.public_inputs.revealed_test_coordinates.begin &&
        outer < plan.variables.public_inputs.revealed_test_coordinates.end()) {
        row = map(plan.variables.public_inputs.revealed_test_coordinates,
                  layout.rows.revealed_test_equalities);
    } else if (
        outer >= plan.variables.public_inputs.revealed_packing_coordinates.begin &&
        outer < plan.variables.public_inputs.revealed_packing_coordinates.end()) {
        row = map(plan.variables.public_inputs.revealed_packing_coordinates,
                  layout.rows.revealed_packing_equalities);
    } else {
        throw std::logic_error(
            "logical public input has no Wiring row");
    }
    return gamma_squared * rows.value(row);
}

void emit_public_columns(
    const OuterRelationPlan &plan,
    const ProofOfPackingR1csLayout &layout,
    const spartan::R1csMetadata &metadata,
    const PoseidonAdjacency &poseidon,
    const BlockedRowWeights &rows, const Fq2 &gamma,
    const Fq2 &gamma_squared,
    storage::NativeFieldArtifactWriter &writer,
    std::size_t block_elements,
    ProofOfPackingWiringArtifactReport &report) {
    const std::uint64_t public_count = checked_add(
        metadata.shape().public_inputs, 1, "Wiring public columns");
    writer.begin_array(std::string(kProofOfPackingWiringPublicColumns),
                       storage::NativeFieldElementKind::Fq2,
                       public_count);
    BufferedFq2Output output(writer, block_elements, report);
    Fq2 constant =
        plan.shape.ciphertext_commitment_policy.relation ==
                gkr::CiphertextCommitmentRelation::PoseidonV2
            ? evaluate_constant_poseidon_column(
                  plan, layout, poseidon, rows, gamma, gamma_squared)
            : evaluate_constant_simple_hash_column(plan, layout, rows);
    if (plan.shape.ciphertext_commitment_policy.relation ==
        gkr::CiphertextCommitmentRelation::DiagnosticSimpleCtHashV2) {
        constant += gamma * rows.range_sum(
            layout.rows.ciphertext_poseidon.begin,
            layout.rows.ciphertext_poseidon.begin +
                layout.rows.ciphertext_poseidon.live);
    }
    constant += gamma * rows.range_sum(
                            layout.rows.ciphertext_outputs.begin,
                            layout.rows.ciphertext_outputs.begin +
                                layout.rows.ciphertext_outputs.live);
    constant -= gamma * rows.range_sum(
                            layout.rows.challenge_bit_booleanity.begin,
                            layout.rows.challenge_bit_booleanity.begin +
                                layout.rows.challenge_bit_booleanity.live);
    constant += gamma * rows.range_sum(
                            layout.rows.challenge_word_recomposition.begin,
                            layout.rows.challenge_word_recomposition.begin +
                                layout.rows.challenge_word_recomposition.live);
    constant += gamma * rows.range_sum(
                            layout.rows.revealed_test_equalities.begin,
                            layout.rows.revealed_test_equalities.begin +
                                layout.rows.revealed_test_equalities.live);
    constant += gamma * rows.range_sum(
                            layout.rows.revealed_packing_equalities.begin,
                            layout.rows.revealed_packing_equalities.begin +
                                layout.rows.revealed_packing_equalities.live);
    output.push(constant);
    for (std::uint64_t logical = 0;
         logical < metadata.shape().public_inputs; ++logical) {
        output.push(public_column_value(plan, layout, rows, logical,
                                        gamma_squared));
    }
    output.finish();
    if (output.position() != public_count) {
        throw std::logic_error("Wiring public prefix has wrong length");
    }
    writer.finish_array();
}

struct TensorCaches {
    std::vector<FqBlockCache> columns;
    std::size_t digits = 0;

    Fq value(std::size_t tensor, std::size_t digit,
             std::uint64_t address) {
        const std::size_t column = checked_size(
            checked_add(
                checked_mul(checked_u64(tensor, "tensor index"),
                            checked_u64(digits, "tensor digit count"),
                            "tensor column index"),
                checked_u64(digit, "tensor digit index"),
                "tensor column index"),
            "tensor column index");
        return columns.at(column).value(address);
    }
};

TensorCaches make_tensor_caches(
    const OuterRelationPlan &plan,
    const storage::NativeFieldArtifact &artifact,
    std::size_t block_elements,
    ProofOfPackingWiringIoReport &report) {
    TensorCaches result;
    result.digits = plan.shape.packing_digit_count;
    result.columns.reserve(checked_size(
        checked_mul(checked_u64(plan.shape.logical_packed_outputs,
                                "packing tensor count"),
                    checked_u64(result.digits, "packing tensor digits"),
                    "packing tensor columns"),
        "packing tensor columns"));
    for (std::size_t tensor = 0;
         tensor < plan.shape.logical_packed_outputs; ++tensor) {
        for (std::size_t digit = 0; digit < result.digits; ++digit) {
            result.columns.emplace_back(
                artifact,
                spartan::factored_matrix_tensor_column_array_name(
                    tensor, digit),
                block_elements, report);
        }
    }
    return result;
}

Fq2 aligned_coordinate_value(
    const OuterRelationPlan &plan,
    const ProofOfPackingR1csLayout &layout,
    const PoseidonAdjacency &poseidon,
    const ProofOfPackingPoseidonSegment &segment,
    std::uint64_t local_permutation, std::size_t rate,
    std::size_t aligned, std::size_t component,
    std::size_t coordinate, const OwnerAddress &owner,
    const FamilyWeights &family, std::span<const Fq2> coordinate_weights,
    TensorCaches &tensors, const BlockedRowWeights &rows,
    const Fq2 &gamma, const Fq2 &gamma_squared) {
    const std::size_t q_index =
        component * plan.shape.ring_degree + coordinate;
    Fq2 result =
        plan.shape.ciphertext_commitment_policy.relation ==
                gkr::CiphertextCommitmentRelation::PoseidonV2
            ? evaluate_local_terms(
                  poseidon.input[rate], segment, local_permutation, rows,
                  gamma, gamma_squared)
            : rows.value(layout.ciphertext_simple_hash_row(
                  plan, aligned, q_index));
    const Fq2 low = coordinate_weights[q_index];
    result += gamma * family.owner_product_sum[aligned] * low;
    const std::uint64_t tensor_address = checked_add(
        checked_mul(owner.local_owner, plan.shape.ring_degree,
                    "tensor owner address"),
        coordinate, "tensor coordinate address");
    Fq2 fixed = Fq2::zero();
    for (std::size_t digit = 0;
         digit < plan.shape.packing_digit_count; ++digit) {
        fixed += family.packing[
                     owner.tensor * plan.shape.packing_digit_count + digit] *
                 tensors.value(owner.tensor, digit, tensor_address);
    }
    result += low * fixed;
    return result;
}

void emit_challenge_bits(
    const OuterRelationPlan &plan,
    const ProofOfPackingR1csLayout &layout,
    const FamilyWeights &family,
    const BlockedRowWeights &rows, const Fq2 &gamma,
    BufferedFq2Output &output) {
    const std::uint64_t bit_count =
        plan.variables.witness.derived_challenge_bits.count;
    const std::size_t capacity =
        plan.shape.public_input_capacity_bits;
    for (std::uint64_t bit = 0; bit < bit_count; ++bit) {
        Fq2 value = (Fq2::one() + gamma) * rows.value(checked_add(
            layout.rows.challenge_bit_booleanity.begin, bit,
            "booleanity row"));
        const std::uint64_t word = bit / capacity;
        const std::size_t offset =
            checked_size(bit % capacity, "challenge bit offset");
        value += rows.value(checked_add(
                     layout.rows.challenge_word_recomposition.begin, word,
                     "recomposition row")) *
                 Fq(std::uint64_t{1} << offset);
        const Fq2 product = family.product[
            checked_size(bit / 2U, "challenge product family")];
        value += (bit & 1U) == 0 ? product : -product;
        output.push(value);
    }
}

void emit_aligned_coordinates(
    const OuterRelationPlan &plan,
    const ProofOfPackingR1csLayout &layout,
    const PoseidonAdjacency &poseidon,
    const std::vector<OwnerAddress> &owners,
    const FamilyWeights &family,
    std::span<const Fq2> coordinate_weights,
    TensorCaches &tensors, const BlockedRowWeights &rows,
    const Fq2 &gamma, const Fq2 &gamma_squared,
    BufferedFq2Output &output) {
    const std::uint64_t metadata =
        gkr::kCiphertextCommitmentMetadataElements;
    const std::uint64_t preimage = checked_add(
        metadata,
        checked_mul(plan.shape.ciphertext_components,
                    plan.shape.ring_degree,
                    "ciphertext Poseidon preimage"),
        "ciphertext Poseidon preimage");
    const std::uint64_t permutations_per_hash =
        layout.ciphertext_permutations_per_hash;
    for (const ProofOfPackingPoseidonSegment &segment :
         layout.ciphertext_segments) {
        output.pad_to(segment.input_witness_begin);
        for (std::size_t rate = 0; rate < kPoseidonRate; ++rate) {
            for (std::uint64_t local = 0;
                 local < segment.permutations; ++local) {
                const std::uint64_t permutation = checked_add(
                    segment.permutation_begin, local,
                    "Poseidon permutation");
                const std::uint64_t input = checked_add(
                    checked_mul(permutation % permutations_per_hash,
                                kPoseidonRate, "Poseidon input"),
                    rate, "Poseidon input");
                if (input < metadata || input >= preimage) {
                    output.push(Fq2::zero());
                    continue;
                }
                const std::size_t aligned = checked_size(
                    permutation / permutations_per_hash,
                    "aligned ciphertext");
                const std::uint64_t coordinate_index = input - metadata;
                const std::size_t component = checked_size(
                    coordinate_index / plan.shape.ring_degree,
                    "ciphertext component");
                const std::size_t coordinate = checked_size(
                    coordinate_index % plan.shape.ring_degree,
                    "ciphertext coordinate");
                output.push(aligned_coordinate_value(
                    plan, layout, poseidon, segment, local, rate, aligned,
                    component, coordinate, owners.at(aligned), family,
                    coordinate_weights, tensors, rows, gamma,
                    gamma_squared));
            }
        }
    }
}

void emit_well_formedness_products(
    const OuterRelationPlan &plan, const FamilyWeights &family,
    std::span<const Fq2> coordinate_weights,
    const Fq2 &gamma_squared, BufferedFq2Output &output) {
    const std::size_t aligned_count =
        plan.shape.aligned_ciphertexts;
    const std::size_t q = plan.coordinates_per_ciphertext();
    for (std::size_t test = 0; test < plan.shape.repetitions; ++test) {
        for (std::size_t aligned = 0; aligned < aligned_count; ++aligned) {
            const Fq2 high =
                gamma_squared *
                    family.product[test * aligned_count + aligned] +
                family.test[test];
            for (std::size_t local = 0; local < q; ++local) {
                output.push(high * coordinate_weights[local]);
            }
        }
    }
}

void emit_poseidon_auxiliary(
    const ProofOfPackingR1csLayout &layout,
    const PoseidonAdjacency &poseidon,
    const BlockedRowWeights &rows, const Fq2 &gamma,
    const Fq2 &gamma_squared, BufferedFq2Output &output) {
    const auto &local =
        detail::proof_of_packing_poseidon_permutation_template();
    const std::uint64_t permutations_per_hash =
        layout.ciphertext_permutations_per_hash;
    for (std::size_t segment_index = 0;
         segment_index < layout.ciphertext_segments.size();
         ++segment_index) {
        const auto &segment = layout.ciphertext_segments[segment_index];
        output.pad_to(segment.auxiliary_witness_begin);
        for (std::uint64_t auxiliary = 0; auxiliary < local.rows;
             ++auxiliary) {
            for (std::uint64_t local_permutation = 0;
                 local_permutation < segment.permutations;
                 ++local_permutation) {
                const std::uint64_t permutation = checked_add(
                    segment.permutation_begin, local_permutation,
                    "Poseidon auxiliary permutation");
                Fq2 value = evaluate_local_terms(
                    poseidon.auxiliary[checked_size(
                        auxiliary, "Poseidon auxiliary")],
                    segment, local_permutation, rows, gamma,
                    gamma_squared);
                if ((permutation + 1U) % permutations_per_hash != 0) {
                    const ProofOfPackingPoseidonSegment *next_segment =
                        &segment;
                    std::uint64_t next_local = local_permutation + 1U;
                    if (next_local == segment.permutations) {
                        if (segment_index + 1U >=
                            layout.ciphertext_segments.size()) {
                            throw std::logic_error(
                                "Poseidon segment successor is absent");
                        }
                        next_segment =
                            &layout.ciphertext_segments[segment_index + 1U];
                        next_local = 0;
                    }
                    for (const std::size_t word :
                         poseidon.final_words[checked_size(
                             auxiliary, "Poseidon final word")]) {
                        value += evaluate_local_terms(
                            poseidon.prior[word], *next_segment, next_local,
                            rows, gamma, gamma_squared);
                    }
                }
                if ((permutation + 1U) % permutations_per_hash == 0) {
                    const std::size_t ciphertext = checked_size(
                        permutation / permutations_per_hash,
                        "ciphertext output index");
                    for (const std::size_t word :
                         poseidon.final_words[checked_size(
                             auxiliary, "Poseidon final output")]) {
                        if (word < kPoseidonDigestElements) {
                            value += rows.value(
                                layout.ciphertext_output_row(ciphertext,
                                                             word));
                        }
                    }
                }
                output.push(value);
            }
        }
    }
}

void emit_simple_hash_auxiliary(
    const OuterRelationPlan &plan,
    const ProofOfPackingR1csLayout &layout,
    const BlockedRowWeights &rows, const Fq2 &gamma_squared,
    BufferedFq2Output &output) {
    const std::size_t q = plan.coordinates_per_ciphertext();
    const Fq alpha(gkr::kDiagnosticSimpleCtHashAlpha);
    output.pad_to(layout.witness.ciphertext_poseidon_auxiliary.begin);
    for (std::size_t ciphertext = 0;
         ciphertext < plan.shape.aligned_ciphertexts; ++ciphertext) {
        for (std::size_t coordinate = 0; coordinate < q; ++coordinate) {
            Fq2 value = gamma_squared * rows.value(
                layout.ciphertext_simple_hash_row(
                    plan, ciphertext, coordinate));
            if (coordinate + 1 < q) {
                value += rows.value(layout.ciphertext_simple_hash_row(
                             plan, ciphertext, coordinate + 1)) *
                         alpha;
            } else {
                for (std::size_t element = 0;
                     element < kPoseidonDigestElements; ++element) {
                    value += rows.value(layout.ciphertext_output_row(
                        ciphertext, element));
                }
            }
            output.push(value);
        }
    }
}

void emit_witness_columns(
    const OuterRelationPlan &plan,
    const ProofOfPackingR1csLayout &layout,
    const spartan::R1csMetadata &metadata,
    const PoseidonAdjacency &poseidon,
    const std::vector<OwnerAddress> &owners,
    const FamilyWeights &family,
    std::span<const Fq2> coordinate_weights,
    TensorCaches &tensors, const BlockedRowWeights &rows,
    const Fq2 &gamma, const Fq2 &gamma_squared,
    storage::NativeFieldArtifactWriter &writer,
    std::size_t block_elements,
    ProofOfPackingWiringArtifactReport &report) {
    writer.begin_array(std::string(kProofOfPackingWiringWitnessColumns),
                       storage::NativeFieldElementKind::Fq2,
                       metadata.shape().witness_variables);
    BufferedFq2Output output(writer, block_elements, report);
    output.pad_to(layout.witness.challenge_bits.begin);
    emit_challenge_bits(plan, layout, family, rows, gamma, output);
    output.pad_to(layout.witness.aligned_coordinates.begin);
    emit_aligned_coordinates(plan, layout, poseidon, owners, family,
                             coordinate_weights, tensors, rows, gamma,
                             gamma_squared, output);
    output.pad_to(layout.witness.well_formedness_products.begin);
    emit_well_formedness_products(plan, family, coordinate_weights,
                                  gamma_squared, output);
    output.pad_to(
        layout.witness.ciphertext_poseidon_auxiliary.begin);
    if (plan.shape.ciphertext_commitment_policy.relation ==
        gkr::CiphertextCommitmentRelation::PoseidonV2) {
        emit_poseidon_auxiliary(layout, poseidon, rows, gamma,
                                gamma_squared, output);
    } else {
        emit_simple_hash_auxiliary(plan, layout, rows, gamma_squared,
                                   output);
    }
    output.pad_to(metadata.shape().witness_variables);
    output.finish();
    if (output.position() != metadata.shape().witness_variables) {
        throw std::logic_error("Wiring witness prefix has wrong length");
    }
    writer.finish_array();
}

} // namespace

ProofOfPackingWiringArtifact
write_proof_of_packing_wiring_matrix_artifact_impl(
    const OuterRelationPlan &plan,
    const ProofOfPackingR1csLayout &layout,
    const spartan::R1csMetadata &circuit_metadata,
    const spartan::FactoredMatrixProverKey &factored_preprocessing,
    std::span<const Fq2> row_point, const Fq2 &gamma,
    ProofOfPackingWiringArtifactOptions options,
    bool revalidate_source) {
    if (options.directory.empty() ||
        options.storage_limits.max_total_bytes == 0 ||
        options.storage_limits.min_free_bytes == 0 ||
        options.max_live_storage_bytes == 0 ||
        options.max_working_field_bytes == 0 ||
        options.block_elements == 0) {
        throw std::invalid_argument(
            "Wiring artifacts require explicit nonzero limits");
    }
    options.directory =
        std::filesystem::absolute(options.directory).lexically_normal();
    validate_empty_directory(options.directory);
    validate_static_inputs(plan, layout, circuit_metadata, row_point);
    const ValidatedFactored initial = validate_factored_preprocessing(
        plan, circuit_metadata, factored_preprocessing);
    require_disjoint_directories(
        options.directory,
        factored_preprocessing.tensor_columns_artifact->directory());

    std::shared_ptr<const storage::NativeFieldArtifact> validated_tensors =
        factored_preprocessing.tensor_columns_artifact;
    spartan::FactoredMatrixProverKey validated_factored =
        factored_preprocessing;
    ValidatedFactored validated = initial;
    if (revalidate_source) {
        validated_tensors = spartan::open_factored_matrix_artifact(
            factored_preprocessing.tensor_columns_artifact->directory(),
            factored_preprocessing.commitment);
        validated_factored.tensor_columns_artifact = validated_tensors;
        validated = validate_factored_preprocessing(
            plan, circuit_metadata, validated_factored);
        if (validated.mappings != initial.mappings ||
            validated.tensor_columns != initial.tensor_columns) {
            throw std::invalid_argument(
                "Wiring factored source changed during validation");
        }
    }

    const std::uint64_t public_count = checked_add(
        circuit_metadata.shape().public_inputs, 1,
        "Wiring public columns");
    const std::array<storage::NativeFieldArrayLayout, 2> arrays{{
        {std::string(kProofOfPackingWiringPublicColumns),
         storage::NativeFieldElementKind::Fq2, public_count},
        {std::string(kProofOfPackingWiringWitnessColumns),
         storage::NativeFieldElementKind::Fq2,
         circuit_metadata.shape().witness_variables},
    }};
    const std::uint64_t physical_bytes =
        storage::native_field_artifact_physical_bytes(arrays);
    if (physical_bytes > options.storage_limits.max_total_bytes) {
        throw std::invalid_argument(
            "Wiring quota is below the exact artifact size");
    }
    const std::uint64_t peak_live_storage_bytes = checked_add(
        validated_tensors->physical_bytes(), physical_bytes,
        "Wiring live source and output bytes");
    if (peak_live_storage_bytes > options.max_live_storage_bytes) {
        throw std::invalid_argument(
            "Wiring live-storage limit is below source plus output");
    }
    const std::uint64_t required_free = checked_add(
        physical_bytes, options.storage_limits.min_free_bytes,
        "Wiring free-space preflight");
    if (std::filesystem::space(options.directory).available <
        required_free) {
        throw std::runtime_error(
            "Wiring destination has insufficient free space");
    }

    const ProofOfPackingWiringArtifactPlan resource_plan =
        plan_proof_of_packing_wiring_matrix_artifact(
            plan, layout, circuit_metadata, validated_factored,
            options.max_working_field_bytes, options.block_elements);
    const std::size_t coordinate_bits = log2_exact(
        plan.coordinates_per_ciphertext(),
        "ciphertext coordinate count is not a power of two");
    const std::size_t block_elements =
        resource_plan.effective_block_elements;

    ProofOfPackingWiringArtifactReport report{
        .public_column_elements = public_count,
        .witness_column_elements =
            circuit_metadata.shape().witness_variables,
        .logical_padded_column_elements = checked_mul(
            2,
            checked_u64(circuit_metadata.assignment_half_size(),
                        "Wiring assignment half"),
            "Wiring logical columns"),
        .matrix_payload_bytes =
            proof_of_packing_wiring_matrix_payload_bytes(
                circuit_metadata),
        .physical_bytes = physical_bytes,
        .source_artifact_physical_bytes =
            validated_tensors->physical_bytes(),
        .source_artifact_validation_bytes =
            revalidate_source ? validated_tensors->physical_bytes() : 0,
        .peak_live_storage_bytes = peak_live_storage_bytes,
        .row_prefix_equality_table_elements =
            resource_plan.row_prefix_equality_table_elements,
        .coordinate_equality_table_elements =
            resource_plan.coordinate_equality_table_elements,
        .row_family_weight_elements =
            resource_plan.row_family_weight_elements,
        .tensor_cache_elements = resource_plan.tensor_cache_elements,
        .effective_block_elements = block_elements,
        .peak_working_field_bytes =
            resource_plan.peak_working_field_bytes,
    };
    report.virtual_zero_column_elements =
        report.logical_padded_column_elements -
        report.public_column_elements - report.witness_column_elements;

    const BlockedRowWeights rows(row_point, coordinate_bits);
    const std::span<const Fq2> coordinate_weights =
        rows.coordinate_weights();
    const FamilyWeights family = make_family_weights(plan, layout, rows);
    if (rows.high_table_elements() !=
            report.row_prefix_equality_table_elements ||
        rows.low_table_elements() !=
            report.coordinate_equality_table_elements ||
        family_weight_elements(family) !=
            report.row_family_weight_elements) {
        throw std::logic_error(
            "Wiring memory preflight disagrees with retained tables");
    }
    const PoseidonAdjacency poseidon = make_poseidon_adjacency();
    const std::vector<OwnerAddress> owners = make_owner_addresses(
        plan, validated.mappings);
    TensorCaches tensors = make_tensor_caches(
        plan, *validated_tensors, block_elements,
        report.factored_tensor_io);

    const Digest identity =
        proof_of_packing_wiring_matrix_artifact_identity(
            plan, layout, circuit_metadata, validated_factored,
            row_point, gamma);
    DestinationCleanup cleanup(options.directory);
    storage::NativeFieldArtifactWriter writer(
        options.directory, options.storage_limits, identity);
    const Fq2 gamma_squared = gamma * gamma;
    emit_public_columns(plan, layout, circuit_metadata, poseidon, rows,
                        gamma, gamma_squared, writer, block_elements,
                        report);
    emit_witness_columns(
        plan, layout, circuit_metadata, poseidon, owners, family,
        coordinate_weights, tensors, rows, gamma, gamma_squared, writer,
        block_elements, report);
    const storage::NativeFieldArtifactWriteResult written = writer.finish();
    if (written.physical_bytes != physical_bytes ||
        report.sequential_output_payload_bytes !=
            report.matrix_payload_bytes ||
        report.peak_working_field_bytes >
            options.max_working_field_bytes) {
        throw std::logic_error(
            "Wiring preflight disagrees with completed output");
    }
    auto artifact = std::make_shared<storage::NativeFieldArtifact>(
        storage::NativeFieldArtifact::open(options.directory, identity));
    validate_compact_matrix_layout(*artifact, circuit_metadata);
    report.output_artifact_validation_bytes = artifact->physical_bytes();
    cleanup.disarm();
    return {std::move(artifact), report};
}

ProofOfPackingWiringArtifact
write_proof_of_packing_wiring_matrix_artifact(
    const OuterRelationPlan &plan,
    const ProofOfPackingR1csLayout &layout,
    const spartan::R1csMetadata &circuit_metadata,
    const spartan::FactoredMatrixProverKey &factored_preprocessing,
    std::span<const Fq2> row_point, const Fq2 &gamma,
    ProofOfPackingWiringArtifactOptions options) {
    return write_proof_of_packing_wiring_matrix_artifact_impl(
        plan, layout, circuit_metadata, factored_preprocessing,
        row_point, gamma, std::move(options), true);
}

ProofOfPackingWiringArtifact
write_proof_of_packing_wiring_matrix_artifact_admitted_source(
    const OuterRelationPlan &plan,
    const ProofOfPackingR1csLayout &layout,
    const spartan::R1csMetadata &circuit_metadata,
    const spartan::FactoredMatrixProverKey &factored_preprocessing,
    std::span<const Fq2> row_point, const Fq2 &gamma,
    ProofOfPackingWiringArtifactOptions options) {
    return write_proof_of_packing_wiring_matrix_artifact_impl(
        plan, layout, circuit_metadata, factored_preprocessing,
        row_point, gamma, std::move(options), false);
}

} // namespace laminate::packing
