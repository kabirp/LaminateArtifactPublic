/// @file products.cpp
/// @brief Bounded-memory products for the structured packing R1CS.

#include "laminate/packing/proof/matrix/products.hpp"

#include "laminate/crypto/poseidon.hpp"
#include "laminate/packing/proof/detail/poseidon_template.hpp"
#include "laminate/packing/outer_relation/r1cs.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <limits>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace laminate::packing {
namespace {

constexpr std::string_view kIdentityDomain =
    "LaminateImpl/ProofOfPackingMatrixProducts/v2";
constexpr std::string_view kCompletePublicArray =
    kProofOfPackingAssignmentPublicInputs;
constexpr std::string_view kCompleteWitnessArray =
    kProofOfPackingAssignmentWitnessValues;
constexpr std::string_view kOuterPublicArray = "public-inputs";
constexpr std::string_view kOuterWitnessArray = "witness";
constexpr std::array<std::string_view, 3> kProductArrays{
    "az", "bz", "cz"};

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
    append_u64(output,
               checked_u64(layout.ciphertext_segments.size(),
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

void require_array(const storage::NativeFieldArtifact &artifact,
                   std::string_view name, std::uint64_t elements) {
    const storage::NativeFieldArrayDescriptor &array = artifact.array(name);
    if (array.kind != storage::NativeFieldElementKind::Fq ||
        array.element_count != elements ||
        array.encoded_element_bytes !=
            storage::encoded_element_bytes(
                storage::NativeFieldElementKind::Fq)) {
        throw std::invalid_argument(
            "proof-of-packing matrix-product source has the wrong array "
            "layout");
    }
}

void validate_static_inputs(
    const OuterRelationPlan &plan,
    const ProofOfPackingR1csLayout &layout,
    const spartan::R1csMetadata &metadata,
    const storage::NativeFieldArtifact &complete,
    const storage::NativeFieldArtifact &outer) {
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
                                      "matrix row count")) ||
        complete.arrays().size() != 2 || outer.arrays().size() != 2 ||
        outer.identity() != outer_relation_assignment_artifact_identity(plan)) {
        throw std::invalid_argument(
            "proof-of-packing matrix-product inputs are inconsistent");
    }
    require_array(complete, kCompletePublicArray,
                  metadata.shape().public_inputs);
    const ProofOfPackingWitnessStorageLayout witness_storage =
        proof_of_packing_witness_storage_layout(plan, metadata);
    require_array(complete, kCompleteWitnessArray,
                  witness_storage.stored_elements);
    require_array(outer, kOuterPublicArray,
                  plan.variables.public_inputs.total);
    require_array(outer, kOuterWitnessArray,
                  plan.variables.witness.total);
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
            "proof-of-packing matrix-product destination must be an empty "
            "real directory");
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
    std::span<const std::filesystem::path> sources) {
    const std::filesystem::path canonical_destination =
        std::filesystem::canonical(destination);
    for (const std::filesystem::path &source : sources) {
        const std::filesystem::path canonical_source =
            std::filesystem::canonical(source);
        if (path_prefix(canonical_destination, canonical_source) ||
            path_prefix(canonical_source, canonical_destination)) {
            throw std::invalid_argument(
                "matrix-product destination and source directories must be "
                "disjoint");
        }
    }
}

class TrackedFqReader {
  public:
    TrackedFqReader(const storage::NativeFieldArtifact &artifact,
                    std::string_view name,
                    ProofOfPackingMatrixProductIoReport &report)
        : reader_(artifact.open_array(name)), report_(&report) {
        if (reader_.kind() != storage::NativeFieldElementKind::Fq) {
            throw std::invalid_argument(
                "matrix-product source array is not Fq");
        }
    }

    std::uint64_t size() const { return reader_.size(); }
    std::uint64_t position() const { return reader_.position(); }

    void seek(std::uint64_t position) {
        if (position > reader_.size()) {
            throw std::out_of_range(
                "matrix-product source seek is out of range");
        }
        if (reader_.position() != position) {
            reader_.seek(position);
            report_->seek_operations = checked_add(
                report_->seek_operations, 1, "source seek operations");
        }
    }

    void read_exact(std::span<Fq> output) {
        std::size_t offset = 0;
        while (offset < output.size()) {
            const std::size_t count = reader_.read(output.subspan(offset));
            if (count == 0) {
                throw std::runtime_error(
                    "matrix-product source ended unexpectedly");
            }
            report_->payload_bytes = checked_add(
                report_->payload_bytes,
                checked_mul(checked_u64(count, "source read elements"),
                            storage::encoded_element_bytes(
                                storage::NativeFieldElementKind::Fq),
                            "source read bytes"),
                "source read bytes");
            report_->read_operations = checked_add(
                report_->read_operations, 1, "source read operations");
            offset += count;
        }
    }

    void read_at(std::uint64_t position, std::span<Fq> output) {
        seek(position);
        read_exact(output);
    }

    Fq read_one_at(std::uint64_t position) {
        Fq result;
        read_at(position, std::span<Fq>(&result, 1));
        return result;
    }

  private:
    storage::NativeFieldArrayReader reader_;
    ProofOfPackingMatrixProductIoReport *report_ = nullptr;
};

class TrackedProofWitnessReader {
  public:
    TrackedProofWitnessReader(
        const OuterRelationPlan &plan,
        const spartan::R1csMetadata &metadata,
        const storage::NativeFieldArtifact &artifact,
        ProofOfPackingMatrixProductIoReport &report)
        : reader_(plan, metadata, artifact), report_(&report) {}

    std::uint64_t size() const { return reader_.size(); }

    void read_at(std::uint64_t position, std::span<Fq> output) {
        const ProofOfPackingWitnessReadReport read =
            reader_.read_at(position, output);
        report_->payload_bytes = checked_add(
            report_->payload_bytes,
            checked_mul(
                read.stored_elements,
                storage::encoded_element_bytes(
                    storage::NativeFieldElementKind::Fq),
                "compact witness source read bytes"),
            "compact witness source read bytes");
        report_->read_operations = checked_add(
            report_->read_operations, read.read_operations,
            "compact witness source read operations");
        report_->seek_operations = checked_add(
            report_->seek_operations, read.seek_operations,
            "compact witness source seek operations");
    }

    Fq read_one_at(std::uint64_t position) {
        Fq result;
        read_at(position, std::span<Fq>(&result, 1));
        return result;
    }

  private:
    ProofOfPackingWitnessReader reader_;
    ProofOfPackingMatrixProductIoReport *report_ = nullptr;
};

class FqBlockCache {
  public:
    FqBlockCache(const storage::NativeFieldArtifact &artifact,
                 std::string_view name, std::size_t block_elements,
                 ProofOfPackingMatrixProductIoReport &report)
        : reader_(artifact, name, report), buffer_(block_elements) {
        if (block_elements == 0) {
            throw std::invalid_argument("matrix-product cache is empty");
        }
    }

    Fq value(std::uint64_t index) {
        if (index >= reader_.size()) {
            throw std::out_of_range(
                "matrix-product cached index is out of range");
        }
        if (!loaded_ || index < begin_ || index >= begin_ + live_) {
            begin_ = (index / buffer_.size()) * buffer_.size();
            live_ = std::min<std::uint64_t>(
                buffer_.size(), reader_.size() - begin_);
            reader_.read_at(begin_,
                            std::span<Fq>(buffer_).first(
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

class BufferedProductOutput {
  public:
    BufferedProductOutput(storage::NativeFieldArtifactWriter &writer,
                          std::size_t block_elements,
                          ProofOfPackingMatrixProductArtifactReport &report)
        : writer_(&writer), buffer_(block_elements), report_(&report) {}

    ~BufferedProductOutput() = default;

    void push(const Fq &value) {
        buffer_[live_++] = value;
        ++position_;
        if (live_ == buffer_.size()) {
            flush();
        }
    }

    void append(std::span<const Fq> values) {
        for (const Fq &value : values) {
            push(value);
        }
    }

    void zeros(std::uint64_t count) {
        for (std::uint64_t index = 0; index < count; ++index) {
            push(Fq::zero());
        }
    }

    std::uint64_t position() const { return position_; }

    void finish() { flush(); }

  private:
    void flush() {
        if (live_ == 0) {
            return;
        }
        writer_->append(std::span<const Fq>(buffer_).first(live_));
        report_->sequential_output_payload_bytes = checked_add(
            report_->sequential_output_payload_bytes,
            checked_mul(checked_u64(live_, "output elements"),
                        storage::encoded_element_bytes(
                            storage::NativeFieldElementKind::Fq),
                        "output bytes"),
            "sequential output bytes");
        report_->sequential_output_operations = checked_add(
            report_->sequential_output_operations, 1,
            "sequential output operations");
        live_ = 0;
    }

    storage::NativeFieldArtifactWriter *writer_ = nullptr;
    std::vector<Fq> buffer_;
    ProofOfPackingMatrixProductArtifactReport *report_ = nullptr;
    std::size_t live_ = 0;
    std::uint64_t position_ = 0;
};

std::vector<gkr::HashCommitCT> recover_assignment_commitments(
    const OuterRelationPlan &plan,
    const storage::NativeFieldArtifact &complete,
    ProofOfPackingMatrixProductIoReport &io) {
    TrackedFqReader reader(complete, kCompletePublicArray, io);
    std::vector<gkr::HashCommitCT> result(
        plan.shape.aligned_ciphertexts);
    std::array<Fq, kPoseidonDigestElements> fields{};
    for (gkr::HashCommitCT &commitment : result) {
        reader.read_exact(fields);
        for (std::size_t element = 0; element < fields.size(); ++element) {
            const std::uint64_t word = fields[element].value();
            for (std::size_t byte = 0; byte < 8; ++byte) {
                commitment.digest[8 * element + byte] =
                    static_cast<std::uint8_t>(word >> (8U * byte));
            }
        }
    }
    return result;
}

using EntryRange = std::pair<std::size_t, std::size_t>;

std::vector<EntryRange> group_template_entries(
    std::span<const spartan::R1csEntry> entries,
    std::uint64_t row_count) {
    std::vector<EntryRange> result(
        checked_size(row_count, "Poseidon local rows"));
    std::size_t cursor = 0;
    for (std::uint64_t row = 0; row < row_count; ++row) {
        const std::size_t begin = cursor;
        while (cursor < entries.size() && entries[cursor].row == row) {
            ++cursor;
        }
        if (cursor < entries.size() && entries[cursor].row < row) {
            throw std::logic_error(
                "Poseidon template entries are not row ordered");
        }
        result[checked_size(row, "Poseidon local row")] = {begin, cursor};
    }
    if (cursor != entries.size()) {
        throw std::logic_error(
            "Poseidon template entry row is out of range");
    }
    return result;
}

std::span<const spartan::R1csEntry> matrix_template_entries(
    const detail::PoseidonPermutationR1csTemplate &local,
    spartan::Matrix matrix) {
    switch (matrix) {
    case spartan::Matrix::A:
        return local.a;
    case spartan::Matrix::B:
        return local.b;
    case spartan::Matrix::C:
        return local.c;
    }
    throw std::logic_error("unknown Spartan matrix");
}

const OuterRelationR1csLinearCombination &outer_combination(
    const OuterRelationR1csRow &row, spartan::Matrix matrix) {
    switch (matrix) {
    case spartan::Matrix::A:
        return row.a;
    case spartan::Matrix::B:
        return row.b;
    case spartan::Matrix::C:
        return row.c;
    }
    throw std::logic_error("unknown Spartan matrix");
}

Fq evaluate_outer_combination(
    const OuterRelationR1csLinearCombination &combination,
    FqBlockCache &public_inputs, FqBlockCache &witness) {
    Fq result = Fq::zero();
    for (const OuterRelationR1csTerm &term : combination) {
        Fq value;
        switch (term.variable.kind) {
        case OuterRelationR1csVariableKind::ConstantOne:
            if (term.variable.index != 0) {
                throw std::logic_error(
                    "outer relation has a malformed constant variable");
            }
            value = Fq::one();
            break;
        case OuterRelationR1csVariableKind::PublicInput:
            value = public_inputs.value(term.variable.index);
            break;
        case OuterRelationR1csVariableKind::Witness:
            value = witness.value(term.variable.index);
            break;
        }
        result += Fq(term.coefficient) * value;
    }
    return result;
}

void append_gap(BufferedProductOutput &output, std::uint64_t target) {
    if (output.position() > target) {
        throw std::logic_error(
            "matrix-product row families overlap");
    }
    output.zeros(target - output.position());
}

void emit_poseidon_rows(
    spartan::Matrix matrix, const OuterRelationPlan &plan,
    const ProofOfPackingR1csLayout &layout,
    const spartan::R1csMetadata &circuit_metadata,
    const storage::NativeFieldArtifact &complete,
    std::size_t block_elements, BufferedProductOutput &output,
    ProofOfPackingMatrixProductIoReport &io) {
    const auto &local =
        detail::proof_of_packing_poseidon_permutation_template();
    if (local.rows != layout.poseidon_rows_per_permutation) {
        throw std::logic_error(
            "Poseidon template and structured layout disagree");
    }
    const std::span<const spartan::R1csEntry> entries =
        matrix_template_entries(local, matrix);
    const std::vector<EntryRange> groups =
        group_template_entries(entries, local.rows);
    TrackedProofWitnessReader witness(
        plan, circuit_metadata, complete, io);
    std::vector<Fq> values(block_elements);
    std::vector<Fq> scratch(block_elements);
    const std::uint64_t permutations_per_hash =
        layout.ciphertext_permutations_per_hash;
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
    initial[kPoseidonRate] =
        Fq(static_cast<std::uint64_t>(
            PoseidonDomain::CiphertextCommitment));
    initial[kPoseidonRate + 1] = Fq(preimage);
    initial[kPoseidonRate + 2] = Fq(preimage);
    initial[kPoseidonRate + 3] =
        Fq(kPoseidonEncodingVersionDelimiter);

    for (const ProofOfPackingPoseidonSegment &segment :
         layout.ciphertext_segments) {
        append_gap(output, segment.row_begin);
        std::array<Fq, kPoseidonWidth> cross_segment_prior = initial;
        if (segment.permutation_begin % permutations_per_hash != 0) {
            const std::uint64_t previous = segment.permutation_begin - 1;
            for (std::size_t word = 0; word < kPoseidonWidth; ++word) {
                cross_segment_prior[word] = witness.read_one_at(
                    layout.ciphertext_poseidon_auxiliary_witness_index(
                        local.final_auxiliary[word], previous));
            }
        }

        for (std::uint64_t row = 0; row < local.rows; ++row) {
            const auto [entry_begin, entry_end] =
                groups[checked_size(row, "Poseidon row")];
            std::uint64_t local_begin = 0;
            while (local_begin < segment.permutations) {
                const std::size_t count =
                    std::min<std::uint64_t>(
                        block_elements,
                        segment.permutations - local_begin);
                std::fill(values.begin(), values.begin() + count,
                          Fq::zero());
                for (std::size_t entry_index = entry_begin;
                     entry_index < entry_end; ++entry_index) {
                    const spartan::R1csEntry &entry = entries[entry_index];
                    if (entry.column == 0) {
                        for (std::size_t index = 0; index < count; ++index) {
                            values[index] += entry.value;
                        }
                        continue;
                    }

                    if (entry.column <= kPoseidonWidth) {
                        const std::size_t word = checked_size(
                            entry.column - 1, "Poseidon prior word");
                        if (local_begin == 0) {
                            scratch[0] = cross_segment_prior[word];
                            if (count > 1) {
                                witness.read_at(
                                    checked_add(
                                        segment.auxiliary_witness_begin,
                                        checked_mul(
                                            local.final_auxiliary[word],
                                            segment.permutations,
                                            "prior-state auxiliary base"),
                                        "prior-state auxiliary base"),
                                    std::span<Fq>(scratch)
                                        .subspan(1, count - 1));
                            }
                        } else {
                            witness.read_at(
                                checked_add(
                                    segment.auxiliary_witness_begin,
                                    checked_add(
                                        checked_mul(
                                            local.final_auxiliary[word],
                                            segment.permutations,
                                            "prior-state auxiliary base"),
                                        local_begin - 1,
                                        "prior-state auxiliary offset"),
                                    "prior-state auxiliary offset"),
                                std::span<Fq>(scratch).first(count));
                        }
                        for (std::size_t index = 0; index < count; ++index) {
                            const std::uint64_t permutation = checked_add(
                                segment.permutation_begin,
                                checked_add(local_begin, index,
                                            "Poseidon permutation"),
                                "Poseidon permutation");
                            if (permutation % permutations_per_hash == 0) {
                                scratch[index] = initial[word];
                            }
                        }
                    } else if (entry.column <=
                               kPoseidonWidth + kPoseidonRate) {
                        const std::size_t rate = checked_size(
                            entry.column - 1 - kPoseidonWidth,
                            "Poseidon rate word");
                        witness.read_at(
                            checked_add(
                                segment.input_witness_begin,
                                checked_add(
                                    checked_mul(rate,
                                                segment.permutations,
                                                "Poseidon input base"),
                                    local_begin, "Poseidon input offset"),
                                "Poseidon input offset"),
                            std::span<Fq>(scratch).first(count));
                        for (std::size_t index = 0; index < count; ++index) {
                            const std::uint64_t permutation = checked_add(
                                segment.permutation_begin,
                                checked_add(local_begin, index,
                                            "Poseidon permutation"),
                                "Poseidon permutation");
                            const std::uint64_t input = checked_add(
                                checked_mul(
                                    permutation % permutations_per_hash,
                                    kPoseidonRate,
                                    "Poseidon local input"),
                                rate, "Poseidon local input");
                            if (input < metadata.size()) {
                                scratch[index] = metadata[checked_size(
                                    input, "Poseidon metadata input")];
                            } else if (input == preimage) {
                                scratch[index] =
                                    Fq(kPoseidonRatePaddingDelimiter);
                            } else if (input > preimage) {
                                scratch[index] = Fq::zero();
                            }
                        }
                    } else {
                        const std::uint64_t auxiliary =
                            entry.column - 1 - kPoseidonWidth -
                            kPoseidonRate;
                        if (auxiliary >= local.rows) {
                            throw std::logic_error(
                                "Poseidon template auxiliary is out of range");
                        }
                        witness.read_at(
                            checked_add(
                                segment.auxiliary_witness_begin,
                                checked_add(
                                    checked_mul(auxiliary,
                                                segment.permutations,
                                                "Poseidon auxiliary base"),
                                    local_begin,
                                    "Poseidon auxiliary offset"),
                                "Poseidon auxiliary offset"),
                            std::span<Fq>(scratch).first(count));
                    }
                    for (std::size_t index = 0; index < count; ++index) {
                        values[index] += entry.value * scratch[index];
                    }
                }
                output.append(std::span<const Fq>(values).first(count));
                local_begin = checked_add(
                    local_begin, checked_u64(count, "Poseidon row block"),
                    "Poseidon row block");
            }
        }
    }
}

void read_aligned_ciphertext_coordinates(
    const OuterRelationPlan &plan,
    const ProofOfPackingR1csLayout &layout,
    std::size_t ciphertext, std::size_t block_elements,
    TrackedProofWitnessReader &witness,
    std::vector<Fq> &coordinates, std::vector<Fq> &scratch) {
    const std::uint64_t q = plan.coordinates_per_ciphertext();
    if (coordinates.size() != q || scratch.size() < block_elements) {
        throw std::invalid_argument(
            "aligned-coordinate read buffers have the wrong dimensions");
    }
    std::fill(coordinates.begin(), coordinates.end(), Fq::zero());
    const std::uint64_t permutations_per_hash =
        layout.ciphertext_permutations_per_hash;
    const std::uint64_t ciphertext_begin = checked_mul(
        ciphertext, permutations_per_hash,
        "ciphertext permutation begin");
    const std::uint64_t ciphertext_end = checked_add(
        ciphertext_begin, permutations_per_hash,
        "ciphertext permutation end");
    const std::uint64_t input_begin =
        gkr::kCiphertextCommitmentMetadataElements;
    const std::uint64_t input_end = checked_add(
        input_begin, q, "ciphertext coordinate input end");
    std::uint64_t recovered = 0;
    for (const ProofOfPackingPoseidonSegment &segment :
         layout.ciphertext_segments) {
        const std::uint64_t intersection_begin = std::max(
            ciphertext_begin, segment.permutation_begin);
        const std::uint64_t intersection_end = std::min(
            ciphertext_end, segment.permutation_end());
        if (intersection_begin >= intersection_end) {
            continue;
        }
        for (std::size_t rate = 0; rate < kPoseidonRate; ++rate) {
            std::uint64_t permutation = intersection_begin;
            while (permutation < intersection_end) {
                const std::size_t count = std::min<std::uint64_t>(
                    block_elements, intersection_end - permutation);
                witness.read_at(
                    checked_add(
                        segment.input_witness_begin,
                        checked_add(
                            checked_mul(rate, segment.permutations,
                                        "rate-major coordinate base"),
                            permutation - segment.permutation_begin,
                            "rate-major coordinate offset"),
                        "rate-major coordinate offset"),
                    std::span<Fq>(scratch).first(count));
                for (std::size_t offset = 0; offset < count; ++offset) {
                    const std::uint64_t global_permutation = checked_add(
                        permutation, checked_u64(offset,
                                                 "coordinate offset"),
                        "coordinate permutation");
                    const std::uint64_t input = checked_add(
                        checked_mul(global_permutation - ciphertext_begin,
                                    kPoseidonRate,
                                    "ciphertext input block"),
                        rate, "ciphertext input position");
                    if (input >= input_begin && input < input_end) {
                        coordinates[checked_size(
                            input - input_begin,
                            "ciphertext coordinate index")] =
                            scratch[offset];
                        ++recovered;
                    }
                }
                permutation = checked_add(
                    permutation, checked_u64(count, "coordinate block"),
                    "coordinate permutation");
            }
        }
    }
    if (recovered != q) {
        throw std::logic_error(
            "aligned-coordinate reader did not recover every coordinate");
    }
}

void emit_simple_hash_rows(
    spartan::Matrix matrix, const OuterRelationPlan &plan,
    const ProofOfPackingR1csLayout &layout,
    const spartan::R1csMetadata &circuit_metadata,
    const storage::NativeFieldArtifact &complete,
    std::size_t block_elements, BufferedProductOutput &output,
    ProofOfPackingMatrixProductIoReport &io) {
    append_gap(output, layout.rows.ciphertext_poseidon.begin);
    const std::size_t q = plan.coordinates_per_ciphertext();
    TrackedProofWitnessReader witness(
        plan, circuit_metadata, complete, io);
    std::vector<Fq> coordinates(q);
    std::vector<Fq> auxiliaries(q);
    std::vector<Fq> scratch(block_elements);
    const Fq alpha(gkr::kDiagnosticSimpleCtHashAlpha);
    const Fq initial = gkr::diagnostic_simple_ct_hash_initial_state(
        plan.shape.ring_degree);
    for (std::size_t ciphertext = 0;
         ciphertext < plan.shape.aligned_ciphertexts; ++ciphertext) {
        if (matrix == spartan::Matrix::A) {
            read_aligned_ciphertext_coordinates(
                plan, layout, ciphertext, block_elements, witness,
                coordinates, scratch);
        }
        if (matrix != spartan::Matrix::B) {
            witness.read_at(
                layout.ciphertext_simple_hash_auxiliary_witness_index(
                    plan, ciphertext, 0),
                auxiliaries);
        }
        for (std::size_t coordinate = 0; coordinate < q; ++coordinate) {
            switch (matrix) {
            case spartan::Matrix::A:
                output.push(
                    coordinates[coordinate] +
                    alpha * (coordinate == 0
                                 ? initial
                                 : auxiliaries[coordinate - 1]));
                break;
            case spartan::Matrix::B:
                output.push(Fq::one());
                break;
            case spartan::Matrix::C:
                output.push(auxiliaries[coordinate]);
                break;
            }
        }
    }
}

void emit_ciphertext_outputs(
    spartan::Matrix matrix, const OuterRelationPlan &plan,
    const ProofOfPackingR1csLayout &layout,
    const spartan::R1csMetadata &circuit_metadata,
    const storage::NativeFieldArtifact &complete,
    std::size_t block_elements, BufferedProductOutput &output,
    ProofOfPackingMatrixProductIoReport &io) {
    append_gap(output, layout.rows.ciphertext_outputs.begin);
    const auto &local =
        detail::proof_of_packing_poseidon_permutation_template();
    if (matrix == spartan::Matrix::B) {
        for (std::uint64_t row = 0;
             row < layout.rows.ciphertext_outputs.live; ++row) {
            output.push(Fq::one());
        }
        return;
    }
    if (matrix == spartan::Matrix::C) {
        TrackedFqReader public_inputs(complete, kCompletePublicArray, io);
        std::vector<Fq> buffer(block_elements);
        std::uint64_t remaining = layout.rows.ciphertext_outputs.live;
        while (remaining != 0) {
            const std::size_t count = std::min<std::uint64_t>(
                block_elements, remaining);
            public_inputs.read_exact(
                std::span<Fq>(buffer).first(count));
            output.append(std::span<const Fq>(buffer).first(count));
            remaining -= count;
        }
        return;
    }

    TrackedProofWitnessReader witness(
        plan, circuit_metadata, complete, io);
    for (std::size_t ciphertext = 0;
         ciphertext < plan.shape.aligned_ciphertexts; ++ciphertext) {
        if (plan.shape.ciphertext_commitment_policy.relation ==
            gkr::CiphertextCommitmentRelation::DiagnosticSimpleCtHashV2) {
            const Fq final_state = witness.read_one_at(
                layout.ciphertext_simple_hash_auxiliary_witness_index(
                    plan, ciphertext,
                    plan.coordinates_per_ciphertext() - 1));
            for (std::size_t element = 0;
                 element < kPoseidonDigestElements; ++element) {
                output.push(
                    final_state +
                    Fq(gkr::kDiagnosticSimpleCtHashOutputDomains[
                        element]));
            }
            continue;
        }
        const std::uint64_t last_permutation = checked_add(
            checked_mul(ciphertext,
                        layout.ciphertext_permutations_per_hash,
                        "ciphertext permutation base"),
            layout.ciphertext_permutations_per_hash - 1,
            "ciphertext final permutation");
        for (std::size_t element = 0;
             element < kPoseidonDigestElements; ++element) {
            output.push(witness.read_one_at(
                layout.ciphertext_poseidon_auxiliary_witness_index(
                    local.final_auxiliary[element], last_permutation)));
        }
    }
}

void emit_regular_outer_rows(
    spartan::Matrix matrix, const OuterRelationPlan &plan,
    const ProofOfPackingR1csLayout &layout,
    const storage::NativeFieldArtifact &outer,
    std::size_t block_elements, BufferedProductOutput &output,
    ProofOfPackingMatrixProductArtifactReport &report) {
    {
        FqBlockCache public_inputs(outer, kOuterPublicArray, block_elements,
                                   report.outer_assignment_io);
        FqBlockCache witness(outer, kOuterWitnessArray, block_elements,
                             report.outer_assignment_io);
        OuterRelationR1csCursor cursor(
            plan, 0, plan.constraints.revealed_test_equalities.begin);
        while (!cursor.empty()) {
            const OuterRelationR1csRow &row = cursor.next();
            report.maximum_regular_row_terms = std::max<std::uint64_t>(
                report.maximum_regular_row_terms,
                std::max({checked_u64(row.a.size(), "outer A terms"),
                          checked_u64(row.b.size(), "outer B terms"),
                          checked_u64(row.c.size(), "outer C terms")}));
            append_gap(output,
                       layout.outer_constraint_row(
                           plan, row.constraint_index));
            output.push(evaluate_outer_combination(
                outer_combination(row, matrix), public_inputs, witness));
        }
    }

    // A revealed test row sums one product from every aligned ciphertext.
    // Evaluating those T*2N rows through a one-block scalar cache would jump
    // by 2N for every term and reread most of each block. Instead, retain one
    // N-coordinate accumulator and stream each owner's contiguous component
    // slice exactly once. This is the complete T*r*2N product payload.
    append_gap(output, layout.rows.revealed_test_equalities.begin);
    report.maximum_regular_row_terms = std::max<std::uint64_t>(
        report.maximum_regular_row_terms,
        plan.shape.aligned_ciphertexts);
    const std::uint64_t test_rows =
        layout.rows.revealed_test_equalities.live;
    if (matrix == spartan::Matrix::B) {
        for (std::uint64_t row = 0; row < test_rows; ++row) {
            output.push(Fq::one());
        }
        return;
    }
    if (matrix == spartan::Matrix::C) {
        TrackedFqReader revealed(
            outer, kOuterPublicArray, report.outer_assignment_io);
        revealed.seek(
            plan.variables.public_inputs.revealed_test_coordinates.begin);
        std::vector<Fq> buffer(block_elements);
        std::uint64_t remaining = test_rows;
        while (remaining != 0) {
            const std::size_t count = std::min<std::uint64_t>(
                block_elements, remaining);
            revealed.read_exact(std::span<Fq>(buffer).first(count));
            output.append(std::span<const Fq>(buffer).first(count));
            remaining -= count;
        }
        return;
    }

    const ProofOfPackingMatrixProductIoReport before =
        report.outer_assignment_io;
    const std::size_t degree = plan.shape.ring_degree;
    std::vector<Fq> accumulator(degree);
    std::vector<Fq> buffer(block_elements);
    TrackedFqReader products(
        outer, kOuterWitnessArray, report.outer_assignment_io);
    for (std::size_t test = 0; test < plan.shape.repetitions; ++test) {
        for (std::size_t component = 0;
             component < plan.shape.ciphertext_components; ++component) {
            std::fill(accumulator.begin(), accumulator.end(), Fq::zero());
            for (std::size_t aligned = 0;
                 aligned < plan.shape.aligned_ciphertexts; ++aligned) {
                std::size_t offset = 0;
                while (offset < degree) {
                    const std::size_t count = std::min(
                        block_elements, degree - offset);
                    products.read_at(
                        checked_add(
                            plan.product_witness_index(
                                test, aligned, component, 0),
                            offset, "revealed-test product offset"),
                        std::span<Fq>(buffer).first(count));
                    for (std::size_t index = 0; index < count; ++index) {
                        accumulator[offset + index] += buffer[index];
                    }
                    offset += count;
                }
            }
            output.append(accumulator);
        }
    }
    const auto delta = [](std::uint64_t after, std::uint64_t before_value,
                          const char *label) {
        if (after < before_value) {
            throw std::logic_error(std::string(label) + " regressed");
        }
        return after - before_value;
    };
    report.revealed_test_product_payload_bytes = delta(
        report.outer_assignment_io.payload_bytes, before.payload_bytes,
        "revealed-test payload bytes");
    report.revealed_test_product_read_operations = delta(
        report.outer_assignment_io.read_operations,
        before.read_operations, "revealed-test read operations");
    report.revealed_test_product_seek_operations = delta(
        report.outer_assignment_io.seek_operations,
        before.seek_operations, "revealed-test seek operations");
    const std::uint64_t fq_bytes = storage::encoded_element_bytes(
        storage::NativeFieldElementKind::Fq);
    if (report.revealed_test_product_payload_bytes % fq_bytes != 0) {
        throw std::logic_error(
            "revealed-test payload is not an integral Fq count");
    }
    report.revealed_test_product_elements_read =
        report.revealed_test_product_payload_bytes / fq_bytes;
    if (report.revealed_test_product_elements_read !=
        plan.variables.witness.well_formedness_products.count) {
        throw std::logic_error(
            "revealed-test stream did not consume each product once");
    }
}

void emit_fixed_packing_rows(
    spartan::Matrix matrix, const OuterRelationPlan &plan,
    const ProofOfPackingR1csLayout &layout,
    const storage::NativeFieldArtifact &outer,
    const spartan::FactoredMatrixProverKey &factored,
    std::span<const PackingTensorMapping> mappings,
    std::size_t block_elements, BufferedProductOutput &output,
    ProofOfPackingMatrixProductArtifactReport &report) {
    append_gap(output, layout.rows.revealed_packing_equalities.begin);
    const std::uint64_t row_count =
        layout.rows.revealed_packing_equalities.live;
    if (matrix == spartan::Matrix::B) {
        for (std::uint64_t row = 0; row < row_count; ++row) {
            output.push(Fq::one());
        }
        return;
    }
    if (matrix == spartan::Matrix::C) {
        TrackedFqReader public_inputs(
            outer, kOuterPublicArray, report.outer_assignment_io);
        public_inputs.seek(
            plan.variables.public_inputs.revealed_packing_coordinates.begin);
        std::vector<Fq> buffer(block_elements);
        std::uint64_t remaining = row_count;
        while (remaining != 0) {
            const std::size_t count = std::min<std::uint64_t>(
                block_elements, remaining);
            public_inputs.read_exact(
                std::span<Fq>(buffer).first(count));
            output.append(std::span<const Fq>(buffer).first(count));
            remaining -= count;
        }
        return;
    }

    const std::size_t degree = plan.shape.ring_degree;
    std::vector<Fq> accumulator(degree);
    std::vector<Fq> coefficients(block_elements);
    std::vector<Fq> coordinates(block_elements);
    TrackedFqReader outer_witness(
        outer, kOuterWitnessArray, report.outer_assignment_io);
    for (std::size_t logical_output = 0;
         logical_output < mappings.size(); ++logical_output) {
        const PackingTensorMapping &mapping =
            mappings[logical_output];
        for (std::size_t digit = 0;
             digit < plan.shape.packing_digit_count; ++digit) {
            TrackedFqReader tensor_column(
                *factored.tensor_columns_artifact,
                spartan::factored_matrix_tensor_column_array_name(
                    logical_output, digit),
                report.factored_tensor_io);
            for (std::size_t component = 0;
                 component < plan.shape.ciphertext_components;
                 ++component) {
                std::fill(accumulator.begin(), accumulator.end(),
                          Fq::zero());
                for (std::size_t local_owner = 0;
                     local_owner < mapping.global_owners.size();
                     ++local_owner) {
                    const std::size_t owner =
                        mapping.global_owners[local_owner];
                    ++report.fixed_owner_component_passes;
                    std::size_t offset = 0;
                    while (offset < degree) {
                        const std::size_t count = std::min(
                            block_elements, degree - offset);
                        tensor_column.read_at(
                            checked_add(
                                checked_mul(local_owner, degree,
                                            "tensor owner offset"),
                                offset, "tensor coordinate offset"),
                            std::span<Fq>(coefficients).first(count));
                        outer_witness.read_at(
                            checked_add(
                                plan.aligned_coordinate_witness_index(
                                    owner, component, 0),
                                offset, "aligned coordinate offset"),
                            std::span<Fq>(coordinates).first(count));
                        for (std::size_t index = 0; index < count; ++index) {
                            accumulator[offset + index] +=
                                coefficients[index] * coordinates[index];
                        }
                        offset += count;
                    }
                }
                output.append(accumulator);
            }
        }
    }
}

void emit_matrix(
    spartan::Matrix matrix, const OuterRelationPlan &plan,
    const ProofOfPackingR1csLayout &layout,
    const spartan::R1csMetadata &metadata,
    const storage::NativeFieldArtifact &complete,
    const storage::NativeFieldArtifact &outer,
    const spartan::FactoredMatrixProverKey &factored,
    std::span<const PackingTensorMapping> mappings,
    std::size_t block_elements,
    storage::NativeFieldArtifactWriter &writer,
    ProofOfPackingMatrixProductArtifactReport &report) {
    writer.begin_array(
        std::string(kProductArrays[static_cast<std::size_t>(matrix)]),
        storage::NativeFieldElementKind::Fq,
        metadata.shape().constraints);
    BufferedProductOutput output(writer, block_elements, report);
    if (plan.shape.ciphertext_commitment_policy.relation ==
        gkr::CiphertextCommitmentRelation::PoseidonV2) {
        emit_poseidon_rows(matrix, plan, layout, metadata, complete,
                           block_elements, output,
                           report.complete_assignment_io);
    } else {
        emit_simple_hash_rows(matrix, plan, layout, metadata, complete,
                              block_elements, output,
                              report.complete_assignment_io);
    }
    emit_ciphertext_outputs(matrix, plan, layout, metadata, complete,
                            block_elements, output,
                            report.complete_assignment_io);
    emit_regular_outer_rows(matrix, plan, layout, outer, block_elements,
                            output, report);
    emit_fixed_packing_rows(matrix, plan, layout, outer, factored, mappings,
                            block_elements, output, report);
    append_gap(output,
               metadata.shape().constraints);
    output.finish();
    if (output.position() != metadata.shape().constraints) {
        throw std::logic_error(
            "matrix-product output has the wrong row count");
    }
    writer.finish_array();
}

std::vector<PackingTensorMapping>
validate_factored_preprocessing(
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
            "matrix products require artifact-backed committed-factored "
            "preprocessing for the same circuit");
    }

    std::vector<PackingTensorMapping> mappings =
        proof_of_packing_factored_tensor_mappings(*factored.structure);
    if (mappings.size() != plan.shape.logical_packed_outputs) {
        throw std::invalid_argument(
            "factored packing owner map has the wrong output count");
    }
    std::vector<std::size_t> appearances(
        plan.shape.aligned_ciphertexts, 0);
    std::size_t expected_arrays = 0;
    for (std::size_t output = 0; output < mappings.size(); ++output) {
        const PackingTensorMapping &mapping = mappings[output];
        const PackingTensorDescriptor &descriptor = mapping.descriptor;
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
        expected_arrays += descriptor.digit_count;
    }
    if (std::any_of(appearances.begin(), appearances.end(),
                    [](std::size_t count) { return count != 1; }) ||
        factored.tensor_columns_artifact->arrays().size() !=
            expected_arrays) {
        throw std::invalid_argument(
            "factored packing owners or artifact arrays are incomplete");
    }
    std::size_t array_index = 0;
    for (std::size_t output = 0; output < mappings.size(); ++output) {
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
                array.element_count != shape.evaluation_count) {
                throw std::invalid_argument(
                    "factored tensor-column artifact layout is inconsistent");
            }
        }
    }
    return mappings;
}

} // namespace

std::uint64_t proof_of_packing_matrix_product_artifact_physical_bytes(
    const spartan::R1csMetadata &circuit_metadata) {
    if (!circuit_metadata.is_well_formed()) {
        throw std::invalid_argument(
            "matrix-product metadata is malformed");
    }
    const std::array<storage::NativeFieldArrayLayout, 3> arrays{{
        {"az", storage::NativeFieldElementKind::Fq,
         circuit_metadata.shape().constraints},
        {"bz", storage::NativeFieldElementKind::Fq,
         circuit_metadata.shape().constraints},
        {"cz", storage::NativeFieldElementKind::Fq,
         circuit_metadata.shape().constraints},
    }};
    return storage::native_field_artifact_physical_bytes(arrays);
}

ProofOfPackingMatrixProductArtifactPlan
plan_proof_of_packing_matrix_product_artifact(
    const OuterRelationPlan &plan,
    const spartan::R1csMetadata &circuit_metadata,
    std::uint64_t max_working_field_bytes,
    std::size_t requested_block_elements) {
    if (max_working_field_bytes == 0 || requested_block_elements == 0) {
        throw std::invalid_argument(
            "matrix-product planning needs explicit nonzero memory limits");
    }
    const std::uint64_t degree_bytes = checked_mul(
        plan.shape.ring_degree, sizeof(Fq),
        "fixed packing accumulator bytes");
    const std::uint64_t one_block_element_bytes = 3U * sizeof(Fq);
    const std::uint64_t minimum_working_field_bytes = checked_add(
        degree_bytes, one_block_element_bytes,
        "minimum matrix-product working bytes");
    if (max_working_field_bytes < minimum_working_field_bytes) {
        throw std::invalid_argument(
            "matrix-product memory limit cannot hold its accumulator and "
            "one three-vector I/O block");
    }
    const std::uint64_t available_block_elements =
        (max_working_field_bytes - degree_bytes) /
        one_block_element_bytes;
    const std::size_t block_elements = std::min(
        requested_block_elements,
        checked_size(available_block_elements,
                     "matrix-product block capacity"));
    return {
        .physical_bytes =
            proof_of_packing_matrix_product_artifact_physical_bytes(
                circuit_metadata),
        .retained_accumulator_bytes = degree_bytes,
        .minimum_working_field_bytes = minimum_working_field_bytes,
        .effective_block_elements = block_elements,
        .peak_working_field_bytes = checked_add(
            degree_bytes,
            checked_mul(checked_mul(3, block_elements,
                                    "matrix-product live block elements"),
                        sizeof(Fq), "matrix-product live block bytes"),
            "matrix-product peak field bytes"),
    };
}

Digest proof_of_packing_matrix_product_artifact_identity(
    const OuterRelationPlan &plan,
    const ProofOfPackingR1csLayout &layout,
    const spartan::R1csMetadata &circuit_metadata,
    const storage::NativeFieldArtifact &complete_assignment,
    const storage::NativeFieldArtifact &outer_assignment,
    const spartan::FactoredMatrixCommitment &factored_commitment,
    const storage::NativeFieldArtifact &factored_tensor_columns) {
    validate_static_inputs(plan, layout, circuit_metadata,
                           complete_assignment, outer_assignment);
    if (factored_commitment.circuit_digest != circuit_metadata.digest() ||
        factored_tensor_columns.identity() !=
            spartan::factored_matrix_artifact_identity(
                factored_commitment)) {
        throw std::invalid_argument(
            "matrix-product factored preprocessing identity mismatch");
    }
    std::vector<std::uint8_t> encoding(kIdentityDomain.begin(),
                                       kIdentityDomain.end());
    append_bytes(encoding,
                 outer_relation_assignment_artifact_identity(plan));
    append_layout(encoding, layout);
    append_metadata(encoding, circuit_metadata);
    append_artifact(encoding, complete_assignment);
    append_artifact(encoding, outer_assignment);
    const std::vector<std::uint8_t> factored_encoding =
        spartan::encode_factored_matrix_commitment(factored_commitment);
    append_u64(encoding, checked_u64(factored_encoding.size(),
                                     "factored commitment encoding"));
    append_bytes(encoding, factored_encoding);
    append_artifact(encoding, factored_tensor_columns);
    return sha256(encoding);
}

std::shared_ptr<const storage::NativeFieldArtifact>
open_proof_of_packing_matrix_product_artifact(
    const std::filesystem::path &directory,
    const OuterRelationPlan &plan,
    const ProofOfPackingR1csLayout &layout,
    const spartan::R1csMetadata &circuit_metadata,
    const storage::NativeFieldArtifact &complete_assignment,
    const storage::NativeFieldArtifact &outer_assignment,
    const spartan::FactoredMatrixCommitment &factored_commitment,
    const storage::NativeFieldArtifact &factored_tensor_columns) {
    auto artifact = std::make_shared<storage::NativeFieldArtifact>(
        storage::NativeFieldArtifact::open(
            directory,
            proof_of_packing_matrix_product_artifact_identity(
                plan, layout, circuit_metadata, complete_assignment,
                outer_assignment, factored_commitment,
                factored_tensor_columns)));
    if (artifact->arrays().size() != kProductArrays.size()) {
        throw std::invalid_argument(
            "proof-of-packing matrix-product artifact has wrong array count");
    }
    for (std::size_t matrix = 0; matrix < kProductArrays.size(); ++matrix) {
        const storage::NativeFieldArrayDescriptor &array =
            artifact->arrays()[matrix];
        if (array.name != kProductArrays[matrix] ||
            array.kind != storage::NativeFieldElementKind::Fq ||
            array.element_count != circuit_metadata.shape().constraints) {
            throw std::invalid_argument(
                "proof-of-packing matrix-product artifact has wrong layout");
        }
    }
    return artifact;
}

ProofOfPackingMatrixProductArtifact
write_proof_of_packing_matrix_product_artifact_impl(
    const OuterRelationPlan &plan,
    const ProofOfPackingR1csLayout &layout,
    const spartan::R1csMetadata &circuit_metadata,
    const storage::NativeFieldArtifact &complete_assignment,
    const storage::NativeFieldArtifact &outer_assignment,
    const spartan::FactoredMatrixProverKey &factored_preprocessing,
    ProofOfPackingMatrixProductArtifactOptions options,
    bool revalidate_sources) {
    if (options.directory.empty() ||
        options.storage_limits.max_total_bytes == 0 ||
        options.storage_limits.min_free_bytes == 0 ||
        options.max_working_field_bytes == 0 ||
        options.block_elements == 0) {
        throw std::invalid_argument(
            "matrix-product artifacts require explicit nonzero limits");
    }
    options.directory =
        std::filesystem::absolute(options.directory).lexically_normal();
    validate_empty_directory(options.directory);
    validate_static_inputs(plan, layout, circuit_metadata,
                           complete_assignment, outer_assignment);
    (void)validate_factored_preprocessing(
        plan, circuit_metadata, factored_preprocessing);
    const std::array<std::filesystem::path, 3> source_directories{
        complete_assignment.directory(), outer_assignment.directory(),
        factored_preprocessing.tensor_columns_artifact->directory()};
    require_disjoint_directories(options.directory, source_directories);

    // The standalone API reopens every source to defend against a stale
    // cached handle. A composed admission has already performed that scan and
    // passes handles whose lifetime is owned by the one-shot suffix.
    std::shared_ptr<const storage::NativeFieldArtifact> validated_complete(
        &complete_assignment,
        [](const storage::NativeFieldArtifact *) {});
    std::shared_ptr<const storage::NativeFieldArtifact> validated_outer(
        &outer_assignment,
        [](const storage::NativeFieldArtifact *) {});
    std::shared_ptr<const storage::NativeFieldArtifact> validated_tensors =
        factored_preprocessing.tensor_columns_artifact;
    if (revalidate_sources) {
        validated_complete =
            std::make_shared<const storage::NativeFieldArtifact>(
                storage::NativeFieldArtifact::open(
                    complete_assignment.directory(),
                    complete_assignment.identity()));
        validated_outer = open_outer_relation_assignment_artifact(
            outer_assignment.directory(), plan);
        validated_tensors = spartan::open_factored_matrix_artifact(
            factored_preprocessing.tensor_columns_artifact->directory(),
            factored_preprocessing.commitment);
    }
    validate_static_inputs(plan, layout, circuit_metadata,
                           *validated_complete, *validated_outer);
    spartan::FactoredMatrixProverKey validated_factored =
        factored_preprocessing;
    validated_factored.tensor_columns_artifact = validated_tensors;
    const std::vector<PackingTensorMapping> mappings =
        validate_factored_preprocessing(plan, circuit_metadata,
                                        validated_factored);

    const std::uint64_t stored_constraints =
        circuit_metadata.shape().constraints;
    const std::uint64_t padded_constraints = checked_u64(
        circuit_metadata.padded_constraints(), "padded constraints");
    const std::array<storage::NativeFieldArrayLayout, 3> arrays{{
        {std::string(kProductArrays[0]),
         storage::NativeFieldElementKind::Fq, stored_constraints},
        {std::string(kProductArrays[1]),
         storage::NativeFieldElementKind::Fq, stored_constraints},
        {std::string(kProductArrays[2]),
         storage::NativeFieldElementKind::Fq, stored_constraints},
    }};
    const std::uint64_t physical_bytes =
        storage::native_field_artifact_physical_bytes(arrays);
    if (physical_bytes > options.storage_limits.max_total_bytes) {
        throw std::invalid_argument(
            "matrix-product quota is below the exact artifact size");
    }
    const std::uint64_t required_free = checked_add(
        physical_bytes, options.storage_limits.min_free_bytes,
        "matrix-product free-space preflight");
    if (std::filesystem::space(options.directory).available < required_free) {
        throw std::runtime_error(
            "matrix-product destination has insufficient free space");
    }

    const ProofOfPackingMatrixProductArtifactPlan resource_plan =
        plan_proof_of_packing_matrix_product_artifact(
            plan, circuit_metadata, options.max_working_field_bytes,
            options.block_elements);
    const std::size_t block_elements =
        resource_plan.effective_block_elements;

    const ProofOfPackingR1csLedger ledger =
        proof_of_packing_r1cs_ledger(plan);
    const std::uint64_t active_rows = checked_add(
        checked_add(layout.rows.ciphertext_poseidon.live,
                    layout.rows.ciphertext_outputs.live,
                    "active Poseidon rows"),
        plan.constraints.total, "active packing rows");
    if (active_rows > stored_constraints ||
        stored_constraints > padded_constraints) {
        throw std::logic_error(
            "active matrix-product rows exceed Spartan padding");
    }
    ProofOfPackingMatrixProductArtifactReport report{
        .stored_constraint_elements = stored_constraints,
        .logical_padded_constraint_elements = padded_constraints,
        .ciphertext_commitment_rows =
            layout.rows.ciphertext_poseidon.live,
        .ciphertext_output_rows = layout.rows.ciphertext_outputs.live,
        .regular_outer_rows =
            plan.constraints.revealed_packing_equalities.begin,
        .fixed_packing_rows =
            plan.constraints.revealed_packing_equalities.count,
        .structural_zero_rows_per_matrix =
            stored_constraints - active_rows,
        .virtual_zero_rows_per_matrix =
            padded_constraints - stored_constraints,
        .product_payload_bytes = checked_mul(
            checked_mul(3, stored_constraints,
                        "matrix-product elements"),
            storage::encoded_element_bytes(
                storage::NativeFieldElementKind::Fq),
            "matrix-product payload bytes"),
        .physical_bytes = physical_bytes,
        .source_artifact_physical_bytes = checked_add(
            checked_add(validated_complete->physical_bytes(),
                        validated_outer->physical_bytes(),
                        "assignment artifact bytes"),
            validated_tensors->physical_bytes(),
            "all source artifact bytes"),
        .source_artifact_validation_bytes =
            revalidate_sources
                ? checked_add(
                      checked_add(validated_complete->physical_bytes(),
                                  validated_outer->physical_bytes(),
                                  "assignment validation bytes"),
                      validated_tensors->physical_bytes(),
                      "all source validation bytes")
                : 0,
        .fixed_accumulator_elements = plan.shape.ring_degree,
        .effective_block_elements = block_elements,
        .peak_working_field_bytes =
            resource_plan.peak_working_field_bytes,
    };
    if (ledger.total_constraints != active_rows) {
        throw std::logic_error(
            "matrix-product active row ledger disagrees with R1CS ledger");
    }

    const std::vector<gkr::HashCommitCT> commitments =
        recover_assignment_commitments(plan, *validated_complete,
                                       report.complete_assignment_io);
    if (validated_complete->identity() !=
        proof_of_packing_assignment_artifact_identity(
            plan, circuit_metadata, *validated_outer, commitments)) {
        throw std::invalid_argument(
            "complete packing assignment is not bound to the outer source");
    }

    const Digest identity =
        proof_of_packing_matrix_product_artifact_identity(
            plan, layout, circuit_metadata, *validated_complete,
            *validated_outer, validated_factored.commitment,
            *validated_tensors);
    DestinationCleanup cleanup(options.directory);
    storage::NativeFieldArtifactWriter writer(
        options.directory, options.storage_limits, identity);

    emit_matrix(spartan::Matrix::A, plan, layout, circuit_metadata,
                *validated_complete, *validated_outer,
                validated_factored, mappings, block_elements, writer,
                report);
    emit_matrix(spartan::Matrix::B, plan, layout, circuit_metadata,
                *validated_complete, *validated_outer,
                validated_factored, mappings, block_elements, writer,
                report);
    emit_matrix(spartan::Matrix::C, plan, layout, circuit_metadata,
                *validated_complete, *validated_outer,
                validated_factored, mappings, block_elements, writer,
                report);
    const storage::NativeFieldArtifactWriteResult written = writer.finish();
    if (written.physical_bytes != physical_bytes ||
        report.sequential_output_payload_bytes !=
            report.product_payload_bytes) {
        throw std::logic_error(
            "matrix-product preflight disagrees with completed output");
    }
    auto artifact = open_proof_of_packing_matrix_product_artifact(
        options.directory, plan, layout, circuit_metadata,
        *validated_complete, *validated_outer,
        validated_factored.commitment, *validated_tensors);
    report.output_artifact_validation_bytes = artifact->physical_bytes();
    cleanup.disarm();
    return {std::move(artifact), report};
}

ProofOfPackingMatrixProductArtifact
write_proof_of_packing_matrix_product_artifact(
    const OuterRelationPlan &plan,
    const ProofOfPackingR1csLayout &layout,
    const spartan::R1csMetadata &circuit_metadata,
    const storage::NativeFieldArtifact &complete_assignment,
    const storage::NativeFieldArtifact &outer_assignment,
    const spartan::FactoredMatrixProverKey &factored_preprocessing,
    ProofOfPackingMatrixProductArtifactOptions options) {
    return write_proof_of_packing_matrix_product_artifact_impl(
        plan, layout, circuit_metadata, complete_assignment,
        outer_assignment, factored_preprocessing, std::move(options), true);
}

ProofOfPackingMatrixProductArtifact
write_proof_of_packing_matrix_product_artifact_admitted_sources(
    const OuterRelationPlan &plan,
    const ProofOfPackingR1csLayout &layout,
    const spartan::R1csMetadata &circuit_metadata,
    const storage::NativeFieldArtifact &complete_assignment,
    const storage::NativeFieldArtifact &outer_assignment,
    const spartan::FactoredMatrixProverKey &factored_preprocessing,
    ProofOfPackingMatrixProductArtifactOptions options) {
    return write_proof_of_packing_matrix_product_artifact_impl(
        plan, layout, circuit_metadata, complete_assignment,
        outer_assignment, factored_preprocessing, std::move(options), false);
}

} // namespace laminate::packing
