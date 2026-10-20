/// @file assignment.cpp
/// @brief Lazy public/witness values for target-scale outer proving.

#include "laminate/packing/outer_relation/assignment.hpp"

#include "laminate/transcript/hash.hpp"

#include <algorithm>
#include <array>
#include <filesystem>
#include <limits>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>

namespace laminate::packing {
namespace {

constexpr std::string_view kAssignmentIdentityDomain =
    "LaminateImpl/OuterRelationAssignmentArtifact/v1";
constexpr std::string_view kPublicInputsArray = "public-inputs";
constexpr std::string_view kWitnessArray = "witness";

std::size_t as_size(std::uint64_t value, const char *label) {
    if (value > std::numeric_limits<std::size_t>::max()) {
        throw std::overflow_error(std::string(label) + " exceeds size_t");
    }
    return static_cast<std::size_t>(value);
}

std::uint64_t checked_size(std::size_t value, const char *label) {
    if (value > std::numeric_limits<std::uint64_t>::max()) {
        throw std::overflow_error(std::string(label) + " exceeds u64");
    }
    return static_cast<std::uint64_t>(value);
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

void append_range(std::vector<std::uint8_t> &output,
                  const OuterRelationRange &range) {
    append_u64(output, range.begin);
    append_u64(output, range.count);
}

class AssignmentArtifactCleanup {
  public:
    explicit AssignmentArtifactCleanup(std::filesystem::path directory)
        : directory_(std::move(directory)) {}

    AssignmentArtifactCleanup(const AssignmentArtifactCleanup &) = delete;
    AssignmentArtifactCleanup &operator=(
        const AssignmentArtifactCleanup &) = delete;

    ~AssignmentArtifactCleanup() {
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

void validate_empty_assignment_directory(
    const std::filesystem::path &directory) {
    const std::filesystem::file_status status =
        std::filesystem::symlink_status(directory);
    if (!std::filesystem::is_directory(status) ||
        std::filesystem::is_symlink(status) ||
        !std::filesystem::is_empty(directory)) {
        throw std::invalid_argument(
            "outer assignment destination must be an empty real directory");
    }
}

bool contains(const OuterRelationRange &range, std::uint64_t index) {
    return index >= range.begin && index < range.end();
}

std::size_t relative(std::uint64_t index,
                     const OuterRelationRange &range,
                     const char *label) {
    if (!contains(range, index)) {
        throw std::logic_error(std::string(label) +
                               " escaped its assignment range");
    }
    return as_size(index - range.begin, label);
}

void require_size(std::size_t actual, std::uint64_t expected,
                  const char *label) {
    if (actual != as_size(expected, label)) {
        throw std::invalid_argument(std::string("outer assignment view: ") +
                                    label + " has the wrong length");
    }
}

void require_residues(std::span<const std::uint64_t> values,
                      std::uint64_t modulus, const char *label) {
    if (std::any_of(values.begin(), values.end(),
                    [=](std::uint64_t value) {
                        return value >= modulus;
                    })) {
        throw std::invalid_argument(std::string("outer assignment view: ") +
                                    label +
                                    " contains a noncanonical residue");
    }
}

void append_flat_ciphertext_slices(
    std::vector<OuterRelationCiphertextCoordinateSlice> &destination,
    std::span<const std::uint64_t> coordinates,
    std::size_t ciphertext_count, std::size_t coordinates_per_ciphertext) {
    destination.reserve(ciphertext_count);
    for (std::size_t ciphertext = 0; ciphertext < ciphertext_count;
         ++ciphertext) {
        destination.push_back(
            OuterRelationCiphertextCoordinateSlice::borrowed(
                coordinates.subspan(
                    ciphertext * coordinates_per_ciphertext,
                    coordinates_per_ciphertext)));
    }
}

OuterRelationR1csInputSlices make_flat_input_slices(
    const OuterRelationPlan &plan,
    const OuterRelationPublicInputs &public_inputs,
    const OuterRelationWitnessInputs &witness_inputs) {
    require_size(
        public_inputs.packed_challenge_words.size(),
        plan.variables.public_inputs.packed_challenge_words.count,
        "packed challenge words");
    require_size(
        public_inputs.revealed_test_coordinates.size(),
        plan.variables.public_inputs.revealed_test_coordinates.count,
        "revealed test coordinates");
    require_size(
        public_inputs.revealed_packing_coordinates.size(),
        plan.variables.public_inputs.revealed_packing_coordinates.count,
        "revealed packing coordinates");
    require_size(
        witness_inputs.aligned_ciphertext_coordinates.size(),
        plan.variables.witness.aligned_ciphertext_coordinates.count,
        "aligned ciphertext coordinates");

    OuterRelationR1csInputSlices result;
    result.packed_challenge_words =
        public_inputs.packed_challenge_words;
    const std::size_t width = plan.coordinates_per_ciphertext();
    append_flat_ciphertext_slices(
        result.revealed_test_ciphertexts,
        public_inputs.revealed_test_coordinates,
        plan.shape.repetitions, width);
    append_flat_ciphertext_slices(
        result.revealed_packing_ciphertexts,
        public_inputs.revealed_packing_coordinates,
        plan.physical_packed_ciphertexts(), width);
    append_flat_ciphertext_slices(
        result.aligned_ciphertexts,
        witness_inputs.aligned_ciphertext_coordinates,
        plan.shape.aligned_ciphertexts, width);
    return result;
}

void require_ciphertext_slices(
    std::span<const OuterRelationCiphertextCoordinateSlice> slices,
    std::size_t expected_count, std::size_t expected_width,
    std::uint64_t modulus, bool allow_implicit_zero,
    const char *label) {
    if (slices.size() != expected_count) {
        throw std::invalid_argument(
            std::string("outer assignment view: ") + label +
            " has the wrong ciphertext count");
    }
    for (const OuterRelationCiphertextCoordinateSlice &slice : slices) {
        if (slice.is_implicit_zero()) {
            if (!allow_implicit_zero) {
                throw std::invalid_argument(
                    std::string("outer assignment view: ") + label +
                    " cannot contain an absent public-zero coordinate "
                    "slice");
            }
            continue;
        }
        if (slice.size() != expected_width) {
            throw std::invalid_argument(
                std::string("outer assignment view: ") + label +
                " contains a ciphertext with the wrong coordinate count");
        }
        require_residues(slice.coordinates(), modulus, label);
        require_residues(slice.public_c0_coordinates(), modulus, label);
    }
}

std::uint64_t coordinate_value(
    std::span<const OuterRelationCiphertextCoordinateSlice> ciphertexts,
    std::uint64_t local_coordinate,
    std::size_t coordinates_per_ciphertext, const char *label) {
    const std::size_t ciphertext = as_size(
        local_coordinate / coordinates_per_ciphertext, label);
    const std::size_t coordinate = as_size(
        local_coordinate % coordinates_per_ciphertext, label);
    return ciphertexts[ciphertext].value(coordinate);
}

std::uint64_t negate_mod(std::uint64_t value, std::uint64_t modulus) {
    return value == 0 ? 0 : modulus - value;
}

OuterRelationWitnessValueFamily witness_family(
    const OuterRelationPlan &plan, std::uint64_t index) {
    if (contains(plan.variables.witness.derived_challenge_bits, index)) {
        return OuterRelationWitnessValueFamily::DerivedChallengeBit;
    }
    if (contains(plan.variables.witness.aligned_ciphertext_coordinates,
                 index)) {
        return OuterRelationWitnessValueFamily::AlignedCiphertextCoordinate;
    }
    return OuterRelationWitnessValueFamily::WellFormednessProduct;
}

OuterRelationPublicValueFamily public_family(
    const OuterRelationPlan &plan, std::uint64_t index) {
    if (contains(plan.variables.public_inputs.packed_challenge_words,
                 index)) {
        return OuterRelationPublicValueFamily::PackedChallengeWord;
    }
    if (contains(plan.variables.public_inputs.revealed_test_coordinates,
                 index)) {
        return OuterRelationPublicValueFamily::RevealedTestCoordinate;
    }
    return OuterRelationPublicValueFamily::RevealedPackingCoordinate;
}

} // namespace

OuterRelationCiphertextCoordinateSlice::
    OuterRelationCiphertextCoordinateSlice(
        std::span<const std::uint64_t> coordinates,
        std::span<const std::uint64_t> public_c0_coordinates,
        std::size_t logical_size, bool implicit_zero)
    : coordinates_(coordinates),
      public_c0_coordinates_(public_c0_coordinates),
      logical_size_(logical_size), implicit_zero_(implicit_zero) {}

OuterRelationCiphertextCoordinateSlice
OuterRelationCiphertextCoordinateSlice::borrowed(
    std::span<const std::uint64_t> coordinates) {
    return OuterRelationCiphertextCoordinateSlice(
        coordinates, {}, coordinates.size(), false);
}

OuterRelationCiphertextCoordinateSlice
OuterRelationCiphertextCoordinateSlice::mixed(
    std::span<const std::uint64_t> encrypted_coordinates,
    std::span<const std::uint64_t> public_c0_coordinates,
    std::size_t total_width) {
    if ((encrypted_coordinates.empty() ||
         encrypted_coordinates.size() == total_width) &&
        (public_c0_coordinates.empty() ||
         (total_width % 2U == 0 &&
          public_c0_coordinates.size() == total_width / 2U))) {
        return OuterRelationCiphertextCoordinateSlice(
            encrypted_coordinates, public_c0_coordinates, total_width,
            false);
    }
    throw std::invalid_argument(
        "outer relation mixed coordinate slice has malformed dimensions");
}

OuterRelationCiphertextCoordinateSlice
OuterRelationCiphertextCoordinateSlice::implicit_zero() {
    return OuterRelationCiphertextCoordinateSlice({}, {}, 0, true);
}

bool OuterRelationCiphertextCoordinateSlice::is_implicit_zero() const {
    return implicit_zero_;
}

std::size_t OuterRelationCiphertextCoordinateSlice::size() const {
    return logical_size_;
}

std::span<const std::uint64_t>
OuterRelationCiphertextCoordinateSlice::coordinates() const {
    return coordinates_;
}

std::span<const std::uint64_t>
OuterRelationCiphertextCoordinateSlice::public_c0_coordinates() const {
    return public_c0_coordinates_;
}

std::uint64_t OuterRelationCiphertextCoordinateSlice::value(
    std::size_t coordinate) const {
    if (implicit_zero_) {
        return 0;
    }
    if (coordinate >= logical_size_) {
        throw std::out_of_range(
            "outer relation coordinate slice index is out of range");
    }
    std::uint64_t result = coordinates_.empty() ? 0 : coordinates_[coordinate];
    if (coordinate < public_c0_coordinates_.size()) {
        const std::uint64_t public_value =
            public_c0_coordinates_[coordinate];
        result = result >= kOuterFieldOrder - public_value
                     ? result - (kOuterFieldOrder - public_value)
                     : result + public_value;
    }
    return result;
}

OuterRelationR1csAssignmentStorage
estimate_outer_relation_r1cs_assignment_storage(
    const OuterRelationPlan &plan) {
    const std::uint64_t element_bytes = sizeof(std::uint64_t);
    const std::uint64_t public_bytes = checked_mul(
        plan.variables.public_inputs.total, element_bytes,
        "outer public assignment bytes");
    const std::uint64_t aligned_bytes = checked_mul(
        plan.variables.witness.aligned_ciphertext_coordinates.count,
        element_bytes, "outer aligned source bytes");
    const std::uint64_t challenge_word_bytes = checked_mul(
        plan.variables.public_inputs.packed_challenge_words.count,
        element_bytes, "outer challenge-word source bytes");
    const std::uint64_t ciphertext_coordinate_count = checked_add(
        checked_add(
            plan.variables.public_inputs.revealed_test_coordinates.count,
            plan.variables.public_inputs.revealed_packing_coordinates.count,
            "outer borrowed public ciphertext coordinates"),
        plan.variables.witness.aligned_ciphertext_coordinates.count,
        "outer borrowed ciphertext coordinates");
    const std::uint64_t ciphertext_coordinate_bytes = checked_mul(
        ciphertext_coordinate_count, element_bytes,
        "outer borrowed ciphertext-coordinate bytes");
    const std::uint64_t slice_count = checked_add(
        checked_add(
            checked_size(plan.shape.repetitions,
                         "outer test slice count"),
            checked_size(plan.physical_packed_ciphertexts(),
                         "outer packing slice count"),
            "outer public slice count"),
        checked_size(plan.shape.aligned_ciphertexts,
                     "outer aligned slice count"),
        "outer slice count");
    const std::uint64_t slice_descriptor_bytes = checked_mul(
        slice_count, sizeof(OuterRelationCiphertextCoordinateSlice),
        "outer slice descriptor bytes");
    const std::uint64_t product_bytes = checked_mul(
        plan.variables.witness.well_formedness_products.count,
        element_bytes, "outer product auxiliary bytes");
    const std::uint64_t flat_bytes = checked_mul(
        checked_add(plan.variables.public_inputs.total,
                    plan.variables.witness.total,
                    "outer flat assignment elements"),
        element_bytes, "outer flat assignment bytes");
    return OuterRelationR1csAssignmentStorage{
        .public_source_bytes = public_bytes,
        .aligned_source_bytes = aligned_bytes,
        .challenge_word_source_bytes = challenge_word_bytes,
        .borrowed_ciphertext_coordinate_bytes =
            ciphertext_coordinate_bytes,
        .borrowed_slice_descriptor_bytes = slice_descriptor_bytes,
        .flattened_coordinate_copy_bytes_avoided =
            ciphertext_coordinate_bytes,
        .eager_product_auxiliary_bytes = product_bytes,
        .eager_flat_assignment_bytes = flat_bytes,
        .lazy_derived_witness_bytes = 0,
    };
}

Digest outer_relation_assignment_artifact_identity(
    const OuterRelationPlan &plan) {
    std::vector<std::uint8_t> encoding(kAssignmentIdentityDomain.begin(),
                                       kAssignmentIdentityDomain.end());
    append_u64(encoding, plan.shape.native_modulus);
    append_u64(encoding, checked_size(plan.shape.ring_degree,
                                      "assignment ring degree"));
    append_u64(encoding, checked_size(plan.shape.aligned_ciphertexts,
                                      "assignment aligned count"));
    append_u64(encoding, checked_size(plan.shape.repetitions,
                                      "assignment repetition count"));
    append_u64(encoding, checked_size(plan.shape.logical_packed_outputs,
                                      "assignment output count"));
    append_u64(encoding, checked_size(plan.shape.packing_digit_count,
                                      "assignment digit count"));
    append_u64(encoding, checked_size(plan.shape.ciphertext_components,
                                      "assignment component count"));
    append_u64(encoding, checked_size(plan.shape.public_input_capacity_bits,
                                      "assignment public capacity"));
    append_u64(
        encoding, plan.shape.ciphertext_commitment_policy.wire_code());

    append_range(encoding,
                 plan.variables.public_inputs.packed_challenge_words);
    append_range(encoding,
                 plan.variables.public_inputs.revealed_test_coordinates);
    append_range(encoding,
                 plan.variables.public_inputs.revealed_packing_coordinates);
    append_u64(encoding, plan.variables.public_inputs.total);
    append_range(encoding,
                 plan.variables.witness.derived_challenge_bits);
    append_range(encoding,
                 plan.variables.witness.aligned_ciphertext_coordinates);
    append_range(encoding,
                 plan.variables.witness.well_formedness_products);
    append_u64(encoding, plan.variables.witness.total);

    append_range(encoding, plan.constraints.challenge_bit_booleanity);
    append_range(encoding,
                 plan.constraints.challenge_word_recomposition);
    append_range(encoding, plan.constraints.well_formedness_products);
    append_range(encoding, plan.constraints.revealed_test_equalities);
    append_range(encoding, plan.constraints.revealed_packing_equalities);
    append_u64(encoding, plan.constraints.total);
    return sha256(encoding);
}

std::uint64_t outer_relation_assignment_artifact_physical_bytes(
    const OuterRelationPlan &plan) {
    const std::array<storage::NativeFieldArrayLayout, 2> layout{{
        {std::string(kPublicInputsArray),
         storage::NativeFieldElementKind::Fq,
         plan.variables.public_inputs.total},
        {std::string(kWitnessArray), storage::NativeFieldElementKind::Fq,
         plan.variables.witness.total},
    }};
    return storage::native_field_artifact_physical_bytes(layout);
}

std::shared_ptr<const storage::NativeFieldArtifact>
open_outer_relation_assignment_artifact(
    const std::filesystem::path &directory,
    const OuterRelationPlan &plan) {
    auto artifact = std::make_shared<storage::NativeFieldArtifact>(
        storage::NativeFieldArtifact::open(
            directory,
            outer_relation_assignment_artifact_identity(plan)));
    const auto &public_inputs = artifact->array(kPublicInputsArray);
    const auto &witness = artifact->array(kWitnessArray);
    if (artifact->arrays().size() != 2 ||
        public_inputs.kind != storage::NativeFieldElementKind::Fq ||
        witness.kind != storage::NativeFieldElementKind::Fq ||
        public_inputs.element_count !=
            plan.variables.public_inputs.total ||
        witness.element_count != plan.variables.witness.total) {
        throw std::invalid_argument(
            "outer assignment artifact has the wrong layout");
    }
    return artifact;
}

OuterRelationAssignmentArtifact write_outer_relation_assignment_artifact(
    const OuterRelationR1csAssignmentView &assignment,
    OuterRelationAssignmentArtifactOptions options) {
    const OuterRelationPlan &plan = assignment.plan();
    if (options.directory.empty() ||
        options.storage_limits.max_total_bytes == 0 ||
        options.storage_limits.min_free_bytes == 0 ||
        options.max_working_field_bytes == 0 ||
        options.block_elements == 0) {
        throw std::invalid_argument(
            "outer assignment artifact requires explicit nonzero limits");
    }
    options.directory =
        std::filesystem::absolute(options.directory).lexically_normal();
    validate_empty_assignment_directory(options.directory);

    const std::uint64_t expected_physical_bytes =
        outer_relation_assignment_artifact_physical_bytes(plan);
    if (expected_physical_bytes >
        options.storage_limits.max_total_bytes) {
        throw std::invalid_argument(
            "outer assignment artifact quota is below its exact size");
    }
    const std::uint64_t required_free = checked_add(
        expected_physical_bytes, options.storage_limits.min_free_bytes,
        "outer assignment free-space preflight");
    if (std::filesystem::space(options.directory).available <
        required_free) {
        throw std::runtime_error(
            "outer assignment artifact has insufficient free space");
    }

    const std::uint64_t field_limit =
        options.max_working_field_bytes / sizeof(Fq);
    const std::size_t block_elements = std::min(
        options.block_elements,
        as_size(field_limit, "outer assignment field buffer"));
    if (block_elements == 0) {
        throw std::invalid_argument(
            "outer assignment field-memory limit is too small");
    }

    const std::uint64_t encoded_fq_bytes =
        storage::encoded_element_bytes(
            storage::NativeFieldElementKind::Fq);
    const std::uint64_t public_payload_bytes = checked_mul(
        plan.variables.public_inputs.total, encoded_fq_bytes,
        "outer assignment public payload");
    const std::uint64_t witness_payload_bytes = checked_mul(
        plan.variables.witness.total, encoded_fq_bytes,
        "outer assignment witness payload");
    OuterRelationAssignmentArtifactReport report{
        .public_input_elements = plan.variables.public_inputs.total,
        .witness_elements = plan.variables.witness.total,
        .derived_product_elements =
            plan.variables.witness.well_formedness_products.count,
        .public_payload_bytes = public_payload_bytes,
        .witness_payload_bytes = witness_payload_bytes,
        .physical_bytes = expected_physical_bytes,
        .artifact_validation_bytes = expected_physical_bytes,
        .sequential_write_payload_bytes = checked_add(
            public_payload_bytes, witness_payload_bytes,
            "outer assignment written payload"),
        .peak_working_field_bytes = checked_mul(
            checked_size(block_elements, "outer assignment block"),
            sizeof(Fq), "outer assignment field buffer"),
    };

    AssignmentArtifactCleanup cleanup(options.directory);
    storage::NativeFieldArtifactWriter writer(
        options.directory, options.storage_limits,
        outer_relation_assignment_artifact_identity(plan));
    std::vector<Fq> buffer(block_elements);

    writer.begin_array(std::string(kPublicInputsArray),
                       storage::NativeFieldElementKind::Fq,
                       plan.variables.public_inputs.total);
    OuterRelationPublicValueCursor public_cursor(assignment);
    while (!public_cursor.empty()) {
        const std::size_t count = std::min<std::uint64_t>(
            buffer.size(), public_cursor.remaining());
        for (std::size_t index = 0; index < count; ++index) {
            const std::uint64_t value = public_cursor.next().value;
            if (value >= Fq::modulus()) {
                throw std::invalid_argument(
                    "outer assignment public value is not an Fq residue");
            }
            buffer[index] = Fq(value);
        }
        writer.append(std::span<const Fq>(buffer).first(count));
    }
    writer.finish_array();

    writer.begin_array(std::string(kWitnessArray),
                       storage::NativeFieldElementKind::Fq,
                       plan.variables.witness.total);
    OuterRelationWitnessValueCursor witness_cursor(assignment);
    while (!witness_cursor.empty()) {
        const std::size_t count = std::min<std::uint64_t>(
            buffer.size(), witness_cursor.remaining());
        for (std::size_t index = 0; index < count; ++index) {
            const std::uint64_t value = witness_cursor.next().value;
            if (value >= Fq::modulus()) {
                throw std::invalid_argument(
                    "outer assignment witness value is not an Fq residue");
            }
            buffer[index] = Fq(value);
        }
        writer.append(std::span<const Fq>(buffer).first(count));
    }
    writer.finish_array();

    const storage::NativeFieldArtifactWriteResult written = writer.finish();
    if (written.physical_bytes != expected_physical_bytes) {
        throw std::logic_error(
            "outer assignment artifact preflight disagrees with output");
    }
    auto artifact = open_outer_relation_assignment_artifact(
        options.directory, plan);
    cleanup.disarm();
    return {std::move(artifact), report};
}

OuterRelationR1csAssignmentView::OuterRelationR1csAssignmentView(
    const OuterRelationPlan &plan,
    const OuterRelationPublicInputs &public_inputs,
    const OuterRelationWitnessInputs &witness_inputs)
    : OuterRelationR1csAssignmentView(
          plan, make_flat_input_slices(
                    plan, public_inputs, witness_inputs)) {}

OuterRelationR1csAssignmentView::OuterRelationR1csAssignmentView(
    const OuterRelationPlan &plan,
    OuterRelationR1csInputSlices input_slices)
    : plan_(&plan), input_slices_(std::move(input_slices)) {
    require_size(
        input_slices_.packed_challenge_words.size(),
        plan.variables.public_inputs.packed_challenge_words.count,
        "packed challenge words");
    require_residues(input_slices_.packed_challenge_words,
                     plan.shape.native_modulus,
                     "packed challenge words");
    const std::size_t width = plan.coordinates_per_ciphertext();
    require_ciphertext_slices(
        input_slices_.revealed_test_ciphertexts,
        plan.shape.repetitions, width, plan.shape.native_modulus,
        true, "revealed test ciphertexts");
    require_ciphertext_slices(
        input_slices_.revealed_packing_ciphertexts,
        plan.physical_packed_ciphertexts(), width,
        plan.shape.native_modulus, true,
        "revealed packing ciphertexts");
    require_ciphertext_slices(
        input_slices_.aligned_ciphertexts,
        plan.shape.aligned_ciphertexts, width,
        plan.shape.native_modulus, true, "aligned ciphertexts");
}

const OuterRelationPlan &OuterRelationR1csAssignmentView::plan() const {
    return *plan_;
}

std::uint8_t OuterRelationR1csAssignmentView::challenge_bit(
    std::uint64_t local_bit) const {
    if (local_bit >=
        plan_->variables.witness.derived_challenge_bits.count) {
        throw std::out_of_range(
            "outer assignment view: challenge bit is out of range");
    }
    const std::uint64_t capacity =
        plan_->shape.public_input_capacity_bits;
    const std::uint64_t word = local_bit / capacity;
    const std::uint64_t offset = local_bit % capacity;
    return static_cast<std::uint8_t>(
        (input_slices_.packed_challenge_words[as_size(
             word, "challenge word")] >> offset) &
        std::uint64_t{1});
}

std::uint64_t OuterRelationR1csAssignmentView::ternary_coefficient(
    std::size_t test, std::size_t aligned) const {
    const std::uint64_t challenge = checked_add(
        checked_mul(checked_size(test, "challenge test"),
                    checked_size(plan_->shape.aligned_ciphertexts,
                                 "challenge aligned count"),
                    "challenge test offset"),
        checked_size(aligned, "challenge aligned input"),
        "challenge index");
    const std::uint64_t pair = checked_mul(
        challenge, 2, "challenge bit pair");
    const std::uint8_t plus = challenge_bit(pair);
    const std::uint8_t minus = challenge_bit(pair + 1);
    if (plus == minus) {
        return 0;
    }
    return plus == 1 ? 1 : plan_->shape.native_modulus - 1;
}

std::uint64_t OuterRelationR1csAssignmentView::product_value(
    std::uint64_t local_product) const {
    const std::uint64_t coordinates_per_aligned =
        plan_->coordinates_per_ciphertext();
    const std::uint64_t coordinates_per_test =
        plan_->variables.witness.aligned_ciphertext_coordinates.count;
    const std::size_t test = as_size(
        local_product / coordinates_per_test, "product test");
    const std::uint64_t within_test =
        local_product % coordinates_per_test;
    const std::size_t aligned = as_size(
        within_test / coordinates_per_aligned, "product aligned input");
    const std::uint64_t input = coordinate_value(
        input_slices_.aligned_ciphertexts, within_test,
        coordinates_per_aligned, "product aligned coordinate");
    const std::uint64_t coefficient = ternary_coefficient(test, aligned);
    if (coefficient == 0) {
        return 0;
    }
    return coefficient == 1
               ? input
               : negate_mod(input, plan_->shape.native_modulus);
}

std::uint64_t OuterRelationR1csAssignmentView::public_value(
    std::uint64_t index) const {
    if (index >= plan_->variables.public_inputs.total) {
        throw std::out_of_range(
            "outer assignment view: public index is out of range");
    }
    if (contains(plan_->variables.public_inputs.packed_challenge_words,
                 index)) {
        return input_slices_.packed_challenge_words[relative(
            index,
            plan_->variables.public_inputs.packed_challenge_words,
            "packed challenge word")];
    }
    if (contains(plan_->variables.public_inputs.revealed_test_coordinates,
                 index)) {
        return coordinate_value(
            input_slices_.revealed_test_ciphertexts,
            index - plan_->variables.public_inputs
                        .revealed_test_coordinates.begin,
            plan_->coordinates_per_ciphertext(),
            "revealed test coordinate");
    }
    return coordinate_value(
        input_slices_.revealed_packing_ciphertexts,
        index - plan_->variables.public_inputs
                    .revealed_packing_coordinates.begin,
        plan_->coordinates_per_ciphertext(),
        "revealed packing coordinate");
}

std::uint64_t OuterRelationR1csAssignmentView::witness_value(
    std::uint64_t index) const {
    if (index >= plan_->variables.witness.total) {
        throw std::out_of_range(
            "outer assignment view: witness index is out of range");
    }
    if (contains(plan_->variables.witness.derived_challenge_bits, index)) {
        return challenge_bit(
            index - plan_->variables.witness.derived_challenge_bits.begin);
    }
    if (contains(plan_->variables.witness.aligned_ciphertext_coordinates,
                 index)) {
        return coordinate_value(
            input_slices_.aligned_ciphertexts,
            index - plan_->variables.witness
                        .aligned_ciphertext_coordinates.begin,
            plan_->coordinates_per_ciphertext(),
            "aligned ciphertext coordinate");
    }
    return product_value(
        index - plan_->variables.witness.well_formedness_products.begin);
}

const OuterRelationCiphertextCoordinateSlice &
OuterRelationR1csAssignmentView::aligned_ciphertext(
    std::size_t aligned) const {
    return input_slices_.aligned_ciphertexts.at(aligned);
}

OuterRelationPublicValueCursor::OuterRelationPublicValueCursor(
    const OuterRelationR1csAssignmentView &assignment)
    : OuterRelationPublicValueCursor(
          assignment, 0,
          assignment.plan().variables.public_inputs.total) {}

OuterRelationPublicValueCursor::OuterRelationPublicValueCursor(
    const OuterRelationR1csAssignmentView &assignment,
    std::uint64_t begin, std::uint64_t end)
    : assignment_(&assignment), cursor_(begin), end_(end) {
    if (begin > end ||
        end > assignment.plan().variables.public_inputs.total) {
        throw std::out_of_range(
            "outer public cursor range is invalid");
    }
}

bool OuterRelationPublicValueCursor::empty() const {
    return cursor_ == end_;
}

std::uint64_t OuterRelationPublicValueCursor::position() const {
    return cursor_;
}

std::uint64_t OuterRelationPublicValueCursor::remaining() const {
    return end_ - cursor_;
}

OuterRelationPublicValue OuterRelationPublicValueCursor::next() {
    if (empty()) {
        throw std::out_of_range("outer public cursor is exhausted");
    }
    const std::uint64_t index = cursor_++;
    return OuterRelationPublicValue{
        .index = index,
        .family = public_family(assignment_->plan(), index),
        .value = assignment_->public_value(index),
    };
}

OuterRelationWitnessValueCursor::OuterRelationWitnessValueCursor(
    const OuterRelationR1csAssignmentView &assignment)
    : OuterRelationWitnessValueCursor(
          assignment, 0, assignment.plan().variables.witness.total) {}

OuterRelationWitnessValueCursor::OuterRelationWitnessValueCursor(
    const OuterRelationR1csAssignmentView &assignment,
    std::uint64_t begin, std::uint64_t end)
    : assignment_(&assignment), cursor_(begin), end_(end) {
    if (begin > end || end > assignment.plan().variables.witness.total) {
        throw std::out_of_range(
            "outer witness cursor range is invalid");
    }
}

bool OuterRelationWitnessValueCursor::empty() const {
    return cursor_ == end_;
}

std::uint64_t OuterRelationWitnessValueCursor::position() const {
    return cursor_;
}

std::uint64_t OuterRelationWitnessValueCursor::remaining() const {
    return end_ - cursor_;
}

void OuterRelationWitnessValueCursor::initialize_product_position() {
    const OuterRelationPlan &plan = assignment_->plan();
    const std::uint64_t local =
        cursor_ - plan.variables.witness.well_formedness_products.begin;
    const std::uint64_t coordinates_per_aligned =
        plan.coordinates_per_ciphertext();
    const std::uint64_t coordinates_per_test =
        plan.variables.witness.aligned_ciphertext_coordinates.count;
    product_test_ = as_size(local / coordinates_per_test,
                            "product cursor test");
    const std::uint64_t within_test = local % coordinates_per_test;
    product_aligned_ = as_size(
        within_test / coordinates_per_aligned,
        "product cursor aligned input");
    product_coordinate_ = as_size(
        within_test % coordinates_per_aligned,
        "product cursor coordinate");
    product_coefficient_ = assignment_->ternary_coefficient(
        product_test_, product_aligned_);
    product_ciphertext_ =
        &assignment_->aligned_ciphertext(product_aligned_);
    product_position_initialized_ = true;
}

std::uint64_t OuterRelationWitnessValueCursor::next_product_value() {
    if (!product_position_initialized_) {
        initialize_product_position();
    }
    const OuterRelationPlan &plan = assignment_->plan();
    const std::uint64_t input =
        product_ciphertext_->value(product_coordinate_);
    const std::uint64_t result =
        product_coefficient_ == 0
            ? 0
            : (product_coefficient_ == 1
                   ? input
                   : negate_mod(input, plan.shape.native_modulus));
    advance_product_position();
    return result;
}

void OuterRelationWitnessValueCursor::advance_product_position() {
    const OuterRelationPlan &plan = assignment_->plan();
    ++product_coordinate_;
    if (product_coordinate_ != plan.coordinates_per_ciphertext()) {
        return;
    }
    product_coordinate_ = 0;
    ++product_aligned_;
    if (product_aligned_ == plan.shape.aligned_ciphertexts) {
        product_aligned_ = 0;
        ++product_test_;
    }
    if (product_test_ < plan.shape.repetitions) {
        product_coefficient_ = assignment_->ternary_coefficient(
            product_test_, product_aligned_);
        product_ciphertext_ =
            &assignment_->aligned_ciphertext(product_aligned_);
    }
}

OuterRelationWitnessValue OuterRelationWitnessValueCursor::next() {
    if (empty()) {
        throw std::out_of_range("outer witness cursor is exhausted");
    }
    const std::uint64_t index = cursor_;
    const OuterRelationWitnessValueFamily family = witness_family(
        assignment_->plan(), index);
    const std::uint64_t value =
        family == OuterRelationWitnessValueFamily::WellFormednessProduct
            ? next_product_value()
            : assignment_->witness_value(index);
    ++cursor_;
    return OuterRelationWitnessValue{
        .index = index,
        .family = family,
        .value = value,
    };
}

} // namespace laminate::packing
