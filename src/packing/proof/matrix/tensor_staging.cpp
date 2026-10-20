/// @file tensor_staging.cpp
/// @brief Bounded construction of fixed packing-coefficient tensors.

#include "laminate/packing/proof/matrix/tensor_staging.hpp"

#include "laminate/field/serialization.hpp"

#include <algorithm>
#include <limits>
#include <span>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace laminate::packing {
namespace {

std::uint64_t as_u64(std::size_t value, const char *label) {
    if constexpr (sizeof(std::size_t) > sizeof(std::uint64_t)) {
        if (value > std::numeric_limits<std::uint64_t>::max()) {
            throw std::overflow_error(std::string(label) + " exceeds u64");
        }
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

std::uint64_t checked_sub(std::uint64_t left, std::uint64_t right,
                          const char *label) {
    if (right > left) {
        throw std::overflow_error(std::string(label) + " underflows u64");
    }
    return left - right;
}

std::uint64_t checked_mul(std::uint64_t left, std::uint64_t right,
                          const char *label) {
    if (left != 0 &&
        right > std::numeric_limits<std::uint64_t>::max() / left) {
        throw std::overflow_error(std::string(label) + " overflows u64");
    }
    return left * right;
}

std::uint64_t ceil_div(std::uint64_t value, std::uint64_t divisor,
                       const char *label) {
    if (divisor == 0) {
        throw std::invalid_argument(std::string(label) +
                                    " has zero divisor");
    }
    return value / divisor + (value % divisor == 0 ? 0 : 1);
}

bool same_contribution(
    const PackingLinearOperator::AlignedCiphertext &left,
    const PackingLinearOperator::AlignedCiphertext &right) {
    return left.aligned_index == right.aligned_index &&
           left.source_index == right.source_index &&
           left.slot_pattern == right.slot_pattern &&
           left.source_begin == right.source_begin &&
           left.rotation_steps == right.rotation_steps &&
           left.destination_begin == right.destination_begin &&
           left.length == right.length;
}

bool same_operator(const PackingLinearOperator &left,
                   const PackingLinearOperator &right) {
    if (left.slot_count != right.slot_count ||
        left.source_ciphertext_count != right.source_ciphertext_count ||
        left.aligned_ciphertext_count != right.aligned_ciphertext_count ||
        left.rows.size() != right.rows.size()) {
        return false;
    }
    for (std::size_t output = 0; output < left.rows.size(); ++output) {
        const auto &left_row = left.rows[output];
        const auto &right_row = right.rows[output];
        if (left_row.output_index != right_row.output_index ||
            left_row.contributions.size() !=
                right_row.contributions.size()) {
            return false;
        }
        for (std::size_t contribution = 0;
             contribution < left_row.contributions.size(); ++contribution) {
            if (!same_contribution(left_row.contributions[contribution],
                                   right_row.contributions[contribution])) {
                return false;
            }
        }
    }
    return true;
}

std::vector<const PackingLinearOperator::AlignedCiphertext *>
sorted_contributions(const PackingLinearOperator::OutputRow &row) {
    std::vector<const PackingLinearOperator::AlignedCiphertext *> result;
    result.reserve(row.contributions.size());
    for (const auto &contribution : row.contributions) {
        result.push_back(&contribution);
    }
    std::sort(result.begin(), result.end(), [](const auto *left,
                                                const auto *right) {
        return left->aligned_index < right->aligned_index;
    });
    return result;
}

std::vector<storage::NativeFieldArrayLayout> staging_array_layouts(
    const ProofOfPackingStructuredMetadata &metadata) {
    std::vector<storage::NativeFieldArrayLayout> result;
    for (std::size_t tensor = 0;
         tensor < metadata.tensor_mappings.size(); ++tensor) {
        const PackingTensorDescriptor &descriptor =
            metadata.tensor_mappings[tensor].descriptor;
        const std::uint64_t column_elements = checked_mul(
            as_u64(descriptor.padded_owner_count, "padded owner count"),
            as_u64(descriptor.ring_degree, "ring degree"),
            "tensor column elements");
        for (std::size_t digit = 0; digit < descriptor.digit_count; ++digit) {
            result.push_back(storage::NativeFieldArrayLayout{
                .name = spartan::factored_matrix_tensor_column_array_name(
                    tensor, digit),
                .kind = storage::NativeFieldElementKind::Fq,
                .element_count = column_elements,
            });
        }
    }
    return result;
}

void validate_inputs(const ProofOfPackingStructuredMetadata &metadata,
                     const PackingLinearOperator &packing_operator,
                     const BalancedRadix &radix) {
    metadata.validate();
    packing_operator.validate();
    radix.validate();
    if (!same_operator(metadata.packing_operator, packing_operator) ||
        metadata.parameters.packing_radix != radix ||
        metadata.relation_plan.shape.native_modulus != kOuterFieldOrder ||
        metadata.relation_plan.shape.ring_degree !=
            packing_operator.slot_count ||
        metadata.relation_plan.shape.logical_packed_outputs !=
            packing_operator.rows.size() ||
        metadata.relation_plan.shape.packing_digit_count !=
            radix.digit_count ||
        metadata.tensor_mappings.size() != packing_operator.rows.size()) {
        throw std::invalid_argument(
            "packing tensor staging inputs do not describe one relation");
    }

    for (std::size_t output = 0; output < packing_operator.rows.size();
         ++output) {
        const auto contributions =
            sorted_contributions(packing_operator.rows[output]);
        const PackingTensorMapping &mapping =
            metadata.tensor_mappings[output];
        if (mapping.descriptor != metadata.tensor_geometry.outputs[output] ||
            mapping.descriptor.logical_output != output ||
            mapping.descriptor.live_owner_count != contributions.size() ||
            mapping.descriptor.ring_degree != packing_operator.slot_count ||
            mapping.descriptor.digit_count != radix.digit_count ||
            mapping.descriptor.field_element_bytes != kSerializedFqBytes ||
            mapping.global_owners.size() != contributions.size()) {
            throw std::invalid_argument(
                "packing tensor staging mapping is inconsistent");
        }
        for (std::size_t owner = 0; owner < contributions.size(); ++owner) {
            if (mapping.global_owners[owner] !=
                contributions[owner]->aligned_index) {
                throw std::invalid_argument(
                    "packing tensor staging owner order is noncanonical");
            }
        }
    }
}

std::shared_ptr<const spartan::FactoredMatrixStructure> make_structure(
    const ProofOfPackingStructuredMetadata &metadata) {
    return make_proof_of_packing_factored_structure(
        metadata.relation_plan, metadata.r1cs_layout,
        metadata.tensor_mappings, metadata.circuit_metadata);
}

void validate_destination(const std::filesystem::path &directory) {
    if (directory.empty() ||
        !std::filesystem::is_directory(
            std::filesystem::symlink_status(directory)) ||
        std::filesystem::directory_iterator(directory) !=
            std::filesystem::directory_iterator()) {
        throw std::invalid_argument(
            "packing tensor staging destination must be a real empty "
            "directory");
    }
}

class DestinationTransaction {
  public:
    explicit DestinationTransaction(std::filesystem::path directory)
        : directory_(std::move(directory)) {}

    ~DestinationTransaction() {
        if (!committed_) {
            std::error_code ignored;
            for (std::filesystem::directory_iterator iterator(
                     directory_, ignored), end;
                 !ignored && iterator != end; iterator.increment(ignored)) {
                std::filesystem::remove_all(iterator->path(), ignored);
                if (ignored) {
                    break;
                }
            }
        }
    }

    void commit() { committed_ = true; }

  private:
    std::filesystem::path directory_;
    bool committed_ = false;
};

SignedCoefficientMask selected_digit_mask(
    const PackingLinearOperator::AlignedCiphertext &contribution,
    std::size_t slot_count, std::size_t digit,
    const ProofOfPackingR1csEncoders &encoders,
    const BalancedRadix &radix) {
    SignedCoefficientMask centered;
    {
        const fhe::SlotVector mask = contribution.position_mask(slot_count);
        centered = encoders.centered_coefficients(mask);
        if (centered.size() != slot_count) {
            throw std::invalid_argument(
                "packing tensor staging centered encoder returned the "
                "wrong degree");
        }
    }

    std::vector<SignedCoefficientMask> digits =
        decompose_coefficient_mask(centered, radix);
    if (digits.size() != radix.digit_count ||
        std::any_of(digits.begin(), digits.end(),
                    [=](const SignedCoefficientMask &mask) {
                        return mask.size() != slot_count;
                    })) {
        throw std::logic_error(
            "packing tensor staging digit decomposition has the wrong "
            "shape");
    }
    return std::move(digits[digit]);
}

void append_native_polynomial(
    storage::NativeFieldArtifactWriter &writer,
    std::span<const std::uint64_t> native, std::uint64_t modulus,
    std::vector<Fq> &buffer, ProofOfPackingTensorStagingReport &report) {
    if (native.empty()) {
        throw std::invalid_argument(
            "packing tensor staging native polynomial is empty");
    }
    for (std::size_t begin = 0; begin < native.size();
         begin += buffer.size()) {
        const std::size_t count =
            std::min(buffer.size(), native.size() - begin);
        for (std::size_t index = 0; index < count; ++index) {
            const std::uint64_t coefficient = native[begin + index];
            if (coefficient >= modulus) {
                throw std::invalid_argument(
                    "packing tensor staging NTT encoder returned a "
                    "noncanonical residue");
            }
            buffer[index] = Fq(coefficient);
        }
        writer.append(std::span<const Fq>(buffer).first(count));
        report.live_coordinates_written = checked_add(
            report.live_coordinates_written, as_u64(count, "write count"),
            "live coordinates written");
        ++report.append_operations;
    }
}

void append_zeros(storage::NativeFieldArtifactWriter &writer,
                  std::uint64_t count, std::vector<Fq> &buffer,
                  ProofOfPackingTensorStagingReport &report) {
    std::fill(buffer.begin(), buffer.end(), Fq::zero());
    while (count != 0) {
        const std::size_t chunk = static_cast<std::size_t>(
            std::min<std::uint64_t>(count, buffer.size()));
        writer.append(std::span<const Fq>(buffer).first(chunk));
        count -= chunk;
        report.padded_zero_coordinates_written = checked_add(
            report.padded_zero_coordinates_written,
            as_u64(chunk, "padding write count"),
            "padded zero coordinates written");
        ++report.append_operations;
    }
}

} // namespace

ProofOfPackingTensorStagingPlan plan_proof_of_packing_tensor_staging(
    const ProofOfPackingStructuredMetadata &metadata,
    const PackingLinearOperator &packing_operator,
    const BalancedRadix &radix, std::size_t block_elements) {
    validate_inputs(metadata, packing_operator, radix);
    if (block_elements == 0) {
        throw std::invalid_argument(
            "packing tensor staging block size is zero");
    }

    ProofOfPackingTensorStagingPlan result;
    result.geometry = metadata.tensor_geometry;
    result.block_elements =
        std::min(block_elements, packing_operator.slot_count);
    const auto arrays = staging_array_layouts(metadata);
    result.array_count = as_u64(arrays.size(), "staging array count");
    result.artifact_payload_bytes = metadata.tensor_geometry.total_padded_bytes;
    result.artifact_physical_bytes =
        storage::native_field_artifact_physical_bytes(arrays);

    const std::uint64_t degree =
        as_u64(packing_operator.slot_count, "ring degree");
    const std::uint64_t digits = as_u64(radix.digit_count, "digit count");
    const std::uint64_t block =
        as_u64(result.block_elements, "staging block size");
    result.output_buffer_bytes = checked_mul(
        block, sizeof(Fq), "packing staging output buffer bytes");
    result.mask_and_centered_bytes = checked_mul(
        degree, sizeof(Fp) + sizeof(std::int64_t),
        "packing staging mask and centered bytes");
    result.centered_and_digit_masks_bytes = checked_mul(
        checked_mul(degree, sizeof(std::int64_t),
                    "packing staging centered coefficient bytes"),
        checked_add(digits, 1, "packing staging digit payloads"),
        "packing staging centered and digit bytes");
    result.selected_digit_and_native_bytes = checked_mul(
        degree, sizeof(std::int64_t) + sizeof(std::uint64_t),
        "packing staging digit and native bytes");
    result.peak_working_bytes = checked_add(
        result.output_buffer_bytes,
        std::max({result.mask_and_centered_bytes,
                  result.centered_and_digit_masks_bytes,
                  result.selected_digit_and_native_bytes}),
        "packing staging peak working bytes");

    result.live_coordinates = metadata.tensor_geometry.total_live_elements;
    result.padded_zero_coordinates = checked_sub(
        metadata.tensor_geometry.total_padded_elements,
        metadata.tensor_geometry.total_live_elements,
        "packing staging padded zero coordinates");
    const std::uint64_t owner_digit_pairs = checked_mul(
        as_u64(packing_operator.aligned_ciphertext_count,
               "aligned ciphertext count"),
        digits, "packing staging encoder invocations");
    result.encoder_invocations = owner_digit_pairs;
    result.append_operations = checked_mul(
        owner_digit_pairs, ceil_div(degree, block, "live append count"),
        "live append operations");
    for (const PackingTensorDescriptor &descriptor :
         metadata.tensor_geometry.outputs) {
        const std::uint64_t padded_owners = as_u64(
            descriptor.padded_owner_count, "padded owner count");
        const std::uint64_t live_owners =
            as_u64(descriptor.live_owner_count, "live owner count");
        const std::uint64_t padding = checked_mul(
            checked_sub(padded_owners, live_owners, "padding owner count"),
            degree, "padding coordinate count");
        result.append_operations = checked_add(
            result.append_operations,
            checked_mul(digits,
                        ceil_div(padding, block, "padding append count"),
                        "padding append operations"),
            "packing staging append operations");
    }
    return result;
}

ProofOfPackingTensorStaging write_proof_of_packing_tensor_staging(
    const ProofOfPackingStructuredMetadata &metadata,
    const PackingLinearOperator &packing_operator,
    ProofOfPackingR1csEncoders encoders, const BalancedRadix &radix,
    ProofOfPackingTensorStagingOptions options) {
    const ProofOfPackingTensorStagingPlan plan =
        plan_proof_of_packing_tensor_staging(
            metadata, packing_operator, radix, options.block_elements);
    if (!encoders.centered_coefficients || !encoders.native_ntt ||
        options.storage_limits.max_total_bytes <
            plan.artifact_physical_bytes ||
        options.storage_limits.min_free_bytes == 0 ||
        options.max_working_bytes < plan.peak_working_bytes) {
        throw std::invalid_argument(
            "packing tensor staging options fail preflight admission");
    }

    if (options.directory.empty()) {
        throw std::invalid_argument(
            "packing tensor staging destination path is empty");
    }
    options.directory =
        std::filesystem::absolute(options.directory).lexically_normal();
    validate_destination(options.directory);
    const std::uint64_t required_free = checked_add(
        plan.artifact_physical_bytes,
        options.storage_limits.min_free_bytes,
        "packing tensor staging free-space requirement");
    if (std::filesystem::space(options.directory).available < required_free) {
        throw std::runtime_error(
            "packing tensor staging free-space admission failed");
    }

    std::shared_ptr<const spartan::FactoredMatrixStructure> structure =
        make_structure(metadata);
    if (structure->tensor_count() != metadata.tensor_mappings.size()) {
        throw std::logic_error(
            "packing tensor staging structure has wrong tensor count");
    }
    for (std::size_t tensor = 0; tensor < structure->tensor_count(); ++tensor) {
        const spartan::FactoredTensorShape shape =
            structure->tensor_shape(tensor);
        const PackingTensorDescriptor &descriptor =
            metadata.tensor_mappings[tensor].descriptor;
        if (shape.column_count != descriptor.digit_count ||
            shape.evaluation_count !=
                descriptor.padded_owner_count * descriptor.ring_degree) {
            throw std::logic_error(
                "packing tensor staging structure has wrong shape");
        }
    }

    DestinationTransaction transaction(options.directory);
    storage::NativeFieldArtifactWriter writer(
        options.directory, options.storage_limits,
        spartan::factored_matrix_staging_artifact_identity(*structure));
    ProofOfPackingTensorStagingReport report{.plan = plan};
    std::vector<Fq> buffer(plan.block_elements, Fq::zero());

    for (std::size_t output = 0; output < packing_operator.rows.size();
         ++output) {
        const auto contributions =
            sorted_contributions(packing_operator.rows[output]);
        const PackingTensorDescriptor &descriptor =
            metadata.tensor_mappings[output].descriptor;
        const std::uint64_t column_elements = checked_mul(
            as_u64(descriptor.padded_owner_count, "padded owner count"),
            as_u64(descriptor.ring_degree, "ring degree"),
            "tensor column elements");
        for (std::size_t digit = 0; digit < radix.digit_count; ++digit) {
            writer.begin_array(
                spartan::factored_matrix_tensor_column_array_name(output,
                                                                    digit),
                storage::NativeFieldElementKind::Fq, column_elements);
            for (const auto *contribution : contributions) {
                SignedCoefficientMask digit_mask = selected_digit_mask(
                    *contribution, packing_operator.slot_count, digit,
                    encoders, radix);
                ++report.centered_masks_encoded;
                ++report.signed_digit_masks_derived;
                std::vector<std::uint64_t> native =
                    encoders.native_ntt(digit_mask);
                ++report.native_digit_polynomials_encoded;
                if (native.size() != packing_operator.slot_count) {
                    throw std::invalid_argument(
                        "packing tensor staging NTT encoder returned the "
                        "wrong degree");
                }
                append_native_polynomial(
                    writer, native, metadata.relation_plan.shape.native_modulus,
                    buffer, report);
            }
            const std::uint64_t padding = checked_mul(
                checked_sub(
                    as_u64(descriptor.padded_owner_count,
                           "padded owner count"),
                    as_u64(descriptor.live_owner_count, "live owner count"),
                    "padding owner count"),
                as_u64(descriptor.ring_degree, "ring degree"),
                "padding coordinate count");
            append_zeros(writer, padding, buffer, report);
            writer.finish_array();
        }
    }

    const storage::NativeFieldArtifactWriteResult write_result =
        writer.finish();
    if (report.centered_masks_encoded != plan.encoder_invocations ||
        report.signed_digit_masks_derived != plan.encoder_invocations ||
        report.native_digit_polynomials_encoded !=
            plan.encoder_invocations ||
        report.live_coordinates_written != plan.live_coordinates ||
        report.padded_zero_coordinates_written !=
            plan.padded_zero_coordinates ||
        report.append_operations != plan.append_operations ||
        write_result.physical_bytes != plan.artifact_physical_bytes) {
        throw std::logic_error(
            "packing tensor staging report differs from preflight plan");
    }

    std::shared_ptr<const storage::NativeFieldArtifact> artifact =
        spartan::open_factored_matrix_staging_artifact(
            options.directory, *structure);
    report.artifact_physical_bytes = artifact->physical_bytes();
    report.artifact_validation_bytes = artifact->physical_bytes();
    if (report.artifact_physical_bytes != plan.artifact_physical_bytes) {
        throw std::logic_error(
            "packing tensor staging reopened size differs from plan");
    }

    transaction.commit();
    return ProofOfPackingTensorStaging{
        .structure = std::move(structure),
        .artifact = std::move(artifact),
        .report = std::move(report),
    };
}

} // namespace laminate::packing
