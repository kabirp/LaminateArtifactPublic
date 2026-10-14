/// @file tensor.cpp
/// @brief Dense natural-coordinate packing tensor construction.

#include "laminate/packing/outer_relation/tensor.hpp"
#include "laminate/field/serialization.hpp"

#include <bit>
#include <limits>
#include <stdexcept>
#include <string>
#include <utility>

namespace laminate::packing {
namespace {

std::uint64_t as_u64(std::size_t value, const char *label) {
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

std::size_t padded_owner_count(std::size_t live) {
    if (live == 0) {
        throw std::invalid_argument(
            "packing tensor needs at least one live owner");
    }
    constexpr std::size_t kMaximumPowerOfTwo =
        std::size_t{1} << (std::numeric_limits<std::size_t>::digits - 1U);
    if (live > kMaximumPowerOfTwo) {
        throw std::overflow_error("packing tensor owner padding overflows");
    }
    return std::bit_ceil(live);
}

PackingTensorDescriptor make_descriptor(
    std::size_t output, std::size_t live_owners, std::size_t ring_degree,
    std::size_t digit_count, std::size_t field_element_bytes) {
    if (!std::has_single_bit(ring_degree) || digit_count == 0 ||
        field_element_bytes == 0) {
        throw std::invalid_argument(
            "packing tensor geometry has invalid dimensions");
    }
    const std::size_t padded_owners = padded_owner_count(live_owners);
    const std::uint64_t degree = as_u64(ring_degree, "packing tensor degree");
    const std::uint64_t digits = as_u64(digit_count, "packing tensor digits");
    const std::uint64_t live = as_u64(live_owners, "packing tensor owners");
    const std::uint64_t padded =
        as_u64(padded_owners, "padded packing tensor owners");
    const std::uint64_t element_bytes =
        as_u64(field_element_bytes, "packing tensor element bytes");
    const std::uint64_t live_elements = checked_mul(
        checked_mul(live, degree, "live packing tensor elements"), digits,
        "live packing tensor elements");
    const std::uint64_t padded_elements = checked_mul(
        checked_mul(padded, degree, "padded packing tensor elements"), digits,
        "padded packing tensor elements");
    return PackingTensorDescriptor{
        .logical_output = output,
        .live_owner_count = live_owners,
        .padded_owner_count = padded_owners,
        .ring_degree = ring_degree,
        .digit_count = digit_count,
        .field_element_bytes = element_bytes,
        .live_elements = live_elements,
        .padded_elements = padded_elements,
        .live_bytes = checked_mul(live_elements, element_bytes,
                                  "live packing tensor bytes"),
        .padded_bytes = checked_mul(padded_elements, element_bytes,
                                    "padded packing tensor bytes"),
    };
}

std::size_t column_length(const PackingTensorDescriptor &descriptor) {
    if (descriptor.padded_owner_count != 0 &&
        descriptor.ring_degree >
            std::numeric_limits<std::size_t>::max() /
                descriptor.padded_owner_count) {
        throw std::overflow_error("packing tensor column length overflows");
    }
    return descriptor.padded_owner_count * descriptor.ring_degree;
}

} // namespace

PackingTensorGeometry packing_tensor_geometry(
    std::span<const std::size_t> owner_counts, std::size_t ring_degree,
    std::size_t digit_count, std::size_t field_element_bytes) {
    if (owner_counts.empty()) {
        throw std::invalid_argument("packing tensor geometry has no outputs");
    }

    PackingTensorGeometry result;
    result.outputs.reserve(owner_counts.size());
    for (std::size_t output = 0; output < owner_counts.size(); ++output) {
        PackingTensorDescriptor descriptor = make_descriptor(
            output, owner_counts[output], ring_degree, digit_count,
            field_element_bytes);
        result.total_live_elements = checked_add(
            result.total_live_elements, descriptor.live_elements,
            "total live packing tensor elements");
        result.total_padded_elements = checked_add(
            result.total_padded_elements, descriptor.padded_elements,
            "total padded packing tensor elements");
        result.total_live_bytes = checked_add(
            result.total_live_bytes, descriptor.live_bytes,
            "total live packing tensor bytes");
        result.total_padded_bytes = checked_add(
            result.total_padded_bytes, descriptor.padded_bytes,
            "total padded packing tensor bytes");
        result.outputs.push_back(descriptor);
    }
    return result;
}

std::vector<PackingTensorMapping> packing_tensor_mappings(
    const PackingLinearOperator &packing_operator,
    std::size_t digit_count,
    std::size_t field_element_bytes) {
    packing_operator.validate();
    std::vector<std::size_t> owner_counts;
    owner_counts.reserve(packing_operator.rows.size());
    for (const PackingLinearOperator::OutputRow &row :
         packing_operator.rows) {
        owner_counts.push_back(row.contributions.size());
    }
    const PackingTensorGeometry geometry = packing_tensor_geometry(
        owner_counts, packing_operator.slot_count, digit_count,
        field_element_bytes);

    std::vector<PackingTensorMapping> result;
    result.reserve(packing_operator.rows.size());
    for (std::size_t output = 0; output < packing_operator.rows.size();
         ++output) {
        std::vector<std::size_t> owners;
        owners.reserve(packing_operator.rows[output].contributions.size());
        for (const PackingLinearOperator::AlignedCiphertext &contribution :
             packing_operator.rows[output].contributions) {
            owners.push_back(contribution.aligned_index);
        }
        result.push_back(PackingTensorMapping{
            .descriptor = geometry.outputs[output],
            .global_owners = std::move(owners),
        });
    }
    return result;
}

std::vector<PackingTensor> compile_packing_tensors(
    const OuterRelationPlan &plan,
    const NativePackingOperator &packing_operator) {
    packing_operator.validate(plan);
    if (!std::has_single_bit(plan.shape.ring_degree)) {
        throw std::invalid_argument(
            "packing tensor ring degree is not a power of two");
    }

    const std::size_t outputs = packing_operator.logical_outputs;
    const std::size_t digits = packing_operator.digit_count;
    std::vector<std::size_t> owner_counts(outputs, 0);
    for (std::size_t output = 0; output < outputs; ++output) {
        owner_counts[output] =
            packing_operator.rows[output * digits].contributions.size();
    }
    const PackingTensorGeometry geometry = packing_tensor_geometry(
        owner_counts, packing_operator.ring_degree, digits,
        kSerializedFqBytes);

    std::vector<PackingTensor> result;
    result.reserve(outputs);
    for (std::size_t output = 0; output < outputs; ++output) {
        const NativePackingRow &first =
            packing_operator.rows[output * digits];
        PackingTensor tensor;
        tensor.descriptor = geometry.outputs[output];
        tensor.global_owners.reserve(first.contributions.size());
        for (const NativePackingContribution &contribution :
             first.contributions) {
            tensor.global_owners.push_back(
                contribution.aligned_ciphertext);
        }

        const std::size_t length = column_length(tensor.descriptor);
        tensor.digit_columns.assign(
            digits, std::vector<Fq>(length, Fq::zero()));
        for (std::size_t digit = 0; digit < digits; ++digit) {
            const NativePackingRow &row =
                packing_operator.rows[output * digits + digit];
            if (row.logical_output != output || row.digit != digit ||
                row.contributions.size() != tensor.global_owners.size()) {
                throw std::invalid_argument(
                    "packing tensor digit row has inconsistent owners");
            }
            for (std::size_t local_owner = 0;
                 local_owner < row.contributions.size(); ++local_owner) {
                const NativePackingContribution &contribution =
                    row.contributions[local_owner];
                if (contribution.aligned_ciphertext !=
                        tensor.global_owners[local_owner] ||
                    contribution.multiplier_ntt_coordinates.size() !=
                        tensor.descriptor.ring_degree) {
                    throw std::invalid_argument(
                        "packing tensor digit row has inconsistent owners");
                }
                for (std::size_t coordinate = 0;
                     coordinate < tensor.descriptor.ring_degree;
                     ++coordinate) {
                    const std::uint64_t coefficient =
                        contribution.multiplier_ntt_coordinates[coordinate];
                    if (coefficient >= plan.shape.native_modulus) {
                        throw std::invalid_argument(
                            "packing tensor coefficient is not canonical");
                    }
                    const std::size_t index =
                        local_owner * tensor.descriptor.ring_degree +
                        coordinate;
                    tensor.digit_columns[digit][index] = Fq(coefficient);
                }
            }
        }
        result.push_back(std::move(tensor));
    }
    return result;
}

} // namespace laminate::packing
