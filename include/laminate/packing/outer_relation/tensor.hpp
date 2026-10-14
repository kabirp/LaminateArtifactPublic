#ifndef LAMINATE_PACKING_OUTER_RELATION_TENSOR_HPP
#define LAMINATE_PACKING_OUTER_RELATION_TENSOR_HPP

/// @file tensor.hpp
/// @brief Dense natural-coordinate tensors for fixed packing coefficients.

#include "laminate/field/fq.hpp"
#include "laminate/field/serialization.hpp"
#include "laminate/packing/outer_relation/relation.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace laminate::packing {

/// Shape and payload size of one logical output's packing tensor.
///
/// The payload consists of `digit_count` columns. Each column is indexed by
/// `[local owner | NTT coordinate]`, with the NTT coordinate in the least
/// significant `log2(ring_degree)` bits. Byte counts cover field-element
/// payloads only; container metadata and commitment state are excluded.
struct PackingTensorDescriptor {
    std::size_t logical_output = 0;
    std::size_t live_owner_count = 0;
    std::size_t padded_owner_count = 0;
    std::size_t ring_degree = 0;
    std::size_t digit_count = 0;
    std::uint64_t field_element_bytes = 0;
    std::uint64_t live_elements = 0;
    std::uint64_t padded_elements = 0;
    std::uint64_t live_bytes = 0;
    std::uint64_t padded_bytes = 0;

    bool operator==(const PackingTensorDescriptor &) const = default;
};

/// Allocation-free geometry for every logical packing output.
struct PackingTensorGeometry {
    std::vector<PackingTensorDescriptor> outputs;
    std::uint64_t total_live_elements = 0;
    std::uint64_t total_padded_elements = 0;
    std::uint64_t total_live_bytes = 0;
    std::uint64_t total_padded_bytes = 0;

    bool operator==(const PackingTensorGeometry &) const = default;
};

/// Geometry plus the canonical aligned-ciphertext owners of one tensor.
///
/// This is the complete coefficient-free description needed by the compact
/// factored matrix structure.  The coefficient columns themselves belong to
/// the setup-committed tensor artifact and are deliberately absent here.
struct PackingTensorMapping {
    PackingTensorDescriptor descriptor;
    std::vector<std::size_t> global_owners;

    bool operator==(const PackingTensorMapping &) const = default;
};

/// Derive tensor shapes from owner counts without materializing coefficients.
///
/// `field_element_bytes` is explicit so formula-only target accounting does
/// not depend on an in-memory field representation. Every owner count must be
/// positive, and `ring_degree` must be a power of two.
PackingTensorGeometry packing_tensor_geometry(
    std::span<const std::size_t> owner_counts, std::size_t ring_degree,
    std::size_t digit_count, std::size_t field_element_bytes);

/// Derive every tensor descriptor and owner list from the public packing map.
/// No plaintext encoding, NTT, native packing operator, or coefficient tensor
/// is constructed.
std::vector<PackingTensorMapping> packing_tensor_mappings(
    const PackingLinearOperator &packing_operator,
    std::size_t digit_count,
    std::size_t field_element_bytes = kSerializedFqBytes);

/// One materialized logical-output tensor.
struct PackingTensor {
    PackingTensorDescriptor descriptor;
    /// Global aligned-ciphertext indices in the digit-zero contribution order.
    std::vector<std::size_t> global_owners;
    /// One column per digit, each of length `padded_owner_count * ring_degree`.
    std::vector<std::vector<Fq>> digit_columns;
};

/// Validate and materialize the fixed coefficient tensors.
///
/// The operator must match `plan`. For each logical output, every digit row
/// must contain exactly the digit-zero owner sequence and canonical native
/// residues. Owners beyond the live sequence are represented by zero padding.
std::vector<PackingTensor> compile_packing_tensors(
    const OuterRelationPlan &plan,
    const NativePackingOperator &packing_operator);

} // namespace laminate::packing

#endif // LAMINATE_PACKING_OUTER_RELATION_TENSOR_HPP
