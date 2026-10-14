#ifndef LAMINATE_GKR_DETAIL_SHARED_DENSE_MULTIPLICATION_SOURCE_RESOURCE_BOUNDS_HPP
#define LAMINATE_GKR_DETAIL_SHARED_DENSE_MULTIPLICATION_SOURCE_RESOURCE_BOUNDS_HPP

#include "laminate/gkr/detail/shared/dense_multiplication/source/plan.hpp"
#include "laminate/field/fpk.hpp"
#include "laminate/gkr/detail/shared/dense_multiplication/source/disk_bounds.hpp"

#include <algorithm>
#include <cstdint>
#include <limits>
#include <stdexcept>

namespace laminate::gkr::detail {

inline constexpr std::size_t kDenseMultiplicationReaderCacheValues = 64;

inline std::uint64_t dense_resource_add(std::uint64_t a, std::uint64_t b) {
    if (b > std::numeric_limits<std::uint64_t>::max() - a)
        throw std::overflow_error("dense multiplication resource sum overflows");
    return a + b;
}
inline std::uint64_t dense_resource_multiply(std::uint64_t a, std::uint64_t b) {
    if (a != 0 && b > std::numeric_limits<std::uint64_t>::max() / a)
        throw std::overflow_error("dense multiplication resource product overflows");
    return a * b;
}

/// Public maps, signature vectors, and bounded-reader bookkeeping. Include
/// two alias-plan copies (the admitted source and its active reader), vector
/// capacity/allocator slack, and the builder's ordinal-to-output map. The
/// per-operand reader allowance includes cache pointers and scan coverage bits.
inline std::uint64_t dense_multiplication_metadata_ram_bound(
    std::uint64_t pair_count, std::uint64_t operand_count,
    std::uint64_t signature_entries, std::uint64_t stored_value_count) {
    const auto pairs = dense_resource_multiply(pair_count, 3U * sizeof(std::size_t));
    const auto operands = dense_resource_multiply(operand_count,
        3U * sizeof(std::size_t) + sizeof(DenseMultiplicationOperandSignature));
    const auto signatures = dense_resource_multiply(signature_entries,
        sizeof(std::optional<std::size_t>));
    const auto maps = dense_resource_multiply(
        std::max(stored_value_count, dense_resource_multiply(pair_count, 2U)),
        sizeof(std::size_t));
    return dense_resource_add(dense_resource_multiply(
        dense_resource_add(dense_resource_add(pairs, operands), signatures), 4U),
        dense_resource_add(maps, dense_resource_multiply(operand_count, 32U)));
}

/// Sort payload storage is charged separately. Source decoding, chunk
/// multiplication/rotation, and its accumulator have constant residency.
/// Merge readers may each retain twice their largest record allocation.
/// resident_value_bytes must cover both a decoded value and its tagged
/// serialized record; callers with a larger encoding pass that larger bound.
inline std::uint64_t dense_multiplication_builder_ram_bound(
    std::uint64_t pair_count, std::uint64_t operand_count,
    std::uint64_t signature_entries, std::uint64_t stored_value_count,
    std::uint64_t resident_value_bytes) {
    return dense_resource_add(dense_multiplication_metadata_ram_bound(
        pair_count, operand_count, signature_entries, stored_value_count),
        dense_resource_multiply(resident_value_bytes,
            2U * kDenseMultiplicationSortMergeFanIn + 4U));
}

inline std::uint64_t dense_multiplication_signature_entries(
    const DenseMultiplicationAliasPlan &aliases) {
    std::uint64_t result = 0;
    for (const auto &operand : aliases.operands)
        result = dense_resource_add(result, operand.stored_ordinals.size());
    return result;
}
inline std::uint64_t dense_multiplication_builder_workspace_bytes(
    const DenseMultiplicationAliasPlan &aliases, std::uint64_t resident_value_bytes,
    std::size_t stored_value_count = 0) {
    return dense_multiplication_builder_ram_bound(aliases.pair_count,
        aliases.operands.size(), dense_multiplication_signature_entries(aliases),
        stored_value_count, resident_value_bytes);
}

/// The random alias handle retains one framed-record buffer and never submits
/// sequential prefetch. Charge retained vector capacity plus the replacement
/// allocation during growth. The input bound must cover the tagged record.
inline std::uint64_t dense_multiplication_alias_reader_ram_bound(
    std::uint64_t maximum_tagged_record_bytes) {
    return dense_resource_multiply(
        dense_resource_add(maximum_tagged_record_bytes, sizeof(std::uint64_t)),
        3U);
}

inline std::uint64_t dense_multiplication_reduction_workspace_bytes(
    const DenseMultiplicationAliasPlan &aliases, std::uint64_t resident_value_bytes,
    std::size_t output_domain) {
    const auto reused = static_cast<std::size_t>(std::count_if(
        aliases.operand_occurrences.begin(), aliases.operand_occurrences.end(),
        [](std::size_t count) { return count > 1U; }));
    // The alias handle reads one framed record without a sequential transfer
    // slab or prefetch window. As for builder buffers, resident_value_bytes
    // must cover the tagged encoding. Include framing and simultaneous source
    // and destination allocations during growth, plus the decoded operand cache.
    const auto alias_buffer = reused == 0U ? 0U :
        dense_multiplication_alias_reader_ram_bound(resident_value_bytes);
    return dense_resource_add(alias_buffer, dense_resource_add(dense_resource_add(
        dense_multiplication_metadata_ram_bound(aliases.pair_count,
            aliases.operands.size(), dense_multiplication_signature_entries(aliases), 0),
        dense_resource_multiply(resident_value_bytes,
            std::min(reused, kDenseMultiplicationReaderCacheValues) + 4U)),
        dense_resource_multiply(output_domain, sizeof(Fpk))));
}

} // namespace laminate::gkr::detail
#endif
