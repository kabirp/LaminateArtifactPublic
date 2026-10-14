#ifndef LAMINATE_GKR_DETAIL_SHARED_DENSE_MULTIPLICATION_SOURCE_PAIRED_HPP
#define LAMINATE_GKR_DETAIL_SHARED_DENSE_MULTIPLICATION_SOURCE_PAIRED_HPP

/// @file paired.hpp
/// @brief Compact setup metadata for canonical dense multiplication sources.

#include "laminate/payload/trace/trace_wire_support.hpp"

#include <cstddef>
#include <limits>
#include <optional>
#include <stdexcept>
#include <unordered_map>
#include <utility>
#include <vector>

namespace laminate::gkr::detail {

/// A half-open run of multiplication-output indices that share one stored
/// operand pair. Consumers can sum equality weights over these runs without
/// expanding an alias-backed source layer.
struct DensePairedLogicalRange {
    std::size_t begin = 0;
    std::size_t end = 0;

    std::size_t size() const { return end - begin; }

    bool operator==(const DensePairedLogicalRange &) const = default;
};

/// All logical multiplication positions backed by one unique pair of stored
/// source values. Groups appear in the order in which their pair first occurs.
struct DensePairedSourceGroup {
    std::size_t stored_left = 0;
    std::size_t stored_right = 0;
    std::vector<std::size_t> logical_indices;
    std::vector<DensePairedLogicalRange> logical_ranges;

    std::size_t logical_pair_count() const { return logical_indices.size(); }
};

/// Exact public sizes of one dense paired-source plan.
struct DensePairedSourceCounts {
    std::size_t logical_pairs = 0;
    std::size_t active_logical_pairs = 0;
    std::size_t omitted_public_padding_pairs = 0;
    std::size_t unique_stored_pairs = 0;
    std::size_t logical_index_entries = 0;
    std::size_t logical_ranges = 0;

    bool operator==(const DensePairedSourceCounts &) const = default;
};

/// Challenge-independent setup metadata for
///
///   output[i] = source[i] * source[M+i],  0 <= i < M.
///
/// The plan owns public indices only. It neither reads nor retains FHE values.
struct DensePairedSourceMetadata {
    std::size_t pair_count = 0;
    std::size_t source_padded_size = 0;
    std::vector<DensePairedSourceGroup> groups;
    DensePairedSourceCounts counts;
};

namespace dense_paired_source_detail {

struct StoredPair {
    std::size_t left = 0;
    std::size_t right = 0;

    bool operator==(const StoredPair &) const = default;
};

struct StoredPairHash {
    std::size_t operator()(const StoredPair &pair) const noexcept {
        const std::size_t mixed = pair.right +
                                  std::size_t{0x9e3779b97f4a7c15ULL} +
                                  (pair.left << 6U) + (pair.left >> 2U);
        return pair.left ^ mixed;
    }
};

inline void append_logical_index(DensePairedSourceGroup &group,
                                 std::size_t logical_index) {
    group.logical_indices.push_back(logical_index);
    if (!group.logical_ranges.empty() &&
        group.logical_ranges.back().end == logical_index) {
        ++group.logical_ranges.back().end;
        return;
    }
    group.logical_ranges.push_back(
        DensePairedLogicalRange{logical_index, logical_index + 1U});
}

} // namespace dense_paired_source_detail

/// Group a canonical multiplication layer by the stored values named by its
/// two operand halves. The scan is O(M) expected time and O(M) public memory.
/// Hash-table iteration order is never observed: group order is deterministic
/// first occurrence, and logical indices inside each group are increasing.
inline DensePairedSourceMetadata make_dense_paired_source_metadata(
    const payload::MultiplicationLayer &multiplication,
    std::size_t source_padded_size,
    const payload::LayerStorageLayout &source_storage) {
    const std::size_t pair_count = multiplication.dimensions.padded_size;
    payload::validate_layer_storage_layout(source_storage);
    if (pair_count == 0 || multiplication.gates.size() != pair_count ||
        pair_count > std::numeric_limits<std::size_t>::max() / 2U ||
        source_padded_size != 2U * pair_count ||
        source_storage.padded_wire_count != source_padded_size) {
        throw std::invalid_argument(
            "dense paired source has inconsistent layer dimensions");
    }

    DensePairedSourceMetadata result;
    result.pair_count = pair_count;
    result.source_padded_size = source_padded_size;
    result.counts.logical_pairs = pair_count;
    result.groups.reserve(pair_count);

    using dense_paired_source_detail::StoredPair;
    using dense_paired_source_detail::StoredPairHash;
    std::unordered_map<StoredPair, std::size_t, StoredPairHash> group_for;
    group_for.reserve(pair_count);

    for (std::size_t logical = 0; logical < pair_count; ++logical) {
        const payload::MultiplicationGate &gate =
            multiplication.gates[logical];
        if (gate.origin == payload::GateOrigin::Padding) {
            ++result.counts.omitted_public_padding_pairs;
            continue;
        }

        const std::optional<std::size_t> stored_left =
            source_storage.stored_ordinal_of(logical);
        const std::optional<std::size_t> stored_right =
            source_storage.stored_ordinal_of(pair_count + logical);
        if (!stored_left || !stored_right) {
            throw std::invalid_argument(
                "dense paired source omits a non-padding operand");
        }

        const StoredPair pair{*stored_left, *stored_right};
        auto [entry, inserted] = group_for.emplace(pair, result.groups.size());
        if (inserted) {
            result.groups.push_back(DensePairedSourceGroup{
                .stored_left = pair.left,
                .stored_right = pair.right});
        }
        dense_paired_source_detail::append_logical_index(
            result.groups[entry->second], logical);
        ++result.counts.active_logical_pairs;
    }

    result.counts.unique_stored_pairs = result.groups.size();
    for (const DensePairedSourceGroup &group : result.groups) {
        result.counts.logical_index_entries += group.logical_indices.size();
        result.counts.logical_ranges += group.logical_ranges.size();
    }
    return result;
}

/// Circuit-indexed convenience overload used by setup code.
inline DensePairedSourceMetadata make_dense_paired_source_metadata(
    const payload::LayeredCircuit &circuit, std::size_t reduction_layer,
    const payload::LayerStorageLayout &source_storage) {
    if (reduction_layer + 1U >= circuit.layers.size() ||
        !std::holds_alternative<payload::MultiplicationLayer>(
            circuit.layers[reduction_layer])) {
        throw std::invalid_argument(
            "dense paired source does not name a multiplication reduction");
    }
    payload::validate_layer_storage_layout(
        circuit, reduction_layer + 1U, source_storage);
    return make_dense_paired_source_metadata(
        std::get<payload::MultiplicationLayer>(
            circuit.layers[reduction_layer]),
        payload::layer_dimensions(circuit.layers[reduction_layer + 1U])
            .padded_size,
        source_storage);
}

} // namespace laminate::gkr::detail

#endif // LAMINATE_GKR_DETAIL_SHARED_DENSE_MULTIPLICATION_SOURCE_PAIRED_HPP
