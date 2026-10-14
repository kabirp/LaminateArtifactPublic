#ifndef LAMINATE_GKR_DETAIL_SHARED_DENSE_MULTIPLICATION_SOURCE_DESCRIPTOR_HPP
#define LAMINATE_GKR_DETAIL_SHARED_DENSE_MULTIPLICATION_SOURCE_DESCRIPTOR_HPP

/// @file descriptor.hpp
/// @brief Identity, storage geometry, and measurement types for a dense
/// multiplication source.

#include "laminate/packing/alignment/laned.hpp"
#include "laminate/payload/storage/file_trace_store.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <limits>
#include <stdexcept>
#include <string>

namespace laminate::gkr::detail {

/// Storage geometry used by the shared dense-multiplication artifact. Laned
/// sources pack `N/B` trace ciphertexts into one protocol ciphertext. Wide
/// sources already occupy all N slots, so one stored wire is one protocol
/// ciphertext and no packing level is consumed.
inline packing::LanedPackingLayout dense_multiplication_storage_layout(
    const payload::LayeredCircuit &circuit, std::size_t layer) {
    if (layer >= circuit.layers.size()) {
        throw std::out_of_range(
            "dense multiplication storage layer is out of range");
    }
    if (circuit.shape.kind == payload::PayloadKind::Laned) {
        return packing::LanedPackingLayout::create(
            circuit.shape,
            payload::layer_dimensions(circuit.layers[layer]).padded_size);
    }
    circuit.shape.validate();
    const std::size_t wires =
        payload::layer_dimensions(circuit.layers[layer]).padded_size;
    return packing::LanedPackingLayout{
        circuit.shape.slot_count, circuit.shape.slot_count, wires, wires,
        wires};
}

template <fhe::FheBackend Backend>
void validate_dense_artifact_ingress_ciphertext(
    const typename Backend::EvalContext &eval,
    const typename Backend::Ciphertext &ciphertext,
    std::size_t expected_rns_limbs, const char *description) {
    if (expected_rns_limbs == 0U ||
        Backend::rns_limb_count(eval, ciphertext) != expected_rns_limbs) {
        throw std::invalid_argument(
            std::string(description) +
            ": ciphertext is not at the setup-selected proof-ingress RNS "
            "level");
    }
}

/// Immutable identity and geometry of one packed multiplication-source
/// artifact. `reduction_layer` is the multiplication layer; its source is
/// trace layer `reduction_layer + 1`.
struct FileDenseMultiplicationSourceDescriptor {
    Digest artifact_id{};
    Digest setup_id{};
    Digest backend_context_id{};
    Digest circuit_id{};
    Digest layered_circuit_id{};
    Digest trace_id{};
    payload::TraceProvenance provenance =
        payload::TraceProvenance::SyntheticTrace;
    payload::PayloadShape shape;
    std::size_t reduction_layer = 0;
    packing::LanedPackingLayout output_layout;
    packing::LanedPackingLayout source_layout;
    payload::LayerDimensions source_dimensions;
    std::size_t source_required_mult_depth = 0;
    std::size_t source_proof_ingress_rns_limbs = 0;
    std::size_t packed_proof_ingress_rns_limbs = 0;
    std::size_t packed_required_mult_depth = 0;
    std::size_t chunks_per_packed_ciphertext = 0;
    std::size_t pair_count = 0;
    /// Packed indices in `[0, live_pair_count)` are logical source pairs.
    /// Every later index is canonical public zero. Logical positions refer to
    /// `stored_value_count` distinct operands through circuit-derived aliases.
    std::size_t live_pair_count = 0;
    /// Number of distinct packed operand values serialized by the artifact.
    /// Logical pair positions refer to these values through setup-derived
    /// metadata; aliases never duplicate a ciphertext record.
    std::size_t stored_value_count = 0;

    bool operator==(
        const FileDenseMultiplicationSourceDescriptor &other) const =
        default;
};

/// Exact construction counters. Identity sources use two constant-residency
/// half scans and a bounded merge sorter. Wide aliased and eager-packed
/// sources scan into the same bounded sorter; other packed aliases gather
/// one operand at a time through a reused indexed reader. No path retains
/// the entire ciphertext source.
struct FileDenseMultiplicationSourceBuildStatistics {
    std::uint64_t source_range_opens = 0;
    std::uint64_t source_indexed_seeks = 0;
    std::uint64_t source_sequential_passes = 0;
    std::uint64_t source_values_read = 0;
    std::uint64_t source_logical_record_bytes_read = 0;
    std::uint64_t prepared_chunk_bases = 0;
    std::uint64_t prepared_chunk_basis_applications = 0;
    std::uint64_t chunk_placement_rotations = 0;
    std::uint64_t online_slot_vectors_constructed = 0;
    std::uint64_t avoided_online_slot_vector_elements = 0;
    std::uint64_t external_sort_initial_runs = 0;
    std::uint64_t external_sort_runs_created = 0;
    std::uint64_t external_sort_merge_passes = 0;
    std::size_t external_sort_maximum_open_runs = 0;
    std::uint64_t external_sort_temporary_bytes_written = 0;
    std::uint64_t external_sort_temporary_bytes_deleted = 0;
    std::uint64_t external_sort_peak_live_temporary_bytes = 0;
    /// Exact peak of partial/final artifact bytes plus live sort runs.
    std::uint64_t external_sort_peak_combined_artifact_bytes = 0;
    std::uint64_t external_sort_retained_temporary_bytes = 0;
    std::size_t external_sort_peak_buffered_records = 0;
    std::uint64_t external_sort_peak_buffered_payload_bytes = 0;
    std::uint64_t live_pairs_written = 0;
    std::size_t peak_live_source_values = 0;
    std::size_t peak_live_packed_values = 0;

    bool operator==(
        const FileDenseMultiplicationSourceBuildStatistics &other) const =
        default;
};

struct FileDenseMultiplicationSourceReport {
    std::uint64_t logical_record_bytes = 0;
    std::uint64_t physical_bytes = 0;
    std::uint64_t stored_values = 0;

    bool operator==(
        const FileDenseMultiplicationSourceReport &other) const = default;
};

struct FileDenseMultiplicationSourceWriteResult {
    std::filesystem::path directory;
    FileDenseMultiplicationSourceDescriptor descriptor;
    FileDenseMultiplicationSourceReport report;
    FileDenseMultiplicationSourceBuildStatistics statistics;
};

/// Cumulative reader counters. `passes_started` includes the initial pass;
/// every explicit rewind starts one more pass. Logical bytes count complete
/// tagged value records, not store framing.
struct FileDenseMultiplicationSourceReadStatistics {
    std::uint64_t passes_started = 1;
    std::uint64_t rewinds = 0;
    std::uint64_t pairs_read = 0;
    /// Actual decoded records, including cache misses after eviction.
    std::uint64_t values_read = 0;
    /// First successful reads of distinct operands, counted anew per pass.
    std::uint64_t distinct_values_read = 0;
    std::uint64_t logical_record_bytes_read = 0;
    /// Bit toggles used by the incremental bit-reversed iterator. This is
    /// amortized O(1) per pair, including across repeated proof scans.
    std::uint64_t bit_reversal_bit_flips = 0;
    std::size_t peak_live_decoded_values = 0;

    bool operator==(
        const FileDenseMultiplicationSourceReadStatistics &other) const =
        default;
};

namespace file_dense_multiplication_source_detail {

payload::EncryptedTraceDescriptor storage_descriptor(
    const FileDenseMultiplicationSourceDescriptor &descriptor);

void validate_descriptor(
    const FileDenseMultiplicationSourceDescriptor &descriptor);

std::filesystem::path validate_empty_private_directory(
    const std::filesystem::path &directory);

/// True when either existing path is the other path or one of its component-
/// wise ancestors. Canonicalization resolves aliases through parent
/// symlinks; string-prefix matches such as `/trace` and `/trace-backup` do not
/// count as overlap.
inline bool paths_overlap_by_ancestry(
    const std::filesystem::path &left,
    const std::filesystem::path &right) {
    if (left.empty() || right.empty()) {
        throw std::invalid_argument(
            "path-overlap validation requires two nonempty paths");
    }
    const auto normalize = [](const std::filesystem::path &path) {
        return std::filesystem::weakly_canonical(
            std::filesystem::absolute(path));
    };
    const auto is_prefix = [](const std::filesystem::path &prefix,
                              const std::filesystem::path &path) {
        auto prefix_part = prefix.begin();
        auto path_part = path.begin();
        for (; prefix_part != prefix.end(); ++prefix_part, ++path_part) {
            if (path_part == path.end() || *prefix_part != *path_part) {
                return false;
            }
        }
        return true;
    };
    const std::filesystem::path normalized_left = normalize(left);
    const std::filesystem::path normalized_right = normalize(right);
    return is_prefix(normalized_left, normalized_right) ||
           is_prefix(normalized_right, normalized_left);
}

inline void checked_accumulate(std::uint64_t &destination,
                               std::uint64_t value,
                               const char *description) {
    if (value > std::numeric_limits<std::uint64_t>::max() - destination) {
        throw std::overflow_error(std::string(description) +
                                  " overflows u64");
    }
    destination += value;
}

inline std::uint64_t checked_count(std::size_t value,
                                   const char *description) {
    if constexpr (sizeof(std::size_t) > sizeof(std::uint64_t)) {
        if (value > std::numeric_limits<std::uint64_t>::max()) {
            throw std::overflow_error(std::string(description) +
                                      " exceeds u64");
        }
    }
    return static_cast<std::uint64_t>(value);
}

inline std::uint64_t checked_dense_values(std::size_t pair_count) {
    const std::uint64_t pairs =
        checked_count(pair_count, "packed multiplication pair count");
    std::uint64_t result = 0;
    checked_accumulate(result, pairs,
                       "packed multiplication stored value count");
    checked_accumulate(result, pairs,
                       "packed multiplication stored value count");
    return result;
}

inline std::uint64_t checked_stored_values(
    const FileDenseMultiplicationSourceDescriptor &descriptor) {
    return checked_count(descriptor.stored_value_count,
                         "packed multiplication stored value count");
}

} // namespace file_dense_multiplication_source_detail

} // namespace laminate::gkr::detail

#endif // LAMINATE_GKR_DETAIL_SHARED_DENSE_MULTIPLICATION_SOURCE_DESCRIPTOR_HPP
