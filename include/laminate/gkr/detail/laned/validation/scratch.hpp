#ifndef LAMINATE_GKR_DETAIL_LANED_VALIDATION_SCRATCH_HPP
#define LAMINATE_GKR_DETAIL_LANED_VALIDATION_SCRATCH_HPP

/// @file scratch.hpp
/// @brief Read-only scratch-map admission for file-backed Laned proving.

#include "laminate/gkr/detail/laned/proving/types.hpp"

#include <algorithm>
#include <ios>
#include <limits>
#include <stdexcept>

namespace laminate::gkr::laned_detail {

inline FileLanedGkrOptions
preflight_and_normalize_laned_gkr_scratch(
    const payload::LayeredCircuit &circuit,
    const std::filesystem::path &trace_directory,
    const FileLanedGkrOptions &supplied_options) {
    FileLanedGkrOptions options = supplied_options;
    std::vector<std::size_t> expected_layers;
    for (std::size_t layer = 0; layer + 1U < circuit.layers.size(); ++layer) {
        if (payload::layer_kind(circuit.layers[layer]) ==
            payload::LayerKind::Multiplication) {
            expected_layers.push_back(layer);
        }
    }
    if (options.multiplication_scratch.size() != expected_layers.size()) {
        throw std::invalid_argument(
            "file-backed Laned proof requires one scratch directory per "
            "multiplication layer");
    }

    std::vector<std::filesystem::path> directories;
    directories.reserve(expected_layers.size());
    for (std::size_t index = 0; index < expected_layers.size(); ++index) {
        FileLanedMultiplicationScratch &scratch =
            options.multiplication_scratch[index];
        if (scratch.reduction_layer != expected_layers[index]) {
            throw std::invalid_argument(
                "file-backed Laned scratch layers are not in circuit order");
        }
        if (scratch.storage_limits.max_total_bytes == 0 ||
            scratch.storage_limits.min_free_bytes == 0 ||
            scratch.sort_buffer_payload_bytes <
                ::laminate::gkr::detail::
                    kDenseMultiplicationMinimumSortBufferBytes) {
            throw std::invalid_argument(
                "file-backed Laned scratch disk and sort-buffer limits are "
                "invalid");
        }
        constexpr std::streamoff kMaxStreamOffset =
            std::numeric_limits<std::streamoff>::max();
        if constexpr (kMaxStreamOffset >= 0) {
            if (scratch.storage_limits.max_total_bytes >
                static_cast<std::uint64_t>(kMaxStreamOffset)) {
                throw std::invalid_argument(
                    "file-backed Laned scratch byte limit exceeds the "
                    "platform file-offset range");
            }
        }
        if (::laminate::gkr::detail::file_dense_multiplication_source_detail::
                paths_overlap_by_ancestry(
                    trace_directory, scratch.directory)) {
            throw std::invalid_argument(
                "file-backed Laned multiplication scratch must not equal, "
                "contain, or be contained by the trace directory");
        }
        const std::filesystem::path directory =
            std::filesystem::weakly_canonical(
                ::laminate::gkr::detail::
                    file_dense_multiplication_source_detail::
                        validate_empty_private_directory(
                            scratch.directory));
        if (std::filesystem::equivalent(trace_directory, directory)) {
            throw std::invalid_argument(
                "file-backed Laned multiplication scratch must not alias the "
                "trace directory");
        }
        if (std::any_of(
                directories.begin(), directories.end(),
                [&directory](const std::filesystem::path &existing) {
                    return existing == directory ||
                           std::filesystem::equivalent(existing, directory);
                })) {
            throw std::invalid_argument(
                "file-backed Laned scratch directories must be unique");
        }
        directories.push_back(directory);
        scratch.directory = directory;
    }
    return options;
}

} // namespace laminate::gkr::laned_detail

#endif // LAMINATE_GKR_DETAIL_LANED_VALIDATION_SCRATCH_HPP
