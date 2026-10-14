#ifndef LAMINATE_GKR_DETAIL_BASE_VALIDATION_SCRATCH_HPP
#define LAMINATE_GKR_DETAIL_BASE_VALIDATION_SCRATCH_HPP

/// @file scratch.hpp
/// @brief Filesystem admission for Base multiplication-reduction scratch.
///
/// These checks are storage policy, not GKR arithmetic. They run before the
/// transcript is observed or any artifact is written.

#include "laminate/gkr/detail/base/proving/types.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <ios>
#include <limits>
#include <stdexcept>
#include <string>
#include <system_error>
#include <vector>

namespace laminate::gkr::base_detail::scratch_validation_detail {

inline bool is_component_prefix(const std::filesystem::path &prefix,
                                const std::filesystem::path &path) {
    auto prefix_part = prefix.begin();
    auto path_part = path.begin();
    for (; prefix_part != prefix.end(); ++prefix_part, ++path_part) {
        if (path_part == path.end() || *prefix_part != *path_part) {
            return false;
        }
    }
    return true;
}

inline std::filesystem::path canonical_existing_directory(
    const std::filesystem::path &directory, bool require_empty,
    const char *description) {
    if (directory.empty()) {
        throw std::invalid_argument(std::string(description) +
                                    " directory is empty");
    }
    std::error_code error;
    const std::filesystem::file_status link_status =
        std::filesystem::symlink_status(directory, error);
    if (error || std::filesystem::is_symlink(link_status) ||
        !std::filesystem::is_directory(link_status) ||
        (require_empty && !std::filesystem::is_empty(directory, error)) ||
        error) {
        throw std::invalid_argument(std::string(description) +
                                    " must be an existing empty, non-symlink "
                                    "directory");
    }
    const std::filesystem::path canonical =
        std::filesystem::weakly_canonical(
            std::filesystem::absolute(directory), error);
    if (error || canonical.empty()) {
        throw std::invalid_argument(std::string(description) +
                                    " cannot be canonicalized");
    }
    return canonical;
}

inline bool overlaps_by_ancestry(const std::filesystem::path &left,
                                 const std::filesystem::path &right) {
    return is_component_prefix(left, right) ||
           is_component_prefix(right, left);
}

inline void validate_storage_limits(
    const FileBaseMultiplicationScratch &scratch) {
    if (scratch.storage_limits.max_total_bytes == 0 ||
        scratch.storage_limits.min_free_bytes == 0 ||
        scratch.sort_buffer_payload_bytes <
            detail::kDenseMultiplicationMinimumSortBufferBytes) {
        throw std::invalid_argument(
            "Base scratch disk and sort-buffer limits are invalid");
    }
    constexpr std::streamoff kMaxStreamOffset =
        std::numeric_limits<std::streamoff>::max();
    if constexpr (kMaxStreamOffset >= 0) {
        if (scratch.storage_limits.max_total_bytes >
            static_cast<std::uint64_t>(kMaxStreamOffset)) {
            throw std::invalid_argument(
                "Base scratch byte limit exceeds stream range");
        }
    }
    std::error_code error;
    const std::filesystem::space_info available =
        std::filesystem::space(scratch.directory, error);
    if (error || available.available < scratch.storage_limits.min_free_bytes) {
        throw std::invalid_argument(
            "Base scratch free-space floor is unavailable");
    }
}

} // namespace laminate::gkr::base_detail::scratch_validation_detail

namespace laminate::gkr::base_detail {

inline FileEncryptedBaseGkrOptions
preflight_and_normalize_file_base_gkr_scratch(
    const payload::LayeredCircuit &circuit,
    const std::filesystem::path &trace_or_replay_root,
    const FileEncryptedBaseGkrOptions &supplied_options) {
    circuit.validate();
    const std::filesystem::path root =
        scratch_validation_detail::canonical_existing_directory(
            trace_or_replay_root, false, "Base trace");

    std::vector<std::size_t> expected_layers;
    for (std::size_t layer = 0; layer + 1U < circuit.layers.size(); ++layer) {
        if (payload::layer_kind(circuit.layers[layer]) ==
            payload::LayerKind::Multiplication) {
            expected_layers.push_back(layer);
        }
    }
    if (supplied_options.multiplication_scratch.size() !=
        expected_layers.size()) {
        throw std::invalid_argument(
            "Base proof requires one scratch directory per "
            "multiplication layer");
    }

    FileEncryptedBaseGkrOptions options = supplied_options;
    std::vector<std::filesystem::path> accepted;
    accepted.reserve(expected_layers.size());
    for (std::size_t index = 0; index < expected_layers.size(); ++index) {
        FileBaseMultiplicationScratch &scratch =
            options.multiplication_scratch[index];
        if (scratch.reduction_layer != expected_layers[index]) {
            throw std::invalid_argument(
                "Base scratch layers are not in circuit order");
        }
        scratch.directory =
            scratch_validation_detail::canonical_existing_directory(
            scratch.directory, true,
            "Base multiplication scratch");
        scratch_validation_detail::validate_storage_limits(scratch);
        if (scratch_validation_detail::overlaps_by_ancestry(
                root, scratch.directory)) {
            throw std::invalid_argument(
                "Base scratch must be disjoint from the trace or "
                "replay root");
        }
        if (std::any_of(
                accepted.begin(), accepted.end(),
                [&](const std::filesystem::path &other) {
                    return scratch_validation_detail::overlaps_by_ancestry(
                        other, scratch.directory);
                })) {
            throw std::invalid_argument(
                "Base scratch directories must be unique and "
                "disjoint");
        }
        accepted.push_back(scratch.directory);
    }
    return options;
}

} // namespace laminate::gkr::base_detail

#endif // LAMINATE_GKR_DETAIL_BASE_VALIDATION_SCRATCH_HPP
