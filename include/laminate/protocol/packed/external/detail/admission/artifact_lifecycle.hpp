#ifndef LAMINATE_PROTOCOL_PACKED_EXTERNAL_DETAIL_ADMISSION_ARTIFACT_LIFECYCLE_HPP
#define LAMINATE_PROTOCOL_PACKED_EXTERNAL_DETAIL_ADMISSION_ARTIFACT_LIFECYCLE_HPP

/// @file artifact_lifecycle.hpp
/// @brief Disjoint scratch admission and post-GKR retirement checks.

#include <filesystem>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace laminate::protocol::packed_external_detail {

inline bool path_prefix(const std::filesystem::path &prefix,
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

inline std::filesystem::path normalized_path(
    const std::filesystem::path &path) {
    if (path.empty()) {
        throw std::invalid_argument(
            "packed external preflight received an empty root path");
    }
    return std::filesystem::weakly_canonical(
        std::filesystem::absolute(path));
}

/// GKR destroys replay/sumcheck artifacts before Spartan starts. Disjoint
/// roots make that lifecycle check meaningful and prevent either phase from
/// consuming the other phase's files.
inline void reject_cross_root_overlap(
    std::span<const std::filesystem::path> gkr_roots,
    std::span<const std::filesystem::path> packing_roots) {
    for (const auto &gkr_root : gkr_roots) {
        const std::filesystem::path left = normalized_path(gkr_root);
        for (const auto &packing_root : packing_roots) {
            const std::filesystem::path right = normalized_path(packing_root);
            if (path_prefix(left, right) || path_prefix(right, left)) {
                throw std::invalid_argument(
                    "checkpoint replay/GKR roots must be disjoint by "
                    "ancestry from transcript-packing roots");
            }
        }
    }
}

inline std::vector<std::filesystem::path> packing_mutable_roots(
    const TranscriptPackingExternalProverOptions &options) {
    std::vector<std::filesystem::path> roots{
        options.outer_assignment.directory,
        options.spartan.assignment.directory,
        options.spartan.matrix_products.directory,
        options.spartan.witness_commitment.destination_directory,
        options.spartan.witness_commitment.scratch_directory,
        options.spartan.constraint_sumcheck.scratch_directory,
        options.spartan.wiring_matrix.directory,
        options.spartan.wiring_sumcheck.scratch_directory,
        options.spartan.witness_opening.scratch_directory,
    };
    for (const auto &opening :
         options.spartan.factored_evaluation.tensor_openings) {
        roots.push_back(opening.scratch_directory);
    }
    return roots;
}

template <typename GkrOptions>
std::vector<std::filesystem::path> gkr_roots(
    const std::filesystem::path &replay_root,
    const GkrOptions &options) {
    std::vector<std::filesystem::path> roots{replay_root};
    for (const auto &scratch : options.multiplication_scratch) {
        roots.push_back(scratch.directory);
    }
    return roots;
}

template <typename GkrOptions>
std::vector<std::filesystem::path> gkr_scratch_roots(
    const GkrOptions &options) {
    std::vector<std::filesystem::path> roots;
    roots.reserve(options.multiplication_scratch.size());
    for (const auto &scratch : options.multiplication_scratch) {
        roots.push_back(scratch.directory);
    }
    return roots;
}

inline void require_empty_roots(
    const std::vector<std::filesystem::path> &roots,
    std::string_view owner) {
    for (const auto &root : roots) {
        const std::filesystem::file_status status =
            std::filesystem::symlink_status(root);
        if (!std::filesystem::is_directory(status) ||
            std::filesystem::is_symlink(status) ||
            !std::filesystem::is_empty(root)) {
            throw std::logic_error(
                std::string(owner) +
                " did not retire every generated artifact root");
        }
    }
}

template <typename Backend, typename GkrOptions>
void require_gkr_artifacts_retired(
    const payload::PayloadCheckpointReplayTrace<Backend> &trace,
    const GkrOptions &options,
    std::string_view owner) {
    if (!trace.report().all_payload_artifacts_retired ||
        trace.report().live_physical_bytes != 0) {
        throw std::logic_error(
            std::string(owner) +
            " did not retire every replay artifact");
    }
    require_empty_roots(gkr_scratch_roots(options), owner);
}

} // namespace laminate::protocol::packed_external_detail

#endif // LAMINATE_PROTOCOL_PACKED_EXTERNAL_DETAIL_ADMISSION_ARTIFACT_LIFECYCLE_HPP
