#ifndef LAMINATE_GKR_DETAIL_FOLDED_VALIDATION_SCRATCH_HPP
#define LAMINATE_GKR_DETAIL_FOLDED_VALIDATION_SCRATCH_HPP

/// @file scratch.hpp
/// @brief Read-only scratch-map admission for file-backed Folded proving.

#include "laminate/gkr/detail/base/prover.hpp"
#include "laminate/gkr/detail/folded/storage/types.hpp"

#include <utility>

namespace laminate::gkr::folded_detail {

inline FileFoldedGkrOptions
preflight_and_normalize_file_folded_gkr_scratch(
    const payload::LayeredCircuit &circuit,
    const std::filesystem::path &trace_or_replay_root,
    const FileFoldedGkrOptions &supplied) {
    base_detail::FileEncryptedBaseGkrOptions shared;
    shared.multiplication_scratch.reserve(
        supplied.multiplication_scratch.size());
    for (const auto &scratch : supplied.multiplication_scratch) {
        shared.multiplication_scratch.push_back(
            base_detail::FileBaseMultiplicationScratch{
                scratch.reduction_layer, scratch.directory,
                scratch.storage_limits,
                scratch.sort_buffer_payload_bytes});
    }
    shared.progress = supplied.progress;
    shared = base_detail::preflight_and_normalize_file_base_gkr_scratch(
        circuit, trace_or_replay_root, shared);

    FileFoldedGkrOptions result;
    result.progress = std::move(shared.progress);
    result.multiplication_scratch.reserve(
        shared.multiplication_scratch.size());
    for (auto &scratch : shared.multiplication_scratch) {
        result.multiplication_scratch.push_back(
            FileFoldedMultiplicationScratch{
                scratch.reduction_layer, std::move(scratch.directory),
                scratch.storage_limits,
                scratch.sort_buffer_payload_bytes});
    }
    return result;
}

} // namespace laminate::gkr::folded_detail

#endif // LAMINATE_GKR_DETAIL_FOLDED_VALIDATION_SCRATCH_HPP
