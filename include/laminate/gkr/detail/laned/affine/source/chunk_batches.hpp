#ifndef LAMINATE_GKR_DETAIL_LANED_AFFINE_SOURCE_CHUNK_BATCHES_HPP
#define LAMINATE_GKR_DETAIL_LANED_AFFINE_SOURCE_CHUNK_BATCHES_HPP

/// @file chunk_batches.hpp
/// @brief Resident-memory bound for Laned affine chunk accumulation.

#include "laminate/params.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <stdexcept>

namespace laminate::gkr::laned_detail::affine_detail {

/// Maximum SIMD chunks accumulated at once by the production affine prover.
///
/// At the selected N=16384 four-limb proof ingress, a populated extension
/// accumulator owns up to eight roughly-one-MiB ciphertexts. Two sumcheck
/// endpoints therefore use about one GiB for a full 64-chunk batch. Batching
/// changes neither the sumcheck polynomial nor the number of FHE operations:
/// the indexed trace reader visits every source record once and the placed
/// batch results are added into the same two round evaluations.
inline constexpr std::size_t kLanedAffineChunksPerBatch = 64;

/// Maximum number of base-field packed source ciphertexts retained by the
/// low-width affine backend. At target B=1 this is four ciphertexts rather
/// than 61,681 trace records. Wider packed domains retain the existing
/// streaming evaluator until they have a separately admitted file-backed
/// packed-source store.
inline constexpr std::size_t
    kLanedAffineMaterializedPackedCiphertextLimit = 64;

inline std::size_t laned_affine_chunks_per_batch(
    std::size_t chunks_per_ciphertext) {
    if (chunks_per_ciphertext == 0) {
        throw std::invalid_argument(
            "Laned affine chunk count must be nonzero");
    }
    return std::min(chunks_per_ciphertext,
                    kLanedAffineChunksPerBatch);
}

/// Conservative number of resident ciphertext objects during a batched
/// ciphertext-index round. This includes both endpoint batches, cumulative
/// and transient round results, and two source/level-reference values.
inline std::uint64_t laned_affine_peak_resident_ciphertexts(
    std::size_t chunks_per_ciphertext) {
    const std::uint64_t batch = static_cast<std::uint64_t>(
        laned_affine_chunks_per_batch(chunks_per_ciphertext));
    constexpr std::uint64_t extension = kExtensionDegree;
    if (batch >
        (std::numeric_limits<std::uint64_t>::max() / extension - 4U) /
            2U) {
        throw std::overflow_error(
            "Laned affine resident ciphertext count overflows");
    }
    return (2U * batch + 4U) * extension + 2U;
}

} // namespace laminate::gkr::laned_detail::affine_detail

#endif // LAMINATE_GKR_DETAIL_LANED_AFFINE_SOURCE_CHUNK_BATCHES_HPP
