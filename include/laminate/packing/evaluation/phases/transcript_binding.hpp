#ifndef LAMINATE_PACKING_EVALUATION_PHASES_TRANSCRIPT_BINDING_HPP
#define LAMINATE_PACKING_EVALUATION_PHASES_TRANSCRIPT_BINDING_HPP

/// @file transcript_binding.hpp
/// @brief Canonical alignment encoding and Fiat--Shamir challenge binding.

#include "laminate/transcript/hash.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <stdexcept>

namespace laminate::packing::lazy_ternary_detail {

inline void append_u64(std::vector<std::uint8_t> &output,
                       std::uint64_t value) {
    for (std::size_t byte = 0; byte < 8; ++byte) {
        output.push_back(static_cast<std::uint8_t>(
            (value >> (8U * byte)) & std::uint64_t{0xff}));
    }
}

inline void append_size(std::vector<std::uint8_t> &output,
                        std::size_t value) {
    if (value > std::numeric_limits<std::uint64_t>::max()) {
        throw std::overflow_error(
            "lazy-ternary evaluation: size does not fit u64");
    }
    append_u64(output, static_cast<std::uint64_t>(value));
}

inline void append_layout(std::vector<std::uint8_t> &output,
                          const PackingLayout &layout) {
    append_size(output, layout.slot_count);
    output.push_back(static_cast<std::uint8_t>(layout.slot_pattern));
    append_size(output, layout.maximum_row_contributions);
    append_size(output, layout.message_active_slots.size());
    for (const std::size_t width : layout.message_active_slots) {
        append_size(output, width);
    }
    append_size(output, layout.placements.size());
    for (const PackingPlacement &placement : layout.placements) {
        append_size(output, placement.message_index);
        append_size(output, placement.source_begin);
        append_size(output, placement.packed_index);
        append_size(output, placement.destination_begin);
        append_size(output, placement.length);
        append_size(output, placement.rotation_steps);
    }
    append_size(output, layout.packed_ciphertext_count);
}

inline void hash_u64(Sha256Hasher &hasher, std::uint64_t value) {
    std::array<std::uint8_t, 8> encoded{};
    for (std::size_t byte = 0; byte < encoded.size(); ++byte) {
        encoded[byte] = static_cast<std::uint8_t>(
            (value >> (8U * byte)) & std::uint64_t{0xff});
    }
    hasher.update(encoded);
}

inline void hash_size(Sha256Hasher &hasher, std::size_t value) {
    if (value > std::numeric_limits<std::uint64_t>::max()) {
        throw std::overflow_error(
            "lazy-ternary evaluation: size does not fit u64");
    }
    hash_u64(hasher, static_cast<std::uint64_t>(value));
}

inline void hash_u64s(Sha256Hasher &hasher,
                      std::span<const std::uint64_t> values) {
    constexpr std::size_t kWordsPerChunk = 512;
    std::array<std::uint8_t, 8 * kWordsPerChunk> encoded{};
    while (!values.empty()) {
        const std::size_t words = std::min(values.size(), kWordsPerChunk);
        for (std::size_t word = 0; word < words; ++word) {
            for (std::size_t byte = 0; byte < 8; ++byte) {
                encoded[8 * word + byte] = static_cast<std::uint8_t>(
                    (values[word] >> (8U * byte)) &
                    std::uint64_t{0xff});
            }
        }
        hasher.update(
            std::span<const std::uint8_t>(encoded).first(8 * words));
        values = values.subspan(words);
    }
}

inline void hash_zero_u64s(Sha256Hasher &hasher, std::size_t word_count) {
    constexpr std::size_t kWordsPerChunk = 512;
    constexpr std::array<std::uint8_t, 8 * kWordsPerChunk> kZeros{};
    while (word_count != 0) {
        const std::size_t words = std::min(word_count, kWordsPerChunk);
        hasher.update(
            std::span<const std::uint8_t>(kZeros).first(8 * words));
        word_count -= words;
    }
}

template <CoefficientWellFormednessBackend Backend>
Digest digest_aligned_values(
    const PackingLayout &layout,
    const NormalizedAlignedTranscript<Backend> &aligned) {
    std::vector<std::uint8_t> prefix{
        'L', 'M', '/', 'A', 'L', 'I', 'G', 'N', 'E', 'D', '/', 'V', '2'};
    append_layout(prefix, layout);
    append_size(prefix, aligned.values.size());
    Sha256Hasher hasher;
    hasher.update(prefix);
    for (std::size_t index = 0; index < aligned.values.size(); ++index) {
        if constexpr (PublicCoefficientEncodingBackend<Backend>) {
            if (aligned.values[index].is_public() &&
                !aligned.public_sources[index]) {
                throw std::invalid_argument(
                    "standalone aligned-list digest cannot bind a verifier "
                    "projection");
            }
            if (aligned.values[index].is_public_zero() &&
                aligned.public_coordinates[index].empty()) {
                // Hash implicit zeros in chunks; never materialize a 2N-word
                // sidecar merely to preserve the canonical digest.
                const std::size_t width = 2 * layout.slot_count;
                hash_size(hasher, width);
                hash_zero_u64s(hasher, width);
                continue;
            }
            const auto coordinates =
                normalized_aligned_coordinates(aligned, index);
            hash_size(hasher, coordinates.size());
            hash_u64s(hasher, coordinates);
        } else {
            if (!aligned.values[index].is_encrypted()) {
                throw std::invalid_argument(
                    "bound-only aligned transcript cannot encode a public "
                    "value");
            }
            const std::vector<std::uint8_t> bytes =
                Backend::serialize(aligned.values[index].ciphertext());
            hash_size(hasher, bytes.size());
            hasher.update(bytes);
        }
    }
    return hasher.finish();
}

inline void observe_parameters(
    Transcript &transcript, const LazyTernaryParameters &parameters) {
    parameters.packing_radix.validate();
    transcript.observe("laminate/packing/repetitions/v1",
                       static_cast<std::uint64_t>(parameters.repetitions));
    transcript.observe("laminate/packing/honest-error-bound/v1",
                       parameters.honest_error_bound);
    transcript.observe("laminate/packing/signed-radix/modulus/v1",
                       parameters.packing_radix.plaintext_modulus);
    transcript.observe("laminate/packing/signed-radix/base/v1",
                       parameters.packing_radix.base);
    transcript.observe("laminate/packing/signed-radix/digits/v1",
                       static_cast<std::uint64_t>(
                           parameters.packing_radix.digit_count));
}

} // namespace laminate::packing::lazy_ternary_detail

namespace laminate::packing {

inline LazyTernaryChallengeMatrix derive_committed_lazy_ternary_challenges(
    const PackingLayout &layout,
    std::span<const PoseidonDigest> aligned_commitments,
    Transcript &transcript, LazyTernaryParameters parameters) {
    layout.validate();
    if (parameters.repetitions == 0 ||
        aligned_commitments.size() != layout.placements.size()) {
        throw std::invalid_argument(
            "committed lazy-ternary challenge dimensions are invalid");
    }
    parameters.packing_radix.validate();
    if (parameters.packing_radix.plaintext_modulus != kBaseFieldOrder) {
        throw std::invalid_argument(
            "committed lazy-ternary radix differs from the plaintext field");
    }

    std::vector<std::uint8_t> encoding{
        'L', 'M', '/', 'P', 'A', 'C', 'K', '/', 'C', 'O', 'M', 'M',
        'I', 'T', 'S', '/', 'V', '1'};
    lazy_ternary_detail::append_layout(encoding, layout);
    lazy_ternary_detail::append_size(encoding,
                                     aligned_commitments.size());
    for (const PoseidonDigest &commitment : aligned_commitments) {
        encoding.insert(encoding.end(), commitment.begin(), commitment.end());
    }
    transcript.observe("laminate/packing/aligned-commitments/v1", encoding);
    lazy_ternary_detail::observe_parameters(transcript, parameters);
    return derive_lazy_ternary_challenges(
        transcript, parameters.repetitions, aligned_commitments.size());
}

} // namespace laminate::packing

#endif // LAMINATE_PACKING_EVALUATION_PHASES_TRANSCRIPT_BINDING_HPP
