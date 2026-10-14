#ifndef LAMINATE_GKR_DETAIL_BASE_TRANSCRIPT_REDUCTION_HPP
#define LAMINATE_GKR_DETAIL_BASE_TRANSCRIPT_REDUCTION_HPP

/// @file reduction.hpp
/// @brief Fiat--Shamir bindings for Base layer-reduction messages.

#include "laminate/gkr/base.hpp"
#include "laminate/gkr/detail/shared/encoding/canonical.hpp"
#include "laminate/transcript/transcript.hpp"
#include "laminate/verification_profile.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

namespace laminate::gkr::base_detail {

inline constexpr std::string_view kBeginLabel =
    "laminate/base/reduction/v1";
inline constexpr std::string_view kRoundLabel =
    "laminate/base/round/v2";
inline constexpr std::string_view kTerminalLabel =
    "laminate/base/terminal/v1";
inline constexpr std::string_view kOutputPointLabel =
    "laminate/base/output-point/v1";
inline constexpr std::string_view kPartialGateMleLabel =
    "laminate/base/partial-gate-mle/v1";

enum class PartialGateMleKind : std::uint8_t {
    Affine = 0,
};

inline void append_partial_gate_mle(
    std::vector<std::uint8_t> &output,
    const PartialGateMleVector &partial) {
    detail::canonical_encoding::append_size(output,
                                             partial.evaluations.size());
    for (const Fpk &value : partial.evaluations) {
        detail::canonical_encoding::append_fpk(output, value);
    }
}

/// Bind the public output-randomization point without disclosing the private
/// output-layer evaluation. Fiat--Shamir derives this point from the encrypted
/// statement before the prover emits a reduction message.
inline void observe_output_point(std::span<const Fpk> point,
                                 Transcript &transcript) {
    const verification_profile::ScopedTranscriptRecovery recovery;
    std::vector<std::uint8_t> encoded;
    detail::canonical_encoding::append_point(encoded, point);
    transcript.observe(kOutputPointLabel, encoded);
}

inline void observe_begin(std::size_t layer, payload::LayerKind kind,
                          std::size_t rounds, Transcript &transcript) {
    const verification_profile::ScopedTranscriptRecovery recovery;
    std::vector<std::uint8_t> encoded;
    detail::canonical_encoding::append_size(encoded, layer);
    encoded.push_back(static_cast<std::uint8_t>(kind));
    detail::canonical_encoding::append_size(encoded, rounds);
    transcript.observe(kBeginLabel, encoded);
}

template <fhe::FheBackend Backend>
void observe_round(
    std::size_t layer, std::size_t round_index,
    const EncryptedBaseLayerReductionSumcheckRound<Backend> &round,
    Transcript &transcript) {
    const verification_profile::ScopedTranscriptRecovery recovery;
    std::vector<std::uint8_t> encoded;
    detail::canonical_encoding::append_size(encoded, layer);
    detail::canonical_encoding::append_size(encoded, round_index);
    detail::canonical_encoding::append_extension<Backend>(
        encoded, round.evaluations[0]);
    detail::canonical_encoding::append_extension<Backend>(
        encoded, round.evaluations[1]);
    transcript.observe(kRoundLabel, encoded);
}

template <fhe::FheBackend Backend>
void observe_terminal(
    std::size_t layer,
    std::span<const fhe::ExtensionValue<Backend>> values,
    Transcript &transcript) {
    const verification_profile::ScopedTranscriptRecovery recovery;
    std::vector<std::uint8_t> encoded;
    detail::canonical_encoding::append_size(encoded, layer);
    detail::canonical_encoding::append_size(encoded, values.size());
    for (const fhe::ExtensionValue<Backend> &value : values) {
        detail::canonical_encoding::append_extension<Backend>(encoded,
                                                               value);
    }
    transcript.observe(kTerminalLabel, encoded);
}

inline void observe_partial_gate_mle(
    std::size_t layer, PartialGateMleKind kind,
    const PartialGateMleVector &partial, Transcript &transcript) {
    const verification_profile::ScopedTranscriptRecovery recovery;
    std::vector<std::uint8_t> encoded;
    detail::canonical_encoding::append_size(encoded, layer);
    encoded.push_back(static_cast<std::uint8_t>(kind));
    append_partial_gate_mle(encoded, partial);
    transcript.observe(kPartialGateMleLabel, encoded);
}

} // namespace laminate::gkr::base_detail

#endif // LAMINATE_GKR_DETAIL_BASE_TRANSCRIPT_REDUCTION_HPP
