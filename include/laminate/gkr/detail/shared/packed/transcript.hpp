#ifndef LAMINATE_GKR_DETAIL_SHARED_PACKED_TRANSCRIPT_HPP
#define LAMINATE_GKR_DETAIL_SHARED_PACKED_TRANSCRIPT_HPP

/// @file transcript.hpp
/// @brief Canonical Folded/Laned packed-message transcript codec.

#include "laminate/fhe/storage/value_codec.hpp"
#include "laminate/gkr/detail/shared/encoding/canonical.hpp"
#include "laminate/gkr/detail/shared/packed/proof.hpp"
#include "laminate/verification_profile.hpp"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace laminate::gkr::detail {

template <ProtocolVariant Variant, fhe::FheBackend Backend>
void append_packed_proof_message(
    std::vector<std::uint8_t> &output,
    const fhe::FheValue<Backend> &message) {
    static_assert(kIsPackedProofVariant<Variant>);
    const std::vector<std::uint8_t> encoded =
        fhe::encode_canonical_fhe_value<Backend>(
            message, PackedProofTraits<Variant>::message_description);
    canonical_encoding::append_size(output, encoded.size());
    output.insert(output.end(), encoded.begin(), encoded.end());
}

inline void append_packed_proof_commitment(
    std::vector<std::uint8_t> &output,
    const CommittedPackedMessage &message) {
    append_committed_packed_message(output, message);
}

template <ProtocolVariant Variant>
void observe_packed_reduction_begin(std::size_t layer,
                                    payload::LayerKind kind,
                                    std::size_t rounds,
                                    Transcript &transcript) {
    const verification_profile::ScopedTranscriptRecovery recovery;
    static_assert(kIsPackedProofVariant<Variant>);
    std::vector<std::uint8_t> encoded;
    canonical_encoding::append_size(encoded, layer);
    encoded.push_back(static_cast<std::uint8_t>(kind));
    canonical_encoding::append_size(encoded, rounds);
    transcript.observe(PackedProofTraits<Variant>::begin_label, encoded);
}

template <ProtocolVariant Variant>
void observe_packed_round(
    std::size_t layer, std::size_t round_index,
    const PackedRound<CommittedPackedMessage, Variant> &round,
    Transcript &transcript) {
    const verification_profile::ScopedTranscriptRecovery recovery;
    static_assert(kIsPackedProofVariant<Variant>);
    std::vector<std::uint8_t> encoded;
    canonical_encoding::append_size(encoded, layer);
    canonical_encoding::append_size(encoded, round_index);
    append_packed_proof_commitment(encoded, round.packed_evaluations);
    transcript.observe(PackedProofTraits<Variant>::round_label, encoded);
}

template <ProtocolVariant Variant, fhe::FheBackend Backend>
void observe_packed_round(
    std::size_t layer, std::size_t round_index,
    const PackedRound<fhe::FheValue<Backend>, Variant> &round,
    Transcript &transcript,
    const PackedMessageCommitmentFunction<Backend>
        &commitment_function = {}) {
    const verification_profile::ScopedTranscriptRecovery recovery;
    observe_packed_round<Variant>(
        layer, round_index,
        PackedRound<CommittedPackedMessage, Variant>{
            commit_packed_message<Backend>(round.packed_evaluations,
                                           commitment_function)},
        transcript);
}

/// Observe a verifier-side round message without branching at the call site
/// on whether the proof still carries ciphertexts or only commitments.
template <ProtocolVariant Variant, fhe::FheBackend Backend>
void observe_packed_round_message(
    std::size_t layer, std::size_t round_index,
    const PackedRound<fhe::FheValue<Backend>, Variant> &round,
    Transcript &transcript) {
    const verification_profile::ScopedTranscriptRecovery recovery;
    observe_packed_round<Variant, Backend>(layer, round_index, round,
                                           transcript);
}

template <ProtocolVariant Variant, fhe::FheBackend Backend>
void observe_packed_round_message(
    std::size_t layer, std::size_t round_index,
    const PackedRound<CommittedPackedMessage, Variant> &round,
    Transcript &transcript) {
    const verification_profile::ScopedTranscriptRecovery recovery;
    observe_packed_round<Variant>(layer, round_index, round, transcript);
}

template <ProtocolVariant Variant>
void observe_packed_terminal(std::size_t layer,
                             const CommittedPackedMessage &terminal,
                             Transcript &transcript) {
    const verification_profile::ScopedTranscriptRecovery recovery;
    static_assert(kIsPackedProofVariant<Variant>);
    std::vector<std::uint8_t> encoded;
    canonical_encoding::append_size(encoded, layer);
    append_packed_proof_commitment(encoded, terminal);
    transcript.observe(PackedProofTraits<Variant>::terminal_label, encoded);
}

template <ProtocolVariant Variant, fhe::FheBackend Backend>
void observe_packed_terminal(
    std::size_t layer, const fhe::FheValue<Backend> &terminal,
    Transcript &transcript,
    const PackedMessageCommitmentFunction<Backend>
        &commitment_function = {}) {
    const verification_profile::ScopedTranscriptRecovery recovery;
    observe_packed_terminal<Variant>(
        layer,
        commit_packed_message<Backend>(terminal, commitment_function),
        transcript);
}

/// Verifier-side counterpart of `observe_packed_round_message`.
template <ProtocolVariant Variant, fhe::FheBackend Backend>
void observe_packed_terminal_message(
    std::size_t layer, const fhe::FheValue<Backend> &terminal,
    Transcript &transcript) {
    const verification_profile::ScopedTranscriptRecovery recovery;
    observe_packed_terminal<Variant, Backend>(layer, terminal, transcript);
}

template <ProtocolVariant Variant, fhe::FheBackend Backend>
void observe_packed_terminal_message(
    std::size_t layer, const CommittedPackedMessage &terminal,
    Transcript &transcript) {
    const verification_profile::ScopedTranscriptRecovery recovery;
    observe_packed_terminal<Variant>(layer, terminal, transcript);
}

} // namespace laminate::gkr::detail

#endif // LAMINATE_GKR_DETAIL_SHARED_PACKED_TRANSCRIPT_HPP
