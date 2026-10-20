#ifndef LAMINATE_PROTOCOL_DETAIL_PACKING_COMMITTED_GKR_ENCODING_HPP
#define LAMINATE_PROTOCOL_DETAIL_PACKING_COMMITTED_GKR_ENCODING_HPP

/// @file committed_gkr_encoding.hpp
/// @brief Canonical encoding that binds packing to the complete GKR proof.

#include "laminate/field/serialization.hpp"
#include "laminate/gates/outsourced.hpp"
#include "laminate/gkr/ciphertext_commitment.hpp"
#include "laminate/gkr/proof.hpp"
#include "laminate/transcript/hash.hpp"

#include <array>
#include <limits>
#include <string_view>
#include <type_traits>
#include <variant>

namespace laminate::protocol::detail {

struct CommittedGkrEncodingStats {
    std::size_t total_bytes = 0;
    std::size_t commitment_digest_bytes = 0;
    std::size_t gate_mle_opening_bytes = 0;
};

namespace committed_encoding_detail {

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
            "committed GKR encoding: size does not fit u64");
    }
    append_u64(output, static_cast<std::uint64_t>(value));
}

inline void hash_bytes(Sha256Hasher &hasher,
                       std::span<const std::uint8_t> bytes) {
    hasher.update(bytes);
}

inline void hash_u64(Sha256Hasher &hasher, std::uint64_t value) {
    std::array<std::uint8_t, 8> encoded{};
    for (std::size_t byte = 0; byte < encoded.size(); ++byte) {
        encoded[byte] = static_cast<std::uint8_t>(
            (value >> (8U * byte)) & std::uint64_t{0xff});
    }
    hash_bytes(hasher, encoded);
}

inline void hash_size(Sha256Hasher &hasher, std::size_t value) {
    if (value > std::numeric_limits<std::uint64_t>::max()) {
        throw std::overflow_error(
            "committed GKR digest: size does not fit u64");
    }
    hash_u64(hasher, static_cast<std::uint64_t>(value));
}

inline void hash_message(Sha256Hasher &hasher,
                         const gkr::CommittedPackedMessage &message) {
    const std::array<std::uint8_t, 1> kind{
        message.is_public() ? std::uint8_t{0} : std::uint8_t{1}};
    hash_bytes(hasher, kind);
    if (message.is_encrypted()) {
        hash_bytes(hasher, message.commitment().digest);
        return;
    }
    const fhe::PublicPlaintext &plaintext = message.plaintext();
    if (plaintext.is_scalar()) {
        const std::array<std::uint8_t, 1> scalar_kind{0U};
        hash_bytes(hasher, scalar_kind);
        hash_u64(hasher, plaintext.scalar().value());
        return;
    }
    const auto &slots = plaintext.slots();
    const std::size_t nonzero = gkr::committed_public_nonzero_count(slots);
    const bool sparse = gkr::committed_public_uses_sparse(slots.size(), nonzero);
    const std::array<std::uint8_t, 1> plaintext_kind{
        sparse ? std::uint8_t{2} : std::uint8_t{1}};
    hash_bytes(hasher, plaintext_kind);
    hash_size(hasher, slots.size());
    if (sparse) {
        hash_size(hasher, nonzero);
        for (std::size_t index = 0; index < slots.size(); ++index) {
            if (slots[index] == Fp::zero()) {
                continue;
            }
            hash_size(hasher, index);
            hash_u64(hasher, slots[index].value());
        }
    } else {
        for (const Fp &slot : slots) {
            hash_u64(hasher, slot.value());
        }
    }
}

template <typename Proof>
std::array<std::uint8_t, 17> canonical_prefix(const Proof &proof) {
    const char protocol_tag =
        proof.header.profile.variant == gkr::ProtocolVariant::LaminateFolded
            ? 'F'
            : 'L';
    return {
        'L', 'M', '/', 'C', 'O', 'M', 'M', 'I', 'T', 'T', 'E', 'D', '/',
        static_cast<std::uint8_t>(protocol_tag), '/', 'v', '3'};
}

inline std::size_t append_message(
    std::vector<std::uint8_t> &output,
    const gkr::CommittedPackedMessage &message) {
    gkr::append_committed_packed_message(output, message);
    return message.is_encrypted() ? PoseidonDigest{}.size() : 0U;
}

inline std::size_t append_opening(
    std::vector<std::uint8_t> &output,
    const std::optional<gates::OutsourcedGateMleProof> &opening) {
    output.push_back(opening.has_value() ? 1U : 0U);
    if (!opening) {
        return 0;
    }
    const std::vector<std::uint8_t> encoded =
        gates::encode_canonical(*opening);
    append_size(output, encoded.size());
    output.insert(output.end(), encoded.begin(), encoded.end());
    return sizeof(std::uint64_t) + encoded.size();
}

template <typename Proof>
void append_prefix(std::vector<std::uint8_t> &output,
                   const Proof &proof) {
    const auto prefix = canonical_prefix(proof);
    output.insert(output.end(), prefix.begin(), prefix.end());
    const std::vector<std::uint8_t> header =
        gkr::encode_canonical(proof.header);
    append_size(output, header.size());
    output.insert(output.end(), header.begin(), header.end());
    append_size(output, proof.reductions.size());
}

} // namespace committed_encoding_detail

/// SHA-256 of the exact canonical committed-GKR byte encoding, computed
/// without materializing its potentially large public-message vectors.
template <typename Proof>
Digest committed_gkr_encoding_digest(const Proof &proof) {
    using namespace committed_encoding_detail;
    Sha256Hasher hasher;
    const auto prefix = canonical_prefix(proof);
    hash_bytes(hasher, prefix);
    const std::vector<std::uint8_t> header =
        gkr::encode_canonical(proof.header);
    hash_size(hasher, header.size());
    hash_bytes(hasher, header);
    hash_size(hasher, proof.reductions.size());
    for (const auto &reduction : proof.reductions) {
        std::visit(
            [&](const auto &typed) {
                const std::array<std::uint8_t, 1> kind{
                    requires { typed.packed_terminal_value; }
                        ? std::uint8_t{0}
                        : std::uint8_t{1}};
                hash_bytes(hasher, kind);
                hash_size(hasher, typed.rounds.size());
                for (const auto &round : typed.rounds) {
                    hash_message(hasher, round.packed_evaluations);
                }
                if constexpr (requires { typed.packed_terminal_value; }) {
                    hash_message(hasher, typed.packed_terminal_value);
                } else {
                    hash_message(hasher, typed.packed_source_values);
                }
            },
            reduction);
    }
    const std::array<std::uint8_t, 1> opening_present{
        proof.gate_mle_opening ? std::uint8_t{1} : std::uint8_t{0}};
    hash_bytes(hasher, opening_present);
    if (proof.gate_mle_opening) {
        const std::vector<std::uint8_t> opening =
            gates::encode_canonical(*proof.gate_mle_opening);
        hash_size(hasher, opening.size());
        hash_bytes(hasher, opening);
    }
    return hasher.finish();
}

template <typename Proof>
CommittedGkrEncodingStats append_committed_gkr(
    std::vector<std::uint8_t> &output, const Proof &proof) {
    using namespace committed_encoding_detail;
    const std::size_t start = output.size();
    append_prefix(output, proof);
    CommittedGkrEncodingStats stats;
    for (const auto &reduction : proof.reductions) {
        std::visit(
            [&](const auto &typed) {
                output.push_back(
                    requires { typed.packed_terminal_value; }
                        ? 0U
                        : 1U);
                append_size(output, typed.rounds.size());
                for (const auto &round : typed.rounds) {
                    stats.commitment_digest_bytes +=
                        append_message(output, round.packed_evaluations);
                }
                if constexpr (requires { typed.packed_terminal_value; }) {
                    stats.commitment_digest_bytes +=
                        append_message(output, typed.packed_terminal_value);
                } else {
                    stats.commitment_digest_bytes +=
                        append_message(output, typed.packed_source_values);
                }
            },
            reduction);
    }
    stats.gate_mle_opening_bytes =
        append_opening(output, proof.gate_mle_opening);
    stats.total_bytes = output.size() - start;
    return stats;
}

template <typename Proof>
std::vector<std::uint8_t> encode_committed_gkr(const Proof &proof) {
    std::vector<std::uint8_t> output;
    (void)append_committed_gkr(output, proof);
    return output;
}

/// Bind every GKR commitment and the optional outsourced opening before any
/// well-formedness coefficient is sampled.
template <typename CommittedProof>
void bind_committed_gkr_for_packing(const CommittedProof &proof,
                                    Transcript &transcript) {
    const Digest digest = committed_gkr_encoding_digest(proof);
    transcript.observe("laminate/packing/committed-gkr-sha256/v5", digest);
}

} // namespace laminate::protocol::detail

#endif // LAMINATE_PROTOCOL_DETAIL_PACKING_COMMITTED_GKR_ENCODING_HPP
