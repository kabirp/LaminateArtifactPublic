#ifndef LAMINATE_PROTOCOL_DETAIL_PROOF_SIZE_BASE_HPP
#define LAMINATE_PROTOCOL_DETAIL_PROOF_SIZE_BASE_HPP

/// @file base.hpp
/// @brief Canonical Base proof encoding and exact size accounting.

#include "laminate/gkr/detail/base/transcript/reduction.hpp"
#include "laminate/gkr/detail/shared/encoding/canonical.hpp"

#include <algorithm>
#include <limits>

namespace laminate::protocol {

template <fhe::FheBackend Backend>
std::vector<std::uint8_t>
encode_canonical(const gkr::EncryptedBaseProof<Backend> &proof) {
    static_assert(gkr::kEncryptedBaseProofVersion <=
                  std::numeric_limits<std::uint8_t>::max());
    std::vector<std::uint8_t> output{
        'L', 'M', 'B', 'P',
        static_cast<std::uint8_t>(gkr::kEncryptedBaseProofVersion)};
    const std::vector<std::uint8_t> header =
        gkr::encode_canonical(proof.header);
    gkr::detail::canonical_encoding::append_size(output, header.size());
    output.insert(output.end(), header.begin(), header.end());
    gkr::detail::canonical_encoding::append_size(
        output, proof.reductions.size());
    for (const gkr::EncryptedBaseLayerReductionProof<Backend> &reduction :
         proof.reductions) {
        if (const auto *affine =
                std::get_if<gkr::EncryptedBaseAffineLayerReduction<Backend>>(
                    &reduction)) {
            output.push_back(0);
            gkr::detail::canonical_encoding::append_size(
                output, affine->rounds.size());
            for (const gkr::EncryptedBaseLayerReductionSumcheckRound<Backend> &round :
                 affine->rounds) {
                gkr::detail::canonical_encoding::append_extension<Backend>(
                    output, round.evaluations[0]);
                gkr::detail::canonical_encoding::append_extension<Backend>(
                    output, round.evaluations[1]);
            }
            gkr::detail::canonical_encoding::append_extension<Backend>(
                output, affine->source_vector);
            gkr::base_detail::append_partial_gate_mle(
                output, affine->partial_gate_mle);
        } else {
            const auto &multiplication =
                std::get<
                    gkr::EncryptedBaseMultiplicationLayerReduction<Backend>>(
                    reduction);
            output.push_back(1);
            gkr::detail::canonical_encoding::append_size(
                output, multiplication.rounds.size());
            for (const gkr::EncryptedBaseLayerReductionSumcheckRound<Backend> &round :
                 multiplication.rounds) {
                gkr::detail::canonical_encoding::append_extension<Backend>(
                    output, round.evaluations[0]);
                gkr::detail::canonical_encoding::append_extension<Backend>(
                    output, round.evaluations[1]);
            }
            gkr::detail::canonical_encoding::append_extension<Backend>(
                output, multiplication.source_vectors[0]);
            gkr::detail::canonical_encoding::append_extension<Backend>(
                output, multiplication.source_vectors[1]);
        }
    }
    output.push_back(proof.gate_mle_opening.has_value() ? 1U : 0U);
    if (proof.gate_mle_opening) {
        const std::vector<std::uint8_t> opening =
            gates::encode_canonical(*proof.gate_mle_opening);
        gkr::detail::canonical_encoding::append_size(
            output, opening.size());
        output.insert(output.end(), opening.begin(), opening.end());
    }
    return output;
}

template <fhe::FheBackend Backend>
BaseProofSizeBreakdown
measure_proof_size(const gkr::EncryptedBaseProof<Backend> &proof) {
    BaseProofSizeBreakdown result;
    result.total_bytes = encode_canonical(proof).size();

    const auto extension_bytes = [](const auto &ciphertext) {
        // append_extension prefixes the canonical extension by its byte size.
        return std::size_t{8} +
               fhe::serialize_extension_value<Backend>(ciphertext).size();
    };
    const auto live_base_ciphertexts = [](const auto &ciphertext) {
        return ciphertext.ciphertext_count();
    };
    const auto account_public_plaintext = [&](const auto &extension) {
        // Public-zero-only messages use the compact bitmap and carry no
        // plaintext records. A mixed message emits one tagged record for
        // every public coefficient, including explicit zero coefficients.
        if (!extension.has_public_nonzero()) {
            return;
        }
        for (const auto &coefficient : extension) {
            if (!coefficient.is_public()) {
                continue;
            }
            ++result.public_plaintext_coefficients;
            result.public_plaintext_field_elements +=
                coefficient.plaintext().is_scalar()
                    ? 1U
                    : coefficient.plaintext().slots().size();
        }
    };
    const auto partial_gate_bytes = [](const auto &partial) {
        return std::size_t{8} +
               partial.evaluations.size() * kSerializedFpkBytes;
    };
    for (const gkr::EncryptedBaseLayerReductionProof<Backend> &reduction :
         proof.reductions) {
        if (const auto *affine =
                std::get_if<gkr::EncryptedBaseAffineLayerReduction<Backend>>(
                    &reduction)) {
            result.logical_round_messages += affine->rounds.size();
            for (const gkr::EncryptedBaseLayerReductionSumcheckRound<Backend> &round :
                 affine->rounds) {
                result.round_message_bytes +=
                    extension_bytes(round.evaluations[0]) +
                    extension_bytes(round.evaluations[1]);
                result.base_ciphertexts +=
                    live_base_ciphertexts(round.evaluations[0]) +
                    live_base_ciphertexts(round.evaluations[1]);
                account_public_plaintext(round.evaluations[0]);
                account_public_plaintext(round.evaluations[1]);
                result.extension_ciphertexts += 2;
            }
            result.terminal_message_bytes +=
                extension_bytes(affine->source_vector);
            result.base_ciphertexts +=
                live_base_ciphertexts(affine->source_vector);
            account_public_plaintext(affine->source_vector);
            result.partial_gate_mle_bytes +=
                partial_gate_bytes(affine->partial_gate_mle);
            ++result.extension_ciphertexts;
        } else {
            const auto &multiplication =
                std::get<
                    gkr::EncryptedBaseMultiplicationLayerReduction<Backend>>(
                    reduction);
            result.logical_round_messages += multiplication.rounds.size();
            for (const gkr::EncryptedBaseLayerReductionSumcheckRound<Backend> &round :
                 multiplication.rounds) {
                result.round_message_bytes +=
                    extension_bytes(round.evaluations[0]) +
                    extension_bytes(round.evaluations[1]);
                result.base_ciphertexts +=
                    live_base_ciphertexts(round.evaluations[0]) +
                    live_base_ciphertexts(round.evaluations[1]);
                account_public_plaintext(round.evaluations[0]);
                account_public_plaintext(round.evaluations[1]);
                result.extension_ciphertexts += 2;
            }
            result.terminal_message_bytes +=
                extension_bytes(multiplication.source_vectors[0]) +
                extension_bytes(multiplication.source_vectors[1]);
            result.base_ciphertexts +=
                live_base_ciphertexts(multiplication.source_vectors[0]) +
                live_base_ciphertexts(multiplication.source_vectors[1]);
            account_public_plaintext(
                multiplication.source_vectors[0]);
            account_public_plaintext(
                multiplication.source_vectors[1]);
            result.extension_ciphertexts += 2;
        }
    }
    if (proof.gate_mle_opening) {
        result.gate_mle_opening_bytes =
            std::size_t{8} +
            gates::encode_canonical(*proof.gate_mle_opening).size();
    }
    const std::size_t ciphertext_bytes =
        result.round_message_bytes + result.terminal_message_bytes;
    if (ciphertext_bytes + result.partial_gate_mle_bytes +
            result.gate_mle_opening_bytes >
        result.total_bytes) {
        throw std::logic_error(
            "measure_proof_size: component bytes exceed proof encoding");
    }
    result.statement_and_metadata_bytes =
        result.total_bytes - ciphertext_bytes -
        result.partial_gate_mle_bytes -
        result.gate_mle_opening_bytes;
    return result;
}

} // namespace laminate::protocol

#endif // LAMINATE_PROTOCOL_DETAIL_PROOF_SIZE_BASE_HPP
