#ifndef LAMINATE_PROTOCOL_DETAIL_PROOF_SIZE_FOLDED_HPP
#define LAMINATE_PROTOCOL_DETAIL_PROOF_SIZE_FOLDED_HPP

/// @file folded.hpp
/// @brief Canonical encoding and exact size accounting for Folded proofs.

#include "laminate/gkr/folded.hpp"
#include "laminate/gkr/detail/shared/packed/transcript.hpp"
#include "laminate/gkr/detail/shared/encoding/canonical.hpp"

namespace laminate::protocol {

template <fhe::FheBackend Backend>
std::vector<std::uint8_t>
encode_canonical(const gkr::EncryptedFoldedProof<Backend> &proof) {
    std::vector<std::uint8_t> output{
        'L', 'M', 'F', 'P',
        static_cast<std::uint8_t>(gkr::kEncryptedFoldedProofVersion)};
    const std::vector<std::uint8_t> header =
        gkr::encode_canonical(proof.header);
    gkr::detail::canonical_encoding::append_size(output, header.size());
    output.insert(output.end(), header.begin(), header.end());
    gkr::detail::canonical_encoding::append_size(
        output, proof.reductions.size());
    for (const gkr::EncryptedFoldedLayerReductionProof<Backend> &reduction :
         proof.reductions) {
        if (const auto *affine =
                std::get_if<gkr::EncryptedFoldedAffineLayerReduction<Backend>>(
                    &reduction)) {
            output.push_back(0);
            gkr::detail::canonical_encoding::append_size(
                output, affine->rounds.size());
            for (const auto &round : affine->rounds) {
                gkr::detail::append_packed_proof_message<
                    gkr::ProtocolVariant::LaminateFolded, Backend>(
                    output, round.packed_evaluations);
            }
            gkr::detail::append_packed_proof_message<
                gkr::ProtocolVariant::LaminateFolded, Backend>(
                output, affine->packed_terminal_value);
        } else {
            const auto &multiplication = std::get<
                gkr::EncryptedFoldedMultiplicationLayerReduction<Backend>>(
                reduction);
            output.push_back(1);
            gkr::detail::canonical_encoding::append_size(
                output, multiplication.rounds.size());
            for (const auto &round : multiplication.rounds) {
                gkr::detail::append_packed_proof_message<
                    gkr::ProtocolVariant::LaminateFolded, Backend>(
                    output, round.packed_evaluations);
            }
            gkr::detail::append_packed_proof_message<
                gkr::ProtocolVariant::LaminateFolded, Backend>(
                output, multiplication.packed_source_values);
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
FoldedProofSizeBreakdown
measure_proof_size(const gkr::EncryptedFoldedProof<Backend> &proof) {
    FoldedProofSizeBreakdown result;
    result.total_bytes = encode_canonical<Backend>(proof).size();
    const auto message_bytes = [](const auto &message) {
        return std::size_t{8} +
               fhe::encode_canonical_fhe_value<Backend>(message).size();
    };
    const auto account_message = [&](const auto &message) {
        if (message.is_encrypted()) {
            ++result.base_ciphertexts;
            return;
        }
        ++result.public_plaintext_coefficients;
        result.public_plaintext_field_elements +=
            message.plaintext().is_scalar()
                ? 1U
                : message.plaintext().slots().size();
    };
    for (const gkr::EncryptedFoldedLayerReductionProof<Backend> &reduction :
         proof.reductions) {
        if (const auto *affine =
                std::get_if<gkr::EncryptedFoldedAffineLayerReduction<Backend>>(
                    &reduction)) {
            result.logical_round_messages += affine->rounds.size();
            for (const auto &round : affine->rounds) {
                result.round_message_bytes +=
                    message_bytes(round.packed_evaluations);
                account_message(round.packed_evaluations);
            }
            result.terminal_message_bytes +=
                message_bytes(affine->packed_terminal_value);
            account_message(affine->packed_terminal_value);
        } else {
            const auto &multiplication = std::get<
                gkr::EncryptedFoldedMultiplicationLayerReduction<Backend>>(
                reduction);
            result.logical_round_messages += multiplication.rounds.size();
            for (const auto &round : multiplication.rounds) {
                result.round_message_bytes +=
                    message_bytes(round.packed_evaluations);
                account_message(round.packed_evaluations);
            }
            result.terminal_message_bytes +=
                message_bytes(multiplication.packed_source_values);
            account_message(multiplication.packed_source_values);
        }
    }
    const std::size_t ciphertext_total =
        result.round_message_bytes + result.terminal_message_bytes;
    if (proof.gate_mle_opening) {
        result.gate_mle_opening_bytes =
            std::size_t{8} +
            gates::encode_canonical(*proof.gate_mle_opening).size();
    }
    if (ciphertext_total + result.gate_mle_opening_bytes >
        result.total_bytes) {
        throw std::logic_error(
            "measure_proof_size(Folded): components exceed encoding");
    }
    result.statement_and_metadata_bytes =
        result.total_bytes - ciphertext_total -
        result.gate_mle_opening_bytes;
    return result;
}

} // namespace laminate::protocol

#endif // LAMINATE_PROTOCOL_DETAIL_PROOF_SIZE_FOLDED_HPP
