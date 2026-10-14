#ifndef LAMINATE_PROTOCOL_DETAIL_PACKING_MESSAGES_HPP
#define LAMINATE_PROTOCOL_DETAIL_PACKING_MESSAGES_HPP

/// @file messages.hpp
/// @brief Canonical traversal and commitment of Folded/Laned GKR messages.

#include "laminate/gkr/folded.hpp"
#include "laminate/gkr/laned.hpp"

#include <span>
#include <utility>
#include <variant>
#include <vector>

namespace laminate::protocol {

/// Visit Folded fixed messages in canonical proof order. Each message is
/// either public plaintext or encrypted and is consumed by transcript
/// packing without manufacturing a ciphertext sentinel.
template <fhe::FheBackend Backend, typename Function>
void for_each_transcript_packing_round_value(
    const gkr::EncryptedFoldedProof<Backend> &proof, Function &&function) {
    for (const auto &reduction : proof.reductions) {
        if (const auto *affine = std::get_if<
                gkr::EncryptedFoldedAffineLayerReduction<Backend>>(&reduction)) {
            for (const auto &round : affine->rounds) {
                function(round.packed_evaluations);
            }
            function(affine->packed_terminal_value);
            continue;
        }

        const auto &multiplication = std::get<
            gkr::EncryptedFoldedMultiplicationLayerReduction<Backend>>(reduction);
        for (const auto &round : multiplication.rounds) {
            function(round.packed_evaluations);
        }
        function(multiplication.packed_source_values);
    }
}

/// Visit Folded public-or-committed messages in canonical GKR order.
template <typename Function>
void for_each_transcript_packing_committed_message(
    const gkr::CommittedFoldedGkrProof &proof, Function &&function) {
    for (const auto &reduction : proof.reductions) {
        if (const auto *affine =
                std::get_if<gkr::CommittedFoldedAffineLayerReduction>(
                    &reduction)) {
            for (const auto &round : affine->rounds) {
                function(round.packed_evaluations);
            }
            function(affine->packed_terminal_value);
            continue;
        }
        const auto &multiplication =
            std::get<gkr::CommittedFoldedMultiplicationLayerReduction>(reduction);
        for (const auto &round : multiplication.rounds) {
            function(round.packed_evaluations);
        }
        function(multiplication.packed_source_values);
    }
}

/// Visit Laned fixed messages in canonical proof order.
template <fhe::FheBackend Backend, typename Function>
void for_each_transcript_packing_round_value(
    const gkr::EncryptedLanedProof<Backend> &proof, Function &&function) {
    for (const auto &reduction : proof.reductions) {
        if (const auto *affine = std::get_if<
                gkr::EncryptedLanedAffineLayerReduction<Backend>>(&reduction)) {
            for (const auto &round : affine->rounds) {
                function(round.packed_evaluations);
            }
            function(affine->packed_terminal_value);
            continue;
        }

        const auto &multiplication = std::get<
            gkr::EncryptedLanedMultiplicationLayerReduction<Backend>>(reduction);
        for (const auto &round : multiplication.rounds) {
            function(round.packed_evaluations);
        }
        function(multiplication.packed_source_values);
    }
}

/// Visit Laned public-or-committed messages in canonical GKR order.
template <typename Function>
void for_each_transcript_packing_committed_message(
    const gkr::CommittedLanedGkrProof &proof, Function &&function) {
    for (const auto &reduction : proof.reductions) {
        if (const auto *affine =
                std::get_if<gkr::CommittedLanedAffineLayerReduction>(
                    &reduction)) {
            for (const auto &round : affine->rounds) {
                function(round.packed_evaluations);
            }
            function(affine->packed_terminal_value);
            continue;
        }
        const auto &multiplication =
            std::get<gkr::CommittedLanedMultiplicationLayerReduction>(reduction);
        for (const auto &round : multiplication.rounds) {
            function(round.packed_evaluations);
        }
        function(multiplication.packed_source_values);
    }
}

template <fhe::FheBackend Backend, typename Proof>
std::vector<fhe::FheValue<Backend>>
collect_transcript_packing_round_values(const Proof &proof) {
    std::vector<fhe::FheValue<Backend>> result;
    for_each_transcript_packing_round_value<Backend>(
        proof, [&](const fhe::FheValue<Backend> &value) {
            result.push_back(value);
        });
    return result;
}

template <typename CommittedProof>
std::vector<gkr::CommittedPackedMessage>
collect_transcript_packing_committed_messages(
    const CommittedProof &proof) {
    std::vector<gkr::CommittedPackedMessage> result;
    for_each_transcript_packing_committed_message(
        proof, [&](const gkr::CommittedPackedMessage &message) {
            result.push_back(message);
        });
    return result;
}

/// Build a compact ordered view without copying public N-slot plaintexts.
/// The proof must outlive the returned pointers.
template <typename CommittedProof>
std::vector<const gkr::CommittedPackedMessage *>
view_transcript_packing_committed_messages(const CommittedProof &proof) {
    std::vector<const gkr::CommittedPackedMessage *> result;
    for_each_transcript_packing_committed_message(
        proof, [&](const gkr::CommittedPackedMessage &message) {
            result.push_back(&message);
        });
    return result;
}

template <fhe::FheBackend Backend>
gkr::CommittedFoldedGkrProof commit_gkr_round_messages(
    const gkr::EncryptedFoldedProof<Backend> &encrypted) {
    gkr::CommittedFoldedGkrProof committed{
        .header = encrypted.header,
        .gate_mle_opening = encrypted.gate_mle_opening,
    };
    committed.reductions.reserve(encrypted.reductions.size());
    for (const auto &reduction : encrypted.reductions) {
        if (const auto *affine =
                std::get_if<gkr::EncryptedFoldedAffineLayerReduction<Backend>>(
                    &reduction)) {
            gkr::CommittedFoldedAffineLayerReduction result;
            result.rounds.reserve(affine->rounds.size());
            for (const auto &round : affine->rounds) {
                result.rounds.push_back(gkr::CommittedFoldedLayerReductionSumcheckRound{
                    gkr::commit_packed_message<Backend>(
                        round.packed_evaluations)});
            }
            result.packed_terminal_value =
                gkr::commit_packed_message<Backend>(
                affine->packed_terminal_value);
            committed.reductions.emplace_back(std::move(result));
            continue;
        }
        const auto &multiplication =
            std::get<gkr::EncryptedFoldedMultiplicationLayerReduction<Backend>>(
                reduction);
        gkr::CommittedFoldedMultiplicationLayerReduction result;
        result.rounds.reserve(multiplication.rounds.size());
        for (const auto &round : multiplication.rounds) {
            result.rounds.push_back(gkr::CommittedFoldedLayerReductionSumcheckRound{
                gkr::commit_packed_message<Backend>(
                    round.packed_evaluations)});
        }
        result.packed_source_values =
            gkr::commit_packed_message<Backend>(
            multiplication.packed_source_values);
        committed.reductions.emplace_back(std::move(result));
    }
    return committed;
}

/// Build the committed Folded proof from commitments already observed by the
/// online GKR prover. Their order and count must exactly match the encrypted
/// proof traversal; no transient round-ciphertext encoding is re-hashed.
template <fhe::FheBackend Backend>
gkr::CommittedFoldedGkrProof commit_gkr_round_messages(
    const gkr::EncryptedFoldedProof<Backend> &encrypted,
    std::span<const gkr::HashCommitCT> commitments) {
    gkr::CommittedFoldedGkrProof committed{
        .header = encrypted.header,
        .gate_mle_opening = encrypted.gate_mle_opening,
    };
    std::size_t next = 0;
    const auto take = [&]() -> gkr::HashCommitCT {
        if (next >= commitments.size()) {
            throw std::invalid_argument(
                "Folded commitment list is shorter than the GKR proof");
        }
        return commitments[next++];
    };
    const auto take_message = [&](const fhe::FheValue<Backend> &value) {
        const gkr::PackedMessageCommitment commitment = take();
        return value.is_public()
                   ? gkr::CommittedPackedMessage::public_message(
                         value.plaintext())
                   : gkr::CommittedPackedMessage::encrypted_message(
                         commitment);
    };
    committed.reductions.reserve(encrypted.reductions.size());
    for (const auto &reduction : encrypted.reductions) {
        if (const auto *affine =
                std::get_if<gkr::EncryptedFoldedAffineLayerReduction<Backend>>(
                    &reduction)) {
            gkr::CommittedFoldedAffineLayerReduction result;
            result.rounds.reserve(affine->rounds.size());
            for (const auto &round : affine->rounds) {
                result.rounds.push_back(
                    gkr::CommittedFoldedLayerReductionSumcheckRound{
                        take_message(round.packed_evaluations)});
            }
            result.packed_terminal_value =
                take_message(affine->packed_terminal_value);
            committed.reductions.emplace_back(std::move(result));
            continue;
        }
        const auto &multiplication =
            std::get<gkr::EncryptedFoldedMultiplicationLayerReduction<Backend>>(
                reduction);
        gkr::CommittedFoldedMultiplicationLayerReduction result;
        result.rounds.reserve(multiplication.rounds.size());
        for (const auto &round : multiplication.rounds) {
            result.rounds.push_back(gkr::CommittedFoldedLayerReductionSumcheckRound{
                take_message(round.packed_evaluations)});
        }
        result.packed_source_values =
            take_message(multiplication.packed_source_values);
        committed.reductions.emplace_back(std::move(result));
    }
    if (next != commitments.size()) {
        throw std::invalid_argument(
            "Folded commitment list is longer than the GKR proof");
    }
    return committed;
}

template <fhe::FheBackend Backend>
gkr::CommittedLanedGkrProof commit_gkr_round_messages(
    const gkr::EncryptedLanedProof<Backend> &encrypted) {
    gkr::CommittedLanedGkrProof committed{
        .header = encrypted.header,
        .gate_mle_opening = encrypted.gate_mle_opening,
    };
    committed.reductions.reserve(encrypted.reductions.size());
    for (const auto &reduction : encrypted.reductions) {
        if (const auto *affine =
                std::get_if<gkr::EncryptedLanedAffineLayerReduction<Backend>>(
                    &reduction)) {
            gkr::CommittedLanedAffineLayerReduction result;
            result.rounds.reserve(affine->rounds.size());
            for (const auto &round : affine->rounds) {
                result.rounds.push_back(gkr::CommittedLanedLayerReductionSumcheckRound{
                    gkr::commit_packed_message<Backend>(
                        round.packed_evaluations)});
            }
            result.packed_terminal_value =
                gkr::commit_packed_message<Backend>(
                affine->packed_terminal_value);
            committed.reductions.emplace_back(std::move(result));
            continue;
        }
        const auto &multiplication =
            std::get<gkr::EncryptedLanedMultiplicationLayerReduction<Backend>>(
                reduction);
        gkr::CommittedLanedMultiplicationLayerReduction result;
        result.rounds.reserve(multiplication.rounds.size());
        for (const auto &round : multiplication.rounds) {
            result.rounds.push_back(gkr::CommittedLanedLayerReductionSumcheckRound{
                gkr::commit_packed_message<Backend>(
                    round.packed_evaluations)});
        }
        result.packed_source_values =
            gkr::commit_packed_message<Backend>(
            multiplication.packed_source_values);
        committed.reductions.emplace_back(std::move(result));
    }
    return committed;
}

/// Laned counterpart of the online-aligned commitment adapter.
template <fhe::FheBackend Backend>
gkr::CommittedLanedGkrProof commit_gkr_round_messages(
    const gkr::EncryptedLanedProof<Backend> &encrypted,
    std::span<const gkr::HashCommitCT> commitments) {
    gkr::CommittedLanedGkrProof committed{
        .header = encrypted.header,
        .gate_mle_opening = encrypted.gate_mle_opening,
    };
    std::size_t next = 0;
    const auto take = [&]() -> gkr::HashCommitCT {
        if (next >= commitments.size()) {
            throw std::invalid_argument(
                "Laned commitment list is shorter than the GKR proof");
        }
        return commitments[next++];
    };
    const auto take_message = [&](const fhe::FheValue<Backend> &value) {
        const gkr::PackedMessageCommitment commitment = take();
        return value.is_public()
                   ? gkr::CommittedPackedMessage::public_message(
                         value.plaintext())
                   : gkr::CommittedPackedMessage::encrypted_message(
                         commitment);
    };
    committed.reductions.reserve(encrypted.reductions.size());
    for (const auto &reduction : encrypted.reductions) {
        if (const auto *affine =
                std::get_if<gkr::EncryptedLanedAffineLayerReduction<Backend>>(
                    &reduction)) {
            gkr::CommittedLanedAffineLayerReduction result;
            result.rounds.reserve(affine->rounds.size());
            for (const auto &round : affine->rounds) {
                result.rounds.push_back(
                    gkr::CommittedLanedLayerReductionSumcheckRound{
                        take_message(round.packed_evaluations)});
            }
            result.packed_terminal_value =
                take_message(affine->packed_terminal_value);
            committed.reductions.emplace_back(std::move(result));
            continue;
        }
        const auto &multiplication =
            std::get<gkr::EncryptedLanedMultiplicationLayerReduction<Backend>>(
                reduction);
        gkr::CommittedLanedMultiplicationLayerReduction result;
        result.rounds.reserve(multiplication.rounds.size());
        for (const auto &round : multiplication.rounds) {
            result.rounds.push_back(gkr::CommittedLanedLayerReductionSumcheckRound{
                take_message(round.packed_evaluations)});
        }
        result.packed_source_values =
            take_message(multiplication.packed_source_values);
        committed.reductions.emplace_back(std::move(result));
    }
    if (next != commitments.size()) {
        throw std::invalid_argument(
            "Laned commitment list is longer than the GKR proof");
    }
    return committed;
}

} // namespace laminate::protocol

#endif // LAMINATE_PROTOCOL_DETAIL_PACKING_MESSAGES_HPP
