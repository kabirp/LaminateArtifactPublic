#ifndef LAMINATE_GKR_FOLDED_HPP
#define LAMINATE_GKR_FOLDED_HPP

/// @file folded.hpp
/// @brief Encrypted and committed Folded GKR proof-message types.

#include "laminate/gkr/base.hpp"
#include "laminate/gkr/ciphertext_commitment.hpp"
#include "laminate/gkr/detail/shared/packed/proof.hpp"
#include "laminate/fhe/value.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <variant>
#include <vector>

namespace laminate::gkr {

inline constexpr std::uint64_t kEncryptedFoldedProofVersion =
    detail::PackedProofTraits<
        ProtocolVariant::LaminateFolded>::proof_version;

/// Slots 0..7 encode R(1) in affine rounds and S(0) in multiplication rounds.
/// Multiplication uses S(1) when the corresponding output coordinate is zero.
/// Slots 8..15 encode the evaluation at two in either case.
template <typename Message>
using FoldedLayerReductionSumcheckRound = detail::PackedRound<
    Message, ProtocolVariant::LaminateFolded>;

/// Folded affine rounds and their terminal source-layer evaluation.
template <typename Message>
using FoldedAffineLayerReduction = detail::PackedAffineReduction<
    Message, ProtocolVariant::LaminateFolded>;

/// Folded multiplication rounds; terminal slots 0..7 encode the left source
/// evaluation and slots 8..15 encode the right source evaluation.
template <typename Message>
using FoldedMultiplicationLayerReduction =
    detail::PackedMultiplicationReduction<
        Message, ProtocolVariant::LaminateFolded>;

template <typename Message>
using FoldedLayerReductionProof =
    detail::PackedLayerProof<Message,
                             ProtocolVariant::LaminateFolded>;

template <typename Message>
using FoldedGkrProof = detail::PackedGkrProof<
    Message, ProtocolVariant::LaminateFolded>;

template <fhe::FheBackend Backend>
using EncryptedFoldedLayerReductionSumcheckRound =
    FoldedLayerReductionSumcheckRound<fhe::FheValue<Backend>>;
template <fhe::FheBackend Backend>
using EncryptedFoldedAffineLayerReduction =
    FoldedAffineLayerReduction<fhe::FheValue<Backend>>;
template <fhe::FheBackend Backend>
using EncryptedFoldedMultiplicationLayerReduction =
    FoldedMultiplicationLayerReduction<fhe::FheValue<Backend>>;
template <fhe::FheBackend Backend>
using EncryptedFoldedLayerReductionProof =
    FoldedLayerReductionProof<fhe::FheValue<Backend>>;
template <fhe::FheBackend Backend>
using EncryptedFoldedProof =
    FoldedGkrProof<fhe::FheValue<Backend>>;

using CommittedFoldedLayerReductionSumcheckRound =
    FoldedLayerReductionSumcheckRound<CommittedPackedMessage>;
using CommittedFoldedAffineLayerReduction =
    FoldedAffineLayerReduction<CommittedPackedMessage>;
using CommittedFoldedMultiplicationLayerReduction =
    FoldedMultiplicationLayerReduction<CommittedPackedMessage>;
using CommittedFoldedLayerReductionProof =
    FoldedLayerReductionProof<CommittedPackedMessage>;
using CommittedFoldedGkrProof =
    FoldedGkrProof<CommittedPackedMessage>;

} // namespace laminate::gkr

#endif // LAMINATE_GKR_FOLDED_HPP
