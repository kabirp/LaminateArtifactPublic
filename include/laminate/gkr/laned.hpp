#ifndef LAMINATE_GKR_LANED_HPP
#define LAMINATE_GKR_LANED_HPP

/// @file laned.hpp
/// @brief Encrypted and committed Laned GKR proof-message types and geometry.

#include "laminate/gkr/base.hpp"
#include "laminate/gkr/ciphertext_commitment.hpp"
#include "laminate/gkr/detail/shared/packed/proof.hpp"
#include "laminate/fhe/value.hpp"
#include "laminate/packing/alignment/laned.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <variant>
#include <vector>

namespace laminate::gkr {

inline constexpr std::uint64_t kEncryptedLanedProofVersion =
    detail::PackedProofTraits<
        ProtocolVariant::LaminateLaned>::proof_version;

/// Affine rounds encode R(1),R(2). Dense multiplication rounds encode
/// S(0),S(2), except that tau=0 deterministically uses S(1),S(2).
template <typename Message>
using LanedLayerReductionSumcheckRound = detail::PackedRound<
    Message, ProtocolVariant::LaminateLaned>;

/// Laned affine rounds and the terminal evaluation of the lazy eq-weighted
/// table H.
template <typename Message>
using LanedAffineLayerReduction = detail::PackedAffineReduction<
    Message, ProtocolVariant::LaminateLaned>;

/// Laned multiplication rounds and the dense left/right source evaluations.
template <typename Message>
using LanedMultiplicationLayerReduction =
    detail::PackedMultiplicationReduction<
        Message, ProtocolVariant::LaminateLaned>;

template <typename Message>
using LanedLayerReductionProof =
    detail::PackedLayerProof<Message,
                             ProtocolVariant::LaminateLaned>;

template <typename Message>
using LanedGkrProof = detail::PackedGkrProof<
    Message, ProtocolVariant::LaminateLaned>;

template <fhe::FheBackend Backend>
using EncryptedLanedLayerReductionSumcheckRound =
    LanedLayerReductionSumcheckRound<fhe::FheValue<Backend>>;
template <fhe::FheBackend Backend>
using EncryptedLanedAffineLayerReduction =
    LanedAffineLayerReduction<fhe::FheValue<Backend>>;
template <fhe::FheBackend Backend>
using EncryptedLanedMultiplicationLayerReduction =
    LanedMultiplicationLayerReduction<fhe::FheValue<Backend>>;
template <fhe::FheBackend Backend>
using EncryptedLanedLayerReductionProof =
    LanedLayerReductionProof<fhe::FheValue<Backend>>;
template <fhe::FheBackend Backend>
using EncryptedLanedProof = LanedGkrProof<fhe::FheValue<Backend>>;

using CommittedLanedLayerReductionSumcheckRound =
    LanedLayerReductionSumcheckRound<CommittedPackedMessage>;
using CommittedLanedAffineLayerReduction =
    LanedAffineLayerReduction<CommittedPackedMessage>;
using CommittedLanedMultiplicationLayerReduction =
    LanedMultiplicationLayerReduction<CommittedPackedMessage>;
using CommittedLanedLayerReductionProof =
    LanedLayerReductionProof<CommittedPackedMessage>;
using CommittedLanedGkrProof = LanedGkrProof<CommittedPackedMessage>;

packing::LanedPackingLayout
laned_layout(const payload::LayeredCircuit &circuit, std::size_t layer);

std::size_t
laned_layer_variables(const payload::LayeredCircuit &circuit,
                      std::size_t layer);

Fpk evaluate_packed_laned_layer(
    std::span<const fhe::SlotVector> layer,
    const packing::LanedPackingLayout &layout,
    std::span<const Fpk> point);

SingleClaim make_packed_laned_claim(
    std::span<const fhe::SlotVector> layer,
    const packing::LanedPackingLayout &layout, std::vector<Fpk> point);

} // namespace laminate::gkr

#include "laminate/gkr/detail/laned/geometry/layers.hpp"

#endif // LAMINATE_GKR_LANED_HPP
