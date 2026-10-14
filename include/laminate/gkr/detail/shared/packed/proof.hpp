#ifndef LAMINATE_GKR_DETAIL_SHARED_PACKED_PROOF_HPP
#define LAMINATE_GKR_DETAIL_SHARED_PACKED_PROOF_HPP

/// @file proof.hpp
/// @brief Neutral proof-message schema shared by Folded and Laned GKR.

#include "laminate/gates/outsourced.hpp"
#include "laminate/gkr/ciphertext_commitment.hpp"
#include "laminate/gkr/proof.hpp"

#include <cstdint>
#include <optional>
#include <string_view>
#include <variant>
#include <vector>

namespace laminate::gkr::detail {

/// Wire and transcript constants for one packed GKR protocol variant.
///
/// The schema below is common to Folded and Laned. The trait keeps their
/// domain separation and independently versioned canonical encodings
/// explicit instead of scattering variant tests through the data model.
template <ProtocolVariant Variant> struct PackedProofTraits;

template <>
struct PackedProofTraits<ProtocolVariant::LaminateFolded> {
    static constexpr std::uint64_t proof_version = 9;
    static constexpr std::string_view message_description =
        "LaminateFolded packed proof message";
    static constexpr std::string_view begin_label =
        "laminate/folded/reduction/v1";
    static constexpr std::string_view round_label =
        "laminate/folded/round/v3";
    static constexpr std::string_view terminal_label =
        "laminate/folded/terminal/v2";
};

template <>
struct PackedProofTraits<ProtocolVariant::LaminateLaned> {
    static constexpr std::uint64_t proof_version = 8;
    static constexpr std::string_view message_description =
        "LaminateLaned packed proof message";
    static constexpr std::string_view begin_label =
        "laminate/laned/reduction/v1";
    static constexpr std::string_view round_label =
        "laminate/laned/round/v3";
    static constexpr std::string_view terminal_label =
        "laminate/laned/terminal/v2";
};

template <ProtocolVariant Variant>
inline constexpr bool kIsPackedProofVariant =
    Variant == ProtocolVariant::LaminateFolded ||
    Variant == ProtocolVariant::LaminateLaned;

/// One fixed-size packed sumcheck message.
template <typename Message, ProtocolVariant Variant> struct PackedRound {
    static_assert(kIsPackedProofVariant<Variant>);
    Message packed_evaluations;
};

/// Packed affine sumcheck rounds followed by one terminal source message.
template <typename Message, ProtocolVariant Variant>
struct PackedAffineReduction {
    static_assert(kIsPackedProofVariant<Variant>);
    std::vector<PackedRound<Message, Variant>> rounds;
    Message packed_terminal_value;
};

/// Packed multiplication sumcheck rounds followed by both source values.
template <typename Message, ProtocolVariant Variant>
struct PackedMultiplicationReduction {
    static_assert(kIsPackedProofVariant<Variant>);
    std::vector<PackedRound<Message, Variant>> rounds;
    Message packed_source_values;
};

template <typename Message, ProtocolVariant Variant>
using PackedLayerProof =
    std::variant<PackedAffineReduction<Message, Variant>,
                 PackedMultiplicationReduction<Message, Variant>>;

/// Complete packed GKR proof, before or after fixed-message commitment.
template <typename Message, ProtocolVariant Variant>
struct PackedGkrProof {
    static_assert(kIsPackedProofVariant<Variant>);
    ProofHeader header;
    std::vector<PackedLayerProof<Message, Variant>> reductions;
    std::optional<gates::OutsourcedGateMleProof> gate_mle_opening;
};

} // namespace laminate::gkr::detail

#endif // LAMINATE_GKR_DETAIL_SHARED_PACKED_PROOF_HPP
