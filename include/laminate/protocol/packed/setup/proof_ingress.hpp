#ifndef LAMINATE_PROTOCOL_PACKED_SETUP_PROOF_INGRESS_HPP
#define LAMINATE_PROTOCOL_PACKED_SETUP_PROOF_INGRESS_HPP

/// @file proof_ingress.hpp
/// @brief Public policies that select the RNS level entering packed GKR.

#include "laminate/payload/setup/encoding.hpp"
#include "laminate/payload/ir/layered.hpp"
#include "laminate/setup.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace laminate::protocol {

struct MinimumRnsCompletenessAnalysis;

enum class PackingGkrVariant : std::uint8_t { Folded = 0, Laned = 1 };

/// Stable policy used by routine Folded/Laned setup. The policy is deliberately
/// conservative: it fixes one topology-derived ingress vector without running
/// an FHE execution, a proof replay, or the exhaustive completeness search.
/// It makes no claim that the vector is minimal or that a particular modulus
/// chain is complete for honest execution. Exhaustive analysis remains an
/// offline calibration tool.
inline constexpr std::string_view kConservativePackedProofIngressPolicyV1 =
    "LaminateImpl/ConservativePackedProofIngress/v1";
inline constexpr std::string_view kConservativePackedProofIngressPolicyV3 =
    "LaminateImpl/ConservativePackedProofIngress/v3";
inline constexpr std::string_view kConservativePackedProofIngressPolicyV4 =
    "LaminateImpl/ConservativePackedProofIngress/v4";

/// An explicit setup choice. VariantDefault preserves Folded v1 and Laned v3;
/// FoldedAffine4 reserves four affine-source limbs and six multiplication
/// limbs. It is selected only by the Folded pyramid benchmark profile.
enum class ConservativePackedProofIngressPolicy : std::uint8_t {
    VariantDefault = 0,
    FoldedAffine4 = 1,
};

/// Default Folded uses v1. Laned uses v3, which accounts for witness packing
/// at B<N and its bypass at B=N. The explicit Folded affine4 choice uses v4.
inline constexpr std::string_view conservative_packed_proof_ingress_policy(
    PackingGkrVariant variant,
    ConservativePackedProofIngressPolicy policy =
        ConservativePackedProofIngressPolicy::VariantDefault) {
    if (policy == ConservativePackedProofIngressPolicy::FoldedAffine4 &&
        variant == PackingGkrVariant::Folded) {
        return kConservativePackedProofIngressPolicyV4;
    }
    if (policy != ConservativePackedProofIngressPolicy::VariantDefault ||
        (variant != PackingGkrVariant::Folded &&
         variant != PackingGkrVariant::Laned)) {
        throw std::invalid_argument("unsupported packed proof-ingress policy");
    }
    return variant == PackingGkrVariant::Folded
               ? kConservativePackedProofIngressPolicyV1
               : kConservativePackedProofIngressPolicyV3;
}

inline constexpr ConservativePackedProofIngressPolicy
conservative_packed_proof_ingress_policy_selection(
    PackingGkrVariant variant, std::string_view policy) {
    if (policy == conservative_packed_proof_ingress_policy(variant))
        return ConservativePackedProofIngressPolicy::VariantDefault;
    if (variant == PackingGkrVariant::Folded &&
        policy == kConservativePackedProofIngressPolicyV4)
        return ConservativePackedProofIngressPolicy::FoldedAffine4;
    throw std::invalid_argument("unsupported packed proof-ingress policy");
}

/// Proof depths used by the fixed policy. An RNS limb count is depth plus
/// one. The affine depths include the transcript-packing reserve; Laned also
/// reserves a level for equality-weighted packing. Its multiplication depth
/// depends on whether source witnesses need packing, as described below.
inline constexpr std::size_t kConservativeFoldedAffineProofDepth =
    kPackingReservedMultDepth;
inline constexpr std::size_t kConservativeLanedAffineProofDepth =
    kPackingReservedMultDepth + 1U;
inline constexpr std::size_t
    kConservativeFoldedMultiplicationProofDepth = 5;
inline constexpr std::size_t
    kConservativeLanedMultiplicationProofDepth = 6;
inline constexpr std::size_t
    kConservativeFullWidthLanedMultiplicationProofDepth =
        kConservativeLanedMultiplicationProofDepth - 1U;

/// B<N reserves one level for packing source chunks into witness ciphertexts.
/// At B=N the source is already packed: both resident and file-backed kernels
/// borrow it without a plaintext mask or the corresponding RNS-level drop.
inline constexpr std::size_t conservative_laned_multiplication_proof_depth(
    std::size_t lanes, std::size_t slots) {
    if (lanes == 0 || slots == 0 || lanes > slots || slots % lanes != 0) {
        throw std::invalid_argument(
            "Laned proof ingress has invalid lane geometry");
    }
    return lanes == slots
               ? kConservativeFullWidthLanedMultiplicationProofDepth
               : kConservativeLanedMultiplicationProofDepth;
}

/// Immutable setup-bound result of the fixed conservative policy. Its digest
/// commits to the policy version, variant, circuit, complete public setup, and
/// every entry of the per-layer vector. Construction is restricted to the
/// topology-only derivation function below.
class ConservativePackedProofIngressSchedule {
  public:
    ConservativePackedProofIngressSchedule(
        const ConservativePackedProofIngressSchedule &) = default;
    ConservativePackedProofIngressSchedule &operator=(
        const ConservativePackedProofIngressSchedule &) = default;
    ConservativePackedProofIngressSchedule(
        ConservativePackedProofIngressSchedule &&) noexcept = default;
    ConservativePackedProofIngressSchedule &operator=(
        ConservativePackedProofIngressSchedule &&) noexcept = default;

    PackingGkrVariant variant() const noexcept { return variant_; }
    std::string_view policy() const noexcept {
        return conservative_packed_proof_ingress_policy(variant_, policy_);
    }
    ConservativePackedProofIngressPolicy policy_selection() const noexcept {
        return policy_;
    }
    std::span<const std::size_t> rns_limbs_by_layer() const noexcept {
        return rns_limbs_by_layer_;
    }
    const Digest &circuit_id() const noexcept { return circuit_id_; }
    const Digest &public_setup_id() const noexcept {
        return public_setup_id_;
    }
    const Digest &digest() const noexcept { return digest_; }

    bool operator==(
        const ConservativePackedProofIngressSchedule &) const = default;

  private:
    ConservativePackedProofIngressSchedule() = default;

    friend ConservativePackedProofIngressSchedule
    derive_conservative_packed_proof_ingress_schedule(
        PackingGkrVariant, const payload::PayloadCircuit &,
        const payload::LayeredCircuit &, const PublicSetup &,
        ConservativePackedProofIngressPolicy);

    PackingGkrVariant variant_ = PackingGkrVariant::Folded;
    ConservativePackedProofIngressPolicy policy_ =
        ConservativePackedProofIngressPolicy::VariantDefault;
    std::vector<std::size_t> rns_limbs_by_layer_;
    Digest circuit_id_{};
    Digest public_setup_id_{};
    Digest digest_{};
};

/// Canonical setup-binding encoding. This low-level helper authenticates its
/// inputs but does not certify that a caller-supplied vector follows the fixed
/// policy; use `derive_conservative_packed_proof_ingress_schedule` for that.
std::vector<std::uint8_t>
encode_conservative_packed_proof_ingress_schedule(
    PackingGkrVariant variant, const Digest &circuit_id,
    const Digest &public_setup_id,
    std::span<const std::size_t> rns_limbs_by_layer,
    ConservativePackedProofIngressPolicy policy =
        ConservativePackedProofIngressPolicy::VariantDefault);

Digest conservative_packed_proof_ingress_schedule_digest(
    PackingGkrVariant variant, const Digest &circuit_id,
    const Digest &public_setup_id,
    std::span<const std::size_t> rns_limbs_by_layer,
    ConservativePackedProofIngressPolicy policy =
        ConservativePackedProofIngressPolicy::VariantDefault);

/// Derive the routine setup policy from public topology only. The public setup
/// is validated against the payload/circuit pair before its complete digest is
/// bound. No backend context, ciphertext, trace, proof, or secret information
/// is accepted by this API.
ConservativePackedProofIngressSchedule
derive_conservative_packed_proof_ingress_schedule(
    PackingGkrVariant variant, const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const PublicSetup &public_setup,
    ConservativePackedProofIngressPolicy policy =
        ConservativePackedProofIngressPolicy::VariantDefault);

/// Re-derive the fixed policy and reject a schedule from another variant,
/// circuit, public setup, policy version, or per-layer vector.
void validate_conservative_packed_proof_ingress_schedule(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const PublicSetup &public_setup,
    const ConservativePackedProofIngressSchedule &schedule);

/// Exact proof-ingress selection projected from a complete RNS-prefix
/// analysis. Construction is private so a raw caller-supplied integer cannot
/// masquerade as a certificate-derived level choice.
class CertifiedProofIngressRnsSelection {
  public:
    PackingGkrVariant variant() const noexcept { return variant_; }
    std::span<const std::size_t> exact_rns_limbs_by_layer() const noexcept {
        return exact_rns_limbs_by_layer_;
    }
    const Digest &circuit_id() const noexcept { return circuit_id_; }
    const Digest &setup_id() const noexcept { return setup_id_; }
    bool live_schedule_parity_established() const noexcept {
        return live_schedule_parity_established_;
    }

  private:
    friend CertifiedProofIngressRnsSelection
    select_proof_ingress_rns_limbs(
        const MinimumRnsCompletenessAnalysis &analysis);

    PackingGkrVariant variant_ = PackingGkrVariant::Folded;
    std::vector<std::size_t> exact_rns_limbs_by_layer_;
    Digest circuit_id_{};
    Digest setup_id_{};
    bool live_schedule_parity_established_ = false;
};

/// Project an exact per-layer schedule from an exhaustive successful
/// Folded/Laned completeness analysis. Every proof-source coordinate must be
/// minimal against the final selected vector. Malformed, incomplete, Base,
/// uniform-only, or unsuccessful analyses are rejected.
CertifiedProofIngressRnsSelection select_proof_ingress_rns_limbs(
    const MinimumRnsCompletenessAnalysis &analysis);

} // namespace laminate::protocol

#endif // LAMINATE_PROTOCOL_PACKED_SETUP_PROOF_INGRESS_HPP
