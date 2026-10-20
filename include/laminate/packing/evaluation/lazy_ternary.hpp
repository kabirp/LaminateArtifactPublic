#ifndef LAMINATE_PACKING_EVALUATION_LAZY_TERNARY_HPP
#define LAMINATE_PACKING_EVALUATION_LAZY_TERNARY_HPP

/// @file lazy_ternary.hpp
/// @brief Lazy-ternary transcript-packing operations and client checks.
///
/// This module evaluates the ciphertext operations and client checks used by
/// transcript packing. Its result is not a proof on its own: the composed
/// protocol separately proves that each reveal is the prescribed linear
/// combination. Standalone uses are completeness and noise diagnostics only.

#include "laminate/crypto/poseidon.hpp"
#include "laminate/fhe/value.hpp"
#include "laminate/packing/alignment/layout.hpp"
#include "laminate/packing/evaluation/signed_digits.hpp"
#include "laminate/packing/evaluation/well_formedness.hpp"
#include "laminate/params.hpp"

#include <concepts>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace laminate::packing {

/// Public, transcript-bound inputs to the selected evaluation. The error
/// bound is a setup promise, never a value inferred from a live secret-key
/// measurement.
struct LazyTernaryParameters {
    std::size_t repetitions = kPackingWellFormednessRepetitions;
    std::uint64_t honest_error_bound =
        kSelectedPackingHonestErrorBound;
    BalancedRadix packing_radix;

    std::uint64_t honest_partial_decryption_bound() const {
        return canonical_partial_decryption_bound(
            packing_radix.plaintext_modulus, honest_error_bound);
    }

    bool operator==(const LazyTernaryParameters &) const = default;
};

/// Parameters used by the transcript-packing wire format. Keeping this factory
/// explicit prevents an in-memory default from silently changing that format.
inline LazyTernaryParameters selected_lazy_ternary_parameters() {
    return LazyTernaryParameters{
        .repetitions = kPackingWellFormednessRepetitions,
        .honest_error_bound = kSelectedPackingHonestErrorBound,
        .packing_radix = make_minimal_balanced_radix(
            kBaseFieldOrder, kSelectedPackingRadixBase),
    };
}

/// Backend operations needed at the coefficient-commitment boundary.
template <typename Backend>
concept CoefficientWellFormednessBackend =
    fhe::FheBackend<Backend> &&
    requires(const typename Backend::EvalContext &eval,
             const typename Backend::ClientContext &client,
             typename Backend::Ciphertext &mutable_ciphertext,
             const typename Backend::Ciphertext &ciphertext,
             std::uint64_t threshold) {
        {
            Backend::normalize_for_coefficient_commitment(
                eval, mutable_ciphertext)
        } -> std::same_as<void>;
        {
            Backend::is_normalized_for_coefficient_commitment(ciphertext)
        } -> std::convertible_to<bool>;
        {
            Backend::partial_decryption_infinity_norm(client, ciphertext)
        } -> std::convertible_to<std::uint64_t>;
        {
            Backend::partial_decryption_within_bound(
                client, ciphertext, threshold)
        } -> std::convertible_to<bool>;
    };

/// Public bottom-q coordinate operations used by the selected packing proof.
/// Bound-only completeness backends intentionally satisfy only the smaller
/// coefficient-well-formedness concept above.
template <typename Backend>
concept PublicCoefficientEncodingBackend =
    CoefficientWellFormednessBackend<Backend> &&
    requires(const typename Backend::EvalContext &eval,
             const typename Backend::ClientContext &client,
             const typename Backend::Ciphertext &ciphertext,
             const typename Backend::Ciphertext *optional_ciphertext,
             const fhe::SlotVector &slots,
             std::span<const std::int64_t> centered_coefficients,
             std::span<const std::uint64_t> public_c0_coordinates) {
        {
            Backend::encode_centered_plaintext_coefficients(eval, slots)
        } -> std::same_as<std::vector<std::int64_t>>;
        {
            Backend::encode_lowest_plaintext_ntt_coordinates(
                eval, centered_coefficients)
        } -> std::same_as<std::vector<std::uint64_t>>;
        {
            Backend::coefficient_commitment_ntt_coordinate_view(ciphertext)
        } -> std::same_as<std::span<const std::uint64_t>>;
        {
            Backend::partial_decryption_with_public_ntt_offset_infinity_norm(
                client, optional_ciphertext, public_c0_coordinates)
        } -> std::convertible_to<std::uint64_t>;
    };

/// Additional public encoding operations needed to execute coefficient-small
/// signed-digit packing with the real plaintext-ring representation.
template <typename Backend>
concept SignedDigitPackingBackend =
    PublicCoefficientEncodingBackend<Backend> &&
    requires(const typename Backend::EvalContext &eval,
             const fhe::SlotVector &slots,
             std::span<const std::int64_t> coefficients) {
        {
            Backend::encode_centered_plaintext_coefficients(eval, slots)
        } -> std::same_as<std::vector<std::int64_t>>;
        {
            Backend::decode_centered_plaintext_coefficients(
                eval, coefficients)
        } -> std::same_as<fhe::SlotVector>;
    };

/// Key-free context operations used while reconstructing the verifier's
/// public transcript-packing statement. Production verification passes a
/// restricted PublicVerifierContext. EvalContext remains accepted only so
/// reference and diagnostic adapters can exercise the same implementation.
template <typename Backend, typename Context>
concept PublicCoefficientVerifierContext =
    PublicCoefficientEncodingBackend<Backend> &&
    requires(const Context &context,
             const typename Backend::Ciphertext &ciphertext,
             const fhe::SlotVector &slots,
             std::span<const std::int64_t> centered_coefficients) {
        { Backend::slot_count(context) } ->
            std::convertible_to<std::size_t>;
        { Backend::rns_limb_count(context, ciphertext) } ->
            std::convertible_to<std::size_t>;
        {
            Backend::encode_centered_plaintext_coefficients(context, slots)
        } -> std::same_as<std::vector<std::int64_t>>;
        {
            Backend::decode_centered_plaintext_coefficients(
                context, centered_coefficients)
        } -> std::same_as<fhe::SlotVector>;
        {
            Backend::encode_lowest_plaintext_ntt_coordinates(
                context, centered_coefficients)
        } -> std::same_as<std::vector<std::uint64_t>>;
    };

/// Canonical aligned inputs denoted by `r` in the selected fixed-message
/// profile. Generic diagnostic layouts may split one BhIP round into multiple
/// aligned inputs.
///
/// Encrypted entries are rotated and then required to be size two, one-prime,
/// NTT-form, and normalized to BGV correction factor one. Public entries use
/// the same formal coordinate space without constructing a transparent SEAL
/// ciphertext: `c0` is the public plaintext's bottom-prime NTT lift and `c1`
/// is the zero polynomial. `public_coordinates[i]` owns those `2N`
/// coordinates for a nonzero public source. It is empty for an encrypted
/// entry, whose coordinates remain borrowed from the ciphertext, and for any
/// public zero, whose formal coordinates are supplied implicitly. Diagnostic
/// transcripts hash the same canonical `2N` zero words by streaming them into
/// the digest rather than retaining an all-zero sidecar.
template <CoefficientWellFormednessBackend Backend>
struct NormalizedAlignedTranscript {
    PackingLayout layout;
    std::vector<fhe::FheValue<Backend>> values;
    std::vector<std::vector<std::uint64_t>> public_coordinates;
    /// True exactly for entries whose public plaintext is part of the GKR
    /// proof. A verifier projection represents encrypted entries by an
    /// allocation-free public-zero placeholder and marks them false so they
    /// contribute to neither the public offset nor its q-coordinate sidecar.
    std::vector<bool> public_sources;
    /// Present only for the explicitly unbound diagnostic, whose Fiat--Shamir
    /// challenges bind this exact coordinate list. The composed
    /// protocol binds ordered per-message commitments instead, so its prover
    /// and verifier projections deliberately omit this redundant digest.
    std::optional<Digest> ciphertext_list_digest;
};

/// Post-rotation, pre-modulus-switch list.
///
/// Keeping this short-lived state explicit lets a benchmark inspect honest
/// finalization without putting client-secret instrumentation inside the
/// server's canonicalization routine.
template <CoefficientWellFormednessBackend Backend>
struct AlignedTranscriptDraft {
    PackingLayout layout;
    std::vector<fhe::FheValue<Backend>> values;
};

/// Exact component-major `(c0,c1)` coordinates used for a public aligned
/// value at the normalized one-prime commitment boundary. This performs only
/// public BatchEncoder/NTT work; it never constructs or encrypts a ciphertext.
template <PublicCoefficientEncodingBackend Backend, typename Context>
    requires PublicCoefficientVerifierContext<Backend, Context>
std::vector<std::uint64_t> normalized_public_value_coordinates(
    const Context &context,
    const fhe::PublicPlaintext &plaintext);

/// Borrow one aligned entry's canonical `2N` coordinate vector.
template <PublicCoefficientEncodingBackend Backend>
std::span<const std::uint64_t> normalized_aligned_coordinates(
    const NormalizedAlignedTranscript<Backend> &aligned,
    std::size_t index);

/// One packing output split at the public/encrypted boundary.
///
/// Public terms are never added into a ciphertext merely to obtain a uniform
/// host type. `public_offset` is their logical SIMD value modulo t, while
/// `public_c0_coordinates` is their exact bottom-q NTT contribution before
/// reduction modulo t. An empty coordinate vector denotes an exact all-zero
/// contribution; otherwise it has N entries. The public c1 contribution is
/// always implicit zero. This split preserves both BGV semantics and the
/// native-q linear relation when public arithmetic wraps modulo t.
template <PublicCoefficientEncodingBackend Backend>
struct MixedPackingValue {
    std::optional<typename Backend::Ciphertext> encrypted_contribution;
    fhe::PublicPlaintext public_offset =
        fhe::PublicPlaintext::from_scalar(Fp::zero());
    std::vector<std::uint64_t> public_c0_coordinates;
    /// Number of nonzero ternary public terms contributing to a
    /// well-formedness row. It is verifier-derived and used to reserve that
    /// part of the public threshold before checking the encrypted component.
    std::size_t public_term_count = 0;
};

/// Compose the exact normalized `(c0,c1)` coordinates without asking the FHE
/// backend to manufacture a ciphertext for the public contribution.
template <PublicCoefficientEncodingBackend Backend, typename Context>
    requires PublicCoefficientVerifierContext<Backend, Context>
std::vector<std::uint64_t> normalized_mixed_value_coordinates(
    const Context &context,
    const MixedPackingValue<Backend> &value);

/// Public Fiat--Shamir masks and split server-produced outputs.
///
/// Each logical packed output has `packing_radix.digit_count` values with
/// small coefficient masks. The client decrypts only an optional encrypted
/// contribution, then adds the verifier-derived public offset in F_t.
template <PublicCoefficientEncodingBackend Backend>
struct LazyTernaryEvaluation {
    LazyTernaryParameters parameters;
    LazyTernaryChallengeMatrix public_challenges;
    std::vector<MixedPackingValue<Backend>> test_values;
    std::size_t logical_packed_outputs = 0;
    std::vector<MixedPackingValue<Backend>> packed_digit_values;
};

/// Exact outcome of the verifier's well-formedness reveal checks.
///
/// This record is populated only after the outer proof has accepted. A
/// malformed reveal count remains fail-closed and performs no secret-key
/// checks. Reveal indices are zero-based.
struct LazyTernaryThresholdAssessment {
    bool checks_performed = false;
    std::size_t expected_reveal_count = 0;
    std::size_t observed_reveal_count = 0;
    std::size_t checked_reveal_count = 0;
    std::uint64_t configured_threshold = 0;
    std::uint64_t maximum_observed_norm = 0;
    std::optional<std::size_t> first_failing_reveal_index;
    std::size_t failing_reveal_count = 0;

    bool accepts() const {
        return checks_performed &&
               observed_reveal_count == expected_reveal_count &&
               checked_reveal_count == observed_reveal_count &&
               failing_reveal_count == 0;
    }

    bool operator==(const LazyTernaryThresholdAssessment &) const = default;
};

/// Materialize and canonicalize the theorem's pre-mask ciphertext list.
template <CoefficientWellFormednessBackend Backend>
AlignedTranscriptDraft<Backend> materialize_aligned_transcript(
    const typename Backend::EvalContext &eval,
    std::span<const typename Backend::Ciphertext> round_ciphertexts,
    const PackingLayout &layout);

/// Mixed-value counterpart used by Folded/Laned proof messages. Public
/// values remain public through rotation and alignment.
template <CoefficientWellFormednessBackend Backend>
AlignedTranscriptDraft<Backend> materialize_aligned_transcript(
    const typename Backend::EvalContext &eval,
    std::span<const fhe::FheValue<Backend>> round_values,
    const PackingLayout &layout);

/// Drop the reserved packing levels, normalize correction factors, and bind
/// the canonical list. The draft is consumed so its higher-level copies are
/// not accidentally reused after Fiat--Shamir begins.
template <CoefficientWellFormednessBackend Backend>
NormalizedAlignedTranscript<Backend> finalize_aligned_transcript(
    const typename Backend::EvalContext &eval,
    AlignedTranscriptDraft<Backend> draft);

/// Short convenience orchestrator over materialization and finalization.
template <CoefficientWellFormednessBackend Backend>
NormalizedAlignedTranscript<Backend> prepare_normalized_aligned_transcript(
    const typename Backend::EvalContext &eval,
    std::span<const typename Backend::Ciphertext> round_ciphertexts,
    std::span<const std::size_t> message_active_slots);

template <CoefficientWellFormednessBackend Backend>
NormalizedAlignedTranscript<Backend> prepare_normalized_aligned_transcript(
    const typename Backend::EvalContext &eval,
    std::span<const typename Backend::Ciphertext> round_ciphertexts,
    const PackingLayout &layout);

template <CoefficientWellFormednessBackend Backend>
NormalizedAlignedTranscript<Backend> prepare_normalized_aligned_transcript(
    const typename Backend::EvalContext &eval,
    std::span<const fhe::FheValue<Backend>> round_values,
    const PackingLayout &layout);

/// Build the verifier's aligned public projection without first allocating
/// concrete coordinates for encrypted-message placeholders. A present entry
/// is one public GKR message; an absent entry is the verifier's implicit zero
/// for a committed encrypted message. The projection deliberately omits the
/// standalone coordinate-list digest: the composed protocol instead binds
/// the ordered GKR message commitments before deriving packing challenges.
template <PublicCoefficientEncodingBackend Backend, typename Context>
    requires PublicCoefficientVerifierContext<Backend, Context>
NormalizedAlignedTranscript<Backend> prepare_verifier_aligned_projection(
    const Context &context,
    std::span<const fhe::PublicPlaintext *const> round_public_values,
    const PackingLayout &layout);

template <PublicCoefficientEncodingBackend Backend, typename Context>
    requires PublicCoefficientVerifierContext<Backend, Context>
NormalizedAlignedTranscript<Backend> prepare_verifier_aligned_projection(
    const Context &context,
    std::span<const std::optional<fhe::PublicPlaintext>>
        round_public_values,
    const PackingLayout &layout);

/// Derive the selected test matrix from the public alignment layout and the
/// ordered, setup-selected ciphertext commitments carried by GKR. This is the
/// outer-proof transcript boundary: verifier and prover can reproduce it
/// without the private aligned ciphertexts. Only the target Poseidon policy
/// gives this boundary a ciphertext-binding security claim.
LazyTernaryChallengeMatrix derive_committed_lazy_ternary_challenges(
    const PackingLayout &layout,
    std::span<const PoseidonDigest> aligned_commitments,
    Transcript &transcript,
    LazyTernaryParameters parameters = {});

/// Form the revealed tests and signed-digit outputs for an already-derived
/// public challenge matrix. The caller is responsible for binding those
/// challenges to its transcript before invoking this evaluator.
template <SignedDigitPackingBackend Backend>
LazyTernaryEvaluation<Backend> evaluate_lazy_ternary(
    const typename Backend::EvalContext &eval,
    const NormalizedAlignedTranscript<Backend> &aligned,
    const LazyTernaryChallengeMatrix &public_challenges,
    LazyTernaryParameters parameters = {});

/// Reconstruct the verifier's public contribution to every reveal without
/// any FHE evaluation capability.  Encrypted messages are represented by
/// implicit zero placeholders until the decoded proof reveals are attached.
template <PublicCoefficientEncodingBackend Backend, typename Context>
    requires PublicCoefficientVerifierContext<Backend, Context>
LazyTernaryEvaluation<Backend>
evaluate_verifier_lazy_ternary(
    const Context &context,
    const NormalizedAlignedTranscript<Backend> &public_projection,
    const LazyTernaryChallengeMatrix &public_challenges,
    LazyTernaryParameters parameters = {});

/// Decrypt every digit row and recompose the logical packed plaintexts in
/// `F_t`. No radix power is ever applied to a ciphertext.
template <PublicCoefficientEncodingBackend Backend>
std::vector<fhe::SlotVector> decrypt_and_recompose_signed_digit_packing(
    const typename Backend::ClientContext &client,
    std::span<const MixedPackingValue<Backend>> packed_digit_values,
    std::size_t logical_packed_outputs, const BalancedRadix &packing_radix);

} // namespace laminate::packing

#include "laminate/packing/evaluation/phases/native_accumulator.hpp"
#include "laminate/packing/evaluation/phases/transcript_binding.hpp"
#include "laminate/packing/evaluation/phases/canonical_coordinates.hpp"
#include "laminate/packing/evaluation/phases/verifier_linear_forms.hpp"
#include "laminate/packing/evaluation/phases/aligned_transcript.hpp"
#include "laminate/packing/evaluation/phases/prover_linear_forms.hpp"
#include "laminate/packing/evaluation/phases/evaluate.hpp"
#include "laminate/packing/evaluation/phases/recomposition.hpp"

#endif // LAMINATE_PACKING_EVALUATION_LAZY_TERNARY_HPP
