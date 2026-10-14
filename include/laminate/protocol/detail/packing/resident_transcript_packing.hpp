#ifndef LAMINATE_PROTOCOL_DETAIL_PACKING_RESIDENT_TRANSCRIPT_PACKING_HPP
#define LAMINATE_PROTOCOL_DETAIL_PACKING_RESIDENT_TRANSCRIPT_PACKING_HPP

/// @file resident_transcript_packing.hpp
/// @brief Spartan-backed proof-of-packing prover and verifier steps.

#include "laminate/packing/outer_relation/assignment.hpp"
#include "laminate/packing/proof/r1cs.hpp"
#include "laminate/packing/alignment/unpack.hpp"
#include "laminate/protocol/packed/setup.hpp"
#include "laminate/protocol/packed/proof.hpp"
#include "laminate/runtime_progress.hpp"
#include "laminate/verification_profile.hpp"

#include <algorithm>
#include <optional>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

namespace laminate::protocol::detail {
namespace packing_protocol_detail {

inline std::vector<PoseidonDigest> commitment_digests(
    std::span<const gkr::HashCommitCT> commitments) {
    std::vector<PoseidonDigest> result;
    result.reserve(commitments.size());
    for (const gkr::HashCommitCT &commitment : commitments) {
        result.push_back(commitment.digest);
    }
    return result;
}

inline const spartan::VerifierKey &spartan_verifier_key(
    const TranscriptPackingSpartanSetup &setup) {
    return setup.spartan.verifier_key;
}

inline const spartan::VerifierKey &spartan_verifier_key(
    const TranscriptPackingSpartanVerifierSetup &setup) {
    return setup.spartan;
}

template <ProofOfPackingBackend Backend, typename VerifierContext,
          typename Setup>
    requires packing::PublicCoefficientVerifierContext<
        Backend, VerifierContext>
packing::OuterRelationPublicInputs make_outer_logical_inputs(
    const VerifierContext &verifier, const Setup &setup,
    const packing::LazyTernaryChallengeMatrix &challenges,
    std::span<const packing::MixedPackingValue<Backend>> tests,
    std::span<const packing::MixedPackingValue<Backend>> packed_digits) {
    const packing::OuterRelationPlan &plan = setup.relation_plan;
    const std::size_t width = plan.coordinates_per_ciphertext();
    if (tests.size() != plan.shape.repetitions ||
        packed_digits.size() != plan.physical_packed_ciphertexts()) {
        throw std::invalid_argument(
            "proof-of-packing reveal count mismatch");
    }

    packing::OuterRelationPublicInputs result;
    result.packed_challenge_words =
        packing::pack_outer_relation_challenge_bits(plan, challenges);
    result.revealed_test_coordinates.reserve(tests.size() * width);
    for (const auto &test : tests) {
        const auto coordinates =
            packing::normalized_mixed_value_coordinates<Backend>(
                verifier, test);
        result.revealed_test_coordinates.insert(
            result.revealed_test_coordinates.end(), coordinates.begin(),
            coordinates.end());
    }
    result.revealed_packing_coordinates.reserve(
        packed_digits.size() * width);
    for (const auto &digit : packed_digits) {
        const auto coordinates =
            packing::normalized_mixed_value_coordinates<Backend>(
                verifier, digit);
        result.revealed_packing_coordinates.insert(
            result.revealed_packing_coordinates.end(), coordinates.begin(),
            coordinates.end());
    }
    return result;
}

template <ProofOfPackingBackend Backend>
packing::LazyTernaryThresholdAssessment assess_threshold_checks(
    const typename Backend::ClientContext &client,
    std::span<const packing::MixedPackingValue<Backend>> tests,
    std::size_t aligned_ciphertext_count,
    const packing::LazyTernaryParameters &parameters) {
    packing::LazyTernaryThresholdAssessment result{
        .expected_reveal_count = parameters.repetitions,
        .observed_reveal_count = tests.size(),
    };
    if (tests.size() != parameters.repetitions) {
        return result;
    }
    result.configured_threshold = packing::lazy_ternary_test_threshold(
        parameters.honest_partial_decryption_bound(),
        aligned_ciphertext_count);
    result.checks_performed = true;

    for (std::size_t index = 0; index < tests.size(); ++index) {
        const auto &test = tests[index];
        const std::uint64_t norm =
            Backend::partial_decryption_with_public_ntt_offset_infinity_norm(
                client,
                test.encrypted_contribution
                    ? &*test.encrypted_contribution
                    : nullptr,
                test.public_c0_coordinates);
        ++result.checked_reveal_count;
        result.maximum_observed_norm =
            std::max(result.maximum_observed_norm, norm);
        if (norm > result.configured_threshold) {
            if (!result.first_failing_reveal_index) {
                result.first_failing_reveal_index = index;
            }
            ++result.failing_reveal_count;
        }
    }
    return result;
}

template <ProofOfPackingBackend Backend>
std::vector<std::optional<typename Backend::Ciphertext>>
take_encrypted_contributions(
    std::span<packing::MixedPackingValue<Backend>> values) {
    std::vector<std::optional<typename Backend::Ciphertext>> result;
    result.reserve(values.size());
    for (auto &value : values) {
        result.push_back(std::move(value.encrypted_contribution));
    }
    return result;
}

template <ProofOfPackingBackend Backend>
void attach_encrypted_contributions(
    std::span<packing::MixedPackingValue<Backend>> values,
    std::span<const std::optional<typename Backend::Ciphertext>>
        encrypted) {
    if (values.size() != encrypted.size()) {
        throw std::invalid_argument(
            "proof-of-packing encrypted contribution count mismatch");
    }
    for (std::size_t index = 0; index < values.size(); ++index) {
        if (values[index].encrypted_contribution) {
            throw std::logic_error(
                "public verifier projection unexpectedly contains an "
                "encrypted contribution");
        }
        values[index].encrypted_contribution = encrypted[index];
    }
}

template <ProofOfPackingBackend Backend>
struct VerifierAlignedInputs {
    std::vector<gkr::HashCommitCT> commitments;
    packing::NormalizedAlignedTranscript<Backend> public_projection;
};

template <ProofOfPackingBackend Backend, typename VerifierContext>
    requires packing::PublicCoefficientVerifierContext<
        Backend, VerifierContext>
VerifierAlignedInputs<Backend> derive_verifier_aligned_inputs(
    const VerifierContext &verifier,
    const packing::PackingLayout &layout,
    gkr::CiphertextCommitmentPolicy ciphertext_commitment_policy,
    std::span<const gkr::CommittedPackedMessage *const> messages) {
    ciphertext_commitment_policy.validate();
    if (messages.size() != layout.message_active_slots.size() ||
        layout.placements.size() != messages.size()) {
        throw std::invalid_argument(
            "proof-of-packing committed messages do not match alignment");
    }
    for (std::size_t index = 0; index < messages.size(); ++index) {
        if (layout.placements[index].message_index != index) {
            throw std::invalid_argument(
                "proof-of-packing committed messages are not in canonical "
                "alignment order");
        }
    }
    std::vector<const fhe::PublicPlaintext *> public_values;
    public_values.reserve(messages.size());
    for (const gkr::CommittedPackedMessage *message : messages) {
        if (message == nullptr) {
            throw std::invalid_argument(
                "proof-of-packing committed message view is null");
        }
        if (message->is_public()) {
            public_values.push_back(&message->plaintext());
        } else {
            public_values.push_back(nullptr);
        }
    }

    VerifierAlignedInputs<Backend> result;
    result.public_projection =
        packing::prepare_verifier_aligned_projection<Backend>(
            verifier, public_values, layout);
    result.commitments.reserve(messages.size());
    std::optional<gkr::HashCommitCT> public_zero_commitment;
    for (std::size_t index = 0; index < messages.size(); ++index) {
        const gkr::CommittedPackedMessage &message = *messages[index];
        if (message.is_public()) {
            if (result.public_projection.values[index].is_public_zero()) {
                if (!public_zero_commitment) {
                    public_zero_commitment =
                        gkr::hash_commit_normalized_zero_ciphertext_coordinates(
                            layout.slot_count,
                            ciphertext_commitment_policy);
                }
                result.commitments.push_back(*public_zero_commitment);
            } else {
                result.commitments.push_back(
                    gkr::hash_commit_normalized_ciphertext_coordinates(
                        layout.slot_count,
                        packing::normalized_aligned_coordinates(
                            result.public_projection, index),
                        ciphertext_commitment_policy));
            }
        } else {
            result.commitments.push_back(message.commitment());
        }
    }
    return result;
}

} // namespace packing_protocol_detail

/// Server-side proof after the committed GKR proof has been bound.
template <ProofOfPackingBackend Backend>
TranscriptPackingProof<Backend> prove_transcript_packing(
    const typename Backend::EvalContext &eval,
    const TranscriptPackingSpartanSetup &setup,
    const packing::NormalizedAlignedTranscript<Backend> &aligned,
    std::span<const gkr::HashCommitCT> commitments,
    Transcript &packing_transcript,
    const RuntimeProgressCallback &progress = {}) {
    // Step 1: derive the committed well-formedness coefficients and evaluate
    // the split public/encrypted test and digit reveals.
    const auto &parameters = setup.parameters;
    if (aligned.layout != setup.alignment_layout ||
        aligned.values.size() !=
            setup.relation_plan.shape.aligned_ciphertexts) {
        throw std::invalid_argument(
            "proof-of-packing aligned witness does not match setup");
    }
    notify_runtime_progress(
        progress,
        {.boundary = RuntimeProgressBoundary::Begin,
         .stage = RuntimeProgressStage::TranscriptPackingRevealEvaluation});
    const std::vector<PoseidonDigest> digests =
        packing_protocol_detail::commitment_digests(commitments);
    const packing::LazyTernaryChallengeMatrix challenges =
        packing::derive_committed_lazy_ternary_challenges(
            setup.alignment_layout, digests, packing_transcript,
            parameters);
    packing::LazyTernaryEvaluation<Backend> experiment =
        packing::evaluate_lazy_ternary<Backend>(
            eval, aligned, challenges, parameters);
    notify_runtime_progress(
        progress,
        {.boundary = RuntimeProgressBoundary::End,
         .stage = RuntimeProgressStage::TranscriptPackingRevealEvaluation});

    // Step 2: borrow the normalized sources. Public-zero reveals and aligned
    // messages remain implicit coordinate slices while the fixed R1CS shape
    // and setup-selected commitment relation still see their formal all-zero
    // values.
    notify_runtime_progress(
        progress,
        {.boundary = RuntimeProgressBoundary::Begin,
         .stage = RuntimeProgressStage::TranscriptPackingAssignment});
    const std::vector<std::uint64_t> packed_challenge_words =
        packing::pack_outer_relation_challenge_bits(
            setup.relation_plan, challenges);
    const packing::OuterRelationR1csAssignmentView outer_assignment =
        packing::borrow_outer_relation_r1cs_assignment<Backend>(
            eval, setup.relation_plan, packed_challenge_words,
            experiment.test_values, experiment.packed_digit_values, aligned,
            [](const typename Backend::Ciphertext &ciphertext)
                -> std::span<const std::uint64_t> {
                return Backend::coefficient_commitment_ntt_coordinate_view(
                    ciphertext);
            });
    const spartan::R1csAssignment assignment =
        packing::make_proof_of_packing_r1cs_assignment(
            setup.relation_plan, commitments, outer_assignment);
    notify_runtime_progress(
        progress,
        {.boundary = RuntimeProgressBoundary::End,
         .stage = RuntimeProgressStage::TranscriptPackingAssignment});

    // Step 3: prove the public relation with Spartan, its factored matrix
    // argument, and BaseFold openings.
    notify_runtime_progress(
        progress,
        {.boundary = RuntimeProgressBoundary::Begin,
         .stage = RuntimeProgressStage::TranscriptPackingSpartanProve});
    const spartan::BaseFoldPcs pcs(setup.basefold_parameters);
    spartan::Proof spartan_proof = spartan::prove(
        setup.spartan.prover_key, assignment, pcs, packing_transcript);
    notify_runtime_progress(
        progress,
        {.boundary = RuntimeProgressBoundary::End,
         .stage = RuntimeProgressStage::TranscriptPackingSpartanProve});

    return TranscriptPackingProof<Backend>{
        .well_formedness_reveals =
            packing_protocol_detail::take_encrypted_contributions<Backend>(
                experiment.test_values),
        .digit_decomposed_packed_values =
            packing_protocol_detail::take_encrypted_contributions<Backend>(
                experiment.packed_digit_values),
        .proof_of_packing = std::move(spartan_proof),
    };
}

struct VerifiedPackedTranscript {
    bool threshold_checks = false;
    bool spartan_proof = false;
    packing::LazyTernaryThresholdAssessment threshold_assessment;
    std::vector<fhe::SlotVector> logical_messages;

    bool accepts() const {
        return threshold_checks && spartan_proof &&
               !logical_messages.empty();
    }
};

/// Client-side check. The public Spartan proof is rejected before any
/// secret-key operation; no digit ciphertext is decrypted until the later
/// threshold predicate has also accepted.
template <ProofOfPackingBackend Backend, typename VerifierContext,
          typename Setup>
    requires packing::PublicCoefficientVerifierContext<
        Backend, VerifierContext>
VerifiedPackedTranscript verify_transcript_packing(
    const VerifierContext &verifier,
    const typename Backend::ClientContext &client,
    const Setup &setup,
    std::span<const gkr::CommittedPackedMessage *const> gkr_messages,
    const TranscriptPackingProof<Backend> &proof,
    Transcript &packing_transcript,
    const RuntimeProgressCallback &progress = {}) {
    const verification_profile::ScopedVerificationPhase packing_phase(
        verification_profile::Category::PackingSNARK);
    VerifiedPackedTranscript result;
    // Step 1: reconstruct the canonical public statement, then verify the
    // Spartan proof before using the secret key.
    notify_runtime_progress(
        progress,
        {.boundary = RuntimeProgressBoundary::Begin,
         .stage = RuntimeProgressStage::TranscriptPackingVerifierStatement});
    const auto &parameters = setup.parameters;
    auto verifier_inputs =
        packing_protocol_detail::derive_verifier_aligned_inputs<Backend>(
            verifier, setup.alignment_layout,
            setup.relation_plan.shape.ciphertext_commitment_policy,
            gkr_messages);
    const std::vector<PoseidonDigest> digests =
        packing_protocol_detail::commitment_digests(
            verifier_inputs.commitments);
    const packing::LazyTernaryChallengeMatrix challenges =
        packing::derive_committed_lazy_ternary_challenges(
            setup.alignment_layout, digests, packing_transcript,
            parameters);
    auto public_experiment =
        packing::evaluate_verifier_lazy_ternary<Backend>(
            verifier, verifier_inputs.public_projection, challenges,
            parameters);
    packing_protocol_detail::attach_encrypted_contributions<Backend>(
        public_experiment.test_values, proof.well_formedness_reveals);
    packing_protocol_detail::attach_encrypted_contributions<Backend>(
        public_experiment.packed_digit_values,
        proof.digit_decomposed_packed_values);
    const packing::OuterRelationPublicInputs outer_logical_inputs =
        packing_protocol_detail::make_outer_logical_inputs<Backend>(
            verifier, setup, challenges, public_experiment.test_values,
            public_experiment.packed_digit_values);
    const std::vector<Fq> public_inputs =
        packing::make_proof_of_packing_public_inputs(
            setup.relation_plan, verifier_inputs.commitments,
            outer_logical_inputs);
    notify_runtime_progress(
        progress,
        {.boundary = RuntimeProgressBoundary::End,
         .stage = RuntimeProgressStage::TranscriptPackingVerifierStatement});

    notify_runtime_progress(
        progress,
        {.boundary = RuntimeProgressBoundary::Begin,
         .stage = RuntimeProgressStage::TranscriptPackingSpartanVerify});
    const spartan::BaseFoldPcs pcs(setup.basefold_parameters);
    result.spartan_proof = spartan::verify(
        packing_protocol_detail::spartan_verifier_key(setup), public_inputs,
        proof.proof_of_packing, pcs, packing_transcript);
    notify_runtime_progress(
        progress,
        {.boundary = RuntimeProgressBoundary::End,
         .stage = RuntimeProgressStage::TranscriptPackingSpartanVerify});
    if (!result.spartan_proof) {
        return result;
    }

    // Step 2: enforce the coefficient-domain error thresholds.
    notify_runtime_progress(
        progress,
        {.boundary = RuntimeProgressBoundary::Begin,
         .stage = RuntimeProgressStage::TranscriptPackingThresholdChecks});
    {
        const verification_profile::ScopedVerificationPhase phase(
            verification_profile::Category::WFNoise);
        result.threshold_assessment =
            packing_protocol_detail::assess_threshold_checks<Backend>(
                client, public_experiment.test_values,
                setup.relation_plan.shape.aligned_ciphertexts, parameters);
        result.threshold_checks = result.threshold_assessment.accepts();
    }
    notify_runtime_progress(
        progress,
        {.boundary = RuntimeProgressBoundary::End,
         .stage = RuntimeProgressStage::TranscriptPackingThresholdChecks});
    if (!result.threshold_checks) {
        return result;
    }

    // Step 3: decrypt the accepted digits and recover the GKR transcript.
    notify_runtime_progress(
        progress,
        {.boundary = RuntimeProgressBoundary::Begin,
         .stage = RuntimeProgressStage::TranscriptPackingUnpack});
    {
        const verification_profile::ScopedVerificationPhase phase(
            verification_profile::Category::Recovery);
        const std::vector<fhe::SlotVector> packed_plaintexts =
            packing::decrypt_and_recompose_signed_digit_packing<Backend>(
                client, public_experiment.packed_digit_values,
                setup.alignment_layout.packed_ciphertext_count,
                setup.radix);
        result.logical_messages = packing::unpack_packed_plaintexts(
            setup.alignment_layout, packed_plaintexts);
    }
    notify_runtime_progress(
        progress,
        {.boundary = RuntimeProgressBoundary::End,
         .stage = RuntimeProgressStage::TranscriptPackingUnpack});
    return result;
}

/// Adapter for callers that already own a contiguous message
/// array. Production verification passes non-owning views into the proof.
template <ProofOfPackingBackend Backend, typename VerifierContext,
          typename Setup>
    requires packing::PublicCoefficientVerifierContext<
        Backend, VerifierContext>
VerifiedPackedTranscript verify_transcript_packing(
    const VerifierContext &verifier,
    const typename Backend::ClientContext &client,
    const Setup &setup,
    std::span<const gkr::CommittedPackedMessage> gkr_messages,
    const TranscriptPackingProof<Backend> &proof,
    Transcript &packing_transcript,
    const RuntimeProgressCallback &progress = {}) {
    std::vector<const gkr::CommittedPackedMessage *> views;
    views.reserve(gkr_messages.size());
    for (const auto &message : gkr_messages) {
        views.push_back(&message);
    }
    return verify_transcript_packing<Backend>(
        verifier, client, setup,
        std::span<const gkr::CommittedPackedMessage *const>(views), proof,
        packing_transcript, progress);
}

} // namespace laminate::protocol::detail

#endif // LAMINATE_PROTOCOL_DETAIL_PACKING_RESIDENT_TRANSCRIPT_PACKING_HPP
