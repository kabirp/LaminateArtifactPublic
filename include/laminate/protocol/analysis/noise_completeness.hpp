#ifndef LAMINATE_PROTOCOL_ANALYSIS_NOISE_COMPLETENESS_HPP
#define LAMINATE_PROTOCOL_ANALYSIS_NOISE_COMPLETENESS_HPP

/// @file noise_completeness.hpp
/// @brief Prefix search for arithmetic-completeness RNS requirements.

#include "laminate/packing/analysis/operator.hpp"
#include "laminate/protocol/analysis/packing_prerequisites.hpp"

#include <concepts>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace laminate::protocol {

inline constexpr std::string_view kNoiseCompletenessAnalysisScope =
    "ARITHMETIC_COMPLETENESS_UNDER_CURRENT_PUBLIC_BOUND_RULES";

/// Direct-transport completeness result for LaminateBase.
struct BaseNoiseEnvelopeResult {
    packing::DeterministicNoiseStageCertificate trace_ingress;
    packing::DeterministicNoiseStageCertificate emitted_messages;
    std::size_t ring_degree = 0;
    std::uint64_t plaintext_modulus = 0;
    std::uint64_t bottom_modulus = 0;
    std::size_t emitted_ciphertext_count = 0;
    bool challenge_independent_scope = false;
    bool one_prime_boundary = false;

    bool passes() const {
        return challenge_independent_scope && trace_ingress.all_no_wrap() &&
               emitted_messages.all_no_wrap() && one_prime_boundary;
    }
};

/// Replay the complete Base prover with public bounds in place of values.
BaseNoiseEnvelopeResult certify_base_noise_completeness(
    const ProtocolNoiseEnvelopeStatement &statement,
    const fhe::NoiseEnvelopeParameters &parameters,
    std::size_t required_proof_mult_depth);

/// Exact ordered chain and proof-ingress schedules to assess.
struct RnsPrefixSearchSpace {
    /// Candidates are exactly `maximum_parameters.data_moduli.first(k)`.
    /// The bottom prime q_0 and the separate special prime never change.
    fhe::NoiseEnvelopeParameters maximum_parameters;
    /// Empty means assess every structurally valid uniform depth. Otherwise
    /// assess these depths, in ascending order, for every prefix.
    std::vector<std::size_t> required_proof_mult_depths;
    gkr::ProofTransportPolicy transport{
        .reserved_mult_depth = kPackingReservedMultDepth};
    void validate() const;
};

enum class RnsPrefixAssessmentStatus : std::uint8_t {
    Pass,
    InvalidSchedule,
    ArithmeticRejected,
    PackingPrerequisiteRejected,
};

const char *rns_prefix_assessment_status_name(
    RnsPrefixAssessmentStatus status);

struct RnsPrefixCandidateAssessment {
    std::size_t fresh_rns_limbs = 0;
    /// Exact bit length of Q_{k-1}=product(q_0,...,q_{k-1}).
    std::size_t coefficient_modulus_product_bits = 0;
    /// A descriptive ledger only: sum of individual prime bit widths above
    /// q_0. It is not an invariant-noise-budget measurement.
    std::size_t nominal_headroom_prime_bits = 0;
    std::size_t required_proof_mult_depth = 0;
    std::size_t proof_ingress_rns_limbs = 0;
    RnsPrefixAssessmentStatus status =
        RnsPrefixAssessmentStatus::InvalidSchedule;
    std::string detail;
    std::optional<BaseNoiseEnvelopeResult> base;
    std::optional<PackingNoiseEnvelopeResult> packed;
    std::optional<SelectedPackingPrerequisiteCertificate> prerequisites;

    bool passes() const {
        return status == RnsPrefixAssessmentStatus::Pass;
    }
};

/// One full-proof feasibility check made while minimizing a single source
/// layer. `proof_ingress_rns_limbs_by_layer` records every coordinate used by
/// the replay, so an accepted scalar cannot be detached from the other source
/// levels against which it was assessed.
struct ProofIngressCoordinateCandidateAssessment {
    std::size_t source_layer = 0;
    std::size_t candidate_rns_limbs = 0;
    std::vector<std::size_t> proof_ingress_rns_limbs_by_layer;
    RnsPrefixAssessmentStatus status =
        RnsPrefixAssessmentStatus::InvalidSchedule;
    std::string detail;

    bool passes() const {
        return status == RnsPrefixAssessmentStatus::Pass;
    }
};

/// Canonical operator plus the exact integer row norms used by the theorem.
/// `canonical_digest` is an audit handle over every integral operator field
/// and every exact integer weight field; it is not by itself setup admission.
struct PackingOperatorAnalysisBinding {
    packing::PackingLinearOperator linear_operator;
    packing::SignedDigitPackingWeightAnalysis weights;
    Digest canonical_digest{};
};

Digest packing_operator_analysis_digest(
    const packing::PackingLinearOperator &linear_operator,
    const packing::SignedDigitPackingWeightAnalysis &weights);

/// Complete enumeration; no monotonicity or regenerated-prime assumption.
struct MinimumRnsCompletenessAnalysis {
    gkr::ProtocolVariant protocol = gkr::ProtocolVariant::LaminateBase;
    RnsPrefixSearchSpace analyzed_search_space;
    Digest circuit_id{};
    Digest setup_id{};
    Digest trace_id{};
    gkr::SingleClaim output_claim;
    /// Full binding to the canonical operator and the exact row analysis
    /// recomputed inside this analyzer. A summary alone is insufficient:
    /// understated caller-supplied weights could otherwise certify a
    /// different operator.
    std::optional<PackingOperatorAnalysisBinding> packing_operator;
    std::vector<RnsPrefixCandidateAssessment> candidates;
    std::optional<std::size_t> minimum_fresh_rns_limbs;
    std::optional<std::size_t> selected_required_proof_mult_depth;
    /// Exact actual proof-ingress limb count for every circuit layer under
    /// the selected schedule. Entry zero is a non-authoritative output-layer
    /// placeholder; every source coordinate is minimized by full-prover
    /// replay while holding the other final coordinates fixed.
    std::vector<std::size_t> selected_proof_ingress_rns_limbs_by_layer;
    std::vector<ProofIngressCoordinateCandidateAssessment>
        proof_ingress_coordinate_candidates;
    /// True only after every lower admissible limb count for every source
    /// layer has been rejected against the final selected vector. This is an
    /// exact coordinate-wise minimum; it makes no unproved monotonicity or
    /// globally least-vector claim.
    bool coordinatewise_proof_ingress_minimum_established = false;
    bool all_search_space_candidates_resolved = false;
    /// False until a setup-bound explicit schedule is shown to be replayed
    /// identically by both the envelope and live SEAL backends.
    bool live_schedule_parity_established = false;
    std::string_view scope = kNoiseCompletenessAnalysisScope;

    bool certifies_search_space_minimum() const {
        return minimum_fresh_rns_limbs.has_value() &&
               all_search_space_candidates_resolved;
    }
};

MinimumRnsCompletenessAnalysis analyze_base_minimum_rns_limbs(
    const ProtocolNoiseEnvelopeStatement &statement,
    const RnsPrefixSearchSpace &search_space);

/// Backend context used only for the real public plaintext encoder. The
/// arithmetic envelope itself remains value-free and uses NoiseEnvelopeBackend.
template <typename Backend>
concept PackingCompletenessEncoderBackend =
    requires(const typename Backend::EvalContext &eval,
             const fhe::SlotVector &mask) {
        {
            Backend::slot_count(eval)
        } -> std::convertible_to<std::size_t>;
        {
            Backend::plaintext_modulus(eval)
        } -> std::convertible_to<std::uint64_t>;
        {
            Backend::lowest_coefficient_modulus(eval)
        } -> std::convertible_to<std::uint64_t>;
        {
            Backend::encode_centered_plaintext_coefficients(eval, mask)
        } -> std::same_as<std::vector<std::int64_t>>;
    };

namespace detail {

MinimumRnsCompletenessAnalysis
analyze_folded_minimum_rns_limbs_with_encoder(
    const ProtocolNoiseEnvelopeStatement &statement,
    const RnsPrefixSearchSpace &search_space,
    const packing::PlaintextCoefficientEncoder &encode_coefficients);

MinimumRnsCompletenessAnalysis
analyze_laned_minimum_rns_limbs_with_encoder(
    const ProtocolNoiseEnvelopeStatement &statement,
    const RnsPrefixSearchSpace &search_space,
    const packing::PlaintextCoefficientEncoder &encode_coefficients);

} // namespace detail

template <PackingCompletenessEncoderBackend Backend>
MinimumRnsCompletenessAnalysis analyze_folded_minimum_rns_limbs(
    const ProtocolNoiseEnvelopeStatement &statement,
    const RnsPrefixSearchSpace &search_space,
    const typename Backend::EvalContext &encoder_context) {
    search_space.validate();
    if (Backend::slot_count(encoder_context) !=
            search_space.maximum_parameters.policy.ring_degree ||
        Backend::plaintext_modulus(encoder_context) !=
            search_space.maximum_parameters.policy.plaintext_modulus ||
        Backend::lowest_coefficient_modulus(encoder_context) !=
            search_space.maximum_parameters.data_moduli.front()) {
        throw std::invalid_argument(
            "packed RNS prefix search: encoder context differs in N, t, or "
            "q_0");
    }
    return detail::analyze_folded_minimum_rns_limbs_with_encoder(
        statement, search_space,
        [&](const fhe::SlotVector &mask) {
            return Backend::encode_centered_plaintext_coefficients(
                encoder_context, mask);
        });
}

template <PackingCompletenessEncoderBackend Backend>
MinimumRnsCompletenessAnalysis analyze_laned_minimum_rns_limbs(
    const ProtocolNoiseEnvelopeStatement &statement,
    const RnsPrefixSearchSpace &search_space,
    const typename Backend::EvalContext &encoder_context) {
    search_space.validate();
    if (Backend::slot_count(encoder_context) !=
            search_space.maximum_parameters.policy.ring_degree ||
        Backend::plaintext_modulus(encoder_context) !=
            search_space.maximum_parameters.policy.plaintext_modulus ||
        Backend::lowest_coefficient_modulus(encoder_context) !=
            search_space.maximum_parameters.data_moduli.front()) {
        throw std::invalid_argument(
            "packed RNS prefix search: encoder context differs in N, t, or "
            "q_0");
    }
    return detail::analyze_laned_minimum_rns_limbs_with_encoder(
        statement, search_space,
        [&](const fhe::SlotVector &mask) {
            return Backend::encode_centered_plaintext_coefficients(
                encoder_context, mask);
        });
}

} // namespace laminate::protocol

#endif // LAMINATE_PROTOCOL_ANALYSIS_NOISE_COMPLETENESS_HPP
