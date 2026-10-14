/// @file noise_completeness.cpp
/// @brief Exact prefix enumeration for Base, Folded, and Laned.

#include "laminate/protocol/analysis/noise_completeness.hpp"

#include "laminate/payload/trace/encrypted_trace.hpp"
#include "laminate/payload/trace/trace_crypto.hpp"
#include "laminate/protocol/reference/base.hpp"
#include "laminate/transcript/hash.hpp"

#include <algorithm>
#include <bit>
#include <limits>
#include <stdexcept>
#include <utility>
#include <variant>

namespace laminate::protocol {
namespace {

using Backend = fhe::NoiseEnvelopeBackend;

void append_u64(std::vector<std::uint8_t> &output, std::uint64_t value) {
    for (int byte = 7; byte >= 0; --byte) {
        output.push_back(static_cast<std::uint8_t>(
            (value >> (8 * byte)) & std::uint64_t{0xff}));
    }
}

void append_size(std::vector<std::uint8_t> &output, std::size_t value) {
    if constexpr (sizeof(std::size_t) > sizeof(std::uint64_t)) {
        if (value > std::numeric_limits<std::uint64_t>::max()) {
            throw std::overflow_error(
                "packing operator digest: size exceeds uint64_t");
        }
    }
    append_u64(output, static_cast<std::uint64_t>(value));
}

void validate_operator_analysis_pair(
    const packing::PackingLinearOperator &linear_operator,
    const packing::SignedDigitPackingWeightAnalysis &weights) {
    linear_operator.validate();
    weights.radix.validate();
    const std::size_t digits = weights.radix.digit_count;
    if (weights.ring_degree != linear_operator.slot_count ||
        weights.source_ciphertext_count !=
            linear_operator.source_ciphertext_count ||
        weights.aligned_ciphertext_count !=
            linear_operator.aligned_ciphertext_count ||
        weights.logical_output_count != linear_operator.rows.size() ||
        weights.logical_output_count >
            std::numeric_limits<std::size_t>::max() / digits ||
        weights.rows.size() != weights.logical_output_count * digits) {
        throw std::invalid_argument(
            "packing operator digest: operator and weights disagree");
    }

    std::size_t total_nonzero = 0;
    std::uint64_t maximum_upper = 0;
    std::uint64_t maximum_absolute = 0;
    for (std::size_t index = 0; index < weights.rows.size(); ++index) {
        const auto &row = weights.rows[index];
        const std::size_t logical_output = index / digits;
        if (row.output_index != logical_output ||
            row.digit_index != index % digits ||
            row.contribution_count !=
                linear_operator.rows[logical_output].contributions.size() ||
            row.mask_nonzero_coefficients >
                std::numeric_limits<std::size_t>::max() - total_nonzero) {
            throw std::invalid_argument(
                "packing operator digest: malformed weight row");
        }
        total_nonzero += row.mask_nonzero_coefficients;
        maximum_upper = std::max(
            maximum_upper, row.weight.conservative_integer_upper);
        maximum_absolute = std::max(
            maximum_absolute,
            row.weight.total_absolute_coefficient_weight);
    }
    if (total_nonzero == 0 || maximum_upper == 0 || maximum_absolute == 0 ||
        total_nonzero != weights.total_mask_nonzero_coefficients ||
        maximum_upper != weights.maximum_digit_row_weight_upper ||
        maximum_absolute !=
            weights.maximum_digit_row_absolute_weight) {
        throw std::invalid_argument(
            "packing operator digest: inconsistent weight summaries");
    }
}

bool envelope_matches_operator_binding(
    const PackingNoiseEnvelopeResult &envelope,
    const PackingOperatorAnalysisBinding &binding) {
    const auto &linear = binding.linear_operator;
    const auto &weights = binding.weights;
    return envelope.ring_degree == linear.slot_count &&
           envelope.ring_degree == weights.ring_degree &&
           envelope.plaintext_modulus == weights.radix.plaintext_modulus &&
           envelope.bhip_round_count == linear.source_ciphertext_count &&
           envelope.bhip_round_count ==
               weights.source_ciphertext_count &&
           linear.aligned_ciphertext_count ==
               weights.aligned_ciphertext_count &&
           linear.rows.size() == weights.logical_output_count &&
           envelope.logical_packed_output_count == linear.rows.size() &&
           envelope.certificate.round.ciphertext_count ==
               envelope.bhip_round_count &&
           envelope.certificate.aligned.ciphertext_count ==
               linear.aligned_ciphertext_count &&
           envelope.certificate.final.ciphertext_count ==
               linear.aligned_ciphertext_count;
}

std::vector<Backend::Ciphertext> flatten_trace(
    const payload::EncryptedTrace<Backend> &trace) {
    std::vector<Backend::Ciphertext> result;
    for (const auto &layer : trace.layers) {
        for (const auto &wire : layer.wires) {
            if (wire.is_encrypted()) {
                result.push_back(wire.ciphertext());
            }
        }
    }
    return result;
}

void append_extension(std::vector<Backend::Ciphertext> &output,
                      const fhe::ExtensionValue<Backend> &value) {
    for (const auto &coefficient : value) {
        if (coefficient.is_encrypted()) {
            output.push_back(coefficient.ciphertext());
        }
    }
}

std::vector<Backend::Ciphertext> flatten_base_proof(
    const gkr::EncryptedBaseProof<Backend> &proof) {
    std::vector<Backend::Ciphertext> result;
    for (const auto &reduction : proof.reductions) {
        if (const auto *affine =
                std::get_if<gkr::EncryptedBaseAffineLayerReduction<Backend>>(
                    &reduction)) {
            for (const auto &round : affine->rounds) {
                append_extension(result, round.evaluations[0]);
                append_extension(result, round.evaluations[1]);
            }
            append_extension(result, affine->source_vector);
            continue;
        }
        const auto &multiplication =
            std::get<gkr::EncryptedBaseMultiplicationLayerReduction<Backend>>(
                reduction);
        for (const auto &round : multiplication.rounds) {
            append_extension(result, round.evaluations[0]);
            append_extension(result, round.evaluations[1]);
        }
        append_extension(result, multiplication.source_vectors[0]);
        append_extension(result, multiplication.source_vectors[1]);
    }
    return result;
}

std::size_t modulus_product_bits(
    std::span<const std::uint64_t> moduli) {
    return fhe::NaturalMagnitude::product(moduli).bit_count();
}

std::size_t nominal_headroom_bits(
    std::span<const std::uint64_t> moduli) {
    std::size_t result = 0;
    for (std::size_t index = 1; index < moduli.size(); ++index) {
        result += std::bit_width(moduli[index]);
    }
    return result;
}

std::vector<std::size_t> candidate_depths(
    const RnsPrefixSearchSpace &space, std::size_t limbs,
    bool packed) {
    if (!space.required_proof_mult_depths.empty()) {
        std::vector<std::size_t> result =
            space.required_proof_mult_depths;
        std::sort(result.begin(), result.end());
        result.erase(std::unique(result.begin(), result.end()), result.end());
        return result;
    }
    const std::size_t first =
        packed ? space.transport.reserved_mult_depth : 0;
    std::vector<std::size_t> result;
    for (std::size_t depth = first; depth < limbs; ++depth) {
        result.push_back(depth);
    }
    if (result.empty()) {
        result.push_back(first);
    }
    return result;
}

RnsPrefixCandidateAssessment candidate_shell(
    std::span<const std::uint64_t> moduli, std::size_t depth) {
    return RnsPrefixCandidateAssessment{
        .fresh_rns_limbs = moduli.size(),
        .coefficient_modulus_product_bits = modulus_product_bits(moduli),
        .nominal_headroom_prime_bits = nominal_headroom_bits(moduli),
        .required_proof_mult_depth = depth,
        .proof_ingress_rns_limbs = depth + 1,
    };
}

template <typename AssessCandidate>
MinimumRnsCompletenessAnalysis enumerate_prefixes(
    gkr::ProtocolVariant protocol,
    const RnsPrefixSearchSpace &space,
    bool packed,
    AssessCandidate assess_candidate) {
    space.validate();
    MinimumRnsCompletenessAnalysis result;
    result.protocol = protocol;
    result.analyzed_search_space = space;

    for (std::size_t limbs = 1;
         limbs <= space.maximum_parameters.data_moduli.size(); ++limbs) {
        fhe::NoiseEnvelopeParameters parameters = space.maximum_parameters;
        parameters.data_moduli.resize(limbs);
        const auto depths = candidate_depths(space, limbs, packed);
        for (const std::size_t depth : depths) {
            RnsPrefixCandidateAssessment candidate = candidate_shell(
                parameters.data_moduli, depth);
            const bool invalid =
                depth >= limbs ||
                (packed && depth < space.transport.reserved_mult_depth);
            if (invalid) {
                candidate.status =
                    RnsPrefixAssessmentStatus::InvalidSchedule;
                candidate.detail =
                    "proof ingress depth is not available in this prefix";
            } else {
                try {
                    assess_candidate(candidate, parameters, depth);
                } catch (const std::overflow_error &error) {
                    candidate.status =
                        RnsPrefixAssessmentStatus::ArithmeticRejected;
                    candidate.detail = error.what();
                }
            }
            result.candidates.push_back(std::move(candidate));
        }
    }

    // Enumeration is exhaustive over the stated finite prefix/schedule set.
    result.all_search_space_candidates_resolved = true;
    for (const auto &candidate : result.candidates) {
        if (!candidate.passes()) {
            continue;
        }
        if (!result.minimum_fresh_rns_limbs ||
            candidate.fresh_rns_limbs < *result.minimum_fresh_rns_limbs ||
            (candidate.fresh_rns_limbs == *result.minimum_fresh_rns_limbs &&
             candidate.required_proof_mult_depth <
                 *result.selected_required_proof_mult_depth)) {
            result.minimum_fresh_rns_limbs = candidate.fresh_rns_limbs;
            result.selected_required_proof_mult_depth =
                candidate.required_proof_mult_depth;
        }
    }
    return result;
}

template <typename CertifyPacked>
MinimumRnsCompletenessAnalysis analyze_packed(
    gkr::ProtocolVariant protocol,
    const ProtocolNoiseEnvelopeStatement &statement,
    const RnsPrefixSearchSpace &space,
    const packing::PlaintextCoefficientEncoder &encode_coefficients,
    CertifyPacked certify_packed) {
    if (space.transport.reserved_mult_depth < kPackingReservedMultDepth) {
        throw std::invalid_argument(
            "packed RNS prefix search: invalid transport reserve");
    }
    if (!encode_coefficients) {
        throw std::invalid_argument(
            "packed RNS prefix search: coefficient encoder is absent");
    }
    std::optional<PackingOperatorAnalysisBinding> operator_binding;
    const auto assess_packed_schedule =
        [&](const PackingNoiseEnvelopeSchedule &schedule,
            std::optional<PackingNoiseEnvelopeResult> &packed,
            std::optional<SelectedPackingPrerequisiteCertificate>
                &prerequisites,
            RnsPrefixAssessmentStatus &status, std::string &detail) {
            packed = certify_packed(statement, schedule);
            if (!operator_binding) {
                const packing::PackingLayout layout =
                    packing::make_fixed_message_coset_packing_layout(
                        packed->ring_degree, packed->bhip_round_count,
                        packed->ring_degree /
                            fhe::kFixedMessageCellCount);
                packing::PackingLinearOperator linear_operator =
                    packing::make_packing_linear_operator(layout);
                packing::SignedDigitPackingWeightAnalysis weights =
                    packing::analyze_signed_digit_packing_weights(
                        linear_operator, encode_coefficients,
                        packing::selected_lazy_ternary_parameters()
                            .packing_radix);
                operator_binding.emplace(
                    PackingOperatorAnalysisBinding{
                        .linear_operator = std::move(linear_operator),
                        .weights = std::move(weights),
                    });
                operator_binding->canonical_digest =
                    packing_operator_analysis_digest(
                        operator_binding->linear_operator,
                        operator_binding->weights);
            }
            if (!envelope_matches_operator_binding(
                    *packed, *operator_binding)) {
                throw std::logic_error(
                    "packed RNS prefix search: prover topology changed "
                    "across candidates");
            }
            if (!packed->passes()) {
                status = RnsPrefixAssessmentStatus::ArithmeticRejected;
                detail =
                    "challenge-independent arithmetic envelope rejected";
                return;
            }
            prerequisites = assess_selected_packing_prerequisites(
                *packed, operator_binding->weights);
            if (!prerequisites->passes_arithmetic_prerequisites()) {
                status = RnsPrefixAssessmentStatus::
                    PackingPrerequisiteRejected;
                detail =
                    "well-formedness or packing no-wrap prerequisite "
                    "rejected";
                return;
            }
            status = RnsPrefixAssessmentStatus::Pass;
            detail.clear();
        };
    MinimumRnsCompletenessAnalysis result = enumerate_prefixes(
        protocol, space, true,
        [&](RnsPrefixCandidateAssessment &candidate,
            const fhe::NoiseEnvelopeParameters &parameters,
            std::size_t depth) {
            PackingNoiseEnvelopeSchedule schedule{
                .fhe_parameters = parameters,
                .required_proof_mult_depth = depth,
                .transport = space.transport,
                .selected_final_error_cap =
                    kSelectedPackingHonestErrorBound,
            };
            assess_packed_schedule(
                schedule, candidate.packed, candidate.prerequisites,
                candidate.status, candidate.detail);
        });
    result.circuit_id = combined_digest(statement.payload, statement.circuit);
    result.setup_id = setup_digest(statement.public_setup);
    result.trace_id = digest(statement.trace, result.circuit_id);
    result.output_claim = statement.output_claim;
    if (result.selected_required_proof_mult_depth &&
        result.minimum_fresh_rns_limbs) {
        std::vector<std::size_t> selected(
            statement.circuit.layers.size(),
            *result.selected_required_proof_mult_depth + 1U);
        // Entry zero is never consumed by reverse GKR. Keep it at the
        // selected fresh prefix so the envelope trace remains a valid
        // stand-in for the client-decryptable payload output.
        selected.front() = *result.minimum_fresh_rns_limbs;

        fhe::NoiseEnvelopeParameters parameters =
            space.maximum_parameters;
        parameters.data_moduli.resize(*result.minimum_fresh_rns_limbs);
        const std::size_t first_admissible_limbs =
            space.transport.reserved_mult_depth + 1U;

        const auto assess_coordinate =
            [&](std::size_t source_layer, std::size_t candidate_limbs,
                const std::vector<std::size_t> &schedule_vector) {
                ProofIngressCoordinateCandidateAssessment assessment{
                    .source_layer = source_layer,
                    .candidate_rns_limbs = candidate_limbs,
                    .proof_ingress_rns_limbs_by_layer = schedule_vector,
                };
                PackingNoiseEnvelopeSchedule schedule{
                    .fhe_parameters = parameters,
                    .required_proof_mult_depth =
                        *result.selected_required_proof_mult_depth,
                    .proof_ingress_rns_limbs_by_layer = schedule_vector,
                    .transport = space.transport,
                    .selected_final_error_cap =
                        kSelectedPackingHonestErrorBound,
                };
                std::optional<PackingNoiseEnvelopeResult> packed;
                std::optional<SelectedPackingPrerequisiteCertificate>
                    prerequisites;
                try {
                    assess_packed_schedule(
                        schedule, packed, prerequisites,
                        assessment.status, assessment.detail);
                } catch (const std::overflow_error &error) {
                    assessment.status =
                        RnsPrefixAssessmentStatus::ArithmeticRejected;
                    assessment.detail = error.what();
                } catch (const std::invalid_argument &error) {
                    assessment.status =
                        RnsPrefixAssessmentStatus::ArithmeticRejected;
                    assessment.detail = error.what();
                }
                result.proof_ingress_coordinate_candidates.push_back(
                    assessment);
                return assessment.passes();
            };

        // Deterministic coordinate descent is followed by a complete audit
        // against the final vector. No monotonicity assumption is used: every
        // lower admissible limb count is replayed, not just the neighbor.
        bool changed = false;
        do {
            changed = false;
            for (std::size_t source_layer = 1;
                 source_layer < selected.size(); ++source_layer) {
                for (std::size_t limbs = first_admissible_limbs;
                     limbs < selected[source_layer]; ++limbs) {
                    std::vector<std::size_t> candidate = selected;
                    candidate[source_layer] = limbs;
                    if (assess_coordinate(source_layer, limbs, candidate)) {
                        selected = std::move(candidate);
                        changed = true;
                        break;
                    }
                }
            }
        } while (changed);

        bool all_lower_rejected = true;
        for (std::size_t source_layer = 1;
             source_layer < selected.size(); ++source_layer) {
            for (std::size_t limbs = first_admissible_limbs;
                 limbs < selected[source_layer]; ++limbs) {
                std::vector<std::size_t> candidate = selected;
                candidate[source_layer] = limbs;
                if (assess_coordinate(source_layer, limbs, candidate)) {
                    all_lower_rejected = false;
                }
            }
        }
        result.selected_proof_ingress_rns_limbs_by_layer =
            std::move(selected);
        result.coordinatewise_proof_ingress_minimum_established =
            all_lower_rejected;
    }
    result.packing_operator = std::move(operator_binding);
    return result;
}

} // namespace

Digest packing_operator_analysis_digest(
    const packing::PackingLinearOperator &linear_operator,
    const packing::SignedDigitPackingWeightAnalysis &weights) {
    validate_operator_analysis_pair(linear_operator, weights);
    std::vector<std::uint8_t> encoding{
        'L', 'M', '/', 'P', 'A', 'C', 'K', '/', 'O', 'P', '/', 'V', '1'};
    append_size(encoding, linear_operator.slot_count);
    append_size(encoding, linear_operator.source_ciphertext_count);
    append_size(encoding, linear_operator.aligned_ciphertext_count);
    append_size(encoding, linear_operator.rows.size());
    for (const auto &row : linear_operator.rows) {
        append_size(encoding, row.output_index);
        append_size(encoding, row.contributions.size());
        for (const auto &entry : row.contributions) {
            append_size(encoding, entry.aligned_index);
            append_size(encoding, entry.source_index);
            append_u64(encoding,
                       static_cast<std::uint8_t>(entry.slot_pattern));
            append_size(encoding, entry.source_begin);
            append_size(encoding, entry.rotation_steps);
            append_size(encoding, entry.destination_begin);
            append_size(encoding, entry.length);
        }
    }
    append_u64(encoding, weights.radix.plaintext_modulus);
    append_u64(encoding, weights.radix.base);
    append_size(encoding, weights.radix.digit_count);
    append_size(encoding, weights.ring_degree);
    append_size(encoding, weights.source_ciphertext_count);
    append_size(encoding, weights.aligned_ciphertext_count);
    append_size(encoding, weights.logical_output_count);
    append_size(encoding, weights.total_mask_nonzero_coefficients);
    append_u64(encoding, weights.maximum_digit_row_weight_upper);
    append_u64(encoding, weights.maximum_digit_row_absolute_weight);
    append_size(encoding, weights.rows.size());
    for (const auto &row : weights.rows) {
        append_size(encoding, row.output_index);
        append_size(encoding, row.digit_index);
        append_size(encoding, row.contribution_count);
        append_size(encoding, row.mask_nonzero_coefficients);
        append_u64(encoding, row.weight.conservative_integer_upper);
        append_u64(encoding,
                   row.weight.total_absolute_coefficient_weight);
    }
    return sha256(encoding);
}

BaseNoiseEnvelopeResult certify_base_noise_completeness(
    const ProtocolNoiseEnvelopeStatement &statement,
    const fhe::NoiseEnvelopeParameters &parameters,
    std::size_t required_proof_mult_depth) {
    parameters.validate();
    if (required_proof_mult_depth >= parameters.data_moduli.size()) {
        throw std::invalid_argument(
            "base noise envelope: proof depth exceeds the chain");
    }
    Backend::Contexts contexts = Backend::create(parameters);
    payload::EncryptedTrace<Backend> encrypted_trace =
        payload::encrypt_compact_synthetic_trace<Backend>(
            contexts.eval, contexts.client, statement.payload,
            statement.circuit, statement.trace,
            payload::TraceEncryptionPlan::uniform(
                statement.circuit, required_proof_mult_depth));
    const std::vector<Backend::Ciphertext> ingress =
        flatten_trace(encrypted_trace);
    const EvaluationSetup<Backend> setup = make_evaluation_setup<Backend>(
        statement.public_setup, contexts.eval,
        statement.gate_mle_prover_key);
    Transcript transcript("laminate/noise-envelope/base/v1");
    const gkr::EncryptedBaseProof<Backend> proof =
        reference::prove_base<Backend>(
        statement.payload, statement.circuit, encrypted_trace, setup,
        statement.output_claim.point, transcript);
    const std::vector<Backend::Ciphertext> messages =
        flatten_base_proof(proof);

    BaseNoiseEnvelopeResult result;
    result.trace_ingress = packing::assess_deterministic_noise_stage<Backend>(
        contexts.eval, ingress, parameters.policy);
    result.emitted_messages =
        packing::assess_deterministic_noise_stage<Backend>(
            contexts.eval, messages, parameters.policy);
    result.ring_degree = parameters.policy.ring_degree;
    result.plaintext_modulus = parameters.policy.plaintext_modulus;
    result.bottom_modulus = parameters.data_moduli.front();
    result.emitted_ciphertext_count = messages.size();
    result.challenge_independent_scope =
        fhe::forces_challenge_independent_topology<Backend>(contexts.eval);
    result.one_prime_boundary =
        result.emitted_messages.minimum_rns_limbs == 1 &&
        result.emitted_messages.maximum_rns_limbs == 1;
    return result;
}

void RnsPrefixSearchSpace::validate() const {
    maximum_parameters.validate();
    if (std::find(required_proof_mult_depths.begin(),
                  required_proof_mult_depths.end(),
                  std::numeric_limits<std::size_t>::max()) !=
        required_proof_mult_depths.end()) {
        throw std::invalid_argument(
            "RNS prefix search: proof depth overflows ingress limb count");
    }
}

const char *rns_prefix_assessment_status_name(
    RnsPrefixAssessmentStatus status) {
    switch (status) {
    case RnsPrefixAssessmentStatus::Pass:
        return "pass";
    case RnsPrefixAssessmentStatus::InvalidSchedule:
        return "invalid-schedule";
    case RnsPrefixAssessmentStatus::ArithmeticRejected:
        return "arithmetic-rejected";
    case RnsPrefixAssessmentStatus::PackingPrerequisiteRejected:
        return "packing-prerequisite-rejected";
    }
    return "unknown";
}

MinimumRnsCompletenessAnalysis analyze_base_minimum_rns_limbs(
    const ProtocolNoiseEnvelopeStatement &statement,
    const RnsPrefixSearchSpace &search_space) {
    MinimumRnsCompletenessAnalysis result = enumerate_prefixes(
        gkr::ProtocolVariant::LaminateBase, search_space, false,
        [&](RnsPrefixCandidateAssessment &candidate,
            const fhe::NoiseEnvelopeParameters &parameters,
            std::size_t depth) {
            candidate.base = certify_base_noise_completeness(
                statement, parameters, depth);
            candidate.status = candidate.base->passes()
                                   ? RnsPrefixAssessmentStatus::Pass
                                   : RnsPrefixAssessmentStatus::
                                         ArithmeticRejected;
            if (!candidate.base->passes()) {
                candidate.detail =
                    "challenge-independent Base envelope rejected";
            }
        });
    result.circuit_id = combined_digest(statement.payload, statement.circuit);
    result.setup_id = setup_digest(statement.public_setup);
    result.trace_id = digest(statement.trace, result.circuit_id);
    result.output_claim = statement.output_claim;
    return result;
}

MinimumRnsCompletenessAnalysis
detail::analyze_folded_minimum_rns_limbs_with_encoder(
    const ProtocolNoiseEnvelopeStatement &statement,
    const RnsPrefixSearchSpace &search_space,
    const packing::PlaintextCoefficientEncoder &encode_coefficients) {
    return analyze_packed(
        gkr::ProtocolVariant::LaminateFolded, statement, search_space,
        encode_coefficients, certify_folded_packing_completeness);
}

MinimumRnsCompletenessAnalysis
detail::analyze_laned_minimum_rns_limbs_with_encoder(
    const ProtocolNoiseEnvelopeStatement &statement,
    const RnsPrefixSearchSpace &search_space,
    const packing::PlaintextCoefficientEncoder &encode_coefficients) {
    return analyze_packed(
        gkr::ProtocolVariant::LaminateLaned, statement, search_space,
        encode_coefficients, certify_laned_packing_completeness);
}

} // namespace laminate::protocol
