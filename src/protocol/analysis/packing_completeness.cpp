/// @file packing_completeness.cpp
/// @brief Typed orchestration for challenge-independent packing certificates.

#include "laminate/protocol/analysis/packing_completeness.hpp"

#include "laminate/fhe/layout/fixed_message.hpp"
#include "laminate/gkr/detail/folded/reference/prover.hpp"
#include "laminate/gkr/detail/laned/reference/prover.hpp"
#include "laminate/payload/trace/encrypted_trace.hpp"
#include "laminate/payload/trace/trace_crypto.hpp"
#include "laminate/protocol/detail/packing/messages.hpp"

#include <stdexcept>
#include <string_view>
#include <utility>

namespace laminate::protocol {
namespace {

using Backend = fhe::NoiseEnvelopeBackend;

constexpr std::string_view kFoldedTranscriptDomain =
    "laminate/noise-envelope/folded/v1";
constexpr std::string_view kLanedTranscriptDomain =
    "laminate/noise-envelope/laned/v1";

/// Shared preparation deliberately uses the ordinary trace encryptor and
/// setup constructor. Only the backend changes from ciphertext values to
/// public worst-case bounds.
struct PreparedEnvelopeExecution {
    Backend::Contexts contexts;
    payload::EncryptedTrace<Backend> encrypted_trace;
    EvaluationSetup<Backend> evaluation_setup;
};

std::vector<std::size_t> exact_ingress_limbs(
    const payload::LayeredCircuit &circuit,
    const PackingNoiseEnvelopeSchedule &schedule) {
    if (schedule.proof_ingress_rns_limbs_by_layer.empty()) {
        return std::vector<std::size_t>(
            circuit.layers.size(), schedule.required_proof_mult_depth + 1U);
    }
    if (schedule.proof_ingress_rns_limbs_by_layer.size() !=
        circuit.layers.size()) {
        throw std::invalid_argument(
            "packing noise envelope: exact proof-ingress schedule has the "
            "wrong layer count");
    }
    return schedule.proof_ingress_rns_limbs_by_layer;
}

payload::TraceEncryptionPlan exact_trace_encryption_plan(
    const payload::LayeredCircuit &circuit,
    const PackingNoiseEnvelopeSchedule &schedule) {
    const std::vector<std::size_t> limbs =
        exact_ingress_limbs(circuit, schedule);
    payload::TraceEncryptionPlan result;
    result.required_mult_depth_by_layer.reserve(limbs.size());
    for (const std::size_t count : limbs) {
        if (count == 0) {
            throw std::invalid_argument(
                "packing noise envelope: proof ingress selected zero "
                "limbs");
        }
        result.required_mult_depth_by_layer.push_back(count - 1U);
    }
    return result;
}

PreparedEnvelopeExecution prepare_execution(
    const PackingNoiseEnvelopeStatement &statement,
    const PackingNoiseEnvelopeSchedule &schedule) {
    schedule.validate();
    Backend::Contexts contexts = Backend::create(schedule.fhe_parameters);
    payload::EncryptedTrace<Backend> encrypted_trace =
        payload::encrypt_compact_synthetic_trace<Backend>(
            contexts.eval, contexts.client, statement.payload,
            statement.circuit, statement.trace,
            exact_trace_encryption_plan(statement.circuit, schedule));
    EvaluationSetup<Backend> evaluation_setup =
        make_evaluation_setup<Backend>(
            statement.public_setup, contexts.eval,
            statement.gate_mle_prover_key);
    return PreparedEnvelopeExecution{
        std::move(contexts), std::move(encrypted_trace),
        std::move(evaluation_setup)};
}

template <typename Proof>
PackingNoiseEnvelopeResult finish_certificate(
    const Backend::EvalContext &eval, const Proof &proof,
    std::uint64_t selected_final_error_cap) {
    std::vector<fhe::FheValue<Backend>> round_values =
        collect_transcript_packing_round_values<Backend>(proof);
    const std::size_t messages_per_output =
        Backend::slot_count(eval) / fhe::kFixedMessageCellCount;
    const packing::PackingLayout layout =
        packing::make_fixed_message_coset_packing_layout(
            Backend::slot_count(eval), round_values.size(),
            messages_per_output);
    auto certificate =
        packing::certify_deterministic_packing_completeness<Backend>(
            eval, round_values, layout, eval.parameters.policy,
            selected_final_error_cap,
            packing::DeterministicPackingCertificateScope::
                ChallengeIndependentEnvelope);
    return PackingNoiseEnvelopeResult{
        .certificate = std::move(certificate),
        .ring_degree = Backend::slot_count(eval),
        .plaintext_modulus = eval.parameters.policy.plaintext_modulus,
        .packing_modulus = eval.parameters.data_moduli.front(),
        .bhip_round_count = round_values.size(),
        .logical_packed_output_count = layout.packed_ciphertext_count,
    };
}

} // namespace

void PackingNoiseEnvelopeSchedule::validate() const {
    fhe_parameters.validate();
    const bool uniform_schedule =
        proof_ingress_rns_limbs_by_layer.empty();
    if (fhe_parameters.policy.ring_degree <
            2 * fhe::kFixedMessageCellCount ||
        (uniform_schedule &&
         required_proof_mult_depth >= fhe_parameters.data_moduli.size()) ||
        transport.reserved_mult_depth < kPackingReservedMultDepth ||
        (uniform_schedule &&
         transport.reserved_mult_depth > required_proof_mult_depth) ||
        selected_final_error_cap == 0) {
        throw std::invalid_argument(
            "packing noise envelope: invalid ring, depth, reserve, or cap");
    }
    for (const std::size_t limbs : proof_ingress_rns_limbs_by_layer) {
        if (limbs == 0 || limbs > fhe_parameters.data_moduli.size()) {
            throw std::invalid_argument(
                "packing noise envelope: exact proof-ingress level is "
                "outside the selected RNS prefix");
        }
    }
    for (std::size_t layer = 1;
         layer < proof_ingress_rns_limbs_by_layer.size(); ++layer) {
        if (proof_ingress_rns_limbs_by_layer[layer] <=
            transport.reserved_mult_depth) {
            throw std::invalid_argument(
                "packing noise envelope: proof source lacks the reserved "
                "transport depth");
        }
    }
}

PackingNoiseEnvelopeResult certify_folded_packing_completeness(
    const PackingNoiseEnvelopeStatement &statement,
    const PackingNoiseEnvelopeSchedule &schedule) {
    // Step 1: encrypt the validated plaintext trace as public bounds.
    PreparedEnvelopeExecution execution =
        prepare_execution(statement, schedule);

    // Step 2: replay every Folded round with bounds for all challenge terms.
    Transcript transcript(kFoldedTranscriptDomain);
    const gkr::EncryptedFoldedProof<Backend> proof =
        gkr::folded_detail::prove_folded_gkr_resident<Backend>(
        statement.payload, statement.circuit, execution.encrypted_trace,
        execution.evaluation_setup, statement.output_claim.point, transcript,
        exact_ingress_limbs(statement.circuit, schedule),
        schedule.transport);

    // Step 3: certify rotation alignment and one-prime normalization.
    return finish_certificate(execution.contexts.eval, proof,
                              schedule.selected_final_error_cap);
}

PackingNoiseEnvelopeResult certify_laned_packing_completeness(
    const PackingNoiseEnvelopeStatement &statement,
    const PackingNoiseEnvelopeSchedule &schedule) {
    // Step 1: encrypt the validated plaintext trace as public bounds.
    PreparedEnvelopeExecution execution =
        prepare_execution(statement, schedule);

    // Step 2: replay every Laned round with bounds for all challenge terms.
    Transcript transcript(kLanedTranscriptDomain);
    const gkr::EncryptedLanedProof<Backend> proof =
        gkr::laned_detail::prove_laned_gkr_resident<Backend>(
            statement.payload, statement.circuit,
            execution.encrypted_trace, execution.evaluation_setup,
            exact_ingress_limbs(statement.circuit, schedule),
            statement.output_claim.point, transcript,
            schedule.transport);

    // Step 3: certify rotation alignment and one-prime normalization.
    return finish_certificate(execution.contexts.eval, proof,
                              schedule.selected_final_error_cap);
}

} // namespace laminate::protocol
