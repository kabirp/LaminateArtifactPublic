#ifndef LAMINATE_DELEGATION_BASE_SERVER_EVALUATE_PAYLOAD_HPP
#define LAMINATE_DELEGATION_BASE_SERVER_EVALUATE_PAYLOAD_HPP

/// @file server/evaluate_payload.hpp
/// @brief Base server evaluation and compact-checkpoint publication.

#include "laminate/delegation/base/server/capacity/admission.hpp"
#include "laminate/delegation/base/statement/digest.hpp"
#include "laminate/gkr/detail/base/validation/scratch.hpp"

#include <stdexcept>
#include <utility>
#include <vector>

namespace laminate::delegation {

template <fhe::PersistableFheBackend Backend>
CheckpointReplayBaseServerEvaluationResult<Backend>
evaluate_base_request(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const EvaluationSetup<Backend> &server,
    const BaseRequest<Backend> &request,
    const payload::CertifiedHonestPayloadSchedule &certified_schedule,
    const payload::PayloadCheckpointReplayProblem &problem,
    const payload::PayloadCheckpointReplayBudgets &budgets,
    const payload::PayloadCheckpointReplayPlan &replay_plan,
    payload::PayloadCheckpointReplayExecutionOptions replay_options,
    protocol::BaseProverOptions proof_options,
    protocol::BaseServerCapacityCaps capacity_caps,
    protocol::BaseServerCapacityComponents capacity_components) {
    // Admission is deliberately complete before the first FHE operation.
    base_server_detail::validate_checkpoint_replay_schedule(
        payload, circuit, server, request, certified_schedule);
    if (replay_options.lifecycle !=
        payload::FileTraceSessionLifecycle::IrreversibleNoRetry) {
        throw std::invalid_argument(
            "Base checkpoint evaluation requires IrreversibleNoRetry");
    }
    replay_options.directory =
        payload::preflight_and_normalize_payload_checkpoint_replay_root(
            replay_options.directory);
    proof_options =
        gkr::base_detail::preflight_and_normalize_file_base_gkr_scratch(
            circuit, replay_options.directory, proof_options);
    capacity_components =
        base_server_detail::bind_base_capacity_to_execution(
            circuit, server, request, problem, budgets, replay_plan,
            proof_options, std::move(capacity_components));
    const protocol::BaseServerCapacityAdmission capacity_admission =
        protocol::admit_base_server_capacity(
            capacity_caps, capacity_components);
    CheckpointReplayBaseServerResources resources{
        std::move(proof_options), capacity_caps,
        std::move(capacity_components), capacity_admission};

    // Payload evaluation emits only canonical stored values. Structural
    // padding remains the public zero polynomial and never gets a record.
    std::vector<fhe::FheValue<Backend>> output;
    auto trace = payload::PayloadCheckpointReplayTrace<
        Backend>::publish_authenticated(
        server.context, payload, circuit, request.encrypted_inputs,
        certified_schedule, problem, budgets, replay_plan,
        std::move(replay_options), output);
    const payload::EncryptedTraceDescriptor &descriptor = trace.descriptor();
    if (descriptor.provenance != payload::TraceProvenance::FheEvaluated ||
        descriptor.circuit_id != request.circuit_id ||
        descriptor.trace_id != request.trace_id ||
        descriptor.shape.kind != payload::PayloadKind::Wide ||
        descriptor.layers.empty() ||
        output.size() != descriptor.layers.front().record_count ||
        trace.backend_context_id() !=
            Backend::storage_context_id(server.context) ||
        trace.layered_circuit_id() != certified_schedule.circuit_digest() ||
        !trace.report().checkpoint_set_published ||
        trace.report().all_payload_artifacts_retired) {
        throw std::logic_error(
            "Base checkpoint evaluator returned a mismatched session");
    }

    BaseFheOutput<Backend> response_output{
        descriptor.layers.front().dimensions, std::move(output)};
    const Digest request_commitment = base_request_commitment<Backend>(request);
    const Digest statement_digest =
        base_encrypted_statement_digest<Backend>(
            request_commitment, request.setup_id, request.session_id,
            request.circuit_id, request.trace_id, response_output);
    return CheckpointReplayBaseServerEvaluationResult<Backend>{
        std::move(response_output),
        CheckpointReplayBaseServerEvaluated<Backend>{
            request.setup_id, request.session_id, request.circuit_id,
            request.trace_id, request_commitment, statement_digest,
            std::move(trace), std::move(resources)}};
}

} // namespace laminate::delegation

#endif // LAMINATE_DELEGATION_BASE_SERVER_EVALUATE_PAYLOAD_HPP
