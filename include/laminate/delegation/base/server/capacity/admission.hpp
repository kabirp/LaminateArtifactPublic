#ifndef LAMINATE_DELEGATION_BASE_SERVER_CAPACITY_ADMISSION_HPP
#define LAMINATE_DELEGATION_BASE_SERVER_CAPACITY_ADMISSION_HPP

/// @file server/capacity/admission.hpp
/// @brief Bind caller resource declarations to one concrete Base execution.

#include "laminate/delegation/base/server/capacity/workspace.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <vector>

namespace laminate::delegation::base_server_detail {

inline void validate_capacity_contract(
    const payload::LayeredCircuit &circuit,
    const payload::PayloadCheckpointReplayProblem &problem,
    const payload::PayloadCheckpointReplayBudgets &budgets,
    const payload::PayloadCheckpointReplayPlan &replay_plan,
    const protocol::BaseServerCapacityComponents &components) {
    const payload::PayloadCheckpointReplayPlan expected =
        payload::plan_payload_checkpoint_replay(problem, budgets);
    if (!(expected == replay_plan) || !replay_plan.selected.feasible() ||
        problem.layers.size() != circuit.layers.size()) {
        throw std::invalid_argument(
            "Base capacity contract: replay plan is not the admitted plan");
    }

    require_capacity_declaration(
        components.operational_reserve.local_disk_bytes != 0 &&
            components.operational_reserve.resident_ram_bytes != 0,
        "operational disk and RAM reserves must be nonzero");
    require_capacity_declaration(
        components.preprocessed_keys.local_disk_bytes != 0 &&
            components.preprocessed_keys.resident_ram_bytes != 0,
        "serialized and resident preprocessed-key bytes must be declared");
    require_capacity_declaration(
        components.encrypted_input_request.resident_ram_bytes != 0 &&
            components.encrypted_output_response.resident_ram_bytes != 0,
        "input-request and output-response RAM must be declared");
    require_capacity_declaration(
        components.affine_reduction_workspace.resident_ram_bytes != 0 &&
            components.accumulated_proof.resident_ram_bytes != 0 &&
            components.proof_encoding.resident_ram_bytes != 0 &&
            components.transport_framing.resident_ram_bytes != 0,
        "affine, proof, encoding, and framing RAM must be declared");
    require_capacity_declaration(
        components.payload_replay_phase_floor ==
                protocol::ServerResourcePair{} &&
            components.compact_replay_trace.local_disk_bytes == 0,
        "planner phase floor and compact replay disk are derived; callers "
        "must leave them zero");
}

inline void bind_replay_artifact_capacity(
    const payload::PayloadCheckpointReplayProblem &problem,
    const payload::PayloadCheckpointReplayPlan &replay_plan,
    protocol::BaseServerCapacityComponents &components) {
    components.payload_replay_phase_floor = protocol::ServerResourcePair{
        replay_plan.selected.peak_live_scratch_bytes,
        replay_plan.selected.peak_resident_bytes};
    components.compact_replay_trace.local_disk_bytes =
        compact_replay_post_replay_disk(problem, replay_plan);
    components.compact_replay_trace.resident_ram_bytes = std::max(
        components.compact_replay_trace.resident_ram_bytes,
        compact_replay_record_metadata_ram(problem, replay_plan));
}

template <fhe::PersistableFheBackend Backend>
void bind_request_response_capacity(
    const EvaluationSetup<Backend> &server,
    const BaseRequest<Backend> &request,
    const payload::PayloadCheckpointReplayProblem &problem,
    protocol::BaseServerCapacityComponents &components) {
    std::uint64_t encoded_input_bytes = 0;
    for (const typename Backend::Ciphertext &ciphertext :
         request.encrypted_inputs) {
        encoded_input_bytes = checked_capacity_add(
            encoded_input_bytes,
            capacity_count(
                Backend::serialize_for_storage(server.context, ciphertext)
                    .size(),
                "encoded Base input ciphertext"),
            "encoded Base input request");
    }
    components.encrypted_input_request.resident_ram_bytes = std::max(
        components.encrypted_input_request.resident_ram_bytes,
        encoded_input_bytes);

    const payload::PayloadReplayLayer &output = problem.layers.front();
    const std::uint64_t output_residency = checked_capacity_multiply(
        capacity_count(output.stored_value_count,
                       "Base output value count"),
        output.resident_ciphertext_bytes,
        "Base output response residency");
    components.encrypted_output_response.resident_ram_bytes = std::max(
        components.encrypted_output_response.resident_ram_bytes,
        output_residency);
}

inline void validate_replay_reserve(
    const payload::PayloadCheckpointReplayBudgets &budgets,
    const protocol::BaseServerCapacityComponents &components) {
    const protocol::ServerResourcePair required =
        required_payload_replay_reserve(components);
    require_capacity_declaration(
        required.local_disk_bytes <= budgets.reserved_live_scratch_bytes &&
            required.resident_ram_bytes <= budgets.reserved_resident_bytes,
        "planner reserves do not cover the detailed non-artifact resources");
}

inline void bind_multiplication_layer_capacity(
    const payload::LayeredCircuit &circuit, std::size_t layer,
    const payload::PayloadCheckpointReplayProblem &problem,
    const protocol::BaseProverOptions &proof_options,
    const payload::LayerWireSupport &source_support,
    const payload::LayerStorageLayout &source_storage,
    protocol::BaseServerCapacityComponents &components) {
    const gkr::detail::DenseMultiplicationAliasPlan aliases =
        gkr::detail::make_dense_multiplication_alias_plan(
            circuit, layer, source_support, source_storage);
    const auto scratch = std::find_if(
        proof_options.multiplication_scratch.begin(),
        proof_options.multiplication_scratch.end(),
        [&](const gkr::base_detail::FileBaseMultiplicationScratch &entry) {
            return entry.reduction_layer == layer;
        });
    require_capacity_declaration(
        scratch != proof_options.multiplication_scratch.end(),
        "each multiplication layer needs scratch storage");

    const payload::PayloadReplayLayer &source_problem =
        problem.layers.at(layer + 1U);
    const std::uint64_t proof_ingress_record_bytes =
        source_problem.proof_ingress_serialized_ciphertext_bytes == 0
            ? source_problem.serialized_ciphertext_bytes
            : source_problem.proof_ingress_serialized_ciphertext_bytes;
    const gkr::detail::FileDenseMultiplicationSourceDiskBounds disk_bounds =
        gkr::detail::file_dense_multiplication_source_disk_bounds(
            aliases.operands.size(), proof_ingress_record_bytes,
            true, scratch->sort_buffer_payload_bytes);
    require_capacity_declaration(
        scratch->storage_limits.max_total_bytes >=
            disk_bounds.build_peak_bytes,
        "multiplication scratch quota is below its derived build peak");
    components.multiplication_build_scratch.local_disk_bytes = std::max(
        components.multiplication_build_scratch.local_disk_bytes,
        disk_bounds.build_peak_bytes);
    components.multiplication_artifact.local_disk_bytes = std::max(
        components.multiplication_artifact.local_disk_bytes,
        disk_bounds.completed_artifact_bytes);

    const std::uint64_t builder_floor =
        minimum_dense_multiplication_builder_ram(
            source_support, source_storage, source_problem, aliases);
    const std::uint64_t reduction_value_bytes = std::max(
        source_problem.proof_ingress_resident_ciphertext_bytes == 0
            ? source_problem.resident_ciphertext_bytes
            : source_problem.proof_ingress_resident_ciphertext_bytes,
        checked_capacity_add(proof_ingress_record_bytes, 1U,
                             "Base dense tagged source record bytes"));
    const std::uint64_t reduction_floor =
        gkr::detail::dense_multiplication_reduction_workspace_bytes(
            aliases, reduction_value_bytes,
            payload::layer_dimensions(circuit.layers[layer]).padded_size);
    const std::uint64_t builder_with_sort_buffer = checked_capacity_add(
        builder_floor,
        checked_capacity_multiply(scratch->sort_buffer_payload_bytes, 2U,
                                  "Base sort resident allowance"),
        "Base dense builder and sort-buffer workspace");
    components.multiplication_builder_workspace.resident_ram_bytes = std::max(
        components.multiplication_builder_workspace.resident_ram_bytes,
        builder_with_sort_buffer);
    components.multiplication_reduction_workspace.resident_ram_bytes =
        std::max(
            components.multiplication_reduction_workspace.resident_ram_bytes,
            reduction_floor);
}

inline void bind_multiplication_capacity(
    const payload::LayeredCircuit &circuit,
    const payload::PayloadCheckpointReplayProblem &problem,
    const protocol::BaseProverOptions &proof_options,
    protocol::BaseServerCapacityComponents &components,
    bool workspaces_were_declared) {
    const std::vector<payload::LayerWireSupport> wire_support =
        payload::canonical_trace_wire_support(circuit);
    const std::vector<payload::LayerStorageLayout> storage =
        payload::canonical_trace_storage_layout(circuit);
    bool has_multiplication = false;
    for (std::size_t layer = 0; layer + 1U < circuit.layers.size(); ++layer) {
        if (payload::layer_kind(circuit.layers[layer]) !=
            payload::LayerKind::Multiplication) {
            continue;
        }
        has_multiplication = true;
        bind_multiplication_layer_capacity(
            circuit, layer, problem, proof_options, wire_support.at(layer + 1U),
            storage.at(layer + 1U), components);
    }
    if (has_multiplication) {
        require_capacity_declaration(
            workspaces_were_declared,
            "multiplication builder and reduction RAM must be declared");
    }
}

template <fhe::PersistableFheBackend Backend>
void bind_gate_mle_capacity(
    const EvaluationSetup<Backend> &server,
    protocol::BaseServerCapacityComponents &components) {
    if (server.public_setup.gate_mle_profile !=
        GateMleProfile::OutsourcedBaseFold) {
        return;
    }
    require_capacity_declaration(
        server.gate_mle_prover_key != nullptr &&
            components.gate_mle_preprocessing.resident_ram_bytes != 0 &&
            components.gate_mle_opening_workspace.resident_ram_bytes != 0,
        "outsourced GateMLE preprocessing and opening RAM must be declared");
    components.gate_mle_opening_workspace.resident_ram_bytes = std::max(
        components.gate_mle_opening_workspace.resident_ram_bytes,
        minimum_outsourced_gate_opening_ram(*server.gate_mle_prover_key));
}

/// Turn portable caller declarations into the concrete resource envelope for
/// this request, replay plan, multiplication aliasing, and GateMLE profile.
template <fhe::PersistableFheBackend Backend>
protocol::BaseServerCapacityComponents bind_base_capacity_to_execution(
    const payload::LayeredCircuit &circuit,
    const EvaluationSetup<Backend> &server,
    const BaseRequest<Backend> &request,
    const payload::PayloadCheckpointReplayProblem &problem,
    const payload::PayloadCheckpointReplayBudgets &budgets,
    const payload::PayloadCheckpointReplayPlan &replay_plan,
    const protocol::BaseProverOptions &proof_options,
    protocol::BaseServerCapacityComponents components) {
    validate_capacity_contract(circuit, problem, budgets, replay_plan,
                               components);
    const bool multiplication_workspaces_were_declared =
        components.multiplication_builder_workspace.resident_ram_bytes != 0 &&
        components.multiplication_reduction_workspace.resident_ram_bytes != 0;
    bind_replay_artifact_capacity(problem, replay_plan, components);
    bind_request_response_capacity(server, request, problem, components);
    validate_replay_reserve(budgets, components);
    bind_multiplication_capacity(circuit, problem, proof_options, components,
                                 multiplication_workspaces_were_declared);
    bind_gate_mle_capacity(server, components);
    return components;
}

} // namespace laminate::delegation::base_server_detail

#endif // LAMINATE_DELEGATION_BASE_SERVER_CAPACITY_ADMISSION_HPP
