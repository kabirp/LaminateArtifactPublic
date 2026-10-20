#ifndef LAMINATE_DELEGATION_BASE_SERVER_CAPACITY_ARITHMETIC_HPP
#define LAMINATE_DELEGATION_BASE_SERVER_CAPACITY_ARITHMETIC_HPP

/// @file server/capacity/arithmetic.hpp
/// @brief Overflow-safe Base resource arithmetic and replay coexistence model.

#include "laminate/delegation/base/server/request_validation.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>

namespace laminate::delegation::base_server_detail {

inline std::uint64_t checked_capacity_add(
    std::uint64_t left, std::uint64_t right, const char *description) {
    if (right > std::numeric_limits<std::uint64_t>::max() - left) {
        throw std::overflow_error(std::string(description) + " overflows");
    }
    return left + right;
}

inline std::uint64_t checked_capacity_multiply(
    std::uint64_t left, std::uint64_t right, const char *description) {
    if (left != 0 &&
        right > std::numeric_limits<std::uint64_t>::max() / left) {
        throw std::overflow_error(std::string(description) + " overflows");
    }
    return left * right;
}

inline protocol::ServerResourcePair checked_capacity_add(
    protocol::ServerResourcePair left,
    protocol::ServerResourcePair right, const char *description) {
    return protocol::ServerResourcePair{
        checked_capacity_add(left.local_disk_bytes, right.local_disk_bytes,
                             description),
        checked_capacity_add(left.resident_ram_bytes,
                             right.resident_ram_bytes, description)};
}

inline protocol::ServerResourcePair capacity_pair_max(
    protocol::ServerResourcePair left,
    protocol::ServerResourcePair right) {
    return protocol::ServerResourcePair{
        std::max(left.local_disk_bytes, right.local_disk_bytes),
        std::max(left.resident_ram_bytes, right.resident_ram_bytes)};
}

inline std::uint64_t capacity_count(std::size_t count,
                                    const char *description) {
    if constexpr (sizeof(std::size_t) > sizeof(std::uint64_t)) {
        if (count > std::numeric_limits<std::uint64_t>::max()) {
            throw std::overflow_error(std::string(description) +
                                      " does not fit u64");
        }
    }
    return static_cast<std::uint64_t>(count);
}

inline void require_capacity_declaration(bool condition,
                                         const char *description) {
    if (!condition) {
        throw std::invalid_argument(std::string("Base capacity contract: ") +
                                    description);
    }
}

inline std::uint64_t compact_replay_record_metadata_ram(
    const payload::PayloadCheckpointReplayProblem &problem,
    const payload::PayloadCheckpointReplayPlan &plan) {
    std::uint64_t checkpoint_records = 0;
    for (std::size_t layer : plan.selected.checkpoint_layers) {
        checkpoint_records = checked_capacity_add(
            checkpoint_records,
            capacity_count(problem.layers.at(layer).stored_value_count,
                           "Base checkpoint record count"),
            "Base checkpoint record count");
    }

    // Charge the largest state that can coexist with selected checkpoints.
    // A relation owns its non-checkpoint input and output stores. At proof
    // ingress a replayed source remains live while its reduced copy publishes,
    // so the same large source can contribute twice.
    std::uint64_t transient_records = 0;
    for (std::size_t output = 0; output + 1U < problem.layers.size();
         ++output) {
        const std::size_t input = output + 1U;
        const bool input_is_checkpoint = std::binary_search(
            plan.selected.checkpoint_layers.begin(),
            plan.selected.checkpoint_layers.end(), input);
        const bool output_is_checkpoint = std::binary_search(
            plan.selected.checkpoint_layers.begin(),
            plan.selected.checkpoint_layers.end(), output);
        const std::uint64_t relation_records = checked_capacity_add(
            input_is_checkpoint
                ? 0
                : capacity_count(problem.layers[input].stored_value_count,
                                 "Base transient relation input records"),
            output_is_checkpoint
                ? 0
                : capacity_count(problem.layers[output].stored_value_count,
                                 "Base transient relation output records"),
            "Base transient relation record count");
        transient_records = std::max(transient_records, relation_records);
    }
    for (const payload::PayloadReplaySegment &segment :
         plan.reverse_gkr_segments) {
        const std::size_t source = segment.required_source_layer;
        const bool source_is_checkpoint = segment.checkpoint_layer == source;
        const std::uint64_t source_records = capacity_count(
            problem.layers.at(source).stored_value_count,
            "Base proof-ingress source records");
        const std::uint64_t ingress_records = checked_capacity_add(
            source_is_checkpoint ? 0 : source_records,
            segment.proof_ingress_artifact_bytes_upper_bound == 0
                ? 0
                : source_records,
            "Base proof-ingress coexisting records");
        transient_records = std::max(transient_records, ingress_records);
    }
    const std::uint64_t records = checked_capacity_add(
        checkpoint_records, transient_records,
        "Base compact replay metadata record count");
    return checked_capacity_multiply(
        records, sizeof(std::uint64_t) + sizeof(Digest),
        "Base compact replay record metadata");
}

inline std::uint64_t compact_replay_post_replay_disk(
    const payload::PayloadCheckpointReplayProblem &problem,
    const payload::PayloadCheckpointReplayPlan &plan) {
    std::uint64_t result = plan.selected.checkpoint_bytes;
    for (const payload::PayloadReplaySegment &segment :
         plan.reverse_gkr_segments) {
        const std::uint64_t transient_source =
            segment.checkpoint_layer == segment.required_source_layer
                ? 0
                : problem.layers.at(segment.required_source_layer)
                      .checkpoint_bytes;
        result = std::max(
            result,
            checked_capacity_add(
                checked_capacity_add(
                    segment.artifact_peak.live_checkpoint_bytes,
                    transient_source,
                    "Base post-replay natural artifacts"),
                segment.proof_ingress_artifact_bytes_upper_bound,
                "Base post-replay compact artifacts"));
    }
    return result;
}

inline protocol::ServerResourcePair persistent_capacity_resources(
    const protocol::BaseServerCapacityComponents &components) {
    return checked_capacity_add(
        checked_capacity_add(
            checked_capacity_add(components.operational_reserve,
                                 components.preprocessed_keys,
                                 "Base persistent capacity resources"),
            components.prepared_plaintext_cache,
            "Base persistent capacity resources"),
        components.gate_mle_preprocessing,
        "Base persistent capacity resources");
}

inline protocol::ServerResourcePair required_payload_replay_reserve(
    const protocol::BaseServerCapacityComponents &components) {
    protocol::ServerResourcePair common = checked_capacity_add(
        persistent_capacity_resources(components),
        components.payload_replay_workspace,
        "Base replay common resources");
    common = checked_capacity_add(
        common,
        protocol::ServerResourcePair{
            0, components.compact_replay_trace.resident_ram_bytes},
        "Base replay compact metadata");

    // Input request and accumulated proof belong to disjoint phases. Charge
    // their component-wise maximum instead of pretending both coexist.
    const protocol::ServerResourcePair evaluation_only =
        checked_capacity_add(
            components.encrypted_input_request,
            protocol::ServerResourcePair{
                components.encrypted_output_response.local_disk_bytes, 0},
            "Base replay evaluation-only resources");
    return checked_capacity_add(
        common,
        capacity_pair_max(evaluation_only, components.accumulated_proof),
        "Base replay required reserve");
}

} // namespace laminate::delegation::base_server_detail

#endif // LAMINATE_DELEGATION_BASE_SERVER_CAPACITY_ARITHMETIC_HPP
