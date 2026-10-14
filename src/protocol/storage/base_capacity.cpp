/// @file base_capacity.cpp
/// @brief Pure phase composition for file-backed Base server admission.

#include "laminate/protocol/storage/base_capacity.hpp"

#include <algorithm>
#include <limits>
#include <stdexcept>
#include <string>

namespace laminate::protocol {
namespace {

std::size_t phase_index(BaseServerCapacityPhase phase) {
    const std::size_t index = static_cast<std::size_t>(phase);
    if (index >= kBaseServerCapacityPhaseCount) {
        throw std::invalid_argument("unknown Base server capacity phase");
    }
    return index;
}

const char *phase_name(BaseServerCapacityPhase phase) {
    switch (phase) {
    case BaseServerCapacityPhase::PreprocessedReady:
        return "preprocessed-ready phase";
    case BaseServerCapacityPhase::PayloadCheckpointReplay:
        return "payload/checkpoint-replay phase";
    case BaseServerCapacityPhase::AffineReduction:
        return "Base affine-reduction phase";
    case BaseServerCapacityPhase::MultiplicationScratchBuild:
        return "Base multiplication-scratch build phase";
    case BaseServerCapacityPhase::MultiplicationReduction:
        return "Base multiplication-reduction phase";
    case BaseServerCapacityPhase::GateMleOpening:
        return "Base GateMLE-opening phase";
    case BaseServerCapacityPhase::ProofPublication:
        return "Base proof-publication phase";
    }
    throw std::invalid_argument("unknown Base server capacity phase");
}

std::uint64_t checked_add(std::uint64_t left, std::uint64_t right,
                          const char *label) {
    if (right > std::numeric_limits<std::uint64_t>::max() - left) {
        throw std::overflow_error(std::string(label) + " overflows");
    }
    return left + right;
}

ServerResourcePair checked_add(ServerResourcePair left,
                               ServerResourcePair right,
                               const char *label) {
    return ServerResourcePair{
        checked_add(left.local_disk_bytes, right.local_disk_bytes, label),
        checked_add(left.resident_ram_bytes, right.resident_ram_bytes,
                    label),
    };
}

class PhaseComposer {
  public:
    explicit PhaseComposer(BaseServerCapacityPhase phase)
        : phase_(phase) {}

    PhaseComposer &add(ServerResourcePair component) {
        resources_ = checked_add(resources_, component, phase_name(phase_));
        return *this;
    }

    PhaseComposer &floor(ServerResourcePair lower_bound) {
        resources_.local_disk_bytes = std::max(
            resources_.local_disk_bytes, lower_bound.local_disk_bytes);
        resources_.resident_ram_bytes = std::max(
            resources_.resident_ram_bytes, lower_bound.resident_ram_bytes);
        return *this;
    }

    BaseServerCapacityPhasePeak finish() const {
        return BaseServerCapacityPhasePeak{
            .phase = phase_,
            .live_local_disk_bytes = resources_.local_disk_bytes,
            .resident_ram_bytes = resources_.resident_ram_bytes,
            .combined_bytes = checked_add(
                resources_.local_disk_bytes,
                resources_.resident_ram_bytes, phase_name(phase_)),
        };
    }

  private:
    BaseServerCapacityPhase phase_;
    ServerResourcePair resources_;
};

ServerResourcePair persistent_resources(
    const BaseServerCapacityComponents &components) {
    return checked_add(
        checked_add(
            checked_add(components.operational_reserve,
                        components.preprocessed_keys,
                        "persistent Base resources"),
            components.prepared_plaintext_cache,
            "persistent Base resources"),
        components.gate_mle_preprocessing,
        "persistent Base resources");
}

void require_within_caps(const BaseServerCapacityPhasePeak &phase,
                         const BaseServerCapacityCaps &caps) {
    if (phase.live_local_disk_bytes >
        caps.max_live_local_disk_bytes) {
        throw std::invalid_argument(
            std::string(phase_name(phase.phase)) +
            " requires " +
            std::to_string(phase.live_local_disk_bytes) +
            " live local-disk bytes, exceeding the configured cap of " +
            std::to_string(caps.max_live_local_disk_bytes) + " bytes");
    }
    if (phase.resident_ram_bytes > caps.max_resident_ram_bytes) {
        throw std::invalid_argument(
            std::string(phase_name(phase.phase)) +
            " requires " + std::to_string(phase.resident_ram_bytes) +
            " resident bytes, exceeding the configured cap of " +
            std::to_string(caps.max_resident_ram_bytes) + " bytes");
    }
}

void insert_phase(BaseServerCapacityAdmission &admission,
                  BaseServerCapacityPhasePeak phase) {
    require_within_caps(phase, admission.caps);
    admission.phases[phase_index(phase.phase)] = phase;
    admission.max_live_local_disk_bytes =
        std::max(admission.max_live_local_disk_bytes,
                 phase.live_local_disk_bytes);
    admission.max_resident_ram_bytes =
        std::max(admission.max_resident_ram_bytes,
                 phase.resident_ram_bytes);
    admission.max_phase_combined_bytes =
        std::max(admission.max_phase_combined_bytes,
                 phase.combined_bytes);
}

PhaseComposer phase_with_persistent(
    BaseServerCapacityPhase phase, ServerResourcePair persistent) {
    return PhaseComposer(phase).add(persistent);
}

} // namespace

const BaseServerCapacityPhasePeak &BaseServerCapacityAdmission::phase(
    BaseServerCapacityPhase requested) const {
    return phases.at(phase_index(requested));
}

const BaseServerCapacityPhasePeak &
BaseServerCapacityAdmission::peak_live_local_disk_phase() const {
    return *std::max_element(
        phases.begin(), phases.end(),
        [](const BaseServerCapacityPhasePeak &left,
           const BaseServerCapacityPhasePeak &right) {
            return left.live_local_disk_bytes < right.live_local_disk_bytes;
        });
}

BaseServerCapacityAdmission admit_base_server_capacity(
    const BaseServerCapacityCaps &caps,
    const BaseServerCapacityComponents &components) {
    if (caps.max_live_local_disk_bytes == 0 ||
        caps.max_resident_ram_bytes == 0) {
        throw std::invalid_argument(
            "Base server capacity caps must be nonzero");
    }

    const ServerResourcePair persistent = persistent_resources(components);
    BaseServerCapacityAdmission result;
    result.caps = caps;

    insert_phase(
        result,
        phase_with_persistent(
            BaseServerCapacityPhase::PreprocessedReady, persistent)
            .finish());
    insert_phase(
        result,
        phase_with_persistent(
            BaseServerCapacityPhase::PayloadCheckpointReplay, persistent)
            .add(components.compact_replay_trace)
            .add(components.encrypted_input_request)
            .add(components.encrypted_output_response)
            .add(components.payload_replay_workspace)
            .floor(components.payload_replay_phase_floor)
            .finish());
    insert_phase(
        result,
        phase_with_persistent(BaseServerCapacityPhase::AffineReduction,
                              persistent)
            .add(components.compact_replay_trace)
            .add(components.accumulated_proof)
            .add(components.affine_reduction_workspace)
            .finish());
    insert_phase(
        result,
        phase_with_persistent(
            BaseServerCapacityPhase::MultiplicationScratchBuild,
            persistent)
            .add(components.compact_replay_trace)
            .add(components.accumulated_proof)
            .add(components.multiplication_build_scratch)
            .add(components.multiplication_builder_workspace)
            .finish());
    insert_phase(
        result,
        phase_with_persistent(
            BaseServerCapacityPhase::MultiplicationReduction, persistent)
            .add(components.compact_replay_trace)
            .add(components.accumulated_proof)
            .add(components.multiplication_artifact)
            .add(components.multiplication_reduction_workspace)
            .finish());
    insert_phase(
        result,
        phase_with_persistent(BaseServerCapacityPhase::GateMleOpening,
                              persistent)
            .add(components.accumulated_proof)
            .add(components.gate_mle_opening_workspace)
            .finish());
    insert_phase(
        result,
        phase_with_persistent(BaseServerCapacityPhase::ProofPublication,
                              persistent)
            .add(components.accumulated_proof)
            .add(components.proof_encoding)
            .add(components.transport_framing)
            .finish());

    return result;
}

std::uint64_t required_base_setup_available_disk(
    const BaseServerCapacityAdmission &admission,
    std::uint64_t client_preprocessing_bytes,
    std::uint64_t all_preprocessing_bytes,
    std::uint64_t free_space_reserve_bytes) {
    const std::uint64_t server_lifecycle = checked_add(
        checked_add(admission.max_live_local_disk_bytes,
                    client_preprocessing_bytes,
                    "Base setup server and client disk"),
        free_space_reserve_bytes, "Base setup disk reserve");
    const std::uint64_t preprocessing = checked_add(
        all_preprocessing_bytes, free_space_reserve_bytes,
        "Base setup preprocessing disk reserve");
    return std::max(server_lifecycle, preprocessing);
}

std::uint64_t required_base_server_available_disk(
    const BaseServerCapacityAdmission &admission,
    std::uint64_t server_preprocessing_bytes,
    std::uint64_t free_space_reserve_bytes) {
    if (server_preprocessing_bytes >
        admission.max_live_local_disk_bytes) {
        throw std::invalid_argument(
            "server preprocessing exceeds the admitted Base disk peak");
    }
    return checked_add(
        admission.max_live_local_disk_bytes - server_preprocessing_bytes,
        free_space_reserve_bytes, "Base server-start disk reserve");
}

} // namespace laminate::protocol
