#include "laminate/payload/checkpoint/plan.hpp"

#include "laminate/payload/evaluation/fhe_evaluation_plan.hpp"
#include "laminate/payload/evaluation/affine_program.hpp"
#include "laminate/payload/trace/trace_wire_support.hpp"

#include <algorithm>
#include <limits>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace laminate::payload {
namespace {

std::uint64_t checked_add(std::uint64_t left, std::uint64_t right,
                          const char *label) {
    if (right > std::numeric_limits<std::uint64_t>::max() - left) {
        throw std::overflow_error(std::string(label) + " overflows");
    }
    return left + right;
}


std::uint64_t checked_mul(std::uint64_t left, std::uint64_t right,
                          const char *label) {
    if (left != 0 &&
        right > std::numeric_limits<std::uint64_t>::max() / left) {
        throw std::overflow_error(std::string(label) + " overflows");
    }
    return left * right;
}

std::uint64_t checked_u64(std::size_t value, const char *label) {
    if constexpr (sizeof(std::size_t) > sizeof(std::uint64_t)) {
        if (value > std::numeric_limits<std::uint64_t>::max()) {
            throw std::overflow_error(std::string(label) +
                                      " does not fit u64");
        }
    }
    return static_cast<std::uint64_t>(value);
}

bool affine_constant_is_zero(const AffineConstant &constant) {
    if (const auto *scalar = std::get_if<Fp>(&constant)) {
        return scalar->is_zero();
    }
    const fhe::SlotVector &slots = std::get<fhe::SlotVector>(constant);
    return std::all_of(slots.begin(), slots.end(),
                       [](const Fp &value) { return value.is_zero(); });
}

std::uint64_t affine_gate_replay_work_units(
    const AffineGate &gate, const LayerWireSupport &source_support) {
    std::uint64_t live_terms = 0;
    for (const AffineTerm &term : gate.terms) {
        if (!term.coefficient.is_zero() &&
            (term.source >= source_support.padded_wire_count ||
             source_support.is_live(term.source))) {
            live_terms = checked_add(
                live_terms, 1, "payload replay affine terms");
        }
    }
    std::uint64_t work = live_terms;
    // A constant-only gate stays public and performs no FHE operation. A
    // nonzero constant costs one AddPlain only when the gate also depends on
    // an encrypted source.
    if (live_terms != 0 && !affine_constant_is_zero(gate.constant)) {
        work = checked_add(work, 1,
                           "payload replay affine constant");
    }
    return work;
}

} // namespace

std::uint64_t file_trace_layer_artifact_bytes(
    std::size_t stored_record_count,
    std::uint64_t serialized_record_bytes) {
    constexpr std::uint64_t kLayerAndIndexHeaders = 64;
    constexpr std::uint64_t kRecordAndIndexBytes = 16;
    const std::uint64_t count =
        checked_u64(stored_record_count,
                    "file-trace stored record count");
    return checked_add(
        kLayerAndIndexHeaders,
        checked_mul(
            count,
            checked_add(serialized_record_bytes,
                        kRecordAndIndexBytes,
                        "file-trace record bytes"),
            "file-trace layer records"),
        "file-trace layer artifact");
}

std::uint64_t file_trace_manifest_bytes(std::size_t layer_count) {
    return checked_add(
        file_trace_manifest_fixed_bytes(),
        checked_mul(checked_u64(layer_count, "file-trace layer count"),
                    file_trace_manifest_layer_descriptor_bytes(),
                    "file-trace manifest layers"),
        "file-trace manifest");
}

std::uint64_t file_trace_manifest_fixed_bytes() { return 200; }

std::uint64_t file_trace_manifest_layer_descriptor_bytes() {
    return 96;
}

std::uint64_t standalone_checkpoint_layer_artifact_bytes(
    std::size_t stored_record_count,
    std::uint64_t serialized_record_bytes) {
    return checked_add(
        file_trace_layer_artifact_bytes(stored_record_count,
                                        serialized_record_bytes),
        file_trace_manifest_bytes(1),
        "standalone checkpoint layer artifact bytes");
}

std::uint64_t checkpoint_replay_metadata_identity_bytes(
    std::size_t selected_checkpoint_count) {
    // "LMN-CHKPT-SET1", version, three SHA-256 digests, chunk and layer
    // counts, followed by one u64 layer index per selected checkpoint.
    constexpr std::uint64_t kFixedIdentityBytes =
        14U + 1U + 3U * 32U + 2U * sizeof(std::uint64_t);
    return checked_add(
        kFixedIdentityBytes,
        checked_mul(checked_u64(selected_checkpoint_count,
                                "checkpoint metadata layer count"),
                    sizeof(std::uint64_t),
                    "checkpoint metadata layer identities"),
        "checkpoint metadata identity");
}

void PayloadCheckpointReplayProblem::validate() const {
    if (layers.size() < 2) {
        throw std::invalid_argument(
            "checkpoint replay requires output and input layers");
    }
    if (layers.back().kind != LayerKind::Input) {
        throw std::invalid_argument(
            "checkpoint replay requires the input layer last");
    }

    std::uint64_t work = 0;
    for (std::size_t index = 0; index < layers.size(); ++index) {
        const PayloadReplayLayer &layer = layers[index];
        if (layer.layer != index || layer.stored_value_count == 0 ||
            layer.virtual_wire_count == 0 ||
            layer.stored_value_count > layer.virtual_wire_count ||
            (layer.semantic_live_value_count != 0 &&
             (layer.semantic_live_value_count < layer.stored_value_count ||
              layer.semantic_live_value_count >
                  layer.virtual_wire_count)) ||
            layer.rns_limb_count == 0 || layer.checkpoint_bytes == 0 ||
            layer.serialized_ciphertext_bytes == 0 ||
            layer.resident_ciphertext_bytes == 0) {
            throw std::invalid_argument(
                "checkpoint replay layer resources are incomplete");
        }
        if (index + 1U < layers.size() && layer.kind == LayerKind::Input) {
            throw std::invalid_argument(
                "checkpoint replay has an early input layer");
        }
        if (layer.required_proof_depth >= layer.rns_limb_count) {
            throw std::invalid_argument(
                "checkpoint RNS level cannot satisfy proof ingress");
        }
        if ((layer.proof_ingress_serialized_ciphertext_bytes == 0) !=
                (layer.proof_ingress_resident_ciphertext_bytes == 0) ||
            layer.proof_ingress_serialized_ciphertext_bytes >
                layer.serialized_ciphertext_bytes ||
            layer.proof_ingress_resident_ciphertext_bytes >
                layer.resident_ciphertext_bytes) {
            throw std::invalid_argument(
                "checkpoint proof-ingress byte bounds are incomplete or "
                "exceed the natural level");
        }
        const std::uint64_t payload = checked_mul(
            checked_u64(layer.stored_value_count,
                        "layer stored ciphertext count"),
            layer.serialized_ciphertext_bytes,
            "layer serialized payload bytes");
        if (layer.checkpoint_bytes < payload) {
            throw std::invalid_argument(
                "checkpoint bytes omit serialized ciphertext payload");
        }
        if (index == 0 && layer.preferred_checkpoint) {
            throw std::invalid_argument(
                "output layer is not a reverse-GKR checkpoint candidate");
        }
        if (layer.preferred_checkpoint &&
            layer.modulus_switches_after_layer == 0) {
            throw std::invalid_argument(
                "preferred checkpoint is not after a modulus switch");
        }
        if (index + 1U < layers.size()) {
            work = checked_add(work, layer.replay_work_units,
                               "payload replay work");
            const PayloadReplayLayer &source = layers[index + 1U];
            if (source.rns_limb_count < layer.rns_limb_count ||
                source.rns_limb_count - layer.rns_limb_count !=
                    layer.modulus_switches_after_layer) {
                throw std::invalid_argument(
                    "checkpoint RNS levels disagree with modulus switches");
            }
        } else if (layer.replay_work_units != 0 ||
                   layer.modulus_switches_after_layer != 0) {
            throw std::invalid_argument(
                "input layer cannot carry replay work or an after-layer "
                "switch");
        }
    }
    if (work == 0) {
        throw std::invalid_argument(
            "checkpoint replay requires nonzero forward work");
    }
}

void validate_executable_checkpoint_artifact_accounting(
    const PayloadCheckpointReplayProblem &problem) {
    for (const PayloadReplayLayer &layer : problem.layers) {
        if (layer.checkpoint_bytes !=
            standalone_checkpoint_layer_artifact_bytes(
                layer.stored_value_count,
                layer.serialized_ciphertext_bytes)) {
            throw std::invalid_argument(
                "checkpoint replay execution requires standalone one-"
                "layer artifact accounting (including one " +
                std::to_string(file_trace_manifest_bytes(1)) +
                "-byte manifest per layer)");
        }
    }
}

void PayloadCheckpointReplayBudgets::validate() const {
    if (max_live_scratch_bytes == 0 ||
        max_resident_ciphertext_bytes == 0 ||
        max_ciphertexts_per_chunk == 0 ||
        max_recomputation_factor.denominator == 0 ||
        max_recomputation_factor.numerator <
            max_recomputation_factor.denominator ||
        reserved_live_scratch_bytes >= max_live_scratch_bytes ||
        reserved_resident_bytes >= max_resident_ciphertext_bytes) {
        throw std::invalid_argument(
            "checkpoint replay budgets are invalid");
    }
    switch (selection_objective) {
    case PayloadCheckpointSelectionObjective::MinimumStorage:
    case PayloadCheckpointSelectionObjective::MinimumReplayWork:
    case PayloadCheckpointSelectionObjective::OutputOnlyAdjacentLayers:
        break;
    default:
        throw std::invalid_argument(
            "checkpoint replay selection objective is invalid");
    }
}

namespace {

PayloadCheckpointReplayProblem
make_payload_checkpoint_replay_problem_from_layout(
    const LayeredCircuit &circuit,
    const FheEvaluationPlan &evaluation_plan,
    std::span<const LayerWireSupport> support,
    std::span<const LayerStorageLayout> storage,
    std::span<const PayloadLayerResourceEstimate> resources,
    std::uint64_t checkpoint_set_fixed_bytes,
    std::uint64_t checkpoint_set_bytes_per_layer) {
    evaluation_plan.validate(circuit);
    if (resources.size() != circuit.layers.size()) {
        throw std::invalid_argument(
            "checkpoint replay requires one resource estimate per layer");
    }

    PayloadCheckpointReplayProblem problem;
    problem.checkpoint_set_fixed_bytes = checkpoint_set_fixed_bytes;
    problem.checkpoint_set_bytes_per_layer =
        checkpoint_set_bytes_per_layer;
    problem.checkpoint_validation_identity_fixed_bytes =
        checkpoint_replay_metadata_identity_bytes(0);
    problem.checkpoint_validation_identity_bytes_per_layer =
        checkpoint_replay_metadata_identity_bytes(1) -
        checkpoint_replay_metadata_identity_bytes(0);
    problem.layers.reserve(circuit.layers.size());
    for (std::size_t layer = 0; layer < circuit.layers.size(); ++layer) {
        const PayloadLayerResourceEstimate &resource = resources[layer];
        const std::size_t natural_depth =
            evaluation_plan.trace.required_mult_depth_by_layer[layer];
        if (natural_depth == std::numeric_limits<std::size_t>::max() ||
            resource.rns_limb_count != natural_depth + 1U) {
            throw std::invalid_argument(
                "checkpoint replay resource RNS limbs must equal the "
                "natural evaluation level");
        }
        problem.layers.push_back(PayloadReplayLayer{
            layer,
            layer_kind(circuit.layers[layer]),
            storage[layer].stored_wire_count,
            support[layer].padded_wire_count,
            resource.rns_limb_count,
            evaluation_plan.proof_ingress_mult_depth_by_layer[layer],
            evaluation_plan.modulus_switches_after_layer[layer],
            resource.checkpoint_bytes,
            resource.serialized_ciphertext_bytes,
            resource.resident_ciphertext_bytes,
            resource.replay_work_units,
            resource.prefer_post_modulus_switch_checkpoint,
            resource.proof_ingress_serialized_ciphertext_bytes,
            resource.proof_ingress_resident_ciphertext_bytes,
            support[layer].live_wire_count,
        });
        if (const auto *affine = std::get_if<AffineLayer>(&circuit.layers[layer])) {
            problem.layers.back().affine_workspace_bytes = affine_program_workspace_bytes(
                *affine, storage[layer + 1U].padded_wire_count,
                storage[layer].representative_padded_indices,
                resources[layer + 1U].resident_ciphertext_bytes);
        }
    }
    problem.validate();
    return problem;
}

std::vector<std::uint64_t> payload_replay_work_units_from_layout(
    const LayeredCircuit &circuit,
    std::span<const LayerWireSupport> support,
    std::span<const LayerStorageLayout> storage) {
    std::vector<std::uint64_t> result(circuit.layers.size(), 0);
    for (std::size_t layer = 0; layer + 1U < circuit.layers.size();
         ++layer) {
        if (const auto *affine =
                std::get_if<AffineLayer>(&circuit.layers[layer])) {
            const LayerWireSupport &source_support =
                support[layer + 1U];
            const auto program = affine_program_plan(*affine,
                source_support.padded_wire_count,
                storage[layer].representative_padded_indices);
            for (const auto &step : program.steps) {
                const auto &gate = step.output
                    ? affine->gates.at(step.index)
                    : affine->intermediate_gates.at(step.index);
                result[layer] = checked_add(
                    result[layer],
                    affine_gate_replay_work_units(gate, source_support),
                    "payload replay affine layer work");
            }
        } else {
            // A live multiplication/forwarding output is one logical gate
            // evaluation. Its structural padding outputs are absent from the
            // support count.
            result[layer] = checked_u64(
                storage[layer].stored_wire_count,
                "payload replay stored multiplication output count");
        }
    }
    return result;
}

} // namespace

PayloadCheckpointReplayProblem make_payload_checkpoint_replay_problem(
    const LayeredCircuit &circuit, const FheEvaluationPlan &evaluation_plan,
    std::span<const PayloadLayerResourceEstimate> resources,
    std::uint64_t checkpoint_set_fixed_bytes,
    std::uint64_t checkpoint_set_bytes_per_layer) {
    const std::vector<LayerWireSupport> support =
        canonical_trace_wire_support(circuit);
    const std::vector<LayerStorageLayout> storage =
        canonical_trace_storage_layout(circuit);
    return make_payload_checkpoint_replay_problem_from_layout(
        circuit, evaluation_plan, support, storage, resources,
        checkpoint_set_fixed_bytes, checkpoint_set_bytes_per_layer);
}

PayloadCheckpointReplayProblem make_payload_checkpoint_replay_problem(
    const CertifiedCanonicalTraceLayout &certified_trace_layout,
    const FheEvaluationPlan &evaluation_plan,
    std::span<const PayloadLayerResourceEstimate> resources,
    std::uint64_t checkpoint_set_fixed_bytes,
    std::uint64_t checkpoint_set_bytes_per_layer) {
    return make_payload_checkpoint_replay_problem_from_layout(
        certified_trace_layout.circuit(), evaluation_plan,
        certified_trace_layout.layout().wire_support,
        certified_trace_layout.layout().storage, resources,
        checkpoint_set_fixed_bytes, checkpoint_set_bytes_per_layer);
}

std::vector<std::uint64_t>
payload_replay_work_units(const LayeredCircuit &circuit) {
    const std::vector<LayerWireSupport> support =
        canonical_trace_wire_support(circuit);
    const std::vector<LayerStorageLayout> storage =
        canonical_trace_storage_layout(circuit);
    return payload_replay_work_units_from_layout(
        circuit, support, storage);
}

std::vector<std::uint64_t> payload_replay_work_units(
    const CertifiedCanonicalTraceLayout &certified_trace_layout) {
    return payload_replay_work_units_from_layout(
        certified_trace_layout.circuit(),
        certified_trace_layout.layout().wire_support,
        certified_trace_layout.layout().storage);
}


} // namespace laminate::payload
