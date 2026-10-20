#include "laminate/payload/checkpoint/plan.hpp"

#include <algorithm>
#include <limits>
#include <numeric>
#include <span>
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

std::uint64_t saturating_add(std::uint64_t left, std::uint64_t right) {
    if (right > std::numeric_limits<std::uint64_t>::max() - left) {
        return std::numeric_limits<std::uint64_t>::max();
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

struct DoubleWord {
    std::uint64_t high = 0;
    std::uint64_t low = 0;
};

DoubleWord multiply_words(std::uint64_t left, std::uint64_t right) {
    constexpr std::uint64_t kLowMask = 0xffff'ffffULL;
    const std::uint64_t left_low = left & kLowMask;
    const std::uint64_t left_high = left >> 32U;
    const std::uint64_t right_low = right & kLowMask;
    const std::uint64_t right_high = right >> 32U;
    const std::uint64_t low_low = left_low * right_low;
    const std::uint64_t low_high = left_low * right_high;
    const std::uint64_t high_low = left_high * right_low;
    const std::uint64_t high_high = left_high * right_high;
    const std::uint64_t middle =
        (low_low >> 32U) + (low_high & kLowMask) +
        (high_low & kLowMask);
    return DoubleWord{
        high_high + (low_high >> 32U) + (high_low >> 32U) +
            (middle >> 32U),
        (middle << 32U) | (low_low & kLowMask),
    };
}

bool less_equal(DoubleWord left, DoubleWord right) {
    return left.high < right.high ||
           (left.high == right.high && left.low <= right.low);
}

bool factor_fits(std::uint64_t forward, std::uint64_t replay,
                 const PayloadRecomputationFactorLimit &limit) {
    if (replay > std::numeric_limits<std::uint64_t>::max() - forward) {
        return false;
    }
    const std::uint64_t cumulative = forward + replay;
    return less_equal(multiply_words(cumulative, limit.denominator),
                      multiply_words(forward, limit.numerator));
}

struct ChunkPeak {
    std::size_t serialized_input_layer = 0;
    std::size_t serialized_output_layer = 0;
    std::uint64_t serialized_input_bytes = 0;
    std::uint64_t serialized_output_bytes = 0;
    std::size_t resident_input_layer = 0;
    std::size_t resident_output_layer = 0;
    std::uint64_t resident_input_bytes = 0;
    std::uint64_t resident_output_bytes = 0;

    std::uint64_t serialized_total() const {
        return checked_add(serialized_input_bytes,
                           serialized_output_bytes,
                           "serialized chunk pair");
    }

    std::uint64_t resident_total() const {
        return checked_add(resident_input_bytes, resident_output_bytes,
                           "resident chunk pair");
    }

    std::uint64_t ram_total() const {
        return checked_add(serialized_total(), resident_total(),
                           "encoded and decoded chunk RAM");
    }
};

std::uint64_t chunk_bytes(const PayloadReplayLayer &layer,
                          std::size_t chunk_ciphertexts,
                          bool resident) {
    const std::size_t count =
        std::min(chunk_ciphertexts, layer.stored_value_count);
    return checked_mul(
        checked_u64(count, "chunk ciphertext count"),
        resident ? layer.resident_ciphertext_bytes
                 : layer.serialized_ciphertext_bytes,
        resident ? "resident chunk bytes" : "serialized chunk bytes");
}

ChunkPeak relation_chunk_peak(const PayloadCheckpointReplayProblem &problem,
                              std::size_t output_layer,
                              std::size_t chunk_ciphertexts) {
    const std::size_t input_layer = output_layer + 1U;
    const PayloadReplayLayer &input = problem.layers.at(input_layer);
    const PayloadReplayLayer &output = problem.layers.at(output_layer);
    return ChunkPeak{
        input_layer,
        output_layer,
        chunk_bytes(input, chunk_ciphertexts, false),
        chunk_bytes(output, chunk_ciphertexts, false),
        input_layer,
        output_layer,
        checked_add(chunk_bytes(input, chunk_ciphertexts, true),
                    output.affine_workspace_bytes, "affine DAG workspace"),
        chunk_bytes(output, chunk_ciphertexts, true),
    };
}

ChunkPeak direct_source_chunk_peak(
    const PayloadCheckpointReplayProblem &problem, std::size_t source_layer,
    std::size_t chunk_ciphertexts) {
    const PayloadReplayLayer &source = problem.layers.at(source_layer);
    return ChunkPeak{
        source_layer,
        source_layer,
        chunk_bytes(source, chunk_ciphertexts, false),
        0,
        source_layer,
        source_layer,
        chunk_bytes(source, chunk_ciphertexts, true),
        0,
    };
}

void update_ram_peak(ChunkPeak &peak, const ChunkPeak &candidate) {
    if (candidate.ram_total() > peak.ram_total()) {
        peak = candidate;
    }
}

ChunkPeak all_relations_chunk_peak(
    const PayloadCheckpointReplayProblem &problem,
    std::size_t chunk_ciphertexts) {
    ChunkPeak peak =
        relation_chunk_peak(problem, 0, chunk_ciphertexts);
    for (std::size_t output = 1; output + 1U < problem.layers.size();
         ++output) {
        const ChunkPeak candidate =
            relation_chunk_peak(problem, output, chunk_ciphertexts);
        update_ram_peak(peak, candidate);
    }
    return peak;
}

std::uint64_t retained_output_peak_resident_bytes(
    const PayloadCheckpointReplayProblem &problem,
    const PayloadCheckpointReplayBudgets &budgets) {
    const PayloadReplayLayer &output = problem.layers.front();
    const std::uint64_t bytes_per_ciphertext = checked_add(
        output.serialized_ciphertext_bytes,
        output.resident_ciphertext_bytes,
        "encoded and decoded output ciphertext bytes");
    return checked_add(
        budgets.reserved_resident_bytes,
        checked_mul(checked_u64(output.stored_value_count,
                                "stored output ciphertext count"),
                    bytes_per_ciphertext,
                    "retained encrypted output bytes"),
        "retained encrypted output peak RAM");
}

std::uint64_t checkpoint_bytes(
    const PayloadCheckpointReplayProblem &problem,
    std::span<const std::size_t> checkpoints) {
    std::uint64_t result = checked_add(
        problem.checkpoint_set_fixed_bytes,
        checked_mul(checked_u64(checkpoints.size(),
                                "checkpoint metadata count"),
                    problem.checkpoint_set_bytes_per_layer,
                    "checkpoint metadata bytes"),
        "checkpoint-set metadata bytes");
    for (std::size_t layer : checkpoints) {
        result = checked_add(result, problem.layers.at(layer).checkpoint_bytes,
                             "checkpoint-set bytes");
    }
    return result;
}

std::uint64_t checkpoint_metadata_bytes(
    const PayloadCheckpointReplayProblem &problem,
    std::size_t checkpoint_count) {
    return checked_add(
        problem.checkpoint_set_fixed_bytes,
        checked_mul(checked_u64(checkpoint_count,
                                "checkpoint metadata count"),
                    problem.checkpoint_set_bytes_per_layer,
                    "checkpoint metadata bytes"),
        "checkpoint-set metadata bytes");
}

std::uint64_t checkpoint_validation_identity_bytes(
    const PayloadCheckpointReplayProblem &problem,
    std::size_t checkpoint_count) {
    return checked_add(
        problem.checkpoint_validation_identity_fixed_bytes,
        checked_mul(
            checked_u64(checkpoint_count,
                        "checkpoint validation identity count"),
            problem.checkpoint_validation_identity_bytes_per_layer,
            "checkpoint validation identity bytes"),
        "checkpoint validation identity");
}

PayloadLayerArtifactPeak make_artifact_peak(
    const PayloadCheckpointReplayProblem &problem,
    const PayloadCheckpointReplayBudgets &budgets,
    std::uint64_t live_checkpoint_bytes, std::size_t input_layer,
    std::size_t output_layer, bool input_is_checkpoint,
    bool has_output_artifact, bool output_is_checkpoint = false,
    std::uint64_t proof_ingress_artifact_bytes_upper_bound = 0) {
    const std::uint64_t input_bytes =
        problem.layers.at(input_layer).checkpoint_bytes;
    const std::uint64_t transient_input_bytes =
        input_is_checkpoint ? 0 : input_bytes;
    const std::uint64_t output_bytes =
        has_output_artifact
            ? problem.layers.at(output_layer).checkpoint_bytes
            : 0;
    const std::uint64_t peak_without_ingress = checked_add(
        checked_add(
            checked_add(budgets.reserved_live_scratch_bytes,
                        live_checkpoint_bytes, "artifact checkpoint bytes"),
            transient_input_bytes, "transient input artifact bytes"),
        output_bytes, "output artifact bytes");
    const std::uint64_t peak = checked_add(
        peak_without_ingress, proof_ingress_artifact_bytes_upper_bound,
        "proof-ingress artifact bytes");
    return PayloadLayerArtifactPeak{
        input_layer,
        output_layer,
        live_checkpoint_bytes,
        input_bytes,
        input_is_checkpoint,
        transient_input_bytes,
        output_bytes,
        proof_ingress_artifact_bytes_upper_bound,
        !input_is_checkpoint,
        has_output_artifact && !output_is_checkpoint,
        peak,
    };
}

std::uint64_t post_replay_consumer_artifact_bytes(
    const PayloadCheckpointReplayBudgets &budgets,
    std::size_t reduction_layer) {
    if (budgets.post_replay_consumer_artifact_bytes_by_reduction.empty()) {
        return 0;
    }
    return budgets.post_replay_consumer_artifact_bytes_by_reduction.at(
        reduction_layer);
}

std::uint64_t post_replay_consumer_peak(
    const PayloadCheckpointReplayProblem &problem,
    const PayloadCheckpointReplayBudgets &budgets,
    std::uint64_t live_checkpoint_bytes, std::size_t source_layer,
    bool source_is_checkpoint) {
    const PayloadLayerArtifactPeak source_peak = make_artifact_peak(
        problem, budgets, live_checkpoint_bytes, source_layer, source_layer,
        source_is_checkpoint, false);
    return checked_add(
        source_peak.peak_live_scratch_bytes,
        post_replay_consumer_artifact_bytes(budgets, source_layer - 1U),
        "post-replay consumer artifact peak");
}

std::uint64_t proof_ingress_artifact_bytes_upper_bound(
    const PayloadReplayLayer &layer) {
    const std::size_t ingress_limbs = layer.required_proof_depth + 1U;
    if (ingress_limbs == layer.rns_limb_count) {
        return 0;
    }
    const std::uint64_t natural_payload = checked_mul(
        checked_u64(layer.stored_value_count,
                    "proof-ingress ciphertext count"),
        layer.serialized_ciphertext_bytes,
        "natural checkpoint ciphertext payload");
    if (natural_payload > layer.checkpoint_bytes) {
        throw std::logic_error(
            "natural ciphertext payload exceeds its checkpoint artifact");
    }
    const std::uint64_t ingress_serialized =
        layer.proof_ingress_serialized_ciphertext_bytes == 0
            ? layer.serialized_ciphertext_bytes
            : layer.proof_ingress_serialized_ciphertext_bytes;
    return checked_add(
        layer.checkpoint_bytes - natural_payload,
        checked_mul(checked_u64(layer.stored_value_count,
                                "proof-ingress ciphertext count"),
                    ingress_serialized,
                    "proof-ingress checkpoint ciphertext payload"),
        "proof-ingress checkpoint artifact");
}

std::uint64_t proof_ingress_peak_resident_bytes(
    const PayloadReplayLayer &layer,
    const PayloadCheckpointReplayBudgets &budgets) {
    if (proof_ingress_artifact_bytes_upper_bound(layer) == 0) {
        return budgets.reserved_resident_bytes;
    }
    const std::uint64_t natural_ciphertext = checked_add(
        layer.serialized_ciphertext_bytes, layer.resident_ciphertext_bytes,
        "natural proof-ingress input ciphertext bytes");
    const std::uint64_t ingress_ciphertext = checked_add(
        layer.proof_ingress_serialized_ciphertext_bytes == 0
            ? layer.serialized_ciphertext_bytes
            : layer.proof_ingress_serialized_ciphertext_bytes,
        layer.proof_ingress_resident_ciphertext_bytes == 0
            ? layer.resident_ciphertext_bytes
            : layer.proof_ingress_resident_ciphertext_bytes,
        "reduced proof-ingress output ciphertext bytes");
    return checked_add(
        budgets.reserved_resident_bytes,
        checked_add(natural_ciphertext, ingress_ciphertext,
                    "proof-ingress input and output ciphertext bytes"),
        "proof-ingress resident peak");
}

void update_artifact_peak(PayloadLayerArtifactPeak &peak,
                          const PayloadLayerArtifactPeak &candidate) {
    if (candidate.peak_live_scratch_bytes >
        peak.peak_live_scratch_bytes) {
        peak = candidate;
    }
}

PayloadLayerArtifactPeak forward_artifact_peak(
    const PayloadCheckpointReplayProblem &problem,
    const PayloadCheckpointReplayBudgets &budgets,
    std::span<const std::size_t> checkpoints) {
    PayloadLayerArtifactPeak peak;
    bool initialized = false;
    const std::uint64_t metadata =
        checkpoint_metadata_bytes(problem, checkpoints.size());
    for (std::size_t output = problem.layers.size() - 1U; output-- > 0;) {
        const std::size_t input = output + 1U;
        std::uint64_t live = metadata;
        for (std::size_t checkpoint : checkpoints) {
            if (checkpoint > output) {
                live = checked_add(
                    live, problem.layers[checkpoint].checkpoint_bytes,
                    "forward live checkpoints");
            }
        }
        const bool input_is_checkpoint =
            std::binary_search(checkpoints.begin(), checkpoints.end(), input);
        const bool output_is_checkpoint =
            std::binary_search(checkpoints.begin(), checkpoints.end(), output);
        const PayloadLayerArtifactPeak candidate = make_artifact_peak(
            problem, budgets, live, input, output, input_is_checkpoint, true,
            output_is_checkpoint);
        if (!initialized) {
            peak = candidate;
            initialized = true;
        } else {
            update_artifact_peak(peak, candidate);
        }
    }
    if (!initialized) {
        throw std::logic_error("forward artifact ledger has no relation");
    }
    return peak;
}

std::uint64_t forward_work(
    const PayloadCheckpointReplayProblem &problem) {
    std::uint64_t result = 0;
    for (std::size_t layer = 0; layer + 1U < problem.layers.size();
         ++layer) {
        result = checked_add(result, problem.layers[layer].replay_work_units,
                             "initial forward work");
    }
    return result;
}

std::vector<std::vector<std::uint64_t>> segment_replay_costs(
    const PayloadCheckpointReplayProblem &problem) {
    const std::size_t count = problem.layers.size();
    std::vector<std::vector<std::uint64_t>> costs(
        count, std::vector<std::uint64_t>(count, 0));
    for (std::size_t lower = 0; lower + 1U < count; ++lower) {
        for (std::size_t checkpoint = lower + 1U; checkpoint < count;
             ++checkpoint) {
            std::uint64_t segment = 0;
            for (std::size_t source = lower + 1U; source < checkpoint;
                 ++source) {
                std::uint64_t source_replay = 0;
                for (std::size_t output = source; output < checkpoint;
                     ++output) {
                    source_replay = saturating_add(
                        source_replay,
                        problem.layers[output].replay_work_units);
                }
                segment = saturating_add(segment, source_replay);
            }
            costs[lower][checkpoint] = segment;
        }
    }
    return costs;
}

struct SelectionState {
    std::uint64_t checkpoint_layer_bytes = 0;
    std::uint64_t replay_work_units = 0;
    std::uint64_t checkpoint_metadata_bytes = 0;
    std::uint64_t partial_peak_live_scratch_bytes = 0;
    std::size_t preferred_checkpoints = 0;
    std::size_t ordinary_checkpoints = 0;
    std::vector<std::size_t> checkpoints;
};

std::uint64_t selected_checkpoint_bytes(const SelectionState &state) {
    return checked_add(state.checkpoint_layer_bytes,
                       state.checkpoint_metadata_bytes,
                       "selected checkpoint-set bytes");
}

bool dominates(const SelectionState &left, const SelectionState &right) {
    const bool no_worse =
        left.checkpoint_layer_bytes <= right.checkpoint_layer_bytes &&
        left.replay_work_units <= right.replay_work_units &&
        left.checkpoint_metadata_bytes <=
            right.checkpoint_metadata_bytes &&
        left.partial_peak_live_scratch_bytes <=
            right.partial_peak_live_scratch_bytes &&
        left.ordinary_checkpoints <= right.ordinary_checkpoints &&
        left.preferred_checkpoints >= right.preferred_checkpoints;
    const bool strictly_better =
        left.checkpoint_layer_bytes < right.checkpoint_layer_bytes ||
        left.replay_work_units < right.replay_work_units ||
        left.checkpoint_metadata_bytes <
            right.checkpoint_metadata_bytes ||
        left.partial_peak_live_scratch_bytes <
            right.partial_peak_live_scratch_bytes ||
        left.ordinary_checkpoints < right.ordinary_checkpoints ||
        left.preferred_checkpoints > right.preferred_checkpoints;
    return no_worse && strictly_better;
}

void insert_frontier(std::vector<SelectionState> &frontier,
                     SelectionState candidate) {
    for (const SelectionState &current : frontier) {
        if (dominates(current, candidate)) {
            return;
        }
        if (current.checkpoint_layer_bytes ==
                candidate.checkpoint_layer_bytes &&
            current.replay_work_units == candidate.replay_work_units &&
            current.checkpoint_metadata_bytes ==
                candidate.checkpoint_metadata_bytes &&
            current.partial_peak_live_scratch_bytes ==
                candidate.partial_peak_live_scratch_bytes &&
            current.preferred_checkpoints ==
                candidate.preferred_checkpoints &&
            current.ordinary_checkpoints == candidate.ordinary_checkpoints &&
            current.checkpoints <= candidate.checkpoints) {
            return;
        }
    }
    std::erase_if(frontier, [&](const SelectionState &current) {
        if (dominates(candidate, current)) {
            return true;
        }
        return current.checkpoint_layer_bytes ==
                   candidate.checkpoint_layer_bytes &&
               current.replay_work_units == candidate.replay_work_units &&
               current.checkpoint_metadata_bytes ==
                   candidate.checkpoint_metadata_bytes &&
               current.partial_peak_live_scratch_bytes ==
                   candidate.partial_peak_live_scratch_bytes &&
               current.preferred_checkpoints ==
                   candidate.preferred_checkpoints &&
               current.ordinary_checkpoints ==
                   candidate.ordinary_checkpoints &&
               candidate.checkpoints < current.checkpoints;
    });
    frontier.push_back(std::move(candidate));
}

std::size_t largest_feasible_chunk(
    const PayloadCheckpointReplayProblem &problem,
    const PayloadCheckpointReplayBudgets &budgets) {
    if (retained_output_peak_resident_bytes(problem, budgets) >
        budgets.max_resident_ciphertext_bytes) {
        return 0;
    }
    const auto fits = [&](std::size_t chunk) {
        const ChunkPeak peak = all_relations_chunk_peak(problem, chunk);
        const std::uint64_t resident = checked_add(
            budgets.reserved_resident_bytes, peak.ram_total(),
            "forward encoded and decoded RAM");
        return resident <= budgets.max_resident_ciphertext_bytes;
    };

    if (!fits(1)) {
        return 0;
    }
    std::size_t lower = 1;
    std::size_t upper = budgets.max_ciphertexts_per_chunk;
    while (lower < upper) {
        const std::size_t middle = lower + (upper - lower + 1U) / 2U;
        if (fits(middle)) {
            lower = middle;
        } else {
            upper = middle - 1U;
        }
    }
    return lower;
}

PayloadCheckpointStorageProfile make_profile(
    const PayloadCheckpointReplayProblem &problem,
    const PayloadCheckpointReplayBudgets &budgets,
    std::vector<std::size_t> checkpoints, std::uint64_t replay_work_units,
    bool include_segments,
    std::vector<PayloadReplaySegment> *segments) {
    PayloadCheckpointStorageProfile profile;
    profile.checkpoint_layers = std::move(checkpoints);
    profile.checkpoint_metadata_bytes = checkpoint_metadata_bytes(
        problem, profile.checkpoint_layers.size());
    profile.checkpoint_metadata_validation_buffer_bytes = checked_add(
        profile.checkpoint_metadata_bytes,
        checkpoint_validation_identity_bytes(
            problem, profile.checkpoint_layers.size()),
        "checkpoint metadata validation buffers");
    profile.checkpoint_bytes =
        checkpoint_bytes(problem, profile.checkpoint_layers);
    profile.initial_forward_work_units = forward_work(problem);
    profile.replay_work_units = replay_work_units;
    profile.cumulative_work_units = checked_add(
        profile.initial_forward_work_units, replay_work_units,
        "cumulative payload work");
    profile.recomputation_feasible = factor_fits(
        profile.initial_forward_work_units, replay_work_units,
        budgets.max_recomputation_factor);

    profile.forward_artifact_peak = forward_artifact_peak(
        problem, budgets, profile.checkpoint_layers);
    profile.forward_peak_live_scratch_bytes =
        profile.forward_artifact_peak.peak_live_scratch_bytes;
    profile.peak_live_scratch_bytes =
        profile.forward_peak_live_scratch_bytes;
    profile.live_scratch_feasible =
        profile.peak_live_scratch_bytes <= budgets.max_live_scratch_bytes;

    profile.chunk_ciphertexts = largest_feasible_chunk(problem, budgets);
    profile.retained_output_peak_resident_bytes =
        retained_output_peak_resident_bytes(problem, budgets);
    const std::size_t modeled_chunk =
        profile.chunk_ciphertexts == 0 ? 1 : profile.chunk_ciphertexts;
    const ChunkPeak forward_peak =
        all_relations_chunk_peak(problem, modeled_chunk);
    for (std::size_t output = 0; output + 1U < problem.layers.size();
         ++output) {
        profile.dense_multiplication_alias_cache_peak_resident_bytes =
            std::max(
                profile
                    .dense_multiplication_alias_cache_peak_resident_bytes,
                dense_multiplication_alias_cache_peak_resident_bytes(
                    problem, budgets, output));
    }
    const std::uint64_t output_and_metadata_peak = checked_add(
        profile.retained_output_peak_resident_bytes,
        profile.checkpoint_metadata_validation_buffer_bytes,
        "retained output and checkpoint metadata RAM");
    profile.peak_resident_bytes = std::max(
        profile.dense_multiplication_alias_cache_peak_resident_bytes,
        std::max(output_and_metadata_peak,
                 checked_add(budgets.reserved_resident_bytes,
                             forward_peak.ram_total(),
                             "forward encoded and decoded peak RAM")));
    profile.resident_feasible =
        profile.chunk_ciphertexts != 0 &&
        profile.peak_resident_bytes <=
        budgets.max_resident_ciphertext_bytes;

    if (include_segments && segments == nullptr) {
        throw std::logic_error("replay segment destination is missing");
    }
    if (segments != nullptr) {
        segments->clear();
        segments->reserve(problem.layers.size() - 1U);
    }

    std::uint64_t replay_check = 0;
    for (std::size_t source = 1; source < problem.layers.size(); ++source) {
        const auto found = std::lower_bound(profile.checkpoint_layers.begin(),
                                            profile.checkpoint_layers.end(),
                                            source);
        if (found == profile.checkpoint_layers.end()) {
            throw std::logic_error(
                "checkpoint plan cannot supply a GKR source layer");
        }
        const std::size_t checkpoint = *found;
        std::uint64_t live_checkpoint_bytes =
            profile.checkpoint_metadata_bytes;
        for (auto current = found;
             current != profile.checkpoint_layers.end(); ++current) {
            live_checkpoint_bytes = checked_add(
                live_checkpoint_bytes,
                problem.layers[*current].checkpoint_bytes,
                "live reverse-GKR checkpoints");
        }

        ChunkPeak ram_peak = direct_source_chunk_peak(
            problem, source, modeled_chunk);
        PayloadLayerArtifactPeak artifact_peak = make_artifact_peak(
            problem, budgets, live_checkpoint_bytes, source, source, true,
            false);
        std::uint64_t step_replay = 0;
        if (checkpoint != source) {
            ram_peak = relation_chunk_peak(problem, checkpoint - 1U,
                                           modeled_chunk);
            artifact_peak = make_artifact_peak(
                problem, budgets, live_checkpoint_bytes, checkpoint,
                checkpoint - 1U, true, true);
            for (std::size_t output = checkpoint - 1U;; --output) {
                const ChunkPeak ram_candidate =
                    relation_chunk_peak(problem, output, modeled_chunk);
                update_ram_peak(ram_peak, ram_candidate);
                const std::size_t input = output + 1U;
                const PayloadLayerArtifactPeak artifact_candidate =
                    make_artifact_peak(
                        problem, budgets, live_checkpoint_bytes, input,
                        output, input == checkpoint, true);
                update_artifact_peak(artifact_peak, artifact_candidate);
                step_replay = checked_add(
                    step_replay,
                    problem.layers[output].replay_work_units,
                    "GKR source replay work");
                if (output == source) {
                    break;
                }
            }
        }
        const bool source_is_checkpoint = checkpoint == source;
        const std::uint64_t ingress_artifact_bound =
            proof_ingress_artifact_bytes_upper_bound(
                problem.layers[source]);
        const PayloadLayerArtifactPeak ingress_artifact_peak =
            make_artifact_peak(
                problem, budgets, live_checkpoint_bytes, source, source,
                source_is_checkpoint, false, false,
                ingress_artifact_bound);
        update_artifact_peak(artifact_peak, ingress_artifact_peak);
        const std::uint64_t ingress_resident_peak =
            proof_ingress_peak_resident_bytes(problem.layers[source],
                                              budgets);
        const std::uint64_t consumer_artifact =
            post_replay_consumer_artifact_bytes(budgets, source - 1U);
        const std::uint64_t consumer_peak = post_replay_consumer_peak(
            problem, budgets, live_checkpoint_bytes, source,
            source_is_checkpoint);
        std::uint64_t replay_alias_cache_peak = 0;
        for (std::size_t output = source; output < checkpoint; ++output) {
            replay_alias_cache_peak = std::max(
                replay_alias_cache_peak,
                dense_multiplication_alias_cache_peak_resident_bytes(
                    problem, budgets, output));
        }
        replay_check = checked_add(replay_check, step_replay,
                                   "GKR replay ledger");

        const std::uint64_t retired_checkpoint =
            checkpoint == source
                ? problem.layers[source].checkpoint_bytes
                : 0;
        const std::uint64_t retired_fixed_metadata =
            checkpoint == source && source + 1U == problem.layers.size()
                ? profile.checkpoint_metadata_bytes
                : 0;
        if (retired_checkpoint > live_checkpoint_bytes ||
            retired_fixed_metadata >
                live_checkpoint_bytes - retired_checkpoint) {
            throw std::logic_error(
                "reverse-GKR checkpoint retirement underflows");
        }
        const std::uint64_t live_after =
            live_checkpoint_bytes - retired_checkpoint -
            retired_fixed_metadata;

        PayloadReplaySegment segment{
            source - 1U,
            source,
            checkpoint,
            source,
            checkpoint,
            step_replay,
            ingress_artifact_bound,
            ingress_artifact_peak.peak_live_scratch_bytes,
            ingress_resident_peak,
            consumer_artifact,
            consumer_peak,
            artifact_peak,
            ram_peak.serialized_input_layer,
            ram_peak.serialized_output_layer,
            ram_peak.serialized_input_bytes,
            ram_peak.serialized_output_bytes,
            ram_peak.resident_input_layer,
            ram_peak.resident_output_layer,
            ram_peak.resident_input_bytes,
            ram_peak.resident_output_bytes,
            std::max(
                replay_alias_cache_peak,
                std::max(
                    checked_add(
                        budgets.reserved_resident_bytes,
                        ram_peak.ram_total(),
                        "reverse-GKR encoded and decoded peak RAM"),
                    ingress_resident_peak)),
            retired_checkpoint,
            retired_fixed_metadata,
            live_after,
        };
        profile.peak_live_scratch_bytes = std::max(
            profile.peak_live_scratch_bytes,
            segment.artifact_peak.peak_live_scratch_bytes);
        profile.proof_ingress_artifact_bytes_upper_bound = std::max(
            profile.proof_ingress_artifact_bytes_upper_bound,
            segment.proof_ingress_artifact_bytes_upper_bound);
        profile.proof_ingress_peak_live_scratch_bytes = std::max(
            profile.proof_ingress_peak_live_scratch_bytes,
            segment.proof_ingress_peak_live_scratch_bytes);
        profile.proof_ingress_peak_resident_bytes = std::max(
            profile.proof_ingress_peak_resident_bytes,
            segment.proof_ingress_peak_resident_bytes);
        profile.post_replay_consumer_artifact_bytes_upper_bound = std::max(
            profile.post_replay_consumer_artifact_bytes_upper_bound,
            segment.post_replay_consumer_artifact_bytes);
        profile.post_replay_consumer_peak_live_scratch_bytes = std::max(
            profile.post_replay_consumer_peak_live_scratch_bytes,
            segment.post_replay_consumer_peak_live_scratch_bytes);
        profile.peak_live_scratch_bytes = std::max(
            profile.peak_live_scratch_bytes,
            segment.post_replay_consumer_peak_live_scratch_bytes);
        profile.peak_resident_bytes = std::max(
            profile.peak_resident_bytes, segment.peak_resident_bytes);
        profile.peak_resident_bytes = std::max(
            profile.peak_resident_bytes,
            segment.proof_ingress_peak_resident_bytes);
        if (include_segments) {
            segments->push_back(std::move(segment));
        }
    }
    if (replay_check != replay_work_units) {
        throw std::logic_error("checkpoint replay-work ledger drifted");
    }
    profile.live_scratch_feasible =
        profile.peak_live_scratch_bytes <= budgets.max_live_scratch_bytes;
    profile.resident_feasible =
        profile.chunk_ciphertexts != 0 &&
        profile.peak_resident_bytes <=
        budgets.max_resident_ciphertext_bytes;
    return profile;
}

PayloadCheckpointStorageProfile make_output_only_profile(
    const PayloadCheckpointReplayProblem &problem,
    const PayloadCheckpointReplayBudgets &budgets) {
    PayloadCheckpointStorageProfile profile;
    profile.initial_forward_work_units = forward_work(problem);
    profile.replay_work_units = 0;
    profile.cumulative_work_units = profile.initial_forward_work_units;
    profile.recomputation_feasible = factor_fits(
        profile.initial_forward_work_units, 0,
        budgets.max_recomputation_factor);

    bool initialized = false;
    for (std::size_t output = problem.layers.size() - 1U; output-- > 0;) {
        const PayloadLayerArtifactPeak candidate = make_artifact_peak(
            problem, budgets, 0, output + 1U, output, false, true);
        if (!initialized ||
            candidate.peak_live_scratch_bytes >
                profile.forward_artifact_peak.peak_live_scratch_bytes) {
            profile.forward_artifact_peak = candidate;
            initialized = true;
        }
    }
    if (!initialized) {
        throw std::logic_error(
            "output-only artifact ledger has no relation");
    }
    profile.forward_peak_live_scratch_bytes =
        profile.forward_artifact_peak.peak_live_scratch_bytes;
    profile.peak_live_scratch_bytes =
        profile.forward_peak_live_scratch_bytes;
    profile.live_scratch_feasible =
        profile.peak_live_scratch_bytes <= budgets.max_live_scratch_bytes;

    profile.chunk_ciphertexts = largest_feasible_chunk(problem, budgets);
    profile.retained_output_peak_resident_bytes =
        retained_output_peak_resident_bytes(problem, budgets);
    const std::size_t modeled_chunk =
        profile.chunk_ciphertexts == 0 ? 1 : profile.chunk_ciphertexts;
    const ChunkPeak forward_peak =
        all_relations_chunk_peak(problem, modeled_chunk);
    for (std::size_t output = 0; output + 1U < problem.layers.size();
         ++output) {
        profile.dense_multiplication_alias_cache_peak_resident_bytes =
            std::max(
                profile
                    .dense_multiplication_alias_cache_peak_resident_bytes,
                dense_multiplication_alias_cache_peak_resident_bytes(
                    problem, budgets, output));
    }
    profile.peak_resident_bytes = std::max(
        profile.dense_multiplication_alias_cache_peak_resident_bytes,
        std::max(profile.retained_output_peak_resident_bytes,
                 checked_add(budgets.reserved_resident_bytes,
                             forward_peak.ram_total(),
                             "output-only encoded and decoded peak RAM")));
    profile.resident_feasible =
        profile.chunk_ciphertexts != 0 &&
        profile.peak_resident_bytes <=
            budgets.max_resident_ciphertext_bytes;
    return profile;
}

bool preferred_only_better(const SelectionState &left,
                           const SelectionState &right) {
    const std::uint64_t left_bytes = selected_checkpoint_bytes(left);
    const std::uint64_t right_bytes = selected_checkpoint_bytes(right);
    if (left_bytes != right_bytes) {
        return left_bytes < right_bytes;
    }
    if (left.replay_work_units != right.replay_work_units) {
        return left.replay_work_units < right.replay_work_units;
    }
    if (left.checkpoints.size() != right.checkpoints.size()) {
        return left.checkpoints.size() < right.checkpoints.size();
    }
    return left.checkpoints < right.checkpoints;
}

bool fallback_better(const SelectionState &left,
                     const SelectionState &right) {
    if (left.ordinary_checkpoints != right.ordinary_checkpoints) {
        return left.ordinary_checkpoints < right.ordinary_checkpoints;
    }
    const std::uint64_t left_bytes = selected_checkpoint_bytes(left);
    const std::uint64_t right_bytes = selected_checkpoint_bytes(right);
    if (left_bytes != right_bytes) {
        return left_bytes < right_bytes;
    }
    if (left.replay_work_units != right.replay_work_units) {
        return left.replay_work_units < right.replay_work_units;
    }
    if (left.preferred_checkpoints != right.preferred_checkpoints) {
        return left.preferred_checkpoints > right.preferred_checkpoints;
    }
    return left.checkpoints < right.checkpoints;
}

bool minimum_replay_better(const SelectionState &left,
                           const SelectionState &right) {
    if (left.replay_work_units != right.replay_work_units) {
        return left.replay_work_units < right.replay_work_units;
    }
    const std::uint64_t left_bytes = selected_checkpoint_bytes(left);
    const std::uint64_t right_bytes = selected_checkpoint_bytes(right);
    if (left_bytes != right_bytes) {
        return left_bytes < right_bytes;
    }
    if (left.partial_peak_live_scratch_bytes !=
        right.partial_peak_live_scratch_bytes) {
        return left.partial_peak_live_scratch_bytes <
               right.partial_peak_live_scratch_bytes;
    }
    if (left.checkpoints.size() != right.checkpoints.size()) {
        return left.checkpoints.size() < right.checkpoints.size();
    }
    if (left.ordinary_checkpoints != right.ordinary_checkpoints) {
        return left.ordinary_checkpoints < right.ordinary_checkpoints;
    }
    if (left.preferred_checkpoints != right.preferred_checkpoints) {
        return left.preferred_checkpoints > right.preferred_checkpoints;
    }
    return left.checkpoints < right.checkpoints;
}

/// Exact disk peak contributed by a partial checkpoint set whose final entry
/// is treated as the temporary input boundary. Extending two partial states
/// with the same higher checkpoints adds the same live bytes to every edge
/// below this boundary; above it, the partial states contribute only their
/// retained metadata. These two values therefore make frontier dominance
/// safe for location-dependent artifact sizes.
std::uint64_t partial_artifact_peak(
    const PayloadCheckpointReplayProblem &problem,
    const PayloadCheckpointReplayBudgets &budgets,
    std::span<const std::size_t> checkpoints) {
    if (checkpoints.empty()) {
        throw std::logic_error("partial checkpoint set is empty");
    }
    const std::size_t boundary = checkpoints.back();
    const std::uint64_t metadata =
        checkpoint_metadata_bytes(problem, checkpoints.size());
    std::uint64_t peak = 0;

    for (std::size_t output = boundary; output-- > 0;) {
        const std::size_t input = output + 1U;
        std::uint64_t live = metadata;
        for (std::size_t checkpoint : checkpoints) {
            if (checkpoint > output) {
                live = checked_add(
                    live, problem.layers[checkpoint].checkpoint_bytes,
                    "partial forward checkpoints");
            }
        }
        const PayloadLayerArtifactPeak edge = make_artifact_peak(
            problem, budgets, live, input, output,
            std::binary_search(checkpoints.begin(), checkpoints.end(),
                               input),
            true,
            std::binary_search(checkpoints.begin(), checkpoints.end(),
                               output));
        peak = std::max(peak, edge.peak_live_scratch_bytes);
    }

    for (std::size_t source = 1; source <= boundary; ++source) {
        const auto found = std::lower_bound(
            checkpoints.begin(), checkpoints.end(), source);
        if (found == checkpoints.end()) {
            throw std::logic_error(
                "partial checkpoint set cannot supply a source");
        }
        const std::size_t checkpoint = *found;
        std::uint64_t live = metadata;
        for (auto current = found; current != checkpoints.end(); ++current) {
            live = checked_add(
                live, problem.layers[*current].checkpoint_bytes,
                "partial reverse checkpoints");
        }
        if (checkpoint == source) {
            peak = std::max(
                peak,
                make_artifact_peak(problem, budgets, live, source, source,
                                   true, false)
                    .peak_live_scratch_bytes);
        } else {
            for (std::size_t output = checkpoint - 1U;; --output) {
                const std::size_t input = output + 1U;
                const PayloadLayerArtifactPeak edge = make_artifact_peak(
                    problem, budgets, live, input, output,
                    input == checkpoint, true);
                peak = std::max(peak, edge.peak_live_scratch_bytes);
                if (output == source) {
                    break;
                }
            }
        }
        const std::uint64_t ingress_bound =
            proof_ingress_artifact_bytes_upper_bound(
                problem.layers[source]);
        peak = std::max(
            peak,
            make_artifact_peak(problem, budgets, live, source, source,
                               checkpoint == source, false, false,
                               ingress_bound)
                .peak_live_scratch_bytes);
        peak = std::max(
            peak,
            post_replay_consumer_peak(problem, budgets, live, source,
                                      checkpoint == source));
    }
    return peak;
}

std::vector<SelectionState> selection_frontier(
    const PayloadCheckpointReplayProblem &problem,
    const PayloadCheckpointReplayBudgets &budgets, bool preferred_only) {
    const std::size_t count = problem.layers.size();
    const std::size_t input_layer = count - 1U;
    const std::uint64_t initial_work = forward_work(problem);
    const auto costs = segment_replay_costs(problem);
    std::vector<std::vector<SelectionState>> frontiers(count);

    for (std::size_t checkpoint = 1; checkpoint < count; ++checkpoint) {
        const bool mandatory = checkpoint == input_layer;
        if (!mandatory &&
            (preferred_only &&
             !problem.layers[checkpoint].preferred_checkpoint)) {
            continue;
        }

        const auto extend = [&](const SelectionState *prefix,
                                std::size_t lower) {
            SelectionState candidate =
                prefix == nullptr ? SelectionState{} : *prefix;
            candidate.checkpoint_layer_bytes = checked_add(
                candidate.checkpoint_layer_bytes,
                problem.layers[checkpoint].checkpoint_bytes,
                "selected checkpoint bytes");
            if (costs[lower][checkpoint] >
                std::numeric_limits<std::uint64_t>::max() -
                    candidate.replay_work_units) {
                return;
            }
            candidate.replay_work_units += costs[lower][checkpoint];
            if (!factor_fits(initial_work, candidate.replay_work_units,
                             budgets.max_recomputation_factor)) {
                return;
            }
            const std::uint64_t with_fixed = checked_add(
                checkpoint_metadata_bytes(
                    problem, candidate.checkpoints.size() + 1U),
                candidate.checkpoint_layer_bytes,
                "selected checkpoint-set bytes");
            if (with_fixed > budgets.max_live_scratch_bytes) {
                return;
            }
            if (!mandatory) {
                if (problem.layers[checkpoint].preferred_checkpoint) {
                    ++candidate.preferred_checkpoints;
                } else {
                    ++candidate.ordinary_checkpoints;
                }
            }
            candidate.checkpoints.push_back(checkpoint);
            candidate.checkpoint_metadata_bytes =
                checkpoint_metadata_bytes(problem,
                                          candidate.checkpoints.size());
            candidate.partial_peak_live_scratch_bytes =
                partial_artifact_peak(problem, budgets,
                                      candidate.checkpoints);
            if (candidate.partial_peak_live_scratch_bytes >
                budgets.max_live_scratch_bytes) {
                return;
            }
            insert_frontier(frontiers[checkpoint], std::move(candidate));
        };

        extend(nullptr, 0);
        for (std::size_t lower = 1; lower < checkpoint; ++lower) {
            for (const SelectionState &prefix : frontiers[lower]) {
                extend(&prefix, lower);
            }
        }
    }
    return frontiers[input_layer];
}

std::vector<SelectionState> feasible_selections(
    const PayloadCheckpointReplayProblem &problem,
    const PayloadCheckpointReplayBudgets &budgets, bool preferred_only) {
    std::vector<SelectionState> result;
    for (SelectionState &state :
         selection_frontier(problem, budgets, preferred_only)) {
        const PayloadCheckpointStorageProfile profile = make_profile(
            problem, budgets, state.checkpoints, state.replay_work_units,
            false, nullptr);
        if (profile.feasible()) {
            result.push_back(std::move(state));
        }
    }
    return result;
}

} // namespace

std::uint64_t dense_multiplication_alias_cache_peak_resident_bytes(
    const PayloadCheckpointReplayProblem &problem,
    const PayloadCheckpointReplayBudgets &budgets,
    std::size_t output_layer) {
    if (output_layer + 1U >= problem.layers.size() ||
        problem.layers[output_layer].kind != LayerKind::Multiplication) {
        return 0;
    }
    const PayloadReplayLayer &source = problem.layers[output_layer + 1U];
    const PayloadReplayLayer &output = problem.layers[output_layer];
    if (source.semantic_live_value_count == 0 ||
        source.stored_value_count >= source.semantic_live_value_count) {
        return 0;
    }

    // Optional caches may consume otherwise idle admitted RAM, but never make
    // an otherwise feasible plan fail. Bound the arithmetic directly by the
    // global cap so an oversized candidate simply retains the chunked path.
    const std::uint64_t cap = budgets.max_resident_ciphertext_bytes;
    if (budgets.reserved_resident_bytes >= cap) {
        return 0;
    }
    const std::uint64_t source_count =
        checked_u64(source.stored_value_count,
                    "dense multiplication alias-cache source count");
    const std::uint64_t cache_capacity =
        cap - budgets.reserved_resident_bytes;
    if (source.resident_ciphertext_bytes == 0 ||
        source_count >
            cache_capacity / source.resident_ciphertext_bytes) {
        return 0;
    }
    const std::uint64_t cache_base =
        budgets.reserved_resident_bytes +
        source_count * source.resident_ciphertext_bytes;
    if (source.serialized_ciphertext_bytes > cap - cache_base ||
        output.serialized_ciphertext_bytes > cap - cache_base ||
        output.resident_ciphertext_bytes >
            cap - cache_base - output.serialized_ciphertext_bytes) {
        return 0;
    }
    return std::max(
        cache_base + source.serialized_ciphertext_bytes,
        cache_base + output.serialized_ciphertext_bytes +
            output.resident_ciphertext_bytes);
}

PayloadCheckpointReplayPlan plan_payload_checkpoint_replay(
    const PayloadCheckpointReplayProblem &problem,
    const PayloadCheckpointReplayBudgets &budgets) {
    problem.validate();
    budgets.validate();
    if (!budgets.post_replay_consumer_artifact_bytes_by_reduction.empty() &&
        budgets.post_replay_consumer_artifact_bytes_by_reduction.size() !=
            problem.layers.size() - 1U) {
        throw std::invalid_argument(
            "checkpoint replay requires one post-replay consumer artifact "
            "bound per reduction");
    }

    PayloadCheckpointReplayPlan result;
    std::vector<std::size_t> full_layers(problem.layers.size());
    std::iota(full_layers.begin(), full_layers.end(), std::size_t{0});
    result.full_trace_reference = make_profile(
        problem, budgets, std::move(full_layers), 0, false, nullptr);

    if (budgets.selection_objective ==
        PayloadCheckpointSelectionObjective::OutputOnlyAdjacentLayers) {
        if (!budgets.post_replay_consumer_artifact_bytes_by_reduction.empty()) {
            throw std::invalid_argument(
                "output-only payload planning has no post-replay consumer");
        }
        result.selected = make_output_only_profile(problem, budgets);
        if (!result.selected.feasible()) {
            throw std::invalid_argument(
                "output-only adjacent-layer execution exceeds the supplied "
                "disk or RAM budget");
        }
        return result;
    }

    const bool minimum_storage =
        budgets.selection_objective ==
        PayloadCheckpointSelectionObjective::MinimumStorage;
    bool preferred_only = minimum_storage;
    std::vector<SelectionState> candidates = feasible_selections(
        problem, budgets, preferred_only);
    if (minimum_storage && candidates.empty()) {
        preferred_only = false;
        candidates = feasible_selections(problem, budgets, false);
    }
    if (candidates.empty()) {
        throw std::invalid_argument(
            "no checkpoint replay schedule satisfies the supplied budgets");
    }

    const auto better = [&](const SelectionState &left,
                            const SelectionState &right) {
        if (!minimum_storage) {
            return minimum_replay_better(left, right);
        }
        return preferred_only ? preferred_only_better(left, right)
                              : fallback_better(left, right);
    };
    const SelectionState &selected = *std::min_element(
        candidates.begin(), candidates.end(),
        [&](const SelectionState &left, const SelectionState &right) {
            return better(left, right);
        });
    result.selected = make_profile(
        problem, budgets, selected.checkpoints, selected.replay_work_units,
        true, &result.reverse_gkr_segments);
    const std::size_t input_layer = problem.layers.size() - 1U;
    result.used_nonpreferred_checkpoint = std::any_of(
        selected.checkpoints.begin(), selected.checkpoints.end(),
        [&](std::size_t layer) {
            return layer != input_layer &&
                   !problem.layers[layer].preferred_checkpoint;
        });
    if (!result.selected.feasible()) {
        throw std::logic_error(
            "selected checkpoint replay plan failed its own budget ledger");
    }
    return result;
}


} // namespace laminate::payload
