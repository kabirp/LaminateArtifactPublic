#ifndef LAMINATE_BENCHES_PROTOCOL_PROGRESS_HPP
#define LAMINATE_BENCHES_PROTOCOL_PROGRESS_HPP

/// @file protocol_progress.hpp
/// @brief Continuously flushed progress journal for protocol benchmark runs.

#include "benchmark_support.hpp"

#include "laminate/runtime_progress.hpp"

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace laminate::bench {

inline constexpr std::string_view kProtocolProgressSchema =
    "laminate-protocol-progress-v1";

inline const char *protocol_progress_stage_name(
    RuntimeProgressStage stage) {
    switch (stage) {
    case RuntimeProgressStage::Unspecified:
        return "unspecified";
    case RuntimeProgressStage::PayloadForwardRelation:
        return "payload.forward_relation";
    case RuntimeProgressStage::PayloadReplaySegment:
        return "payload.replay_segment";
    case RuntimeProgressStage::PayloadProofIngress:
        return "payload.proof_ingress";
    case RuntimeProgressStage::PayloadReplayRelation:
        return "payload.replay_relation";
    case RuntimeProgressStage::LanedWitnessPacking:
        return "laned.witness_packing";
    case RuntimeProgressStage::BaseReduction:
        return "base.reduction";
    case RuntimeProgressStage::BaseTraceLayerRetirement:
        return "base.trace_layer_retirement";
    case RuntimeProgressStage::BaseAffineSumcheckRound:
        return "base.affine.sumcheck_round";
    case RuntimeProgressStage::BaseAffineTerminalEvaluation:
        return "base.affine.terminal_source_evaluation";
    case RuntimeProgressStage::BaseMultiplicationSourceBuild:
        return "base.multiplication.source_artifact_build";
    case RuntimeProgressStage::BaseMultiplicationSumcheckRound:
        return "base.multiplication.sumcheck_round";
    case RuntimeProgressStage::BaseMultiplicationTerminalSourceEvaluation:
        return "base.multiplication.terminal_source_evaluation";
    case RuntimeProgressStage::BaseMultiplicationSourceReclaim:
        return "base.multiplication.source_artifact_reclaim";
    case RuntimeProgressStage::BaseGateMleFinish:
        return "base.gate_mle_opening";
    case RuntimeProgressStage::FoldedReduction:
        return "folded.reduction";
    case RuntimeProgressStage::FoldedTraceLayerRetirement:
        return "folded.trace_layer_retirement";
    case RuntimeProgressStage::FoldedAffineSumcheckRound:
        return "folded.affine.sumcheck_round";
    case RuntimeProgressStage::FoldedAffineSlotCheckpoint:
        return "folded.affine.slot_checkpoint";
    case RuntimeProgressStage::FoldedMultiplicationSourceBuild:
        return "folded.multiplication.source_artifact_build";
    case RuntimeProgressStage::FoldedMultiplicationSumcheckRound:
        return "folded.multiplication.sumcheck_round";
    case RuntimeProgressStage::FoldedMultiplicationSlotCheckpoint:
        return "folded.multiplication.slot_checkpoint";
    case RuntimeProgressStage::FoldedMultiplicationSourceReclaim:
        return "folded.multiplication.source_artifact_reclaim";
    case RuntimeProgressStage::FoldedGateMleFinish:
        return "folded.gate_mle_opening";
    case RuntimeProgressStage::LanedReduction:
        return "laned.reduction";
    case RuntimeProgressStage::LanedTraceLayerRetirement:
        return "laned.trace_layer_retirement";
    case RuntimeProgressStage::LanedAffineSourcePacking:
        return "laned.affine.source_packing";
    case RuntimeProgressStage::LanedAffineSumcheckRound:
        return "laned.affine.sumcheck_round";
    case RuntimeProgressStage::LanedAffineSlotCheckpoint:
        return "laned.affine.slot_checkpoint";
    case RuntimeProgressStage::LanedMultiplicationSourceBuild:
        return "laned.multiplication.source_artifact_build";
    case RuntimeProgressStage::LanedMultiplicationSumcheckRound:
        return "laned.multiplication.sumcheck_round";
    case RuntimeProgressStage::LanedMultiplicationSlotCheckpoint:
        return "laned.multiplication.slot_checkpoint";
    case RuntimeProgressStage::LanedMultiplicationSourceReclaim:
        return "laned.multiplication.source_artifact_reclaim";
    case RuntimeProgressStage::LanedGateMleFinish:
        return "laned.gate_mle_opening";
    case RuntimeProgressStage::TranscriptPackingRevealEvaluation:
        return "transcript_packing.reveal_evaluation";
    case RuntimeProgressStage::TranscriptPackingAssignment:
        return "transcript_packing.assignment";
    case RuntimeProgressStage::TranscriptPackingAlignedSourceRetirement:
        return "transcript_packing.aligned_source_retirement";
    case RuntimeProgressStage::TranscriptPackingSpartanProve:
        return "transcript_packing.spartan_prove";
    case RuntimeProgressStage::TranscriptPackingSpartanAssignment:
        return "transcript_packing.spartan.assignment";
    case RuntimeProgressStage::TranscriptPackingSpartanWitnessCommitment:
        return "transcript_packing.spartan.witness_commitment";
    case RuntimeProgressStage::
        TranscriptPackingSpartanWitnessCommitmentMobius:
        return "transcript_packing.spartan.witness_commitment.mobius";
    case RuntimeProgressStage::
        TranscriptPackingSpartanWitnessCommitmentRateExpansion:
        return "transcript_packing.spartan.witness_commitment.rate_expansion";
    case RuntimeProgressStage::
        TranscriptPackingSpartanWitnessCommitmentNtt:
        return "transcript_packing.spartan.witness_commitment.ntt";
    case RuntimeProgressStage::
        TranscriptPackingSpartanWitnessCommitmentMerkleTree:
        return "transcript_packing.spartan.witness_commitment.merkle_tree";
    case RuntimeProgressStage::
        TranscriptPackingSpartanWitnessCommitmentFinalPublication:
        return "transcript_packing.spartan.witness_commitment.final_publication";
    case RuntimeProgressStage::TranscriptPackingSpartanMatrixProducts:
        return "transcript_packing.spartan.matrix_products";
    case RuntimeProgressStage::TranscriptPackingSpartanConstraintCheck:
        return "transcript_packing.spartan.constraint_check";
    case RuntimeProgressStage::TranscriptPackingSpartanWiringMatrix:
        return "transcript_packing.spartan.wiring_matrix";
    case RuntimeProgressStage::TranscriptPackingSpartanWiringCheck:
        return "transcript_packing.spartan.wiring_check";
    case RuntimeProgressStage::TranscriptPackingSpartanFactoredOpenings:
        return "transcript_packing.spartan.factored_openings";
    case RuntimeProgressStage::TranscriptPackingSpartanWitnessOpening:
        return "transcript_packing.spartan.witness_opening";
    case RuntimeProgressStage::TranscriptPackingSpartanRetirement:
        return "transcript_packing.spartan.retirement";
    case RuntimeProgressStage::TranscriptPackingOuterAssignmentRetirement:
        return "transcript_packing.outer_assignment_retirement";
    case RuntimeProgressStage::TranscriptPackingVerifierStatement:
        return "transcript_packing.verifier_statement";
    case RuntimeProgressStage::TranscriptPackingSpartanVerify:
        return "transcript_packing.spartan_verify";
    case RuntimeProgressStage::TranscriptPackingThresholdChecks:
        return "transcript_packing.threshold_checks";
    case RuntimeProgressStage::TranscriptPackingUnpack:
        return "transcript_packing.unpack";
    }
    return "unknown";
}

inline const char *protocol_progress_layer_name(
    RuntimeProgressLayerKind kind) {
    switch (kind) {
    case RuntimeProgressLayerKind::Unspecified:
        return "unspecified";
    case RuntimeProgressLayerKind::Affine:
        return "affine";
    case RuntimeProgressLayerKind::Multiplication:
        return "multiplication";
    }
    return "unknown";
}

inline const char *protocol_progress_side_name(RuntimeProgressSide side) {
    switch (side) {
    case RuntimeProgressSide::Unspecified:
        return "unspecified";
    case RuntimeProgressSide::Left:
        return "left";
    case RuntimeProgressSide::Right:
        return "right";
    }
    return "unknown";
}

inline const char *protocol_progress_coordinate_domain_name(
    RuntimeProgressCoordinateDomain domain) {
    switch (domain) {
    case RuntimeProgressCoordinateDomain::Unspecified:
        return "unspecified";
    case RuntimeProgressCoordinateDomain::CiphertextIndex:
        return "ciphertext_index";
    case RuntimeProgressCoordinateDomain::SlotIndex:
        return "slot_index";
    }
    return "unknown";
}

inline const char *protocol_progress_subpass_name(
    RuntimeProgressSubpass subpass) {
    switch (subpass) {
    case RuntimeProgressSubpass::Unspecified:
        return "unspecified";
    case RuntimeProgressSubpass::SourceLocalMobius:
        return "source_local_mobius";
    case RuntimeProgressSubpass::LocalMobius:
        return "local_mobius";
    case RuntimeProgressSubpass::RateExpansion:
        return "rate_expansion";
    case RuntimeProgressSubpass::Transpose:
        return "transpose";
    case RuntimeProgressSubpass::TwiddleTranspose:
        return "twiddle_transpose";
    case RuntimeProgressSubpass::LocalNtt:
        return "local_ntt";
    case RuntimeProgressSubpass::MerkleTree:
        return "merkle_tree";
    case RuntimeProgressSubpass::MessagePublication:
        return "message_publication";
    case RuntimeProgressSubpass::CodewordPublication:
        return "codeword_publication";
    case RuntimeProgressSubpass::MerklePublication:
        return "merkle_publication";
    case RuntimeProgressSubpass::ArtifactPublication:
        return "artifact_publication";
    }
    return "unknown";
}

inline const char *protocol_progress_work_unit_name(
    RuntimeProgressWorkUnit unit) {
    switch (unit) {
    case RuntimeProgressWorkUnit::Unspecified:
        return "unspecified";
    case RuntimeProgressWorkUnit::FieldElements:
        return "field_elements";
    case RuntimeProgressWorkUnit::NttButterflies:
        return "ntt_butterflies";
    case RuntimeProgressWorkUnit::MerkleItems:
        return "merkle_items";
    case RuntimeProgressWorkUnit::PublicationSteps:
        return "publication_steps";
    }
    return "unknown";
}

/// The fields needed to explain one machine-readable progress record to a
/// human. Indices retain the zero-based representation used by JSONL; this
/// formatter is the single place which turns rounds into one-based labels.
struct ProtocolProgressDescriptionView {
    std::string_view stage = "unspecified";
    std::string_view layer_kind = "unspecified";
    std::string_view side = "unspecified";
    std::string_view coordinate_domain = "unspecified";
    std::string_view subpass = "unspecified";
    std::size_t reduction_layer = kRuntimeProgressNoIndex;
    std::size_t source_layer = kRuntimeProgressNoIndex;
    std::size_t output_layer = kRuntimeProgressNoIndex;
    std::size_t checkpoint_layer = kRuntimeProgressNoIndex;
    std::size_t round = kRuntimeProgressNoIndex;
    std::size_t round_count = 0;
};

inline std::size_t protocol_progress_parse_index(
    std::optional<std::string_view> value,
    std::size_t absent = kRuntimeProgressNoIndex) {
    if (!value || value->empty()) {
        return absent;
    }
    std::size_t parsed = 0;
    const char *const begin = value->data();
    const char *const end = begin + value->size();
    const auto result = std::from_chars(begin, end, parsed);
    return result.ec == std::errc{} && result.ptr == end ? parsed : absent;
}

inline std::optional<double> protocol_progress_parse_real(
    std::optional<std::string_view> value) {
    if (!value) {
        return std::nullopt;
    }
    std::istringstream input{std::string(*value)};
    double parsed = 0.0;
    input >> parsed;
    if (!input || parsed < 0.0) {
        return std::nullopt;
    }
    return parsed;
}

inline std::optional<std::uint64_t> protocol_progress_parse_u64(
    std::optional<std::string_view> value) {
    if (!value) {
        return std::nullopt;
    }
    std::uint64_t parsed = 0;
    const char *begin = value->data();
    const char *end = begin + value->size();
    const auto [position, error] = std::from_chars(begin, end, parsed);
    if (error != std::errc{} || position != end) {
        return std::nullopt;
    }
    return parsed;
}

/// Print the live, phase-local snapshot carried by a payload-relation update.
/// The timed I/O values are wall time spent inside the corresponding API;
/// they deliberately do not claim that all of that wall time was sleep.
template <typename JsonValue>
void print_payload_relation_snapshot(std::ostream &output,
                                     std::string_view line,
                                     JsonValue json_value) {
    const auto stage = json_value(line, "stage");
    if (!stage ||
        (!stage->starts_with("payload.forward_relation") &&
         !stage->starts_with("payload.replay_relation"))) {
        return;
    }
    const auto phase_wall = protocol_progress_parse_real(
        json_value(line, "phase_wall_ms"));
    if (!phase_wall || *phase_wall <= 0.0) {
        return;
    }
    const auto real = [&](const char *name) {
        return protocol_progress_parse_real(json_value(line, name))
            .value_or(0.0);
    };
    const auto count = [&](const char *name) {
        return protocol_progress_parse_u64(json_value(line, name))
            .value_or(0);
    };
    const double phase_cpu = real("phase_cpu_ms");
    const auto seconds = [&](const char *name) {
        return real(name) / 1000.0;
    };
    constexpr double bytes_per_gib = 1024.0 * 1024.0 * 1024.0;
    const double read_gib =
        static_cast<double>(count("application_read_bytes")) / bytes_per_gib;
    const double write_gib =
        static_cast<double>(count("application_write_bytes")) / bytes_per_gib;
    const double prefetch_gib =
        static_cast<double>(count("prefetch_bytes_requested")) /
        bytes_per_gib;
    const double writeback_scheduled_gib =
        static_cast<double>(count("writeback_range_bytes_submitted")) /
        bytes_per_gib;
    const double writeback_waited_gib =
        static_cast<double>(count("writeback_range_bytes_waited")) /
        bytes_per_gib;

    const std::ios::fmtflags flags = output.flags();
    const std::streamsize precision = output.precision();
    output << "    live phase snapshot: " << std::fixed
           << std::setprecision(1) << *phase_wall / 1000.0
           << "s wall, "
           << 100.0 * phase_cpu / *phase_wall << "% CPU/wall"
           << "; FHE " << seconds("fhe_wall_ms")
           << "s, modulus switch "
           << seconds("modulus_switch_wall_ms") << "s"
           << "; serialization/buffering/hash "
           << seconds("serialization_wall_ms") << '/'
           << seconds("buffer_assembly_wall_ms") << '/'
           << seconds("hashing_wall_ms") << "s"
           << "; timed read/write/prefetch/writeback-submit/wait "
           << seconds("storage_read_wall_ms") << '/'
           << seconds("storage_write_wall_ms") << '/'
           << seconds("prefetch_wall_ms") << '/'
           << seconds("writeback_submission_wall_ms") << '/'
           << seconds("writeback_wait_wall_ms") << "s"
           << "; read/write " << read_gib << '/' << write_gib
           << " GiB in " << count("read_syscalls") << '/'
           << count("write_syscalls") << " syscalls"
           << "; prefetch " << prefetch_gib << " GiB in "
           << count("prefetch_requests") << " requests"
           << " (fallbacks/seek-disables "
           << count("prefetch_fallbacks") << '/'
           << count("prefetch_seek_disables") << ')'
           << "; writeback hinted/waited range "
           << writeback_scheduled_gib << '/'
           << writeback_waited_gib << " GiB in "
           << count("writeback_submission_successes") << '/'
           << count("writeback_submission_attempts") << " successful/attempted submits, "
           << count("writeback_wait_successes") << '/'
           << count("writeback_wait_attempts") << " successful/attempted waits"
           << " (submit-only files/drains/skipped "
           << count("writeback_files_submit_only") << '/'
           << count("writeback_drains") << '/'
           << count("writeback_drains_skipped") << ")\n";
    const std::uint64_t alias_relations =
        count("identity_affine_alias_relations");
    const std::uint64_t alias_fallbacks =
        count("identity_affine_alias_fallbacks");
    if (alias_relations != 0 || alias_fallbacks != 0) {
        output << "    identity-affine alias relations/fallbacks "
               << alias_relations << '/' << alias_fallbacks
               << "; records reused "
               << count("identity_affine_alias_records_reused")
               << "; existing layer bytes reused "
               << count("identity_affine_alias_layer_bytes_reused")
               << "; unique manifest bytes written "
               << count("identity_affine_alias_unique_bytes_written")
               << '\n';
    }
    output.flags(flags);
    output.precision(precision);
}

inline std::string_view protocol_progress_operation_stage(
    std::string_view span_name) {
    std::size_t end = span_name.size();
    // Indexed fields are appended as `.source_12`, `.round_4`, and so on.
    // Match the numeric suffix, not merely the field prefix: semantic stage
    // names such as `.source_artifact_build` and `.slot_checkpoint` must
    // remain visible in human output.
    for (const std::string_view indexed_suffix : {
             ".reduction_", ".source_", ".output_", ".checkpoint_",
             ".round_"}) {
        std::size_t position = span_name.find(indexed_suffix);
        while (position != std::string_view::npos) {
            const std::size_t value_begin = position + indexed_suffix.size();
            if (value_begin < span_name.size() &&
                span_name[value_begin] >= '0' &&
                span_name[value_begin] <= '9') {
                end = std::min(end, position);
                break;
            }
            position = span_name.find(indexed_suffix, position + 1U);
        }
    }
    for (const std::string_view label_suffix : {
             ".left", ".right", ".ciphertext_index", ".slot_index"}) {
        const std::size_t position = span_name.find(label_suffix);
        if (position != std::string_view::npos) {
            end = std::min(end, position);
        }
    }
    return span_name.substr(0, end);
}

inline std::string protocol_progress_readable_stage(std::string_view stage) {
    if (stage == "base.gate_mle_opening") {
        return "LaminateBase GateMLE opening";
    }
    if (stage == "folded.gate_mle_opening") {
        return "LaminateFolded GateMLE opening";
    }
    if (stage == "laned.gate_mle_opening") {
        return "LaminateLaned GateMLE opening";
    }
    if (stage == "base.affine.terminal_source_evaluation") {
        return "LaminateBase affine terminal source evaluation";
    }

    std::string result(stage);
    std::replace(result.begin(), result.end(), '.', ' ');
    std::replace(result.begin(), result.end(), '_', ' ');
    if (result.starts_with("base ")) {
        result.replace(0, 4, "LaminateBase");
    } else if (result.starts_with("folded ")) {
        result.replace(0, 6, "LaminateFolded");
    } else if (result.starts_with("laned ")) {
        result.replace(0, 5, "LaminateLaned");
    }
    return result;
}

inline std::string_view protocol_progress_variant_label(
    std::string_view stage) {
    if (stage.starts_with("base.")) {
        return "LaminateBase";
    }
    if (stage.starts_with("folded.")) {
        return "LaminateFolded";
    }
    if (stage.starts_with("laned.")) {
        return "LaminateLaned";
    }
    return {};
}

/// Human-readable work category for terminal progress display. The caller
/// retains the original stage identifier for machine-readable telemetry.
inline std::string_view protocol_progress_human_category(
    std::string_view stage) {
    if (stage.find(".trace_layer_retirement") != std::string_view::npos ||
        stage.find(".source_artifact_build") != std::string_view::npos ||
        stage.find(".source_artifact_reclaim") != std::string_view::npos ||
        stage.find(".spartan.retirement") != std::string_view::npos ||
        stage.find(".aligned_source_retirement") !=
            std::string_view::npos ||
        stage.find(".outer_assignment_retirement") !=
            std::string_view::npos) {
        return "STORAGE";
    }
    if (stage.starts_with("payload.")) {
        return "PAYLOAD/FHE";
    }
    if (stage.starts_with("transcript_packing.")) {
        return "TRANSCRIPT PACKING";
    }
    if (stage == "laned.witness_packing") {
        return "WITNESS PACKING/FHE";
    }
    if (stage.find(".sumcheck_round") != std::string_view::npos ||
        stage.find(".source_packing") != std::string_view::npos ||
        stage.find(".slot_checkpoint") != std::string_view::npos ||
        stage.find(".terminal_source_evaluation") !=
            std::string_view::npos) {
        return "PROTOCOL/FHE";
    }
    return "PROTOCOL";
}

inline void append_protocol_progress_layers(
    std::ostringstream &output,
    const ProtocolProgressDescriptionView &progress) {
    const bool has_source =
        progress.source_layer != kRuntimeProgressNoIndex;
    const bool has_reduction =
        progress.reduction_layer != kRuntimeProgressNoIndex;
    if (!has_source && !has_reduction) {
        return;
    }
    output << " | ";
    if (has_reduction) {
        output << "layer " << progress.reduction_layer;
    }
    if (has_source && has_reduction) {
        output << " -> ";
    }
    if (has_source) {
        output << "source layer " << progress.source_layer;
    }
}

/// A protocol-first description for terminal output and `status`. GKR rounds
/// lead with the variant, reduction kind, layer transition, and coordinate
/// family; storage-oriented stage names remain available in the JSONL.
inline std::string protocol_progress_human_description(
    const ProtocolProgressDescriptionView &progress) {
    const std::string_view operation_stage =
        protocol_progress_operation_stage(progress.stage);
    const std::string_view variant =
        protocol_progress_variant_label(operation_stage);
    const bool reduction = operation_stage.ends_with(".reduction");
    const bool sumcheck = operation_stage.find(".sumcheck_round") !=
                          std::string_view::npos;
    const bool slot_checkpoint =
        operation_stage.ends_with(".slot_checkpoint");

    std::ostringstream output;
    output << '[' << protocol_progress_human_category(operation_stage)
           << "] ";
    if (!variant.empty() &&
        progress.layer_kind != "unspecified" &&
        (reduction || sumcheck)) {
        output << variant << ' ' << progress.layer_kind
               << " layer reduction";
    } else {
        output << protocol_progress_readable_stage(operation_stage);
    }
    append_protocol_progress_layers(output, progress);

    if (progress.output_layer != kRuntimeProgressNoIndex) {
        output << " | output layer " << progress.output_layer;
    }
    if (slot_checkpoint) {
        output << " | ciphertext-index prefix -> slot-index checkpoint";
        if (progress.checkpoint_layer != kRuntimeProgressNoIndex) {
            output << " at layer " << progress.checkpoint_layer;
        }
    } else if (progress.checkpoint_layer != kRuntimeProgressNoIndex) {
        output << " | checkpoint layer " << progress.checkpoint_layer;
    }
    if (progress.side != "unspecified") {
        output << " | " << progress.side << " side";
    }
    if (progress.subpass != "unspecified") {
        output << " | " << protocol_progress_readable_stage(
            progress.subpass);
    }

    if (sumcheck) {
        output << " | ";
        if (progress.coordinate_domain == "ciphertext_index") {
            output << "ciphertext-index ";
        } else if (progress.coordinate_domain == "slot_index") {
            output << "slot-index ";
        }
        output << "sumcheck";
        if (progress.round != kRuntimeProgressNoIndex) {
            output << " round " << progress.round + 1U;
            if (progress.round_count != 0) {
                output << '/' << progress.round_count;
            }
        }
    }
    return output.str();
}

inline ProtocolProgressDescriptionView protocol_progress_description_view(
    const RuntimeProgressEvent &event) {
    return ProtocolProgressDescriptionView{
        .stage = protocol_progress_stage_name(event.stage),
        .layer_kind = protocol_progress_layer_name(event.layer_kind),
        .side = protocol_progress_side_name(event.side),
        .coordinate_domain =
            protocol_progress_coordinate_domain_name(
                event.coordinate_domain),
        .subpass = protocol_progress_subpass_name(event.subpass),
        .reduction_layer = event.reduction_layer,
        .source_layer = event.source_layer,
        .output_layer = event.output_layer,
        .checkpoint_layer = event.checkpoint_layer,
        .round = event.round,
        .round_count = event.round_count,
    };
}

inline std::string protocol_progress_human_description(
    const RuntimeProgressEvent &event) {
    return protocol_progress_human_description(
        protocol_progress_description_view(event));
}

inline void append_protocol_progress_index(
    std::ostringstream &output, std::string_view label,
    std::size_t value) {
    if (value != kRuntimeProgressNoIndex) {
        output << '.' << label << '_' << value;
    }
}

/// Stable machine name used both in JSONL and benchmark result records.
inline std::string protocol_progress_span_name(
    const RuntimeProgressEvent &event) {
    std::ostringstream result;
    result << protocol_progress_stage_name(event.stage);
    append_protocol_progress_index(
        result, "reduction", event.reduction_layer);
    append_protocol_progress_index(result, "source", event.source_layer);
    append_protocol_progress_index(result, "output", event.output_layer);
    append_protocol_progress_index(
        result, "checkpoint", event.checkpoint_layer);
    if (event.side != RuntimeProgressSide::Unspecified) {
        result << '.' << protocol_progress_side_name(event.side);
    }
    if (event.coordinate_domain !=
        RuntimeProgressCoordinateDomain::Unspecified) {
        result << '.' << protocol_progress_coordinate_domain_name(
                           event.coordinate_domain);
    }
    append_protocol_progress_index(result, "round", event.round);
    return result.str();
}

inline std::string protocol_progress_json_string(std::string_view value) {
    std::string result;
    result.reserve(value.size() + 2U);
    result.push_back('"');
    for (const char character : value) {
        switch (character) {
        case '"':
            result += "\\\"";
            break;
        case '\\':
            result += "\\\\";
            break;
        case '\n':
            result += "\\n";
            break;
        case '\r':
            result += "\\r";
            break;
        case '\t':
            result += "\\t";
            break;
        default:
            result.push_back(character);
            break;
        }
    }
    result.push_back('"');
    return result;
}

/// Append the phase-local timing and storage-attribution fields shared by all
/// benchmark progress journals. Keeping this serialization in one place is
/// important: Base has its own lifecycle journal, while Packed and
/// noIntegrity use ProtocolProgressJournal, but operators must see identical
/// live evidence for the same RuntimeProgressEvent.
inline void append_protocol_progress_diagnostics_json(
    std::ostream &output, const RuntimeProgressEvent &event) {
    const auto write_real = [&](const char *name, double value) {
        if (value != 0.0) {
            output << ",\"" << name << "\":" << std::setprecision(9)
                   << value;
        }
    };
    const auto write_u64 = [&](const char *name, std::uint64_t value) {
        if (value != 0) {
            output << ",\"" << name << "\":" << value;
        }
    };

    write_real("phase_wall_ms", event.phase_wall_ms);
    write_real("phase_cpu_ms", event.phase_cpu_ms);
    write_real("fhe_wall_ms", event.fhe_wall_ms);
    write_real("fhe_cpu_ms", event.fhe_cpu_ms);
    write_real("modulus_switch_wall_ms", event.modulus_switch_wall_ms);
    write_real("modulus_switch_cpu_ms", event.modulus_switch_cpu_ms);
    write_real("serialization_wall_ms", event.serialization_wall_ms);
    write_real("serialization_cpu_ms", event.serialization_cpu_ms);
    write_real("buffer_assembly_wall_ms", event.buffer_assembly_wall_ms);
    write_real("buffer_assembly_cpu_ms", event.buffer_assembly_cpu_ms);
    write_real("hashing_wall_ms", event.hashing_wall_ms);
    write_real("hashing_cpu_ms", event.hashing_cpu_ms);
    write_real("deserialization_wall_ms", event.deserialization_wall_ms);
    write_real("deserialization_cpu_ms", event.deserialization_cpu_ms);
    write_real("storage_read_wall_ms", event.storage_read_wall_ms);
    write_real("storage_read_cpu_ms", event.storage_read_cpu_ms);
    write_real("storage_write_wall_ms", event.storage_write_wall_ms);
    write_real("storage_write_cpu_ms", event.storage_write_cpu_ms);
    write_real("prefetch_wall_ms", event.prefetch_wall_ms);
    write_real("prefetch_cpu_ms", event.prefetch_cpu_ms);
    write_real("storage_wait_wall_ms", event.storage_wait_wall_ms);
    write_real("storage_wait_cpu_ms", event.storage_wait_cpu_ms);
    write_real("writeback_submission_wall_ms",
               event.writeback_submission_wall_ms);
    write_real("writeback_submission_cpu_ms",
               event.writeback_submission_cpu_ms);
    write_real("writeback_wait_wall_ms", event.writeback_wait_wall_ms);
    write_real("writeback_wait_cpu_ms", event.writeback_wait_cpu_ms);
    write_u64("capacity_probes", event.capacity_probes);
    write_u64("read_batches", event.read_batches);
    write_u64("read_syscalls", event.read_syscalls);
    write_u64("application_read_bytes", event.application_read_bytes);
    write_u64("prefetch_requests", event.prefetch_requests);
    write_u64("prefetch_bytes_requested", event.prefetch_bytes_requested);
    write_u64("prefetch_fallbacks", event.prefetch_fallbacks);
    write_u64("prefetch_seek_disables", event.prefetch_seek_disables);
    write_u64("prefetch_window_bytes", event.prefetch_window_bytes);
    write_u64("maximum_prefetch_request_bytes",
              event.maximum_prefetch_request_bytes);
    write_u64("write_batches", event.write_batches);
    write_u64("write_syscalls", event.write_syscalls);
    write_u64("application_write_bytes", event.application_write_bytes);
    write_u64("authenticated_record_bytes", event.authenticated_record_bytes);
    write_u64("same_process_unhashed_record_bytes",
              event.same_process_unhashed_record_bytes);
    write_u64("record_copy_bytes", event.record_copy_bytes);
    write_u64("writeback_submission_attempts",
              event.writeback_submission_attempts);
    write_u64("writeback_submission_successes",
              event.writeback_submission_successes);
    write_u64("writeback_wait_attempts", event.writeback_wait_attempts);
    write_u64("writeback_wait_successes", event.writeback_wait_successes);
    write_u64("writeback_range_bytes_submitted",
              event.writeback_range_bytes_submitted);
    write_u64("writeback_range_bytes_waited",
              event.writeback_range_bytes_waited);
    write_u64("maximum_writeback_submission_bytes",
              event.maximum_writeback_submission_bytes);
    write_u64("writeback_window_bytes", event.writeback_window_bytes);
    write_u64("maximum_unwaited_writeback_range_bytes",
              event.maximum_unwaited_writeback_range_bytes);
    write_u64("writeback_files_submit_only",
              event.writeback_files_submit_only);
    write_u64("writeback_drains", event.writeback_drains);
    write_u64("writeback_drain_range_bytes",
              event.writeback_drain_range_bytes);
    write_u64("writeback_drains_skipped", event.writeback_drains_skipped);
    write_u64("writeback_range_bytes_without_explicit_wait",
              event.writeback_range_bytes_without_explicit_wait);
    write_u64("positional_write_calls", event.positional_write_calls);
    write_u64("positional_write_bytes", event.positional_write_bytes);
    write_u64("maximum_read_batch_bytes", event.maximum_read_batch_bytes);
    write_u64("maximum_write_batch_bytes", event.maximum_write_batch_bytes);
    write_u64("identity_affine_alias_relations",
              event.identity_affine_alias_relations);
    write_u64("identity_affine_alias_fallbacks",
              event.identity_affine_alias_fallbacks);
    write_u64("identity_affine_alias_records_reused",
              event.identity_affine_alias_records_reused);
    write_u64("identity_affine_alias_layer_bytes_reused",
              event.identity_affine_alias_layer_bytes_reused);
    write_u64("identity_affine_alias_unique_bytes_written",
              event.identity_affine_alias_unique_bytes_written);
}

/// Records coarse benchmark phases and fine GKR layer/round callbacks. Every
/// line is flushed before the next protocol operation, so the last BEGIN or
/// progress line identifies the active span after a crash or interruption.
class ProtocolProgressJournal {
  public:
    explicit ProtocolProgressJournal(std::filesystem::path path)
        : path_(std::move(path)),
          start_(std::chrono::steady_clock::now()),
          uncaught_on_entry_(std::uncaught_exceptions()) {
        if (!path_.empty()) {
            open_file();
            std::cerr << "telemetry.progress_file=" << path_.string()
                      << std::endl;
        }
        write_status("started");
    }

    ProtocolProgressJournal(const ProtocolProgressJournal &) = delete;
    ProtocolProgressJournal &operator=(const ProtocolProgressJournal &) =
        delete;

    ~ProtocolProgressJournal() {
        if (!terminal_ ||
            std::uncaught_exceptions() > uncaught_on_entry_) {
            write_status("failed");
        }
    }

    void phase(std::string_view name) noexcept {
        try {
            write_phase(name);
        } catch (...) {
            disable_once();
        }
    }

    RuntimeProgressCallback callback() {
        return [this](const RuntimeProgressEvent &event) noexcept {
            observe(event);
        };
    }

    void mark_complete(bool accepted) noexcept {
        terminal_ = true;
        write_status(accepted ? "accepted" : "rejected");
    }

    /// End a non-verifying diagnostic lifecycle without implying a protocol
    /// acceptance verdict.
    void mark_complete_without_verdict() noexcept {
        terminal_ = true;
        write_status("completed");
    }

    void emit(const Record &record) const {
        record.text("telemetry.schema", std::string(kProtocolProgressSchema));
        record.text("telemetry.progress_file",
                    path_.empty() ? "not-requested" : path_.string());
        record.text("telemetry.logging_status",
                    disabled_ ? "failed"
                              : path_.empty() ? "stderr-only" : "complete");
        record.integer("telemetry.completed_spans", completed_.size());
        for (std::size_t index = 0; index < completed_.size(); ++index) {
            const std::string prefix =
                "telemetry.span." + std::to_string(index);
            record.text(prefix + ".name", completed_[index].name);
            record.real(prefix + ".wall_ms",
                        completed_[index].timing.wall_ms);
            record.real(prefix + ".cpu_ms",
                        completed_[index].timing.cpu_ms);
        }
    }

  private:
    struct ActiveSpan {
        RuntimeProgressEvent event;
        std::chrono::steady_clock::time_point wall_start;
        std::clock_t cpu_start = 0;
    };

    struct CompletedSpan {
        std::string name;
        Timing timing;
    };

    void open_file() {
        std::error_code error;
        const std::filesystem::file_status destination =
            std::filesystem::symlink_status(path_, error);
        if (error == std::errc::no_such_file_or_directory) {
            error.clear();
        } else if (error) {
            throw std::runtime_error(
                "cannot inspect --progress-file destination: " +
                error.message());
        } else if (destination.type() !=
                   std::filesystem::file_type::not_found) {
            throw std::invalid_argument(
                "--progress-file must not already exist");
        }
        const std::filesystem::path parent =
            path_.parent_path().empty() ? std::filesystem::path(".")
                                        : path_.parent_path();
        if (!std::filesystem::is_directory(parent, error) || error) {
            throw std::invalid_argument(
                "--progress-file parent must be an existing directory");
        }
        output_.open(path_, std::ios::out | std::ios::trunc);
        if (!output_) {
            throw std::runtime_error("failed to create --progress-file");
        }
        std::filesystem::permissions(
            path_,
            std::filesystem::perms::owner_read |
                std::filesystem::perms::owner_write,
            std::filesystem::perm_options::replace, error);
        if (error) {
            output_.close();
            std::error_code ignored;
            std::filesystem::remove(path_, ignored);
            throw std::runtime_error(
                "failed to make --progress-file owner-only");
        }
    }

    static bool same_span(const RuntimeProgressEvent &left,
                          const RuntimeProgressEvent &right) {
        return left.stage == right.stage &&
               left.layer_kind == right.layer_kind &&
               left.side == right.side &&
               left.coordinate_domain == right.coordinate_domain &&
               left.reduction_layer == right.reduction_layer &&
               left.source_layer == right.source_layer &&
               left.output_layer == right.output_layer &&
               left.checkpoint_layer == right.checkpoint_layer &&
               left.round == right.round &&
               left.column_index == right.column_index;
    }

    static Timing elapsed(
        std::chrono::steady_clock::time_point wall_start,
        std::clock_t cpu_start) {
        const auto wall_end = std::chrono::steady_clock::now();
        const std::clock_t cpu_end = std::clock();
        const double cpu_ms =
            cpu_start == static_cast<std::clock_t>(-1) ||
                    cpu_end == static_cast<std::clock_t>(-1)
                ? 0.0
                : 1000.0 * static_cast<double>(cpu_end - cpu_start) /
                      static_cast<double>(CLOCKS_PER_SEC);
        return Timing{
            std::chrono::duration<double, std::milli>(wall_end - wall_start)
                .count(),
            cpu_ms};
    }

    double run_elapsed_ms() const {
        return std::chrono::duration<double, std::milli>(
                   std::chrono::steady_clock::now() - start_)
            .count();
    }

    void observe(const RuntimeProgressEvent &event) noexcept {
        try {
            const std::string name = protocol_progress_span_name(event);
            if (event.boundary == RuntimeProgressBoundary::Begin) {
                active_.push_back(ActiveSpan{
                    event, std::chrono::steady_clock::now(), std::clock()});
                write_boundary("begin", name, std::nullopt, &event);
                return;
            }
            if (event.boundary == RuntimeProgressBoundary::Update) {
                write_boundary("progress", name, std::nullopt, &event);
                return;
            }
            for (std::size_t index = active_.size(); index-- > 0;) {
                if (!same_span(active_[index].event, event)) {
                    continue;
                }
                const Timing timing = elapsed(
                    active_[index].wall_start, active_[index].cpu_start);
                completed_.push_back(CompletedSpan{name, timing});
                active_.erase(
                    active_.begin() + static_cast<std::ptrdiff_t>(index));
                write_boundary("end", name, timing, &event);
                return;
            }
            write_boundary("unmatched-end", name, std::nullopt, &event);
        } catch (...) {
            disable_once();
        }
    }

    void write_phase(std::string_view name) {
        if (output_) {
            output_ << '{'
                    << "\"schema\":"
                    << protocol_progress_json_string(kProtocolProgressSchema)
                    << ",\"seq\":" << sequence_++
                    << ",\"event\":\"phase\",\"stage\":"
                    << protocol_progress_json_string(name)
                    << ",\"run_elapsed_ms\":" << std::fixed
                    << std::setprecision(3) << run_elapsed_ms() << "}\n";
            flush_or_disable();
        }
        std::cerr << "progress phase=" << name
                  << " elapsed_ms="
                  << static_cast<std::uint64_t>(run_elapsed_ms())
                  << std::endl;
    }

    void write_boundary(
        std::string_view boundary, std::string_view name,
        std::optional<Timing> timing,
        const RuntimeProgressEvent *event) {
        if (output_) {
            const ResidentMemorySample memory = resident_memory_sample();
            output_ << '{'
                    << "\"schema\":"
                    << protocol_progress_json_string(kProtocolProgressSchema)
                    << ",\"seq\":" << sequence_++ << ",\"event\":"
                    << protocol_progress_json_string(boundary)
                    << ",\"stage\":"
                    << protocol_progress_json_string(name)
                    << ",\"run_elapsed_ms\":" << std::fixed
                    << std::setprecision(3) << run_elapsed_ms()
                    << ",\"current_rss_bytes\":"
                    << memory.current_bytes
                    << ",\"peak_rss_bytes\":" << memory.peak_bytes;
            if (timing) {
                output_ << ",\"wall_ms\":" << timing->wall_ms
                        << ",\"cpu_ms\":" << timing->cpu_ms;
            }
            if (event != nullptr) {
                output_ << ",\"layer_kind\":"
                        << protocol_progress_json_string(
                               protocol_progress_layer_name(
                                   event->layer_kind));
                write_index("reduction_layer", event->reduction_layer);
                write_index("source_layer", event->source_layer);
                write_index("output_layer", event->output_layer);
                write_index("checkpoint_layer", event->checkpoint_layer);
                write_index("round", event->round);
                if (event->round_count != 0) {
                    output_ << ",\"rounds\":" << event->round_count;
                }
                if (event->side != RuntimeProgressSide::Unspecified) {
                    output_ << ",\"side\":"
                            << protocol_progress_json_string(
                                   protocol_progress_side_name(event->side));
                }
                if (event->coordinate_domain !=
                    RuntimeProgressCoordinateDomain::Unspecified) {
                    output_ << ",\"coordinate_domain\":"
                            << protocol_progress_json_string(
                                   protocol_progress_coordinate_domain_name(
                                   event->coordinate_domain));
                }
                if (event->subpass != RuntimeProgressSubpass::Unspecified) {
                    output_ << ",\"subpass\":"
                            << protocol_progress_json_string(
                                   protocol_progress_subpass_name(
                                       event->subpass));
                }
                if (event->progress_work_unit !=
                    RuntimeProgressWorkUnit::Unspecified) {
                    output_ << ",\"progress_work_unit\":"
                            << protocol_progress_json_string(
                                   protocol_progress_work_unit_name(
                                       event->progress_work_unit));
                }
                if (event->work_units != 0) {
                    output_ << ",\"work_units\":" << event->work_units;
                }
                if (event->total_steps != 0) {
                    output_ << ",\"completed_steps\":"
                            << event->completed_steps
                            << ",\"total_steps\":" << event->total_steps;
                }
                if (event->total_work_units != 0) {
                    output_ << ",\"completed_work_units\":"
                            << event->completed_work_units
                            << ",\"total_work_units\":"
                            << event->total_work_units;
                }
                if (event->phase_total_steps != 0) {
                    output_ << ",\"phase_completed_steps\":"
                            << event->phase_completed_steps
                            << ",\"phase_total_steps\":"
                            << event->phase_total_steps;
                }
                if (event->total_read_bytes != 0) {
                    output_ << ",\"completed_read_bytes\":"
                            << event->completed_read_bytes
                            << ",\"total_read_bytes\":"
                            << event->total_read_bytes;
                }
                if (event->total_write_bytes != 0) {
                    output_ << ",\"completed_write_bytes\":"
                            << event->completed_write_bytes
                            << ",\"total_write_bytes\":"
                            << event->total_write_bytes;
                }
                if (event->phase_total_read_bytes != 0) {
                    output_ << ",\"phase_completed_read_bytes\":"
                            << event->phase_completed_read_bytes
                            << ",\"phase_total_read_bytes\":"
                            << event->phase_total_read_bytes;
                }
                if (event->phase_total_write_bytes != 0) {
                    output_ << ",\"phase_completed_write_bytes\":"
                            << event->phase_completed_write_bytes
                            << ",\"phase_total_write_bytes\":"
                            << event->phase_total_write_bytes;
                }
                if (event->total_butterflies != 0) {
                    output_ << ",\"completed_butterflies\":"
                            << event->completed_butterflies
                            << ",\"total_butterflies\":"
                            << event->total_butterflies;
                }
                if (event->phase_total_butterflies != 0) {
                    output_ << ",\"phase_completed_butterflies\":"
                            << event->phase_completed_butterflies
                            << ",\"phase_total_butterflies\":"
                            << event->phase_total_butterflies;
                }
                if (event->radix_elements != 0) {
                    output_ << ",\"radix_elements\":"
                            << event->radix_elements;
                }
                if (event->row_count != 0) {
                    output_ << ",\"row_count\":" << event->row_count;
                }
                if (event->row_size != 0) {
                    output_ << ",\"row_size\":" << event->row_size;
                }
                if (event->recent_work_units != 0 &&
                    event->recent_elapsed_milliseconds != 0) {
                    output_ << ",\"recent_work_units\":"
                            << event->recent_work_units
                            << ",\"recent_elapsed_ms\":"
                            << event->recent_elapsed_milliseconds
                            << ",\"recent_work_units_per_second\":"
                            << std::setprecision(3)
                            << 1000.0 *
                                   static_cast<double>(
                                       event->recent_work_units) /
                                   static_cast<double>(
                                       event->recent_elapsed_milliseconds)
                            << ",\"estimated_remaining_ms\":"
                            << event->estimated_remaining_milliseconds;
                }
                append_protocol_progress_diagnostics_json(output_, *event);
                write_index("column_index", event->column_index);
                if (event->column_count != 0) {
                    output_ << ",\"column_count\":"
                            << event->column_count;
                }
            }
            output_ << "}\n";
            flush_or_disable();
        }
        std::cerr << "progress " << boundary << ' ';
        if (event != nullptr) {
            std::cerr << protocol_progress_human_description(*event)
                      << " [stage=" << name << ']';
        } else {
            std::cerr << name;
        }
        std::cerr << " elapsed_ms="
                  << static_cast<std::uint64_t>(run_elapsed_ms());
        if (timing) {
            std::cerr << " wall_ms=" << std::fixed
                      << std::setprecision(3) << timing->wall_ms;
        }
        std::cerr << std::endl;
    }

    void write_index(std::string_view name, std::size_t value) {
        if (value != kRuntimeProgressNoIndex) {
            output_ << ",\"" << name << "\":" << value;
        }
    }

    void write_status(std::string_view status) noexcept {
        try {
            const double elapsed_ms = run_elapsed_ms();
            if (output_) {
                output_ << '{'
                        << "\"schema\":"
                        << protocol_progress_json_string(
                               kProtocolProgressSchema)
                        << ",\"seq\":" << sequence_++
                        << ",\"event\":\"run-status\",\"status\":"
                        << protocol_progress_json_string(status)
                        << ",\"run_elapsed_ms\":" << std::fixed
                        << std::setprecision(3) << elapsed_ms;
                if (status == "accepted") {
                    output_ << ",\"verification_result\":\"ACCEPT\""
                            << ",\"result_file_status\":"
                               "\"pending-publication\""
                            << ",\"next_action\":"
                               "\"require-result-file-ACCEPT-and-zero-exit\"";
                }
                if (status == "failed" && !active_.empty()) {
                    output_ << ",\"last_active_stage\":"
                            << protocol_progress_json_string(
                                   protocol_progress_span_name(
                                       active_.back().event));
                }
                output_ << "}\n";
                flush_or_disable();
            }

            std::cerr << "progress status=";
            if (status == "accepted") {
                std::cerr << "ACCEPT verification passed; result publication "
                             "is pending (require a zero exit and an ACCEPT "
                             "result file)";
            } else if (status == "rejected") {
                std::cerr << "REJECT verification failed; no accepted result "
                             "will be published";
            } else if (status == "failed") {
                std::cerr << "FAILED run did not complete";
                if (!active_.empty()) {
                    std::cerr << "; last active stage="
                              << protocol_progress_span_name(
                                     active_.back().event);
                }
            } else {
                std::cerr << "RUNNING";
            }
            std::cerr << " elapsed_ms=" << std::fixed
                      << std::setprecision(3) << elapsed_ms << std::endl;
        } catch (...) {
            disable_once();
        }
    }

    void flush_or_disable() noexcept {
        output_.flush();
        if (!output_) {
            disable_once();
        }
    }

    void disable_once() noexcept {
        if (disabled_) {
            return;
        }
        disabled_ = true;
        std::cerr << "warning: protocol progress logging failed; protocol "
                     "execution continues"
                  << std::endl;
    }

    std::filesystem::path path_;
    std::ofstream output_;
    std::chrono::steady_clock::time_point start_;
    int uncaught_on_entry_ = 0;
    std::size_t sequence_ = 0;
    bool terminal_ = false;
    bool disabled_ = false;
    std::vector<ActiveSpan> active_;
    std::vector<CompletedSpan> completed_;
};

} // namespace laminate::bench

#endif // LAMINATE_BENCHES_PROTOCOL_PROGRESS_HPP
