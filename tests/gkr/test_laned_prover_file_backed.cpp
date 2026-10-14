/// @file test_laned_prover_file_backed.cpp
/// @brief End-to-end Mock parity for the file-backed Laned GKR prover.

#include "test_helpers.hpp"

#include "laminate/fhe/mock_backend.hpp"
#include "laminate/gkr/detail/laned/reference/prover.hpp"
#include "laminate/gkr/detail/laned/prover.hpp"
#include "laminate/gkr/detail/laned/verifier.hpp"
#include "laminate/gkr/detail/laned/affine/source/chunk_batches.hpp"
#include "laminate/payload/compiler.hpp"
#include "laminate/payload/storage/file_trace_store.hpp"
#include "laminate/payload/trace/trace_crypto.hpp"
#include "laminate/protocol/metrics/proof_size.hpp"

#include <bit>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <iomanip>
#include <iterator>
#include <locale>
#include <numeric>
#include <sstream>
#include <span>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace {

using namespace laminate;
using namespace laminate::fhe;
using namespace laminate::gkr;
using namespace laminate::payload;

constexpr std::size_t kSlots = 16;

std::vector<std::size_t> exact_ingress_schedule(
    const EncryptedTrace<MockBackend> &trace) {
    std::vector<std::size_t> result;
    result.reserve(trace.layers.size());
    for (const auto &layer : trace.layers) {
        CHECK(!layer.wires.empty());
        result.push_back(layer.wires.front().ciphertext().rns_limbs);
    }
    return result;
}

class TemporaryDirectory {
  public:
    TemporaryDirectory() {
        const auto stamp = std::chrono::steady_clock::now()
                               .time_since_epoch()
                               .count();
        for (std::size_t attempt = 0; attempt < 100; ++attempt) {
            path_ = std::filesystem::temp_directory_path() /
                    ("laminate-laned-prover-stream-" +
                     std::to_string(stamp) + "-" +
                     std::to_string(attempt));
            if (std::filesystem::create_directory(path_)) {
                return;
            }
        }
        throw std::runtime_error("failed to create temporary directory");
    }

    ~TemporaryDirectory() {
        std::error_code ignored;
        std::filesystem::remove_all(path_, ignored);
    }

    std::filesystem::path make_child(const std::string &name) const {
        const std::filesystem::path child = path_ / name;
        if (!std::filesystem::create_directory(child)) {
            throw std::runtime_error("failed to create test directory");
        }
        return child;
    }

  private:
    std::filesystem::path path_;
};

PayloadCircuit make_payload(std::size_t lanes) {
    PayloadBuilder builder(PayloadShape::laned(lanes, kSlots), 2);
    const WireId first = builder.mul(0, 1);
    const WireId mixed = builder.add(first, 0);
    const WireId second = builder.mul(mixed, first);
    builder.set_outputs({builder.add(second, 1)});
    return builder.finish();
}

SlotVector values(std::size_t lanes, std::size_t seed) {
    SlotVector result;
    result.reserve(lanes);
    for (std::size_t lane = 0; lane < lanes; ++lane) {
        result.emplace_back(seed + 9U * lane + lane * lane);
    }
    return result;
}

FileTraceStoreOptions store_limits() {
    return FileTraceStoreOptions{
        .max_total_bytes = std::uint64_t{1} << 30U,
        .min_free_bytes = 1,
    };
}

std::filesystem::path layer_file(const std::filesystem::path &directory,
                                 std::size_t layer_index) {
    std::ostringstream name;
    name.imbue(std::locale::classic());
    name << "layer-" << std::setw(16) << std::setfill('0') << layer_index
         << ".bin";
    return directory / name.str();
}

std::vector<std::size_t> sequential_layers(std::size_t layer_count) {
    std::vector<std::size_t> result(layer_count);
    std::iota(result.begin(), result.end(), std::size_t{0});
    return result;
}

std::vector<std::size_t>
multiplication_layers(const LayeredCircuit &circuit) {
    std::vector<std::size_t> result;
    for (std::size_t layer = 0; layer + 1U < circuit.layers.size();
         ++layer) {
        if (layer_kind(circuit.layers[layer]) ==
            LayerKind::Multiplication) {
            result.push_back(layer);
        }
    }
    return result;
}

void append_progress_span(std::vector<RuntimeProgressEvent> &events,
                          RuntimeProgressEvent begin) {
    events.push_back(begin);
    begin.boundary = RuntimeProgressBoundary::End;
    events.push_back(begin);
}

std::vector<RuntimeProgressEvent> span_boundaries(
    std::span<const RuntimeProgressEvent> events) {
    std::vector<RuntimeProgressEvent> result;
    std::copy_if(events.begin(), events.end(), std::back_inserter(result),
                 [](const RuntimeProgressEvent &event) {
                     return event.boundary !=
                            RuntimeProgressBoundary::Update;
                 });
    return result;
}

std::vector<RuntimeProgressEvent>
expected_progress(const LayeredCircuit &circuit,
                  bool include_file_scratch,
                  bool include_scratch_reclaim) {
    std::vector<RuntimeProgressEvent> events;
    if (include_scratch_reclaim) {
        append_progress_span(
            events,
            RuntimeProgressEvent{
                .boundary = RuntimeProgressBoundary::Begin,
                .stage = RuntimeProgressStage::LanedTraceLayerRetirement,
                .source_layer = 0,
            });
    }
    for (std::size_t layer = 0; layer + 1U < circuit.layers.size(); ++layer) {
        const LayerKind kind = layer_kind(circuit.layers[layer]);
        const RuntimeProgressLayerKind progress_kind =
            kind == LayerKind::Affine
                ? RuntimeProgressLayerKind::Affine
                : RuntimeProgressLayerKind::Multiplication;
        const RuntimeProgressEvent reduction{
            .boundary = RuntimeProgressBoundary::Begin,
            .stage = RuntimeProgressStage::LanedReduction,
            .layer_kind = progress_kind,
            .reduction_layer = layer,
            .source_layer = layer + 1U,
        };
        events.push_back(reduction);

        const auto append_scratch_stage = [&](RuntimeProgressStage stage) {
            const std::uint64_t source_values =
                stage == RuntimeProgressStage::
                             LanedMultiplicationSourceBuild
                    ? static_cast<std::uint64_t>(
                          layer_dimensions(circuit.layers[layer + 1U])
                              .logical_size)
                    : 0U;
            append_progress_span(
                events,
                RuntimeProgressEvent{
                    .boundary = RuntimeProgressBoundary::Begin,
                    .stage = stage,
                    .layer_kind = RuntimeProgressLayerKind::Multiplication,
                    .reduction_layer = layer,
                    .source_layer = layer + 1U,
                    .work_units = source_values,
                    .total_steps = source_values,
                    .total_work_units = source_values,
                });
        };
        if (kind == LayerKind::Multiplication && include_file_scratch) {
            append_scratch_stage(
                RuntimeProgressStage::LanedMultiplicationSourceBuild);
        }
        if (kind == LayerKind::Multiplication && include_scratch_reclaim) {
            append_progress_span(
                events,
                RuntimeProgressEvent{
                    .boundary = RuntimeProgressBoundary::Begin,
                    .stage = RuntimeProgressStage::LanedTraceLayerRetirement,
                    .source_layer = layer + 1U,
                });
        }

        const auto layout = laned_layout(
            circuit, kind == LayerKind::Affine ? layer + 1U : layer);
        const std::size_t ciphertext_variables =
            std::bit_width(layout.padded_ciphertext_count) - 1U;
        const std::size_t slot_variables =
            std::bit_width(layout.slot_count) - 1U;
        const std::size_t rounds = ciphertext_variables + slot_variables;
        const LayerWireSupport source_support =
            canonical_layer_wire_support(circuit, layer + 1U);
        std::uint64_t scanned_values = source_support.live_wire_count;
        if (kind == LayerKind::Affine && include_file_scratch &&
            layout.logical_ciphertext_count <=
                laned_detail::affine_detail::
                    kLanedAffineMaterializedPackedCiphertextLimit) {
            append_progress_span(
                events,
                RuntimeProgressEvent{
                    .boundary = RuntimeProgressBoundary::Begin,
                    .stage =
                        RuntimeProgressStage::LanedAffineSourcePacking,
                    .layer_kind = RuntimeProgressLayerKind::Affine,
                    .coordinate_domain = RuntimeProgressCoordinateDomain::
                        CiphertextIndex,
                    .reduction_layer = layer,
                    .source_layer = layer + 1U,
                    .work_units = source_support.live_wire_count,
                });
            scanned_values = layout.logical_ciphertext_count;
        }
        if (kind == LayerKind::Multiplication) {
            const auto source_layout = laned_layout(circuit, layer + 1U);
            const std::size_t chunks = source_layout.chunks_per_ciphertext();
            const std::size_t half_source_wires =
                layout.padded_ciphertext_count * chunks;
            const std::size_t left_live =
                trace_storage::live_wire_rank(
                    source_support, half_source_wires);
            CHECK(left_live != 0U);
            const std::size_t live_pair_count =
                (left_live - 1U) / chunks + 1U;
            scanned_values = 2U * live_pair_count;
        }
        const RuntimeProgressStage round_stage =
            kind == LayerKind::Affine
                ? RuntimeProgressStage::LanedAffineSumcheckRound
                : RuntimeProgressStage::LanedMultiplicationSumcheckRound;
        for (std::size_t round = 0; round < ciphertext_variables; ++round) {
            append_progress_span(
                events,
                RuntimeProgressEvent{
                    .boundary = RuntimeProgressBoundary::Begin,
                    .stage = round_stage,
                    .layer_kind = progress_kind,
                    .coordinate_domain =
                        RuntimeProgressCoordinateDomain::CiphertextIndex,
                    .reduction_layer = layer,
                    .source_layer = layer + 1U,
                    .round = round,
                    .round_count = rounds,
                    .work_units = scanned_values,
                });
        }
        append_progress_span(
            events,
            RuntimeProgressEvent{
                .boundary = RuntimeProgressBoundary::Begin,
                .stage =
                    kind == LayerKind::Affine
                        ? RuntimeProgressStage::LanedAffineSlotCheckpoint
                        : RuntimeProgressStage::
                              LanedMultiplicationSlotCheckpoint,
                .layer_kind = progress_kind,
                .coordinate_domain =
                    RuntimeProgressCoordinateDomain::SlotIndex,
                .reduction_layer = layer,
                .source_layer = layer + 1U,
                .checkpoint_layer = layer + 1U,
                .work_units = scanned_values,
            });
        for (std::size_t round = ciphertext_variables; round < rounds;
             ++round) {
            append_progress_span(
                events,
                RuntimeProgressEvent{
                    .boundary = RuntimeProgressBoundary::Begin,
                    .stage = round_stage,
                    .layer_kind = progress_kind,
                    .coordinate_domain =
                        RuntimeProgressCoordinateDomain::SlotIndex,
                    .reduction_layer = layer,
                    .source_layer = layer + 1U,
                    .round = round,
                    .round_count = rounds,
                    .work_units = kind == LayerKind::Affine ? 1U : 2U,
                });
        }
        if (kind == LayerKind::Affine && include_scratch_reclaim) {
            append_progress_span(
                events,
                RuntimeProgressEvent{
                    .boundary = RuntimeProgressBoundary::Begin,
                    .stage = RuntimeProgressStage::LanedTraceLayerRetirement,
                    .source_layer = layer + 1U,
                });
        }
        if (kind == LayerKind::Multiplication &&
            include_scratch_reclaim) {
            append_scratch_stage(
                RuntimeProgressStage::LanedMultiplicationSourceReclaim);
        }
        RuntimeProgressEvent reduction_end = reduction;
        reduction_end.boundary = RuntimeProgressBoundary::End;
        events.push_back(reduction_end);
    }
    append_progress_span(
        events,
        RuntimeProgressEvent{
            .boundary = RuntimeProgressBoundary::Begin,
            .stage = RuntimeProgressStage::LanedGateMleFinish,
        });
    return events;
}

std::uint64_t layer_storage_bytes(
    const MockBackend::EvalContext &eval,
    const EncryptedTraceLayer<MockBackend> &layer,
    const LayerWireSupport &support) {
    std::uint64_t result = 0;
    CHECK(layer.wires.size() == support.live_wire_count);
    for (const auto &value : layer.wires) {
        result += fhe::encode_fhe_value_record<MockBackend>(eval, value)
                      .size();
    }
    return result;
}

void compare_regime(std::size_t lanes) {
    const PayloadCircuit payload = make_payload(lanes);
    const LayeredCircuit circuit = compile(payload);
    const std::vector<SlotVector> inputs{
        values(lanes, 5), values(lanes, 37)};
    const PlainTrace plain = synthesize_trace(
        payload, circuit, inputs);
    auto contexts = MockBackend::create(MockParameters{
        .slot_count = kSlots,
        .fresh_rns_limbs = 14,
        .bits_per_limb = 120,
    });
    const EncryptedTrace<MockBackend> compact =
        encrypt_compact_synthetic_trace<MockBackend>(
            contexts.eval, contexts.client, payload, circuit, plain,
            TraceEncryptionPlan::uniform(circuit, 9));
    const PublicSetup public_setup = make_direct_setup(payload, circuit);
    const EvaluationSetup<MockBackend> evaluation =
        make_packed_evaluation_setup<MockBackend>(public_setup,
                                                  contexts.eval);
    const std::vector<Fpk> point(
        laned_layer_variables(circuit, 0), Fpk::from_base(Fp(19)));
    const SingleClaim output_claim = make_packed_laned_claim(
        plain.layers.front(), laned_layout(circuit, 0), point);

    TemporaryDirectory root;
    const std::filesystem::path trace_directory =
        root.make_child("trace");
    (void)write_file_encrypted_trace(
        contexts.eval, trace_directory, store_limits(), circuit, compact);
    const auto trace = FileEncryptedTraceStore<MockBackend>::open(
        contexts.eval, trace_directory, payload, circuit,
        compact.provenance, compact.trace_id);

    laned_detail::FileLanedGkrOptions options;
    std::vector<RuntimeProgressEvent> file_backed_progress;
    options.progress = [&file_backed_progress](const RuntimeProgressEvent &event) {
        file_backed_progress.push_back(event);
    };
    for (const std::size_t layer : multiplication_layers(circuit)) {
        options.multiplication_scratch.push_back(
            laned_detail::FileLanedMultiplicationScratch{
                layer,
                root.make_child("multiplication-" +
                                std::to_string(layer)),
                store_limits(),
            });
    }
    CHECK(options.multiplication_scratch.size() == 2);

    const std::filesystem::path destructive_trace_directory =
        root.make_child("destructive-trace");
    const auto destructive_written = write_file_encrypted_trace(
        contexts.eval, destructive_trace_directory, store_limits(),
        circuit, compact);
    std::vector<std::uint64_t> destructive_layer_bytes;
    destructive_layer_bytes.reserve(circuit.layers.size());
    for (std::size_t layer = 0; layer < circuit.layers.size(); ++layer) {
        destructive_layer_bytes.push_back(std::filesystem::file_size(
            layer_file(destructive_trace_directory, layer)));
    }
    auto destructive_store = FileEncryptedTraceStore<MockBackend>::open(
        contexts.eval, destructive_trace_directory, payload, circuit,
        compact.provenance, compact.trace_id);
    auto destructive_trace =
        FileEncryptedTraceReclamationSession<MockBackend>::begin(
            std::move(destructive_store),
            FileTraceReclamationOptions{
                FileTraceSessionLifecycle::IrreversibleNoRetry});
    laned_detail::IrreversibleFileLanedGkrOptions destructive_options;
    destructive_options.lifecycle =
        FileTraceSessionLifecycle::IrreversibleNoRetry;
    destructive_options.reclaim_completed_multiplication_scratch = true;
    std::vector<RuntimeProgressEvent> destructive_progress;
    destructive_options.proof.progress =
        [&destructive_progress](const RuntimeProgressEvent &event) {
            destructive_progress.push_back(event);
            throw std::runtime_error("injected progress callback failure");
        };
    std::vector<std::filesystem::path> destructive_scratch_directories;
    for (const std::size_t layer : multiplication_layers(circuit)) {
        const std::filesystem::path directory = root.make_child(
            "destructive-multiplication-" + std::to_string(layer));
        destructive_scratch_directories.push_back(directory);
        destructive_options.proof.multiplication_scratch.push_back(
            laned_detail::FileLanedMultiplicationScratch{
                layer,
                directory,
                store_limits(),
            });
    }

    std::vector<HashCommitCT> file_backed_commitments;
    const PackedMessageCommitmentFunction<MockBackend> file_backed_commit =
        [&](const FheValue<MockBackend> &message) {
            const HashCommitCT commitment =
                hash_commit_packed_message<MockBackend>(message);
            file_backed_commitments.push_back(commitment);
            return commitment;
        };
    std::vector<HashCommitCT> resident_commitments;
    const PackedMessageCommitmentFunction<MockBackend> resident_commit =
        [&](const FheValue<MockBackend> &message) {
            const HashCommitCT commitment =
                hash_commit_packed_message<MockBackend>(message);
            resident_commitments.push_back(commitment);
            return commitment;
        };
    std::vector<HashCommitCT> destructive_commitments;
    const PackedMessageCommitmentFunction<MockBackend> destructive_commit =
        [&](const FheValue<MockBackend> &message) {
            const HashCommitCT commitment =
                hash_commit_packed_message<MockBackend>(message);
            destructive_commitments.push_back(commitment);
            return commitment;
        };

    const std::string domain =
        "test/laned/prover-file-backed/" + std::to_string(lanes);
    const std::vector<std::size_t> ingress =
        exact_ingress_schedule(compact);
    std::vector<RuntimeProgressEvent> resident_progress;
    Transcript resident_transcript(domain);
    const auto resident = laned_detail::prove_laned_gkr_resident<MockBackend>(
        payload, circuit, compact, evaluation, ingress, output_claim.point,
        resident_transcript, {}, resident_commit,
        [&resident_progress](const RuntimeProgressEvent &event) {
            resident_progress.push_back(event);
        });
    Transcript file_backed_transcript(domain);
    const auto file_backed =
        laned_detail::prove_laned_gkr<MockBackend>(
            payload, circuit, trace, evaluation, ingress, output_claim.point,
            file_backed_transcript, std::move(options), {}, file_backed_commit);

    Transcript destructive_transcript(domain);
    const auto destructive =
        laned_detail::prove_laned_gkr_irreversible<MockBackend>(
            payload, circuit, destructive_trace, evaluation, ingress,
            output_claim.point,
            destructive_transcript, std::move(destructive_options), {},
            destructive_commit);

    CHECK(protocol::encode_canonical<MockBackend>(destructive.proof) ==
          protocol::encode_canonical<MockBackend>(file_backed.proof));
    CHECK(destructive_commitments == file_backed_commitments);
    const Fpk file_backed_challenge = file_backed_transcript.challenge_fpk();
    const Fpk destructive_challenge = destructive_transcript.challenge_fpk();
    CHECK(destructive_challenge == file_backed_challenge);
    CHECK(resident_progress == expected_progress(circuit, false, false));
    CHECK(span_boundaries(file_backed_progress) ==
          expected_progress(circuit, true, false));
    CHECK(span_boundaries(destructive_progress) ==
          expected_progress(circuit, true, true));
    CHECK(std::any_of(
        file_backed_progress.begin(), file_backed_progress.end(),
        [](const RuntimeProgressEvent &event) {
            return event.boundary == RuntimeProgressBoundary::Update &&
                   event.stage == RuntimeProgressStage::
                       LanedMultiplicationSourceBuild &&
                   event.completed_steps != 0 &&
                   event.completed_steps <= event.total_steps;
        }));
    CHECK(std::any_of(
        file_backed_progress.begin(), file_backed_progress.end(),
        [](const RuntimeProgressEvent &event) {
            return event.boundary == RuntimeProgressBoundary::Update &&
                   event.stage == RuntimeProgressStage::
                       LanedAffineSourcePacking &&
                   event.completed_steps != 0U &&
                   event.completed_steps <= event.total_steps;
        }));

    const ClientSetup<MockBackend> client =
        make_client_setup<MockBackend>(public_setup, contexts.client);
    Transcript resident_verifier_transcript(domain);
    CHECK(laned_detail::verify_encrypted_gkr<MockBackend>(
        payload, circuit, plain.layers.back(), client,
        compact.provenance, compact.trace_id, output_claim, resident,
        resident_verifier_transcript));
    Transcript verifier_transcript(domain);
    CHECK(laned_detail::verify_encrypted_gkr<MockBackend>(
        payload, circuit, plain.layers.back(), client,
        compact.provenance, compact.trace_id, output_claim,
        file_backed.proof, verifier_transcript));
    Transcript destructive_verifier_transcript(domain);
    CHECK(laned_detail::verify_encrypted_gkr<MockBackend>(
        payload, circuit, plain.layers.back(), client,
        compact.provenance, compact.trace_id, output_claim,
        destructive.proof, destructive_verifier_transcript));

    CHECK(file_backed.report.reductions.size() ==
          circuit.layers.size() - 1U);
    CHECK(!file_backed.report.output_trace_retirement.has_value());
    std::size_t multiplication_index = 0;
    for (std::size_t layer = 0;
         layer < file_backed.report.reductions.size(); ++layer) {
        const auto &report = file_backed.report.reductions[layer];
        const LayerKind kind = layer_kind(circuit.layers[layer]);
        CHECK(report.reduction_layer == layer);
        CHECK(report.kind == kind);
        CHECK(!report.trace_retirement.has_value());
        CHECK(report.scratch_reclaimed_physical_bytes == 0);
        if (kind == LayerKind::Affine) {
            CHECK(report.affine.has_value());
            CHECK(!report.multiplication_artifact.has_value());
            CHECK(!report.multiplication.has_value());
            const auto source_layout = laned_layout(circuit, layer + 1U);
            const std::size_t ciphertext_variables =
                std::bit_width(source_layout.padded_ciphertext_count) - 1U;
            const bool materialized =
                source_layout.logical_ciphertext_count <=
                laned_detail::affine_detail::
                    kLanedAffineMaterializedPackedCiphertextLimit;
            const std::uint64_t expected_scans =
                materialized
                    ? 1U
                    : static_cast<std::uint64_t>(
                          ciphertext_variables + 1U);
            const LayerWireSupport wire_support =
                canonical_layer_wire_support(circuit, layer + 1U);
            const std::uint64_t stored_source_count =
                wire_support.live_wire_count;
            const std::uint64_t source_bytes = layer_storage_bytes(
                contexts.eval, compact.layers[layer + 1U], wire_support);
            CHECK(report.affine->source_scans == expected_scans);
            CHECK(report.affine->source_rewinds == expected_scans);
            CHECK(report.affine->source_ciphertexts_read ==
                  expected_scans * stored_source_count);
            CHECK(report.affine->source_logical_bytes_read ==
                  expected_scans * source_bytes);
            CHECK(report.affine->source_framed_record_bytes_read ==
                  expected_scans *
                      (source_bytes + stored_source_count *
                                          sizeof(std::uint64_t)));
            CHECK(report.affine->peak_live_source_ciphertexts ==
                  1U);
            CHECK(report.affine->peak_retained_extension_checkpoints ==
                  1U);
            if (materialized) {
                CHECK(report.affine->materialized_packed_source_values >
                      0U);
                CHECK(report.affine->materialized_packed_source_values <=
                      source_layout.logical_ciphertext_count);
                CHECK(report.affine
                          ->materialized_packed_mask_applications > 0U);
                CHECK(report.affine->source_scalar_promotions == 0U);
            } else {
                CHECK(report.affine->materialized_packed_source_values ==
                      0U);
                CHECK(report.affine->source_scalar_promotions > 0U);
            }
        } else {
            CHECK(!report.affine.has_value());
            CHECK(report.multiplication_artifact.has_value());
            CHECK(report.multiplication.has_value());
            const auto &artifact = *report.multiplication_artifact;
            const auto &statistics = *report.multiplication;
            const auto aliases =
                gkr::detail::make_dense_multiplication_alias_plan(
                    circuit, layer);
            CHECK(artifact.descriptor.reduction_layer == layer);
            CHECK(artifact.descriptor.setup_id ==
                  setup_digest(public_setup));
            CHECK(artifact.directory ==
                  std::filesystem::absolute(
                      artifact.directory).lexically_normal());
            CHECK(!std::filesystem::is_empty(artifact.directory));
            CHECK(artifact.report.stored_values ==
                  aliases.operands.size());
            CHECK(artifact.report.stored_values <=
                  2U * artifact.descriptor.live_pair_count);
            const auto source_storage =
                canonical_layer_storage_layout(circuit, layer + 1U);
            const auto source_support =
                canonical_layer_wire_support(circuit, layer + 1U);
            if (source_storage.stored_wire_count !=
                source_support.live_wire_count) {
                std::size_t expected_reads = 0;
                for (const auto &operand : aliases.operands)
                    for (const auto ordinal : operand.stored_ordinals)
                        expected_reads += ordinal.has_value();
                CHECK(artifact.statistics.source_values_read ==
                      (artifact.descriptor.chunks_per_packed_ciphertext == 1U
                           ? source_storage.stored_wire_count : expected_reads));
                CHECK(artifact.statistics.peak_live_source_values <= 1U);
                CHECK(artifact.statistics.peak_live_packed_values <= 2U);
                CHECK(artifact.statistics.source_range_opens == 1U);
            }
            const std::uint64_t expected_scans =
                static_cast<std::uint64_t>(
                    std::bit_width(
                        laned_layout(circuit, layer)
                            .padded_ciphertext_count) -
                    1U + 1U);
            CHECK(statistics.artifact_scans == expected_scans);
            CHECK(statistics.artifact_pairs_read ==
                  expected_scans * artifact.descriptor.live_pair_count);
            CHECK(statistics.artifact_logical_record_bytes_read ==
                  expected_scans *
                      artifact.report.logical_record_bytes);
            CHECK(statistics.artifact_framed_record_bytes_read ==
                  expected_scans *
                      (artifact.report.logical_record_bytes +
                       artifact.report.stored_values *
                           sizeof(std::uint64_t)));
            CHECK(statistics
                      .peak_live_decoded_source_values <= 5);
            CHECK(statistics.peak_retained_slot_checkpoints == 2);
            ++multiplication_index;
        }
    }
    CHECK(multiplication_index == 2);

    CHECK(destructive.report.reductions.size() ==
          circuit.layers.size() - 1U);
    CHECK(destructive.report.output_trace_retirement.has_value());
    CHECK(destructive.report.output_trace_retirement->layer_index == 0);
    CHECK(destructive.report.output_trace_retirement
              ->reclaimed_physical_bytes == destructive_layer_bytes[0]);

    std::uint64_t reported_trace_reclamation =
        destructive.report.output_trace_retirement
            ->reclaimed_physical_bytes;
    std::size_t destructive_multiplication_index = 0;
    for (std::size_t layer = 0;
         layer < destructive.report.reductions.size(); ++layer) {
        const auto &report = destructive.report.reductions[layer];
        CHECK(report.reduction_layer == layer);
        CHECK(report.kind == layer_kind(circuit.layers[layer]));
        CHECK(report.trace_retirement.has_value());
        CHECK(report.trace_retirement->layer_index == layer + 1U);
        CHECK(report.trace_retirement->reclaimed_physical_bytes ==
              destructive_layer_bytes[layer + 1U]);
        reported_trace_reclamation +=
            report.trace_retirement->reclaimed_physical_bytes;
        if (report.kind == LayerKind::Multiplication) {
            CHECK(report.multiplication_artifact.has_value());
            CHECK(report.scratch_reclaimed_physical_bytes ==
                  report.multiplication_artifact->report.physical_bytes);
            CHECK(std::filesystem::is_empty(
                destructive_scratch_directories.at(
                    destructive_multiplication_index)));
            ++destructive_multiplication_index;
        } else {
            CHECK(report.scratch_reclaimed_physical_bytes == 0);
        }
    }
    CHECK(destructive_multiplication_index ==
          destructive_scratch_directories.size());

    const auto journal = destructive_trace.journal_state();
    CHECK(journal.generation == circuit.layers.size());
    CHECK(journal.retirement_order ==
          sequential_layers(circuit.layers.size()));
    CHECK(journal.retired_layers ==
          std::vector<bool>(circuit.layers.size(), true));
    CHECK(journal.reclaimed_physical_bytes ==
          reported_trace_reclamation);
    CHECK(journal.remaining_trace_physical_bytes ==
          destructive_written.report.physical_bytes -
              reported_trace_reclamation);
    for (std::size_t layer = 0; layer < circuit.layers.size(); ++layer) {
        CHECK(!std::filesystem::exists(
            layer_file(destructive_trace_directory, layer)));
    }
    const auto inspected = inspect_file_trace_retirement_journal(
        destructive_trace_directory);
    CHECK(inspected.generation == journal.generation);
    CHECK(inspected.retirement_order == journal.retirement_order);
    CHECK(inspected.retired_layers == journal.retired_layers);
    CHECK(inspected.reclaimed_physical_bytes ==
          journal.reclaimed_physical_bytes);
}

void expect_invalid_without_scratch_writes() {
    constexpr std::size_t kLanes = 4;
    const PayloadCircuit payload = make_payload(kLanes);
    const LayeredCircuit circuit = compile(payload);
    const std::vector<SlotVector> inputs{
        values(kLanes, 3), values(kLanes, 43)};
    const PlainTrace plain = synthesize_trace(
        payload, circuit, inputs);
    auto contexts = MockBackend::create(MockParameters{
        .slot_count = kSlots,
        .fresh_rns_limbs = 14,
        .bits_per_limb = 120,
    });
    const EncryptedTrace<MockBackend> compact =
        encrypt_compact_synthetic_trace<MockBackend>(
            contexts.eval, contexts.client, payload, circuit, plain,
            TraceEncryptionPlan::uniform(circuit, 9));
    const PublicSetup public_setup = make_direct_setup(payload, circuit);
    const auto evaluation = make_packed_evaluation_setup<MockBackend>(
        public_setup, contexts.eval);
    const std::vector<Fpk> point(
        laned_layer_variables(circuit, 0), Fpk::from_base(Fp(17)));
    const SingleClaim output_claim = make_packed_laned_claim(
        plain.layers.front(), laned_layout(circuit, 0), point);

    TemporaryDirectory root;
    const std::filesystem::path trace_directory =
        root.make_child("trace");
    (void)write_file_encrypted_trace(
        contexts.eval, trace_directory, store_limits(), circuit, compact);
    const auto trace = FileEncryptedTraceStore<MockBackend>::open(
        contexts.eval, trace_directory, payload, circuit,
        compact.provenance, compact.trace_id);
    const std::vector<std::size_t> layers =
        multiplication_layers(circuit);
    CHECK(layers.size() == 2);
    const std::filesystem::path first = root.make_child("first");
    const std::filesystem::path second = root.make_child("second");

    const auto complete_options = [&] {
        laned_detail::FileLanedGkrOptions result;
        result.multiplication_scratch = {
            {layers[0], first, store_limits()},
            {layers[1], second, store_limits()},
        };
        return result;
    };
    const auto expect_invalid = [&](
                                    laned_detail::FileLanedGkrOptions
                                        options,
                                    const SingleClaim &claim) {
        bool rejected = false;
        try {
            Transcript transcript(
                "test/laned/prover-file-backed/rejected");
            (void)laned_detail::prove_laned_gkr<MockBackend>(
                payload, circuit, trace, evaluation,
                exact_ingress_schedule(compact), claim.point, transcript,
                std::move(options));
        } catch (const std::invalid_argument &) {
            rejected = true;
        }
        CHECK(rejected);
        CHECK(std::filesystem::is_empty(first));
        CHECK(std::filesystem::is_empty(second));
    };

    auto missing = complete_options();
    missing.multiplication_scratch.pop_back();
    expect_invalid(std::move(missing), output_claim);

    auto wrong_layer = complete_options();
    wrong_layer.multiplication_scratch[1].reduction_layer = layers[0];
    expect_invalid(std::move(wrong_layer), output_claim);

    auto zero_limit = complete_options();
    zero_limit.multiplication_scratch[1]
        .storage_limits.max_total_bytes = 0;
    expect_invalid(std::move(zero_limit), output_claim);

    auto duplicate = complete_options();
    duplicate.multiplication_scratch[1].directory = first;
    expect_invalid(std::move(duplicate), output_claim);

    SingleClaim bad_claim = output_claim;
    bad_claim.point.pop_back();
    expect_invalid(complete_options(), bad_claim);
}

void expect_irreversible_failure_handoffs() {
    constexpr std::size_t kLanes = 4;
    const PayloadCircuit payload = make_payload(kLanes);
    const LayeredCircuit circuit = compile(payload);
    const std::vector<SlotVector> inputs{
        values(kLanes, 11), values(kLanes, 71)};
    const PlainTrace plain = synthesize_trace(payload, circuit, inputs);
    auto contexts = MockBackend::create(MockParameters{
        .slot_count = kSlots,
        .fresh_rns_limbs = 14,
        .bits_per_limb = 120,
    });
    const EncryptedTrace<MockBackend> compact =
        encrypt_compact_synthetic_trace<MockBackend>(
            contexts.eval, contexts.client, payload, circuit, plain,
            TraceEncryptionPlan::uniform(circuit, 9));
    const PublicSetup public_setup = make_direct_setup(payload, circuit);
    const auto evaluation = make_packed_evaluation_setup<MockBackend>(
        public_setup, contexts.eval);
    const std::vector<Fpk> point(
        laned_layer_variables(circuit, 0), Fpk::from_base(Fp(29)));
    const SingleClaim output_claim = make_packed_laned_claim(
        plain.layers.front(), laned_layout(circuit, 0), point);
    const std::vector<std::size_t> multiplication =
        multiplication_layers(circuit);
    CHECK(multiplication.size() == 2);
    CHECK(layer_kind(circuit.layers.front()) == LayerKind::Affine);

    TemporaryDirectory root;
    const auto make_options =
        [&](const std::string &prefix,
            std::vector<std::filesystem::path> &directories) {
        laned_detail::IrreversibleFileLanedGkrOptions result;
        result.proof.multiplication_scratch.reserve(
            multiplication.size());
        for (const std::size_t layer : multiplication) {
            const std::filesystem::path directory = root.make_child(
                prefix + "-multiplication-" + std::to_string(layer));
            directories.push_back(directory);
            result.proof.multiplication_scratch.push_back(
                laned_detail::FileLanedMultiplicationScratch{
                    layer,
                    directory,
                    store_limits(),
                });
        }
        return result;
    };

    {
        const std::filesystem::path trace_directory =
            root.make_child("fail-closed-trace");
        (void)write_file_encrypted_trace(
            contexts.eval, trace_directory, store_limits(), circuit,
            compact);
        auto store = FileEncryptedTraceStore<MockBackend>::open(
            contexts.eval, trace_directory, payload, circuit,
            compact.provenance, compact.trace_id);
        auto session =
            FileEncryptedTraceReclamationSession<MockBackend>::begin(
                std::move(store),
                FileTraceReclamationOptions{
                    FileTraceSessionLifecycle::IrreversibleNoRetry});
        std::vector<std::filesystem::path> scratch;
        auto options = make_options("fail-closed", scratch);
        bool rejected = false;
        try {
            Transcript transcript(
                "test/laned/prover-file-backed/irreversible-fail-closed");
            (void)laned_detail::
                prove_laned_gkr_irreversible<MockBackend>(
                    payload, circuit, session, evaluation,
                    exact_ingress_schedule(compact), output_claim.point,
                    transcript, std::move(options));
        } catch (const std::invalid_argument &) {
            rejected = true;
        }
        CHECK(rejected);
        CHECK(session.journal_state().generation == 0);
        CHECK(session.journal_state().retirement_order.empty());
        for (std::size_t layer = 0; layer < circuit.layers.size(); ++layer) {
            CHECK(std::filesystem::is_regular_file(
                layer_file(trace_directory, layer)));
        }
        for (const auto &directory : scratch) {
            CHECK(std::filesystem::is_empty(directory));
        }
    }

    {
        const std::filesystem::path trace_directory =
            root.make_child("affine-failure-trace");
        (void)write_file_encrypted_trace(
            contexts.eval, trace_directory, store_limits(), circuit,
            compact);
        auto store = FileEncryptedTraceStore<MockBackend>::open(
            contexts.eval, trace_directory, payload, circuit,
            compact.provenance, compact.trace_id);
        auto session =
            FileEncryptedTraceReclamationSession<MockBackend>::begin(
                std::move(store),
                FileTraceReclamationOptions{
                    FileTraceSessionLifecycle::IrreversibleNoRetry});
        std::vector<std::filesystem::path> scratch;
        auto options = make_options("affine-failure", scratch);
        options.lifecycle = FileTraceSessionLifecycle::IrreversibleNoRetry;
        options.reclaim_completed_multiplication_scratch = true;
        const PackedMessageCommitmentFunction<MockBackend> fail_commitment =
            [](const FheValue<MockBackend> &) -> HashCommitCT {
                throw std::runtime_error(
                    "injected affine commitment failure");
            };
        bool failed = false;
        try {
            Transcript transcript(
                "test/laned/prover-file-backed/affine-failure");
            (void)laned_detail::
                prove_laned_gkr_irreversible<MockBackend>(
                    payload, circuit, session, evaluation,
                    exact_ingress_schedule(compact), output_claim.point,
                    transcript, std::move(options), {}, fail_commitment);
        } catch (const std::runtime_error &) {
            failed = true;
        }
        CHECK(failed);
        const auto journal = session.journal_state();
        CHECK(journal.retirement_order == std::vector<std::size_t>{0});
        CHECK(!std::filesystem::exists(layer_file(trace_directory, 0)));
        CHECK(std::filesystem::is_regular_file(
            layer_file(trace_directory, 1)));
        for (const auto &directory : scratch) {
            CHECK(std::filesystem::is_empty(directory));
        }
    }

    {
        const std::filesystem::path trace_directory =
            root.make_child("multiplication-failure-trace");
        (void)write_file_encrypted_trace(
            contexts.eval, trace_directory, store_limits(), circuit,
            compact);
        auto store = FileEncryptedTraceStore<MockBackend>::open(
            contexts.eval, trace_directory, payload, circuit,
            compact.provenance, compact.trace_id);
        auto session =
            FileEncryptedTraceReclamationSession<MockBackend>::begin(
                std::move(store),
                FileTraceReclamationOptions{
                    FileTraceSessionLifecycle::IrreversibleNoRetry});
        std::vector<std::filesystem::path> scratch;
        auto options = make_options("multiplication-failure", scratch);
        options.lifecycle = FileTraceSessionLifecycle::IrreversibleNoRetry;
        options.reclaim_completed_multiplication_scratch = true;
        const std::size_t reduction_layer = multiplication.front();
        const std::size_t source_layer = reduction_layer + 1U;
        bool injected = false;
        const PackedMessageCommitmentFunction<MockBackend> fail_commitment =
            [&](const FheValue<MockBackend> &message) -> HashCommitCT {
                if (std::filesystem::is_regular_file(
                        scratch.front() / "manifest.bin") &&
                    !std::filesystem::exists(
                        layer_file(trace_directory, source_layer))) {
                    injected = true;
                    throw std::runtime_error(
                        "injected multiplication commitment failure");
                }
                return hash_commit_packed_message<MockBackend>(message);
            };
        bool failed = false;
        try {
            Transcript transcript(
                "test/laned/prover-file-backed/multiplication-failure");
            (void)laned_detail::
                prove_laned_gkr_irreversible<MockBackend>(
                    payload, circuit, session, evaluation,
                    exact_ingress_schedule(compact), output_claim.point,
                    transcript, std::move(options), {}, fail_commitment);
        } catch (const std::runtime_error &) {
            failed = true;
        }
        CHECK(failed);
        CHECK(injected);
        const auto journal = session.journal_state();
        CHECK(journal.retirement_order ==
              sequential_layers(source_layer + 1U));
        CHECK(!std::filesystem::exists(
            layer_file(trace_directory, source_layer)));
        CHECK(std::filesystem::is_regular_file(
            layer_file(trace_directory, source_layer + 1U)));
        CHECK(!std::filesystem::is_empty(scratch.front()));
        CHECK(std::filesystem::is_regular_file(
            scratch.front() / "manifest.bin"));
        for (std::size_t index = 1; index < scratch.size(); ++index) {
            CHECK(std::filesystem::is_empty(scratch[index]));
        }

        const CanonicalTraceLayout canonical =
            canonical_trace_layout(circuit);
        const auto source_plan =
            gkr::detail::make_dense_multiplication_source_plan(
                circuit, session.descriptor(),
                session.layered_circuit_id(), session.backend_context_id(),
                reduction_layer,
                canonical.wire_support.at(reduction_layer + 1U),
                canonical.storage.at(reduction_layer + 1U),
                setup_digest(public_setup),
                exact_ingress_schedule(compact).at(
                    reduction_layer + 1U));
        const auto expected =
            gkr::detail::bind_dense_multiplication_source_descriptor(
                source_plan, session.descriptor(),
                session.layered_circuit_id(), session.backend_context_id());
        const auto replacement =
            gkr::detail::FileDenseMultiplicationSource<MockBackend>::open(
                contexts.eval, scratch.front(), expected, source_plan);
        CHECK(replacement.descriptor() == expected);
        CHECK(replacement.report().physical_bytes > 0);
    }
}

} // namespace

int main() {
    laminate::test::Runner runner("file-backed Laned GKR prover");
    runner.run("B=1 file-backed and destructive proofs agree", [] {
        compare_regime(1);
    });
    runner.run("1<B<N file-backed and destructive proofs agree", [] {
        compare_regime(4);
    });
    runner.run("B=N file-backed and destructive proofs agree", [] {
        compare_regime(16);
    });
    runner.run("invalid requests write no scratch artifacts", [] {
        expect_invalid_without_scratch_writes();
    });
    runner.run("irreversible failures preserve the owned handoff", [] {
        expect_irreversible_failure_handoffs();
    });
    return runner.summary();
}
