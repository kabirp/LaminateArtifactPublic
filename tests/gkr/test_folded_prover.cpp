/// @file test_folded_prover.cpp
/// @brief Full-proof parity and lifecycle tests for LaminateFolded.

#include "test_helpers.hpp"

#include "laminate/fhe/mock_backend.hpp"
#include "laminate/gkr/detail/folded/prover.hpp"
#include "laminate/gkr/detail/folded/reference/prover.hpp"
#include "laminate/gkr/detail/folded/verifier.hpp"
#include "laminate/payload/compiler.hpp"
#include "laminate/payload/evaluator.hpp"
#include "laminate/payload/storage/file_trace_store.hpp"
#include "laminate/payload/trace/trace_crypto.hpp"
#include "laminate/protocol/reference/folded.hpp"
#include "laminate/protocol/metrics/proof_size.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <numeric>
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

constexpr std::size_t kSlots = 32;
constexpr std::size_t kPaddedWires = 1024;
constexpr std::size_t kIngressLimbs = 4;

class TemporaryDirectory {
  public:
    TemporaryDirectory() {
        const auto stamp = std::chrono::steady_clock::now()
                               .time_since_epoch()
                               .count();
        for (std::size_t attempt = 0; attempt < 100; ++attempt) {
            path_ = std::filesystem::temp_directory_path() /
                    ("laminate-folded-prover-" +
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

SlotVector values(std::uint64_t seed) {
    SlotVector result;
    result.reserve(kSlots);
    for (std::size_t slot = 0; slot < kSlots; ++slot) {
        result.emplace_back(seed + 7U * slot + slot * slot);
    }
    return result;
}

PayloadCircuit make_payload(bool affine_program = false) {
    PayloadBuilder builder(PayloadShape::wide(kSlots), 2);
    WireId first = 0;
    for (std::size_t gate = 0; gate < 513; ++gate) {
        const WireId product = builder.mul(0, 1);
        if (gate == 0) {
            first = product;
        }
    }
    if (affine_program) {
        const auto mask = builder.add_plaintext(values(7));
        const auto biased = builder.add_plain(first, mask);
        first = builder.rotate(builder.mul_plain(biased, mask), 5);
    }
    builder.set_outputs({first});
    return builder.finish();
}

FileTraceStoreOptions store_limits() {
    return FileTraceStoreOptions{
        .max_total_bytes = std::uint64_t{1} << 28U,
        .min_free_bytes = 1,
    };
}

std::vector<std::size_t>
multiplication_layers(const LayeredCircuit &circuit) {
    std::vector<std::size_t> result;
    for (std::size_t layer = 0; layer + 1U < circuit.layers.size(); ++layer) {
        if (layer_kind(circuit.layers[layer]) ==
            LayerKind::Multiplication) {
            result.push_back(layer);
        }
    }
    return result;
}

folded_detail::FileFoldedGkrOptions scratch_options(
    const LayeredCircuit &circuit, const TemporaryDirectory &root,
    const std::string &prefix,
    std::vector<std::filesystem::path> *directories = nullptr) {
    folded_detail::FileFoldedGkrOptions result;
    for (const std::size_t layer : multiplication_layers(circuit)) {
        const std::filesystem::path directory =
            root.make_child(prefix + std::to_string(layer));
        if (directories != nullptr) {
            directories->push_back(directory);
        }
        result.multiplication_scratch.push_back(
            folded_detail::FileFoldedMultiplicationScratch{
                layer, directory, store_limits()});
    }
    return result;
}

std::vector<std::size_t> ingress_schedule(
    const LayeredCircuit &circuit) {
    return std::vector<std::size_t>(circuit.layers.size(), kIngressLimbs);
}

std::vector<std::size_t> sequential_layers(std::size_t count) {
    std::vector<std::size_t> result(count);
    std::iota(result.begin(), result.end(), std::size_t{0});
    return result;
}

bool is_folded_storage_stage(RuntimeProgressStage stage) {
    return stage == RuntimeProgressStage::FoldedTraceLayerRetirement ||
           stage == RuntimeProgressStage::FoldedMultiplicationSourceBuild ||
           stage ==
               RuntimeProgressStage::FoldedMultiplicationSourceReclaim;
}

std::vector<RuntimeProgressEvent> without_folded_storage_events(
    std::span<const RuntimeProgressEvent> events) {
    std::vector<RuntimeProgressEvent> result;
    std::copy_if(
        events.begin(), events.end(), std::back_inserter(result),
        [](const RuntimeProgressEvent &event) {
            return !is_folded_storage_stage(event.stage);
        });
    return result;
}

std::vector<RuntimeProgressEvent> without_folded_trace_retirement_events(
    std::span<const RuntimeProgressEvent> events) {
    std::vector<RuntimeProgressEvent> result;
    std::copy_if(
        events.begin(), events.end(), std::back_inserter(result),
        [](const RuntimeProgressEvent &event) {
            return event.stage !=
                RuntimeProgressStage::FoldedTraceLayerRetirement;
        });
    return result;
}

std::size_t progress_event_count(
    std::span<const RuntimeProgressEvent> events,
    RuntimeProgressStage stage, RuntimeProgressBoundary boundary) {
    return static_cast<std::size_t>(std::count_if(
        events.begin(), events.end(),
        [stage, boundary](const RuntimeProgressEvent &event) {
            return event.stage == stage && event.boundary == boundary;
        }));
}

std::size_t first_progress_event(
    std::span<const RuntimeProgressEvent> events,
    RuntimeProgressStage stage, RuntimeProgressBoundary boundary) {
    const auto found = std::find_if(
        events.begin(), events.end(),
        [stage, boundary](const RuntimeProgressEvent &event) {
            return event.stage == stage && event.boundary == boundary;
        });
    CHECK(found != events.end());
    return static_cast<std::size_t>(found - events.begin());
}

void check_balanced_progress(
    std::span<const RuntimeProgressEvent> events) {
    std::vector<RuntimeProgressEvent> active;
    for (const RuntimeProgressEvent &event : events) {
        if (event.boundary == RuntimeProgressBoundary::Update) {
            CHECK(!active.empty());
            continue;
        }
        if (event.boundary == RuntimeProgressBoundary::Begin) {
            active.push_back(event);
            continue;
        }
        CHECK(!active.empty());
        RuntimeProgressEvent expected = active.back();
        active.pop_back();
        expected.boundary = RuntimeProgressBoundary::End;
        CHECK(event == expected);
    }
    CHECK(active.empty());
}

void check_sumcheck_coordinate_labels(
    std::span<const RuntimeProgressEvent> events) {
    bool saw_ciphertext_index_round = false;
    bool saw_slot_index_round = false;
    for (const RuntimeProgressEvent &event : events) {
        if (event.boundary != RuntimeProgressBoundary::Begin ||
            (event.stage != RuntimeProgressStage::FoldedAffineSumcheckRound &&
             event.stage !=
                 RuntimeProgressStage::FoldedMultiplicationSumcheckRound)) {
            continue;
        }
        CHECK(event.coordinate_domain !=
              RuntimeProgressCoordinateDomain::Unspecified);
        saw_ciphertext_index_round |=
            event.coordinate_domain ==
            RuntimeProgressCoordinateDomain::CiphertextIndex;
        saw_slot_index_round |=
            event.coordinate_domain ==
            RuntimeProgressCoordinateDomain::SlotIndex;
    }
    CHECK(saw_ciphertext_index_round);
    CHECK(saw_slot_index_round);
}

protocol::FoldedSetup make_test_packing_setup(
    const MockBackend::EvalContext &eval,
    const LayeredCircuit &circuit) {
    auto parameters = packing::selected_lazy_ternary_parameters();
    parameters.repetitions = 1;
    return protocol::FoldedSetup{
        protocol::make_transcript_packing_spartan_setup(
            protocol::PackingGkrVariant::Folded,
            MockBackend::slot_count(eval),
            protocol::folded_bhip_round_count(circuit),
            {.centered_coefficients =
                 [&eval](const SlotVector &slots) {
                     return MockBackend::
                         encode_centered_plaintext_coefficients(eval, slots);
                 },
             .native_ntt =
                 [&eval](std::span<const std::int64_t> coefficients) {
                     return MockBackend::
                         encode_lowest_plaintext_ntt_coordinates(
                             eval, coefficients);
                 }},
            parameters,
            spartan::BaseFoldPcsParameters{.log_rate = 1, .query_count = 1},
            spartan::Options{
                .matrix_evaluation =
                    spartan::MatrixEvaluationMode::CommittedFactored}),
        ingress_schedule(circuit)};
}

struct Fixture {
    PayloadCircuit payload = make_payload();
    LayeredCircuit circuit = compile(payload);
    std::vector<SlotVector> inputs{values(3), values(29)};
    PlainTrace plain = synthesize_trace(
        payload, circuit, inputs);
    MockBackend::Contexts contexts = MockBackend::create(MockParameters{
        .slot_count = kSlots,
        .fresh_rns_limbs = 14,
        .bits_per_limb = 300,
    });
    EncryptedTrace<MockBackend> compact;
    PublicSetup public_setup;
    EvaluationSetup<MockBackend> evaluation;
    SingleClaim output_claim;

    explicit Fixture(bool affine_program = false)
        : payload(make_payload(affine_program)), compact([&] {
              return encrypt_compact_synthetic_trace<MockBackend>(
                  contexts.eval, contexts.client, payload, circuit, plain,
                  TraceEncryptionPlan::uniform(circuit,
                                               kIngressLimbs - 1U));
          }()),
          public_setup(make_direct_setup(payload, circuit)),
          evaluation(make_packed_evaluation_setup<MockBackend>(
              public_setup, contexts.eval)),
          output_claim(make_layer_claim(
              plain.layers.front(),
              std::vector<Fpk>(base_detail::layer_vars(circuit, 0),
                               Fpk::from_base(Fp(19))))) {
        const auto support = canonical_trace_wire_support(circuit);
        const auto storage = canonical_trace_storage_layout(circuit);
        CHECK(support.size() == compact.layers.size());
        CHECK(storage.size() == compact.layers.size());
        bool saw_large_padding = false;
        for (std::size_t layer = 0; layer < support.size(); ++layer) {
            CHECK(compact.layers[layer].wires.size() ==
                  storage[layer].stored_wire_count);
            saw_large_padding |=
                support[layer].padded_wire_count == kPaddedWires &&
                support[layer].live_wire_count == 513U;
        }
        CHECK(saw_large_padding);
    }
};

bool verify_proof(const Fixture &fixture,
                  const EncryptedFoldedProof<MockBackend> &proof,
                  const std::string &domain) {
    const auto client = make_client_setup<MockBackend>(
        fixture.public_setup, fixture.contexts.client);
    Transcript transcript(domain);
    return folded_detail::verify_encrypted_gkr<MockBackend>(
        fixture.payload, fixture.circuit, fixture.plain.layers.back(), client,
        fixture.compact.provenance, fixture.compact.trace_id,
        fixture.output_claim, proof, transcript);
}

void test_diagonal_affine_program_proof_parity() {
    Fixture fixture(true);
    TemporaryDirectory root;
    const std::string domain = "test/folded/diagonal-affine-program/v1";
    Transcript resident_transcript(domain);
    const auto resident = folded_detail::prove_folded_gkr_resident<MockBackend>(
        fixture.payload, fixture.circuit, fixture.compact, fixture.evaluation,
        fixture.output_claim.point, resident_transcript,
        ingress_schedule(fixture.circuit));
    const auto directory = root.make_child("diagonal-trace");
    (void)write_file_encrypted_trace(fixture.contexts.eval, directory,
        store_limits(), fixture.circuit, fixture.compact);
    const auto trace = FileEncryptedTraceStore<MockBackend>::open(
        fixture.contexts.eval, directory, fixture.payload, fixture.circuit,
        fixture.compact.provenance, fixture.compact.trace_id);
    Transcript file_transcript(domain);
    const auto file = folded_detail::prove_folded_gkr<MockBackend>(
        fixture.payload, fixture.circuit, trace, fixture.evaluation,
        fixture.output_claim.point, file_transcript,
        scratch_options(fixture.circuit, root, "diagonal-scratch-"),
        ingress_schedule(fixture.circuit));
    CHECK(protocol::encode_canonical<MockBackend>(resident) ==
          protocol::encode_canonical<MockBackend>(file.proof));
    CHECK(resident_transcript.challenge_fpk() == file_transcript.challenge_fpk());
    CHECK(verify_proof(fixture, file.proof, domain));
}

void test_full_path_parity_and_retirement() {
    Fixture fixture;
    TemporaryDirectory root;
    const auto schedule = ingress_schedule(fixture.circuit);
    const std::string domain = "test/folded/prover/v1";

    std::vector<HashCommitCT> resident_commitments;
    std::vector<RuntimeProgressEvent> resident_progress;
    Transcript resident_transcript(domain);
    const auto resident = folded_detail::prove_folded_gkr_resident<MockBackend>(
        fixture.payload, fixture.circuit, fixture.compact,
        fixture.evaluation, fixture.output_claim.point, resident_transcript,
        schedule, {},
        [&](const FheValue<MockBackend> &message) {
            const HashCommitCT result =
                hash_commit_packed_message<MockBackend>(message);
            resident_commitments.push_back(result);
            return result;
        },
        [&resident_progress](const RuntimeProgressEvent &event) {
            resident_progress.push_back(event);
        });

    const std::filesystem::path trace_directory =
        root.make_child("trace");
    (void)write_file_encrypted_trace(
        fixture.contexts.eval, trace_directory, store_limits(),
        fixture.circuit, fixture.compact);
    const auto trace = FileEncryptedTraceStore<MockBackend>::open(
        fixture.contexts.eval, trace_directory, fixture.payload,
        fixture.circuit, fixture.compact.provenance,
        fixture.compact.trace_id);

    auto options = scratch_options(fixture.circuit, root, "scratch-");
    std::vector<RuntimeProgressEvent> file_backed_progress;
    options.progress = [&file_backed_progress](
                           const RuntimeProgressEvent &event) {
        file_backed_progress.push_back(event);
    };
    for (const auto &scratch : options.multiplication_scratch) {
        CHECK(std::filesystem::is_empty(scratch.directory));
    }
    folded_detail::validate_folded_gkr_request<MockBackend>(
        fixture.payload, fixture.circuit, trace, fixture.evaluation,
        fixture.output_claim.point, options, schedule);
    for (const auto &scratch : options.multiplication_scratch) {
        CHECK(std::filesystem::is_empty(scratch.directory));
    }

    std::vector<HashCommitCT> file_backed_commitments;
    Transcript file_backed_transcript(domain);
    const auto file_backed =
        folded_detail::prove_folded_gkr<MockBackend>(
            fixture.payload, fixture.circuit, trace, fixture.evaluation,
            fixture.output_claim.point, file_backed_transcript,
            std::move(options), schedule, {},
            [&](const FheValue<MockBackend> &message) {
                const HashCommitCT result =
                    hash_commit_packed_message<MockBackend>(message);
                file_backed_commitments.push_back(result);
                return result;
            });

    CHECK(protocol::encode_canonical<MockBackend>(resident) ==
          protocol::encode_canonical<MockBackend>(file_backed.proof));
    CHECK(resident_commitments == file_backed_commitments);
    CHECK(resident_transcript.challenge_fpk() ==
          file_backed_transcript.challenge_fpk());
    CHECK(verify_proof(fixture, resident, domain));
    CHECK(verify_proof(fixture, file_backed.proof, domain));
    CHECK(!file_backed.report.output_trace_retirement.has_value());

    const auto support = canonical_trace_wire_support(fixture.circuit);
    CHECK(file_backed.report.reductions.size() ==
          fixture.circuit.layers.size() - 1U);
    for (std::size_t layer = 0;
         layer < file_backed.report.reductions.size(); ++layer) {
        const auto &report = file_backed.report.reductions[layer];
        CHECK(!report.trace_retirement.has_value());
        if (report.affine) {
            CHECK(report.affine->source_ciphertexts_read ==
                  report.affine->source_scans *
                      support[layer + 1U].live_wire_count);
            CHECK(report.affine->public_zero_positions ==
                  report.affine->source_scans *
                      (support[layer + 1U].padded_wire_count -
                       support[layer + 1U].live_wire_count));
            CHECK(report.affine->online_slot_vectors_constructed == 0);
            CHECK(report.affine->peak_live_source_ciphertexts <= 1U);
        } else {
            CHECK(report.multiplication.has_value());
            const std::size_t wire_variables =
                base_detail::ciphertext_index_variables(
                    fixture.circuit, layer);
            CHECK(report.multiplication->artifact_scans ==
                  wire_variables + 1U);
            CHECK(report.multiplication->artifact_pairs_read > 0);
            CHECK(report.multiplication->online_slot_vectors_constructed ==
                  0);
            CHECK(report.multiplication
                      ->peak_retained_slot_checkpoints == 2U);
            CHECK(report.scratch_reclaimed_physical_bytes ==
                  report.multiplication_artifact->storage.physical_bytes);
        }
    }

    const std::filesystem::path destructive_directory =
        root.make_child("destructive-trace");
    const auto written = write_file_encrypted_trace(
        fixture.contexts.eval, destructive_directory, store_limits(),
        fixture.circuit, fixture.compact);
    auto destructive_store = FileEncryptedTraceStore<MockBackend>::open(
        fixture.contexts.eval, destructive_directory, fixture.payload,
        fixture.circuit, fixture.compact.provenance,
        fixture.compact.trace_id);
    auto session = FileEncryptedTraceReclamationSession<MockBackend>::begin(
        std::move(destructive_store),
        FileTraceReclamationOptions{
            FileTraceSessionLifecycle::IrreversibleNoRetry});
    folded_detail::IrreversibleFileFoldedGkrOptions
        destructive_options;
    destructive_options.lifecycle =
        FileTraceSessionLifecycle::IrreversibleNoRetry;
    destructive_options.proof =
        scratch_options(fixture.circuit, root, "destructive-scratch-");
    std::vector<RuntimeProgressEvent> destructive_progress;
    destructive_options.proof.progress =
        [&destructive_progress](const RuntimeProgressEvent &event) {
            destructive_progress.push_back(event);
            throw std::runtime_error("injected progress callback failure");
        };
    Transcript destructive_transcript(domain);
    const auto destructive =
        folded_detail::prove_folded_gkr_irreversible<MockBackend>(
            fixture.payload, fixture.circuit, session, fixture.evaluation,
            fixture.output_claim.point, destructive_transcript,
            std::move(destructive_options), schedule);
    CHECK(protocol::encode_canonical<MockBackend>(resident) ==
          protocol::encode_canonical<MockBackend>(destructive.proof));
    check_balanced_progress(resident_progress);
    check_balanced_progress(file_backed_progress);
    check_balanced_progress(destructive_progress);
    check_sumcheck_coordinate_labels(file_backed_progress);
    CHECK(without_folded_storage_events(file_backed_progress) ==
          resident_progress);
    CHECK(without_folded_storage_events(destructive_progress) ==
          resident_progress);
    const std::size_t multiplication_count =
        multiplication_layers(fixture.circuit).size();
    for (const RuntimeProgressStage stage : {
             RuntimeProgressStage::FoldedMultiplicationSourceBuild,
             RuntimeProgressStage::FoldedMultiplicationSourceReclaim}) {
        CHECK(progress_event_count(
                  file_backed_progress, stage,
                  RuntimeProgressBoundary::Begin) == multiplication_count);
        CHECK(progress_event_count(
                  file_backed_progress, stage,
                  RuntimeProgressBoundary::End) == multiplication_count);
        CHECK(progress_event_count(
                  destructive_progress, stage,
                  RuntimeProgressBoundary::Begin) == multiplication_count);
        CHECK(progress_event_count(
                  destructive_progress, stage,
                  RuntimeProgressBoundary::End) == multiplication_count);
    }
    CHECK(progress_event_count(
              file_backed_progress,
              RuntimeProgressStage::FoldedTraceLayerRetirement,
              RuntimeProgressBoundary::Begin) == 0U);
    CHECK(progress_event_count(
              destructive_progress,
              RuntimeProgressStage::FoldedTraceLayerRetirement,
              RuntimeProgressBoundary::Begin) ==
          fixture.circuit.layers.size());
    CHECK(progress_event_count(
              destructive_progress,
              RuntimeProgressStage::FoldedTraceLayerRetirement,
              RuntimeProgressBoundary::End) ==
          fixture.circuit.layers.size());
    CHECK(destructive.report.output_trace_retirement.has_value());
    CHECK(destructive.report.output_trace_retirement->layer_index == 0);
    for (std::size_t layer = 0;
         layer < destructive.report.reductions.size(); ++layer) {
        CHECK(destructive.report.reductions[layer]
                  .trace_retirement.has_value());
        CHECK(destructive.report.reductions[layer]
                  .trace_retirement->layer_index == layer + 1U);
    }
    const auto journal = session.journal_state();
    CHECK(journal.retirement_order ==
          sequential_layers(fixture.circuit.layers.size()));
    CHECK(journal.retired_layers ==
          std::vector<bool>(fixture.circuit.layers.size(), true));
    CHECK(journal.remaining_trace_physical_bytes ==
          written.report.physical_bytes -
              journal.reclaimed_physical_bytes);
}

void test_top_level_file_progress() {
    Fixture fixture;
    TemporaryDirectory root;
    const protocol::FoldedSetup packing_setup =
        make_test_packing_setup(fixture.contexts.eval, fixture.circuit);
    CHECK(packing_setup.proof_ingress_rns_limbs_by_layer ==
          ingress_schedule(fixture.circuit));
    const std::string domain = "test/folded/prover/selected/v1";

    const std::filesystem::path retryable_directory =
        root.make_child("selected-retryable-trace");
    (void)write_file_encrypted_trace(
        fixture.contexts.eval, retryable_directory, store_limits(),
        fixture.circuit, fixture.compact);
    const auto retryable_trace =
        FileEncryptedTraceStore<MockBackend>::open(
            fixture.contexts.eval, retryable_directory, fixture.payload,
            fixture.circuit, fixture.compact.provenance,
            fixture.compact.trace_id);
    protocol::reference::RetryableFoldedFileProofOptions retryable_options =
        scratch_options(fixture.circuit, root,
                        "selected-retryable-scratch-");
    std::vector<RuntimeProgressEvent> retryable_progress;
    retryable_options.progress =
        [&retryable_progress](const RuntimeProgressEvent &event) {
            retryable_progress.push_back(event);
        };
    Transcript retryable_transcript(domain);
    const auto retryable =
        protocol::reference::prove_folded_file_reference<MockBackend>(
            fixture.payload, fixture.circuit, retryable_trace,
            fixture.evaluation, packing_setup, fixture.output_claim.point,
            retryable_transcript, std::move(retryable_options));

    const std::filesystem::path destructive_directory =
        root.make_child("selected-destructive-trace");
    (void)write_file_encrypted_trace(
        fixture.contexts.eval, destructive_directory, store_limits(),
        fixture.circuit, fixture.compact);
    auto destructive_store = FileEncryptedTraceStore<MockBackend>::open(
        fixture.contexts.eval, destructive_directory, fixture.payload,
        fixture.circuit, fixture.compact.provenance,
        fixture.compact.trace_id);
    auto destructive_trace =
        FileEncryptedTraceReclamationSession<MockBackend>::begin(
            std::move(destructive_store),
            FileTraceReclamationOptions{
                FileTraceSessionLifecycle::IrreversibleNoRetry});
    protocol::reference::IrreversibleFoldedFileProofOptions
        destructive_options;
    destructive_options.lifecycle =
        FileTraceSessionLifecycle::IrreversibleNoRetry;
    destructive_options.reclaim_completed_multiplication_scratch = true;
    destructive_options.proof = scratch_options(
        fixture.circuit, root, "selected-destructive-scratch-");
    std::vector<RuntimeProgressEvent> destructive_progress;
    destructive_options.proof.progress =
        [&destructive_progress](const RuntimeProgressEvent &event) {
            destructive_progress.push_back(event);
            throw std::runtime_error("injected progress callback failure");
        };
    Transcript destructive_transcript(domain);
    const auto destructive =
        protocol::reference::prove_folded_file_irreversible_reference<
            MockBackend>(
            fixture.payload, fixture.circuit, destructive_trace,
            fixture.evaluation, packing_setup, fixture.output_claim.point,
            destructive_transcript, std::move(destructive_options));

    CHECK(protocol::encode_canonical<MockBackend>(retryable.proof) ==
          protocol::encode_canonical<MockBackend>(destructive.proof));
    check_balanced_progress(retryable_progress);
    check_balanced_progress(destructive_progress);
    CHECK(without_folded_trace_retirement_events(retryable_progress) ==
          without_folded_trace_retirement_events(destructive_progress));
    for (const RuntimeProgressStage stage : {
             RuntimeProgressStage::TranscriptPackingRevealEvaluation,
             RuntimeProgressStage::TranscriptPackingAssignment,
             RuntimeProgressStage::TranscriptPackingSpartanProve}) {
        CHECK(progress_event_count(
                  retryable_progress, stage,
                  RuntimeProgressBoundary::Begin) == 1U);
        CHECK(progress_event_count(
                  retryable_progress, stage,
                  RuntimeProgressBoundary::End) == 1U);
    }
    CHECK(first_progress_event(
              retryable_progress,
              RuntimeProgressStage::FoldedGateMleFinish,
              RuntimeProgressBoundary::End) <
          first_progress_event(
              retryable_progress,
              RuntimeProgressStage::TranscriptPackingRevealEvaluation,
              RuntimeProgressBoundary::Begin));

    const auto client = make_client_setup<MockBackend>(
        fixture.public_setup, fixture.contexts.client);
    const protocol::FoldedVerifierSetup verifier_setup =
        protocol::verifier_setup(packing_setup);
    Transcript verifier_transcript(domain);
    CHECK(protocol::verify_folded<MockBackend>(
        fixture.payload, fixture.circuit, fixture.plain.layers.back(),
        fixture.contexts.eval, verifier_setup, client,
        fixture.compact.provenance, fixture.compact.trace_id,
        fixture.output_claim, retryable.proof, verifier_transcript));
}

void test_exact_ingress_rejection_is_preflight_only() {
    Fixture fixture;
    TemporaryDirectory root;
    const std::filesystem::path trace_directory =
        root.make_child("trace");
    (void)write_file_encrypted_trace(
        fixture.contexts.eval, trace_directory, store_limits(),
        fixture.circuit, fixture.compact);
    const auto trace = FileEncryptedTraceStore<MockBackend>::open(
        fixture.contexts.eval, trace_directory, fixture.payload,
        fixture.circuit, fixture.compact.provenance,
        fixture.compact.trace_id);

    const auto expect_rejected = [&](std::size_t wrong_limbs,
                                     const std::string &prefix) {
        std::vector<std::size_t> schedule =
            ingress_schedule(fixture.circuit);
        schedule[1] = wrong_limbs;

        bool resident_rejected = false;
        try {
            Transcript transcript("test/folded/ingress/resident");
            (void)folded_detail::prove_folded_gkr_resident<MockBackend>(
                fixture.payload, fixture.circuit, fixture.compact,
                fixture.evaluation, fixture.output_claim.point, transcript,
                schedule);
        } catch (const std::invalid_argument &) {
            resident_rejected = true;
        }
        CHECK(resident_rejected);

        auto options = scratch_options(
            fixture.circuit, root, prefix);
        bool file_rejected = false;
        try {
            folded_detail::validate_folded_gkr_request<MockBackend>(
                fixture.payload, fixture.circuit, trace,
                fixture.evaluation, fixture.output_claim.point, options,
                schedule);
        } catch (const std::invalid_argument &) {
            file_rejected = true;
        }
        CHECK(file_rejected);
        for (const auto &scratch : options.multiplication_scratch) {
            CHECK(std::filesystem::is_empty(scratch.directory));
        }
    };

    expect_rejected(kIngressLimbs - 1U, "under-");
    expect_rejected(kIngressLimbs + 1U, "over-");
}

void test_public_file_ingress_is_level_less() {
    Fixture fixture;
    TemporaryDirectory root;
    CHECK(fixture.compact.layers.size() > 1U);
    for (std::size_t wire = 0;
         wire < fixture.compact.layers[1].wires.size(); ++wire) {
        fixture.compact.layers[1].wires[wire] =
            FheValue<MockBackend>::public_scalar(Fp(37 + wire));
    }

    const std::filesystem::path trace_directory =
        root.make_child("public-trace");
    (void)write_file_encrypted_trace(
        fixture.contexts.eval, trace_directory, store_limits(),
        fixture.circuit, fixture.compact);
    const auto trace = FileEncryptedTraceStore<MockBackend>::open(
        fixture.contexts.eval, trace_directory, fixture.payload,
        fixture.circuit, fixture.compact.provenance,
        fixture.compact.trace_id);
    const auto options =
        scratch_options(fixture.circuit, root, "public-scratch-");

    folded_detail::validate_folded_gkr_request<MockBackend>(
        fixture.payload, fixture.circuit, trace, fixture.evaluation,
        fixture.output_claim.point, options, ingress_schedule(fixture.circuit));
}

void test_standalone_affine_rejects_other_circuit() {
    Fixture fixture;
    TemporaryDirectory root;
    const std::filesystem::path trace_directory =
        root.make_child("affine-identity-trace");
    (void)write_file_encrypted_trace(
        fixture.contexts.eval, trace_directory, store_limits(),
        fixture.circuit, fixture.compact);
    const auto trace = FileEncryptedTraceStore<MockBackend>::open(
        fixture.contexts.eval, trace_directory, fixture.payload,
        fixture.circuit, fixture.compact.provenance,
        fixture.compact.trace_id);

    // Keep every public dimension unchanged while changing one affine gate.
    // Shape-only admission would incorrectly accept this circuit with the
    // original circuit's source store.
    LayeredCircuit other_circuit = fixture.circuit;
    auto &output_layer =
        std::get<AffineLayer>(other_circuit.layers.front());
    output_layer.gates.front().constant = Fp(17);
    other_circuit.validate();
    CHECK(other_circuit.shape == fixture.circuit.shape);
    CHECK(layer_dimensions(other_circuit.layers.front()) ==
          layer_dimensions(fixture.circuit.layers.front()));
    CHECK(digest(other_circuit) != digest(fixture.circuit));

    const std::string domain = "test/folded/affine-source-admission/v1";
    Transcript rejected_transcript(domain);
    bool rejected = false;
    try {
        const LayerClaim claim = fixture.output_claim;
        (void)folded_detail::prove_affine<MockBackend>(
            fixture.contexts.eval, other_circuit, trace,
            trace.layer_support(1U), 0U, claim, rejected_transcript);
    } catch (const std::invalid_argument &) {
        rejected = true;
    }
    CHECK(rejected);

    // Admission precedes every proof message and challenge.
    Transcript untouched_transcript(domain);
    CHECK(rejected_transcript.challenge_fpk() ==
          untouched_transcript.challenge_fpk());
}

void test_public_zero_affine_checkpoint_is_null() {
    Fixture fixture;
    TemporaryDirectory root;
    constexpr std::size_t source_layer = 1;
    CHECK(fixture.compact.layers.size() > source_layer);
    for (auto &wire : fixture.compact.layers[source_layer].wires) {
        wire = FheValue<MockBackend>::public_zero();
    }

    const std::filesystem::path trace_directory =
        root.make_child("public-zero-trace");
    (void)write_file_encrypted_trace(
        fixture.contexts.eval, trace_directory, store_limits(),
        fixture.circuit, fixture.compact);
    const auto trace = FileEncryptedTraceStore<MockBackend>::open(
        fixture.contexts.eval, trace_directory, fixture.payload,
        fixture.circuit, fixture.compact.provenance,
        fixture.compact.trace_id);
    const LayerWireSupport &support = trace.layer_support(source_layer);
    auto ciphertext_index_equalities =
        folded_detail::PreparedCiphertextIndexEqualities::create(
            base_detail::ciphertext_index_variables(
                fixture.circuit, source_layer));
    while (ciphertext_index_equalities.bound_variables() <
           ciphertext_index_equalities.variables()) {
        ciphertext_index_equalities.bind(Fpk::from_base(
            Fp(41 + ciphertext_index_equalities.bound_variables())));
    }
    auto reader = trace.active_layer_reader(source_layer);
    folded_detail::FoldedAffineStatistics statistics;

    const auto checkpoint =
        folded_detail::evaluate_affine_slot_checkpoint<MockBackend>(
            fixture.contexts.eval, reader, support,
            ciphertext_index_equalities,
            statistics);

    CHECK(checkpoint.is_public_zero());
    CHECK(checkpoint.ciphertext_count() == 0);
    CHECK(statistics.source_scans == 1);
    CHECK(statistics.source_ciphertexts_read == 0);
    CHECK(statistics.peak_live_source_ciphertexts == 0);
}

} // namespace

int main() {
    laminate::test::Runner runner("file-backed Folded GKR prover");
    runner.run("diagonal affine DAG resident and file proofs agree",
               test_diagonal_affine_program_proof_parity);
    runner.run("resident, file, and destructive full proofs agree",
               test_full_path_parity_and_retirement);
    runner.run("selected file paths publish balanced packing telemetry",
               test_top_level_file_progress);
    runner.run("exact under and over ingress levels fail before writes",
               test_exact_ingress_rejection_is_preflight_only);
    runner.run("public file ingress values are level-less",
               test_public_file_ingress_is_level_less);
    runner.run("standalone affine rejects another same-shape circuit",
               test_standalone_affine_rejects_other_circuit);
    runner.run("public-zero affine checkpoint remains null",
               test_public_zero_affine_checkpoint_is_null);
    return runner.summary();
}
