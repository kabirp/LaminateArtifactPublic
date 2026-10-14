/// @file test_laned_affine_file_backed.cpp
/// @brief Exact Mock comparison for file-backed Laned affine reduction.

#include "test_helpers.hpp"

#include "laminate/fhe/mock_backend.hpp"
#include "laminate/fhe/storage/value_codec.hpp"
#include "laminate/gates/gate_mle.hpp"
#include "laminate/gkr/detail/laned/affine/reference/prover.hpp"
#include "laminate/gkr/detail/laned/affine/prover.hpp"
#include "laminate/gkr/detail/laned/affine/verifier.hpp"
#include "laminate/gkr/detail/laned/affine/source/chunk_batches.hpp"
#include "laminate/gkr/detail/shared/packed/message_reader.hpp"
#include "laminate/payload/compiler.hpp"
#include "laminate/payload/storage/file_trace_store.hpp"
#include "laminate/payload/trace/trace_crypto.hpp"
#include "laminate/poly/eq.hpp"

#include <chrono>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <span>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace {

using laminate::Fp;
using laminate::Fpk;
using laminate::Transcript;
using laminate::fhe::MockBackend;
using laminate::fhe::MockParameters;
using laminate::fhe::SlotVector;
using laminate::gkr::LayerClaim;
using laminate::gkr::SingleClaim;
using laminate::payload::EncryptedTrace;
using laminate::payload::FileEncryptedTraceStore;
using laminate::payload::FileTraceStoreOptions;
using laminate::payload::LayeredCircuit;
using laminate::payload::PayloadBuilder;
using laminate::payload::PayloadCircuit;
using laminate::payload::PayloadShape;
using laminate::payload::PlainTrace;
using laminate::payload::TraceEncryptionPlan;

std::vector<Fpk> evaluate_public_table_prefix(
    std::span<const Fpk> table, std::span<const Fpk> prefix) {
    const std::vector<Fpk> weights = laminate::poly::eq_evaluations(
        std::vector<Fpk>(prefix.begin(), prefix.end()));
    const std::size_t suffix_count = table.size() / weights.size();
    std::vector<Fpk> result(suffix_count, Fpk::zero());
    for (std::size_t bound = 0; bound < weights.size(); ++bound) {
        for (std::size_t suffix = 0; suffix < suffix_count; ++suffix) {
            result[suffix] +=
                weights[bound] * table[bound * suffix_count + suffix];
        }
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
                    ("laminate-affine-file-backed-" + std::to_string(stamp) +
                     "-" + std::to_string(attempt));
            if (!std::filesystem::exists(path_)) {
                return;
            }
        }
        throw std::runtime_error("failed to select a temporary directory");
    }

    ~TemporaryDirectory() {
        std::error_code ignored;
        std::filesystem::remove_all(path_, ignored);
    }

    const std::filesystem::path &path() const { return path_; }

  private:
    std::filesystem::path path_;
};

PayloadCircuit make_affine_payload(std::size_t source_width,
                                   std::size_t lane_count,
                                   std::size_t slot_count = 16) {
    PayloadBuilder builder(PayloadShape::laned(lane_count, slot_count),
                           source_width);
    const auto output = builder.add(0, 1);
    builder.set_outputs({output});
    return builder.finish();
}

PayloadCircuit make_same_geometry_affine_payload(
    std::size_t source_width, std::size_t lane_count,
    std::size_t slot_count = 16) {
    PayloadBuilder builder(PayloadShape::laned(lane_count, slot_count),
                           source_width);
    const std::size_t scalar = builder.add_scalar_plaintext(Fp(9));
    builder.set_outputs({builder.add_plain(0, scalar)});
    return builder.finish();
}

SlotVector input_lanes(std::size_t input, std::size_t lane_count) {
    SlotVector result;
    result.reserve(lane_count);
    for (std::size_t lane = 0; lane < lane_count; ++lane) {
        result.emplace_back(17 * input + 5 * lane + 3);
    }
    return result;
}

struct ComparisonResult {
    laminate::gkr::laned_detail::LanedAffineStatistics statistics;
    std::size_t source_wire_count = 0;
    std::size_t chunks_per_ciphertext = 0;
};

ComparisonResult compare_reference_and_file_backed(
    std::size_t source_width, std::size_t lane_count = 16,
    std::size_t slot_count = 16) {
    const PayloadCircuit payload =
        make_affine_payload(source_width, lane_count, slot_count);
    const LayeredCircuit circuit = laminate::payload::compile(payload);
    std::vector<SlotVector> inputs;
    inputs.reserve(source_width);
    for (std::size_t input = 0; input < source_width; ++input) {
        inputs.push_back(input_lanes(input, lane_count));
    }
    const PlainTrace plain = laminate::payload::synthesize_trace(
        payload, circuit, inputs);
    auto contexts = MockBackend::create(MockParameters{
        .slot_count = slot_count,
        .fresh_rns_limbs = 12,
        .bits_per_limb = 80,
    });
    MockBackend::preprocess_fixed_message_cells(contexts.eval);
    const EncryptedTrace<MockBackend> resident =
        laminate::payload::encrypt_compact_synthetic_trace<MockBackend>(
            contexts.eval, contexts.client, payload, circuit, plain,
            TraceEncryptionPlan::uniform(circuit, 8));

    CHECK(circuit.layers.size() == 2);
    constexpr std::size_t kAffineLayer = 0;
    const auto source_layout =
        laminate::gkr::laned_layout(circuit, kAffineLayer + 1);
    CHECK(source_layout.lane_count == lane_count);
    CHECK(source_layout.slot_count == slot_count);
    const auto source_support =
        laminate::payload::canonical_layer_wire_support(
            circuit, kAffineLayer + 1);
    CHECK(source_layout.original_wire_count ==
          source_support.padded_wire_count);
    CHECK(resident.layers[kAffineLayer + 1].wires.size() ==
          source_support.live_wire_count);
    const std::size_t source_rns_limbs =
        MockBackend::rns_limb_count(
            contexts.eval,
            resident.layers[kAffineLayer + 1].wires.front().ciphertext());

    const std::vector<Fpk> output_point(
        laminate::gkr::laned_layer_variables(circuit, kAffineLayer),
        Fpk::from_base(Fp(23)));
    const SingleClaim output_claim =
        laminate::gkr::make_packed_laned_claim(
            plain.layers[kAffineLayer],
            laminate::gkr::laned_layout(circuit, kAffineLayer),
            output_point);
    const LayerClaim claim = output_claim;

    EncryptedTrace<MockBackend> mismatched = resident;
    CHECK(mismatched.layers[kAffineLayer + 1].required_mult_depth > 0);
    --mismatched.layers[kAffineLayer + 1].required_mult_depth;
    bool rejected_mismatched_level = false;
    try {
        TemporaryDirectory mismatched_directory;
        (void)laminate::payload::write_file_encrypted_trace(
            contexts.eval, mismatched_directory.path(),
            FileTraceStoreOptions{
                .max_total_bytes = 1ULL << 28U,
                .min_free_bytes = 1,
            },
            circuit, mismatched);
    } catch (const std::invalid_argument &) {
        rejected_mismatched_level = true;
    }
    CHECK(rejected_mismatched_level);

    TemporaryDirectory directory;
    (void)laminate::payload::write_file_encrypted_trace(
        contexts.eval, directory.path(),
        FileTraceStoreOptions{
            .max_total_bytes = 1ULL << 28U,
            .min_free_bytes = 1,
        },
        circuit, resident);
    const auto store = FileEncryptedTraceStore<MockBackend>::open(
        contexts.eval, directory.path(), payload, circuit,
        resident.provenance, resident.trace_id);

    const PayloadCircuit other_payload =
        make_same_geometry_affine_payload(
            source_width, lane_count, slot_count);
    const LayeredCircuit other_circuit =
        laminate::payload::compile(other_payload);
    CHECK(laminate::payload::digest(other_circuit) !=
          laminate::payload::digest(circuit));
    CHECK(other_circuit.layers.size() == circuit.layers.size());
    bool rejected_other_circuit = false;
    try {
        Transcript rejected_transcript(
            "test/laned/affine-file-backed/v1");
        (void)laminate::gkr::laned_detail::prove_affine<
            MockBackend>(contexts.eval, other_circuit, store,
                         store.layer_support(kAffineLayer + 1U),
                         kAffineLayer, claim, rejected_transcript,
                         source_rns_limbs);
    } catch (const std::invalid_argument &) {
        rejected_other_circuit = true;
    }
    CHECK(rejected_other_circuit);

    Transcript resident_transcript("test/laned/affine-file-backed/v1");
    const auto resident_proof =
        laminate::gkr::laned_detail::prove_affine_resident_reference<MockBackend>(
            contexts.eval, circuit, resident, kAffineLayer, claim,
            resident_transcript, source_rns_limbs);

    laminate::gkr::laned_detail::LanedAffineStatistics statistics;
    Transcript file_backed_transcript("test/laned/affine-file-backed/v1");
    const auto file_backed_proof =
        laminate::gkr::laned_detail::prove_affine<MockBackend>(
            contexts.eval, circuit, store,
            store.layer_support(kAffineLayer + 1U), kAffineLayer, claim,
            file_backed_transcript, source_rns_limbs, 0, nullptr, {},
            &statistics);

    CHECK(file_backed_proof.proof.rounds.size() ==
          resident_proof.proof.rounds.size());
    const laminate::gkr::detail::FixedMessageReader<MockBackend>
        message_reader(contexts.client);
    // The optimized circuit produces different ciphertext bytes and thus a
    // different Fiat--Shamir suffix. The first message precedes that
    // divergence and provides a direct fixed-point comparison.
    CHECK(message_reader.read(
              file_backed_proof.proof.rounds.front().packed_evaluations,
              2) ==
          message_reader.read(
              resident_proof.proof.rounds.front().packed_evaluations,
              2));
    laminate::gates::DirectGateMle gate_mles(circuit);
    Transcript verifier_transcript(
        "test/laned/affine-file-backed/v1");
    const auto verified =
        laminate::gkr::laned_detail::verify_affine_reduction<MockBackend>(
            message_reader, circuit, kAffineLayer, claim,
            file_backed_proof.proof, gate_mles, verifier_transcript);
    CHECK(verified.has_value());
    CHECK(verified->point == file_backed_proof.next_claim.point);
    CHECK(*verified == laminate::gkr::make_packed_laned_claim(
                           plain.layers[kAffineLayer + 1U], source_layout,
                           verified->point));
    CHECK(statistics.source_rewinds > 0);
    const std::size_t ciphertext_variables =
        std::bit_width(source_layout.padded_ciphertext_count) - 1U;
    const bool materialized =
        source_layout.logical_ciphertext_count <=
        laminate::gkr::laned_detail::affine_detail::
            kLanedAffineMaterializedPackedCiphertextLimit;
    const std::size_t expected_passes =
        materialized ? 1U : ciphertext_variables + 1U;
    CHECK(statistics.source_rewinds == expected_passes);
    CHECK(statistics.source_ciphertexts_read ==
          expected_passes * source_width);
    CHECK(statistics.public_prefix_weight_entries_built ==
          4U * (source_layout.padded_ciphertext_count - 1U));
    CHECK(statistics.public_prefix_weight_lookups > 0);
    const std::size_t active_gate_entries =
        source_layout.padded_ciphertext_count *
        source_layout.chunks_per_ciphertext();
    CHECK(statistics.public_gate_table_entries_processed ==
          3U * (active_gate_entries - 1U));
    CHECK(statistics.peak_live_source_ciphertexts == 1);
    CHECK(statistics.peak_retained_extension_checkpoints == 1);
    CHECK(statistics.prepared_lane_bases ==
          (materialized ? 0U : 1U));
    CHECK(statistics.online_slot_vectors_constructed == 0 ||
          materialized);
    CHECK(statistics.accumulator_presence_observations ==
          statistics.source_scalar_promotions);
    CHECK(statistics.slot_checkpoint_prefix_bindings ==
          std::bit_width(source_layout.slot_count) - 1U);
    CHECK(statistics.slot_public_mask_pairs_constructed ==
          statistics.slot_checkpoint_prefix_bindings);

    return ComparisonResult{statistics, source_width,
                            source_layout.chunks_per_ciphertext()};
}

std::uint64_t exercise_gate_table_fold(std::size_t size) {
    std::vector<Fpk> table(size);
    for (std::size_t index = 0; index < size; ++index) {
        table[index] = Fpk::from_base(Fp(3U * index + 1U));
    }
    laminate::gkr::laned_detail::AffineGateTableFoldState state(table);
    std::vector<Fpk> prefix;
    for (std::size_t round = 0;
         round < std::bit_width(size) - 1U; ++round) {
        const laminate::gkr::laned_detail::
            LanedAffineRoundEvaluationPoints points;
        const auto evaluated = state.round_evaluations(points);
        std::vector<Fpk> at_one_bound = prefix;
        at_one_bound.push_back(points.at_one);
        CHECK(evaluated.at_one ==
              evaluate_public_table_prefix(table, at_one_bound));
        std::vector<Fpk> at_two_bound = prefix;
        at_two_bound.push_back(points.at_two);
        CHECK(evaluated.at_two ==
              evaluate_public_table_prefix(table, at_two_bound));
        const Fpk challenge = Fpk::from_base(Fp(11U + round));
        prefix.push_back(challenge);
        state.bind(challenge);
    }
    CHECK(state.entries_processed() == 3U * (size - 1U));
    return state.entries_processed();
}

} // namespace

int main() {
    laminate::test::Runner runner("Laned file-backed affine reduction");

    runner.run(
        "file-backed messages equal resident messages",
        [] {
            const ComparisonResult narrow =
                compare_reference_and_file_backed(2);
            const ComparisonResult padded =
                compare_reference_and_file_backed(3);
            const ComparisonResult doubled =
                compare_reference_and_file_backed(4);
            const ComparisonResult wide =
                compare_reference_and_file_backed(8);
            CHECK(doubled.source_wire_count ==
                  2U * narrow.source_wire_count);
            CHECK(wide.source_wire_count ==
                  2U * doubled.source_wire_count);
            CHECK(narrow.statistics.source_scans == 1U);
            CHECK(doubled.statistics.source_scans == 1U);
            CHECK(wide.statistics.source_scans == 1U);
            CHECK(doubled.statistics.source_ciphertexts_read ==
                  doubled.source_wire_count *
                      doubled.statistics.source_scans);
            CHECK(wide.statistics.source_ciphertexts_read ==
                  wide.source_wire_count * wide.statistics.source_scans);
            CHECK(padded.source_wire_count == 3);
            CHECK(narrow.statistics.peak_live_source_ciphertexts ==
                  wide.statistics.peak_live_source_ciphertexts);
            CHECK(narrow.statistics.peak_retained_extension_checkpoints ==
                  wide.statistics.peak_retained_extension_checkpoints);
        });
    runner.run("rolling public gate contraction is linear", [] {
        const std::uint64_t small = exercise_gate_table_fold(64);
        const std::uint64_t large = exercise_gate_table_fold(128);
        CHECK(large <= 2U * small + 3U);
    });
    runner.run("large packed domains retain the streaming fallback", [] {
        const ComparisonResult streaming =
            compare_reference_and_file_backed(128, 16, 16);
        CHECK(streaming.chunks_per_ciphertext == 1);
        CHECK(streaming.statistics.source_scans == 8);
        CHECK(streaming.statistics.source_scalar_promotions > 0);
        CHECK(streaming.statistics.accumulator_presence_observations ==
              streaming.statistics.source_scalar_promotions);
        CHECK(streaming.statistics.materialized_packed_source_values == 0);
    });
    runner.run("B=1 materializes and reuses the S/N packed source", [] {
        const ComparisonResult packed =
            compare_reference_and_file_backed(256, 1, 128);
        CHECK(packed.chunks_per_ciphertext == 128);
        CHECK(packed.statistics.source_scans == 1);
        CHECK(packed.statistics.source_ciphertexts_read == 256);
        CHECK(packed.statistics.materialized_packed_source_values == 2);
        CHECK(packed.statistics.materialized_source_plain_multiplications ==
              256);
        CHECK(packed.statistics.materialized_source_rotations == 254);
        CHECK(packed.statistics.materialized_packed_mask_applications > 0);
        CHECK(packed.statistics.chunk_batches == 0);

        // The streaming fallback remains explicitly bounded for packed
        // domains above the materialization limit.
        constexpr std::size_t target_chunks = 1U << 14U;
        const std::uint64_t bounded_ciphertexts =
            laminate::gkr::laned_detail::affine_detail::
                laned_affine_peak_resident_ciphertexts(target_chunks);
        const std::uint64_t unbounded_ciphertexts =
            2U * target_chunks * laminate::kExtensionDegree;
        CHECK(bounded_ciphertexts == 1058);
        CHECK(bounded_ciphertexts * 200U < unbounded_ciphertexts);
    });

    return runner.summary();
}
