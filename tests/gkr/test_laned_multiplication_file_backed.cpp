/// @file test_laned_multiplication_file_backed.cpp
/// @brief Exact Mock parity for file-backed Laned multiplication.

#include "test_helpers.hpp"

#include "laminate/bench/schedule_cost.hpp"
#include "laminate/fhe/mock_backend.hpp"
#include "laminate/fhe/storage/value_codec.hpp"
#include "laminate/gkr/laned.hpp"
#include "laminate/gkr/detail/base/multiplication/evaluator.hpp"
#include "laminate/gkr/detail/folded/multiplication/prover.hpp"
#include "laminate/gkr/detail/laned/multiplication/reference/prover.hpp"
#include "laminate/gkr/detail/laned/multiplication/prover.hpp"
#include "laminate/gkr/detail/laned/multiplication/verifier.hpp"
#include "laminate/gkr/detail/shared/packed/message_reader.hpp"
#include "laminate/payload/compiler.hpp"
#include "laminate/payload/storage/file_trace_store.hpp"
#include "laminate/payload/trace/trace_crypto.hpp"

#include <array>
#include <bit>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
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
constexpr std::size_t kProducts = 32;

class TemporaryDirectory {
  public:
    TemporaryDirectory() {
        const auto stamp = std::chrono::steady_clock::now()
                               .time_since_epoch()
                               .count();
        for (std::size_t attempt = 0; attempt < 100; ++attempt) {
            path_ = std::filesystem::temp_directory_path() /
                    ("laminate-multiplication-stream-" +
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

Digest setup_id(std::size_t lanes) {
    const std::string label =
        "Laminate file-backed multiplication setup " +
        std::to_string(lanes);
    return sha256(std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t *>(label.data()),
        label.size()));
}

PayloadCircuit make_payload(std::size_t lanes,
                            std::size_t products = kProducts) {
    PayloadBuilder builder(PayloadShape::laned(lanes, kSlots),
                           2U * products);
    std::vector<WireId> outputs;
    outputs.reserve(products);
    for (std::size_t product = 0; product < products; ++product) {
        outputs.push_back(builder.mul(2U * product,
                                      2U * product + 1U));
    }
    builder.set_outputs(std::move(outputs));
    return builder.finish();
}

SlotVector values(std::size_t lanes, std::size_t input) {
    SlotVector result;
    result.reserve(lanes);
    for (std::size_t lane = 0; lane < lanes; ++lane) {
        result.emplace_back(13U * input + 7U * lane + lane * lane + 3U);
    }
    return result;
}

std::vector<SlotVector> inputs(std::size_t lanes,
                              std::size_t products = kProducts) {
    std::vector<SlotVector> result;
    result.reserve(2U * products);
    for (std::size_t input = 0; input < 2U * products; ++input) {
        result.push_back(values(lanes, input));
    }
    return result;
}

FileTraceStoreOptions store_options() {
    return FileTraceStoreOptions{
        .max_total_bytes = std::uint64_t{1} << 30U,
        .min_free_bytes = 1,
    };
}

std::size_t multiplication_layer(const LayeredCircuit &circuit) {
    for (std::size_t layer = 0; layer + 1U < circuit.layers.size();
         ++layer) {
        if (layer_kind(circuit.layers[layer]) ==
            LayerKind::Multiplication) {
            return layer;
        }
    }
    throw std::logic_error("fixture has no multiplication layer");
}

template <typename TraceSource>
gkr::detail::DenseMultiplicationSourcePlan make_source_plan(
    const LayeredCircuit &circuit, const TraceSource &trace,
    std::size_t layer, const Digest &selected_setup_id,
    std::size_t source_rns_limbs) {
    const CanonicalTraceLayout canonical = canonical_trace_layout(circuit);
    return gkr::detail::make_dense_multiplication_source_plan(
        circuit, trace.descriptor(), trace.layered_circuit_id(),
        trace.backend_context_id(), layer,
        canonical.wire_support.at(layer + 1U),
        canonical.storage.at(layer + 1U), selected_setup_id,
        source_rns_limbs);
}

void compare_one_claim(
    std::size_t lanes, std::size_t layer, bool tau_one,
    const LayeredCircuit &circuit, const PlainTrace &plain,
    const MockBackend::Contexts &contexts,
    const EncryptedTrace<MockBackend> &resident,
    const gkr::detail::FileDenseMultiplicationSource<MockBackend>
        &artifact,
    std::vector<Fpk> point = {}, std::string case_name = {},
    bool expect_first_primary_zero = false,
    bool expect_cache_evictions = false) {
    const auto output_layout = laned_layout(circuit, layer);
    const auto source_layout = laned_layout(circuit, layer + 1U);
    const std::size_t ciphertext_index_variables =
        std::bit_width(output_layout.padded_ciphertext_count) - 1U;
    if (point.empty()) {
        point.resize(laned_layer_variables(circuit, layer));
        for (std::size_t coordinate = 0; coordinate < point.size();
             ++coordinate) {
            point[coordinate] =
                Fpk::from_base(Fp(23U + 2U * coordinate));
        }
        if (tau_one) {
            point.front() = Fpk::one();
        }
    } else if (point.size() != laned_layer_variables(circuit, layer)) {
        throw std::invalid_argument("custom claim point has wrong size");
    }
    const SingleClaim claim = make_packed_laned_claim(
        plain.layers[layer], output_layout, point);
    const std::string domain = case_name.empty()
                                   ? "test/laned/multiplication-file-backed/" +
                                         std::to_string(lanes) +
                                         (tau_one ? "/tau-one"
                                                  : "/ordinary")
                                   : "test/laned/multiplication-file-backed/" +
                                         std::move(case_name);

    std::vector<std::vector<std::uint8_t>> resident_commitment_inputs;
    std::vector<std::vector<std::uint8_t>> file_backed_commitment_inputs;
    const PackedMessageCommitmentFunction<MockBackend>
        resident_commitment =
            [&resident_commitment_inputs](
                const FheValue<MockBackend> &message) {
                resident_commitment_inputs.push_back(
                    encode_canonical_fhe_value<MockBackend>(message));
                return hash_commit_packed_message<MockBackend>(message);
            };
    const PackedMessageCommitmentFunction<MockBackend>
        file_backed_commitment =
            [&file_backed_commitment_inputs](
                const FheValue<MockBackend> &message) {
                file_backed_commitment_inputs.push_back(
                    encode_canonical_fhe_value<MockBackend>(message));
                return hash_commit_packed_message<MockBackend>(message);
            };
    std::vector<RuntimeProgressEvent> resident_progress;
    std::vector<RuntimeProgressEvent> file_backed_progress;

    Transcript resident_transcript(domain);
    const std::size_t source_rns_limbs =
        MockBackend::rns_limb_count(
            contexts.eval,
            resident.layers[layer + 1U].wires.front().ciphertext());
    const auto resident_proof =
        laned_detail::prove_multiplication_resident_reference<MockBackend>(
            contexts.eval, circuit, resident, layer, claim,
            resident_transcript, source_rns_limbs, 0,
            resident_commitment,
            [&resident_progress](const RuntimeProgressEvent &event) {
                resident_progress.push_back(event);
            });

    gkr::detail::FileBackedMultiplicationStatistics statistics;
    Transcript file_backed_transcript(domain);
    const auto file_backed_proof =
        laned_detail::prove_multiplication<MockBackend>(
            contexts.eval, circuit, artifact, layer, claim,
            file_backed_transcript, 0, file_backed_commitment, &statistics,
            [&file_backed_progress](const RuntimeProgressEvent &event) {
                file_backed_progress.push_back(event);
            });

    CHECK(file_backed_proof.proof.rounds.size() ==
          resident_proof.proof.rounds.size());
    CHECK(resident_commitment_inputs == file_backed_commitment_inputs);
    CHECK(resident_commitment_inputs.size() ==
          resident_proof.proof.rounds.size() + 1U);
    CHECK(resident_progress == file_backed_progress);
    for (std::size_t round = 0;
         round < resident_proof.proof.rounds.size(); ++round) {
        CHECK(resident_commitment_inputs[round] ==
              encode_canonical_fhe_value<MockBackend>(
                  resident_proof.proof.rounds[round]
                      .packed_evaluations));
        CHECK(encode_canonical_fhe_value<MockBackend>(
                  file_backed_proof.proof.rounds[round].packed_evaluations) ==
              encode_canonical_fhe_value<MockBackend>(
                  resident_proof.proof.rounds[round].packed_evaluations));
    }
    CHECK(encode_canonical_fhe_value<MockBackend>(
              file_backed_proof.proof.packed_source_values) ==
          encode_canonical_fhe_value<MockBackend>(
              resident_proof.proof.packed_source_values));
    CHECK(resident_commitment_inputs.back() ==
          encode_canonical_fhe_value<MockBackend>(
              resident_proof.proof.packed_source_values));
    CHECK(file_backed_proof.next_claim ==
          resident_proof.next_claim);
    CHECK(file_backed_transcript.challenge_fpk() ==
          resident_transcript.challenge_fpk());
    if (expect_first_primary_zero) {
        // The first primary evaluation uses X=1 at tau=0. The
        // remaining Boolean coordinates select a suffix whose high branch is
        // virtual padding, so both implementations must transmit zero.
        CHECK(point.front().is_zero());
        const auto resident_first = unpack_extension_scalars<MockBackend>(
            contexts.client,
            resident_proof.proof.rounds.front().packed_evaluations, 2);
        const auto file_backed_first = unpack_extension_scalars<MockBackend>(
            contexts.client,
            file_backed_proof.proof.rounds.front().packed_evaluations, 2);
        CHECK(resident_first.front().is_zero());
        CHECK(file_backed_first.front().is_zero());
    }

    Transcript verifier_transcript(domain);
    ::laminate::gkr::detail::FixedMessageReader<MockBackend> proof_reader(
        contexts.client);
    const auto verified =
        laned_detail::verify_multiplication_reduction<MockBackend>(
            proof_reader, circuit, layer, claim,
            file_backed_proof.proof, verifier_transcript);
    CHECK(verified.has_value());
    CHECK(verified->point == file_backed_proof.next_claim.point);
    CHECK(*verified == make_packed_laned_claim(
        plain.layers[layer + 1U], source_layout, verified->point));

    const std::uint64_t expected_scans =
        static_cast<std::uint64_t>(ciphertext_index_variables + 1U);
    const std::uint64_t live_pair_count =
        static_cast<std::uint64_t>(
            artifact.descriptor().live_pair_count);
    std::uint64_t values_per_scan = artifact.report().stored_values;
    std::uint64_t bytes_per_scan = artifact.report().logical_record_bytes;
    if (expect_cache_evictions) {
        // Physical decoding includes rereads after bounded-cache eviction.
        // Compare the complete prover ledger with a standalone source pass.
        auto reader = artifact.reader();
        while (reader.next()) {
        }
        values_per_scan = reader.statistics().values_read;
        bytes_per_scan = reader.statistics().logical_record_bytes_read;
        CHECK(values_per_scan > artifact.report().stored_values);
        CHECK(bytes_per_scan > artifact.report().logical_record_bytes);
    }
    CHECK(statistics.artifact_scans == expected_scans);
    CHECK(statistics.artifact_rewinds ==
          static_cast<std::uint64_t>(ciphertext_index_variables));
    CHECK(statistics.artifact_pairs_read ==
          expected_scans * live_pair_count);
    CHECK(statistics.artifact_values_read ==
          expected_scans * values_per_scan);
    CHECK(statistics.artifact_logical_record_bytes_read ==
          expected_scans * bytes_per_scan);
    CHECK(statistics.artifact_framed_record_bytes_read ==
          expected_scans *
              (bytes_per_scan + values_per_scan *
                   sizeof(std::uint64_t)));
    CHECK(statistics.artifact_index_bit_flips == 0);
    if (expect_cache_evictions) {
        CHECK(statistics.peak_live_decoded_source_values <=
              gkr::detail::kDenseMultiplicationReaderCacheValues + 2U);
    } else {
        CHECK(statistics.peak_live_decoded_source_values == 4);
    }
    const std::size_t expected_extension_peak =
        ciphertext_index_variables < 3U
            ? 2U
            : (expect_first_primary_zero ? 4U : 6U);
    CHECK(statistics.peak_retained_extension_accumulators ==
          expected_extension_peak);
    CHECK(statistics.peak_retained_slot_checkpoints == 2);
    const std::uint64_t slot_index_variables =
        static_cast<std::uint64_t>(claim.point.size() -
                                   ciphertext_index_variables);
    CHECK(statistics.slot_checkpoint_prefix_pairs_bound ==
          slot_index_variables);
    CHECK(statistics.slot_public_mask_pairs_constructed ==
          slot_index_variables);
}

Fpk slot_inner_product(std::span<const Fpk> values,
                       std::span<const Fpk> weights) {
    if (values.size() != weights.size()) {
        throw std::invalid_argument("test slot inner-product shape mismatch");
    }
    Fpk result = Fpk::zero();
    for (std::size_t slot = 0; slot < values.size(); ++slot) {
        result += values[slot] * weights[slot];
    }
    return result;
}

void check_common_wire_scan_ledger(
    const gkr::detail::FileBackedMultiplicationStatistics &preserved,
    const gkr::detail::FileBackedMultiplicationStatistics &folded) {
    CHECK(preserved.artifact_scans == folded.artifact_scans);
    CHECK(preserved.artifact_rewinds == folded.artifact_rewinds);
    CHECK(preserved.artifact_pairs_read == folded.artifact_pairs_read);
    CHECK(preserved.artifact_values_read == folded.artifact_values_read);
    CHECK(preserved.artifact_logical_record_bytes_read ==
          folded.artifact_logical_record_bytes_read);
    CHECK(preserved.artifact_framed_record_bytes_read ==
          folded.artifact_framed_record_bytes_read);
    CHECK(preserved.artifact_index_bit_flips ==
          folded.artifact_index_bit_flips);
    CHECK(preserved.base_products == folded.base_products);
    CHECK(preserved.extension_products == folded.extension_products);
    CHECK(preserved.suffix_scalar_promotions ==
          folded.suffix_scalar_promotions);
    CHECK(preserved.peak_live_decoded_source_values ==
          folded.peak_live_decoded_source_values);
    CHECK(preserved.peak_retained_extension_accumulators ==
          folded.peak_retained_extension_accumulators);
    CHECK(preserved.prepared_output_slot_basis_applications == 0);
    CHECK(preserved.avoided_online_slot_vector_elements == 0);
    CHECK(folded.prepared_output_slot_basis_applications == 2);
    CHECK(folded.avoided_online_slot_vector_elements == 2U * kSlots);
}

void compare_wire_aggregation_policies(
    std::size_t layer, const LayeredCircuit &circuit,
    const MockBackend::Contexts &contexts,
    const gkr::detail::FileDenseMultiplicationSource<MockBackend>
        &artifact,
    const PlainTrace *eviction_plain_trace = nullptr) {
    const auto output_layout = laned_layout(circuit, layer);
    const std::size_t ciphertext_index_variables =
        std::bit_width(output_layout.padded_ciphertext_count) - 1U;
    std::vector<Fpk> output_point(laned_layer_variables(circuit, layer));
    for (std::size_t coordinate = 0; coordinate < output_point.size();
         ++coordinate) {
        output_point[coordinate] =
            Fpk::from_base(Fp(67U + 2U * coordinate));
    }
    const std::span<const Fpk> output_wire(output_point.data(),
                                           ciphertext_index_variables);
    const std::vector<Fpk> output_slot_point(
        output_point.begin() + static_cast<std::ptrdiff_t>(ciphertext_index_variables),
        output_point.end());
    const std::vector<Fpk> output_slot_weights =
        poly::eq_evaluations(output_slot_point);

    const auto compare_round = [&](std::span<const Fpk> prefix) {
        const std::size_t round = prefix.size();
        const ::laminate::gkr::detail::LayerReductionRoundPoints round_points{
            .endpoint =
                ::laminate::gkr::detail::dense_multiplication_primary_point(
                    output_wire[round]),
        };

        gkr::detail::FileBackedMultiplicationStatistics preserve_statistics;
        gkr::base_detail::BaseMultiplicationRoundEvaluator<
            MockBackend,
            gkr::detail::FileDenseMultiplicationSource<MockBackend>>
            preserve_evaluator(contexts.eval, output_wire, artifact,
                               &preserve_statistics);
        const auto preserved =
            preserve_evaluator.evaluate_ciphertext_index_round(
                prefix, round_points);

        auto folded_reader = artifact.reader();
        gkr::detail::FileBackedMultiplicationStatistics folded_statistics;
        std::optional<
            ::laminate::gkr::detail::MixedPreparedFpkSlotBasis<MockBackend>>
            prepared_output_slots;
        const auto folded =
            ::laminate::gkr::detail::
                evaluate_packed_multiplication_ciphertext_round<MockBackend>(
                contexts.eval, folded_reader, output_wire, ciphertext_index_variables,
                prefix, round_points, output_slot_weights,
                prepared_output_slots, folded_statistics);

        const auto check_evaluation = [&](const auto &preserved_value,
                                          const auto &folded_value,
                                          const Fpk &round_value) {
            const std::vector<Fpk> preserved_slots =
                read_extension_value<MockBackend>(contexts.client,
                                                  preserved_value);
            if (eviction_plain_trace != nullptr) {
                // B=N makes every source wire one ciphertext. Evaluate the
                // restricted left/right MLEs directly from plaintext logical
                // wires, independently of the alias reader and FHE kernels.
                const auto &source =
                    eviction_plain_trace->layers.at(layer + 1U);
                const std::size_t pairs = artifact.descriptor().pair_count;
                CHECK(source.size() == 2U * pairs);
                std::vector<Fpk> bound_point(prefix.begin(), prefix.end());
                bound_point.push_back(round_value);
                const auto bound_weights = poly::eq_evaluations(bound_point);
                const auto suffix_weights = poly::eq_evaluations(
                    std::vector<Fpk>(output_wire.begin() +
                                        static_cast<std::ptrdiff_t>(round + 1U),
                                    output_wire.end()));
                for (std::size_t slot = 0; slot < kSlots; ++slot) {
                    Fpk expected_slot = Fpk::zero();
                    for (std::size_t suffix = 0;
                         suffix < suffix_weights.size(); ++suffix) {
                        Fpk left = Fpk::zero();
                        Fpk right = Fpk::zero();
                        for (std::size_t bound = 0;
                             bound < bound_weights.size(); ++bound) {
                            const std::size_t wire =
                                bound * suffix_weights.size() + suffix;
                            left += bound_weights[bound] *
                                    Fpk::from_base(source[wire][slot]);
                            right += bound_weights[bound] *
                                     Fpk::from_base(source[pairs + wire][slot]);
                        }
                        expected_slot += suffix_weights[suffix] * left * right;
                    }
                    CHECK(preserved_slots[slot] == expected_slot);
                }
            }
            const Fpk expected = slot_inner_product(
                preserved_slots, output_slot_weights);
            const std::vector<Fpk> folded_slots =
                read_extension_value<MockBackend>(contexts.client,
                                                  folded_value);
            for (const Fpk &slot : folded_slots) {
                CHECK(slot == expected);
            }
        };
        check_evaluation(preserved.at_endpoint, folded.at_endpoint,
                         round_points.endpoint);
        check_evaluation(preserved.at_two, folded.at_two, round_points.at_two);
        check_common_wire_scan_ledger(preserve_statistics,
                                      folded_statistics);
        if (eviction_plain_trace != nullptr) {
            CHECK(preserve_statistics.artifact_scans == 1U);
            CHECK(preserve_statistics.artifact_values_read >
                  artifact.report().stored_values);
            CHECK(preserve_statistics.artifact_logical_record_bytes_read >
                  artifact.report().logical_record_bytes);
            CHECK(preserve_statistics.peak_live_decoded_source_values <=
                  gkr::detail::kDenseMultiplicationReaderCacheValues + 2U);
        }
    };

    compare_round({});
    if (ciphertext_index_variables > 1U) {
        const std::array<Fpk, 1> prefix{
            Fpk::from_base(Fp(101))};
        compare_round(prefix);
    }
}

void check_evicted_aliases_preserve_base_and_packed_proofs() {
    constexpr std::size_t input_count = 128;
    constexpr std::size_t products = 256;
    PayloadBuilder builder(PayloadShape::laned(kSlots, kSlots), input_count);
    std::vector<WireId> outputs;
    for (std::size_t pair = 0; pair < products; ++pair) {
        // The scan sees 128 distinct reused operands before repeating them,
        // so the second pass through those aliases exceeds the 64-entry cache.
        const auto input = gkr::detail::bit_reverse_index(pair, 8) % input_count;
        outputs.push_back(builder.mul(input, input));
    }
    builder.set_outputs(std::move(outputs));
    const PayloadCircuit payload = builder.finish();
    const LayeredCircuit circuit = compile(payload);
    const std::size_t layer = multiplication_layer(circuit);
    std::vector<SlotVector> plain_inputs;
    for (std::size_t input = 0; input < input_count; ++input) {
        plain_inputs.push_back(values(kSlots, input));
    }
    const PlainTrace plain = synthesize_trace(payload, circuit, plain_inputs);
    const auto contexts = MockBackend::create(MockParameters{
        .slot_count = kSlots,
        .fresh_rns_limbs = 12,
        .bits_per_limb = 120,
    });
    MockBackend::preprocess_fixed_message_cells(contexts.eval);
    const auto resident = encrypt_compact_synthetic_trace<MockBackend>(
        contexts.eval, contexts.client, payload, circuit, plain,
        TraceEncryptionPlan::uniform(circuit, 8));
    TemporaryDirectory root;
    const auto trace_directory = root.make_child("trace");
    (void)write_file_encrypted_trace(contexts.eval, trace_directory,
                                   store_options(), circuit, resident);
    const auto trace = FileEncryptedTraceStore<MockBackend>::open(
        contexts.eval, trace_directory, payload, circuit,
        resident.provenance, resident.trace_id);
    const auto source_rns_limbs = MockBackend::rns_limb_count(
        contexts.eval, resident.layers[layer + 1U].wires.front().ciphertext());
    const auto source_plan = make_source_plan(
        circuit, trace, layer, setup_id(kSlots), source_rns_limbs);
    CHECK(source_plan.aliases.operands.size() >
          gkr::detail::kDenseMultiplicationReaderCacheValues);
    CHECK(source_plan.aliases.has_aliases());
    const auto built =
        gkr::detail::build_file_dense_multiplication_source<MockBackend>(
            contexts.eval, trace, source_plan, root.make_child("artifact"),
            store_options());
    compare_wire_aggregation_policies(layer, circuit, contexts, built.source,
                                      &plain);
    compare_one_claim(kSlots, layer, false, circuit, plain, contexts,
                      resident, built.source, {}, "evicted-aliases", false,
                      true);
}

void compare_regime(std::size_t lanes) {
    const PayloadCircuit payload = make_payload(lanes);
    const LayeredCircuit circuit = compile(payload);
    const std::size_t layer = multiplication_layer(circuit);
    const std::vector<SlotVector> plain_inputs = inputs(lanes);
    const PlainTrace plain =
        synthesize_trace(payload, circuit, plain_inputs);
    const auto contexts = MockBackend::create(MockParameters{
        .slot_count = kSlots,
        .fresh_rns_limbs = 12,
        .bits_per_limb = 120,
    });
    MockBackend::preprocess_fixed_message_cells(contexts.eval);
    const EncryptedTrace<MockBackend> resident =
        encrypt_compact_synthetic_trace<MockBackend>(
            contexts.eval, contexts.client, payload, circuit, plain,
            TraceEncryptionPlan::uniform(circuit, 8));

    TemporaryDirectory root;
    const std::filesystem::path trace_directory =
        root.make_child("trace");
    (void)write_file_encrypted_trace(
        contexts.eval, trace_directory, store_options(), circuit, resident);
    const auto trace = FileEncryptedTraceStore<MockBackend>::open(
        contexts.eval, trace_directory, payload, circuit,
        resident.provenance, resident.trace_id);
    const std::filesystem::path artifact_directory =
        root.make_child("artifact");
    const std::size_t source_rns_limbs =
        MockBackend::rns_limb_count(
            contexts.eval,
            resident.layers[layer + 1U].wires.front().ciphertext());
    const auto source_plan = make_source_plan(
        circuit, trace, layer, setup_id(lanes), source_rns_limbs);
    const auto built =
        gkr::detail::build_file_dense_multiplication_source<MockBackend>(
            contexts.eval, trace, source_plan, artifact_directory,
            store_options());
    const auto &artifact = built.source;

    compare_wire_aggregation_policies(layer, circuit, contexts, artifact);
    compare_one_claim(lanes, layer, false, circuit, plain, contexts,
                      resident, artifact);
    compare_one_claim(lanes, layer, true, circuit, plain, contexts,
                      resident, artifact);
}

void check_virtual_high_first_round_zero() {
    constexpr std::size_t kLanes = 4;
    constexpr std::size_t kProductsWithPartialHighHalf = 17;
    const PayloadCircuit payload =
        make_payload(kLanes, kProductsWithPartialHighHalf);
    const LayeredCircuit circuit = compile(payload);
    const std::size_t layer = multiplication_layer(circuit);
    const std::vector<SlotVector> plain_inputs =
        inputs(kLanes, kProductsWithPartialHighHalf);
    const PlainTrace plain =
        synthesize_trace(payload, circuit, plain_inputs);
    auto contexts = MockBackend::create(MockParameters{
        .slot_count = kSlots,
        .fresh_rns_limbs = 12,
        .bits_per_limb = 120,
    });
    MockBackend::preprocess_fixed_message_cells(contexts.eval);
    const EncryptedTrace<MockBackend> resident =
        encrypt_compact_synthetic_trace<MockBackend>(
            contexts.eval, contexts.client, payload, circuit, plain,
            TraceEncryptionPlan::uniform(circuit, 8));

    TemporaryDirectory root;
    const std::filesystem::path trace_directory = root.make_child("trace");
    (void)write_file_encrypted_trace(contexts.eval, trace_directory,
                                     store_options(), circuit, resident);
    const auto trace = FileEncryptedTraceStore<MockBackend>::open(
        contexts.eval, trace_directory, payload, circuit,
        resident.provenance, resident.trace_id);
    const std::filesystem::path artifact_directory =
        root.make_child("artifact");
    const std::size_t source_rns_limbs = MockBackend::rns_limb_count(
        contexts.eval,
        resident.layers[layer + 1U].wires.front().ciphertext());
    const auto source_plan = make_source_plan(
        circuit, trace, layer, setup_id(kLanes), source_rns_limbs);
    const auto built =
        gkr::detail::build_file_dense_multiplication_source<MockBackend>(
            contexts.eval, trace, source_plan, artifact_directory,
            store_options());
    const auto &artifact = built.source;
    CHECK(artifact.descriptor().pair_count == 8);
    CHECK(artifact.descriptor().live_pair_count == 5);

    std::vector<Fpk> point(laned_layer_variables(circuit, layer),
                           Fpk::from_base(Fp(37)));
    point[0] = Fpk::zero();
    point[1] = Fpk::zero();
    point[2] = Fpk::one();
    compare_one_claim(
        kLanes, layer, false, circuit, plain, contexts, resident, artifact,
        std::move(point), "virtual-high-first-round", true);
}

void check_padded_cost_regression() {
    constexpr std::size_t kPaddedProducts = 10;
    constexpr std::size_t kLanes = 4;
    const PayloadCircuit payload =
        make_payload(kLanes, kPaddedProducts);
    const LayeredCircuit circuit = compile(payload);
    const std::size_t layer = multiplication_layer(circuit);
    const std::vector<SlotVector> plain_inputs =
        inputs(kLanes, kPaddedProducts);
    const PlainTrace plain =
        synthesize_trace(payload, circuit, plain_inputs);
    auto contexts = MockBackend::create(MockParameters{
        .slot_count = kSlots,
        .fresh_rns_limbs = 12,
        .bits_per_limb = 120,
    });
    MockBackend::preprocess_fixed_message_cells(contexts.eval);
    const EncryptedTrace<MockBackend> compact =
        encrypt_compact_synthetic_trace<MockBackend>(
            contexts.eval, contexts.client, payload, circuit, plain,
            TraceEncryptionPlan::uniform(circuit, 8));

    TemporaryDirectory root;
    const std::filesystem::path trace_directory = root.make_child("trace");
    (void)write_file_encrypted_trace(contexts.eval, trace_directory,
                                     store_options(), circuit, compact);
    const auto trace = FileEncryptedTraceStore<MockBackend>::open(
        contexts.eval, trace_directory, payload, circuit,
        compact.provenance, compact.trace_id);
    const std::filesystem::path artifact_directory =
        root.make_child("artifact");
    const std::size_t source_rns_limbs =
        MockBackend::rns_limb_count(
            contexts.eval,
            compact.layers[layer + 1U].wires.front().ciphertext());
    const auto source_plan = make_source_plan(
        circuit, trace, layer, setup_id(kLanes), source_rns_limbs);
    const auto built =
        gkr::detail::build_file_dense_multiplication_source<MockBackend>(
            contexts.eval, trace, source_plan, artifact_directory,
            store_options());
    const auto &artifact = built.source;

    const bench::ScheduleFormula formula =
        bench::laned_schedule_formula(circuit);
    const bench::ScheduleLayerFormula &layer_formula =
        formula.layers.at(layer);
    CHECK(layer_formula.source_stored_values == 20);
    CHECK(layer_formula.source_virtual_wire_positions == 32);
    CHECK(layer_formula.source_materialized_packed_ciphertexts == 6);
    CHECK(layer_formula.source_virtual_packed_positions == 8);
    CHECK(layer_formula.reduction_domain_variables == 2);
    CHECK(layer_formula.operations.witness_base_plain_multiplications == 20);
    CHECK(layer_formula.operations.witness_base_additions == 14);
    CHECK(layer_formula.operations.base_ciphertext_multiplications == 4);
    CHECK(layer_formula.operations.base_additions == 2);
    CHECK(layer_formula.operations.base_subtractions == 2);
    CHECK(layer_formula.operations.base_negations == 2);

    const auto output_layout = laned_layout(circuit, layer);
    std::vector<Fpk> claim_point(laned_layer_variables(circuit, layer));
    for (std::size_t coordinate = 0; coordinate < claim_point.size();
         ++coordinate) {
        claim_point[coordinate] =
            Fpk::from_base(Fp(31U + 2U * coordinate));
    }
    const SingleClaim claim = make_packed_laned_claim(
        plain.layers[layer], output_layout, claim_point);
    const std::string domain =
        "test/laned/multiplication-file-backed/padded-cost";
    Transcript resident_transcript(domain);
    const auto resident =
        laned_detail::prove_multiplication_resident_reference<MockBackend>(
            contexts.eval, circuit, compact, layer, claim,
            resident_transcript, source_rns_limbs);
    MockBackend::reset_counts(contexts.eval);
    Transcript prover_transcript(domain);
    const auto proved =
        laned_detail::prove_multiplication<MockBackend>(
            contexts.eval, circuit, artifact, layer, claim,
            prover_transcript);
    const OperationCounts operations = MockBackend::counts(contexts.eval);
    CHECK(proved.proof.rounds.size() == resident.proof.rounds.size());
    for (std::size_t round = 0; round < proved.proof.rounds.size();
         ++round) {
        CHECK(encode_canonical_fhe_value<MockBackend>(
                  proved.proof.rounds[round].packed_evaluations) ==
              encode_canonical_fhe_value<MockBackend>(
                  resident.proof.rounds[round].packed_evaluations));
    }
    CHECK(encode_canonical_fhe_value<MockBackend>(
              proved.proof.packed_source_values) ==
          encode_canonical_fhe_value<MockBackend>(
              resident.proof.packed_source_values));
    CHECK(proved.next_claim == resident.next_claim);
    CHECK(prover_transcript.challenge_fpk() ==
          resident_transcript.challenge_fpk());
    const bench::ConcretePrimitiveUpperBound bound =
        bench::concrete_primitive_upper_bound(layer_formula.operations,
                                              kSlots);
    CHECK(operations.mul_plain_scalar + operations.mul_plain_vector <=
          bound.plain_multiplications);
    CHECK(operations.mul_no_relin <=
          bound.ciphertext_multiplications_no_relinearization);
    CHECK(operations.relinearize <= bound.relinearizations);
    CHECK(operations.negate <= bound.negations);
    CHECK(operations.add <= bound.additions);

    Transcript verifier_transcript(domain);
    ::laminate::gkr::detail::FixedMessageReader<MockBackend> proof_reader(
        contexts.client);
    const auto verified =
        laned_detail::verify_multiplication_reduction<MockBackend>(
            proof_reader, circuit, layer, claim, proved.proof,
            verifier_transcript);
    CHECK(verified.has_value());
}

void check_uniform_prefix_scalars_do_not_encode_slot_vectors() {
    auto contexts = MockBackend::create(MockParameters{.slot_count = kSlots});
    const auto ciphertext = MockBackend::encrypt(
        contexts.client, SlotVector(kSlots, Fp(9)));
    Fpk::Coefficients coefficients{};
    for (std::size_t index = 0; index < coefficients.size(); ++index) {
        coefficients[index] = Fp(19U + index);
    }
    gkr::detail::dense_multiplication_accumulation_detail::
        WeightedBaseAccumulator<MockBackend> accumulator;
    MockBackend::reset_counts(contexts.eval);
    accumulator.add(contexts.eval, ciphertext, Fpk(coefficients));
    (void)std::move(accumulator).finish(contexts.eval);
    const OperationCounts counts = MockBackend::counts(contexts.eval);
    CHECK(counts.mul_plain_scalar_api_calls == kExtensionDegree);
    CHECK(counts.mul_plain_vector_api_calls == 0);
    CHECK(counts.mul_plain_vector_api_elements == 0);
}

} // namespace

int main() {
    laminate::test::Runner runner("Laned file-backed multiplication");
    runner.run("B=1 proof, transcript, claim, and I/O parity", [] {
        compare_regime(1);
    });
    runner.run("1<B<N proof, transcript, claim, and I/O parity", [] {
        compare_regime(4);
    });
    runner.run("B=N proof, transcript, claim, and I/O parity", [] {
        compare_regime(16);
    });
    runner.run("evicted aliases preserve Base and packed multiplication", [] {
        check_evicted_aliases_preserve_base_and_packed_proofs();
    });
    runner.run("padded packed domain prices only live pairs", [] {
        check_padded_cost_regression();
    });
    runner.run("virtual high suffix evaluates to zero", [] {
        check_virtual_high_first_round_zero();
    });
    runner.run("file-backed prefix weights use scalar plaintexts", [] {
        check_uniform_prefix_scalars_do_not_encode_slot_vectors();
    });
    return runner.summary();
}
