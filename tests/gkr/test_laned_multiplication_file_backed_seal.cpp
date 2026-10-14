/// @file test_laned_multiplication_file_backed_seal.cpp
/// @brief Real-BGV verification of file-backed Laned multiplication.

#include "test_helpers.hpp"

#include "laminate/fhe/seal_backend.hpp"
#include "laminate/gkr/laned.hpp"
#include "laminate/gkr/detail/laned/multiplication/reference/prover.hpp"
#include "laminate/gkr/detail/laned/multiplication/prover.hpp"
#include "laminate/gkr/detail/laned/multiplication/verifier.hpp"
#include "laminate/gkr/detail/shared/dense_multiplication/source/scan.hpp"
#include "laminate/gkr/detail/shared/packed/message_reader.hpp"
#include "laminate/payload/compiler.hpp"
#include "laminate/payload/laned_fhe_evaluator.hpp"
#include "laminate/payload/storage/file_trace_store.hpp"
#include "laminate/payload/input_encryption.hpp"
#include "laminate/payload/trace.hpp"
#include "laminate/payload/trace/trace_crypto.hpp"
#include "laminate/setup.hpp"

#include <bit>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace {

using namespace laminate;
using namespace laminate::fhe;
using namespace laminate::gkr;
using namespace laminate::payload;

constexpr std::size_t kSlots = 1024;
constexpr std::size_t kLanes = kSlots / 4U;
constexpr std::size_t kProducts = 17;

class TemporaryDirectory {
  public:
    TemporaryDirectory() {
        const auto stamp = std::chrono::steady_clock::now()
                               .time_since_epoch()
                               .count();
        for (std::size_t attempt = 0; attempt < 100; ++attempt) {
            path_ = std::filesystem::temp_directory_path() /
                    ("laminate-multiplication-stream-seal-" +
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
    result.reserve(kLanes);
    for (std::size_t lane = 0; lane < kLanes; ++lane) {
        result.emplace_back(seed + 3U * lane + lane * lane);
    }
    return result;
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

Digest setup_id() {
    constexpr std::string_view label =
        "Laminate file-backed multiplication SEAL setup";
    return sha256(std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t *>(label.data()),
        label.size()));
}

void test_cache_eviction_preserves_complete_scan() {
    // Bit-reversed physical traversal visits all 128 operands before their
    // second use, exceeding the 64-value cache while keeping the test small.
    constexpr std::size_t kDistinctOperands = 128;
    constexpr std::size_t kPairs = 2U * kDistinctOperands;
    PayloadBuilder builder(PayloadShape::laned(kSlots, kSlots),
                           kDistinctOperands);
    std::vector<WireId> outputs;
    outputs.reserve(kPairs);
    for (std::size_t pair = 0; pair < kPairs; ++pair) {
        const auto input =
            gkr::detail::bit_reverse_index(pair, 8) % kDistinctOperands;
        outputs.push_back(builder.mul(input, input));
    }
    builder.set_outputs(std::move(outputs));
    const auto payload = builder.finish();
    const auto circuit = compile(payload);
    const auto layer = multiplication_layer(circuit);
    const auto canonical = canonical_trace_layout(circuit);
    std::vector<SlotVector> inputs;
    inputs.reserve(kDistinctOperands);
    for (std::size_t input = 0; input < kDistinctOperands; ++input) {
        SlotVector slots;
        slots.reserve(kSlots);
        for (std::size_t slot = 0; slot < kSlots; ++slot) {
            slots.emplace_back(3U + 26U * input + 7U * slot);
        }
        inputs.push_back(std::move(slots));
    }
    const auto plain = synthesize_trace(payload, circuit, inputs);
    auto contexts = SealBackend::create(SealParameters{
        .poly_modulus_degree = kSlots,
        .fresh_rns_limbs = 4,
        .bits_per_data_prime = 50,
        .special_prime_bits = 50,
        .security_level = seal::sec_level_type::none,
    });
    const auto encrypted = encrypt_compact_synthetic_trace<SealBackend>(
        contexts.eval, contexts.client, payload, circuit, plain,
        TraceEncryptionPlan::uniform(circuit, 2));
    TemporaryDirectory root;
    const FileTraceStoreOptions options{
        .max_total_bytes = std::uint64_t{1} << 29U,
        .min_free_bytes = 1,
    };
    const auto trace_directory = root.make_child("trace");
    (void)write_file_encrypted_trace(
        contexts.eval, trace_directory, options, circuit, encrypted);
    const auto trace = FileEncryptedTraceStore<SealBackend>::open(
        contexts.eval, trace_directory, payload, circuit,
        encrypted.provenance, encrypted.trace_id);
    const auto plan = gkr::detail::make_dense_multiplication_source_plan(
        circuit, trace.descriptor(), trace.layered_circuit_id(),
        trace.backend_context_id(), layer,
        canonical.wire_support.at(layer + 1U),
        canonical.storage.at(layer + 1U), setup_id(), 3);
    const auto built =
        gkr::detail::build_file_dense_multiplication_source<SealBackend>(
            contexts.eval, trace, plan, root.make_child("artifact"), options);
    CHECK(built.source.descriptor().live_pair_count == kPairs);
    CHECK(built.source.report().stored_values == kDistinctOperands);
    CHECK(kDistinctOperands >
          gkr::detail::kDenseMultiplicationReaderCacheValues);

    auto reader = built.source.reader();
    gkr::detail::FileBackedMultiplicationStatistics statistics;
    for (std::size_t pass = 0; pass < 2; ++pass) {
        const auto previous = reader.statistics();
        const auto before =
            gkr::detail::multiplication_detail::begin_scan(reader, statistics);
        while (auto pair = reader.next()) {
            CHECK(SealBackend::decrypt(contexts.client,
                                       pair->left().ciphertext()) ==
                  plain.layers[layer + 1U].at(pair->packed_index));
            CHECK(SealBackend::decrypt(contexts.client,
                                       pair->right().ciphertext()) ==
                  plain.layers[layer + 1U].at(
                      reader.domain_size() + pair->packed_index));
        }
        gkr::detail::multiplication_detail::finish_scan(
            reader, before, statistics);
        CHECK(reader.statistics().pairs_read - previous.pairs_read == kPairs);
        CHECK(reader.statistics().distinct_values_read -
                  previous.distinct_values_read == kDistinctOperands);
        CHECK(reader.statistics().values_read - previous.values_read >
              kDistinctOperands);
        CHECK(reader.statistics().peak_live_decoded_values <=
              gkr::detail::kDenseMultiplicationReaderCacheValues + 2U);
    }
    CHECK(statistics.artifact_scans == 2);
    CHECK(statistics.artifact_rewinds == 1);
    CHECK(statistics.artifact_pairs_read == 2U * kPairs);
    CHECK(statistics.artifact_values_read == reader.statistics().values_read);
    CHECK(statistics.artifact_logical_record_bytes_read ==
          reader.statistics().logical_record_bytes_read);
    CHECK(statistics.artifact_framed_record_bytes_read ==
          statistics.artifact_logical_record_bytes_read +
              sizeof(std::uint64_t) * statistics.artifact_values_read);
}

} // namespace

int main() {
    test::Runner runner("Laned file-backed multiplication with SEAL");
    runner.run("evicted encrypted aliases preserve complete scan accounting",
               test_cache_eviction_preserves_complete_scan);
    runner.run("virtual high suffix is zero in resident and file-backed proofs",
               [] {
        PayloadBuilder builder(PayloadShape::laned(kLanes, kSlots),
                               2U * kProducts);
        std::vector<WireId> outputs;
        outputs.reserve(kProducts);
        for (std::size_t product = 0; product < kProducts; ++product) {
            // The first packed group squares its inputs. Its left and right
            // packed operands therefore share one immutable artifact value.
            const WireId right = product < 4U
                                     ? 2U * product
                                     : 2U * product + 1U;
            outputs.push_back(builder.mul(2U * product, right));
        }
        builder.set_outputs(std::move(outputs));
        const PayloadCircuit payload = builder.finish();
        const LayeredCircuit circuit = compile(payload);
        const std::size_t layer = multiplication_layer(circuit);
        std::vector<SlotVector> plain_inputs;
        plain_inputs.reserve(2U * kProducts);
        for (std::size_t input = 0; input < 2U * kProducts; ++input) {
            plain_inputs.push_back(values(5U + 36U * input));
        }
        const PlainTrace plain =
            synthesize_trace(payload, circuit, plain_inputs);

        auto contexts = SealBackend::create(SealParameters{
            .poly_modulus_degree = kSlots,
            .fresh_rns_limbs = 11,
            .bits_per_data_prime = 50,
            .special_prime_bits = 50,
            .security_level = seal::sec_level_type::none,
        });
        const PublicSetup public_setup = make_direct_setup(payload, circuit);
        const auto evaluation = make_packed_evaluation_setup<SealBackend>(
            public_setup, contexts.eval);
        CHECK(SealBackend::plaintext_preprocessing_stats(
                  evaluation.context)
                  .logical_plaintexts == kFixedMessageCellCount);
        const auto encrypted_inputs =
            encrypt_laned_payload_inputs<SealBackend>(
                contexts.client, payload, plain_inputs);
        const auto resident = evaluate_laned_fhe_trace<SealBackend>(
            evaluation.context, payload, circuit, encrypted_inputs,
            FheEvaluationPlan::without_payload_switches(circuit, 9));

        TemporaryDirectory root;
        const FileTraceStoreOptions options{
            .max_total_bytes = std::uint64_t{1} << 31U,
            .min_free_bytes = 1,
        };
        const std::filesystem::path trace_directory =
            root.make_child("trace");
        (void)write_file_encrypted_trace(
            evaluation.context, trace_directory, options, circuit,
            resident);
        const auto trace = FileEncryptedTraceStore<SealBackend>::open(
            evaluation.context, trace_directory, payload, circuit,
            resident.provenance, resident.trace_id);
        const std::filesystem::path artifact_directory =
            root.make_child("artifact");
        const std::size_t source_rns_limbs =
            SealBackend::rns_limb_count(
                evaluation.context,
                resident.layers[layer + 1U].wires.front().ciphertext());
        const CanonicalTraceLayout canonical =
            canonical_trace_layout(circuit);
        const auto source_plan =
            gkr::detail::make_dense_multiplication_source_plan(
                circuit, trace.descriptor(), trace.layered_circuit_id(),
                trace.backend_context_id(), layer,
                canonical.wire_support.at(layer + 1U),
                canonical.storage.at(layer + 1U), setup_id(),
                source_rns_limbs);
        const auto built =
            gkr::detail::build_file_dense_multiplication_source<SealBackend>(
                evaluation.context, trace, source_plan, artifact_directory,
                options);
        const auto &artifact = built.source;
        CHECK(artifact.descriptor().pair_count == 8);
        CHECK(artifact.descriptor().live_pair_count == 5);
        CHECK(source_plan.aliases.has_aliases());
        auto alias_reader = artifact.reader();
        bool observed_shared_pair = false;
        while (auto pair = alias_reader.next()) {
            const std::size_t packed = pair->packed_index;
            if (source_plan.aliases.left_operand[packed] ==
                source_plan.aliases.right_operand[packed]) {
                CHECK(&pair->left() == &pair->right());
                observed_shared_pair = true;
            }
        }
        CHECK(observed_shared_pair);

        std::vector<Fpk> point(laned_layer_variables(circuit, layer),
                               Fpk::from_base(Fp(29)));
        point[0] = Fpk::zero();
        point[1] = Fpk::zero();
        point[2] = Fpk::one();
        const SingleClaim claim = make_packed_laned_claim(
            plain.layers[layer], laned_layout(circuit, layer), point);
        constexpr std::string_view kDomain =
            "test/laned/multiplication-file-backed-seal/v1";

        Transcript resident_transcript(kDomain);
        const auto resident_proof =
            laned_detail::prove_multiplication_resident_reference<SealBackend>(
                evaluation.context, circuit, resident, layer, claim,
                resident_transcript, source_rns_limbs);
        gkr::detail::FileBackedMultiplicationStatistics statistics;
        Transcript file_backed_transcript(kDomain);
        const auto file_backed_proof =
            laned_detail::prove_multiplication<SealBackend>(
                evaluation.context, circuit, artifact, layer, claim,
                file_backed_transcript, 0, {}, &statistics);

        CHECK(file_backed_proof.proof.rounds.size() ==
              resident_proof.proof.rounds.size());
        // Before either proof samples its first challenge, the transmitted
        // X=1/at-two values must agree algebraically. Ciphertext bytes can
        // differ after persistence, which then gives each valid proof its
        // own Fiat--Shamir challenges.
        const auto file_backed_first = unpack_extension_scalars<SealBackend>(
            contexts.client,
            file_backed_proof.proof.rounds.front().packed_evaluations, 2);
        const auto resident_first = unpack_extension_scalars<SealBackend>(
            contexts.client,
            resident_proof.proof.rounds.front().packed_evaluations, 2);
        CHECK(file_backed_first == resident_first);
        CHECK(file_backed_first.front().is_zero());

        Transcript verifier_transcript(kDomain);
        ::laminate::gkr::detail::FixedMessageReader<SealBackend>
            proof_reader(
            contexts.client);
        const auto verified =
            laned_detail::verify_multiplication_reduction<SealBackend>(
                proof_reader, circuit, layer, claim,
                file_backed_proof.proof, verifier_transcript);
        CHECK(verified.has_value());
        const auto source_layout = laned_layout(circuit, layer + 1U);
        CHECK(verified->point == file_backed_proof.next_claim.point);
        CHECK(*verified == make_packed_laned_claim(
            plain.layers[layer + 1U], source_layout, verified->point));

        Transcript resident_verifier_transcript(kDomain);
        ::laminate::gkr::detail::FixedMessageReader<SealBackend>
            resident_reader(
            contexts.client);
        const auto resident_verified =
            laned_detail::verify_multiplication_reduction<SealBackend>(
                resident_reader, circuit, layer, claim,
                resident_proof.proof, resident_verifier_transcript);
        CHECK(resident_verified.has_value());
        CHECK(resident_verified->point == resident_proof.next_claim.point);
        CHECK(*resident_verified == make_packed_laned_claim(
            plain.layers[layer + 1U], source_layout, resident_verified->point));

        const std::size_t ciphertext_index_variables =
            std::bit_width(
                laned_layout(circuit, layer).padded_ciphertext_count) -
            1U;
        CHECK(statistics.artifact_scans ==
              ciphertext_index_variables + 1U);
        CHECK(statistics.artifact_rewinds ==
              ciphertext_index_variables);
        CHECK(statistics.peak_live_decoded_source_values == 4);
        CHECK(statistics.peak_retained_extension_accumulators == 4);
        CHECK(statistics.peak_retained_slot_checkpoints == 2);
    });
    return runner.summary();
}
