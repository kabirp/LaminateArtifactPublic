/// @file test_base_affine_file_backed_seal.cpp
/// @brief Real-BGV verification of compact LaminateBase affine reduction.

#include "test_helpers.hpp"

#include "laminate/fhe/seal_backend.hpp"
#include "laminate/gates/gate_mle.hpp"
#include "laminate/gkr/detail/base/affine/verifier.hpp"
#include "laminate/gkr/detail/base/affine/prover.hpp"
#include "laminate/gkr/detail/base/verification/proof_reader.hpp"
#include "laminate/payload/compiler.hpp"
#include "laminate/payload/storage/file_trace_store.hpp"
#include "laminate/payload/input_encryption.hpp"
#include "laminate/payload/trace.hpp"
#include "laminate/payload/wide_fhe_evaluator.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <system_error>
#include <vector>

namespace {

using namespace laminate;
using namespace laminate::fhe;
using namespace laminate::gkr;
using namespace laminate::payload;

constexpr std::size_t kSlots = 1024;

class TemporaryDirectory {
  public:
    TemporaryDirectory() {
        const auto stamp = std::chrono::steady_clock::now()
                               .time_since_epoch()
                               .count();
        for (std::size_t attempt = 0; attempt < 100; ++attempt) {
            path_ = std::filesystem::temp_directory_path() /
                    ("laminate-base-affine-file-backed-seal-" +
                     std::to_string(stamp) + "-" +
                     std::to_string(attempt));
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

SlotVector values(std::uint64_t seed) {
    SlotVector result;
    result.reserve(kSlots);
    for (std::size_t slot = 0; slot < kSlots; ++slot) {
        result.emplace_back(seed + 3 * slot + slot * slot);
    }
    return result;
}

} // namespace

int main() {
    test::Runner runner("Base affine reduction with SEAL");

    runner.run("compact Wide source verifies over real BGV", [] {
        PayloadBuilder builder(PayloadShape::wide(kSlots), 3);
        const auto mask = builder.add_plaintext(values(7));
        const auto biased = builder.add_plain(builder.add(0, 1), mask);
        builder.set_outputs({builder.rotate(builder.mul_plain(biased, mask), 5)});
        const PayloadCircuit payload = builder.finish();
        const LayeredCircuit circuit = compile(payload);
        CHECK(circuit.layers.size() == 2);
        const std::vector<SlotVector> inputs{
            values(5), values(41), values(103)};
        const PlainTrace plain = synthesize_trace(
            payload, circuit, inputs);
        auto contexts = SealBackend::create(SealParameters{
            .poly_modulus_degree = kSlots,
            .fresh_rns_limbs = 6,
            .bits_per_data_prime = 40,
            .special_prime_bits = 40,
            .security_level = seal::sec_level_type::none,
        });
        const auto encrypted_inputs =
            encrypt_wide_payload_inputs<SealBackend>(
                contexts.client, payload, inputs);

        TemporaryDirectory directory;
        const FileTraceStoreWriteResult written =
            evaluate_wide_fhe_trace_into<SealBackend>(
                contexts.eval, payload, circuit, encrypted_inputs,
                FheEvaluationPlan::without_payload_switches(circuit, 4),
                FileEncryptedTraceSink<SealBackend>(
                    contexts.eval, directory.path(),
                    FileTraceStoreOptions{
                        .max_total_bytes = std::uint64_t{1} << 30U,
                        .min_free_bytes = 1,
                    }));
        const auto store = FileEncryptedTraceStore<SealBackend>::open(
            contexts.eval, directory.path(), payload, circuit,
            TraceProvenance::FheEvaluated,
            written.descriptor.trace_id);
        const LayerWireSupport &support = store.layer_support(1);
        CHECK(support.padded_wire_count == 4);
        CHECK(support.live_wire_count == 3);

        constexpr std::size_t kLayer = 0;
        Transcript output_coin("test/base/affine-file-backed-seal/output/v1");
        const SingleClaim claim = make_layer_claim(
            plain.layers[kLayer], output_coin.challenge_vector(
                base_detail::layer_vars(circuit, kLayer)));
        const LayerClaim layer_claim = claim;
        const gates::DirectGateMle provider(circuit);

        base_detail::BaseAffineStatistics statistics;
        Transcript prover_transcript(
            "test/base/affine-file-backed-seal/v1");
        SealBackend::reset_counts(contexts.eval);
        SealBackend::set_counting(contexts.eval, true);
        const auto proved =
            base_detail::prove_affine_reduction<SealBackend>(
                contexts.eval, circuit, store,
                store.layer_support(kLayer + 1U), kLayer, layer_claim,
                provider, prover_transcript, nullptr, &statistics);
        SealBackend::set_counting(contexts.eval, false);
        const SealBackend::OperationCounts operations =
            SealBackend::counts(contexts.eval);

        base_detail::ProofReader<SealBackend> reader(contexts.client);
        gates::DirectGateMle verifier_provider(circuit);
        Transcript verifier_transcript(
            "test/base/affine-file-backed-seal/v1");
        const auto verified =
            base_detail::verify_affine_reduction<SealBackend>(
            reader, circuit, kLayer, layer_claim, proved.proof,
            verifier_provider, verifier_transcript);
        CHECK(verified.has_value());
        CHECK(verified->point == proved.next_claim.point);
        CHECK(*verified ==
              make_layer_claim(plain.layers[kLayer + 1], verified->point));

        const std::uint64_t expected_scans =
            static_cast<std::uint64_t>(
                base_detail::ciphertext_index_variables(circuit, 1) + 1);
        CHECK(statistics.source_scans == expected_scans);
        CHECK(statistics.source_rewinds == expected_scans);
        CHECK(statistics.source_ciphertexts_read ==
              expected_scans * support.live_wire_count);
        CHECK(statistics.public_zero_positions ==
              expected_scans * (support.padded_wire_count -
                                support.live_wire_count));
        CHECK(statistics.peak_live_source_ciphertexts == 1);
        CHECK(statistics.peak_retained_extension_accumulators == 2);
        CHECK(statistics.online_slot_vectors_constructed == 0);
        CHECK(statistics.per_record_coefficient_allocations == 0);
        CHECK(statistics.per_record_coefficient_hash_probes == 0);
    });

    return runner.summary();
}
