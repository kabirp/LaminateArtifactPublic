/// @file test_laned_affine_file_backed_seal.cpp
/// @brief Real-BGV verification of a file-backed Laned affine reduction.

#include "test_helpers.hpp"

#include "laminate/fhe/seal_backend.hpp"
#include "laminate/gates/gate_mle.hpp"
#include "laminate/gkr/detail/laned/affine/prover.hpp"
#include "laminate/gkr/detail/laned/affine/verifier.hpp"
#include "laminate/gkr/detail/shared/packed/message_reader.hpp"
#include "laminate/payload/compiler.hpp"
#include "laminate/payload/laned_fhe_evaluator.hpp"
#include "laminate/payload/storage/file_trace_store.hpp"
#include "laminate/payload/input_encryption.hpp"
#include "laminate/payload/trace.hpp"
#include "laminate/setup.hpp"

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
                    ("laminate-affine-file-backed-seal-" +
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

SlotVector lanes(std::uint64_t seed, std::size_t lane_count) {
    SlotVector result;
    result.reserve(lane_count);
    for (std::size_t lane = 0; lane < lane_count; ++lane) {
        result.emplace_back(seed + 3 * lane + lane * lane);
    }
    return result;
}

} // namespace

int main() {
    test::Runner runner("Laned file-backed affine reduction with SEAL");

    runner.run("B=1 materialized affine proof verifies over real BGV", [] {
        constexpr std::size_t kLanes = 1;
        PayloadBuilder builder(PayloadShape::laned(kLanes, kSlots), 2);
        builder.set_outputs({builder.add(0, 1)});
        const PayloadCircuit payload = builder.finish();
        const LayeredCircuit circuit = compile(payload);
        CHECK(circuit.layers.size() == 2);

        const std::vector<SlotVector> inputs{
            lanes(5, kLanes), lanes(41, kLanes)};
        const PlainTrace plain = synthesize_trace(payload, circuit, inputs);
        auto contexts = SealBackend::create(SealParameters{
            .poly_modulus_degree = kSlots,
            .fresh_rns_limbs = 8,
            .bits_per_data_prime = 40,
            .special_prime_bits = 40,
            .security_level = seal::sec_level_type::none,
        });
        const PublicSetup public_setup = make_direct_setup(payload, circuit);
        const auto evaluation = make_packed_evaluation_setup<SealBackend>(
            public_setup, contexts.eval);
        const auto encrypted_inputs =
            encrypt_laned_payload_inputs<SealBackend>(
                contexts.client, payload, inputs);

        TemporaryDirectory directory;
        const FheEvaluationPlan plan =
            FheEvaluationPlan::without_payload_switches(circuit, 5);
        const FileTraceStoreWriteResult write_result =
            evaluate_laned_fhe_trace_into<SealBackend>(
                evaluation.context, payload, circuit, encrypted_inputs, plan,
                FileEncryptedTraceSink<SealBackend>(
                    evaluation.context, directory.path(),
                    FileTraceStoreOptions{
                        .max_total_bytes = std::uint64_t{1} << 30U,
                        .min_free_bytes = 1,
                    }));
        const auto store = FileEncryptedTraceStore<SealBackend>::open(
            evaluation.context, directory.path(), payload, circuit,
            TraceProvenance::FheEvaluated,
            write_result.descriptor.trace_id);

        constexpr std::size_t kLayer = 0;
        const std::vector<Fpk> output_point(
            laned_layer_variables(circuit, kLayer),
            Fpk::from_base(Fp(23)));
        const SingleClaim claim = make_packed_laned_claim(
            plain.layers[kLayer], laned_layout(circuit, kLayer),
            output_point);

        Transcript prover_transcript(
            "test/laned/affine-file-backed-seal/v1");
        laned_detail::LanedAffineStatistics statistics;
        const std::size_t source_proof_ingress_rns_limbs =
            plan.proof_ingress_mult_depth_by_layer.at(kLayer + 1U) + 1U;
        const auto proved = laned_detail::prove_affine<SealBackend>(
            evaluation.context, circuit, store,
            store.layer_support(kLayer + 1U), kLayer, claim,
            prover_transcript, source_proof_ingress_rns_limbs, 0, nullptr,
            {}, &statistics);

        gates::DirectGateMle gate_mles(circuit);
        Transcript verifier_transcript(
            "test/laned/affine-file-backed-seal/v1");
        ::laminate::gkr::detail::FixedMessageReader<SealBackend>
            proof_reader(
            contexts.client);
        const auto verified =
            laned_detail::verify_affine_reduction<SealBackend>(
            proof_reader, circuit, kLayer, claim, proved.proof,
            gate_mles, verifier_transcript);
        CHECK(verified.has_value());
        CHECK(verified->point == proved.next_claim.point);
        CHECK(*verified == make_packed_laned_claim(
                               plain.layers[kLayer + 1],
                               laned_layout(circuit, kLayer + 1),
                               verified->point));
        CHECK(statistics.source_rewinds == 1);
        CHECK(statistics.materialized_packed_source_values == 1);
        CHECK(statistics.materialized_source_plain_multiplications == 2);
        CHECK(statistics.materialized_source_rotations == 1);
        CHECK(statistics.materialized_source_additions == 1);
        CHECK(statistics.materialized_packed_mask_applications > 0);
        CHECK(statistics.peak_live_source_ciphertexts == 1);
        CHECK(statistics.peak_retained_extension_checkpoints == 1);
    });

    return runner.summary();
}
