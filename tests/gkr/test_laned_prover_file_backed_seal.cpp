/// @file test_laned_prover_file_backed_seal.cpp
/// @brief Real-BGV verification of the file-backed Laned GKR prover.

#include "test_helpers.hpp"

#include "laminate/bench/packed_process_profile.hpp"
#include "laminate/fhe/seal_backend.hpp"
#include "laminate/gkr/detail/laned/prover.hpp"
#include "laminate/gkr/detail/laned/reference/prover.hpp"
#include "laminate/gkr/detail/laned/verifier.hpp"
#include "laminate/payload/compiler.hpp"
#include "laminate/payload/input_encryption.hpp"
#include "laminate/payload/laned_fhe_evaluator.hpp"
#include "laminate/payload/storage/file_trace_store.hpp"
#include "laminate/payload/trace/trace_crypto.hpp"
#include "laminate/protocol/detail/packing/messages.hpp"
#include "laminate/protocol/packed/setup/proof_ingress.hpp"
#include "laminate/setup.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <limits>
#include <numeric>
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

class TemporaryDirectory {
  public:
    TemporaryDirectory() {
        const auto stamp = std::chrono::steady_clock::now()
                               .time_since_epoch()
                               .count();
        for (std::size_t attempt = 0; attempt < 100; ++attempt) {
            path_ = std::filesystem::temp_directory_path() /
                    ("laminate-laned-prover-stream-seal-" +
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
    for (std::size_t lane = 0; lane < kSlots; ++lane) {
        result.emplace_back(seed + 7U * lane + lane * lane);
    }
    return result;
}

// The target-ring payload test omits rotation keys: generating all of them
// at fourteen data primes exceeds the bounded test's memory budget. Full GKR
// runs at N=B=1024 with the same chain widths and selected ingress floors.
void check_reduced_full_width_candidate(std::size_t slots, bool prove_gkr) {
    const auto profile = bench::packed_process_profile(
        bench::PackedProcessVariant::Laned,
        bench::PackedProcessTier::TargetBalanced,
        kDefaultPolyModulusDegree);
    CHECK(profile.proof_ingress_depth == 5);
    CHECK(profile.fresh_rns_limbs() == 14);
    SealParameters parameters{
        .poly_modulus_degree = slots,
        .fresh_rns_limbs = profile.fresh_rns_limbs(),
        .data_prime_bit_sizes = profile.data_prime_bit_sizes,
        .special_prime_bits = profile.special_prime_bits,
        .security_level = seal::sec_level_type::none,
        .generate_galois_keys = prove_gkr,
    };
    std::vector<std::uint64_t> balanced_folded_moduli;
    {
        const auto folded = bench::packed_process_profile(
            bench::PackedProcessVariant::Folded,
            bench::PackedProcessTier::TargetBalanced, 0);
        auto folded_contexts = SealBackend::create(SealParameters{
            .poly_modulus_degree = slots,
            .fresh_rns_limbs = folded.fresh_rns_limbs(),
            .data_prime_bit_sizes = folded.data_prime_bit_sizes,
            .special_prime_bits = folded.special_prime_bits,
            .security_level = seal::sec_level_type::none,
            .generate_galois_keys = false,
        });
        balanced_folded_moduli = SealBackend::coefficient_moduli(folded_contexts.eval);
    }
    auto contexts = SealBackend::create(parameters);
    // Includes the special key-switching prime. Full-width Laned shares the
    // balanced Folded chain and its target-ring privacy estimate. Folded
    // pyramid has an independent chain and is not the reference for Laned.
    CHECK(SealBackend::coefficient_moduli(contexts.eval) == balanced_folded_moduli);

    PayloadBuilder builder(PayloadShape::laned(slots, slots), 2);
    const auto scalar = builder.add_plaintext(SlotVector(slots, Fp(3)));
    WireId product = builder.mul(0, 1);
    for (std::size_t depth = 1; depth < profile.multiplicative_depth; ++depth) {
        product = builder.mul(builder.add_plain(product, scalar), product);
    }
    builder.set_outputs({product});
    const auto payload = builder.finish();
    const auto circuit = compile(payload);
    const auto public_setup = make_direct_setup(payload, circuit);
    const auto ingress =
        protocol::derive_conservative_packed_proof_ingress_schedule(
            protocol::PackingGkrVariant::Laned, payload, circuit, public_setup);
    CHECK(ingress.policy() == protocol::kConservativePackedProofIngressPolicyV3);
    std::vector<std::size_t> proof_depths;
    for (const auto limbs : ingress.rns_limbs_by_layer()) {
        proof_depths.push_back(limbs - 1U);
    }
    const auto plan = bench::packed_process_evaluation_plan(profile, circuit, proof_depths);
    std::vector<SlotVector> inputs(2, SlotVector(slots));
    for (std::size_t input = 0; input < inputs.size(); ++input) {
        for (std::size_t slot = 0; slot < slots; ++slot) {
            inputs[input][slot] = Fp(3U + 7U * input + slot * slot + 5U * slot);
        }
    }
    const auto plain = synthesize_trace(payload, circuit, inputs);
    const auto evaluation = prove_gkr
        ? make_packed_evaluation_setup<SealBackend>(public_setup, contexts.eval)
        : make_evaluation_setup<SealBackend>(public_setup, contexts.eval);
    const auto encrypted_inputs = encrypt_laned_payload_inputs<SealBackend>(
        contexts.client, payload, inputs);
    const auto trace = evaluate_laned_fhe_trace<SealBackend>(
        evaluation.context, payload, circuit, encrypted_inputs, plan);
    CHECK(decrypt_trace_layer<SealBackend>(
              contexts.client, circuit, trace, 0) == plain.layers.front());
    int minimum_output_noise_budget = std::numeric_limits<int>::max();
    for (const auto &value : trace.layers.front().wires) {
        if (value.is_encrypted()) {
            const int budget = SealBackend::invariant_noise_budget(
                contexts.client, value.ciphertext());
            minimum_output_noise_budget =
                std::min(minimum_output_noise_budget, budget);
            CHECK(budget > 0);
        }
    }
    CHECK(minimum_output_noise_budget != std::numeric_limits<int>::max());
    std::cout << "  N=B=" << slots << " output noise budget: "
              << minimum_output_noise_budget << " bits\n";
    for (std::size_t source = 1; source < trace.layers.size(); ++source) {
        for (const auto &value : trace.layers[source].wires) {
            if (value.is_encrypted()) {
                CHECK(SealBackend::rns_limb_count(
                          contexts.eval, value.ciphertext()) ==
                      ingress.rns_limbs_by_layer()[source]);
                CHECK(SealBackend::invariant_noise_budget(
                          contexts.client, value.ciphertext()) > 0);
            }
        }
    }
    if (!prove_gkr) {
        return;
    }
    const std::vector<Fpk> point(laned_layer_variables(circuit, 0),
                                 Fpk::from_base(Fp(23)));
    const auto output_claim = make_packed_laned_claim(
        plain.layers.front(), laned_layout(circuit, 0), point);
    constexpr std::string_view domain = "test/laned/full-width-reduced-chain/v1";
    Transcript prover(domain);
    const auto proof = laned_detail::prove_laned_gkr_resident<SealBackend>(
        payload, circuit, trace, evaluation, ingress.rns_limbs_by_layer(),
        point, prover,
        ProofTransportPolicy{.reserved_mult_depth = kPackingReservedMultDepth});
    const auto client = make_client_setup<SealBackend>(public_setup, contexts.client);
    Transcript verifier(domain);
    CHECK(laned_detail::verify_encrypted_gkr<SealBackend>(
        payload, circuit, plain.layers.back(), client, trace.provenance,
        trace.trace_id, output_claim, proof, verifier));
    CHECK(prover.challenge_fpk() == verifier.challenge_fpk());
    std::size_t encrypted_messages = 0;
    int minimum_noise_budget = std::numeric_limits<int>::max();
    protocol::for_each_transcript_packing_round_value<SealBackend>(
        proof, [&](const auto &message) {
            if (message.is_encrypted()) {
                ++encrypted_messages;
                const int budget = SealBackend::invariant_noise_budget(
                    contexts.client, message.ciphertext());
                minimum_noise_budget = std::min(minimum_noise_budget, budget);
                CHECK(budget > 0);
                CHECK(SealBackend::rns_limb_count(
                          contexts.eval, message.ciphertext()) >=
                      kPackingReservedMultDepth + 1U);
            }
        });
    CHECK(encrypted_messages > 0);
    std::cout << "  full-width minimum proof-message noise budget: "
              << minimum_noise_budget << " bits\n";
}

} // namespace

int main() {
    laminate::test::Runner runner("file-backed Laned GKR prover with SEAL");
    runner.run("target-ring depth-eight payload retains noise with reduced chain", [] {
        check_reduced_full_width_candidate(kDefaultPolyModulusDegree, false);
    });
    runner.run("full-width depth-eight GKR verifies with reduced chain", [] {
        check_reduced_full_width_candidate(kSlots, true);
    });
    runner.run("two multiplication layers prove and verify", [] {
        PayloadBuilder builder(PayloadShape::laned(kSlots, kSlots), 4);
        const WireId first = builder.mul(0, 1);
        const WireId second = builder.mul(2, 3);
        builder.set_outputs({builder.mul(first, second)});
        const PayloadCircuit payload = builder.finish();
        const LayeredCircuit circuit = compile(payload);
        const std::vector<SlotVector> inputs{
            values(5), values(47), values(89), values(131)};
        const PlainTrace plain = synthesize_trace(
            payload, circuit, inputs);

        auto contexts = SealBackend::create(SealParameters{
            .poly_modulus_degree = kSlots,
            .fresh_rns_limbs = 11,
            .bits_per_data_prime = 50,
            .special_prime_bits = 50,
            .security_level = seal::sec_level_type::none,
        });
        const EncryptedTrace<SealBackend> resident =
            encrypt_compact_synthetic_trace<SealBackend>(
                contexts.eval, contexts.client, payload, circuit, plain,
                TraceEncryptionPlan::uniform(circuit, 9));
        std::vector<std::size_t> proof_ingress_rns_limbs_by_layer;
        proof_ingress_rns_limbs_by_layer.reserve(resident.layers.size());
        for (const auto &resident_layer : resident.layers) {
            CHECK(!resident_layer.wires.empty());
            CHECK(resident_layer.wires.front().is_encrypted());
            proof_ingress_rns_limbs_by_layer.push_back(
                SealBackend::rns_limb_count(
                    contexts.eval,
                    resident_layer.wires.front().ciphertext()));
        }
        const PublicSetup public_setup = make_direct_setup(payload, circuit);
        const auto evaluation = make_packed_evaluation_setup<SealBackend>(
            public_setup, contexts.eval);
        CHECK(SealBackend::plaintext_preprocessing_stats(
                  evaluation.context)
                  .logical_plaintexts == kFixedMessageCellCount);
        const std::vector<Fpk> point(
            laned_layer_variables(circuit, 0),
            Fpk::from_base(Fp(23)));
        const SingleClaim output_claim = make_packed_laned_claim(
            plain.layers.front(), laned_layout(circuit, 0), point);

        TemporaryDirectory root;
        const FileTraceStoreOptions limits{
            .max_total_bytes = std::uint64_t{1} << 31U,
            .min_free_bytes = 1,
        };
        const std::filesystem::path trace_directory =
            root.make_child("trace");
        (void)write_file_encrypted_trace(
            contexts.eval, trace_directory, limits, circuit, resident);
        auto trace_store = FileEncryptedTraceStore<SealBackend>::open(
            contexts.eval, trace_directory, payload, circuit,
            resident.provenance, resident.trace_id);
        auto trace =
            FileEncryptedTraceReclamationSession<SealBackend>::begin(
                std::move(trace_store),
                FileTraceReclamationOptions{
                    FileTraceSessionLifecycle::IrreversibleNoRetry});

        laned_detail::IrreversibleFileLanedGkrOptions options;
        options.lifecycle = FileTraceSessionLifecycle::IrreversibleNoRetry;
        options.reclaim_completed_multiplication_scratch = true;
        std::vector<std::filesystem::path> scratch_directories;
        for (std::size_t layer = 0;
             layer + 1U < circuit.layers.size(); ++layer) {
            if (layer_kind(circuit.layers[layer]) ==
                LayerKind::Multiplication) {
                const auto directory = root.make_child(
                    "multiplication-" + std::to_string(layer));
                scratch_directories.push_back(directory);
                options.proof.multiplication_scratch.push_back(
                    laned_detail::FileLanedMultiplicationScratch{
                        layer,
                        directory,
                        limits,
                    });
            }
        }
        CHECK(options.proof.multiplication_scratch.size() == 2);

        constexpr std::string_view kDomain =
            "test/laned/prover-file-backed-seal/v1";
        Transcript prover_transcript(kDomain);
        const auto file_backed =
            laned_detail::
                prove_laned_gkr_irreversible<SealBackend>(
                    payload, circuit, trace, evaluation,
                    proof_ingress_rns_limbs_by_layer, output_claim.point,
                    prover_transcript, std::move(options));
        CHECK(file_backed.report.reductions.size() ==
              circuit.layers.size() - 1U);
        std::vector<std::size_t> expected_order(circuit.layers.size());
        std::iota(expected_order.begin(), expected_order.end(),
                  std::size_t{0});
        const auto journal = trace.journal_state();
        CHECK(journal.retirement_order == expected_order);
        CHECK(journal.retired_layers ==
              std::vector<bool>(circuit.layers.size(), true));
        for (const auto &directory : scratch_directories) {
            CHECK(std::filesystem::is_empty(directory));
        }

        const ClientSetup<SealBackend> client =
            make_client_setup<SealBackend>(public_setup, contexts.client);
        Transcript verifier_transcript(kDomain);
        CHECK(laned_detail::verify_encrypted_gkr<SealBackend>(
            payload, circuit, plain.layers.back(), client,
            resident.provenance, resident.trace_id, output_claim,
            file_backed.proof, verifier_transcript));
    });
    return runner.summary();
}
