/// @file test_base_seal.cpp
/// @brief Complete LaminateBase proof under a toy Microsoft SEAL context.

#include "test_helpers.hpp"
#include "target_cost_test_helpers.hpp"

#include "laminate/bench/schedule_cost.hpp"
#include "laminate/bench/target_cost.hpp"
#include "laminate/fhe/seal_backend.hpp"
#include "laminate/payload/compiler.hpp"
#include "laminate/payload/trace/trace_crypto.hpp"
#include "laminate/protocol/base.hpp"
#include "laminate/protocol/metrics/profiling.hpp"
#include "laminate/protocol/metrics/proof_size.hpp"
#include "laminate/protocol/reference/base.hpp"
#include "laminate/gkr/detail/base/verification/diagnostic.hpp"

#include <algorithm>
#include <bit>
#include <cstddef>
#include <limits>
#include <utility>
#include <vector>

using namespace laminate;
using namespace laminate::bench;
using namespace laminate::fhe;
using namespace laminate::gkr;
using namespace laminate::payload;
using namespace laminate::protocol;

namespace {

constexpr std::size_t kSlots = 1024;

SlotVector slots(std::uint64_t seed) {
    SlotVector result(kSlots);
    for (std::size_t slot = 0; slot < result.size(); ++slot) {
        result[slot] = Fp(seed + 5 * slot + slot * slot);
    }
    return result;
}

PayloadCircuit sequential_multiplication_payload() {
    PayloadBuilder builder(PayloadShape::wide(kSlots), 2);
    const std::size_t diagonal = builder.add_plaintext(slots(11));
    const WireId rotated = builder.rotate(0, kSlots / 2 + 1);
    const WireId ctct = builder.mul(rotated, 1);
    const WireId plainct = builder.mul_plain(ctct, diagonal);
    builder.set_outputs({plainct});
    return builder.finish();
}

template <typename Function>
void for_each_proof_ciphertext(const EncryptedBaseProof<SealBackend> &proof,
                               Function function) {
    const auto extension = [&](const ExtensionValue<SealBackend> &value) {
        for (const auto &coefficient : value) {
            if (coefficient.is_encrypted()) {
                function(coefficient.ciphertext());
            }
        }
    };
    for (const auto &reduction : proof.reductions) {
        if (const auto *affine =
                std::get_if<EncryptedBaseAffineLayerReduction<SealBackend>>(
                    &reduction)) {
            for (const auto &round : affine->rounds) {
                extension(round.evaluations[0]);
                extension(round.evaluations[1]);
            }
            extension(affine->source_vector);
        } else {
            const auto &multiplication =
                std::get<EncryptedBaseMultiplicationLayerReduction<SealBackend>>(
                    reduction);
            for (const auto &round : multiplication.rounds) {
                extension(round.evaluations[0]);
                extension(round.evaluations[1]);
            }
            extension(multiplication.source_vectors[0]);
            extension(multiplication.source_vectors[1]);
        }
    }
}

} // namespace

int main() {
    test::Runner runner("test_base_seal");

    runner.run("sequential CT-CT and PT-CT Base proof verifies under toy BGV", [] {
        const PayloadCircuit payload = sequential_multiplication_payload();
        const LayeredCircuit circuit = compile(payload);
        const PlainTrace trace = synthesize_trace(
            payload, circuit, std::vector<SlotVector>{slots(3), slots(47)});
        const PublicSetup public_setup = make_direct_setup(payload, circuit);
        SealBackend::Contexts contexts = SealBackend::create(SealParameters{
            .poly_modulus_degree = kSlots,
            .fresh_rns_limbs = 5,
            .bits_per_data_prime = 60,
            .special_prime_bits = 60,
            .security_level = seal::sec_level_type::none,
        });
        const EncryptedTrace<SealBackend> encrypted =
            encrypt_compact_synthetic_trace<SealBackend>(
                contexts.eval, contexts.client, payload, circuit, trace,
                TraceEncryptionPlan::uniform(circuit, 4));
        const std::size_t output_variables =
            (std::bit_width(
                 layer_dimensions(circuit.layers.front()).padded_size) -
             1U) +
            (std::bit_width(circuit.shape.value_width()) - 1U);
        Transcript output_randomness("test/base/seal/output/v1");
        const SingleClaim output_claim = make_layer_claim(
            trace.layers.front(),
            output_randomness.challenge_vector(output_variables));
        const auto evaluation = make_evaluation_setup<SealBackend>(
            public_setup, contexts.eval);
        const auto client =
            make_client_setup<SealBackend>(public_setup, contexts.client);

        SealBackend::reset_counts(contexts.eval);
        SealBackend::set_counting(contexts.eval, true);
        Transcript prover_transcript("test/base/seal/v1");
        BaseProverTimings prover_timings;
        const EncryptedBaseProof<SealBackend> proof =
            prove_base_reference_profiled<SealBackend>(
            payload, circuit, encrypted, evaluation, output_claim.point,
            prover_transcript, prover_timings);
        SealBackend::set_counting(contexts.eval, false);
        const auto prove_counts = SealBackend::counts(contexts.eval);
        CHECK(prove_counts.calls(SealBackend::OperationKind::Decrypt) == 0);
        bool saw_multiplication = false;
        for (const auto &reduction : proof.reductions) {
            if (const auto *multiplication = std::get_if<
                    EncryptedBaseMultiplicationLayerReduction<SealBackend>>(
                    &reduction)) {
                saw_multiplication = true;
                // Each multiplication in this sequential fixture has one
                // dense output pair. Its reduction therefore has no wire
                // sumcheck round: Base transports the two terminal operands
                // and the verifier checks their product after decryption.
                CHECK(multiplication->rounds.empty());
            }
        }
        CHECK(saw_multiplication);
        CHECK(prove_counts.calls(SealBackend::OperationKind::MulNoRelin) == 0);
        CHECK(prove_counts.calls(SealBackend::OperationKind::Relinearize) == 0);
        CHECK(prover_timings.layers.size() == proof.reductions.size());

        int minimum_noise = std::numeric_limits<int>::max();
        std::size_t ciphertext_count = 0;
        for_each_proof_ciphertext(proof, [&](const auto &ciphertext) {
            CHECK(SealBackend::rns_limb_count(contexts.eval, ciphertext) == 1);
            minimum_noise = std::min(
                minimum_noise,
                SealBackend::invariant_noise_budget(contexts.client,
                                                    ciphertext));
            ++ciphertext_count;
        });
        CHECK(minimum_noise > 0);
        const BaseProofSizeBreakdown proof_size = measure_proof_size(proof);
        CHECK(ciphertext_count == proof_size.base_ciphertexts);

        const ScheduleFormula schedule = base_schedule_formula(circuit);
        CHECK(encrypted.layers.front().wires.front().is_encrypted());
        const std::size_t core_limbs = SealBackend::rns_limb_count(
            contexts.eval,
            encrypted.layers.front().wires.front().ciphertext());
        const HonestBaseProofNormalizationPlan normalization =
            derive_honest_base_proof_normalization_plan(
                circuit,
                FheEvaluationPlan::without_payload_switches(
                    circuit, core_limbs - 1U));
        const ProverOperationLedger ledger = base_operation_ledger(
            schedule, kSlots, normalization);
        CHECK(ciphertext_count == ledger.direct_transcript_ciphertexts);
        CHECK(ledger.paper_raw_ciphertext_footprint == 0);
        CHECK(ledger.aligned_ciphertexts == 0);
        CHECK(ledger.logical_packed_outputs == 0);
        test::check_seal_operation_ledger(prove_counts, ledger);
        const ProofSizeEstimate estimated_size =
            estimate_base_proof_size(circuit, schedule);
        CHECK(proof_size.total_bytes <
              estimated_size.canonical_bytes_excluding_packing_argument);

        Transcript verifier_transcript("test/base/seal/v1");
        BaseVerifierTimings verifier_timings;
        CHECK(verify_base_reference_profiled<SealBackend>(
            payload, circuit, trace.layers.back(), client, trace.provenance,
            encrypted.trace_id, output_claim, proof, verifier_transcript,
            verifier_timings));
        CHECK(verifier_timings.layers.size() == proof.reductions.size());
        CHECK(verifier_timings.packed_message_verification_wall_ms > 0);

        SingleClaim wrong_output = output_claim;
        wrong_output.value += Fpk::one();
        Transcript wrong_output_transcript("test/base/seal/v1");
        CHECK(!reference::verify_base<SealBackend>(
            payload, circuit, trace.layers.back(), client, trace.provenance,
            encrypted.trace_id, wrong_output, proof,
            wrong_output_transcript));
        // A rejected proof must leave a populated failure location.
        CHECK(!base_detail::base_verifier_diagnostic().stage.empty());

        Digest wrong_trace = encrypted.trace_id;
        wrong_trace.front() ^= 1U;
        Transcript wrong_trace_transcript("test/base/seal/v1");
        CHECK(!reference::verify_base<SealBackend>(
            payload, circuit, trace.layers.back(), client, trace.provenance,
            wrong_trace, output_claim, proof, wrong_trace_transcript));
        // A wrong trace id is rejected while binding the header and geometry.
        CHECK(base_detail::base_verifier_diagnostic().stage ==
              "header-and-geometry");

        LayeredCircuit changed_circuit = circuit;
        for (Layer &layer : changed_circuit.layers) {
            if (auto *affine = std::get_if<AffineLayer>(&layer);
                affine != nullptr && !affine->gates.empty() &&
                !affine->gates.front().terms.empty()) {
                affine->gates.front().terms.front().coefficient += Fp::one();
                break;
            }
        }
        Transcript changed_gate_transcript("test/base/seal/v1");
        CHECK(!reference::verify_base<SealBackend>(
            payload, changed_circuit, trace.layers.back(), client,
            trace.provenance, encrypted.trace_id, output_claim, proof,
            changed_gate_transcript));

        auto changed = proof;
        bool mutated = false;
        const auto mutate_extension = [&](ExtensionValue<SealBackend> &value) {
            const auto coefficient = std::find_if(
                value.begin(), value.end(),
                [](const auto &entry) { return entry.is_encrypted(); });
            if (coefficient == value.end()) {
                return false;
            }
            coefficient->ciphertext() = SealBackend::add_plain(
                contexts.eval, coefficient->ciphertext(),
                SlotVector(kSlots, Fp::one()));
            return true;
        };
        for (auto &reduction : changed.reductions) {
            if (auto *affine =
                    std::get_if<EncryptedBaseAffineLayerReduction<SealBackend>>(
                        &reduction)) {
                if (affine->rounds.empty()) {
                    continue;
                }
                if (mutate_extension(
                        affine->rounds.front().evaluations[0])) {
                    mutated = true;
                    break;
                }
            }
            auto &multiplication =
                std::get<EncryptedBaseMultiplicationLayerReduction<SealBackend>>(
                    reduction);
            if (!multiplication.rounds.empty()) {
                if (mutate_extension(
                        multiplication.rounds.front().evaluations[0])) {
                    mutated = true;
                    break;
                }
            }
        }
        CHECK(mutated);
        Transcript changed_transcript("test/base/seal/v1");
        CHECK(!reference::verify_base<SealBackend>(
            payload, circuit, trace.layers.back(), client, trace.provenance,
            encrypted.trace_id, output_claim, changed, changed_transcript));
    });

    return runner.summary();
}
