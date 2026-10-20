#include "test_helpers.hpp"

#include "laminate/fhe/seal_backend.hpp"
#include "laminate/payload/compiler.hpp"
#include "laminate/payload/evaluator.hpp"
#include "laminate/payload/fixtures/workloads.hpp"
#include "laminate/payload/input_encryption.hpp"
#include "laminate/payload/laned_fhe_evaluator.hpp"
#include "laminate/payload/trace.hpp"
#include "laminate/payload/trace/trace_crypto.hpp"
#include "laminate/payload/wide_fhe_evaluator.hpp"

#include <cstddef>

namespace {

using laminate::fhe::SealBackend;
using namespace laminate::payload;

constexpr std::size_t kSlots = 1024;

void check_real_fhe_evaluation(const WorkloadSpec &spec) {
    const Workload workload = make_workload(spec);
    const auto layered = compile(workload.circuit);
    CHECK(analyze(workload.circuit).ct_ct_multiplicative_depth == 8);
    CHECK(layered.proof_multiplication_depth == 8);
    const auto plain = synthesize_trace(workload.circuit, layered,
                                        workload.inputs);
    CHECK(plain.payload_outputs ==
          evaluate(workload.circuit, workload.inputs)
              .output_values(workload.circuit));
    auto contexts = SealBackend::create(laminate::fhe::SealParameters{
        .poly_modulus_degree = kSlots,
        .fresh_rns_limbs = 16,
        .bits_per_data_prime = 50,
        .special_prime_bits = 50,
        .security_level = seal::sec_level_type::none,
    });
    const auto plan = FheEvaluationPlan::switch_after_multiplication_layers(
        layered, 1);
    if (spec.shape.kind == PayloadKind::Laned) {
        const auto encrypted_inputs = encrypt_laned_payload_inputs<SealBackend>(
            contexts.client, workload.circuit, workload.inputs);
        const auto encrypted = evaluate_laned_fhe_trace<SealBackend>(
            contexts.eval, workload.circuit, layered, encrypted_inputs, plan);
        CHECK(decrypt_trace_layers<SealBackend>(contexts.client, layered,
                                                encrypted) == plain.layers);
        for (const auto &value : encrypted.layers.front().wires) {
            if (value.is_encrypted()) {
                CHECK(SealBackend::invariant_noise_budget(
                          contexts.client, value.ciphertext()) > 0);
            }
        }
    } else {
        const auto encrypted_inputs = encrypt_wide_payload_inputs<SealBackend>(
            contexts.client, workload.circuit, workload.inputs);
        const auto encrypted = evaluate_wide_fhe_trace_into<SealBackend>(
            contexts.eval, workload.circuit, layered, encrypted_inputs, plan,
            InMemoryTraceSink<SealBackend>{contexts.eval});
        CHECK(decrypt_trace_layers<SealBackend>(contexts.client, layered,
                                                encrypted) == plain.layers);
        for (const auto &value : encrypted.layers.front().wires) {
            if (value.is_encrypted()) {
                CHECK(SealBackend::invariant_noise_budget(
                          contexts.client, value.ciphertext()) > 0);
            }
        }
    }
}

void test_balanced_payload_seal() {
    WorkloadSpec spec{WorkloadKind::BalancedLaned, PayloadShape::laned(4, kSlots),
                      8, 64, 73};
    spec.input_count = 8;
    spec.operation_count = 1024;
    spec.multiplication_widths.assign(8, 64);
    check_real_fhe_evaluation(spec);
}

void test_mulheavy_payload_seal() {
    WorkloadSpec spec{WorkloadKind::MulHeavyPyramid, PayloadShape::wide(kSlots),
                      8, 422, 73};
    spec.input_count = 16;
    spec.operation_count = 1024;
    spec.multiplication_widths = {422, 224, 112, 56, 28, 14, 7, 7};
    check_real_fhe_evaluation(spec);
}

} // namespace

int main() {
    laminate::test::Runner runner("test_workloads_seal");
    runner.run("balancedLaned fixture matches clear evaluation",
               test_balanced_payload_seal);
    runner.run("mulHeavyPyramid fixture matches clear evaluation",
               test_mulheavy_payload_seal);
    return runner.summary();
}
