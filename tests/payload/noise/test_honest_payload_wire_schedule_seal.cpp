#include "test_helpers.hpp"

#include "laminate/fhe/seal_backend.hpp"
#include "laminate/payload/compiler.hpp"
#include "laminate/payload/input_encryption.hpp"
#include "laminate/payload/noise/honest_noise_schedule.hpp"
#include "laminate/payload/trace.hpp"
#include "laminate/payload/trace/trace_wire_support.hpp"
#include "laminate/payload/wide_fhe_evaluator.hpp"

#include <vector>

namespace {
using namespace laminate;
using namespace laminate::fhe;
using namespace laminate::payload;

constexpr std::size_t kSlots = 1024;

void check_branch_rich_payload() {
    // Bounded randomized check with a diagnostic chain and small ring/circuit;
    // it does not calibrate target parameters or establish a privacy claim.
    const std::vector<std::uint64_t> moduli{
        1'053'858'393'162'252'289ULL, 15'032'614'913ULL,
        53'687'910'401ULL, 96'638'238'721ULL, 98'785'755'137ULL,
        118'113'402'881ULL, 122'408'435'713ULL, 246'964'387'841ULL,
        272'734'584'833ULL, 292'062'232'577ULL};
    const HonestPayloadNoiseCalibration calibration{
        .fresh_canonical_error_bound = 59'904,
        .ctct_relinearized_debit_bits = 36,
        .plaintext_multiplication_debit_bits = 24,
        .rotation_debit_bits = 34,
        .maximum_switch_tax_bits = 10,
        .switch_rounding_error_bound = 921,
        .modeled_switch_events_upper_bound = 12'000'000,
        .switch_model_failure_budget_bits = 110,
        .proof_suffix_level_reserve = 0};

    PayloadBuilder builder(PayloadShape::wide(kSlots), 3);
    const auto scalar = builder.add_scalar_plaintext(Fp(3));
    const auto zero = builder.add_scalar_plaintext(Fp::zero());
    SlotVector mask(kSlots), bias(kSlots);
    std::vector<SlotVector> inputs(3, SlotVector(kSlots));
    for (std::size_t slot = 0; slot < kSlots; ++slot) {
        mask[slot] = Fp(2 + slot % 11);
        bias[slot] = Fp(17 + slot);
        for (std::size_t input = 0; input < inputs.size(); ++input)
            inputs[input][slot] = Fp(3 + 7 * input + slot % 19);
    }
    const auto mask_id = builder.add_plaintext(mask);
    const auto bias_id = builder.add_plaintext(bias);
    const auto rotated = builder.rotate(0, kSlots / 2 + 3);
    const auto scaled = builder.mul_plain(rotated, scalar);
    const auto rotated_again = builder.rotate(scaled, 5);
    const auto first_product = builder.mul(1, 1);
    const auto second_product = builder.mul(first_product, first_product);
    const auto masked = builder.mul_plain(2, mask_id);
    const auto public_zero = builder.mul_plain(2, zero);
    const auto public_constant = builder.add_plain(public_zero, scalar);
    builder.set_outputs({builder.add(rotated_again, masked),
                         builder.add_plain(second_product, bias_id),
                         public_zero, public_constant,
                         builder.mul(1, public_constant)});
    const auto payload = builder.finish();
    const auto circuit = compile(payload);
    const auto schedule = derive_uniform_honest_base_proof_schedule(
        circuit, moduli, calibration, 3);
    CHECK(schedule.payload_model_accepts());
    CHECK(schedule.switch_points.size() == 2);
    validate_honest_payload_noise_schedule(circuit, schedule);
    const auto expected = synthesize_trace(payload, circuit, inputs);
    const auto storage = canonical_trace_storage_layout(circuit);
    const auto support = canonical_trace_wire_support(circuit);
    CHECK(support.front().live_wire_count < support.front().padded_wire_count);

    auto contexts = SealBackend::create(SealParameters{
        .poly_modulus_degree = kSlots,
        .fresh_rns_limbs = moduli.size(),
        .exact_data_primes = moduli,
        .exact_special_prime = 8'590'163'969ULL,
        .special_prime_bits = 34,
        .security_level = seal::sec_level_type::none,
        .max_fresh_ciphertext_modulus_bits = 392,
        .max_key_modulus_bits = 426});
    const auto encrypted = encrypt_wide_payload_inputs<SealBackend>(
        contexts.client, payload, inputs);
    SealBackend::reset_counts(contexts.eval);
    SealBackend::set_counting(contexts.eval, true);
    const auto trace = evaluate_wide_fhe_trace_into<SealBackend>(
        contexts.eval, payload, circuit, encrypted, schedule.evaluation_plan,
        InMemoryTraceSink<SealBackend>{contexts.eval});
    SealBackend::set_counting(contexts.eval, false);
    const auto counts = SealBackend::counts(contexts.eval);
    CHECK(counts.calls(SealBackend::OperationKind::Rotate) > 0);
    CHECK(counts.calls(SealBackend::OperationKind::MulNoRelin) > 0);
    CHECK(counts.calls(SealBackend::OperationKind::Relinearize) > 0);
    CHECK(counts.calls(SealBackend::OperationKind::MulPlainScalar) > 0);
    CHECK(counts.calls(SealBackend::OperationKind::MulPlainVector) > 0);
    CHECK(counts.calls(SealBackend::OperationKind::ModSwitch) > 0);
    // This sink stores independent proof copies at the selected ingress
    // levels, so telemetry includes both payload drops and ingress drops.
    CHECK(counts.calls(SealBackend::OperationKind::ModSwitch) <=
          schedule.modeled_payload_switch_events +
              schedule.modeled_base_proof_ingress_switch_events);
    CHECK(counts.calls(SealBackend::OperationKind::Encrypt) == 0);

    bool saw_public_zero = false;
    bool saw_public_nonzero = false;
    std::uint64_t exact_switches = 0;
    for (std::size_t layer = 0; layer < trace.layers.size(); ++layer) {
        CHECK(trace.layers[layer].wires.size() == storage[layer].stored_wire_count);
        for (std::size_t stored = 0; stored < trace.layers[layer].wires.size(); ++stored) {
            const auto &value = trace.layers[layer].wires[stored];
            const auto wire = storage[layer].representative_padded_index_of(stored);
            if (value.is_public()) {
                CHECK(value.plaintext().materialize(kSlots) == expected.layers[layer][wire]);
                saw_public_zero |= value.is_public_zero();
                saw_public_nonzero |= !value.is_public_zero();
                continue;
            }
            CHECK(SealBackend::decrypt(contexts.client, value.ciphertext()) == expected.layers[layer][wire]);
            CHECK(SealBackend::invariant_noise_budget(contexts.client, value.ciphertext()) > 0);
            CHECK(SealBackend::rns_limb_count(contexts.eval, value.ciphertext()) ==
                  schedule.evaluation_plan.proof_ingress_mult_depth_by_layer[layer] + 1);
            exact_switches += schedule.evaluation_plan.modulus_switches_after_layer[layer] +
                schedule.evaluation_plan.trace.required_mult_depth_by_layer[layer] -
                schedule.evaluation_plan.proof_ingress_mult_depth_by_layer[layer];
            if (layer == 0) {
                auto terminal = value.ciphertext();
                auto modeled = schedule.layers_in_evaluation_order.back().output_canonical_error_bound;
                auto limbs = SealBackend::rns_limb_count(contexts.eval, terminal);
                while (limbs > 1) {
                    modeled = NaturalMagnitude::add(
                        NaturalMagnitude::divide_ceil(modeled, moduli[--limbs]),
                        NaturalMagnitude(calibration.switch_rounding_error_bound));
                }
                SealBackend::mod_switch_to_lowest(contexts.eval, terminal);
                CHECK(SealBackend::decrypt(contexts.client, terminal) == expected.layers[layer][wire]);
                const auto observed = SealBackend::canonical_error_infinity_norm(
                    contexts.eval, contexts.client, terminal);
                CHECK(!(modeled < NaturalMagnitude(observed)));
            }
        }
    }
    CHECK(saw_public_zero);
    CHECK(saw_public_nonzero);
    CHECK(counts.calls(SealBackend::OperationKind::ModSwitch) == exact_switches);
}
} // namespace

int main() {
    laminate::test::Runner runner("per-wire schedule with real SEAL");
    runner.run("branch-rich Wide evaluation follows the derived plan", check_branch_rich_payload);
    return runner.summary();
}
