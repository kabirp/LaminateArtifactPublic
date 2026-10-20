#include "test_helpers.hpp"

#include "laminate/field/fq.hpp"
#include "laminate/payload/compiler.hpp"
#include "laminate/payload/noise/honest_noise_schedule.hpp"
#include "laminate/payload/trace.hpp"

#include <algorithm>
#include <vector>

namespace {
using namespace laminate;
using namespace laminate::payload;
using fhe::NaturalMagnitude;

std::vector<std::uint64_t> chain() {
    return {kOuterFieldOrder, 1'152'921'497'895'862'273ULL,
            53'687'910'401ULL, 96'638'238'721ULL, 98'785'755'137ULL};
}

HonestPayloadNoiseCalibration calibration() {
    return {.fresh_canonical_error_bound = 64,
            .ctct_relinearized_debit_bits = 3,
            .plaintext_multiplication_debit_bits = 2,
            .rotation_debit_bits = 2,
            .maximum_switch_tax_bits = 10,
            .switch_rounding_error_bound = 649,
            .modeled_switch_events_upper_bound = 1'000'000,
            .switch_model_failure_budget_bits = 40,
            .proof_suffix_level_reserve = 4};
}

PayloadCircuit independent_branches(bool rotate_branch) {
    PayloadBuilder builder(PayloadShape::wide(8), 3);
    WireId branch = 0;
    if (rotate_branch) {
        branch = builder.rotate(branch, 1);
        branch = builder.rotate(branch, 3);
    }
    const auto first_product = builder.mul(1, 1);
    const auto second_product = builder.mul(first_product, first_product);
    // Three outputs force structural padding and carry the independent
    // branches through compiler-inserted forwarding multiplication gates.
    builder.set_outputs({branch, second_product, 2});
    return builder.finish();
}

template <class F> bool rejects(F &&call) {
    try { call(); } catch (const std::invalid_argument &) { return true; }
    return false;
}

NaturalMagnitude final_error(const HonestPayloadNoiseSchedule &schedule) {
    return schedule.layers_in_evaluation_order.back().output_canonical_error_bound;
}

void branch_independence() {
    const auto rotated = compile(independent_branches(true));
    const auto plain = compile(independent_branches(false));
    const auto scheduled = derive_honest_payload_noise_schedule(rotated, chain(), calibration());
    const auto baseline = derive_honest_payload_noise_schedule(plain, chain(), calibration());
    // Independent branch errors are 64*4*4 and 64*8*8. Rotations on the
    // smaller branch must not increase the multiplication branch's envelope.
    CHECK(final_error(scheduled) == NaturalMagnitude(4096));
    CHECK(final_error(scheduled) == final_error(baseline));
    CHECK(scheduled.payload_model_accepts());
    CHECK(scheduled.switch_points.empty());
    bool forwarding = false;
    bool padding = false;
    for (const auto &layer : rotated.layers) {
        if (const auto *multiplication = std::get_if<MultiplicationLayer>(&layer)) {
            for (const auto &gate : multiplication->gates) {
                forwarding |= gate.origin == GateOrigin::Forward;
                padding |= gate.origin == GateOrigin::Padding;
            }
        }
    }
    CHECK(forwarding);
    CHECK(padding);
}

void public_operands() {
    auto public_heavy = calibration();
    public_heavy.plaintext_multiplication_debit_bits = 5;
    PayloadBuilder builder(PayloadShape::wide(8), 2);
    const auto zero = builder.add_scalar_plaintext(Fp::zero());
    const auto seven = builder.add_scalar_plaintext(Fp(7));
    const auto public_zero = builder.mul_plain(0, zero);
    const auto public_seven = builder.add_plain(public_zero, seven);
    builder.set_outputs({builder.mul(1, public_seven), public_seven, public_zero});
    const auto circuit = compile(builder.finish());
    const auto schedule = derive_honest_payload_noise_schedule(circuit, chain(), public_heavy);
    // The public operand costs the plaintext debit, which exceeds the CTCT
    // debit in this fixture. Public zero/constant branches carry no error.
    CHECK(final_error(schedule) == NaturalMagnitude(2048));
    CHECK(std::none_of(schedule.layers_in_evaluation_order.begin(),
                       schedule.layers_in_evaluation_order.end(), [](const auto &layer) {
        return layer.completed_relinearized_payload_multiplication;
    }));

    PayloadBuilder public_builder(PayloadShape::wide(8), 1);
    const auto public_zero_id = public_builder.add_scalar_plaintext(Fp::zero());
    const auto public_seven_id = public_builder.add_scalar_plaintext(Fp(7));
    const auto erased = public_builder.mul_plain(0, public_zero_id);
    const auto constant = public_builder.add_plain(erased, public_seven_id);
    public_builder.set_outputs({public_builder.mul(constant, constant), erased});
    auto permissive = public_heavy;
    permissive.proof_suffix_level_reserve = 0;
    permissive.maximum_switch_tax_bits = 120;
    const auto all_public = derive_honest_payload_noise_schedule(
        compile(public_builder.finish()), chain(), permissive);
    CHECK(final_error(all_public).is_zero());
    CHECK(all_public.switch_points.empty());

    PayloadBuilder switched_builder(PayloadShape::wide(8), 2);
    const auto zero_id = switched_builder.add_scalar_plaintext(Fp::zero());
    const auto private_product = switched_builder.mul(0, 1);
    const auto erased_product = switched_builder.mul_plain(private_product, zero_id);
    switched_builder.set_outputs({switched_builder.mul(erased_product, erased_product)});
    const auto erased_after_switch = derive_honest_payload_noise_schedule(
        compile(switched_builder.finish()), chain(), permissive);
    CHECK(erased_after_switch.switch_points.size() == 1);
    CHECK(final_error(erased_after_switch).is_zero());

    PayloadBuilder ancestry(PayloadShape::wide(8), 2);
    const auto ancestry_zero = ancestry.add_scalar_plaintext(Fp::zero());
    const auto ancestry_seven = ancestry.add_scalar_plaintext(Fp(7));
    const auto known_zero = ancestry.mul_plain(0, ancestry_zero);
    const auto untracked_zero = ancestry.mul(1, known_zero);
    const auto nonzero_constant = ancestry.add_plain(untracked_zero, ancestry_seven);
    ancestry.set_outputs({ancestry.mul(1, nonzero_constant)});
    const auto public_ancestry = derive_honest_payload_noise_schedule(
        compile(ancestry.finish()), chain(), public_heavy);
    // The first product's positive conservative envelope cannot establish
    // encrypted dispatch. Its later use must still cover the larger PT debit.
    CHECK(final_error(public_ancestry) == NaturalMagnitude(65536));
}

void intermediate_phase_guard() {
    PayloadBuilder builder(PayloadShape::wide(8), 1);
    const auto zero = builder.add_scalar_plaintext(Fp::zero());
    builder.set_outputs({builder.mul_plain(builder.rotate(0, 1), zero)});
    auto excessive = calibration();
    excessive.rotation_debit_bits = 400;
    const auto schedule = derive_honest_payload_noise_schedule(
        compile(builder.finish()), chain(), excessive);
    CHECK(final_error(schedule).is_zero());
    CHECK(!schedule.payload_model_accepts());
    CHECK(std::any_of(schedule.layers_in_evaluation_order.begin(),
                      schedule.layers_in_evaluation_order.end(), [](const auto &layer) {
        return !layer.evaluated_phase_fits && layer.output_phase_fits;
    }));
}

void schedule_binding() {
    const auto circuit = compile(independent_branches(true));
    const auto original = derive_honest_payload_noise_schedule(circuit, chain(), calibration());
    CHECK(original.payload_noise_model == kDependencyAwareHonestPayloadNoiseModelV1);
    const auto repeated = derive_honest_payload_noise_schedule(circuit, chain(), calibration());
    CHECK(original == repeated);
    CHECK(honest_payload_noise_schedule_digest(circuit, original) ==
          honest_payload_noise_schedule_digest(circuit, repeated));

    auto tampered = original;
    tampered.layers_in_evaluation_order.back().evaluated_canonical_error_bound =
        NaturalMagnitude(1);
    CHECK(rejects([&] { validate_honest_payload_noise_schedule(circuit, tampered); }));
    CHECK(rejects([&] { (void)encode_canonical(circuit, tampered); }));
    tampered = original;
    tampered.payload_noise_model = "LaminateImpl/LayerMaximumNoise/legacy";
    CHECK(rejects([&] { validate_honest_payload_noise_schedule(circuit, tampered); }));
    CHECK(rejects([&] {
        validate_honest_payload_plan_parity(circuit, tampered, tampered.evaluation_plan);
    }));
    CHECK(rejects([&] { (void)honest_payload_noise_schedule_digest(circuit, tampered); }));
}

void switch_guards() {
    const auto circuit = compile(independent_branches(true));
    auto strict = calibration();
    strict.proof_suffix_level_reserve = 0;
    strict.maximum_switch_tax_bits = 0;
    const auto retained = derive_honest_payload_noise_schedule(circuit, chain(), strict);
    CHECK(retained.switch_points.empty());
    CHECK(std::any_of(retained.layers_in_evaluation_order.begin(),
                      retained.layers_in_evaluation_order.end(), [](const auto &layer) {
        return layer.decision == HonestPayloadSwitchDecision::RetainForThreshold;
    }));
    auto permissive = strict;
    permissive.maximum_switch_tax_bits = 120;
    const auto switched = derive_honest_payload_noise_schedule(circuit, chain(), permissive);
    CHECK(switched.switch_points.size() == 2);
    validate_honest_payload_plan_parity(circuit, switched, switched.evaluation_plan);
    permissive.proof_suffix_level_reserve = 4;
    const auto reserved = derive_honest_payload_noise_schedule(circuit, chain(), permissive);
    CHECK(reserved.switch_points.empty());
    CHECK(final_error(reserved) == NaturalMagnitude(4096));
    // Preserve the inclusive tax boundary independently of circuit geometry.
    CHECK(honest_switch_within_tax_threshold(NaturalMagnitude(3), NaturalMagnitude(4), 3, 2));
    CHECK(!honest_switch_within_tax_threshold(NaturalMagnitude(2), NaturalMagnitude(4), 3, 2));
}
} // namespace

int main() {
    laminate::test::Runner runner("per-wire honest payload schedule");
    runner.run("independent branches, forwarding and structural padding", branch_independence);
    runner.run("public constants and zero preserve correct operation debits", public_operands);
    runner.run("zero output cannot conceal an overflowing intermediate", intermediate_phase_guard);
    runner.run("recomputation and model binding reject stale reports", schedule_binding);
    runner.run("switch threshold and reserve guards", switch_guards);
    return runner.summary();
}
