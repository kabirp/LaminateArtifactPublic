/// @file test_modulus_switch_policy.cpp
/// @brief Exact separation of switch correctness and efficiency policy.

#include "test_helpers.hpp"

#include "laminate/bench/payload_profile.hpp"
#include "laminate/fhe/mock_backend.hpp"
#include "laminate/fhe/noise/modulus_switch_policy.hpp"
#include "laminate/gkr/detail/shared/dense_multiplication/source/file.hpp"
#include "laminate/gkr/detail/base/reference/prover.hpp"
#include "laminate/payload/compiler.hpp"
#include "laminate/payload/noise/honest_noise_schedule.hpp"
#include "laminate/payload/input_encryption.hpp"
#include "laminate/payload/fixtures/workloads.hpp"
#include "laminate/payload/wide_fhe_evaluator.hpp"
#include "laminate/protocol/base.hpp"
#include "laminate/setup.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <string>
#include <vector>

using namespace laminate::fhe;
using namespace laminate::payload;
using laminate::Fp;
using laminate::kOuterFieldOrder;
using laminate::test::Runner;

namespace {

constexpr std::uint64_t kPrime0 = 1'152'921'422'732'787'713ULL;
constexpr std::uint64_t kPrime1 = 1'152'921'409'847'689'217ULL;

DeterministicNoisePolicy noise_policy() {
    return DeterministicNoisePolicy{
        .ring_degree = 16'384,
        .plaintext_modulus = 65'537,
        .secret_hamming_weight_upper = 16'384,
        .sampled_error_coefficient_bound = 21,
    };
}

DeterministicNoiseBound bound_with_error(std::uint64_t beta) {
    const auto policy = noise_policy();
    return DeterministicNoiseBound{
        .partial_decryption_bound = NaturalMagnitude::add(
            NaturalMagnitude::multiply(
                NaturalMagnitude(beta), policy.plaintext_modulus),
            NaturalMagnitude(policy.plaintext_radius())),
    };
}

PayloadCircuit two_multiplication_payload(
    std::uint64_t addend_value = 7) {
    PayloadBuilder builder(PayloadShape::wide(8), 2);
    const std::size_t addend =
        builder.add_scalar_plaintext(Fp(addend_value));
    const WireId first_product = builder.mul(0, 1);
    const WireId shifted = builder.add_plain(first_product, addend);
    const WireId second_product = builder.mul(shifted, 0);
    builder.set_outputs({second_product});
    return builder.finish();
}

LayeredCircuit two_multiplication_circuit() {
    return compile(two_multiplication_payload());
}

std::vector<std::uint64_t> correction_preserving_chain() {
    // Bottom-to-top test chain. Every droppable prime preserves correction
    // factor one.
    return {
        kOuterFieldOrder,
        1'152'921'497'895'862'273ULL,
        53'687'910'401ULL,
        96'638'238'721ULL,
        98'785'755'137ULL,
    };
}

HonestPayloadNoiseCalibration honest_calibration(
    std::size_t ctct_debit_bits = 40) {
    return HonestPayloadNoiseCalibration{
        .fresh_canonical_error_bound = 64,
        .ctct_relinearized_debit_bits = ctct_debit_bits,
        .plaintext_multiplication_debit_bits = 3,
        .rotation_debit_bits = 2,
        .maximum_switch_tax_bits = 10,
        .switch_rounding_error_bound = 649,
        .modeled_switch_events_upper_bound = 1'000,
        .switch_model_failure_budget_bits = 40,
        .proof_suffix_level_reserve = 2,
    };
}

bool throws_invalid_argument(const auto &body) {
    try {
        body();
    } catch (const std::invalid_argument &) {
        return true;
    }
    return false;
}

bool throws_logic_error(const auto &body) {
    try {
        body();
    } catch (const std::logic_error &) {
        return true;
    }
    return false;
}

} // namespace

int main() {
    Runner runner("test_modulus_switch_policy");

    runner.run("big-integer shift crosses machine-word boundaries", [] {
        CHECK(NaturalMagnitude::shift_left(NaturalMagnitude(3), 0) ==
              NaturalMagnitude(3));
        CHECK(NaturalMagnitude::shift_left(NaturalMagnitude(1), 63) ==
              NaturalMagnitude(std::uint64_t{1} << 63U));
        const NaturalMagnitude two_to_64 = NaturalMagnitude::multiply(
            NaturalMagnitude(std::uint64_t{1} << 63U), 2);
        CHECK(NaturalMagnitude::shift_left(NaturalMagnitude(1), 64) ==
              two_to_64);
        CHECK(NaturalMagnitude::shift_left(NaturalMagnitude(3), 65) ==
              NaturalMagnitude::multiply(two_to_64, 6));
    });

    runner.run("default ten-bit target rejects an early optional switch", [] {
        const std::vector<std::uint64_t> moduli{kPrime0, kPrime1};
        const auto plan = plan_modulus_switch_to_next(
            noise_policy(), bound_with_error(688'149), 2, moduli);
        CHECK(plan.policy.maximum_budget_tax_bits == 10);
        CHECK(plan.transition.output_bound.certifies_no_wrap());
        CHECK(!plan.tax_within_target);
        CHECK(plan.decision == ModulusSwitchTaxDecision::RetainForTax);
        CHECK(!plan.should_switch());
    });

    runner.run("tax target is tunable and transition is unchanged", [] {
        const std::vector<std::uint64_t> moduli{kPrime0, 917'519};
        const auto strict = plan_modulus_switch_to_next(
            noise_policy(), bound_with_error(std::uint64_t{1} << 24U),
            2, moduli,
            ModulusSwitchTaxPolicy{.maximum_budget_tax_bits = 9});
        const auto relaxed = plan_modulus_switch_to_next(
            noise_policy(), bound_with_error(std::uint64_t{1} << 24U),
            2, moduli,
            ModulusSwitchTaxPolicy{.maximum_budget_tax_bits = 10});
        CHECK(!strict.tax_within_target);
        CHECK(relaxed.tax_within_target);
        CHECK(relaxed.should_switch());
        CHECK(strict.transition.output_bound.partial_decryption_bound ==
              relaxed.transition.output_bound.partial_decryption_bound);
        CHECK(strict.transition.output_canonical_error_bound ==
              relaxed.transition.output_canonical_error_bound);
        CHECK(strict.transition.output_bound.first_failure.has_value() ==
              relaxed.transition.output_bound.first_failure.has_value());
    });

    runner.run("mandatory switch uses exact transition, not tax policy", [] {
        const std::vector<std::uint64_t> moduli{kPrime0, kPrime1};
        const auto input = bound_with_error(688'149);
        const auto transition = derive_modulus_switch_transition(
            noise_policy(), input, 2, moduli);
        const auto bound = bound_modulus_switch(
            noise_policy(), input, 2, moduli);
        CHECK(transition.output_bound.partial_decryption_bound ==
              bound.partial_decryption_bound);
        CHECK(transition.output_bound.first_failure.has_value() ==
              bound.first_failure.has_value());
        CHECK(transition.rounding_error_bound == NaturalMagnitude(16'385));
    });

    runner.run("ten-bit equality is accepted and one unit below is not", [] {
        const DeterministicNoisePolicy policy{
            .ring_degree = 512,
            .plaintext_modulus = 3,
            .secret_hamming_weight_upper = 339,
            .sampled_error_coefficient_bound = 1,
        };
        // Both primes are 1 mod lcm(2N,t). For P=12,289, beta=4,096,
        // beta'=341, P'=1,024, and q*P'=2^10*P exactly.
        const std::vector<std::uint64_t> moduli{15'361, 12'289};
        const DeterministicNoiseBound equality{
            .partial_decryption_bound = NaturalMagnitude(12'289),
        };
        const auto accepted = plan_modulus_switch_to_next(
            policy, equality, 2, moduli,
            ModulusSwitchTaxPolicy{.maximum_budget_tax_bits = 10});
        CHECK(accepted.tax_within_target);
        CHECK(accepted.tax_ceiling_bits == 10);
        CHECK(accepted.should_switch());

        const DeterministicNoiseBound one_below{
            .partial_decryption_bound = NaturalMagnitude(12'288),
        };
        const auto rejected = plan_modulus_switch_to_next(
            policy, one_below, 2, moduli,
            ModulusSwitchTaxPolicy{.maximum_budget_tax_bits = 10});
        CHECK(!rejected.tax_within_target);
        CHECK(rejected.tax_ceiling_bits == 11);
        CHECK(rejected.decision == ModulusSwitchTaxDecision::RetainForTax);
    });

    runner.run("unsafe zero-bound transition is rejected before tax", [] {
        const std::vector<std::uint64_t> moduli{3, kPrime1};
        const DeterministicNoiseBound zero{
            .partial_decryption_bound = NaturalMagnitude(),
        };
        const auto plan = plan_modulus_switch_to_next(
            noise_policy(), zero, 2, moduli);
        CHECK(plan.decision ==
              ModulusSwitchTaxDecision::RejectUncertifiedTransition);
        CHECK(!plan.should_switch());
    });

    runner.run("honest threshold switches on exact equality", [] {
        const NaturalMagnitude input_phase(3);
        const NaturalMagnitude switched_phase(4);
        // 3 * 4 == 2^2 * 3.
        CHECK(honest_switch_within_tax_threshold(
            input_phase, switched_phase, 3, 2));
        CHECK(!honest_switch_within_tax_threshold(
            NaturalMagnitude(2), switched_phase, 3, 2));
    });

    runner.run("randomized rounding tail bound constrains calibration",
               [] {
        CHECK(randomized_mod_switch_rounding_heuristic_bound(
                  16'384, 398'798, 40) == 650);
        CHECK(randomized_mod_switch_rounding_heuristic_bound(
                  16'384, 398'798, 41) >= 650);
        CHECK(throws_invalid_argument([&] {
            (void)randomized_mod_switch_rounding_heuristic_bound(
                16'384, 0, 40);
        }));

        HonestPayloadNoiseCalibration calibration = honest_calibration();
        calibration.modeled_switch_events_upper_bound = 398'798;
        calibration.switch_model_failure_budget_bits = 40;
        calibration.switch_rounding_error_bound = 649;
        PayloadBuilder builder(PayloadShape::wide(16'384), 1);
        builder.set_outputs({0});
        const LayeredCircuit circuit = compile(builder.finish());
        CHECK(throws_invalid_argument([&] {
            calibration.validate(circuit);
        }));
        calibration.switch_rounding_error_bound = 650;
        calibration.validate(circuit);
    });

    runner.run("Base target profiles fit the committed switch-event domain",
               [] {
        const std::vector<std::uint64_t> chain{
            1'053'858'393'162'252'289ULL,
            15'032'614'913ULL,
            53'687'910'401ULL,
            96'638'238'721ULL,
            98'785'755'137ULL,
            118'113'402'881ULL,
            122'408'435'713ULL,
            246'964'387'841ULL,
            272'734'584'833ULL,
            292'062'232'577ULL,
        };
        const HonestPayloadNoiseCalibration calibration{
            .fresh_canonical_error_bound = 59'904,
            .ctct_relinearized_debit_bits = 36,
            .plaintext_multiplication_debit_bits = 24,
            .rotation_debit_bits = 34,
            .maximum_switch_tax_bits = 10,
            .switch_rounding_error_bound = 921,
            .modeled_switch_events_upper_bound = 12'000'000,
            .switch_model_failure_budget_bits = 110,
            .proof_suffix_level_reserve = 0,
        };
        CHECK(randomized_mod_switch_rounding_heuristic_bound(
                  16'384, calibration.modeled_switch_events_upper_bound,
                  calibration.switch_model_failure_budget_bits) == 921);

        struct Expected {
            laminate::bench::BenchmarkPayloadTier tier;
            std::uint64_t payload_events;
            std::uint64_t proof_events;
            std::uint64_t total_events;
        };
        constexpr std::array<Expected, 2> expected{{
            {laminate::bench::BenchmarkPayloadTier::TargetBalanced,
             458'752, 4'367'843, 4'826'595},
            {laminate::bench::BenchmarkPayloadTier::TargetMulHeavy,
             // Nonuniform PT products are included in affine-layer work.
             888'360, 9'992'305, 10'880'665},
        }};
        for (const Expected &entry : expected) {
            const auto profile =
                laminate::bench::benchmark_payload_profile(entry.tier);
            const PayloadCircuit payload = make_payload_circuit(
                laminate::bench::benchmark_payload_workload_spec(
                    profile, PayloadShape::wide(16'384)));
            const LayeredCircuit circuit = compile(payload);
            const CertifiedHonestPayloadSchedule certified =
                derive_certified_uniform_honest_base_proof_schedule(
                    circuit, chain, calibration, 3);
            const HonestPayloadNoiseSchedule &schedule =
                certified.schedule();
            if (schedule.modeled_payload_switch_events != entry.payload_events ||
                schedule.modeled_base_proof_switch_events != entry.proof_events ||
                schedule.modeled_switch_events != entry.total_events) {
                throw std::runtime_error(
                    "switch-event ledger changed for " + std::string(profile.name) +
                    ": payload=" +
                    std::to_string(schedule.modeled_payload_switch_events) +
                    ", proof=" +
                    std::to_string(schedule.modeled_base_proof_switch_events) +
                    ", total=" + std::to_string(schedule.modeled_switch_events));
            }
            CHECK(schedule.modeled_payload_switch_events ==
                  entry.payload_events);
            CHECK(schedule.modeled_base_proof_switch_events ==
                  entry.proof_events);
            CHECK(schedule.modeled_switch_events == entry.total_events);
            CHECK(schedule.modeled_switch_events <=
                  calibration.modeled_switch_events_upper_bound);
        }
    });

    runner.run("honest schedule is fixed by circuit chain and calibration",
               [] {
        const LayeredCircuit circuit = two_multiplication_circuit();
        const std::vector<std::uint64_t> chain =
            correction_preserving_chain();
        const HonestPayloadNoiseCalibration calibration =
            honest_calibration();
        const HonestPayloadNoiseSchedule schedule =
            derive_honest_payload_noise_schedule(
                circuit, chain, calibration);
        const HonestPayloadNoiseSchedule repeated =
            derive_honest_payload_noise_schedule(
                circuit, chain, calibration);

        CHECK(schedule.policy ==
              kHonestDeterministicSwitchPolicyV3);
        CHECK(schedule.payload_model_accepts());
        CHECK(!schedule.base_proof_noise_assessment.has_value());
        CHECK(schedule.switch_points.size() == 2);
        CHECK(schedule.modeled_payload_switch_events > 0);
        CHECK(schedule.modeled_base_proof_switch_events > 0);
        CHECK(schedule.modeled_switch_events ==
              schedule.modeled_payload_switch_events +
                  schedule.modeled_base_proof_switch_events);
        CHECK(schedule.base_proof_normalization_plan.reductions.size() + 1 ==
              circuit.layers.size());
        CHECK(schedule.base_proof_normalization_plan.switch_events ==
              schedule.modeled_base_proof_switch_events);
        CHECK(schedule.base_proof_normalization_plan.ingress_switch_events ==
              schedule.modeled_base_proof_ingress_switch_events);
        CHECK(schedule.base_proof_normalization_plan
                  .proof_message_switch_events ==
              schedule.modeled_base_proof_message_switch_events);
        CHECK(schedule.modeled_switch_events > 0);
        CHECK(schedule.modeled_switch_events <=
              calibration.modeled_switch_events_upper_bound);
        CHECK(schedule.evaluation_plan
                  .modulus_switches_after_layer ==
              repeated.evaluation_plan
                  .modulus_switches_after_layer);
        CHECK(schedule.evaluation_plan.trace
                  .required_mult_depth_by_layer ==
              repeated.evaluation_plan.trace
                  .required_mult_depth_by_layer);
        CHECK(schedule == repeated);
        CHECK(encode_canonical(circuit, schedule) ==
              encode_canonical(circuit, repeated));
        CHECK(honest_payload_noise_schedule_digest(circuit, schedule) ==
              honest_payload_noise_schedule_digest(circuit, repeated));

        std::size_t active = chain.size();
        for (const auto &layer :
             schedule.layers_in_evaluation_order) {
            CHECK(layer.input_rns_limb_count == active);
            if (layer.switched()) {
                CHECK(layer.completed_relinearized_payload_multiplication);
                CHECK(layer.kind == LayerKind::Multiplication);
                CHECK(layer.output_rns_limb_count + 1 == active);
                --active;
            } else {
                CHECK(layer.output_rns_limb_count == active);
            }
        }
        CHECK(active == calibration.proof_suffix_level_reserve + 1);
        CHECK(schedule.evaluation_plan
                  .proof_ingress_mult_depth_by_layer.front() ==
              schedule.evaluation_plan.trace
                  .required_mult_depth_by_layer.front());
        for (std::size_t layer = 1; layer < circuit.layers.size(); ++layer) {
            CHECK(schedule.evaluation_plan
                      .proof_ingress_mult_depth_by_layer[layer] ==
                  std::min(
                      schedule.evaluation_plan.trace
                          .required_mult_depth_by_layer[layer],
                      calibration.proof_suffix_level_reserve));
        }
        CHECK(std::all_of(
            schedule.switch_points.begin(),
            schedule.switch_points.end(),
            [&](const HonestPayloadSwitchPoint &point) {
                return schedule.evaluation_plan
                           .modulus_switches_after_layer
                           .at(point.after_layer) == 1;
            }));
        validate_honest_payload_plan_parity(
            circuit, schedule, schedule.evaluation_plan);
        validate_honest_base_proof_normalization_plan(
            circuit, schedule.evaluation_plan,
            schedule.base_proof_normalization_plan);
        validate_honest_payload_noise_schedule(circuit, schedule);
    });

    runner.run("uniform Base proof policy is cheap and setup-fixed", [] {
        const LayeredCircuit circuit = two_multiplication_circuit();
        HonestPayloadNoiseCalibration calibration = honest_calibration();
        calibration.proof_suffix_level_reserve = 0;
        const HonestPayloadNoiseSchedule schedule =
            derive_uniform_honest_base_proof_schedule(
                circuit, correction_preserving_chain(), calibration, 3);
        const CertifiedHonestPayloadSchedule certified =
            derive_certified_uniform_honest_base_proof_schedule(
                circuit, correction_preserving_chain(), calibration, 3);

        CHECK(schedule.payload_model_accepts());
        CHECK(certified.schedule() == schedule);
        CHECK(certified.digest() ==
              honest_payload_noise_schedule_digest(circuit, schedule));
        CHECK(!certified.proof_assessment_digest().has_value());
        CHECK(schedule.calibration.proof_suffix_level_reserve == 2);
        CHECK(!schedule.base_proof_noise_assessment.has_value());
        CHECK(schedule.evaluation_plan
                  .proof_ingress_mult_depth_by_layer.front() ==
              schedule.evaluation_plan.trace
                  .required_mult_depth_by_layer.front());
        for (std::size_t source_layer = 1;
             source_layer < circuit.layers.size(); ++source_layer) {
            CHECK(schedule.evaluation_plan
                      .proof_ingress_mult_depth_by_layer[source_layer] == 2);
            CHECK(schedule.base_proof_normalization_plan.reductions
                      .at(source_layer - 1U)
                      .proof_ingress_rns_limb_count == 3);
        }
        validate_honest_payload_noise_schedule(circuit, schedule);
        const PayloadCircuit payload = two_multiplication_payload();
        const laminate::PublicSetup setup =
            laminate::bind_uniform_honest_base_proof_schedule(
                laminate::make_direct_setup(payload, circuit), payload,
                circuit, schedule);
        CHECK(setup.honest_payload_noise_schedule_digest ==
              honest_payload_noise_schedule_digest(circuit, schedule));
        CHECK(!setup.honest_base_proof_noise_assessment_digest.has_value());
        const laminate::PublicSetup certified_setup =
            laminate::bind_certified_uniform_honest_base_proof_schedule(
                laminate::make_direct_setup(payload, circuit), payload,
                circuit, certified);
        certified_setup.validate_certified_payload_schedule(
            payload, circuit, certified);
        CHECK(certified_setup.honest_payload_noise_schedule_digest ==
              setup.honest_payload_noise_schedule_digest);

        const PayloadCircuit other_payload =
            two_multiplication_payload(8);
        const LayeredCircuit other_circuit = compile(other_payload);
        CHECK(other_circuit.shape == circuit.shape);
        CHECK(throws_invalid_argument([&] {
            (void)laminate::bind_certified_uniform_honest_base_proof_schedule(
                laminate::make_direct_setup(
                    other_payload, other_circuit),
                other_payload, other_circuit, certified);
        }));

        laminate::PublicSetup forged = laminate::make_direct_setup(
            other_payload, other_circuit);
        forged.honest_payload_noise_schedule_digest = certified.digest();
        CHECK(throws_invalid_argument([&] {
            forged.validate_certified_payload_schedule(
                other_payload, other_circuit, certified);
        }));

        CertifiedHonestPayloadSchedule movable =
            derive_certified_uniform_honest_base_proof_schedule(
                circuit, correction_preserving_chain(), calibration, 3);
        const laminate::Digest movable_digest = movable.digest();
        CertifiedHonestPayloadSchedule moved = std::move(movable);
        CHECK(moved.digest() == movable_digest);
        CHECK(throws_logic_error([&] { (void)movable.digest(); }));
        CHECK(throws_logic_error([&] { (void)movable.schedule(); }));

        HonestPayloadNoiseSchedule altered = schedule;
        ++altered.fresh_modulus_product_bits;
        CHECK(throws_invalid_argument([&] {
            (void)certify_honest_payload_noise_schedule(
                circuit, std::move(altered));
        }));
        CHECK(throws_invalid_argument([&] {
            (void)laminate::bind_honest_payload_noise_schedule(
                laminate::make_direct_setup(payload, circuit), payload,
                circuit, schedule);
        }));

        CHECK(throws_invalid_argument([&] {
            (void)derive_uniform_honest_base_proof_schedule(
                circuit, correction_preserving_chain(), calibration, 0);
        }));
        CHECK(throws_invalid_argument([&] {
            (void)derive_uniform_honest_base_proof_schedule(
                circuit, correction_preserving_chain(), calibration, 6);
        }));
    });

    runner.run("wide six-layer fixture derives the committed schedule", [] {
        WorkloadSpec spec{
            .kind = WorkloadKind::Diamond,
            .shape = PayloadShape::wide(16'384),
            .multiplicative_depth = 6,
            .width = 24'576,
            .seed = 1,
        };
        spec.input_count = 64;
        const LayeredCircuit circuit = compile(make_payload_circuit(spec));
        const std::vector<std::uint64_t> chain{
            1'053'858'393'162'252'289ULL,
            15'032'614'913ULL,
            53'687'910'401ULL,
            96'638'238'721ULL,
            98'785'755'137ULL,
            118'113'402'881ULL,
            122'408'435'713ULL,
            246'964'387'841ULL,
            272'734'584'833ULL,
        };
        const HonestPayloadNoiseCalibration calibration{
            .fresh_canonical_error_bound = 59'904,
            .ctct_relinearized_debit_bits = 36,
            .plaintext_multiplication_debit_bits = 24,
            .rotation_debit_bits = 34,
            .maximum_switch_tax_bits = 10,
            .switch_rounding_error_bound = 921,
            .modeled_switch_events_upper_bound = 10'000'000,
            .switch_model_failure_budget_bits = 110,
            .proof_suffix_level_reserve = 0,
        };
        const HonestPayloadNoiseSchedule schedule =
            derive_uniform_honest_base_proof_schedule(
                circuit, chain, calibration, 3);

        CHECK(schedule.payload_model_accepts());
        CHECK(schedule.base_proof_ingress_policy ==
              kUniformBaseProofIngressPolicyV1);
        CHECK(schedule.base_proof_normalization_plan.reductions.size() == 13);
        CHECK(std::all_of(
            schedule.base_proof_normalization_plan.reductions.begin(),
            schedule.base_proof_normalization_plan.reductions.end(),
            [](const HonestBaseProofNormalizationLayerPlan &reduction) {
                return reduction.proof_ingress_rns_limb_count == 3;
            }));

        const auto support = canonical_trace_wire_support(circuit);
        const auto storage = canonical_trace_storage_layout(circuit);
        constexpr std::uint64_t kThreeLimbRecordBytes =
            2ULL * 16'384ULL * 3ULL * sizeof(std::uint64_t) +
            (1ULL << 16U);
        std::uint64_t maximum_build_peak = 0;
        std::uint64_t maximum_artifact = 0;
        for (std::size_t layer = 0;
             layer + 1U < circuit.layers.size(); ++layer) {
            if (layer_kind(circuit.layers[layer]) !=
                LayerKind::Multiplication) {
                continue;
            }
            CHECK(schedule.evaluation_plan
                      .proof_ingress_mult_depth_by_layer[layer + 1U] == 2);
            const auto aliases =
                laminate::gkr::detail::make_dense_multiplication_alias_plan(
                    circuit, layer, support.at(layer + 1U),
                    storage.at(layer + 1U));
            const auto bounds = laminate::gkr::detail::
                file_dense_multiplication_source_disk_bounds(
                    aliases.operands.size(), kThreeLimbRecordBytes,
                    storage.at(layer + 1U).stored_wire_count ==
                        support.at(layer + 1U).live_wire_count);
            maximum_build_peak =
                std::max(maximum_build_peak, bounds.build_peak_bytes);
            maximum_artifact = std::max(
                maximum_artifact, bounds.completed_artifact_bytes);
        }
        CHECK(maximum_build_peak == 83'754'221'928ULL);
        CHECK(maximum_artifact == 41'876'717'928ULL);
    });

    runner.run("canonical honest schedule rejects mutated derived state", [] {
        const LayeredCircuit circuit = two_multiplication_circuit();
        const HonestPayloadNoiseSchedule original =
            derive_honest_payload_noise_schedule(
                circuit, correction_preserving_chain(),
                honest_calibration());

        HonestPayloadNoiseSchedule altered = original;
        ++altered.fresh_modulus_product_bits;
        CHECK(throws_invalid_argument([&] {
            (void)encode_canonical(circuit, altered);
        }));

        altered = original;
        ++altered.layers_in_evaluation_order.front()
              .output_rns_limb_count;
        CHECK(throws_invalid_argument([&] {
            validate_honest_payload_noise_schedule(circuit, altered);
        }));

        altered = original;
        ++altered.switch_points.front().dropped_modulus;
        CHECK(throws_invalid_argument([&] {
            (void)honest_payload_noise_schedule_digest(circuit, altered);
        }));

        altered = original;
        const std::size_t switched_layer =
            altered.switch_points.front().after_layer;
        altered.evaluation_plan
            .modulus_switches_after_layer[switched_layer] = 0;
        CHECK(throws_invalid_argument([&] {
            validate_honest_payload_noise_schedule(circuit, altered);
        }));

        altered = original;
        ++altered.modeled_base_proof_switch_events;
        CHECK(throws_invalid_argument([&] {
            validate_honest_payload_noise_schedule(circuit, altered);
        }));

        altered = original;
        altered.base_proof_normalization_plan.reductions.front()
            .message_coordinate_masks.front() ^= 1U;
        CHECK(throws_invalid_argument([&] {
            (void)encode_canonical(circuit, altered);
        }));

        altered = original;
        --altered.evaluation_plan
              .proof_ingress_mult_depth_by_layer.front();
        CHECK(throws_invalid_argument([&] {
            (void)encode_canonical(circuit, altered);
        }));

        altered = original;
        ++altered.base_proof_normalization_plan.reductions.front()
              .switch_events;
        CHECK(throws_invalid_argument([&] {
            validate_honest_payload_noise_schedule(circuit, altered);
        }));

        altered = original;
        altered.base_proof_noise_assessment =
            HonestBaseProofNoiseAssessment{
                .policy = "test/injected-assessment",
                .topology_complete = true,
                .all_messages_fit = true,
            };
        CHECK(throws_invalid_argument([&] {
            validate_honest_payload_noise_schedule(circuit, altered);
        }));

        altered = original;
        ++altered.calibration.maximum_switch_tax_bits;
        CHECK(throws_invalid_argument([&] {
            validate_honest_payload_noise_schedule(circuit, altered);
        }));
    });

    runner.run("proof suffix reserve vetoes otherwise eligible drops", [] {
        const LayeredCircuit circuit = two_multiplication_circuit();
        std::vector<std::uint64_t> chain =
            correction_preserving_chain();
        chain.resize(3);
        const HonestPayloadNoiseSchedule schedule =
            derive_honest_payload_noise_schedule(
                circuit, chain, honest_calibration());
        CHECK(schedule.switch_points.empty());
        CHECK(std::all_of(
            schedule.layers_in_evaluation_order.begin(),
            schedule.layers_in_evaluation_order.end(),
            [](const HonestPayloadLayerSchedule &layer) {
                return !layer.completed_relinearized_payload_multiplication ||
                       layer.decision ==
                           HonestPayloadSwitchDecision::
                               RetainForProofSuffix;
            }));
    });

    runner.run("plan parity rejects any changed switch point", [] {
        const LayeredCircuit circuit = two_multiplication_circuit();
        const HonestPayloadNoiseSchedule schedule =
            derive_honest_payload_noise_schedule(
                circuit, correction_preserving_chain(),
                honest_calibration());
        FheEvaluationPlan altered = schedule.evaluation_plan;
        const std::size_t layer = schedule.switch_points.front().after_layer;
        altered.modulus_switches_after_layer[layer] = 0;
        bool rejected = false;
        try {
            validate_honest_payload_plan_parity(
                circuit, schedule, altered);
        } catch (const std::invalid_argument &) {
            rejected = true;
        }
        CHECK(rejected);
    });

    runner.run("ordered prefix search selects the first accepted chain",
               [] {
        const LayeredCircuit circuit = two_multiplication_circuit();
        const auto search = assess_honest_payload_chain_prefixes(
            circuit, correction_preserving_chain(),
            honest_calibration(80));
        CHECK(search.assessments.size() == 3);
        CHECK(!search.assessments[0].payload_model_accepts());
        CHECK(search.selected() != nullptr);
        CHECK(search.selected()->fresh_rns_limb_count == 4);
        CHECK(search.selected()->payload_model_accepts());
        CHECK(search.assessments[0].fresh_modulus_product_bits <
              search.assessments[1].fresh_modulus_product_bits);
    });

    runner.run("honest schedule rejects correction-changing chain entries",
               [] {
        const LayeredCircuit circuit = two_multiplication_circuit();
        std::vector<std::uint64_t> chain =
            correction_preserving_chain();
        chain[1] = 133'857'281ULL;
        bool rejected = false;
        try {
            (void)derive_honest_payload_noise_schedule(
                circuit, chain, honest_calibration());
        } catch (const std::invalid_argument &) {
            rejected = true;
        }
        CHECK(rejected);
    });

    runner.run("Base proof switch-event count matches exact execution", [] {
        const PayloadCircuit payload = two_multiplication_payload();
        const LayeredCircuit circuit = compile(payload);
        const std::vector<std::uint64_t> chain =
            correction_preserving_chain();
        const HonestPayloadNoiseSchedule schedule =
            derive_honest_payload_noise_schedule(
                circuit, chain, honest_calibration());
        const std::vector<LayerWireSupport> support =
            canonical_trace_wire_support(circuit);
        CHECK(std::all_of(support.begin(), support.end(), [](const auto &layer) {
            return layer.live_wire_count == layer.padded_wire_count;
        }));

        std::vector<laminate::fhe::SlotVector> inputs{
            laminate::fhe::SlotVector(8, Fp(3)),
            laminate::fhe::SlotVector(8, Fp(5)),
        };
        const PlainTrace plain = synthesize_trace(
            payload, circuit, inputs);
        auto contexts = laminate::fhe::MockBackend::create(
            laminate::fhe::MockParameters{
                .slot_count = 8,
                .fresh_rns_limbs = chain.size(),
                .bits_per_limb = 256,
            });
        const auto encrypted_inputs =
            encrypt_wide_payload_inputs<laminate::fhe::MockBackend>(
                contexts.client, payload, inputs);
        FheEvaluationPlan natural_trace_plan = schedule.evaluation_plan;
        natural_trace_plan.proof_ingress_mult_depth_by_layer =
            natural_trace_plan.trace.required_mult_depth_by_layer;
        auto trace = evaluate_wide_fhe_trace_into<
            laminate::fhe::MockBackend>(
            contexts.eval, payload, circuit, encrypted_inputs,
            natural_trace_plan,
            InMemoryTraceSink<laminate::fhe::MockBackend>{contexts.eval});

        const laminate::PublicSetup public_setup =
            laminate::make_direct_setup(payload, circuit);
        const auto setup =
            laminate::make_evaluation_setup<laminate::fhe::MockBackend>(
                public_setup, contexts.eval);
        const std::size_t output_variables =
            (std::bit_width(layer_dimensions(circuit.layers.front())
                                .padded_size) -
             1U) +
            (std::bit_width(circuit.shape.slot_count) - 1U);
        laminate::Fpk::Coefficients output_coordinate_coefficients{};
        for (std::size_t coefficient = 0;
             coefficient < laminate::kExtensionDegree; ++coefficient) {
            output_coordinate_coefficients[coefficient] =
                Fp(coefficient + 1U);
        }
        const laminate::Fpk output_coordinate(
            output_coordinate_coefficients);
        const laminate::gkr::SingleClaim output_claim =
            laminate::gkr::make_layer_claim(
                plain.layers.front(),
                std::vector<laminate::Fpk>(output_variables,
                                            output_coordinate));
        laminate::Transcript transcript(
            "test/base/proof-switch-accounting/v1");
        laminate::fhe::MockBackend::reset_counts(contexts.eval);
        for (std::size_t layer = 0; layer < trace.layers.size(); ++layer) {
            const std::size_t ingress_limbs =
                schedule.evaluation_plan
                    .proof_ingress_mult_depth_by_layer[layer] +
                1U;
            for (auto &value : trace.layers[layer].wires) {
                while (value.is_encrypted() &&
                       laminate::fhe::MockBackend::rns_limb_count(
                           contexts.eval, value.ciphertext()) >
                           ingress_limbs) {
                    laminate::fhe::value_mod_switch_to_next<
                        laminate::fhe::MockBackend>(contexts.eval, value);
                }
            }
            trace.layers[layer].required_mult_depth = ingress_limbs - 1U;
        }
        const auto proof = laminate::gkr::base_detail::
            prove_resident_test_reference<
                laminate::fhe::MockBackend>(
                payload, circuit, trace, setup, output_claim.point,
                transcript);
        CHECK(!proof.reductions.empty());
        CHECK(laminate::fhe::MockBackend::counts(contexts.eval).mod_switch ==
              schedule.modeled_base_proof_switch_events);
    });

    runner.run("Base normalization plan exposes a safe proof envelope", [] {
        const LayeredCircuit circuit = two_multiplication_circuit();
        const HonestPayloadNoiseSchedule schedule =
            derive_honest_payload_noise_schedule(
                circuit, correction_preserving_chain(),
                honest_calibration());
        const HonestBaseProofNormalizationPlan independently_derived =
            derive_honest_base_proof_normalization_plan(
                circuit, schedule.evaluation_plan);
        CHECK(independently_derived ==
              schedule.base_proof_normalization_plan);

        std::uint64_t switch_events = 0;
        for (const auto &reduction : independently_derived.reductions) {
            CHECK(reduction.round_extension_ciphertext_count ==
                  2U * reduction.wire_variables);
            CHECK(reduction.terminal_extension_ciphertext_count ==
                  (reduction.kind == LayerKind::Affine ? 1U : 2U));
            const HonestBaseProofMessageTopology topology =
                derive_honest_base_proof_message_topology(reduction);
            CHECK(topology ==
                  derive_honest_base_proof_message_topology(
                      circuit, reduction.reduction_layer));
            CHECK(reduction.public_zero_extension_message_count ==
                  topology.public_zero_extension_message_count);
            CHECK(reduction.base_ciphertext_count ==
                  topology.base_ciphertext_count);
            CHECK(reduction.ingress_switch_events ==
                  reduction.live_source_ciphertext_count *
                      (reduction.natural_source_rns_limb_count -
                       reduction.proof_ingress_rns_limb_count));
            CHECK(reduction.proof_message_switch_events ==
                  reduction.base_ciphertext_count *
                      (reduction.proof_ingress_rns_limb_count - 1U));
            CHECK(reduction.switch_events ==
                  reduction.ingress_switch_events +
                      reduction.proof_message_switch_events);
            switch_events += reduction.switch_events;
        }
        CHECK(switch_events == independently_derived.switch_events);

        HonestBaseProofNormalizationPlan altered = independently_derived;
        ++altered.reductions.front().wire_variables;
        CHECK(throws_invalid_argument([&] {
            validate_honest_base_proof_normalization_plan(
                circuit, schedule.evaluation_plan, altered);
        }));

        CHECK(std::string_view(honest_base_proof_message_family_name(
                  HonestBaseProofMessageFamily::AffineRoundAtOne)) ==
              "affine-round-at-one");
        CHECK(std::string_view(honest_base_proof_message_family_name(
                  HonestBaseProofMessageFamily::
                      MultiplicationRightTerminal)) ==
              "multiplication-right-terminal");
    });

    runner.run("structural padding has no normalization record", [] {
        PayloadBuilder builder(PayloadShape::wide(8), 3);
        builder.set_outputs({builder.add(0, 1)});
        const LayeredCircuit circuit = compile(builder.finish());
        const LayerWireSupport source_support =
            canonical_layer_wire_support(circuit, 1);
        CHECK(source_support.live_wire_count == 3);
        CHECK(source_support.padded_wire_count == 4);

        const HonestPayloadNoiseSchedule schedule =
            derive_honest_payload_noise_schedule(
                circuit, correction_preserving_chain(),
                honest_calibration());
        CHECK(schedule.base_proof_normalization_plan.reductions.size() == 1);
        const auto &reduction =
            schedule.base_proof_normalization_plan.reductions.front();
        CHECK(reduction.wire_variables == 2);
        CHECK(reduction.round_extension_ciphertext_count == 4);
        CHECK(reduction.terminal_extension_ciphertext_count == 1);
        constexpr HonestBaseProofCoordinateMask full_mask =
            static_cast<HonestBaseProofCoordinateMask>(
                (std::uint16_t{1} << laminate::kExtensionDegree) - 1U);
        CHECK(reduction.message_coordinate_masks ==
              std::vector<HonestBaseProofCoordinateMask>(
                  {0, full_mask, full_mask, full_mask, full_mask}));
        CHECK(reduction.public_zero_extension_message_count == 1);
        CHECK(reduction.base_ciphertext_count ==
              4 * laminate::kExtensionDegree);
        CHECK(reduction.live_source_ciphertext_count == 3);
        CHECK(reduction.ingress_switch_events ==
              reduction.live_source_ciphertext_count *
                  (reduction.natural_source_rns_limb_count -
                   reduction.proof_ingress_rns_limb_count));
        CHECK(reduction.proof_message_switch_events ==
              reduction.base_ciphertext_count *
                  (reduction.proof_ingress_rns_limb_count - 1U));
        CHECK(reduction.switch_events ==
              reduction.ingress_switch_events +
                  reduction.proof_message_switch_events);
        CHECK(!schedule.base_proof_noise_assessment.has_value());
    });

    runner.run("honest schedule enforces end-to-end switch calibration", [] {
        const LayeredCircuit circuit = two_multiplication_circuit();
        HonestPayloadNoiseCalibration calibration = honest_calibration();
        const HonestPayloadNoiseSchedule accepted =
            derive_honest_payload_noise_schedule(
                circuit, correction_preserving_chain(), calibration);
        CHECK(accepted.modeled_switch_events >
              accepted.modeled_payload_switch_events);
        calibration.modeled_switch_events_upper_bound =
            accepted.modeled_switch_events;
        const HonestPayloadNoiseSchedule exact =
            derive_honest_payload_noise_schedule(
                circuit, correction_preserving_chain(), calibration);
        CHECK(exact.modeled_switch_events ==
              calibration.modeled_switch_events_upper_bound);

        --calibration.modeled_switch_events_upper_bound;
        CHECK(throws_invalid_argument([&] {
            (void)derive_honest_payload_noise_schedule(
                circuit, correction_preserving_chain(), calibration);
        }));
    });

    return runner.summary();
}
