/// @file test_honest_finalization.cpp
/// @brief Exact checks for the selected BGV finalization recurrence.

#include "test_helpers.hpp"

#include "laminate/packing/analysis/honest_finalization.hpp"

#include <array>
#include <cstdint>

using namespace laminate;
using namespace laminate::packing;

namespace {

// First three stable data primes generated for N=2^14, t=65537, and 60-bit
// limbs. The separate larger special prime is not part of finalization.
constexpr std::uint64_t kQ0 = kOuterFieldOrder;
constexpr std::uint64_t kQ1 = 1'152'921'409'847'689'217ULL;
constexpr std::uint64_t kQ2 = 1'152'921'396'962'590'721ULL;

HonestFinalizationPolicy target_policy() {
    return HonestFinalizationPolicy{
        .plaintext_modulus = kBaseFieldOrder,
        .secret_hamming_weight_upper = kDefaultPolyModulusDegree,
        .target_error_bound = kSelectedPackingHonestErrorBound,
        .final_rounding_reserve = kPackingFinalRoundingErrorBound,
    };
}

} // namespace

int main() {
    test::Runner runner("test_honest_finalization");

    runner.run("selected target pins the deterministic allowance", [] {
        const auto assessment = assess_observed_honest_finalization(
            target_policy(), std::array{kQ0, kQ1},
            ObservedInvariantNoiseEvidence{
                .invariant_noise_budget_bits = 80,
            });

        CHECK(assessment.proven_per_switch_rounding_bound == 16'385);
        CHECK(assessment.selected_final_rounding_reserve == 16'386);
        CHECK(assessment.selected_scaled_inherited_allowance == 1'395);
        CHECK(assessment.switches.size() == 1);
        CHECK(assessment.switches.front().scaled_inherited_error_bound == 1);
        CHECK(assessment.final_error_bound == 16'386);
        CHECK(assessment.minimum_required_invariant_noise_budget_bits == 33);
        CHECK(assessment.certifies_observed_finalization());
    });

    runner.run("two reserved drops crush earlier rounding", [] {
        const auto assessment = assess_observed_honest_finalization(
            target_policy(), std::array{kQ0, kQ1, kQ2},
            ObservedInvariantNoiseEvidence{
                .invariant_noise_budget_bits = 157,
            });

        CHECK(assessment.switches.size() == 2);
        CHECK(assessment.switches[0].input_limb_count == 3);
        CHECK(assessment.switches[1].input_limb_count == 2);
        CHECK(assessment.switches[0].pre_switch_no_wrap);
        CHECK(assessment.switches[1].pre_switch_no_wrap);
        CHECK(assessment.final_scaled_inherited_error_bound == 1);
        CHECK(assessment.final_error_bound == 16'386);
        CHECK(assessment.minimum_required_invariant_noise_budget_bits == 33);
        CHECK(assessment.certifies_observed_finalization());
    });

    runner.run("minimum budget is an executable fail-closed frontier", [] {
        const std::array moduli{kQ0, kQ1, kQ2};
        const auto ample = assess_observed_honest_finalization(
            target_policy(), moduli,
            ObservedInvariantNoiseEvidence{
                .invariant_noise_budget_bits = 157,
            });
        const std::size_t minimum =
            ample.minimum_required_invariant_noise_budget_bits;
        CHECK(minimum > 1);
        CHECK(minimum < 157);

        const auto boundary = assess_observed_honest_finalization(
            target_policy(), moduli,
            ObservedInvariantNoiseEvidence{
                .invariant_noise_budget_bits = minimum,
            });
        CHECK(boundary.certifies_observed_finalization());

        const auto below = assess_observed_honest_finalization(
            target_policy(), moduli,
            ObservedInvariantNoiseEvidence{
                .invariant_noise_budget_bits = minimum - 1,
            });
        CHECK(!below.certifies_observed_finalization());
    });

    runner.run("zero invariant budget never certifies", [] {
        const auto assessment = assess_observed_honest_finalization(
            target_policy(), std::array{kQ0, kQ1},
            ObservedInvariantNoiseEvidence{
                .invariant_noise_budget_bits = 0,
            });
        CHECK(!assessment.input_noise_budget_positive);
        CHECK(!assessment.certifies_observed_finalization());
    });

    runner.run("undersized rounding reserve fails closed", [] {
        HonestFinalizationPolicy policy = target_policy();
        policy.final_rounding_reserve = 100;
        const auto assessment = assess_observed_honest_finalization(
            policy, std::array{kQ0, kQ1},
            ObservedInvariantNoiseEvidence{
                .invariant_noise_budget_bits = 80,
            });
        CHECK(!assessment.rounding_reserve_is_sufficient);
        CHECK(!assessment.certifies_observed_finalization());
    });

    return runner.summary();
}
