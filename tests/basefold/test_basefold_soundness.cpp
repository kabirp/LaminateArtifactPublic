#include "test_helpers.hpp"
#include "laminate/basefold/soundness.hpp"
#include "laminate/params.hpp"

#include <limits>

using namespace laminate;

int main() {
    test::Runner runner("test_basefold_soundness");
    runner.run("selected policy meets the RBR target in both fields", [] {
        CHECK(kTargetSecurityBits == 110);
        CHECK(kGateMleBaseFoldLogRate == 3);
        CHECK(kGateMleBaseFoldQueries == 150);
        CHECK(kTranscriptPackingBaseFoldLogRate == 3);
        CHECK(kTranscriptPackingBaseFoldQueries == 150);
        // q >=3*2^58 implies q^2 >=9*2^116 >2^119.
        CHECK(kOuterFieldOrder >= 3ULL * (1ULL << 58U));
        for (const std::size_t n : {0U, 1U, 13U, 32U, 34U}) {
            const auto packing = basefold::conservative_rbr_soundness_bound(
                n, 0, 3, 150, 119);
            CHECK(packing.folding_bits == 110);
            CHECK(packing.query_bits == 112);
            CHECK(packing.rbr_bits == kBaseFoldIntegrityTargetBits);
            const auto gates = basefold::conservative_rbr_soundness_bound(
                n, 23, 3, 150, 128);
            CHECK(gates.folding_bits == 119);
            CHECK(gates.batching_bits == 123);
            CHECK(gates.rbr_bits == 112);
        }
    });
    runner.run("query rounding follows exact rational inequalities", [] {
        // After <=34 folds: miss <=77775/131072 <19/32.
        CHECK(77775ULL * 32U < 19ULL * 131072U);
        CHECK(19U * 19U * 2U < 32U * 32U);
        CHECK(19U * 19U * 19U * 4U < 32U * 32U * 32U);
        CHECK(19U * 19U * 19U * 19U * 8U < 32U * 32U * 32U * 32U);
        const std::size_t expected[] = {0, 0, 1, 2, 3, 3, 4, 5, 6};
        for (std::size_t q = 1; q < 9; ++q) {
            CHECK(basefold::conservative_rbr_soundness_bound(34, 0, 3, q, 119)
                      .query_bits == expected[q]);
        }
        CHECK(basefold::conservative_rbr_soundness_bound(34, 0, 3, 147, 119)
                  .rbr_bits == 110);
        CHECK(basefold::conservative_rbr_soundness_bound(34, 0, 3, 146, 119)
                  .rbr_bits < 110);
        CHECK(basefold::conservative_rbr_soundness_bound(34, 0, 3, 133, 119)
                  .rbr_bits < 110);
        // Query count cannot amplify the finite-field folding transition.
        CHECK(basefold::conservative_rbr_soundness_bound(34, 0, 3, 1000, 119)
                  .rbr_bits == 110);
    });
    runner.run("batch degree and unsupported shapes are enforced", [] {
        CHECK(basefold::conservative_rbr_soundness_bound(13, 65, 3, 150, 128)
                  .rbr_bits >= 110);
        // Powers-of-one-challenge batching at this width would miss the target.
        CHECK(basefold::conservative_rbr_soundness_bound(
                  13, std::size_t{1} << 22U, 3, 150, 128).rbr_bits == 106);
        CHECK(basefold::conservative_rbr_soundness_bound(35, 0, 3, 150, 119)
                  .rbr_bits == 0);
        CHECK(basefold::conservative_rbr_soundness_bound(32, 0, 1, 150, 119)
                  .rbr_bits == 0);
        CHECK(basefold::conservative_rbr_soundness_bound(32, 0, 3, 0, 119)
                  .rbr_bits == 0);
        CHECK(basefold::conservative_rbr_soundness_bound(32, 0, 3, 150, 9)
                  .rbr_bits == 0);
        const auto huge = basefold::conservative_rbr_soundness_bound(
            34, 0, 3, std::numeric_limits<std::size_t>::max(), 119);
        CHECK(huge.rbr_bits == 110);
    });
    return runner.summary();
}
