#include "test_helpers.hpp"
#include "laminate/basefold/foldable.hpp"
#include "laminate/basefold/foldable_query_policy.hpp"

#include <limits>

namespace fb = laminate::basefold::foldable;

int main() {
    laminate::test::Runner runner("test_foldable_query_policy");
    runner.run("every admitted shape enforces its explicit query count", [] {
        for (std::size_t variables = 0; variables <= fb::kMaxVariables;
             ++variables) {
            const auto m = std::size_t{1} << variables;
            const auto queries = fb::minimum_queries(m);
            const fb::Metadata meta{{}, m, 1};
            CHECK(queries >= 226 && queries <= 295);
            CHECK(fb::admitted_query_count(m, queries));
            CHECK(!fb::admitted_query_count(m, queries - 1));
            CHECK(!fb::admitted_query_count(m, 0));
            CHECK(fb::valid_shape(meta, fb::Parameters{queries}));
            CHECK(!fb::valid_shape(meta, fb::Parameters{queries - 1}));
            CHECK(fb::valid_shape(meta));
            CHECK(fb::valid_shape(meta, fb::Parameters{350}));
            CHECK(fb::conservative_rbr_soundness_bits(
                meta, fb::Parameters{queries}) == 110);
            CHECK(fb::admitted_query_count(m, 65536));
            CHECK(!fb::admitted_query_count(m, 65537));
        }
        CHECK(fb::minimum_queries(1) == 226);
        CHECK(fb::minimum_queries(std::size_t{1} << 13) == 226);
        CHECK(fb::minimum_queries(std::size_t{1} << 14) == 228);
        CHECK(fb::minimum_queries(std::size_t{1} << 31) == 266);
        CHECK(fb::minimum_queries(std::size_t{1} << 40) == 295);
    });
    runner.run("unsupported dimensions do not obtain a certificate", [] {
        for (const auto m : {std::size_t{0}, std::size_t{3},
                             (std::size_t{1} << 40) + 1,
                             std::size_t{1} << 41,
                             std::numeric_limits<std::size_t>::max()}) {
            CHECK(fb::minimum_queries(m) == 0);
            CHECK(!fb::admitted_query_count(m, 300));
            CHECK(!fb::valid_shape(fb::Metadata{{}, m, 1}));
        }
    });
    return runner.summary();
}
