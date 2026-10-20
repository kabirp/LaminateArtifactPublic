#include "laminate/bench/packed_checkpoint_policy.hpp"

#include "test_helpers.hpp"

#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <limits>

using namespace laminate;

namespace {

template <typename Exception, typename Function>
bool throws_as(Function &&function) {
    try {
        function();
        return false;
    } catch (const Exception &) {
        return true;
    }
}

gates::GateTableVerifierKey key_with_widths(
    std::initializer_list<std::size_t> widths) {
    gates::GateTableVerifierKey key;
    key.layout.table_set = gates::GateTableSet::Laned;
    for (const std::size_t width : widths) {
        key.layout.tables.push_back(gates::GateTableDescriptor{});
        key.tables.push_back(gates::SparseTableCommitment{
            .physical_width = width,
        });
    }
    return key;
}

void check_aggregates_all_rows_and_tables() {
    CHECK(bench::packed_gate_mle_target_cell_limit(
              key_with_widths({3, 5, 11})) == 38);
    CHECK(bench::packed_gate_mle_target_cell_limit(key_with_widths({})) == 0);
    auto wide = key_with_widths({3, 5, 11});
    wide.layout.table_set = gates::GateTableSet::Wide;
    wide.layout.wide_layers.resize(3);
    CHECK(bench::packed_gate_mle_target_cell_limit(wide) == 24U * 3U * 19U);
}

void check_rejects_mismatched_table_shapes() {
    gates::GateTableVerifierKey key = key_with_widths({3});
    key.layout.tables.clear();
    CHECK(throws_as<std::invalid_argument>([&] {
        (void)bench::packed_gate_mle_target_cell_limit(key);
    }));
}

void check_rejects_checked_arithmetic_overflow() {
    if constexpr (std::numeric_limits<std::size_t>::digits >=
                  std::numeric_limits<std::uint64_t>::digits) {
        CHECK(throws_as<std::overflow_error>([] {
            (void)bench::packed_gate_mle_target_cell_limit(
                key_with_widths({
                    static_cast<std::size_t>(
                        std::numeric_limits<std::uint64_t>::max() / 2U +
                        1U),
                }));
        }));

        CHECK(throws_as<std::overflow_error>([] {
            (void)bench::packed_gate_mle_target_cell_limit(
                key_with_widths({
                    static_cast<std::size_t>(
                        std::numeric_limits<std::uint64_t>::max() / 2U),
                    1,
                }));
        }));
    }
}

} // namespace

int main() {
    laminate::test::Runner runner("Packed checkpoint codec policy");
    runner.run("aggregates GateMLE target cells across rows and tables",
               check_aggregates_all_rows_and_tables);
    runner.run("rejects mismatched GateMLE table shapes",
               check_rejects_mismatched_table_shapes);
    runner.run("rejects GateMLE target-cell arithmetic overflow",
               check_rejects_checked_arithmetic_overflow);
    return runner.summary();
}
