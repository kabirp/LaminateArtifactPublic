#ifndef LAMINATE_BENCHES_GATE_MLE_REPORT_POLICY_HPP
#define LAMINATE_BENCHES_GATE_MLE_REPORT_POLICY_HPP

#include "laminate/gates/table_types.hpp"
#include <string_view>

namespace laminate::bench {
inline std::string_view gate_mle_strategy_name(
    const gates::GateTableVerifierKey &key) {
    return key.layout.table_set == gates::GateTableSet::Wide
        ? "wide-local-adjoint-foldable" : "structured-sparse-basefold";
}
inline std::size_t gate_mle_query_count(
    const gates::GateTableVerifierKey &key) {
    return key.layout.table_set == gates::GateTableSet::Wide
        ? key.foldable_parameters.num_queries
        : key.basefold_parameters.num_queries;
}
} // namespace laminate::bench
#endif
