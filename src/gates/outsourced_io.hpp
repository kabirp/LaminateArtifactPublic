#ifndef LAMINATE_GATES_OUTSOURCED_IO_HPP
#define LAMINATE_GATES_OUTSOURCED_IO_HPP

/// @file outsourced_io.hpp
/// @brief Private transcript encoders for outsourced gate claims.

#include "laminate/gates/outsourced.hpp"

namespace laminate::gates::detail {

void observe_claim(const RecordedGateQuery &query, const Fpk &value,
                   Transcript &transcript);
void observe_targets(std::size_t table_selector,
                     const basefold::ColumnTargets &targets,
                     Transcript &transcript);

} // namespace laminate::gates::detail

#endif // LAMINATE_GATES_OUTSOURCED_IO_HPP
