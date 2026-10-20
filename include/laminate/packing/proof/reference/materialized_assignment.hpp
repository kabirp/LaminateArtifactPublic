#ifndef LAMINATE_PACKING_PROOF_REFERENCE_MATERIALIZED_ASSIGNMENT_HPP
#define LAMINATE_PACKING_PROOF_REFERENCE_MATERIALIZED_ASSIGNMENT_HPP

/// @file materialized_assignment.hpp
/// @brief Test-only adapter from an owning outer assignment to Spartan.
///
/// Production proving borrows ciphertext slices and keeps known-zero regions
/// implicit. This adapter exists for small materialized reference circuits and
/// tests that deliberately mutate auxiliary witness values.

#include "laminate/packing/proof/r1cs.hpp"

namespace laminate::packing::reference {

spartan::R1csAssignment make_materialized_proof_of_packing_assignment(
    const OuterRelationPlan &plan,
    std::span<const gkr::HashCommitCT> commitments,
    const OuterRelationR1csAssignment &packing_assignment);

} // namespace laminate::packing::reference

#endif // LAMINATE_PACKING_PROOF_REFERENCE_MATERIALIZED_ASSIGNMENT_HPP
