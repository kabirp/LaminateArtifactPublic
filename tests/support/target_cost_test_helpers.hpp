#ifndef LAMINATE_TESTS_TARGET_COST_TEST_HELPERS_HPP
#define LAMINATE_TESTS_TARGET_COST_TEST_HELPERS_HPP

/// @file target_cost_test_helpers.hpp
/// @brief Real-SEAL checks for the independently derived RNS cost ledger.

#include "test_helpers.hpp"

#include "laminate/bench/target_cost.hpp"
#include "laminate/fhe/seal_backend.hpp"

#include <cstddef>
#include <cstdint>
#include <limits>

namespace laminate::test {

inline std::uint64_t seal_calls_at(
    const fhe::SealBackend::OperationCounts &counts,
    fhe::SealBackend::OperationKind kind, std::size_t rns_limbs) {
    const auto &buckets = counts.buckets(kind);
    const auto found = buckets.find(rns_limbs);
    return found == buckets.end() ? 0 : found->second;
}

/// Check each modeled primitive at the RNS level where SEAL actually ran it.
/// The public-or-encrypted value layer removes structurally public zeros
/// before this raw-ciphertext ledger; no encryption work is hidden here.
inline void check_seal_operation_ledger(
    const fhe::SealBackend::OperationCounts &measured,
    const bench::ProverOperationLedger &ledger) {
    using Kind = fhe::SealBackend::OperationKind;
    std::uint64_t rotation_limb_upper_bound = 0;
    for (const bench::RnsLevelOperations &row : ledger.levels) {
        const std::size_t limbs = row.rns_limbs;
        const bench::ConcretePrimitiveUpperBound &upper = row.primitives;
        const auto check_upper = [&](const char *name,
                                     std::uint64_t actual,
                                     std::uint64_t bound) {
            if (actual <= bound) {
                return;
            }
            std::ostringstream message;
            message << name << " formula mismatch at " << limbs
                    << " limbs: measured " << actual << ", upper bound "
                    << bound;
            throw CheckFailure(message.str());
        };
        check_upper(
            "plaintext multiplication",
            seal_calls_at(measured, Kind::MulPlainScalar, limbs) +
                seal_calls_at(measured, Kind::MulPlainVector, limbs),
            upper.plain_multiplications);
        check_upper("ciphertext multiplication",
                    seal_calls_at(measured, Kind::MulNoRelin, limbs),
                    upper.ciphertext_multiplications_no_relinearization);
        check_upper("relinearization",
                    seal_calls_at(measured, Kind::Relinearize, limbs),
                    upper.relinearizations);
        check_upper("additive operation",
                    seal_calls_at(measured, Kind::Negate, limbs) +
                        seal_calls_at(measured, Kind::Add, limbs) +
                        seal_calls_at(measured, Kind::Sub, limbs),
                    upper.negations + upper.additions + upper.subtractions);
        if (upper.rotations >
            (std::numeric_limits<std::uint64_t>::max() -
             rotation_limb_upper_bound) /
                limbs) {
            throw CheckFailure("rotation limb-operation bound overflows");
        }
        rotation_limb_upper_bound += upper.rotations * limbs;
        const std::uint64_t switches =
            seal_calls_at(measured, Kind::ModSwitch, limbs);
        if (switches < row.modulus_switches) {
            std::ostringstream message;
            message << "modulus-switch formula undercounts execution at "
                    << limbs << " limbs: measured " << switches
                    << ", algorithmic minimum " << row.modulus_switches
                    << "; measured buckets";
            for (const auto &[bucket, count] :
                 measured.buckets(Kind::ModSwitch)) {
                message << ' ' << bucket << ':' << count;
            }
            throw CheckFailure(message.str());
        }
    }
    // Adaptive transport compaction can move an alignment rotation between
    // levels. Its total limb work must remain below the formula, which charges
    // every such rotation at the highest possible level.
    if (measured.limb_operations(Kind::Rotate) >
        rotation_limb_upper_bound) {
        std::ostringstream message;
        message << "rotation limb-operation formula mismatch: measured "
                << measured.limb_operations(Kind::Rotate)
                << ", upper bound " << rotation_limb_upper_bound;
        throw CheckFailure(message.str());
    }
}

} // namespace laminate::test

#endif // LAMINATE_TESTS_TARGET_COST_TEST_HELPERS_HPP
