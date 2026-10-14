#ifndef LAMINATE_PACKING_OUTER_RELATION_PACKING_R1CS_HPP
#define LAMINATE_PACKING_OUTER_RELATION_PACKING_R1CS_HPP

/// @file packing_r1cs.hpp
/// @brief Bounded-memory R1CS stream for the fixed packing matrix.

#include "laminate/packing/outer_relation/r1cs.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace laminate::packing {

/// Which sparse matrix receives one coordinate triple.
enum class OuterRelationR1csMatrix : std::uint8_t { A, B, C };

/// One nonzero entry of a sparse R1CS matrix.
///
/// Unlike `OuterRelationR1csRow`, entries need not arrive in row order. This
/// lets preprocessing consume one SEAL plaintext NTT vector at a time instead
/// of retaining or transposing the complete `r * d * N` constant matrix.
struct OuterRelationR1csMatrixEntry {
    OuterRelationR1csMatrix matrix = OuterRelationR1csMatrix::A;
    std::uint64_t constraint_index = 0;
    OuterRelationR1csVariable variable;
    std::uint64_t coefficient = 0;

    bool operator==(const OuterRelationR1csMatrixEntry &) const = default;
};

/// Exact payload comparison between the reference materialized operator and the
/// bounded-memory stream. Container metadata and encoder-internal scratch are
/// intentionally excluded from both byte counts. The streamed count covers
/// the retained `d` signed-digit vectors and one native NTT vector; transient
/// position masks and centered lifts are also excluded.
struct FixedPackingR1csStorageEstimate {
    std::uint64_t materialized_multiplier_coordinates = 0;
    std::uint64_t materialized_multiplier_bytes = 0;
    std::uint64_t streamed_digit_and_ntt_coordinates = 0;
    std::uint64_t streamed_digit_and_ntt_bytes = 0;
};

FixedPackingR1csStorageEstimate estimate_fixed_packing_r1cs_storage(
    const OuterRelationPlan &plan);

/// Progress and exact entry counts observed while streaming.
struct FixedPackingR1csStreamStatistics {
    std::uint64_t aligned_masks_encoded = 0;
    std::uint64_t native_digit_polynomials_encoded = 0;
    std::uint64_t a_nonzero_entries = 0;
    std::uint64_t b_nonzero_entries = 0;
    std::uint64_t c_nonzero_entries = 0;
    std::uint64_t total_nonzero_entries = 0;
    bool complete = false;
};

/// Contribution-major stream of the fixed signed-base-17 R1CS submatrix.
///
/// The cursor emits all nonzero `A` entries in canonical
/// `(logical output, aligned input, digit, NTT coordinate, component)` order,
/// followed by the row-ordered unit entries of `B` and `C`. Matrix consumers
/// must therefore accept coordinate triples whose row indices are not
/// monotone. Every row index and variable index still follows
/// `OuterRelationPlan` exactly.
///
/// Preconditions:
/// - `plan` and `packing_operator` describe the same `N`, `r`, output count,
///   and signed-digit count;
/// - both public encoders are deterministic and use the plan's final native
///   modulus; and
/// - the referenced plan/operator outlive the cursor.
///
/// Postcondition after exhaustion: every fixed packing R1CS entry has been
/// emitted exactly once, zero `A` coefficients have been omitted, and
/// `statistics().complete` is true.
class FixedPackingR1csEntryCursor {
  public:
    struct Encoders {
        PlaintextCoefficientEncoder centered_coefficients;
        NativePlaintextNttEncoder native_ntt;
    };

    FixedPackingR1csEntryCursor(
        const OuterRelationPlan &plan,
        const PackingLinearOperator &packing_operator,
        Encoders encoders, BalancedRadix radix);

    FixedPackingR1csEntryCursor(const FixedPackingR1csEntryCursor &) = delete;
    FixedPackingR1csEntryCursor &operator=(
        const FixedPackingR1csEntryCursor &) = delete;

    bool empty() const;
    OuterRelationR1csMatrixEntry next();

    const FixedPackingR1csStreamStatistics &statistics() const;

  private:
    struct ContributionReference {
        std::size_t logical_output = 0;
        const PackingLinearOperator::AlignedCiphertext *aligned = nullptr;
    };

    enum class Stage : std::uint8_t { PackingA, PackingB, PackingC, Done };

    std::optional<OuterRelationR1csMatrixEntry> next_a_entry();
    OuterRelationR1csMatrixEntry next_unit_entry(
        OuterRelationR1csMatrix matrix);
    void load_contribution();
    void load_digit_polynomial();

    const OuterRelationPlan *plan_ = nullptr;
    const PackingLinearOperator *packing_operator_ = nullptr;
    Encoders encoders_;
    BalancedRadix radix_;
    std::vector<ContributionReference> contributions_;

    Stage stage_ = Stage::PackingA;
    std::size_t contribution_index_ = 0;
    std::size_t digit_index_ = 0;
    std::size_t ntt_coordinate_ = 0;
    std::size_t component_ = 0;
    bool contribution_loaded_ = false;
    bool digit_polynomial_loaded_ = false;
    std::vector<SignedCoefficientMask> digit_masks_;
    std::vector<std::uint64_t> native_digit_polynomial_;
    std::uint64_t aligned_witness_base_ = 0;
    std::uint64_t digit_constraint_base_ = 0;
    std::uint64_t unit_row_offset_ = 0;
    FixedPackingR1csStreamStatistics statistics_;
};

} // namespace laminate::packing

#endif // LAMINATE_PACKING_OUTER_RELATION_PACKING_R1CS_HPP
