#ifndef LAMINATE_BENCH_SCHEDULE_COST_HPP
#define LAMINATE_BENCH_SCHEDULE_COST_HPP

/// @file schedule_cost.hpp
/// @brief Circuit-only operation formulas for the three Laminate provers.

#include "laminate/payload/ir/layered.hpp"

#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>

namespace laminate::bench {

enum class ScheduleProtocol : std::uint8_t { Base, Folded, Laned };

/// Logical calls made by the prover schedule. Counts are
/// conservative where the implementation elides structurally zero gate terms.
/// The packing subset fields are included in the corresponding total fields.
struct ScheduleOperations {
    std::uint64_t weighted_base_terms = 0;
    /// Subset whose extension weight varies by SIMD slot and depends on an
    /// online transcript challenge.  Fixed masks and uniform scalars are not
    /// included: their NTT representation can be prepared ahead of proving.
    std::uint64_t online_vector_weighted_base_terms = 0;
    std::uint64_t weighted_base_accumulations = 0;
    std::uint64_t base_ciphertext_multiplications = 0;
    std::uint64_t base_additions = 0;
    std::uint64_t base_subtractions = 0;
    std::uint64_t base_negations = 0;
    std::uint64_t base_rotations = 0;
    std::uint64_t extension_plain_multiplications = 0;
    /// Multiplication of an extension ciphertext by one preprocessed
    /// base-field SIMD basis. One logical call expands to R base
    /// ciphertext--plaintext products, rather than the R^2 products of a
    /// general F_{p^R} plaintext multiplication.
    std::uint64_t prepared_base_slot_extension_multiplications = 0;
    /// Subset using an online, slot-varying extension plaintext.  One logical
    /// operation has R plaintext components, each reusable across R encrypted
    /// extension components.
    std::uint64_t online_vector_extension_plain_multiplications = 0;
    std::uint64_t extension_ciphertext_multiplications = 0;
    std::uint64_t extension_additions = 0;
    std::uint64_t extension_subtractions = 0;
    std::uint64_t extension_rotations = 0;
    std::uint64_t extension_folds = 0;
    std::uint64_t extension_relinearizations = 0;

    std::uint64_t witness_base_plain_multiplications = 0;
    std::uint64_t witness_base_additions = 0;
    /// Extension-field values carried by aligned BhIP round ciphertexts.
    std::uint64_t round_extension_values = 0;
    /// One aligned ciphertext emitted for each ordinary or terminal BhIP round.
    std::uint64_t aligned_round_ciphertexts = 0;
    std::uint64_t logical_rounds = 0;
    std::uint64_t terminal_messages = 0;

    bool operator==(const ScheduleOperations &other) const = default;
};

struct ScheduleLayerFormula {
    std::size_t layer = 0;
    payload::LayerKind kind = payload::LayerKind::Affine;
    /// Nonpadding source-wire positions in the protocol relation. Aliasing
    /// does not reduce this count.
    std::size_t source_logical_live_wires = 0;
    /// Distinct FheValue records physically present in the compact source
    /// trace, including public plaintext constants.
    std::size_t source_stored_values = 0;
    /// Subset of `source_stored_values` that actually contains ciphertexts.
    /// Only these values incur proof-ingress modulus switching.
    std::size_t source_encrypted_ciphertexts = 0;
    /// Source-wire positions in the protocol's power-of-two MLE domain.
    /// Positions absent from `source_logical_live_wires` are structural
    /// padding and have no stored value.
    std::size_t source_virtual_wire_positions = 0;
    /// Distinct operand values materialized for the reduction source.
    /// Setup-derived aliases can make this smaller than the logical source.
    std::size_t source_materialized_packed_ciphertexts = 0;
    /// Materialized operands referenced more than once. The alias-aware
    /// sequential reader retains exactly this many values across a scan.
    std::size_t source_reused_packed_ciphertexts = 0;
    /// Positions in the packed power-of-two protocol domain.
    std::size_t source_virtual_packed_positions = 0;
    /// Variables in the wire-index reduction domain. In a Laned
    /// multiplication layer this is the output packed domain, whose two
    /// operands occupy the source packed domain above.
    std::size_t reduction_domain_variables = 0;
    std::size_t slot_variables = 0;
    ScheduleOperations operations;
    /// Multiplication slot rounds, excluding checkpoints and terminal openings.
    ScheduleOperations multiplication_slot_rounds;
};

struct ScheduleFormula {
    ScheduleProtocol protocol = ScheduleProtocol::Folded;
    ScheduleOperations operations;
    ScheduleOperations multiplication_slot_rounds;
    std::vector<ScheduleLayerFormula> layers;
};

/// Dense base-ciphertext expansion of ScheduleOperations for the degree-eight
/// extension implementation. Plain products, additions, and negations are
/// conservative upper bounds: structurally zero coefficients and zero
/// challenge-derived weights let a backend elide work. It excludes transport
/// modulus switching. A transparent raw-ciphertext result is an invariant
/// failure; public zero belongs in `fhe::FheValue` and has no backend cost.
struct ConcretePrimitiveUpperBound {
    std::uint64_t plain_multiplications = 0;
    /// Base-ciphertext products whose plaintext is an online SIMD vector.
    /// This is a subset of `plain_multiplications`.
    std::uint64_t online_vector_plain_multiplications = 0;
    /// Distinct online SIMD plaintexts requiring conversion to the current
    /// ciphertext-modulus NTT representation.  This can be smaller than the
    /// preceding product count because one extension plaintext component is
    /// reused across all encrypted extension components.
    std::uint64_t online_vector_plaintext_preparations = 0;
    std::uint64_t ciphertext_multiplications_no_relinearization = 0;
    std::uint64_t relinearizations = 0;
    /// Portable dense-reduction upper bound. The Mock backend negates once
    /// for each nonzero reduction target; SEAL negates a high coefficient
    /// once and reuses it for both nonzero terms of x^8 + x^3 + 1.
    std::uint64_t negations = 0;
    std::uint64_t additions = 0;
    /// Explicit base-field subtractions in the schedule. This intentionally
    /// excludes coefficientwise extension subtraction and test-backend
    /// structural-zero synthesis, so it is not an upper bound on every
    /// backend subtraction call.
    std::uint64_t subtractions = 0;
    std::uint64_t rotations = 0;

    bool operator==(const ConcretePrimitiveUpperBound &other) const = default;
};

enum class FormulaComparisonStatus : std::uint8_t {
    Match,
    ExpectedDelta,
    Investigate,
};

ScheduleFormula folded_schedule_formula(
    const payload::LayeredCircuit &circuit);
ScheduleFormula laned_schedule_formula(
    const payload::LayeredCircuit &circuit);
ScheduleFormula base_schedule_formula(
    const payload::LayeredCircuit &circuit);

ConcretePrimitiveUpperBound concrete_primitive_upper_bound(
    const ScheduleOperations &operations, std::size_t slot_count);
FormulaComparisonStatus compare_measured_to_upper_bound(
    std::uint64_t measured, std::uint64_t upper_bound);
std::string_view comparison_status_name(FormulaComparisonStatus status);
std::string_view schedule_protocol_name(ScheduleProtocol protocol);

} // namespace laminate::bench

#endif // LAMINATE_BENCH_SCHEDULE_COST_HPP
