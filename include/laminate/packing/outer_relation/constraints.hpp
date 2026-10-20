#ifndef LAMINATE_PACKING_OUTER_RELATION_CONSTRAINTS_HPP
#define LAMINATE_PACKING_OUTER_RELATION_CONSTRAINTS_HPP

/// @file constraints.hpp
/// @brief Allocation-free typed rows for the native-Q outer relation.

#include "laminate/packing/outer_relation/relation.hpp"

#include <cstddef>
#include <cstdint>
#include <variant>

namespace laminate::packing {

struct OuterRelationPublicVariable {
    std::uint64_t index = 0;
    bool operator==(const OuterRelationPublicVariable &) const = default;
};

struct OuterRelationWitnessVariable {
    std::uint64_t index = 0;
    bool operator==(const OuterRelationWitnessVariable &) const = default;
};

/// One R1CS row enforcing `b * (b-1) = 0`.
struct ChallengeBitBooleanityConstraint {
    OuterRelationWitnessVariable bit;
};

/// One linear row enforcing `word = sum_j 2^j bit_j`.
struct ChallengeWordRecompositionConstraint {
    OuterRelationPublicVariable packed_word;
    OuterRelationWitnessVariable first_bit;
    std::size_t bit_count = 0;
};

/// One online product row
/// `(b_plus-b_minus) * aligned_coordinate = product`.
struct WellFormednessProductConstraint {
    OuterRelationWitnessVariable plus_bit;
    OuterRelationWitnessVariable minus_bit;
    OuterRelationWitnessVariable aligned_coordinate;
    OuterRelationWitnessVariable product;
};

/// One linear row `revealed_test = sum_i product_i`.
///
/// Products for successive aligned ciphertexts are separated by
/// `product_stride` witness positions.
struct RevealedTestEqualityConstraint {
    OuterRelationPublicVariable revealed_coordinate;
    OuterRelationWitnessVariable first_product;
    std::uint64_t product_stride = 0;
    std::size_t product_count = 0;
};

/// One fixed linear base-17 row. The native packing operator supplies the
/// preprocessed NTT constants and aligned-input ownership for this row.
struct RevealedPackingEqualityConstraint {
    OuterRelationPublicVariable revealed_coordinate;
    std::size_t logical_output = 0;
    std::size_t digit = 0;
    std::size_t component = 0;
    std::size_t ntt_coordinate = 0;
};

using OuterRelationConstraintEquation = std::variant<
    ChallengeBitBooleanityConstraint,
    ChallengeWordRecompositionConstraint,
    WellFormednessProductConstraint,
    RevealedTestEqualityConstraint,
    RevealedPackingEqualityConstraint>;

enum class OuterRelationConstraintFamily : std::uint8_t {
    ChallengeBitBooleanity,
    ChallengeWordRecomposition,
    WellFormednessProduct,
    RevealedTestEquality,
    RevealedPackingEquality,
};

/// One row in the canonical constraint order.
struct OuterRelationConstraintDescriptor {
    std::uint64_t index = 0;
    OuterRelationConstraintFamily family =
        OuterRelationConstraintFamily::ChallengeBitBooleanity;
    OuterRelationConstraintEquation equation;
};

/// Decode one target-scale row without allocating neighboring rows.
OuterRelationConstraintDescriptor describe_outer_relation_constraint(
    const OuterRelationPlan &plan, std::uint64_t constraint_index);

/// Forward-only allocation-free cursor over the canonical row order.
class OuterRelationConstraintCursor {
  public:
    explicit OuterRelationConstraintCursor(const OuterRelationPlan &plan);
    OuterRelationConstraintCursor(const OuterRelationPlan &plan,
                                  std::uint64_t begin,
                                  std::uint64_t end);

    bool empty() const;
    std::uint64_t position() const;
    std::uint64_t remaining() const;

    /// Return the current descriptor and advance by one row.
    /// Throws `std::out_of_range` after the selected range is exhausted.
    OuterRelationConstraintDescriptor next();

  private:
    OuterRelationPlan plan_;
    std::uint64_t cursor_ = 0;
    std::uint64_t end_ = 0;
};

} // namespace laminate::packing

#endif // LAMINATE_PACKING_OUTER_RELATION_CONSTRAINTS_HPP
