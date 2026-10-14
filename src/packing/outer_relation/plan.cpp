/// @file plan.cpp
/// @brief Target-scale variable and constraint schedule for outer packing.

#include "laminate/packing/outer_relation/relation.hpp"

#include <algorithm>
#include <bit>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

namespace laminate::packing {
namespace {

std::uint64_t checked_size(std::size_t value, const char *label) {
    if (value > std::numeric_limits<std::uint64_t>::max()) {
        throw std::overflow_error(std::string(label) + " exceeds u64");
    }
    return static_cast<std::uint64_t>(value);
}

std::uint64_t checked_add(std::uint64_t left, std::uint64_t right,
                          const char *label) {
    if (right > std::numeric_limits<std::uint64_t>::max() - left) {
        throw std::overflow_error(std::string(label) + " overflows u64");
    }
    return left + right;
}

std::size_t checked_size_product(std::size_t left, std::size_t right,
                                 const char *label) {
    if (left != 0 && right > std::numeric_limits<std::size_t>::max() / left) {
        throw std::overflow_error(std::string(label) + " overflows size_t");
    }
    return left * right;
}

OuterRelationRange append_range(std::uint64_t &cursor,
                                std::uint64_t count,
                                const char *label) {
    const OuterRelationRange result{cursor, count};
    cursor = checked_add(cursor, count, label);
    return result;
}

void validate_shape(const OuterRelationShape &shape) {
    shape.ciphertext_commitment_policy.validate();
    if (shape.native_modulus < 3 || shape.ring_degree == 0 ||
        shape.aligned_ciphertexts == 0 || shape.repetitions == 0 ||
        shape.logical_packed_outputs == 0 ||
        shape.packing_digit_count == 0 ||
        shape.ciphertext_components == 0 ||
        shape.public_input_capacity_bits == 0 ||
        shape.public_input_capacity_bits > 63) {
        throw std::invalid_argument(
            "outer relation: dimensions and native modulus must be nonzero");
    }
    const std::uint64_t packed_word_range =
        std::uint64_t{1} << shape.public_input_capacity_bits;
    if (packed_word_range > shape.native_modulus) {
        throw std::invalid_argument(
            "outer relation: packed challenge word does not fit native field");
    }
}

void require_index(std::size_t index, std::size_t bound,
                   const char *label) {
    if (index >= bound) {
        throw std::out_of_range(std::string("outer relation: ") + label);
    }
}

std::uint64_t flatten_ciphertext_coordinate(
    const OuterRelationPlan &plan, std::size_t ciphertext,
    std::size_t ciphertext_count, std::size_t component,
    std::size_t ntt_coordinate) {
    require_index(ciphertext, ciphertext_count, "ciphertext index");
    require_index(component, plan.shape.ciphertext_components,
                  "component index");
    require_index(ntt_coordinate, plan.shape.ring_degree,
                  "NTT coordinate");
    const std::uint64_t components = checked_size(
        plan.shape.ciphertext_components, "component count");
    const std::uint64_t degree =
        checked_size(plan.shape.ring_degree, "ring degree");
    return (checked_size(ciphertext, "ciphertext index") * components +
            checked_size(component, "component index")) *
               degree +
           checked_size(ntt_coordinate, "NTT coordinate");
}

} // namespace

std::uint64_t OuterRelationRange::end() const {
    return checked_add(begin, count, "outer relation range");
}

std::size_t OuterRelationPlan::physical_packed_ciphertexts() const {
    return checked_size_product(shape.logical_packed_outputs,
                                shape.packing_digit_count,
                                "physical packing output count");
}

std::size_t OuterRelationPlan::coordinates_per_ciphertext() const {
    return checked_size_product(shape.ciphertext_components,
                                shape.ring_degree,
                                "ciphertext coordinate count");
}

std::size_t outer_relation_public_input_capacity(
    std::uint64_t native_modulus,
    std::size_t preferred_capacity_bits) {
    if (native_modulus < 3 || preferred_capacity_bits == 0) {
        throw std::invalid_argument(
            "outer relation public-input capacity needs Q >= 3 and a "
            "nonzero preference");
    }
    const std::size_t maximum =
        static_cast<std::size_t>(std::bit_width(native_modulus) - 1U);
    return std::min({preferred_capacity_bits, maximum, std::size_t{63}});
}

std::uint64_t OuterRelationPlan::challenge_bit_witness_index(
    std::size_t test, std::size_t aligned, ChallengeBit bit) const {
    require_index(test, shape.repetitions, "test index");
    require_index(aligned, shape.aligned_ciphertexts,
                  "aligned ciphertext index");
    const std::uint64_t row =
        checked_size(test, "test index") *
            checked_size(shape.aligned_ciphertexts, "aligned count") +
        checked_size(aligned, "aligned index");
    return variables.witness.derived_challenge_bits.begin + row * 2 +
           static_cast<std::uint8_t>(bit);
}

std::uint64_t OuterRelationPlan::aligned_coordinate_witness_index(
    std::size_t aligned, std::size_t component,
    std::size_t ntt_coordinate) const {
    return variables.witness.aligned_ciphertext_coordinates.begin +
           flatten_ciphertext_coordinate(
               *this, aligned, shape.aligned_ciphertexts, component,
               ntt_coordinate);
}

std::uint64_t OuterRelationPlan::product_witness_index(
    std::size_t test, std::size_t aligned, std::size_t component,
    std::size_t ntt_coordinate) const {
    require_index(test, shape.repetitions, "test index");
    const std::uint64_t aligned_coordinate =
        flatten_ciphertext_coordinate(
            *this, aligned, shape.aligned_ciphertexts, component,
            ntt_coordinate);
    const std::uint64_t coordinates_per_test =
        fixed_packing.witness_input_coordinates;
    return variables.witness.well_formedness_products.begin +
           checked_size(test, "test index") * coordinates_per_test +
           aligned_coordinate;
}

std::uint64_t OuterRelationPlan::test_coordinate_public_index(
    std::size_t test, std::size_t component,
    std::size_t ntt_coordinate) const {
    return variables.public_inputs.revealed_test_coordinates.begin +
           flatten_ciphertext_coordinate(
               *this, test, shape.repetitions, component, ntt_coordinate);
}

std::uint64_t OuterRelationPlan::packing_coordinate_public_index(
    std::size_t logical_output, std::size_t digit,
    std::size_t component, std::size_t ntt_coordinate) const {
    require_index(logical_output, shape.logical_packed_outputs,
                  "logical packing output");
    require_index(digit, shape.packing_digit_count, "packing digit");
    const std::size_t physical = checked_size_product(
        logical_output, shape.packing_digit_count,
        "physical packing output index") +
        digit;
    return variables.public_inputs.revealed_packing_coordinates.begin +
           flatten_ciphertext_coordinate(
               *this, physical, physical_packed_ciphertexts(), component,
               ntt_coordinate);
}

OuterRelationPlan make_outer_relation_plan(
    const OuterRelationShape &shape) {
    validate_shape(shape);
    const std::size_t physical_outputs = checked_size_product(
        shape.logical_packed_outputs, shape.packing_digit_count,
        "physical packing output count");

    OuterRelationPlan result;
    result.shape = shape;
    result.well_formedness = estimate_well_formedness_constraints(
        WellFormednessRelationShape{
            .ring_degree = shape.ring_degree,
            .ciphertext_count = shape.aligned_ciphertexts,
            .repetitions = shape.repetitions,
            .ciphertext_components = shape.ciphertext_components,
            .distribution = TestCoefficientDistribution::LazyTernary,
            .public_input_capacity_bits =
                shape.public_input_capacity_bits,
        });
    result.fixed_packing = estimate_fixed_packing_relation(
        FixedPackingRelationShape{
            .ring_degree = shape.ring_degree,
            .aligned_ciphertexts = shape.aligned_ciphertexts,
            .packed_digit_ciphertexts = physical_outputs,
            .digit_count = shape.packing_digit_count,
            .ciphertext_components = shape.ciphertext_components,
        });

    std::uint64_t public_cursor = 0;
    result.variables.public_inputs.packed_challenge_words = append_range(
        public_cursor, result.well_formedness.packed_public_inputs,
        "public challenge words");
    result.variables.public_inputs.revealed_test_coordinates = append_range(
        public_cursor,
        result.well_formedness.revealed_ciphertext_coordinates,
        "public test coordinates");
    result.variables.public_inputs.revealed_packing_coordinates = append_range(
        public_cursor, result.fixed_packing.public_output_coordinates,
        "public packing coordinates");
    result.variables.public_inputs.total = public_cursor;

    std::uint64_t witness_cursor = 0;
    result.variables.witness.derived_challenge_bits = append_range(
        witness_cursor, result.well_formedness.challenge_bits,
        "challenge-bit witnesses");
    result.variables.witness.aligned_ciphertext_coordinates = append_range(
        witness_cursor, result.fixed_packing.witness_input_coordinates,
        "aligned-ciphertext witnesses");
    result.variables.witness.well_formedness_products = append_range(
        witness_cursor, result.well_formedness.coefficient_products,
        "well-formedness product witnesses");
    result.variables.witness.total = witness_cursor;

    std::uint64_t constraint_cursor = 0;
    result.constraints.challenge_bit_booleanity = append_range(
        constraint_cursor, result.well_formedness.booleanity_constraints,
        "challenge booleanity constraints");
    result.constraints.challenge_word_recomposition = append_range(
        constraint_cursor,
        result.well_formedness.public_input_recomposition_constraints,
        "challenge recomposition constraints");
    result.constraints.well_formedness_products = append_range(
        constraint_cursor, result.well_formedness.coefficient_products,
        "well-formedness product constraints");
    result.constraints.revealed_test_equalities = append_range(
        constraint_cursor, result.well_formedness.output_relations,
        "test output constraints");
    result.constraints.revealed_packing_equalities = append_range(
        constraint_cursor,
        result.fixed_packing.output_relation_constraints,
        "packing output constraints");
    result.constraints.total = constraint_cursor;
    return result;
}

void NativePackingOperator::validate(
    const OuterRelationPlan &plan) const {
    if (native_modulus != plan.shape.native_modulus ||
        ring_degree != plan.shape.ring_degree ||
        aligned_ciphertexts != plan.shape.aligned_ciphertexts ||
        logical_outputs != plan.shape.logical_packed_outputs ||
        digit_count != plan.shape.packing_digit_count ||
        rows.size() != plan.physical_packed_ciphertexts()) {
        throw std::invalid_argument(
            "native packing operator does not match outer relation plan");
    }

    const std::size_t no_owner = std::numeric_limits<std::size_t>::max();
    std::vector<std::size_t> logical_owner(aligned_ciphertexts, no_owner);
    std::vector<std::size_t> appearances(aligned_ciphertexts, 0);
    for (std::size_t row_index = 0; row_index < rows.size(); ++row_index) {
        const NativePackingRow &row = rows[row_index];
        if (row.logical_output != row_index / digit_count ||
            row.digit != row_index % digit_count ||
            row.contributions.empty()) {
            throw std::invalid_argument(
                "native packing operator rows are not canonical");
        }
        std::vector<bool> seen(plan.shape.aligned_ciphertexts, false);
        std::size_t previous = 0;
        bool has_previous = false;
        for (const NativePackingContribution &contribution :
             row.contributions) {
            if (contribution.aligned_ciphertext >= seen.size() ||
                seen[contribution.aligned_ciphertext] ||
                (has_previous &&
                 contribution.aligned_ciphertext <= previous) ||
                contribution.multiplier_ntt_coordinates.size() !=
                    ring_degree) {
                throw std::invalid_argument(
                    "native packing operator contribution is malformed");
            }
            seen[contribution.aligned_ciphertext] = true;
            previous = contribution.aligned_ciphertext;
            has_previous = true;
            std::size_t &owner =
                logical_owner[contribution.aligned_ciphertext];
            if (owner == no_owner) {
                owner = row.logical_output;
            } else if (owner != row.logical_output) {
                throw std::invalid_argument(
                    "native packing input occurs in multiple logical rows");
            }
            ++appearances[contribution.aligned_ciphertext];
            for (const std::uint64_t coefficient :
                 contribution.multiplier_ntt_coordinates) {
                if (coefficient >= native_modulus) {
                    throw std::invalid_argument(
                        "native packing multiplier is not a field residue");
                }
            }
        }
    }
    if (std::any_of(appearances.begin(), appearances.end(),
                    [=](std::size_t count) {
                        return count != digit_count;
                    })) {
        throw std::invalid_argument(
            "native packing input is missing from a digit row");
    }
}

OuterRelationPlan make_outer_relation_plan(
    const NativePackingOperator &packing_operator, std::size_t repetitions,
    std::size_t ciphertext_components,
    std::size_t public_input_capacity_bits) {
    OuterRelationPlan result = make_outer_relation_plan(
        OuterRelationShape{
            .native_modulus = packing_operator.native_modulus,
            .ring_degree = packing_operator.ring_degree,
            .aligned_ciphertexts = packing_operator.aligned_ciphertexts,
            .repetitions = repetitions,
            .logical_packed_outputs = packing_operator.logical_outputs,
            .packing_digit_count = packing_operator.digit_count,
            .ciphertext_components = ciphertext_components,
            .public_input_capacity_bits = public_input_capacity_bits,
        });
    packing_operator.validate(result);
    return result;
}

std::uint64_t NativePackingOperator::nonzero_constant_matrix_terms(
    std::size_t ciphertext_components) const {
    if (ciphertext_components == 0) {
        throw std::invalid_argument(
            "native packing operator needs a ciphertext component");
    }
    std::uint64_t nonzero = 0;
    for (const NativePackingRow &row : rows) {
        for (const NativePackingContribution &contribution :
             row.contributions) {
            for (const std::uint64_t coefficient :
                 contribution.multiplier_ntt_coordinates) {
                if (coefficient != 0) {
                    nonzero = checked_add(nonzero, 1,
                                          "nonzero packing terms");
                }
            }
        }
    }
    const std::uint64_t components =
        checked_size(ciphertext_components, "ciphertext components");
    if (nonzero != 0 &&
        components > std::numeric_limits<std::uint64_t>::max() / nonzero) {
        throw std::overflow_error(
            "native packing term count overflows u64");
    }
    return nonzero * components;
}

} // namespace laminate::packing
