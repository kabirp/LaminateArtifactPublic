/// @file evaluator.cpp
/// @brief Exact native-Q witness construction and relation evaluation.

#include "laminate/packing/outer_relation/relation.hpp"

#include <algorithm>
#include <limits>
#include <stdexcept>
#include <string>

namespace laminate::packing {
namespace {

std::size_t as_size(std::uint64_t value, const char *label) {
    if (value > std::numeric_limits<std::size_t>::max()) {
        throw std::overflow_error(std::string(label) + " exceeds size_t");
    }
    return static_cast<std::size_t>(value);
}

void require_size(std::size_t actual, std::uint64_t expected,
                  const char *label) {
    if (actual != as_size(expected, label)) {
        throw std::invalid_argument(std::string("outer relation: wrong ") +
                                    label + " length");
    }
}

void require_residues(std::span<const std::uint64_t> values,
                      std::uint64_t modulus, const char *label) {
    if (std::any_of(values.begin(), values.end(),
                    [=](std::uint64_t value) {
                        return value >= modulus;
                    })) {
        throw std::invalid_argument(std::string("outer relation: ") + label +
                                    " contains a noncanonical residue");
    }
}

std::uint64_t add_mod(std::uint64_t left, std::uint64_t right,
                      std::uint64_t modulus) {
    return static_cast<std::uint64_t>(
        (static_cast<unsigned __int128>(left) + right) % modulus);
}

std::uint64_t mul_mod(std::uint64_t left, std::uint64_t right,
                      std::uint64_t modulus) {
    return static_cast<std::uint64_t>(
        (static_cast<unsigned __int128>(left) * right) % modulus);
}

std::size_t relative(std::uint64_t absolute,
                     const OuterRelationRange &range,
                     const char *label) {
    if (absolute < range.begin || absolute >= range.end()) {
        throw std::logic_error(std::string("outer relation: ") + label +
                               " escaped its variable range");
    }
    return as_size(absolute - range.begin, label);
}

std::size_t challenge_bit_position(
    const OuterRelationPlan &plan, std::size_t test, std::size_t aligned,
    OuterRelationPlan::ChallengeBit bit) {
    return relative(plan.challenge_bit_witness_index(test, aligned, bit),
                    plan.variables.witness.derived_challenge_bits,
                    "challenge bit");
}

std::size_t aligned_coordinate_position(
    const OuterRelationPlan &plan, std::size_t aligned,
    std::size_t component, std::size_t coordinate) {
    return relative(
        plan.aligned_coordinate_witness_index(aligned, component, coordinate),
        plan.variables.witness.aligned_ciphertext_coordinates,
        "aligned coordinate");
}

std::size_t product_position(const OuterRelationPlan &plan,
                             std::size_t test, std::size_t aligned,
                             std::size_t component,
                             std::size_t coordinate) {
    return relative(
        plan.product_witness_index(test, aligned, component, coordinate),
        plan.variables.witness.well_formedness_products,
        "well-formedness product");
}

std::size_t test_output_position(const OuterRelationPlan &plan,
                                 std::size_t test, std::size_t component,
                                 std::size_t coordinate) {
    return relative(
        plan.test_coordinate_public_index(test, component, coordinate),
        plan.variables.public_inputs.revealed_test_coordinates,
        "test output");
}

std::size_t packing_output_position(
    const OuterRelationPlan &plan, std::size_t logical_output,
    std::size_t digit, std::size_t component, std::size_t coordinate) {
    return relative(plan.packing_coordinate_public_index(
                        logical_output, digit, component, coordinate),
                    plan.variables.public_inputs
                        .revealed_packing_coordinates,
                    "packing output");
}

void validate_primary_inputs(
    const OuterRelationPlan &plan,
    std::span<const std::uint64_t> packed_challenge_words,
    const OuterRelationWitnessInputs &witness_inputs) {
    require_size(packed_challenge_words.size(),
                 plan.variables.public_inputs.packed_challenge_words.count,
                 "packed challenge word");
    require_size(
        witness_inputs.aligned_ciphertext_coordinates.size(),
        plan.variables.witness.aligned_ciphertext_coordinates.count,
        "aligned witness coordinate");
    require_residues(packed_challenge_words, plan.shape.native_modulus,
                     "packed challenge words");
    require_residues(witness_inputs.aligned_ciphertext_coordinates,
                     plan.shape.native_modulus,
                     "aligned witness coordinates");
}

std::vector<std::uint8_t> unpack_challenge_bits(
    const OuterRelationPlan &plan,
    std::span<const std::uint64_t> packed_challenge_words) {
    require_size(packed_challenge_words.size(),
                 plan.variables.public_inputs.packed_challenge_words.count,
                 "packed challenge word");
    require_residues(packed_challenge_words, plan.shape.native_modulus,
                     "packed challenge words");

    const std::size_t bit_count = as_size(
        plan.variables.witness.derived_challenge_bits.count,
        "challenge bit count");
    std::vector<std::uint8_t> result(bit_count, 0);
    const std::size_t capacity = plan.shape.public_input_capacity_bits;
    for (std::size_t bit = 0; bit < bit_count; ++bit) {
        result[bit] = static_cast<std::uint8_t>(
            (packed_challenge_words[bit / capacity] >> (bit % capacity)) &
            std::uint64_t{1});
    }
    return result;
}

std::uint64_t ternary_product(std::uint8_t plus, std::uint8_t minus,
                              std::uint64_t input,
                              std::uint64_t modulus) {
    if (plus == minus) {
        return 0;
    }
    return plus == 1 ? input : (input == 0 ? 0 : modulus - input);
}

std::vector<std::uint64_t> build_products(
    const OuterRelationPlan &plan,
    std::span<const std::uint8_t> challenge_bits,
    const OuterRelationWitnessInputs &witness_inputs) {
    const std::size_t product_count = as_size(
        plan.variables.witness.well_formedness_products.count,
        "well-formedness product count");
    std::vector<std::uint64_t> result(product_count, 0);
    for (std::size_t test = 0; test < plan.shape.repetitions; ++test) {
        for (std::size_t aligned = 0;
             aligned < plan.shape.aligned_ciphertexts; ++aligned) {
            const std::uint8_t plus = challenge_bits[challenge_bit_position(
                plan, test, aligned, OuterRelationPlan::ChallengeBit::Plus)];
            const std::uint8_t minus = challenge_bits[challenge_bit_position(
                plan, test, aligned, OuterRelationPlan::ChallengeBit::Minus)];
            for (std::size_t component = 0;
                 component < plan.shape.ciphertext_components; ++component) {
                for (std::size_t coordinate = 0;
                     coordinate < plan.shape.ring_degree; ++coordinate) {
                    const std::uint64_t input =
                        witness_inputs.aligned_ciphertext_coordinates
                            [aligned_coordinate_position(
                                plan, aligned, component, coordinate)];
                    result[product_position(plan, test, aligned, component,
                                            coordinate)] =
                        ternary_product(plus, minus, input,
                                        plan.shape.native_modulus);
                }
            }
        }
    }
    return result;
}

std::vector<std::uint64_t> sum_test_outputs(
    const OuterRelationPlan &plan,
    std::span<const std::uint64_t> products) {
    std::vector<std::uint64_t> result(
        as_size(plan.well_formedness.revealed_ciphertext_coordinates,
                "test output coordinates"),
        0);
    for (std::size_t test = 0; test < plan.shape.repetitions; ++test) {
        for (std::size_t component = 0;
             component < plan.shape.ciphertext_components; ++component) {
            for (std::size_t coordinate = 0;
                 coordinate < plan.shape.ring_degree; ++coordinate) {
                std::uint64_t sum = 0;
                for (std::size_t aligned = 0;
                     aligned < plan.shape.aligned_ciphertexts; ++aligned) {
                    sum = add_mod(
                        sum,
                        products[product_position(
                            plan, test, aligned, component, coordinate)],
                        plan.shape.native_modulus);
                }
                result[test_output_position(plan, test, component,
                                            coordinate)] = sum;
            }
        }
    }
    return result;
}

std::vector<std::uint64_t> compute_packing_outputs(
    const OuterRelationPlan &plan,
    const OuterRelationWitnessInputs &witness_inputs,
    const NativePackingOperator &packing_operator) {
    packing_operator.validate(plan);
    std::vector<std::uint64_t> result(
        as_size(plan.fixed_packing.public_output_coordinates,
                "packing output coordinates"),
        0);
    for (const NativePackingRow &row : packing_operator.rows) {
        for (std::size_t component = 0;
             component < plan.shape.ciphertext_components; ++component) {
            for (std::size_t coordinate = 0;
                 coordinate < plan.shape.ring_degree; ++coordinate) {
                std::uint64_t sum = 0;
                for (const NativePackingContribution &contribution :
                     row.contributions) {
                    const std::uint64_t input =
                        witness_inputs.aligned_ciphertext_coordinates
                            [aligned_coordinate_position(
                                plan, contribution.aligned_ciphertext,
                                component, coordinate)];
                    const std::uint64_t multiplier =
                        contribution.multiplier_ntt_coordinates[coordinate];
                    sum = add_mod(
                        sum,
                        mul_mod(input, multiplier,
                                plan.shape.native_modulus),
                        plan.shape.native_modulus);
                }
                result[packing_output_position(
                    plan, row.logical_output, row.digit, component,
                    coordinate)] = sum;
            }
        }
    }
    return result;
}

bool challenge_words_recompose(
    const OuterRelationPlan &plan,
    std::span<const std::uint64_t> packed_words,
    std::span<const std::uint8_t> bits) {
    const std::size_t capacity = plan.shape.public_input_capacity_bits;
    for (std::size_t word = 0; word < packed_words.size(); ++word) {
        std::uint64_t recomposed = 0;
        const std::size_t begin = word * capacity;
        const std::size_t count =
            std::min(capacity, bits.size() - begin);
        for (std::size_t offset = 0; offset < count; ++offset) {
            if (bits[begin + offset] > 1) {
                return false;
            }
            recomposed |= static_cast<std::uint64_t>(bits[begin + offset])
                          << offset;
        }
        if (recomposed != packed_words[word]) {
            return false;
        }
    }
    return true;
}

} // namespace

bool OuterRelationAssessment::assignment_satisfies_relation() const {
    return challenge_bits_are_boolean && challenge_words_recompose &&
           well_formedness_products_match && revealed_tests_match &&
           revealed_packing_matches;
}

std::vector<std::uint64_t> pack_outer_relation_challenge_bits(
    const OuterRelationPlan &plan,
    std::span<const std::vector<LazyTernaryChallenge>> challenges) {
    if (challenges.size() != plan.shape.repetitions) {
        throw std::invalid_argument(
            "outer relation: challenge row count differs from plan");
    }
    std::vector<std::uint64_t> result(
        as_size(plan.variables.public_inputs.packed_challenge_words.count,
                "packed challenge words"),
        0);
    const std::size_t capacity = plan.shape.public_input_capacity_bits;
    for (std::size_t test = 0; test < challenges.size(); ++test) {
        if (challenges[test].size() != plan.shape.aligned_ciphertexts) {
            throw std::invalid_argument(
                "outer relation: challenge row width differs from plan");
        }
        for (std::size_t aligned = 0; aligned < challenges[test].size();
             ++aligned) {
            const LazyTernaryChallenge challenge = challenges[test][aligned];
            const std::size_t base = 2 *
                (test * plan.shape.aligned_ciphertexts + aligned);
            if (challenge.plus_bit) {
                result[base / capacity] |=
                    std::uint64_t{1} << (base % capacity);
            }
            if (challenge.minus_bit) {
                const std::size_t bit = base + 1;
                result[bit / capacity] |=
                    std::uint64_t{1} << (bit % capacity);
            }
        }
    }
    return result;
}

OuterRelationAuxiliaryWitness build_outer_relation_auxiliary_witness(
    const OuterRelationPlan &plan,
    std::span<const std::uint64_t> packed_challenge_words,
    const OuterRelationWitnessInputs &witness_inputs) {
    validate_primary_inputs(plan, packed_challenge_words, witness_inputs);
    OuterRelationAuxiliaryWitness result;
    result.challenge_bits =
        unpack_challenge_bits(plan, packed_challenge_words);
    result.well_formedness_products =
        build_products(plan, result.challenge_bits, witness_inputs);
    return result;
}

OuterRelationExpectedOutputs compute_outer_relation_expected_outputs(
    const OuterRelationPlan &plan,
    std::span<const std::uint64_t> packed_challenge_words,
    const OuterRelationWitnessInputs &witness_inputs,
    const NativePackingOperator &packing_operator) {
    const OuterRelationAuxiliaryWitness auxiliary =
        build_outer_relation_auxiliary_witness(
            plan, packed_challenge_words, witness_inputs);
    return OuterRelationExpectedOutputs{
        .revealed_test_coordinates = sum_test_outputs(
            plan, auxiliary.well_formedness_products),
        .revealed_packing_coordinates = compute_packing_outputs(
            plan, witness_inputs, packing_operator),
    };
}

OuterRelationAssessment assess_outer_relation(
    const OuterRelationPlan &plan,
    const OuterRelationPublicInputs &public_inputs,
    const OuterRelationWitnessInputs &witness_inputs,
    const OuterRelationAuxiliaryWitness &auxiliary_witness,
    const NativePackingOperator &packing_operator) {
    validate_primary_inputs(plan, public_inputs.packed_challenge_words,
                            witness_inputs);
    require_size(public_inputs.revealed_test_coordinates.size(),
                 plan.well_formedness.revealed_ciphertext_coordinates,
                 "revealed test coordinate");
    require_size(public_inputs.revealed_packing_coordinates.size(),
                 plan.fixed_packing.public_output_coordinates,
                 "revealed packing coordinate");
    require_size(auxiliary_witness.challenge_bits.size(),
                 plan.variables.witness.derived_challenge_bits.count,
                 "challenge-bit witness");
    require_size(auxiliary_witness.well_formedness_products.size(),
                 plan.variables.witness.well_formedness_products.count,
                 "product witness");
    require_residues(public_inputs.revealed_test_coordinates,
                     plan.shape.native_modulus,
                     "revealed test coordinates");
    require_residues(public_inputs.revealed_packing_coordinates,
                     plan.shape.native_modulus,
                     "revealed packing coordinates");
    require_residues(auxiliary_witness.well_formedness_products,
                     plan.shape.native_modulus,
                     "product witnesses");
    packing_operator.validate(plan);

    OuterRelationAssessment result;
    result.challenge_bits_are_boolean = std::all_of(
        auxiliary_witness.challenge_bits.begin(),
        auxiliary_witness.challenge_bits.end(),
        [](std::uint8_t bit) { return bit <= 1; });
    result.challenge_words_recompose = challenge_words_recompose(
        plan, public_inputs.packed_challenge_words,
        auxiliary_witness.challenge_bits);

    if (result.challenge_bits_are_boolean) {
        const std::vector<std::uint64_t> expected_products = build_products(
            plan, auxiliary_witness.challenge_bits, witness_inputs);
        result.well_formedness_products_match =
            expected_products ==
            auxiliary_witness.well_formedness_products;
    }
    result.revealed_tests_match =
        sum_test_outputs(plan,
                         auxiliary_witness.well_formedness_products) ==
        public_inputs.revealed_test_coordinates;
    result.revealed_packing_matches =
        compute_packing_outputs(plan, witness_inputs, packing_operator) ==
        public_inputs.revealed_packing_coordinates;
    return result;
}

} // namespace laminate::packing
