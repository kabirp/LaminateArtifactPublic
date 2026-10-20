#ifndef LAMINATE_PACKING_OUTER_RELATION_RELATION_HPP
#define LAMINATE_PACKING_OUTER_RELATION_RELATION_HPP

/// @file relation.hpp
/// @brief Executable native-Q relation behind transcript packing.
///
/// This module describes and evaluates the algebraic relation embedded in the
/// transcript-packing R1CS. It is not a proof system by itself: commitment
/// hashing, ciphertext normalization, the client's secret-key threshold check,
/// and witness compression are composed by the surrounding protocol.

#include "laminate/packing/analysis/operator.hpp"
#include "laminate/gkr/ciphertext_commitment.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace laminate::packing {

inline constexpr const char *kOuterRelationScope =
    "NATIVE_Q_LINEAR_RELATION_ONLY_NO_HASH_NORMALIZATION_OR_SNARK";

/// Dimensions fixed when preprocessing the outer relation.
///
/// The R1CS scalar field is exactly `native_modulus`, the final prime BGV
/// coefficient modulus. This avoids non-native modular arithmetic; the plan
/// does not attempt to prove primality.
struct OuterRelationShape {
    std::uint64_t native_modulus = 0;
    std::size_t ring_degree = 0;
    std::size_t aligned_ciphertexts = 0;
    std::size_t repetitions = 0;
    std::size_t logical_packed_outputs = 0;
    std::size_t packing_digit_count = 0;
    std::size_t ciphertext_components = 2;
    std::size_t public_input_capacity_bits = 59;
    gkr::CiphertextCommitmentPolicy ciphertext_commitment_policy =
        gkr::CiphertextCommitmentPolicy::poseidon_v2();
};

struct OuterRelationRange {
    std::uint64_t begin = 0;
    std::uint64_t count = 0;

    std::uint64_t end() const;
};

/// Canonical variable order for a native-Q R1CS realization.
struct OuterRelationVariableLayout {
    struct PublicInputs {
        OuterRelationRange packed_challenge_words;
        OuterRelationRange revealed_test_coordinates;
        OuterRelationRange revealed_packing_coordinates;
        std::uint64_t total = 0;
    } public_inputs;

    struct Witness {
        OuterRelationRange derived_challenge_bits;
        OuterRelationRange aligned_ciphertext_coordinates;
        OuterRelationRange well_formedness_products;
        std::uint64_t total = 0;
    } witness;
};

/// Canonical constraint-family order. Each range can be streamed by index;
/// no target-size constraint vector is allocated.
struct OuterRelationConstraintLayout {
    OuterRelationRange challenge_bit_booleanity;
    OuterRelationRange challenge_word_recomposition;
    OuterRelationRange well_formedness_products;
    OuterRelationRange revealed_test_equalities;
    OuterRelationRange revealed_packing_equalities;
    std::uint64_t total = 0;
};

/// Preprocessed shape and exact variable/constraint offsets.
struct OuterRelationPlan {
    enum class ChallengeBit : std::uint8_t { Plus = 0, Minus = 1 };

    OuterRelationShape shape;
    WellFormednessConstraintEstimate well_formedness;
    FixedPackingRelationEstimate fixed_packing;
    OuterRelationVariableLayout variables;
    OuterRelationConstraintLayout constraints;

    std::size_t physical_packed_ciphertexts() const;
    std::size_t coordinates_per_ciphertext() const;

    std::uint64_t challenge_bit_witness_index(
        std::size_t test, std::size_t aligned, ChallengeBit bit) const;
    std::uint64_t aligned_coordinate_witness_index(
        std::size_t aligned, std::size_t component,
        std::size_t ntt_coordinate) const;
    std::uint64_t product_witness_index(
        std::size_t test, std::size_t aligned, std::size_t component,
        std::size_t ntt_coordinate) const;
    std::uint64_t test_coordinate_public_index(
        std::size_t test, std::size_t component,
        std::size_t ntt_coordinate) const;
    std::uint64_t packing_coordinate_public_index(
        std::size_t logical_output, std::size_t digit,
        std::size_t component, std::size_t ntt_coordinate) const;
};

/// Largest requested bit packing that fits injectively in `F_Q`.
std::size_t outer_relation_public_input_capacity(
    std::uint64_t native_modulus,
    std::size_t preferred_capacity_bits = 59);

OuterRelationPlan make_outer_relation_plan(const OuterRelationShape &shape);

/// One fixed plaintext multiplier in native NTT coordinates.
struct NativePackingContribution {
    std::size_t aligned_ciphertext = 0;
    std::vector<std::uint64_t> multiplier_ntt_coordinates;
};

/// One physical `(logical output, signed digit)` ciphertext row.
struct NativePackingRow {
    std::size_t logical_output = 0;
    std::size_t digit = 0;
    std::vector<NativePackingContribution> contributions;
};

/// Fixed native-Q matrix for the four-output base-17 packing relation.
///
/// A multiplier is shared by both ciphertext components. Because aligned
/// ciphertexts are NTT-form, each term is pointwise and the relation remains
/// linear in the witness coordinates.
struct NativePackingOperator {
    std::uint64_t native_modulus = 0;
    std::size_t ring_degree = 0;
    std::size_t aligned_ciphertexts = 0;
    std::size_t logical_outputs = 0;
    std::size_t digit_count = 0;
    std::vector<NativePackingRow> rows;

    void validate(const OuterRelationPlan &plan) const;
    std::uint64_t nonzero_constant_matrix_terms(
        std::size_t ciphertext_components) const;
};

/// Construct the relation plan directly from an already materialized fixed
/// packing matrix. This is the preferred entry point: it cannot accidentally
/// disagree with the matrix about `N`, `r`, the final modulus, or the number
/// of physical base-17 rows.
OuterRelationPlan make_outer_relation_plan(
    const NativePackingOperator &packing_operator, std::size_t repetitions,
    std::size_t ciphertext_components = 2,
    std::size_t public_input_capacity_bits = 59);

/// Public callback that lifts one centered plaintext polynomial to the exact
/// final-modulus NTT vector used by ciphertext--plaintext multiplication.
using NativePlaintextNttEncoder =
    std::function<std::vector<std::uint64_t>(
        std::span<const std::int64_t>)>;

/// Materialize the fixed signed-digit packing matrix in native-Q NTT form.
///
/// `encode_centered_coefficients` is the ordinary BatchEncoder lift used by
/// the real packing operation. `encode_native_ntt` then lifts each small
/// signed digit polynomial to the final ciphertext modulus. Neither callback
/// may depend on a secret key.
NativePackingOperator make_native_signed_digit_packing_operator(
    const PackingLinearOperator &packing_operator,
    const PlaintextCoefficientEncoder &encode_centered_coefficients,
    const NativePlaintextNttEncoder &encode_native_ntt,
    std::uint64_t native_modulus, const BalancedRadix &radix);

/// Public values of the relation. Challenge bits are packed into field
/// elements; revealed ciphertexts use component-major NTT-coordinate order.
struct OuterRelationPublicInputs {
    std::vector<std::uint64_t> packed_challenge_words;
    std::vector<std::uint64_t> revealed_test_coordinates;
    std::vector<std::uint64_t> revealed_packing_coordinates;
};

/// Private aligned ciphertext list, in aligned/component/NTT order.
struct OuterRelationWitnessInputs {
    std::vector<std::uint64_t> aligned_ciphertext_coordinates;
};

/// Extended witness produced from public challenge words and aligned inputs.
struct OuterRelationAuxiliaryWitness {
    std::vector<std::uint8_t> challenge_bits;
    std::vector<std::uint64_t> well_formedness_products;
};

/// Reference outputs used to cross-check prover-generated ciphertexts.
struct OuterRelationExpectedOutputs {
    std::vector<std::uint64_t> revealed_test_coordinates;
    std::vector<std::uint64_t> revealed_packing_coordinates;
};

/// Per-family result of evaluating the exact algebraic relation.
struct OuterRelationAssessment {
    bool challenge_bits_are_boolean = false;
    bool challenge_words_recompose = false;
    bool well_formedness_products_match = false;
    bool revealed_tests_match = false;
    bool revealed_packing_matches = false;

    bool assignment_satisfies_relation() const;
};

/// Pack lazy-ternary `(b_plus,b_minus)` bits in canonical test/input order.
std::vector<std::uint64_t> pack_outer_relation_challenge_bits(
    const OuterRelationPlan &plan,
    std::span<const std::vector<LazyTernaryChallenge>> challenges);

/// Build the R1CS auxiliary variables for a concrete assignment.
OuterRelationAuxiliaryWitness build_outer_relation_auxiliary_witness(
    const OuterRelationPlan &plan,
    std::span<const std::uint64_t> packed_challenge_words,
    const OuterRelationWitnessInputs &witness_inputs);

/// Compute the public test and packing outputs from the same relation.
OuterRelationExpectedOutputs compute_outer_relation_expected_outputs(
    const OuterRelationPlan &plan,
    std::span<const std::uint64_t> packed_challenge_words,
    const OuterRelationWitnessInputs &witness_inputs,
    const NativePackingOperator &packing_operator);

/// Evaluate every relation family exactly modulo the native final prime.
/// Malformed dimensions or noncanonical residues throw; algebraic mutations
/// return named false predicates.
OuterRelationAssessment assess_outer_relation(
    const OuterRelationPlan &plan,
    const OuterRelationPublicInputs &public_inputs,
    const OuterRelationWitnessInputs &witness_inputs,
    const OuterRelationAuxiliaryWitness &auxiliary_witness,
    const NativePackingOperator &packing_operator);

} // namespace laminate::packing

#endif // LAMINATE_PACKING_OUTER_RELATION_RELATION_HPP
