#ifndef LAMINATE_PACKING_PROOF_LAYOUT_HPP
#define LAMINATE_PACKING_PROOF_LAYOUT_HPP

/// @file layout.hpp
/// @brief Structured row and witness coordinates for proof-of-packing R1CS.

#include "laminate/packing/outer_relation/relation.hpp"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace laminate::packing {

/// A live family inside a possibly padded matrix interval.
struct ProofOfPackingR1csRange {
    std::uint64_t begin = 0;
    std::uint64_t live = 0;
    std::uint64_t extent = 0;

    std::uint64_t end() const;
};

/// One power-of-two permutation interval in a transposed Poseidon tensor.
struct ProofOfPackingPoseidonSegment {
    std::uint64_t permutation_begin = 0;
    std::uint64_t permutations = 0;
    std::uint64_t row_begin = 0;
    std::uint64_t input_witness_begin = 0;
    std::uint64_t auxiliary_witness_begin = 0;

    std::uint64_t permutation_end() const;
};

/// Binary-friendly placement of every proof-of-packing row and witness.
///
/// Each Poseidon segment uses the transposed coordinates
///
///     row(local, permutation)
///       = segment_begin + local * segment_size + local_permutation.
///
/// The live permutation count is decomposed into descending power-of-two
/// segments. Thus every segment MLE factors cleanly without padding the whole
/// family to the next power of two. Alignment gaps create only zero rows or
/// unused witnesses and do not change an active R1CS equation.
struct ProofOfPackingR1csLayout {
    struct Rows {
        ProofOfPackingR1csRange ciphertext_poseidon;
        ProofOfPackingR1csRange ciphertext_outputs;
        ProofOfPackingR1csRange challenge_bit_booleanity;
        ProofOfPackingR1csRange challenge_word_recomposition;
        ProofOfPackingR1csRange well_formedness_products;
        ProofOfPackingR1csRange revealed_test_equalities;
        ProofOfPackingR1csRange revealed_packing_equalities;
        std::uint64_t total = 0;
    } rows;

    struct Witness {
        ProofOfPackingR1csRange challenge_bits;
        ProofOfPackingR1csRange aligned_coordinates;
        ProofOfPackingR1csRange well_formedness_products;
        ProofOfPackingR1csRange ciphertext_poseidon_auxiliary;
        std::uint64_t total = 0;
    } witness;

    std::uint64_t logical_inputs = 0;
    std::uint64_t poseidon_rows_per_permutation = 0;
    std::uint64_t ciphertext_permutations_per_hash = 0;
    std::uint64_t ciphertext_permutations = 0;
    std::uint64_t largest_ciphertext_segment = 0;
    std::vector<ProofOfPackingPoseidonSegment> ciphertext_segments;

    const ProofOfPackingPoseidonSegment &ciphertext_segment(
        std::uint64_t permutation) const;

    /// Map one aligned ciphertext coordinate into rate-major hash advice.
    std::uint64_t aligned_coordinate_witness_index(
        const OuterRelationPlan &plan, std::size_t aligned,
        std::size_t component, std::size_t coordinate) const;

    /// Map a canonical outer-relation witness into the structured witness.
    std::uint64_t outer_witness_index(
        const OuterRelationPlan &plan, std::uint64_t index) const;

    std::uint64_t ciphertext_poseidon_row(
        std::uint64_t local_row, std::uint64_t permutation) const;
    std::uint64_t ciphertext_output_row(
        std::size_t ciphertext, std::size_t digest_element) const;
    std::uint64_t outer_constraint_row(
        const OuterRelationPlan &plan, std::uint64_t index) const;

    std::uint64_t ciphertext_poseidon_auxiliary_witness_index(
        std::uint64_t local_auxiliary,
        std::uint64_t permutation) const;

    /// Diagnostic simpleCTHash/v2 recurrence coordinates.  There is one
    /// sparse linear row and one accumulator witness for each canonical
    /// ciphertext coordinate. Fixed metadata is folded into the public
    /// initial state without a constraint.
    std::uint64_t ciphertext_simple_hash_row(
        const OuterRelationPlan &plan, std::size_t ciphertext,
        std::size_t coordinate) const;
    std::uint64_t ciphertext_simple_hash_auxiliary_witness_index(
        const OuterRelationPlan &plan, std::size_t ciphertext,
        std::size_t coordinate) const;
};

/// Derive the complete structured layout from public circuit geometry.
///
/// Preconditions: `plan` is a native-field size-two ciphertext relation.
/// Postcondition: every active row and witness has a unique in-range index;
/// Poseidon and coordinate subdomains are aligned to powers of two.
ProofOfPackingR1csLayout make_proof_of_packing_r1cs_layout(
    const OuterRelationPlan &plan);

} // namespace laminate::packing

#endif // LAMINATE_PACKING_PROOF_LAYOUT_HPP
