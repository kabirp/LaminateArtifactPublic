/// @file layout.cpp
/// @brief Binary-friendly proof-of-packing R1CS coordinates.

#include "laminate/packing/proof/r1cs/layout.hpp"

#include "laminate/crypto/poseidon.hpp"
#include "laminate/gkr/ciphertext_commitment.hpp"

#include <algorithm>
#include <bit>
#include <limits>
#include <stdexcept>

namespace laminate::packing {
namespace {

std::uint64_t checked_add(std::uint64_t left, std::uint64_t right,
                          const char *label) {
    if (right > std::numeric_limits<std::uint64_t>::max() - left) {
        throw std::overflow_error(label);
    }
    return left + right;
}

std::uint64_t checked_mul(std::uint64_t left, std::uint64_t right,
                          const char *label) {
    if (left != 0 &&
        right > std::numeric_limits<std::uint64_t>::max() / left) {
        throw std::overflow_error(label);
    }
    return left * right;
}

std::uint64_t ceil_div(std::uint64_t numerator,
                       std::uint64_t denominator) {
    return numerator / denominator + (numerator % denominator != 0 ? 1 : 0);
}

std::uint64_t align_up(std::uint64_t value, std::uint64_t alignment,
                       const char *label) {
    if (!std::has_single_bit(alignment)) {
        throw std::logic_error("R1CS alignment is not a power of two");
    }
    const std::uint64_t mask = alignment - 1;
    return checked_add(value, (-value) & mask, label);
}

bool contains(const OuterRelationRange &range, std::uint64_t index) {
    return index >= range.begin && index < range.end();
}

ProofOfPackingR1csRange append_range(std::uint64_t &cursor,
                                     std::uint64_t live,
                                     std::uint64_t extent,
                                     const char *label) {
    ProofOfPackingR1csRange result{cursor, live, extent};
    cursor = checked_add(cursor, extent, label);
    return result;
}

std::uint64_t poseidon_rows_per_permutation() {
    const std::uint64_t sboxes = checked_add(
        checked_mul(kPoseidonFullRounds, kPoseidonWidth,
                    "Poseidon full-round S-box count overflows"),
        kPoseidonPartialRounds,
        "Poseidon S-box count overflows");
    std::uint64_t checkpoints = 0;
    for (std::size_t round = 0;
         round < kPoseidonFullRounds + kPoseidonPartialRounds; ++round) {
        checkpoints += poseidon_round_is_r1cs_checkpoint(round) ? 1 : 0;
    }
    return checked_add(
        checked_mul(3, sboxes,
                    "Poseidon multiplication rows overflow"),
        checked_mul(checkpoints, kPoseidonWidth,
                    "Poseidon checkpoint rows overflow"),
        "Poseidon rows per permutation overflow");
}

void require_index(std::uint64_t index, std::uint64_t limit,
                   const char *label) {
    if (index >= limit) {
        throw std::out_of_range(label);
    }
}

std::vector<ProofOfPackingPoseidonSegment> permutation_segments(
    std::uint64_t permutations) {
    if (permutations == 0) {
        throw std::invalid_argument(
            "Poseidon permutation count must be nonzero");
    }
    std::vector<ProofOfPackingPoseidonSegment> result;
    std::uint64_t begin = 0;
    std::uint64_t remaining = permutations;
    while (remaining != 0) {
        const std::uint64_t count = std::bit_floor(remaining);
        result.push_back(ProofOfPackingPoseidonSegment{
            .permutation_begin = begin,
            .permutations = count,
        });
        begin = checked_add(begin, count,
                            "Poseidon segment boundary overflows");
        remaining -= count;
    }
    return result;
}

} // namespace

std::uint64_t ProofOfPackingR1csRange::end() const {
    return checked_add(begin, extent, "R1CS range end overflows");
}

std::uint64_t ProofOfPackingPoseidonSegment::permutation_end() const {
    return checked_add(permutation_begin, permutations,
                       "Poseidon segment end overflows");
}

const ProofOfPackingPoseidonSegment &
ProofOfPackingR1csLayout::ciphertext_segment(
    std::uint64_t permutation) const {
    require_index(permutation, ciphertext_permutations,
                  "ciphertext permutation is out of range");
    const auto found = std::find_if(
        ciphertext_segments.begin(), ciphertext_segments.end(),
        [&](const ProofOfPackingPoseidonSegment &segment) {
            return permutation >= segment.permutation_begin &&
                   permutation < segment.permutation_end();
        });
    if (found == ciphertext_segments.end()) {
        throw std::logic_error("ciphertext permutation has no segment");
    }
    return *found;
}

std::uint64_t
ProofOfPackingR1csLayout::aligned_coordinate_witness_index(
    const OuterRelationPlan &plan, std::size_t aligned,
    std::size_t component, std::size_t coordinate) const {
    if (aligned >= plan.shape.aligned_ciphertexts ||
        component >= plan.shape.ciphertext_components ||
        coordinate >= plan.shape.ring_degree) {
        throw std::out_of_range(
            "aligned coordinate index is out of range");
    }
    const std::uint64_t local_coordinate = checked_add(
        checked_mul(component, plan.shape.ring_degree,
                    "aligned component offset overflows"),
        coordinate, "aligned coordinate offset overflows");
    const std::uint64_t input = checked_add(
        gkr::kCiphertextCommitmentMetadataElements, local_coordinate,
        "ciphertext hash input index overflows");
    const std::uint64_t local_permutation = input / kPoseidonRate;
    const std::uint64_t rate = input % kPoseidonRate;
    const std::uint64_t permutation = checked_add(
        checked_mul(aligned, ciphertext_permutations_per_hash,
                    "ciphertext permutation offset overflows"),
        local_permutation, "ciphertext permutation index overflows");
    const ProofOfPackingPoseidonSegment &segment =
        ciphertext_segment(permutation);
    return checked_add(
        segment.input_witness_begin,
        checked_add(
            checked_mul(rate, segment.permutations,
                        "aligned advice rate offset overflows"),
            permutation - segment.permutation_begin,
            "aligned advice index overflows"),
        "aligned advice index overflows");
}

std::uint64_t ProofOfPackingR1csLayout::outer_witness_index(
    const OuterRelationPlan &plan, std::uint64_t index) const {
    require_index(index, plan.variables.witness.total,
                  "outer witness index is out of range");
    if (contains(plan.variables.witness.derived_challenge_bits, index)) {
        return checked_add(
            witness.challenge_bits.begin,
            index - plan.variables.witness.derived_challenge_bits.begin,
            "challenge-bit witness index overflows");
    }
    if (contains(plan.variables.witness.aligned_ciphertext_coordinates,
                 index)) {
        std::uint64_t local =
            index -
            plan.variables.witness.aligned_ciphertext_coordinates.begin;
        const std::uint64_t coordinates_per_ciphertext = checked_mul(
            plan.shape.ciphertext_components, plan.shape.ring_degree,
            "coordinates per ciphertext overflow");
        const std::size_t aligned = static_cast<std::size_t>(
            local / coordinates_per_ciphertext);
        local %= coordinates_per_ciphertext;
        const std::size_t component = static_cast<std::size_t>(
            local / plan.shape.ring_degree);
        const std::size_t coordinate = static_cast<std::size_t>(
            local % plan.shape.ring_degree);
        return aligned_coordinate_witness_index(
            plan, aligned, component, coordinate);
    }
    return checked_add(
        witness.well_formedness_products.begin,
        index - plan.variables.witness.well_formedness_products.begin,
        "well-formedness product witness index overflows");
}

std::uint64_t ProofOfPackingR1csLayout::ciphertext_poseidon_row(
    std::uint64_t local_row, std::uint64_t permutation) const {
    require_index(local_row, poseidon_rows_per_permutation,
                  "ciphertext Poseidon local row is out of range");
    require_index(permutation, ciphertext_permutations,
                  "ciphertext Poseidon permutation is out of range");
    const ProofOfPackingPoseidonSegment &segment =
        ciphertext_segment(permutation);
    return checked_add(
        segment.row_begin,
        checked_add(
            checked_mul(local_row, segment.permutations,
                        "ciphertext Poseidon row offset overflows"),
            permutation - segment.permutation_begin,
            "ciphertext Poseidon row overflows"),
        "ciphertext Poseidon row overflows");
}

std::uint64_t ProofOfPackingR1csLayout::ciphertext_output_row(
    std::size_t ciphertext, std::size_t digest_element) const {
    if (ciphertext >= ciphertext_permutations /
                          ciphertext_permutations_per_hash ||
        digest_element >= kPoseidonDigestElements) {
        throw std::out_of_range(
            "ciphertext digest output row is out of range");
    }
    return checked_add(
        rows.ciphertext_outputs.begin,
        checked_add(
            checked_mul(ciphertext, kPoseidonDigestElements,
                        "ciphertext digest row offset overflows"),
            digest_element, "ciphertext digest row overflows"),
        "ciphertext digest row overflows");
}

std::uint64_t ProofOfPackingR1csLayout::outer_constraint_row(
    const OuterRelationPlan &plan, std::uint64_t index) const {
    require_index(index, plan.constraints.total,
                  "outer constraint index is out of range");
    const auto map = [&](const OuterRelationRange &source,
                         const ProofOfPackingR1csRange &destination) {
        return checked_add(destination.begin, index - source.begin,
                           "outer constraint row overflows");
    };
    if (contains(plan.constraints.challenge_bit_booleanity, index)) {
        return map(plan.constraints.challenge_bit_booleanity,
                   rows.challenge_bit_booleanity);
    }
    if (contains(plan.constraints.challenge_word_recomposition, index)) {
        return map(plan.constraints.challenge_word_recomposition,
                   rows.challenge_word_recomposition);
    }
    if (contains(plan.constraints.well_formedness_products, index)) {
        return map(plan.constraints.well_formedness_products,
                   rows.well_formedness_products);
    }
    if (contains(plan.constraints.revealed_test_equalities, index)) {
        return map(plan.constraints.revealed_test_equalities,
                   rows.revealed_test_equalities);
    }
    return map(plan.constraints.revealed_packing_equalities,
               rows.revealed_packing_equalities);
}

std::uint64_t
ProofOfPackingR1csLayout::ciphertext_poseidon_auxiliary_witness_index(
    std::uint64_t local_auxiliary, std::uint64_t permutation) const {
    require_index(local_auxiliary, poseidon_rows_per_permutation,
                  "ciphertext Poseidon local auxiliary is out of range");
    require_index(permutation, ciphertext_permutations,
                  "ciphertext Poseidon auxiliary permutation is out of range");
    const ProofOfPackingPoseidonSegment &segment =
        ciphertext_segment(permutation);
    return checked_add(
        segment.auxiliary_witness_begin,
        checked_add(
            checked_mul(local_auxiliary,
                        segment.permutations,
                        "ciphertext Poseidon auxiliary offset overflows"),
            permutation - segment.permutation_begin,
            "ciphertext Poseidon auxiliary overflows"),
        "ciphertext Poseidon auxiliary overflows");
}

std::uint64_t ProofOfPackingR1csLayout::ciphertext_simple_hash_row(
    const OuterRelationPlan &plan, std::size_t ciphertext,
    std::size_t coordinate) const {
    if (plan.shape.ciphertext_commitment_policy.relation !=
            gkr::CiphertextCommitmentRelation::DiagnosticSimpleCtHashV2 ||
        ciphertext >= plan.shape.aligned_ciphertexts) {
        throw std::out_of_range(
            "diagnostic ciphertext-hash row is out of range");
    }
    const std::uint64_t coordinates = checked_mul(
        plan.shape.ciphertext_components, plan.shape.ring_degree,
        "diagnostic ciphertext-hash coordinate count overflows");
    require_index(coordinate, coordinates,
                  "diagnostic ciphertext-hash coordinate is out of range");
    return checked_add(
        rows.ciphertext_poseidon.begin,
        checked_add(
            checked_mul(ciphertext, coordinates,
                        "diagnostic ciphertext-hash row overflows"),
            coordinate,
            "diagnostic ciphertext-hash row overflows"),
        "diagnostic ciphertext-hash row overflows");
}

std::uint64_t
ProofOfPackingR1csLayout::
    ciphertext_simple_hash_auxiliary_witness_index(
        const OuterRelationPlan &plan, std::size_t ciphertext,
        std::size_t coordinate) const {
    const std::uint64_t row = ciphertext_simple_hash_row(
        plan, ciphertext, coordinate);
    return checked_add(
        witness.ciphertext_poseidon_auxiliary.begin,
        row - rows.ciphertext_poseidon.begin,
        "diagnostic ciphertext-hash witness overflows");
}

ProofOfPackingR1csLayout make_proof_of_packing_r1cs_layout(
    const OuterRelationPlan &plan) {
    if (plan.shape.native_modulus != kOuterFieldOrder ||
        plan.shape.ciphertext_components != 2 ||
        plan.shape.aligned_ciphertexts == 0 ||
        plan.shape.ring_degree == 0) {
        throw std::invalid_argument(
            "proof-of-packing layout needs native size-two ciphertexts");
    }

    ProofOfPackingR1csLayout result;
    plan.shape.ciphertext_commitment_policy.validate();
    const bool use_poseidon =
        plan.shape.ciphertext_commitment_policy.relation ==
        gkr::CiphertextCommitmentRelation::PoseidonV2;
    result.poseidon_rows_per_permutation =
        poseidon_rows_per_permutation();
    const std::uint64_t coordinates_per_ciphertext = checked_mul(
        plan.shape.ciphertext_components, plan.shape.ring_degree,
        "ciphertext coordinate count overflows");
    const std::uint64_t ciphertext_preimage = checked_add(
        gkr::kCiphertextCommitmentMetadataElements,
        coordinates_per_ciphertext,
        "ciphertext hash preimage count overflows");
    result.ciphertext_permutations_per_hash = ceil_div(
        checked_add(ciphertext_preimage, 1,
                    "ciphertext hash padding overflows"),
        kPoseidonRate);
    result.ciphertext_permutations = checked_mul(
        plan.shape.aligned_ciphertexts,
        result.ciphertext_permutations_per_hash,
        "ciphertext permutation count overflows");
    result.ciphertext_segments =
        permutation_segments(result.ciphertext_permutations);
    result.largest_ciphertext_segment =
        result.ciphertext_segments.front().permutations;
    result.logical_inputs = checked_add(
        checked_mul(plan.shape.aligned_ciphertexts,
                    kPoseidonDigestElements,
                    "commitment logical input count overflows"),
        plan.variables.public_inputs.total,
        "logical input count overflows");
    // Step 1: place the selected ciphertext-commitment row family. Poseidon
    // keeps its transposed permutation layout; diagnostic simpleCTHash uses
    // one contiguous recurrence row per canonical ciphertext coordinate.
    std::uint64_t row_cursor = 0;
    const std::uint64_t ciphertext_rows_begin = row_cursor;
    if (use_poseidon) {
        for (ProofOfPackingPoseidonSegment &segment :
             result.ciphertext_segments) {
            segment.row_begin = row_cursor;
            row_cursor = checked_add(
                row_cursor,
                checked_mul(result.poseidon_rows_per_permutation,
                            segment.permutations,
                            "ciphertext Poseidon segment rows overflow"),
                "ciphertext Poseidon segment rows overflow");
        }
    } else {
        row_cursor = checked_add(
            row_cursor,
            checked_mul(plan.shape.aligned_ciphertexts,
                        coordinates_per_ciphertext,
                        "diagnostic ciphertext-hash rows overflow"),
            "diagnostic ciphertext-hash rows overflow");
    }
    result.rows.ciphertext_poseidon = ProofOfPackingR1csRange{
        ciphertext_rows_begin,
        row_cursor - ciphertext_rows_begin,
        row_cursor - ciphertext_rows_begin};
    const std::uint64_t commitment_rows = checked_mul(
        plan.shape.aligned_ciphertexts, kPoseidonDigestElements,
        "ciphertext digest rows overflow");
    result.rows.ciphertext_outputs = append_range(
        row_cursor, commitment_rows, commitment_rows,
        "ciphertext digest rows overflow");
    // Step 2: retain the mathematical outer-family order. Large coordinate
    // families begin on a 2N boundary, so their low bits are exactly
    // `(component, NTT coordinate)`.
    result.rows.challenge_bit_booleanity = append_range(
        row_cursor, plan.constraints.challenge_bit_booleanity.count,
        plan.constraints.challenge_bit_booleanity.count,
        "challenge booleanity rows overflow");
    result.rows.challenge_word_recomposition = append_range(
        row_cursor, plan.constraints.challenge_word_recomposition.count,
        plan.constraints.challenge_word_recomposition.count,
        "challenge recomposition rows overflow");
    row_cursor = align_up(row_cursor, coordinates_per_ciphertext,
                          "product row alignment overflows");
    result.rows.well_formedness_products = append_range(
        row_cursor, plan.constraints.well_formedness_products.count,
        plan.constraints.well_formedness_products.count,
        "well-formedness product rows overflow");
    row_cursor = align_up(row_cursor, coordinates_per_ciphertext,
                          "test row alignment overflows");
    result.rows.revealed_test_equalities = append_range(
        row_cursor, plan.constraints.revealed_test_equalities.count,
        plan.constraints.revealed_test_equalities.count,
        "revealed test rows overflow");
    row_cursor = align_up(row_cursor, coordinates_per_ciphertext,
                          "packing row alignment overflows");
    result.rows.revealed_packing_equalities = append_range(
        row_cursor, plan.constraints.revealed_packing_equalities.count,
        plan.constraints.revealed_packing_equalities.count,
        "revealed packing rows overflow");
    result.rows.total = row_cursor;

    // Step 3: place aligned hash inputs rate-major, then retain contiguous
    // product advice for the outer tensor families. Logical inputs occupy the
    // R1CS public-input half and therefore need no witness range.
    std::uint64_t witness_cursor = 0;
    result.witness.challenge_bits = append_range(
        witness_cursor,
        plan.variables.witness.derived_challenge_bits.count,
        plan.variables.witness.derived_challenge_bits.count,
        "challenge-bit witness extent overflows");
    witness_cursor = align_up(
        witness_cursor, result.largest_ciphertext_segment,
        "aligned-coordinate witness alignment overflows");
    const std::uint64_t aligned_begin = witness_cursor;
    for (ProofOfPackingPoseidonSegment &segment :
         result.ciphertext_segments) {
        segment.input_witness_begin = witness_cursor;
        witness_cursor = checked_add(
            witness_cursor,
            checked_mul(kPoseidonRate, segment.permutations,
                        "aligned-coordinate advice segment overflows"),
            "aligned-coordinate advice segment overflows");
    }
    result.witness.aligned_coordinates = ProofOfPackingR1csRange{
        aligned_begin,
        plan.variables.witness.aligned_ciphertext_coordinates.count,
        witness_cursor - aligned_begin};
    witness_cursor = align_up(witness_cursor, coordinates_per_ciphertext,
                              "product witness alignment overflows");
    result.witness.well_formedness_products = append_range(
        witness_cursor,
        plan.variables.witness.well_formedness_products.count,
        plan.variables.witness.well_formedness_products.count,
        "well-formedness product witness extent overflows");
    witness_cursor = align_up(
        witness_cursor,
        use_poseidon ? result.largest_ciphertext_segment
                     : coordinates_per_ciphertext,
        "ciphertext commitment auxiliary alignment overflows");
    const std::uint64_t ciphertext_auxiliary_begin = witness_cursor;
    if (use_poseidon) {
        for (ProofOfPackingPoseidonSegment &segment :
             result.ciphertext_segments) {
            segment.auxiliary_witness_begin = witness_cursor;
            witness_cursor = checked_add(
                witness_cursor,
                checked_mul(result.poseidon_rows_per_permutation,
                            segment.permutations,
                            "ciphertext Poseidon auxiliary segment "
                            "overflows"),
                "ciphertext Poseidon auxiliary segment overflows");
        }
    } else {
        witness_cursor = checked_add(
            witness_cursor,
            checked_mul(plan.shape.aligned_ciphertexts,
                        coordinates_per_ciphertext,
                        "diagnostic ciphertext-hash auxiliaries overflow"),
            "diagnostic ciphertext-hash auxiliaries overflow");
    }
    result.witness.ciphertext_poseidon_auxiliary =
        ProofOfPackingR1csRange{
        ciphertext_auxiliary_begin,
        witness_cursor - ciphertext_auxiliary_begin,
        witness_cursor - ciphertext_auxiliary_begin};
    result.witness.total = witness_cursor;
    return result;
}

} // namespace laminate::packing
