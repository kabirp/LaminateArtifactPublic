/// @file metadata.cpp
/// @brief Coefficient-free identity for the structured packing R1CS.

#include "laminate/packing/proof/matrix/metadata.hpp"

#include "laminate/crypto/poseidon.hpp"
#include "laminate/field/serialization.hpp"
#include "laminate/gkr/ciphertext_commitment.hpp"
#include "laminate/packing/proof/detail/poseidon_template.hpp"
#include "laminate/transcript/hash.hpp"

#include <algorithm>
#include <bit>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace laminate::packing {
namespace {

std::uint64_t as_u64(std::size_t value, const char *label) {
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

std::size_t exact_power_of_two_padding(std::uint64_t value,
                                       const char *label) {
    if (value == 0 ||
        value > std::numeric_limits<std::size_t>::max()) {
        throw std::overflow_error(std::string(label) + " exceeds size_t");
    }
    const std::size_t converted = static_cast<std::size_t>(value);
    constexpr std::size_t kMaximumPowerOfTwo =
        std::size_t{1} << (std::numeric_limits<std::size_t>::digits - 1U);
    if (converted > kMaximumPowerOfTwo) {
        throw std::overflow_error(std::string(label) + " cannot be padded");
    }
    return std::bit_ceil(converted);
}

void append_u64(std::vector<std::uint8_t> &output,
                std::uint64_t value) {
    for (std::size_t byte = 0; byte < 8; ++byte) {
        output.push_back(static_cast<std::uint8_t>(value >> (8U * byte)));
    }
}

void append_size(std::vector<std::uint8_t> &output, std::size_t value,
                 const char *label) {
    append_u64(output, as_u64(value, label));
}

void append_string(std::vector<std::uint8_t> &output,
                   std::string_view value) {
    append_size(output, value.size(), "semantic version length");
    output.insert(output.end(), value.begin(), value.end());
}

void append_digest(std::vector<std::uint8_t> &output,
                   const Digest &digest) {
    output.insert(output.end(), digest.begin(), digest.end());
}

void append_range(std::vector<std::uint8_t> &output,
                  const OuterRelationRange &range) {
    append_u64(output, range.begin);
    append_u64(output, range.count);
}

void append_shape(std::vector<std::uint8_t> &output,
                  const OuterRelationShape &shape) {
    append_u64(output, shape.native_modulus);
    append_size(output, shape.ring_degree, "ring degree");
    append_size(output, shape.aligned_ciphertexts,
                "aligned ciphertext count");
    append_size(output, shape.repetitions, "repetition count");
    append_size(output, shape.logical_packed_outputs,
                "logical packed output count");
    append_size(output, shape.packing_digit_count,
                "packing digit count");
    append_size(output, shape.ciphertext_components,
                "ciphertext component count");
    append_size(output, shape.public_input_capacity_bits,
                "public input capacity");
    append_u64(output, shape.ciphertext_commitment_policy.wire_code());
}

void append_relation_plan(std::vector<std::uint8_t> &output,
                          const OuterRelationPlan &plan) {
    append_shape(output, plan.shape);

    append_u64(output,
               plan.well_formedness.revealed_ciphertext_coordinates);
    append_u64(output, plan.well_formedness.coefficient_products);
    append_u64(output, plan.well_formedness.output_relations);
    append_u64(output, plan.well_formedness.challenge_bits);
    append_u64(output,
               plan.well_formedness.booleanity_constraints);
    append_u64(output, plan.well_formedness.packed_public_inputs);
    append_u64(
        output,
        plan.well_formedness.public_input_recomposition_constraints);
    append_u64(output, plan.well_formedness.subtotal_constraints);

    append_u64(output, plan.fixed_packing.witness_input_coordinates);
    append_u64(output, plan.fixed_packing.public_output_coordinates);
    append_u64(output,
               plan.fixed_packing.output_relation_constraints);
    append_u64(output, plan.fixed_packing.constant_matrix_terms);

    append_range(output,
                 plan.variables.public_inputs.packed_challenge_words);
    append_range(output,
                 plan.variables.public_inputs.revealed_test_coordinates);
    append_range(
        output,
        plan.variables.public_inputs.revealed_packing_coordinates);
    append_u64(output, plan.variables.public_inputs.total);
    append_range(output,
                 plan.variables.witness.derived_challenge_bits);
    append_range(
        output,
        plan.variables.witness.aligned_ciphertext_coordinates);
    append_range(output,
                 plan.variables.witness.well_formedness_products);
    append_u64(output, plan.variables.witness.total);

    append_range(output, plan.constraints.challenge_bit_booleanity);
    append_range(output,
                 plan.constraints.challenge_word_recomposition);
    append_range(output, plan.constraints.well_formedness_products);
    append_range(output, plan.constraints.revealed_test_equalities);
    append_range(output, plan.constraints.revealed_packing_equalities);
    append_u64(output, plan.constraints.total);
}

void append_r1cs_range(std::vector<std::uint8_t> &output,
                       const ProofOfPackingR1csRange &range) {
    append_u64(output, range.begin);
    append_u64(output, range.live);
    append_u64(output, range.extent);
}

void append_r1cs_layout(std::vector<std::uint8_t> &output,
                        const ProofOfPackingR1csLayout &layout) {
    append_r1cs_range(output, layout.rows.ciphertext_poseidon);
    append_r1cs_range(output, layout.rows.ciphertext_outputs);
    append_r1cs_range(output, layout.rows.challenge_bit_booleanity);
    append_r1cs_range(output,
                      layout.rows.challenge_word_recomposition);
    append_r1cs_range(output, layout.rows.well_formedness_products);
    append_r1cs_range(output, layout.rows.revealed_test_equalities);
    append_r1cs_range(output,
                      layout.rows.revealed_packing_equalities);
    append_u64(output, layout.rows.total);

    append_r1cs_range(output, layout.witness.challenge_bits);
    append_r1cs_range(output, layout.witness.aligned_coordinates);
    append_r1cs_range(output,
                      layout.witness.well_formedness_products);
    append_r1cs_range(
        output, layout.witness.ciphertext_poseidon_auxiliary);
    append_u64(output, layout.witness.total);

    append_u64(output, layout.logical_inputs);
    append_u64(output, layout.poseidon_rows_per_permutation);
    append_u64(output, layout.ciphertext_permutations_per_hash);
    append_u64(output, layout.ciphertext_permutations);
    append_u64(output, layout.largest_ciphertext_segment);
    append_size(output, layout.ciphertext_segments.size(),
                "Poseidon segment count");
    for (const ProofOfPackingPoseidonSegment &segment :
         layout.ciphertext_segments) {
        append_u64(output, segment.permutation_begin);
        append_u64(output, segment.permutations);
        append_u64(output, segment.row_begin);
        append_u64(output, segment.input_witness_begin);
        append_u64(output, segment.auxiliary_witness_begin);
    }
}

void append_r1cs_ledger(std::vector<std::uint8_t> &output,
                        const ProofOfPackingR1csLedger &ledger) {
    append_u64(output, ledger.aligned_ciphertexts);
    append_u64(output, ledger.ciphertext_preimage_field_elements);
    append_u64(
        output, ledger.ciphertext_commitment_constraints_per_ciphertext);
    append_u64(output, ledger.ciphertext_commitment_constraints);
    append_u64(output,
               ledger.poseidon_sbox_constraints_per_ciphertext);
    append_u64(
        output,
        ledger.poseidon_checkpoint_constraints_per_ciphertext);
    append_u64(output,
               ledger.poseidon_output_constraints_per_ciphertext);
    append_u64(output, ledger.ciphertext_poseidon_constraints);
    append_u64(output, ledger.total_poseidon_constraints);
    append_u64(output, ledger.packing_relation_constraints);
    append_u64(output, ledger.total_constraints);
    append_u64(output, ledger.matrix_rows);
    append_u64(
        output,
        ledger.ciphertext_poseidon_nonzero_entries_per_ciphertext);
    append_u64(output, ledger.ciphertext_poseidon_nonzero_entries);
    append_u64(
        output,
        ledger.ciphertext_commitment_nonzero_entries_per_ciphertext);
    append_u64(output, ledger.ciphertext_commitment_nonzero_entries);
    append_u64(
        output, ledger.packing_relation_nonzero_entries_upper_bound);
    append_u64(output, ledger.total_nonzero_entries_upper_bound);
    append_u64(output, ledger.commitment_logical_inputs);
    append_u64(output, ledger.packing_logical_inputs);
    append_u64(output, ledger.total_logical_inputs);
    append_u64(output, ledger.total_public_inputs);
    append_u64(output, ledger.packing_witness_variables);
    append_u64(
        output,
        ledger.ciphertext_poseidon_auxiliary_witness_variables);
    append_u64(
        output,
        ledger.ciphertext_commitment_auxiliary_witness_variables);
    append_u64(output, ledger.active_witness_variables);
    append_u64(output, ledger.total_witness_variables);
}

void append_alignment_layout(std::vector<std::uint8_t> &output,
                             const PackingLayout &layout) {
    append_size(output, layout.slot_count, "packing slot count");
    append_u64(output, static_cast<std::uint64_t>(layout.slot_pattern));
    append_size(output, layout.maximum_row_contributions,
                "packing row contribution bound");
    append_size(output, layout.message_active_slots.size(),
                "packing source count");
    for (const std::size_t active : layout.message_active_slots) {
        append_size(output, active, "packing source active slots");
    }
    append_size(output, layout.placements.size(),
                "packing placement count");
    for (const PackingPlacement &placement : layout.placements) {
        append_size(output, placement.message_index,
                    "packing placement message");
        append_size(output, placement.source_begin,
                    "packing placement source begin");
        append_size(output, placement.packed_index,
                    "packing placement output");
        append_size(output, placement.destination_begin,
                    "packing placement destination");
        append_size(output, placement.length,
                    "packing placement length");
        append_size(output, placement.rotation_steps,
                    "packing placement rotation");
    }
    append_size(output, layout.packed_ciphertext_count,
                "packing output count");
}

void append_packing_operator(std::vector<std::uint8_t> &output,
                             const PackingLinearOperator &packing) {
    append_size(output, packing.slot_count, "operator slot count");
    append_size(output, packing.source_ciphertext_count,
                "operator source count");
    append_size(output, packing.aligned_ciphertext_count,
                "operator aligned count");
    append_size(output, packing.rows.size(), "operator row count");
    for (const PackingLinearOperator::OutputRow &row : packing.rows) {
        append_size(output, row.output_index, "operator output index");
        append_size(output, row.contributions.size(),
                    "operator contribution count");
        for (const PackingLinearOperator::AlignedCiphertext &input :
             row.contributions) {
            append_size(output, input.aligned_index,
                        "operator aligned index");
            append_size(output, input.source_index,
                        "operator source index");
            append_u64(output,
                       static_cast<std::uint64_t>(input.slot_pattern));
            append_size(output, input.source_begin,
                        "operator source begin");
            append_size(output, input.rotation_steps,
                        "operator rotation");
            append_size(output, input.destination_begin,
                        "operator destination begin");
            append_size(output, input.length, "operator input length");
        }
    }
}

void append_parameters(
    std::vector<std::uint8_t> &output,
    const LazyTernaryParameters &parameters) {
    append_size(output, parameters.repetitions, "repetitions");
    append_u64(output, parameters.honest_error_bound);
    append_u64(output, parameters.packing_radix.plaintext_modulus);
    append_u64(output, parameters.packing_radix.base);
    append_size(output, parameters.packing_radix.digit_count,
                "packing digit count");
}

void append_tensor_descriptor(
    std::vector<std::uint8_t> &output,
    const PackingTensorDescriptor &descriptor) {
    append_size(output, descriptor.logical_output,
                "tensor logical output");
    append_size(output, descriptor.live_owner_count,
                "tensor live owner count");
    append_size(output, descriptor.padded_owner_count,
                "tensor padded owner count");
    append_size(output, descriptor.ring_degree, "tensor ring degree");
    append_size(output, descriptor.digit_count, "tensor digit count");
    append_u64(output, descriptor.field_element_bytes);
    append_u64(output, descriptor.live_elements);
    append_u64(output, descriptor.padded_elements);
    append_u64(output, descriptor.live_bytes);
    append_u64(output, descriptor.padded_bytes);
}

void append_tensor_geometry(
    std::vector<std::uint8_t> &output,
    const PackingTensorGeometry &geometry) {
    append_size(output, geometry.outputs.size(), "tensor output count");
    for (const PackingTensorDescriptor &descriptor : geometry.outputs) {
        append_tensor_descriptor(output, descriptor);
    }
    append_u64(output, geometry.total_live_elements);
    append_u64(output, geometry.total_padded_elements);
    append_u64(output, geometry.total_live_bytes);
    append_u64(output, geometry.total_padded_bytes);
}

void append_tensor_mappings(
    std::vector<std::uint8_t> &output,
    std::span<const PackingTensorMapping> mappings) {
    append_size(output, mappings.size(), "tensor mapping count");
    for (const PackingTensorMapping &mapping : mappings) {
        append_tensor_descriptor(output, mapping.descriptor);
        append_size(output, mapping.global_owners.size(),
                    "tensor owner count");
        for (const std::size_t owner : mapping.global_owners) {
            append_size(output, owner, "tensor owner");
        }
    }
}

void append_poseidon_template_matrix(
    std::vector<std::uint8_t> &output, spartan::Matrix matrix,
    std::span<const spartan::R1csEntry> entries) {
    append_u64(output, static_cast<std::uint64_t>(matrix));
    append_size(output, entries.size(), "Poseidon template entries");
    for (const spartan::R1csEntry &entry : entries) {
        append_u64(output, entry.row);
        append_u64(output, entry.column);
        append_u64(output, entry.value.value());
    }
}

Digest structured_semantic_digest(
    const ProofOfPackingStructuredMetadata &metadata) {
    std::vector<std::uint8_t> encoding;
    append_string(encoding,
                  kProofOfPackingStructuredR1csSemanticVersion);
    append_alignment_layout(encoding, metadata.alignment_layout);
    append_packing_operator(encoding, metadata.packing_operator);
    append_parameters(encoding, metadata.parameters);
    append_relation_plan(encoding, metadata.relation_plan);
    append_r1cs_layout(encoding, metadata.r1cs_layout);
    append_r1cs_ledger(encoding, metadata.r1cs_ledger);
    append_tensor_geometry(encoding, metadata.tensor_geometry);
    append_tensor_mappings(encoding, metadata.tensor_mappings);
    append_digest(
        encoding, metadata.ciphertext_commitment_gadget_digest);

    const spartan::R1csShape &shape =
        metadata.circuit_metadata.shape();
    append_u64(encoding, shape.constraints);
    append_u64(encoding, shape.public_inputs);
    append_u64(encoding, shape.witness_variables);
    append_size(encoding,
                metadata.circuit_metadata.padded_constraints(),
                "padded constraint count");
    append_size(encoding,
                metadata.circuit_metadata.assignment_half_size(),
                "assignment half");
    return sha256(encoding);
}

ProofOfPackingStructuredMetadata derive_structured_metadata(
    const PackingLayout &alignment_layout,
    LazyTernaryParameters parameters,
    gkr::CiphertextCommitmentPolicy ciphertext_commitment_policy) {
    alignment_layout.validate();
    ciphertext_commitment_policy.validate();
    parameters.packing_radix.validate();
    if (parameters.repetitions == 0 ||
        parameters.honest_error_bound == 0 ||
        parameters.packing_radix.plaintext_modulus != kBaseFieldOrder) {
        throw std::invalid_argument(
            "structured packing metadata has invalid lazy-ternary "
            "parameters");
    }

    ProofOfPackingStructuredMetadata result;
    result.alignment_layout = alignment_layout;
    result.packing_operator =
        make_packing_linear_operator(alignment_layout);
    result.parameters = std::move(parameters);
    result.relation_plan = make_outer_relation_plan(
        OuterRelationShape{
            .native_modulus = kOuterFieldOrder,
            .ring_degree = result.packing_operator.slot_count,
            .aligned_ciphertexts =
                result.packing_operator.aligned_ciphertext_count,
            .repetitions = result.parameters.repetitions,
            .logical_packed_outputs =
                result.packing_operator.rows.size(),
            .packing_digit_count =
                result.parameters.packing_radix.digit_count,
            .ciphertext_components =
                gkr::kCiphertextCommitmentComponents,
            .public_input_capacity_bits =
                outer_relation_public_input_capacity(kOuterFieldOrder),
            .ciphertext_commitment_policy =
                ciphertext_commitment_policy,
        });
    result.r1cs_layout =
        make_proof_of_packing_r1cs_layout(result.relation_plan);
    result.r1cs_ledger =
        proof_of_packing_r1cs_ledger(result.relation_plan);
    result.tensor_mappings = packing_tensor_mappings(
        result.packing_operator,
        result.parameters.packing_radix.digit_count,
        kSerializedFqBytes);
    std::vector<std::size_t> owner_counts;
    owner_counts.reserve(result.tensor_mappings.size());
    for (const PackingTensorMapping &mapping : result.tensor_mappings) {
        owner_counts.push_back(mapping.global_owners.size());
    }
    result.tensor_geometry = packing_tensor_geometry(
        owner_counts, result.relation_plan.shape.ring_degree,
        result.relation_plan.shape.packing_digit_count,
        kSerializedFqBytes);
    result.ciphertext_commitment_gadget_digest =
        proof_of_packing_ciphertext_commitment_gadget_digest(
            ciphertext_commitment_policy);

    const spartan::R1csShape shape{
        .constraints = result.r1cs_ledger.matrix_rows,
        .public_inputs = result.r1cs_ledger.total_public_inputs,
        .witness_variables = result.r1cs_ledger.total_witness_variables,
    };
    const std::size_t padded_constraints = exact_power_of_two_padding(
        shape.constraints, "structured R1CS constraints");
    const std::uint64_t public_side = checked_add(
        shape.public_inputs, 1, "structured R1CS public side");
    const std::size_t assignment_half = exact_power_of_two_padding(
        std::max(public_side, shape.witness_variables),
        "structured R1CS assignment half");
    result.circuit_metadata = spartan::R1csMetadata(
        shape, padded_constraints, assignment_half, Digest{});
    result.semantic_circuit_digest = structured_semantic_digest(result);
    result.circuit_metadata = spartan::R1csMetadata(
        shape, padded_constraints, assignment_half,
        result.semantic_circuit_digest);
    return result;
}

} // namespace

Digest proof_of_packing_poseidon_gadget_digest() {
    std::vector<std::uint8_t> encoding;
    append_string(encoding,
                  kProofOfPackingPoseidonGadgetSemanticVersion);
    append_u64(encoding, kOuterFieldOrder);
    append_size(encoding, kPoseidonWidth, "Poseidon width");
    append_size(encoding, kPoseidonRate, "Poseidon rate");
    append_size(encoding, kPoseidonCapacity, "Poseidon capacity");
    append_size(encoding, kPoseidonFullRounds, "Poseidon full rounds");
    append_size(encoding, kPoseidonPartialRounds,
                "Poseidon partial rounds");
    append_size(encoding, kPoseidonDigestElements,
                "Poseidon digest elements");
    append_u64(
        encoding,
        static_cast<std::uint64_t>(PoseidonDomain::CiphertextCommitment));
    append_size(encoding,
                gkr::kCiphertextCommitmentMetadataElements,
                "ciphertext commitment metadata elements");
    append_u64(encoding, gkr::kCiphertextCommitmentComponents);
    append_u64(encoding, gkr::kCiphertextCommitmentNttFlag);
    append_u64(encoding, gkr::kCiphertextCommitmentCorrectionFactor);
    append_u64(encoding, kPoseidonEncodingVersionDelimiter);
    append_u64(encoding, kPoseidonRatePaddingDelimiter);

    const PoseidonRoundConstants &round_constants =
        poseidon_round_constants();
    append_size(encoding, round_constants.size(),
                "Poseidon round-constant rows");
    for (std::size_t round = 0; round < round_constants.size(); ++round) {
        append_u64(encoding, poseidon_round_is_full(round) ? 1U : 0U);
        append_u64(
            encoding,
            poseidon_round_is_r1cs_checkpoint(round) ? 1U : 0U);
        for (const Fq &constant : round_constants[round]) {
            append_u64(encoding, constant.value());
        }
    }
    const PoseidonMdsMatrix &mds = poseidon_mds_matrix();
    append_size(encoding, mds.size(), "Poseidon MDS rows");
    for (const PoseidonState &row : mds) {
        for (const Fq &coefficient : row) {
            append_u64(encoding, coefficient.value());
        }
    }

    const detail::PoseidonPermutationR1csTemplate &local =
        detail::proof_of_packing_poseidon_permutation_template();
    append_u64(encoding, local.rows);
    append_poseidon_template_matrix(
        encoding, spartan::Matrix::A, local.a);
    append_poseidon_template_matrix(
        encoding, spartan::Matrix::B, local.b);
    append_poseidon_template_matrix(
        encoding, spartan::Matrix::C, local.c);
    for (const std::uint64_t auxiliary : local.final_auxiliary) {
        append_u64(encoding, auxiliary);
    }
    return sha256(encoding);
}

Digest proof_of_packing_ciphertext_commitment_gadget_digest(
    gkr::CiphertextCommitmentPolicy policy) {
    policy.validate();
    if (policy.relation ==
        gkr::CiphertextCommitmentRelation::PoseidonV2) {
        return proof_of_packing_poseidon_gadget_digest();
    }

    std::vector<std::uint8_t> encoding;
    append_string(
        encoding,
        kProofOfPackingDiagnosticSimpleCtHashGadgetSemanticVersion);
    append_u64(encoding, policy.wire_code());
    append_u64(encoding, kOuterFieldOrder);
    append_size(encoding, kPoseidonDigestElements,
                "diagnostic digest elements");
    append_size(encoding,
                gkr::kCiphertextCommitmentMetadataElements,
                "diagnostic metadata elements");
    append_u64(encoding, gkr::kCiphertextCommitmentComponents);
    append_u64(encoding, gkr::kCiphertextCommitmentNttFlag);
    append_u64(encoding, gkr::kCiphertextCommitmentCorrectionFactor);
    append_u64(encoding, gkr::kDiagnosticSimpleCtHashAlpha);
    append_u64(encoding, gkr::kDiagnosticSimpleCtHashInitialState);
    for (const std::uint64_t domain :
         gkr::kDiagnosticSimpleCtHashOutputDomains) {
        append_u64(encoding, domain);
    }
    append_string(
        encoding,
        "metadata-folded-in-initial-state;"
        "state-next=alpha*state+coordinate;"
        "digest-i=state-final+output-domain-i;"
        "one-linear-r1cs-row-per-coordinate-and-output");
    return sha256(encoding);
}

Digest ProofOfPackingStructuredMetadata::
recompute_semantic_circuit_digest() const {
    return structured_semantic_digest(*this);
}

void ProofOfPackingStructuredMetadata::validate() const {
    const gkr::CiphertextCommitmentPolicy policy =
        relation_plan.shape.ciphertext_commitment_policy;
    if (!circuit_metadata.is_well_formed() ||
        circuit_metadata.digest() != semantic_circuit_digest ||
        ciphertext_commitment_gadget_digest !=
            proof_of_packing_ciphertext_commitment_gadget_digest(policy) ||
        recompute_semantic_circuit_digest() !=
            semantic_circuit_digest) {
        throw std::invalid_argument(
            "structured proof-of-packing metadata has an invalid identity");
    }
    const ProofOfPackingStructuredMetadata expected =
        derive_structured_metadata(alignment_layout, parameters, policy);
    if (expected.semantic_circuit_digest != semantic_circuit_digest ||
        expected.circuit_metadata != circuit_metadata ||
        expected.ciphertext_commitment_gadget_digest !=
            ciphertext_commitment_gadget_digest ||
        expected.tensor_geometry != tensor_geometry ||
        expected.tensor_mappings != tensor_mappings) {
        throw std::invalid_argument(
            "structured proof-of-packing metadata is noncanonical");
    }
}

ProofOfPackingStructuredMetadata
make_proof_of_packing_structured_metadata(
    const PackingLayout &alignment_layout,
    LazyTernaryParameters parameters,
    gkr::CiphertextCommitmentPolicy ciphertext_commitment_policy) {
    ProofOfPackingStructuredMetadata result = derive_structured_metadata(
        alignment_layout, std::move(parameters),
        ciphertext_commitment_policy);
    result.validate();
    return result;
}

} // namespace laminate::packing
