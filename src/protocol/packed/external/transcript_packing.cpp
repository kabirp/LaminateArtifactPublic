/// @file transcript_packing.cpp
/// @brief Offline certification for the external packing prover.

#include "laminate/protocol/packed/external/transcript_packing.hpp"

#include "laminate/packing/proof/matrix/oracle.hpp"
#include "laminate/protocol/packed/reference/materialized_external_setup.hpp"

#include <algorithm>
#include <memory>
#include <stdexcept>
#include <utility>

namespace laminate::protocol {

namespace detail {

struct TranscriptPackingExternalReferenceSetupAccess {
    static TranscriptPackingExternalProverSetup make(
        PackingGkrVariant variant, std::size_t bhip_round_count,
        packing::ProofOfPackingStructuredMetadata relation,
        std::shared_ptr<const spartan::BaseFoldPcs> basefold_pcs,
        spartan::ExternalProverKey spartan_key) {
        return TranscriptPackingExternalProverSetup(
            variant, bhip_round_count, std::move(relation),
            std::move(basefold_pcs), std::move(spartan_key));
    }
};

} // namespace detail

namespace {

bool same_range(const packing::OuterRelationRange &left,
                const packing::OuterRelationRange &right) {
    return left.begin == right.begin && left.count == right.count;
}

bool same_plan(const packing::OuterRelationPlan &left,
               const packing::OuterRelationPlan &right) {
    const auto &ls = left.shape;
    const auto &rs = right.shape;
    const bool same_shape =
        ls.native_modulus == rs.native_modulus &&
        ls.ring_degree == rs.ring_degree &&
        ls.aligned_ciphertexts == rs.aligned_ciphertexts &&
        ls.repetitions == rs.repetitions &&
        ls.logical_packed_outputs == rs.logical_packed_outputs &&
        ls.packing_digit_count == rs.packing_digit_count &&
        ls.ciphertext_components == rs.ciphertext_components &&
        ls.public_input_capacity_bits ==
            rs.public_input_capacity_bits &&
        ls.ciphertext_commitment_policy ==
            rs.ciphertext_commitment_policy;
    const auto &lw = left.well_formedness;
    const auto &rw = right.well_formedness;
    const bool same_well_formedness =
        lw.revealed_ciphertext_coordinates ==
            rw.revealed_ciphertext_coordinates &&
        lw.coefficient_products == rw.coefficient_products &&
        lw.output_relations == rw.output_relations &&
        lw.challenge_bits == rw.challenge_bits &&
        lw.booleanity_constraints == rw.booleanity_constraints &&
        lw.packed_public_inputs == rw.packed_public_inputs &&
        lw.public_input_recomposition_constraints ==
            rw.public_input_recomposition_constraints &&
        lw.subtotal_constraints == rw.subtotal_constraints;
    const auto &lf = left.fixed_packing;
    const auto &rf = right.fixed_packing;
    const bool same_fixed =
        lf.witness_input_coordinates == rf.witness_input_coordinates &&
        lf.public_output_coordinates == rf.public_output_coordinates &&
        lf.output_relation_constraints ==
            rf.output_relation_constraints &&
        lf.constant_matrix_terms == rf.constant_matrix_terms;
    const auto &lp = left.variables.public_inputs;
    const auto &rp = right.variables.public_inputs;
    const auto &lv = left.variables.witness;
    const auto &rv = right.variables.witness;
    const bool same_variables =
        same_range(lp.packed_challenge_words,
                   rp.packed_challenge_words) &&
        same_range(lp.revealed_test_coordinates,
                   rp.revealed_test_coordinates) &&
        same_range(lp.revealed_packing_coordinates,
                   rp.revealed_packing_coordinates) &&
        lp.total == rp.total &&
        same_range(lv.derived_challenge_bits,
                   rv.derived_challenge_bits) &&
        same_range(lv.aligned_ciphertext_coordinates,
                   rv.aligned_ciphertext_coordinates) &&
        same_range(lv.well_formedness_products,
                   rv.well_formedness_products) &&
        lv.total == rv.total;
    const auto &lc = left.constraints;
    const auto &rc = right.constraints;
    const bool same_constraints =
        same_range(lc.challenge_bit_booleanity,
                   rc.challenge_bit_booleanity) &&
        same_range(lc.challenge_word_recomposition,
                   rc.challenge_word_recomposition) &&
        same_range(lc.well_formedness_products,
                   rc.well_formedness_products) &&
        same_range(lc.revealed_test_equalities,
                   rc.revealed_test_equalities) &&
        same_range(lc.revealed_packing_equalities,
                   rc.revealed_packing_equalities) &&
        lc.total == rc.total;
    return same_shape && same_well_formedness && same_fixed &&
           same_variables && same_constraints;
}

bool same_operator(
    const packing::PackingLinearOperator &left,
    const packing::PackingLinearOperator &right) {
    if (left.slot_count != right.slot_count ||
        left.source_ciphertext_count !=
            right.source_ciphertext_count ||
        left.aligned_ciphertext_count !=
            right.aligned_ciphertext_count ||
        left.rows.size() != right.rows.size()) {
        return false;
    }
    for (std::size_t row = 0; row < left.rows.size(); ++row) {
        const auto &lr = left.rows[row];
        const auto &rr = right.rows[row];
        if (lr.output_index != rr.output_index ||
            lr.contributions.size() != rr.contributions.size()) {
            return false;
        }
        for (std::size_t contribution = 0;
             contribution < lr.contributions.size(); ++contribution) {
            const auto &lc = lr.contributions[contribution];
            const auto &rc = rr.contributions[contribution];
            if (lc.aligned_index != rc.aligned_index ||
                lc.source_index != rc.source_index ||
                lc.slot_pattern != rc.slot_pattern ||
                lc.source_begin != rc.source_begin ||
                lc.rotation_steps != rc.rotation_steps ||
                lc.destination_begin != rc.destination_begin ||
                lc.length != rc.length) {
                return false;
            }
        }
    }
    return true;
}

void validate_geometry(
    PackingGkrVariant variant, std::size_t bhip_round_count,
    const packing::ProofOfPackingStructuredMetadata &relation) {
    if ((variant != PackingGkrVariant::Folded &&
         variant != PackingGkrVariant::Laned) ||
        bhip_round_count == 0) {
        throw std::invalid_argument(
            "external transcript-packing setup has an invalid variant or "
            "round count");
    }
    if (relation.alignment_layout.placements.size() != bhip_round_count ||
        relation.alignment_layout.message_active_slots.size() !=
            bhip_round_count ||
        relation.packing_operator.source_ciphertext_count !=
            bhip_round_count ||
        relation.packing_operator.aligned_ciphertext_count !=
            bhip_round_count ||
        relation.relation_plan.shape.aligned_ciphertexts !=
            bhip_round_count ||
        relation.relation_plan.shape.repetitions !=
            relation.parameters.repetitions ||
        relation.relation_plan.shape.packing_digit_count !=
            relation.parameters.packing_radix.digit_count ||
        relation.parameters.packing_radix.plaintext_modulus !=
            kBaseFieldOrder) {
        throw std::invalid_argument(
            "external transcript-packing setup geometry is inconsistent");
    }
}

void validate_artifact_backed_key(
    const packing::ProofOfPackingStructuredMetadata &relation,
    const spartan::R1csMetadata &expected_metadata,
    const std::shared_ptr<const spartan::BaseFoldPcs> &basefold_pcs,
    const spartan::ExternalProverKey &spartan_key) {
    if (basefold_pcs == nullptr) {
        throw std::invalid_argument(
            "external transcript-packing setup has no BaseFold PCS");
    }
    spartan::validate_external_prover_key(spartan_key, *basefold_pcs);
    if (spartan_key.circuit_metadata != expected_metadata ||
        spartan_key.options.matrix_evaluation !=
            spartan::MatrixEvaluationMode::CommittedFactored ||
        spartan_key.factored_computation == nullptr ||
        spartan_key.factored_computation->tensor_column_source !=
            spartan::FactoredTensorColumnSource::Artifact ||
        spartan_key.factored_computation->tensor_columns_artifact ==
            nullptr ||
        spartan_key.factored_computation->tensors.size() !=
            relation.tensor_mappings.size() ||
        std::any_of(
            spartan_key.factored_computation->tensors.begin(),
            spartan_key.factored_computation->tensors.end(),
            [](const spartan::FactoredTensorProverKey &tensor) {
                return tensor.opening_state_source !=
                           spartan::FactoredTensorProverKey::
                               OpeningStateSource::External ||
                       tensor.opening_state == nullptr;
            })) {
        throw std::invalid_argument(
            "external transcript-packing setup is not fully "
            "artifact-backed");
    }

    const auto expected_structure =
        packing::make_proof_of_packing_factored_structure(
            relation.relation_plan, relation.r1cs_layout,
            relation.tensor_mappings, expected_metadata);
    const auto &actual_structure =
        spartan_key.factored_computation->structure;
    if (actual_structure == nullptr ||
        actual_structure->circuit_digest() !=
            expected_structure->circuit_digest() ||
        actual_structure->structure_digest() !=
            expected_structure->structure_digest() ||
        actual_structure->row_variables() !=
            expected_structure->row_variables() ||
        actual_structure->column_variables() !=
            expected_structure->column_variables() ||
        packing::proof_of_packing_factored_tensor_mappings(
            *actual_structure) != relation.tensor_mappings) {
        throw std::invalid_argument(
            "external transcript-packing factored structure does not "
            "match the certified relation");
    }
}

} // namespace

TranscriptPackingExternalProverSetup
make_transcript_packing_external_prover_setup(
    PackingGkrVariant variant, std::size_t bhip_round_count,
    packing::ProofOfPackingStructuredMetadata relation,
    std::shared_ptr<const spartan::BaseFoldPcs> basefold_pcs,
    spartan::ExternalProverKey spartan_key) {
    relation.validate();
    validate_geometry(variant, bhip_round_count, relation);
    validate_artifact_backed_key(
        relation, relation.circuit_metadata, basefold_pcs, spartan_key);

    return TranscriptPackingExternalProverSetup(
        variant, bhip_round_count, std::move(relation),
        std::move(basefold_pcs), std::move(spartan_key));
}

namespace reference {

TranscriptPackingExternalProverSetup
make_materialized_reference_external_prover_setup(
    const TranscriptPackingSpartanSetup &resident_setup,
    std::shared_ptr<const spartan::BaseFoldPcs> basefold_pcs,
    spartan::ExternalProverKey spartan_key) {
    packing::ProofOfPackingStructuredMetadata relation =
        packing::make_proof_of_packing_structured_metadata(
            resident_setup.alignment_layout, resident_setup.parameters,
            resident_setup.relation_plan.shape
                .ciphertext_commitment_policy);
    validate_geometry(resident_setup.variant,
                      resident_setup.bhip_round_count, relation);
    if (basefold_pcs == nullptr ||
        basefold_pcs->parameters() !=
            resident_setup.basefold_parameters ||
        resident_setup.alignment_layout != relation.alignment_layout ||
        !same_operator(resident_setup.packing_operator,
                       relation.packing_operator) ||
        !same_plan(resident_setup.relation_plan,
                   relation.relation_plan) ||
        resident_setup.r1cs_ledger != relation.r1cs_ledger ||
        resident_setup.parameters != relation.parameters ||
        resident_setup.radix != relation.parameters.packing_radix ||
        resident_setup.spartan_options.matrix_evaluation !=
            spartan::MatrixEvaluationMode::CommittedFactored ||
        resident_setup.spartan.prover_key.circuit == nullptr ||
        resident_setup.spartan.prover_key.factored_computation == nullptr ||
        resident_setup.spartan.verifier_key.factored_computation == nullptr) {
        throw std::invalid_argument(
            "materialized transcript-packing reference is inconsistent");
    }

    const spartan::R1csMetadata materialized_metadata =
        resident_setup.spartan.prover_key.circuit->metadata();
    if (materialized_metadata !=
            resident_setup.spartan.verifier_key.circuit_metadata ||
        materialized_metadata.shape() !=
            relation.circuit_metadata.shape() ||
        materialized_metadata.padded_constraints() !=
            relation.circuit_metadata.padded_constraints() ||
        materialized_metadata.assignment_half_size() !=
            relation.circuit_metadata.assignment_half_size() ||
        resident_setup.spartan.prover_key.setup_digest !=
            resident_setup.spartan.verifier_key.setup_digest ||
        resident_setup.spartan.prover_key.pcs_scheme !=
            resident_setup.spartan.verifier_key.pcs_scheme ||
        resident_setup.spartan.prover_key.options !=
            resident_setup.spartan.verifier_key.options ||
        spartan_key.circuit_metadata != materialized_metadata ||
        spartan_key.setup_digest !=
            resident_setup.spartan.prover_key.setup_digest ||
        spartan_key.pcs_scheme !=
            resident_setup.spartan.prover_key.pcs_scheme ||
        spartan_key.options !=
            resident_setup.spartan.prover_key.options ||
        spartan_key.factored_computation == nullptr ||
        spartan_key.factored_computation->commitment !=
            resident_setup.spartan.prover_key.factored_computation
                ->commitment) {
        throw std::invalid_argument(
            "external key does not match the materialized reference");
    }
    validate_artifact_backed_key(
        relation, materialized_metadata, basefold_pcs, spartan_key);

    return detail::TranscriptPackingExternalReferenceSetupAccess::make(
        resident_setup.variant, resident_setup.bhip_round_count,
        std::move(relation), std::move(basefold_pcs),
        std::move(spartan_key));
}

} // namespace reference

} // namespace laminate::protocol
