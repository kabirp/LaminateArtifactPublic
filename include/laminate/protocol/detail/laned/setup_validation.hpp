#ifndef LAMINATE_PROTOCOL_DETAIL_LANED_SETUP_VALIDATION_HPP
#define LAMINATE_PROTOCOL_DETAIL_LANED_SETUP_VALIDATION_HPP

/// @file setup_validation.hpp
/// @brief Canonical Laned transcript-packing setup validation.

#include "laminate/protocol/packed/setup.hpp"

namespace laminate::protocol::laned_protocol_detail {

inline bool same_packing_operator(
    const packing::PackingLinearOperator &left,
    const packing::PackingLinearOperator &right) {
    if (left.slot_count != right.slot_count ||
        left.source_ciphertext_count != right.source_ciphertext_count ||
        left.aligned_ciphertext_count != right.aligned_ciphertext_count ||
        left.rows.size() != right.rows.size()) {
        return false;
    }
    for (std::size_t row = 0; row < left.rows.size(); ++row) {
        const auto &left_row = left.rows[row];
        const auto &right_row = right.rows[row];
        if (left_row.output_index != right_row.output_index ||
            left_row.contributions.size() !=
                right_row.contributions.size()) {
            return false;
        }
        for (std::size_t contribution = 0;
             contribution < left_row.contributions.size(); ++contribution) {
            const auto &a = left_row.contributions[contribution];
            const auto &b = right_row.contributions[contribution];
            if (a.aligned_index != b.aligned_index ||
                a.source_index != b.source_index ||
                a.slot_pattern != b.slot_pattern ||
                a.source_begin != b.source_begin ||
                a.rotation_steps != b.rotation_steps ||
                a.destination_begin != b.destination_begin ||
                a.length != b.length) {
                return false;
            }
        }
    }
    return true;
}

inline bool same_outer_range(const packing::OuterRelationRange &left,
                             const packing::OuterRelationRange &right) {
    return left.begin == right.begin && left.count == right.count;
}

/// The outer relation plan is derived setup. Compare every derived range so
/// that a dimension-compatible but noncanonical plan cannot reach proving.
inline bool same_outer_plan(const packing::OuterRelationPlan &left,
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
        ls.public_input_capacity_bits == rs.public_input_capacity_bits &&
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
        lf.output_relation_constraints == rf.output_relation_constraints &&
        lf.constant_matrix_terms == rf.constant_matrix_terms;

    const auto &lp = left.variables.public_inputs;
    const auto &rp = right.variables.public_inputs;
    const bool same_public =
        same_outer_range(lp.packed_challenge_words,
                         rp.packed_challenge_words) &&
        same_outer_range(lp.revealed_test_coordinates,
                         rp.revealed_test_coordinates) &&
        same_outer_range(lp.revealed_packing_coordinates,
                         rp.revealed_packing_coordinates) &&
        lp.total == rp.total;

    const auto &lv = left.variables.witness;
    const auto &rv = right.variables.witness;
    const bool same_witness =
        same_outer_range(lv.derived_challenge_bits,
                         rv.derived_challenge_bits) &&
        same_outer_range(lv.aligned_ciphertext_coordinates,
                         rv.aligned_ciphertext_coordinates) &&
        same_outer_range(lv.well_formedness_products,
                         rv.well_formedness_products) &&
        lv.total == rv.total;

    const auto &lc = left.constraints;
    const auto &rc = right.constraints;
    const bool same_constraints =
        same_outer_range(lc.challenge_bit_booleanity,
                         rc.challenge_bit_booleanity) &&
        same_outer_range(lc.challenge_word_recomposition,
                         rc.challenge_word_recomposition) &&
        same_outer_range(lc.well_formedness_products,
                         rc.well_formedness_products) &&
        same_outer_range(lc.revealed_test_equalities,
                         rc.revealed_test_equalities) &&
        same_outer_range(lc.revealed_packing_equalities,
                         rc.revealed_packing_equalities) &&
        lc.total == rc.total;

    return same_shape && same_well_formedness && same_fixed && same_public &&
           same_witness && same_constraints;
}

template <packing::SignedDigitPackingBackend Backend>
void validate_packing_setup(
    const payload::LayeredCircuit &circuit,
    const EvaluationSetup<Backend> &setup,
    const LanedSetup &packing_setup) {
    const TranscriptPackingSpartanSetup &packing_state =
        packing_setup.transcript_packing;
    const std::size_t slot_count = Backend::slot_count(setup.context);
    const std::size_t bhip_rounds = laned_bhip_round_count(circuit);
    if (packing_state.variant != PackingGkrVariant::Laned ||
        packing_state.bhip_round_count != bhip_rounds ||
        Backend::lowest_coefficient_modulus(setup.context) !=
            kOuterFieldOrder) {
        throw std::invalid_argument(
            "prove_laned: packing setup does not match the circuit");
    }

    // The digit system fixes how aligned ciphertext coefficients become the
    // outer relation's witness and public reveals.
    packing_state.parameters.packing_radix.validate();
    if (packing_state.parameters.repetitions == 0 ||
        packing_state.parameters.packing_radix.plaintext_modulus !=
            kBaseFieldOrder ||
        packing_state.radix != packing_state.parameters.packing_radix) {
        throw std::invalid_argument(
            "prove_laned: packing parameters are inconsistent");
    }
    (void)packing_state.parameters.honest_partial_decryption_bound();
    (void)packing::lazy_ternary_test_threshold(
        packing_state.parameters.honest_partial_decryption_bound(),
        bhip_rounds);

    // The layout and linear operator are canonical functions of the ring
    // geometry and the number of encrypted GKR messages.
    packing_state.alignment_layout.validate();
    const packing::PackingLayout expected_layout =
        packing::make_fixed_message_coset_packing_layout(
            slot_count, bhip_rounds,
            slot_count / fhe::kFixedMessageCellCount);
    if (packing_state.alignment_layout != expected_layout) {
        throw std::invalid_argument(
            "prove_laned: packing layout is not canonical for the circuit");
    }
    packing_state.packing_operator.validate();
    const packing::PackingLinearOperator expected_operator =
        packing::make_packing_linear_operator(expected_layout);
    if (!same_packing_operator(packing_state.packing_operator,
                               expected_operator)) {
        throw std::invalid_argument(
            "prove_laned: packing operator does not match its layout");
    }

    // Re-derive the outer relation and require the setup's sparse matrices
    // and ledger to describe exactly that relation.
    const packing::OuterRelationPlan expected_plan =
        packing::make_outer_relation_plan(packing::OuterRelationShape{
            .native_modulus = kOuterFieldOrder,
            .ring_degree = slot_count,
            .aligned_ciphertexts = bhip_rounds,
            .repetitions = packing_state.parameters.repetitions,
            .logical_packed_outputs =
                expected_layout.packed_ciphertext_count,
            .packing_digit_count = packing_state.radix.digit_count,
            .ciphertext_components = 2,
            .public_input_capacity_bits = 59,
            .ciphertext_commitment_policy =
                packing_state.relation_plan.shape
                    .ciphertext_commitment_policy,
        });
    const packing::ProofOfPackingR1csLedger expected_ledger =
        packing::proof_of_packing_r1cs_ledger(expected_plan);
    if (!same_outer_plan(packing_state.relation_plan, expected_plan) ||
        packing_state.r1cs_ledger != expected_ledger ||
        !packing_state.fixed_matrix_statistics.complete) {
        throw std::invalid_argument(
            "prove_laned: packing relation does not match its geometry");
    }

    // Finally bind the Spartan/BaseFold key material to the re-derived R1CS.
    const spartan::BaseFoldPcs pcs(packing_state.basefold_parameters);
    const spartan::ProverKey &prover = packing_state.spartan.prover_key;
    const spartan::VerifierKey &verifier =
        packing_state.spartan.verifier_key;
    const spartan::R1csShape expected_shape{
        .constraints = expected_ledger.matrix_rows,
        .public_inputs = expected_ledger.total_public_inputs,
        .witness_variables = expected_ledger.total_witness_variables,
    };
    if (prover.circuit == nullptr ||
        prover.circuit->shape() != expected_shape ||
        prover.circuit->metadata() != verifier.circuit_metadata ||
        prover.setup_digest != verifier.setup_digest ||
        prover.pcs_scheme != pcs.scheme_identifier() ||
        verifier.pcs_scheme != pcs.scheme_identifier() ||
        prover.options != packing_state.spartan_options ||
        verifier.options != packing_state.spartan_options) {
        throw std::invalid_argument(
            "prove_laned: Spartan setup does not match the packing relation");
    }
}

} // namespace laminate::protocol::laned_protocol_detail

#endif // LAMINATE_PROTOCOL_DETAIL_LANED_SETUP_VALIDATION_HPP
