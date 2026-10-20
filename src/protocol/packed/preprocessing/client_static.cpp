/// @file client_static.cpp

#include "laminate/protocol/packed/preprocessing/client_static.hpp"

#include "laminate/fhe/layout/fixed_message.hpp"
#include "laminate/packing/proof/matrix/oracle.hpp"
#include "laminate/packing/proof/matrix/metadata.hpp"

#include <algorithm>
#include <stdexcept>
#include <utility>
#include <variant>

namespace laminate::protocol {
namespace {

bool all_zero(const Digest &digest) {
    return std::all_of(
        digest.begin(), digest.end(),
        [](std::uint8_t byte) { return byte == 0; });
}

bool same_range(const packing::OuterRelationRange &left,
                const packing::OuterRelationRange &right) {
    return left.begin == right.begin && left.count == right.count;
}

bool same_outer_plan(const packing::OuterRelationPlan &left,
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
        same_range(lp.packed_challenge_words,
                   rp.packed_challenge_words) &&
        same_range(lp.revealed_test_coordinates,
                   rp.revealed_test_coordinates) &&
        same_range(lp.revealed_packing_coordinates,
                   rp.revealed_packing_coordinates) &&
        lp.total == rp.total;

    const auto &lv = left.variables.witness;
    const auto &rv = right.variables.witness;
    const bool same_witness =
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
           same_public && same_witness && same_constraints;
}

bool same_packing_operator(
    const packing::PackingLinearOperator &left,
    const packing::PackingLinearOperator &right) {
    if (left.slot_count != right.slot_count ||
        left.source_ciphertext_count != right.source_ciphertext_count ||
        left.aligned_ciphertext_count != right.aligned_ciphertext_count ||
        left.rows.size() != right.rows.size()) {
        return false;
    }
    for (std::size_t row = 0; row < left.rows.size(); ++row) {
        const auto &a = left.rows[row];
        const auto &b = right.rows[row];
        if (a.output_index != b.output_index ||
            a.contributions.size() != b.contributions.size()) {
            return false;
        }
        for (std::size_t contribution = 0;
             contribution < a.contributions.size(); ++contribution) {
            const auto &x = a.contributions[contribution];
            const auto &y = b.contributions[contribution];
            if (x.aligned_index != y.aligned_index ||
                x.source_index != y.source_index ||
                x.slot_pattern != y.slot_pattern ||
                x.source_begin != y.source_begin ||
                x.rotation_steps != y.rotation_steps ||
                x.destination_begin != y.destination_begin ||
                x.length != y.length) {
                return false;
            }
        }
    }
    return true;
}

std::size_t expected_bhip_round_count(
    PackingGkrVariant variant,
    const payload::LayeredCircuit &circuit) {
    return variant == PackingGkrVariant::Folded
               ? folded_bhip_round_count(circuit)
               : laned_bhip_round_count(circuit);
}

payload::PayloadKind expected_payload_kind(PackingGkrVariant variant) {
    return variant == PackingGkrVariant::Folded
               ? payload::PayloadKind::Wide
               : payload::PayloadKind::Laned;
}

void validate_factored_structure(
    const spartan::FactoredMatrixStructure *actual,
    const packing::OuterRelationPlan &expected_plan,
    const packing::ProofOfPackingR1csLayout &expected_layout,
    std::span<const packing::PackingTensorMapping> expected_mappings,
    const spartan::R1csMetadata &expected_circuit) {
    if (actual == nullptr) {
        throw std::invalid_argument(
            "certified packed client requires a factored Spartan verifier");
    }
    const auto expected_structure =
        packing::make_proof_of_packing_factored_structure(
            expected_plan, expected_layout, expected_mappings,
            expected_circuit);
    const auto actual_mappings =
        packing::proof_of_packing_factored_tensor_mappings(*actual);
    if (actual->circuit_digest() != expected_structure->circuit_digest() ||
        actual->structure_digest() != expected_structure->structure_digest() ||
        actual->row_variables() != expected_structure->row_variables() ||
        actual->column_variables() != expected_structure->column_variables() ||
        actual->tensor_count() != expected_structure->tensor_count() ||
        actual_mappings.size() != expected_mappings.size() ||
        !std::equal(actual_mappings.begin(), actual_mappings.end(),
                    expected_mappings.begin())) {
        throw std::invalid_argument(
            "certified packed client factored structure is noncanonical");
    }
    for (std::size_t tensor = 0; tensor < actual->tensor_count(); ++tensor) {
        if (actual->tensor_shape(tensor) !=
            expected_structure->tensor_shape(tensor)) {
            throw std::invalid_argument(
                "certified packed client factored tensor shape is noncanonical");
        }
    }
}

void validate_static_setup(
    const CertifiedPackedWorkloadStatic &workload,
    const Digest &fhe_context_storage_id,
    PackingGkrVariant variant,
    const TranscriptPackingSpartanVerifierSetup &setup) {
    if (all_zero(fhe_context_storage_id) ||
        workload.circuit().shape.kind != expected_payload_kind(variant)) {
        throw std::invalid_argument(
            "certified packed client workload or FHE context is invalid");
    }

    const std::size_t bhip_rounds =
        expected_bhip_round_count(variant, workload.circuit());
    const std::size_t slots = workload.public_setup().shape.slot_count;
    const packing::PackingLayout alignment =
        packing::make_fixed_message_coset_packing_layout(
            slots, bhip_rounds,
            slots / fhe::kFixedMessageCellCount);

    setup.parameters.packing_radix.validate();
    if (setup.variant != variant ||
        setup.bhip_round_count != bhip_rounds ||
        setup.alignment_layout != alignment ||
        setup.parameters.repetitions == 0 ||
        setup.parameters.packing_radix.plaintext_modulus !=
            kBaseFieldOrder ||
        setup.radix != setup.parameters.packing_radix) {
        throw std::invalid_argument(
            "certified packed client verifier geometry is inconsistent");
    }
    (void)setup.parameters.honest_partial_decryption_bound();
    (void)packing::lazy_ternary_test_threshold(
        setup.parameters.honest_partial_decryption_bound(), bhip_rounds);

    packing::ProofOfPackingStructuredMetadata expected =
        packing::make_proof_of_packing_structured_metadata(
            alignment, setup.parameters,
            setup.relation_plan.shape.ciphertext_commitment_policy);
    if (!same_outer_plan(setup.relation_plan, expected.relation_plan)) {
        throw std::invalid_argument(
            "certified packed client relation plan is noncanonical");
    }
    if (setup.spartan.circuit_metadata != expected.circuit_metadata) {
        throw std::invalid_argument(
            "certified packed client Spartan circuit metadata is noncanonical");
    }
    if (setup.spartan.options.matrix_evaluation !=
            spartan::MatrixEvaluationMode::CommittedFactored ||
        setup.spartan.direct_matrix != nullptr ||
        setup.spartan.matrix_oracle != nullptr) {
        throw std::invalid_argument(
            "certified packed client Spartan verifier mode is noncanonical");
    }

    const spartan::BaseFoldPcs pcs(setup.basefold_parameters);
    spartan::validate_verifier_key(setup.spartan, pcs);
    validate_factored_structure(
        setup.spartan.factored_computation == nullptr
            ? nullptr
            : setup.spartan.factored_computation->structure.get(),
        expected.relation_plan, expected.r1cs_layout,
        expected.tensor_mappings, expected.circuit_metadata);
}

void validate_resident_static_setup(
    const CertifiedPackedWorkloadStatic &workload,
    const Digest &fhe_context_storage_id,
    PackingGkrVariant variant,
    const TranscriptPackingSpartanSetup &setup) {
    if (all_zero(fhe_context_storage_id) ||
        workload.circuit().shape.kind != expected_payload_kind(variant)) {
        throw std::invalid_argument(
            "resident packed client workload or FHE context is invalid");
    }
    const std::size_t bhip_rounds =
        expected_bhip_round_count(variant, workload.circuit());
    const std::size_t slots = workload.public_setup().shape.slot_count;
    const packing::PackingLayout alignment =
        packing::make_fixed_message_coset_packing_layout(
            slots, bhip_rounds,
            slots / fhe::kFixedMessageCellCount);
    setup.parameters.packing_radix.validate();
    if (setup.variant != variant ||
        setup.bhip_round_count != bhip_rounds ||
        setup.alignment_layout != alignment ||
        setup.parameters.repetitions == 0 ||
        setup.parameters.packing_radix.plaintext_modulus !=
            kBaseFieldOrder ||
        setup.radix != setup.parameters.packing_radix) {
        throw std::invalid_argument(
            "resident packed client verifier geometry is inconsistent");
    }

    const packing::ProofOfPackingStructuredMetadata expected =
        packing::make_proof_of_packing_structured_metadata(
            alignment, setup.parameters,
            setup.relation_plan.shape.ciphertext_commitment_policy);
    const packing::PackingLinearOperator expected_operator =
        packing::make_packing_linear_operator(alignment);
    if (!same_packing_operator(setup.packing_operator, expected_operator) ||
        !same_outer_plan(setup.relation_plan, expected.relation_plan) ||
        setup.r1cs_ledger != expected.r1cs_ledger ||
        !setup.fixed_matrix_statistics.complete) {
        throw std::invalid_argument(
            "resident packed client relation is noncanonical");
    }

    const spartan::BaseFoldPcs pcs(setup.basefold_parameters);
    const auto &prover = setup.spartan.prover_key;
    const auto &verifier = setup.spartan.verifier_key;
    if (setup.spartan_options.matrix_evaluation !=
            spartan::MatrixEvaluationMode::CommittedFactored ||
        prover.circuit == nullptr ||
        prover.circuit->metadata() != verifier.circuit_metadata ||
        verifier.circuit_metadata.shape() !=
            expected.circuit_metadata.shape() ||
        prover.setup_digest != verifier.setup_digest ||
        prover.options != setup.spartan_options ||
        verifier.options != setup.spartan_options ||
        prover.factored_computation == nullptr ||
        verifier.factored_computation == nullptr ||
        prover.factored_computation->commitment !=
            verifier.factored_computation->commitment) {
        throw std::invalid_argument(
            "resident packed client Spartan setup is inconsistent");
    }
    spartan::validate_prover_key(prover, pcs);
    spartan::validate_verifier_key(verifier, pcs);
    validate_factored_structure(
        prover.factored_computation->structure.get(),
        expected.relation_plan, expected.r1cs_layout,
        expected.tensor_mappings, verifier.circuit_metadata);
    validate_factored_structure(
        verifier.factored_computation->structure.get(),
        expected.relation_plan, expected.r1cs_layout,
        expected.tensor_mappings, verifier.circuit_metadata);
}

} // namespace

struct CertifiedPackedClientStatic::State {
    PackingGkrVariant variant = PackingGkrVariant::Folded;
    std::size_t bhip_round_count = 0;
    Digest fhe_context_storage_id{};
    CertifiedPackedWorkloadStatic workload;
    std::variant<FoldedVerifierSetup, LanedVerifierSetup> verifier_setup;
};

CertifiedPackedClientStatic::CertifiedPackedClientStatic(
    std::shared_ptr<const State> state)
    : state_(std::move(state)) {
    if (state_ == nullptr) {
        throw std::invalid_argument(
            "certified packed client static state is null");
    }
}

const CertifiedPackedClientStatic::State &
CertifiedPackedClientStatic::state() const {
    if (state_ == nullptr) {
        throw std::logic_error(
            "certified packed client static state was moved from");
    }
    return *state_;
}

PackingGkrVariant CertifiedPackedClientStatic::variant() const {
    return state().variant;
}

std::size_t CertifiedPackedClientStatic::bhip_round_count() const {
    return state().bhip_round_count;
}

const Digest &CertifiedPackedClientStatic::fhe_context_storage_id() const {
    return state().fhe_context_storage_id;
}

const CertifiedPackedWorkloadStatic &
CertifiedPackedClientStatic::workload() const {
    return state().workload;
}

const FoldedVerifierSetup &
CertifiedPackedClientStatic::folded_verifier_setup() const {
    const auto *selected =
        std::get_if<FoldedVerifierSetup>(&state().verifier_setup);
    if (selected == nullptr) {
        throw std::logic_error("certified packed client is not Folded");
    }
    return *selected;
}

const LanedVerifierSetup &
CertifiedPackedClientStatic::laned_verifier_setup() const {
    const auto *selected =
        std::get_if<LanedVerifierSetup>(&state().verifier_setup);
    if (selected == nullptr) {
        throw std::logic_error("certified packed client is not Laned");
    }
    return *selected;
}

const TranscriptPackingSpartanVerifierSetup &
CertifiedPackedClientStatic::verifier_setup() const {
    if (const auto *folded =
            std::get_if<FoldedVerifierSetup>(&state().verifier_setup)) {
        return folded->transcript_packing;
    }
    return std::get<LanedVerifierSetup>(state().verifier_setup)
        .transcript_packing;
}

CertifiedPackedClientStatic certify_packed_client_static(
    CertifiedPackedWorkloadStatic workload,
    Digest fhe_context_storage_id, FoldedVerifierSetup verifier_setup) {
    validate_static_setup(
        workload, fhe_context_storage_id, PackingGkrVariant::Folded,
        verifier_setup.transcript_packing);
    const std::size_t bhip_rounds =
        verifier_setup.transcript_packing.bhip_round_count;
    return CertifiedPackedClientStatic(
        std::make_shared<const CertifiedPackedClientStatic::State>(
            CertifiedPackedClientStatic::State{
                .variant = PackingGkrVariant::Folded,
                .bhip_round_count = bhip_rounds,
                .fhe_context_storage_id = fhe_context_storage_id,
                .workload = std::move(workload),
                .verifier_setup = std::move(verifier_setup),
            }));
}

CertifiedPackedClientStatic certify_packed_client_static(
    CertifiedPackedWorkloadStatic workload,
    Digest fhe_context_storage_id, LanedVerifierSetup verifier_setup) {
    validate_static_setup(
        workload, fhe_context_storage_id, PackingGkrVariant::Laned,
        verifier_setup.transcript_packing);
    const std::size_t bhip_rounds =
        verifier_setup.transcript_packing.bhip_round_count;
    return CertifiedPackedClientStatic(
        std::make_shared<const CertifiedPackedClientStatic::State>(
            CertifiedPackedClientStatic::State{
                .variant = PackingGkrVariant::Laned,
                .bhip_round_count = bhip_rounds,
                .fhe_context_storage_id = fhe_context_storage_id,
                .workload = std::move(workload),
                .verifier_setup = std::move(verifier_setup),
            }));
}

CertifiedPackedClientStatic certify_packed_client_static(
    CertifiedPackedWorkloadStatic workload,
    Digest fhe_context_storage_id, const FoldedSetup &setup) {
    validate_resident_static_setup(
        workload, fhe_context_storage_id, PackingGkrVariant::Folded,
        setup.transcript_packing);
    FoldedVerifierSetup compact = verifier_setup(setup);
    return CertifiedPackedClientStatic(
        std::make_shared<const CertifiedPackedClientStatic::State>(
            CertifiedPackedClientStatic::State{
                .variant = PackingGkrVariant::Folded,
                .bhip_round_count =
                    compact.transcript_packing.bhip_round_count,
                .fhe_context_storage_id = fhe_context_storage_id,
                .workload = std::move(workload),
                .verifier_setup = std::move(compact),
            }));
}

CertifiedPackedClientStatic certify_packed_client_static(
    CertifiedPackedWorkloadStatic workload,
    Digest fhe_context_storage_id, const LanedSetup &setup) {
    validate_resident_static_setup(
        workload, fhe_context_storage_id, PackingGkrVariant::Laned,
        setup.transcript_packing);
    LanedVerifierSetup compact = verifier_setup(setup);
    return CertifiedPackedClientStatic(
        std::make_shared<const CertifiedPackedClientStatic::State>(
            CertifiedPackedClientStatic::State{
                .variant = PackingGkrVariant::Laned,
                .bhip_round_count =
                    compact.transcript_packing.bhip_round_count,
                .fhe_context_storage_id = fhe_context_storage_id,
                .workload = std::move(workload),
                .verifier_setup = std::move(compact),
            }));
}

} // namespace laminate::protocol
