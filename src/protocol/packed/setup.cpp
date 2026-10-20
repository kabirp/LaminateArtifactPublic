/// @file setup.cpp
/// @brief Circuit geometry and complete transcript-packing setup.

#include "laminate/protocol/packed/setup.hpp"

#include "laminate/gkr/laned.hpp"
#include "laminate/protocol/analysis/noise_completeness.hpp"

#include <algorithm>
#include <bit>
#include <limits>
#include <memory>
#include <ranges>
#include <stdexcept>
#include <string>
#include <utility>

namespace laminate::protocol {
namespace {

using Bytes = std::vector<std::uint8_t>;

void append_u64(Bytes &output, std::uint64_t value) {
    for (std::size_t byte = 0; byte < 8; ++byte) {
        output.push_back(
            static_cast<std::uint8_t>((value >> (8U * byte)) & 0xffU));
    }
}

void append_size(Bytes &output, std::size_t value, const char *label) {
    if constexpr (sizeof(std::size_t) > sizeof(std::uint64_t)) {
        if (value > std::numeric_limits<std::uint64_t>::max()) {
            throw std::overflow_error(std::string(label) +
                                      " does not fit u64");
        }
    }
    append_u64(output, static_cast<std::uint64_t>(value));
}

void append_label(Bytes &output, std::string_view label) {
    append_size(output, label.size(), "canonical label length");
    output.insert(output.end(), label.begin(), label.end());
}

payload::PayloadKind expected_payload_kind(PackingGkrVariant variant) {
    switch (variant) {
    case PackingGkrVariant::Folded:
        return payload::PayloadKind::Wide;
    case PackingGkrVariant::Laned:
        return payload::PayloadKind::Laned;
    }
    throw std::invalid_argument(
        "conservative packed proof ingress has an unknown variant");
}

std::size_t conservative_multiplication_proof_depth(
    PackingGkrVariant variant, const payload::PayloadShape &shape) {
    switch (variant) {
    case PackingGkrVariant::Folded:
        return kConservativeFoldedMultiplicationProofDepth;
    case PackingGkrVariant::Laned:
        return conservative_laned_multiplication_proof_depth(
            shape.lane_count, shape.slot_count);
    }
    throw std::invalid_argument(
        "conservative packed proof ingress has an unknown variant");
}

std::size_t conservative_affine_proof_depth(
    PackingGkrVariant variant, ConservativePackedProofIngressPolicy policy) {
    (void)conservative_packed_proof_ingress_policy(variant, policy);
    if (policy == ConservativePackedProofIngressPolicy::FoldedAffine4)
        return 3U;
    switch (variant) {
    case PackingGkrVariant::Folded:
        return kConservativeFoldedAffineProofDepth;
    case PackingGkrVariant::Laned:
        return kConservativeLanedAffineProofDepth;
    }
    throw std::invalid_argument(
        "conservative packed proof ingress has an unknown variant");
}

std::vector<std::size_t> derive_conservative_ingress_vector(
    PackingGkrVariant variant,
    const payload::LayeredCircuit &circuit,
    ConservativePackedProofIngressPolicy policy) {
    circuit.validate();
    if (circuit.shape.kind != expected_payload_kind(variant) ||
        circuit.layers.size() < 2U) {
        throw std::invalid_argument(
            "conservative packed proof ingress has the wrong circuit "
            "kind or no reduction");
    }

    // Entry zero is a non-authoritative output placeholder. It is never a
    // reverse-GKR source, and apply_packed_proof_ingress_schedule preserves
    // the output's natural payload level instead.
    std::vector<std::size_t> result(circuit.layers.size(), 1U);
    const std::size_t affine_limbs =
        conservative_affine_proof_depth(variant, policy) + 1U;
    const std::size_t multiplication_limbs =
        conservative_multiplication_proof_depth(variant, circuit.shape) + 1U;
    for (std::size_t source_layer = 1;
         source_layer < circuit.layers.size(); ++source_layer) {
        switch (payload::layer_kind(circuit.layers[source_layer - 1U])) {
        case payload::LayerKind::Affine:
            result[source_layer] = affine_limbs;
            break;
        case payload::LayerKind::Multiplication:
            result[source_layer] = multiplication_limbs;
            break;
        case payload::LayerKind::Input:
            throw std::logic_error(
                "conservative packed proof ingress found an input layer "
                "with a predecessor");
        }
    }
    return result;
}

} // namespace

std::vector<std::uint8_t>
encode_conservative_packed_proof_ingress_schedule(
    PackingGkrVariant variant, const Digest &circuit_id,
    const Digest &public_setup_id,
    std::span<const std::size_t> rns_limbs_by_layer,
    ConservativePackedProofIngressPolicy policy) {
    (void)expected_payload_kind(variant);
    if (rns_limbs_by_layer.empty() ||
        std::ranges::any_of(rns_limbs_by_layer,
                            [](std::size_t limbs) { return limbs == 0; })) {
        throw std::invalid_argument(
            "conservative packed proof-ingress encoding requires a "
            "nonempty nonzero vector");
    }

    Bytes output;
    append_label(output,
                 "LaminateImpl/PackedProofIngressScheduleBinding/v1");
    append_label(output,
                 conservative_packed_proof_ingress_policy(variant, policy));
    append_u64(output, static_cast<std::uint64_t>(variant));
    output.insert(output.end(), circuit_id.begin(), circuit_id.end());
    output.insert(output.end(), public_setup_id.begin(),
                  public_setup_id.end());
    append_size(output, rns_limbs_by_layer.size(),
                "proof-ingress layer count");
    for (const std::size_t limbs : rns_limbs_by_layer) {
        append_size(output, limbs, "proof-ingress limb count");
    }
    return output;
}

Digest conservative_packed_proof_ingress_schedule_digest(
    PackingGkrVariant variant, const Digest &circuit_id,
    const Digest &public_setup_id,
    std::span<const std::size_t> rns_limbs_by_layer,
    ConservativePackedProofIngressPolicy policy) {
    return sha256(encode_conservative_packed_proof_ingress_schedule(
        variant, circuit_id, public_setup_id, rns_limbs_by_layer, policy));
}

ConservativePackedProofIngressSchedule
derive_conservative_packed_proof_ingress_schedule(
    PackingGkrVariant variant, const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const PublicSetup &public_setup,
    ConservativePackedProofIngressPolicy policy) {
    public_setup.validate(payload, circuit);

    ConservativePackedProofIngressSchedule result;
    result.variant_ = variant;
    result.policy_ = policy;
    result.rns_limbs_by_layer_ =
        derive_conservative_ingress_vector(variant, circuit, policy);
    result.circuit_id_ = public_setup.circuit_digest;
    result.public_setup_id_ = setup_digest(public_setup);
    result.digest_ = conservative_packed_proof_ingress_schedule_digest(
        result.variant_, result.circuit_id_, result.public_setup_id_,
        result.rns_limbs_by_layer_, policy);
    return result;
}

void validate_conservative_packed_proof_ingress_schedule(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const PublicSetup &public_setup,
    const ConservativePackedProofIngressSchedule &schedule) {
    const ConservativePackedProofIngressSchedule expected =
        derive_conservative_packed_proof_ingress_schedule(
            schedule.variant(), payload, circuit, public_setup,
            schedule.policy_selection());
    if (!(schedule == expected)) {
        throw std::invalid_argument(
            "conservative packed proof-ingress schedule does not match "
            "its variant, circuit, public setup, or fixed vector");
    }
}

CertifiedProofIngressRnsSelection select_proof_ingress_rns_limbs(
    const MinimumRnsCompletenessAnalysis &analysis) {
    PackingGkrVariant variant;
    if (analysis.protocol == gkr::ProtocolVariant::LaminateFolded) {
        variant = PackingGkrVariant::Folded;
    } else if (analysis.protocol ==
               gkr::ProtocolVariant::LaminateLaned) {
        variant = PackingGkrVariant::Laned;
    } else {
        throw std::invalid_argument(
            "proof-ingress selection requires Folded or Laned analysis");
    }
    if (!analysis.certifies_search_space_minimum() ||
        analysis.scope != kNoiseCompletenessAnalysisScope ||
        !analysis.coordinatewise_proof_ingress_minimum_established ||
        analysis.selected_proof_ingress_rns_limbs_by_layer.empty() ||
        std::ranges::any_of(
            analysis.selected_proof_ingress_rns_limbs_by_layer,
            [](std::size_t limbs) { return limbs == 0; })) {
        throw std::invalid_argument(
            "proof-ingress selection requires a certified exact schedule "
            "from a complete RNS analysis");
    }
    CertifiedProofIngressRnsSelection result;
    result.variant_ = variant;
    result.exact_rns_limbs_by_layer_ =
        analysis.selected_proof_ingress_rns_limbs_by_layer;
    result.circuit_id_ = analysis.circuit_id;
    result.setup_id_ = analysis.setup_id;
    result.live_schedule_parity_established_ =
        analysis.live_schedule_parity_established;
    return result;
}

namespace {

std::size_t checked_add(std::size_t left, std::size_t right,
                        const char *label) {
    if (right > std::numeric_limits<std::size_t>::max() - left) {
        throw std::overflow_error(std::string(label) + " overflows");
    }
    return left + right;
}

std::size_t checked_multiply(std::size_t left, std::size_t right,
                             const char *label) {
    if (left != 0 &&
        right > std::numeric_limits<std::size_t>::max() / left) {
        throw std::overflow_error(std::string(label) + " overflows");
    }
    return left * right;
}

std::uint64_t checked_u64(std::size_t value, const char *label) {
    if constexpr (sizeof(std::size_t) > sizeof(std::uint64_t)) {
        if (value > std::numeric_limits<std::uint64_t>::max()) {
            throw std::overflow_error(std::string(label) +
                                      " exceeds u64");
        }
    }
    return static_cast<std::uint64_t>(value);
}

std::size_t log2_exact(std::size_t value, const char *label) {
    if (value == 0 || !std::has_single_bit(value)) {
        throw std::invalid_argument(std::string(label) +
                                    " is not a power of two");
    }
    return std::bit_width(value) - 1U;
}

void validate_protocol_circuit(const payload::LayeredCircuit &circuit,
                               payload::PayloadKind expected,
                               const char *label) {
    circuit.validate();
    if (circuit.shape.kind != expected || circuit.layers.size() < 2) {
        throw std::invalid_argument(std::string(label) +
                                    " has the wrong payload kind");
    }
}

packing::OuterRelationPlan make_relation_plan(
    const packing::PackingLayout &layout,
    std::size_t aligned_ciphertexts,
    const packing::LazyTernaryParameters &parameters,
    gkr::CiphertextCommitmentPolicy ciphertext_commitment_policy) {
    return packing::make_outer_relation_plan(packing::OuterRelationShape{
        .native_modulus = kOuterFieldOrder,
        .ring_degree = layout.slot_count,
        .aligned_ciphertexts = aligned_ciphertexts,
        .repetitions = parameters.repetitions,
        .logical_packed_outputs = layout.packed_ciphertext_count,
        .packing_digit_count = parameters.packing_radix.digit_count,
        .ciphertext_components = 2,
        .public_input_capacity_bits = 59,
        .ciphertext_commitment_policy = ciphertext_commitment_policy,
    });
}

} // namespace

std::size_t folded_bhip_round_count(
    const payload::LayeredCircuit &circuit) {
    validate_protocol_circuit(circuit, payload::PayloadKind::Wide,
                              "Folded circuit");
    const std::size_t slot_variables =
        log2_exact(circuit.shape.slot_count, "Folded slot count");
    std::size_t result = 0;
    for (std::size_t layer = 0; layer + 1 < circuit.layers.size(); ++layer) {
        const std::size_t source_variables = log2_exact(
            payload::layer_dimensions(circuit.layers[layer + 1]).padded_size,
            "Folded source width");
        std::size_t rounds = source_variables;
        if (payload::layer_kind(circuit.layers[layer]) ==
            payload::LayerKind::Multiplication) {
            if (source_variables == 0U) {
                throw std::invalid_argument(
                    "Folded multiplication source has no selector "
                    "variable");
            }
            // Dense halves use the source selector only in the two terminal
            // claims. Sumcheck binds the remaining output-wire variables.
            --rounds;
        }
        rounds = checked_add(rounds, slot_variables,
                             "Folded layer rounds");
        result = checked_add(result, checked_add(rounds, 1,
                                                 "Folded terminal message"),
                             "Folded BhIP round count");
    }
    return result;
}

std::size_t laned_bhip_round_count(
    const payload::LayeredCircuit &circuit) {
    validate_protocol_circuit(circuit, payload::PayloadKind::Laned,
                              "Laned circuit");
    std::size_t result = 0;
    for (std::size_t layer = 0; layer + 1 < circuit.layers.size(); ++layer) {
        const bool affine = payload::layer_kind(circuit.layers[layer]) ==
                            payload::LayerKind::Affine;
        const std::size_t rounds = gkr::laned_layer_variables(
            circuit, affine ? layer + 1 : layer);
        result = checked_add(result, checked_add(rounds, 1,
                                                 "Laned terminal message"),
                             "Laned BhIP round count");
    }
    return result;
}

void validate_selected_packing_well_formedness(
    const packing::PackingLinearOperator &packing_operator,
    const packing::PlaintextCoefficientEncoder &encode_coefficients,
    const packing::LazyTernaryParameters &parameters,
    gkr::CiphertextCommitmentPolicy ciphertext_commitment_policy) {
    ciphertext_commitment_policy.validate();
    if (ciphertext_commitment_policy.is_diagnostic_only() ||
        parameters.repetitions != kPackingWellFormednessRepetitions) {
        return;
    }
    parameters.packing_radix.validate();
    if (parameters.packing_radix.plaintext_modulus != kBaseFieldOrder ||
        !encode_coefficients) {
        throw std::invalid_argument(
            "selected packing well-formedness requires the runtime plaintext "
            "field and a coefficient encoder");
    }
    packing::LazyTernaryCertificateInputs inputs{
        .packing_modulus = kOuterFieldOrder,
        .plaintext_modulus = parameters.packing_radix.plaintext_modulus,
        .honest_partial_decryption_bound =
            parameters.honest_partial_decryption_bound(),
        .ring_degree = packing_operator.slot_count,
        .ciphertext_count = packing_operator.aligned_ciphertext_count,
        .repetitions = parameters.repetitions,
        .maximum_row_weight_upper = 1,
    };
    // Reject unsupported dimensions before encoding or allocating mask rows.
    const auto shape = packing::assess_lazy_ternary_certificate(inputs);
    if (!shape.theorem_shape_supported || !shape.modular_detection_premise) {
        throw std::invalid_argument(
            "selected packing well-formedness geometry or modulus premise failed");
    }
    // This analysis validates all operator rows before encoding them.
    const auto weights = packing::analyze_signed_digit_packing_weights(
        packing_operator, encode_coefficients, parameters.packing_radix);
    inputs.maximum_row_weight_upper = weights.maximum_digit_row_weight_upper;
    if (!packing::assess_lazy_ternary_certificate(inputs)
             .interactive_certificate_holds) {
        throw std::invalid_argument(
            "selected packing well-formedness mask no-wrap premise failed");
    }
}

TranscriptPackingSpartanSetup make_transcript_packing_spartan_setup(
    PackingGkrVariant variant, std::size_t ring_degree,
    std::size_t bhip_round_count,
    packing::ProofOfPackingR1csEncoders encoders,
    packing::LazyTernaryParameters parameters,
    spartan::BaseFoldPcsParameters basefold_parameters,
    spartan::Options options,
    TranscriptPackingPreprocessingOptions preprocessing_options,
    gkr::CiphertextCommitmentPolicy ciphertext_commitment_policy) {
    ciphertext_commitment_policy.validate();
    if ((variant != PackingGkrVariant::Folded &&
         variant != PackingGkrVariant::Laned) ||
        ring_degree < 32 || !std::has_single_bit(ring_degree) ||
        bhip_round_count == 0) {
        throw std::invalid_argument(
            "packing Spartan setup has invalid transcript geometry");
    }
    parameters.packing_radix.validate();
    if (parameters.repetitions == 0 ||
        parameters.packing_radix.plaintext_modulus != kBaseFieldOrder) {
        throw std::invalid_argument(
            "packing Spartan setup has invalid test parameters");
    }
    if (preprocessing_options.factored_tensor_artifact.has_value() &&
        options.matrix_evaluation !=
            spartan::MatrixEvaluationMode::CommittedFactored) {
        throw std::invalid_argument(
            "factored tensor artifacts require committed-factored matrix "
            "evaluation");
    }
    const packing::BalancedRadix radix = parameters.packing_radix;
    const packing::PackingLayout alignment_layout =
        packing::make_fixed_message_coset_packing_layout(
            ring_degree, bhip_round_count,
            ring_degree / fhe::kFixedMessageCellCount);
    const packing::PackingLinearOperator packing_operator =
        packing::make_packing_linear_operator(alignment_layout);
    validate_selected_packing_well_formedness(
        packing_operator, encoders.centered_coefficients, parameters,
        ciphertext_commitment_policy);
    if (packing_operator.source_ciphertext_count != bhip_round_count ||
        packing_operator.aligned_ciphertext_count != bhip_round_count) {
        throw std::logic_error(
            "selected packing layout must produce one aligned ciphertext "
            "per BhIP round");
    }
    const packing::OuterRelationPlan relation_plan = make_relation_plan(
        alignment_layout, packing_operator.aligned_ciphertext_count,
        parameters, ciphertext_commitment_policy);
    packing::CompiledProofOfPackingR1cs compiled =
        packing::compile_proof_of_packing_r1cs(
            relation_plan, packing_operator, std::move(encoders), radix);
    const packing::ProofOfPackingR1csLedger ledger = compiled.ledger;
    const packing::FixedPackingR1csStreamStatistics statistics =
        compiled.fixed_packing_statistics;
    const spartan::BaseFoldPcs pcs(basefold_parameters);
    auto circuit = std::make_shared<const spartan::R1csInstance>(
        std::move(compiled.circuit));
    std::shared_ptr<const spartan::FactoredMatrixProverKey>
        factored_prover;
    std::shared_ptr<const spartan::FactoredMatrixVerifierKey>
        factored_verifier;
    std::optional<TranscriptPackingFactoredStorage> factored_storage;
    if (options.matrix_evaluation ==
        spartan::MatrixEvaluationMode::CommittedFactored) {
        std::vector<packing::PackingTensor> tensors =
            packing::compile_packing_tensors(
                relation_plan, compiled.native_packing_operator);
        compiled.native_packing_operator = packing::NativePackingOperator{};
        const auto structure =
            packing::make_proof_of_packing_factored_structure(
                relation_plan, compiled.layout, tensors,
                circuit->metadata());
        std::vector<std::vector<std::vector<Fq>>> columns;
        columns.reserve(tensors.size());
        std::size_t logical_column_bytes = 0;
        std::size_t resident_column_bytes = 0;
        for (packing::PackingTensor &tensor : tensors) {
            for (const std::vector<Fq> &column : tensor.digit_columns) {
                logical_column_bytes = checked_add(
                    logical_column_bytes,
                    checked_multiply(
                        column.size(),
                        storage::encoded_element_bytes(
                            storage::NativeFieldElementKind::Fq),
                        "factored logical column bytes"),
                    "factored logical column bytes");
                resident_column_bytes = checked_add(
                    resident_column_bytes,
                    checked_multiply(column.size(), sizeof(Fq),
                                     "factored resident column bytes"),
                    "factored resident column bytes");
            }
            columns.push_back(std::move(tensor.digit_columns));
        }
        spartan::FactoredMatrixSetup factored;
        if (preprocessing_options.factored_tensor_artifact.has_value()) {
            factored = spartan::preprocess_factored_matrix_to_artifact(
                structure, std::move(columns), pcs,
                *preprocessing_options.factored_tensor_artifact);
            if (factored.prover_key.tensor_columns_artifact == nullptr) {
                throw std::logic_error(
                    "artifact-backed factored setup returned no artifact");
            }
            factored_storage = TranscriptPackingFactoredStorage{
                .source = spartan::FactoredTensorColumnSource::Artifact,
                .logical_column_payload_bytes = checked_u64(
                    logical_column_bytes, "factored logical column bytes"),
                .retained_raw_column_payload_bytes = 0,
                .artifact_physical_bytes =
                    factored.prover_key.tensor_columns_artifact
                        ->physical_bytes(),
            };
        } else {
            factored = spartan::preprocess_factored_matrix(
                structure, std::move(columns), pcs);
            factored_storage = TranscriptPackingFactoredStorage{
                .source = spartan::FactoredTensorColumnSource::Resident,
                .logical_column_payload_bytes = checked_u64(
                    logical_column_bytes, "factored logical column bytes"),
                .retained_raw_column_payload_bytes = checked_u64(
                    resident_column_bytes,
                    "factored resident column bytes"),
                .artifact_physical_bytes = 0,
            };
        }
        factored_prover =
            std::make_shared<const spartan::FactoredMatrixProverKey>(
                std::move(factored.prover_key));
        factored_verifier =
            std::make_shared<const spartan::FactoredMatrixVerifierKey>(
                std::move(factored.verifier_key));
    }
    std::shared_ptr<const spartan::MatrixEvaluationOracle> matrix_oracle;
    if (options.matrix_evaluation ==
        spartan::MatrixEvaluationMode::Uniform) {
        matrix_oracle = packing::make_proof_of_packing_matrix_oracle(
            relation_plan, compiled.layout,
            std::move(compiled.native_packing_operator), circuit);
    } else if (options.matrix_evaluation ==
               spartan::MatrixEvaluationMode::CommittedFactored) {
        matrix_oracle =
            packing::make_proof_of_packing_factored_prover_oracle(
                relation_plan, compiled.layout, circuit);
    }
    spartan::Setup keys = spartan::setup(
        circuit, pcs, options, std::move(matrix_oracle),
        std::move(factored_prover), std::move(factored_verifier));
    return TranscriptPackingSpartanSetup{
        .variant = variant,
        .bhip_round_count = bhip_round_count,
        .alignment_layout = alignment_layout,
        .packing_operator = packing_operator,
        .relation_plan = relation_plan,
        .r1cs_ledger = ledger,
        .fixed_matrix_statistics = statistics,
        .parameters = parameters,
        .radix = radix,
        .basefold_parameters = basefold_parameters,
        .spartan_options = options,
        .factored_storage = factored_storage,
        .spartan = std::move(keys),
    };
}

TranscriptPackingSpartanVerifierSetup verifier_setup(
    const TranscriptPackingSpartanSetup &setup) {
    const spartan::VerifierKey &key = setup.spartan.verifier_key;
    if (key.options.matrix_evaluation !=
            spartan::MatrixEvaluationMode::CommittedFactored ||
        key.direct_matrix != nullptr || key.matrix_oracle != nullptr ||
        key.factored_computation == nullptr) {
        throw std::invalid_argument(
            "compact verifier setup requires factored matrix commitments");
    }
    return TranscriptPackingSpartanVerifierSetup{
        .variant = setup.variant,
        .bhip_round_count = setup.bhip_round_count,
        .alignment_layout = setup.alignment_layout,
        .relation_plan = setup.relation_plan,
        .parameters = setup.parameters,
        .radix = setup.radix,
        .basefold_parameters = setup.basefold_parameters,
        .spartan = key,
    };
}

FoldedVerifierSetup verifier_setup(const FoldedSetup &setup) {
    return FoldedVerifierSetup{verifier_setup(setup.transcript_packing)};
}

LanedVerifierSetup verifier_setup(const LanedSetup &setup) {
    return LanedVerifierSetup{verifier_setup(setup.transcript_packing)};
}

} // namespace laminate::protocol
