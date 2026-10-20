#ifndef LAMINATE_PROTOCOL_PACKED_SETUP_TRANSCRIPT_PACKING_HPP
#define LAMINATE_PROTOCOL_PACKED_SETUP_TRANSCRIPT_PACKING_HPP

/// @file transcript_packing.hpp
/// @brief Public preprocessing state for the transcript-packing proof.

#include "laminate/packing/evaluation/lazy_ternary.hpp"
#include "laminate/packing/proof/matrix/oracle.hpp"
#include "laminate/packing/proof/r1cs.hpp"
#include "laminate/payload/ir/layered.hpp"
#include "laminate/protocol/packed/setup/proof_ingress.hpp"
#include "laminate/spartan/basefold_pcs.hpp"
#include "laminate/spartan/spartan.hpp"

#include <concepts>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace laminate::protocol {

/// Backend boundary required by the complete proof-of-packing statement.
/// These operations expose only public coefficient-ring representations.
template <typename Backend>
concept ProofOfPackingBackend =
    packing::SignedDigitPackingBackend<Backend> &&
    requires(const typename Backend::EvalContext &eval,
             const typename Backend::Ciphertext &ciphertext,
             std::span<const std::int64_t> centered_coefficients) {
        {
            Backend::lowest_coefficient_modulus(eval)
        } -> std::convertible_to<std::uint64_t>;
        {
            Backend::encode_lowest_plaintext_ntt_coordinates(
                eval, centered_coefficients)
        } -> std::same_as<std::vector<std::uint64_t>>;
        {
            Backend::coefficient_commitment_ntt_coordinate_view(ciphertext)
        } -> std::same_as<std::span<const std::uint64_t>>;
    };

/// Optional caller-owned storage selected during transcript-packing setup.
/// An absent artifact request preserves resident preprocessing. No directory
/// is inferred by the library.
struct TranscriptPackingPreprocessingOptions {
    std::optional<spartan::FactoredMatrixArtifactOptions>
        factored_tensor_artifact;
};

/// Exact payload accounting for the duplicate factored tensor columns. This
/// deliberately excludes BaseFold's opaque prover state, which remains
/// resident in both modes.
struct TranscriptPackingFactoredStorage {
    spartan::FactoredTensorColumnSource source =
        spartan::FactoredTensorColumnSource::Resident;
    /// Canonically encoded Fq payload, excluding all container framing.
    std::uint64_t logical_column_payload_bytes = 0;
    /// Duplicate raw-column vector payload retained outside BaseFold state.
    std::uint64_t retained_raw_column_payload_bytes = 0;
    /// Exact finalized artifact files, including headers and manifest.
    std::uint64_t artifact_physical_bytes = 0;

    bool operator==(const TranscriptPackingFactoredStorage &) const = default;
};

/// Complete transparent setup used by the transcript-packing prover.
struct TranscriptPackingSpartanSetup {
    PackingGkrVariant variant = PackingGkrVariant::Folded;
    std::size_t bhip_round_count = 0;
    packing::PackingLayout alignment_layout;
    packing::PackingLinearOperator packing_operator;
    packing::OuterRelationPlan relation_plan;
    packing::ProofOfPackingR1csLedger r1cs_ledger;
    packing::FixedPackingR1csStreamStatistics fixed_matrix_statistics;
    packing::LazyTernaryParameters parameters;
    packing::BalancedRadix radix;
    spartan::BaseFoldPcsParameters basefold_parameters;
    spartan::Options spartan_options;
    std::optional<TranscriptPackingFactoredStorage> factored_storage;
    spartan::Setup spartan;
};

/// Compact public state needed by the transcript-packing verifier.
///
/// This deliberately excludes the packing operator, compiled R1CS, general
/// matrix oracle, tensor coefficients, and witness/tensor opening state
/// retained by the full setup. It keeps only the compact factored structure
/// and its setup-bound commitments.
struct TranscriptPackingSpartanVerifierSetup {
    PackingGkrVariant variant = PackingGkrVariant::Folded;
    std::size_t bhip_round_count = 0;
    packing::PackingLayout alignment_layout;
    packing::OuterRelationPlan relation_plan;
    packing::LazyTernaryParameters parameters;
    packing::BalancedRadix radix;
    spartan::BaseFoldPcsParameters basefold_parameters;
    spartan::VerifierKey spartan;
};

/// Project the verifier's compact public state from transparent preprocessing.
TranscriptPackingSpartanVerifierSetup verifier_setup(
    const TranscriptPackingSpartanSetup &setup);

/// Exact number of BhIP rounds generated from circuit geometry. Each round
/// contributes one aligned ciphertext to transcript packing.
std::size_t folded_bhip_round_count(
    const payload::LayeredCircuit &circuit);
std::size_t laned_bhip_round_count(
    const payload::LayeredCircuit &circuit);

/// Enforce the paper's public well-formedness premises for the selected
/// 120-test Poseidon profile, using this encoder's actual signed-digit masks.
/// Nonselected repetition counts and diagnostic-hash setups remain
/// diagnostics outside this certificate. This checks
/// integrity prerequisites, not the honest ciphertext-noise completeness cap.
void validate_selected_packing_well_formedness(
    const packing::PackingLinearOperator &packing_operator,
    const packing::PlaintextCoefficientEncoder &encode_coefficients,
    const packing::LazyTernaryParameters &parameters,
    gkr::CiphertextCommitmentPolicy ciphertext_commitment_policy);

/// Non-template synthesis core used by the backend adapters.
TranscriptPackingSpartanSetup make_transcript_packing_spartan_setup(
    PackingGkrVariant variant, std::size_t ring_degree,
    std::size_t bhip_round_count,
    packing::ProofOfPackingR1csEncoders encoders,
    packing::LazyTernaryParameters parameters =
        packing::selected_lazy_ternary_parameters(),
    spartan::BaseFoldPcsParameters basefold_parameters = {},
    spartan::Options options = spartan::Options{
        .matrix_evaluation =
            spartan::MatrixEvaluationMode::CommittedFactored},
    TranscriptPackingPreprocessingOptions preprocessing_options = {},
    gkr::CiphertextCommitmentPolicy ciphertext_commitment_policy =
        gkr::CiphertextCommitmentPolicy::poseidon_v2());

} // namespace laminate::protocol

#endif // LAMINATE_PROTOCOL_PACKED_SETUP_TRANSCRIPT_PACKING_HPP
