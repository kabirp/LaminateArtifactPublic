#ifndef LAMINATE_PACKING_PROOF_STRUCTURED_METADATA_HPP
#define LAMINATE_PACKING_PROOF_STRUCTURED_METADATA_HPP

/// @file metadata.hpp
/// @brief Coefficient-free identity for the structured packing R1CS.

#include "laminate/packing/evaluation/lazy_ternary.hpp"
#include "laminate/packing/outer_relation/tensor.hpp"
#include "laminate/packing/proof/r1cs.hpp"

#include <string_view>
#include <vector>

namespace laminate::packing {

/// Version of the complete semantic relation encoding.  This version must be
/// changed whenever a regular row formula, variable/row layout rule, tensor
/// mapping rule, or ciphertext-commitment gadget changes.
inline constexpr std::string_view
    kProofOfPackingStructuredR1csSemanticVersion =
        "LaminateImpl/ProofOfPackingStructuredR1cs/v2";

/// Version of the exact ciphertext-Poseidon R1CS gadget encoded below.  Its
/// digest also binds all round constants, the MDS matrix, checkpoint schedule,
/// sponge/domain parameters, and the generated local A/B/C template.
inline constexpr std::string_view
    kProofOfPackingPoseidonGadgetSemanticVersion =
        "LaminateImpl/ProofOfPackingPoseidonGadget/v2";

inline constexpr std::string_view
    kProofOfPackingDiagnosticSimpleCtHashGadgetSemanticVersion =
        "LaminateImpl/ProofOfPackingDiagnosticSimpleCtHashGadget/v2";

/// Public, allocation-light description of the proof-of-packing relation.
///
/// Construction is formula-only in the target dimensions.  It derives owner
/// maps and exact row/witness ledgers from `PackingLayout`, but never invokes a
/// plaintext encoder, an NTT, the expanded R1CS compiler, or coefficient-
/// tensor materialization.  The semantic circuit digest is intended for the
/// committed-factored Spartan profile: regular matrices are fixed by this
/// description, while exact irregular packing coefficients are authenticated
/// separately by the setup-bound tensor commitments.
struct ProofOfPackingStructuredMetadata {
    PackingLayout alignment_layout;
    PackingLinearOperator packing_operator;
    LazyTernaryParameters parameters;
    OuterRelationPlan relation_plan;
    ProofOfPackingR1csLayout r1cs_layout;
    ProofOfPackingR1csLedger r1cs_ledger;
    PackingTensorGeometry tensor_geometry;
    std::vector<PackingTensorMapping> tensor_mappings;

    /// Digest of the exact setup-selected commitment gadget definition.
    Digest ciphertext_commitment_gadget_digest{};
    /// Digest of every field above plus the exact Spartan shape and padding.
    Digest semantic_circuit_digest{};
    /// Verifier-facing shape/padding with `semantic_circuit_digest` as its
    /// circuit identity. The digest binds the formulas and tensor commitments
    /// without enumerating every sparse R1CS coefficient.
    spartan::R1csMetadata circuit_metadata;

    /// Re-encode this value without trusting its stored semantic digest.
    Digest recompute_semantic_circuit_digest() const;

    /// Re-derive the canonical value from `alignment_layout` and `parameters`
    /// and reject any inconsistent or noncanonical field.
    void validate() const;
};

/// Bind the exact fixed Poseidon constants and local R1CS template.
Digest proof_of_packing_poseidon_gadget_digest();
Digest proof_of_packing_ciphertext_commitment_gadget_digest(
    gkr::CiphertextCommitmentPolicy policy);

/// Derive the complete structured identity from public geometry alone.
ProofOfPackingStructuredMetadata
make_proof_of_packing_structured_metadata(
    const PackingLayout &alignment_layout,
    LazyTernaryParameters parameters,
    gkr::CiphertextCommitmentPolicy ciphertext_commitment_policy =
        gkr::CiphertextCommitmentPolicy::poseidon_v2());

} // namespace laminate::packing

#endif // LAMINATE_PACKING_PROOF_STRUCTURED_METADATA_HPP
