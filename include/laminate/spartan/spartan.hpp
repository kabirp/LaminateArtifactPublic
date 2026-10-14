#ifndef LAMINATE_SPARTAN_SPARTAN_HPP
#define LAMINATE_SPARTAN_SPARTAN_HPP

/// @file spartan.hpp
/// @brief Top-level regular Spartan PIOP + IPCS + BCS16 entry points.

#include "laminate/spartan/ipcs.hpp"
#include "laminate/spartan/factored.hpp"
#include "laminate/spartan/matrix_oracle.hpp"
#include "laminate/spartan/r1cs.hpp"
#include "laminate/spartan/sumcheck.hpp"
#include "laminate/transcript/transcript.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <vector>

namespace laminate::spartan {

enum class MatrixEvaluationMode : std::uint8_t {
    /// Correctness/reference profile; verification is linear in matrix nnz.
    Direct = 0,
    /// Public evaluator for a repeated or otherwise structured matrix.
    Uniform = 1,
    /// Closed-form regular matrices plus committed dense residual tensors.
    CommittedFactored = 2,
};

struct Options {
    MatrixEvaluationMode matrix_evaluation =
        MatrixEvaluationMode::Direct;

    bool operator==(const Options &) const = default;
};

struct ProverKey {
    std::shared_ptr<const R1csInstance> circuit;
    Digest setup_digest{};
    std::uint64_t pcs_scheme = 0;
    Options options;
    /// Required by Uniform; optional prover acceleration for CommittedFactored.
    std::shared_ptr<const MatrixEvaluationOracle> matrix_oracle;
    std::shared_ptr<const FactoredMatrixProverKey> factored_computation;
};

struct VerifierKey {
    R1csMetadata circuit_metadata;
    Digest setup_digest{};
    std::uint64_t pcs_scheme = 0;
    Options options;
    /// Present only in the linear-time reference profile.
    std::shared_ptr<const R1csInstance> direct_matrix;
    /// Present only in the structured-reference profile.
    std::shared_ptr<const MatrixEvaluationOracle> matrix_oracle;
    std::shared_ptr<const FactoredMatrixVerifierKey> factored_computation;
};

struct Setup {
    ProverKey prover_key;
    VerifierKey verifier_key;
};

/// Minimal setup binding for a CommittedFactored external suffix. It retains
/// neither an expanded R1CS instance nor a matrix oracle. The factored
/// commitment and `circuit_metadata` are bound by
/// exactly the ordinary Spartan setup digest; the suffix separately validates
/// its artifact-backed storage realization.
struct ExternalProverKey {
    R1csMetadata circuit_metadata;
    Digest setup_digest{};
    std::uint64_t pcs_scheme = 0;
    Options options{
        .matrix_evaluation = MatrixEvaluationMode::CommittedFactored,
    };
    std::shared_ptr<const FactoredMatrixProverKey> factored_computation;
};

/// Compact committed-factored prover key plus the ordinary compact verifier
/// key accepted by `verify`.
struct ExternalSetup {
    ExternalProverKey prover_key;
    VerifierKey verifier_key;
};

struct Proof {
    PcsCommitment witness_commitment;
    ConstraintSumcheckProof constraint_sumcheck;
    Fq2 az_evaluation{};
    Fq2 bz_evaluation{};
    Fq2 cz_evaluation{};
    WiringSumcheckProof wiring_sumcheck;
    Fq2 matrix_evaluation{};
    Fq2 assignment_evaluation{};
    std::optional<FactoredMatrixEvaluationProof> factored_evaluation;
    PcsOpeningProof witness_opening;
};

/// Deterministic transparent setup. Direct mode retains the canonical sparse
/// matrices, Uniform mode uses a compact public evaluator, and
/// CommittedFactored accepts setup-bound regular formulas and residual tensor
/// commitments.
/// @param circuit Canonical padded R1CS relation used by both keys.
/// @param pcs Polynomial commitment implementation used for witness openings.
/// @param options Selects direct, structured-reference, or factored committed
/// matrix evaluation.
/// @param matrix_oracle Required in Uniform mode and optional as a prover-only
/// acceleration in CommittedFactored mode. Its circuit digest and dimensions
/// must match `circuit` whenever present.
Setup setup(R1csInstance circuit, const IPCS &pcs,
            const Options &options = {},
            std::shared_ptr<const MatrixEvaluationOracle> matrix_oracle =
                nullptr,
            std::shared_ptr<const FactoredMatrixProverKey>
                factored_prover = nullptr,
            std::shared_ptr<const FactoredMatrixVerifierKey>
                factored_verifier = nullptr);

/// Shared-circuit overload for structured keys whose matrix oracle delegates
/// prover-only linear products to the same immutable R1CS instance.
Setup setup(std::shared_ptr<const R1csInstance> circuit, const IPCS &pcs,
            const Options &options,
            std::shared_ptr<const MatrixEvaluationOracle> matrix_oracle,
            std::shared_ptr<const FactoredMatrixProverKey>
                factored_prover = nullptr,
            std::shared_ptr<const FactoredMatrixVerifierKey>
                factored_verifier = nullptr);

/// Construct committed-factored Spartan keys from formula-derived metadata
/// and matching factored preprocessing. This primary external setup path does
/// not construct, accept, or retain an `R1csInstance`.
ExternalSetup setup_external_committed_factored(
    R1csMetadata circuit_metadata, const IPCS &pcs,
    std::shared_ptr<const FactoredMatrixProverKey> factored_prover,
    std::shared_ptr<const FactoredMatrixVerifierKey> factored_verifier);

/// Validate the complete setup binding required by the external suffix.
void validate_external_prover_key(const ExternalProverKey &key,
                                  const IPCS &pcs);

/// Validate the complete compact verifier binding without constructing a
/// prover key. Persistent client preprocessing calls this after restoring its
/// authenticated verifier certificate.
void validate_verifier_key(const VerifierKey &key, const IPCS &pcs);

/// BCS16-compile Spartan + `pcs` with the SHA-256 transcript and produce
/// a non-interactive proof for `assignment`.
/// Preconditions: the key matches `pcs`, and the public/witness dimensions
/// match its circuit. Postcondition: the returned proof is transcript-bound to
/// the setup digest, public inputs, and witness commitment. Throws when the
/// key, assignment, or terminal prover identities are inconsistent.
Proof prove(const ProverKey &key, const R1csAssignment &assignment,
            const IPCS &pcs, Transcript &transcript);

/// Validate the complete setup binding required by a prover without
/// constructing an assignment. External-memory orchestrators call this
/// before creating artifacts or advancing Fiat--Shamir.
void validate_prover_key(const ProverKey &key, const IPCS &pcs);

/// Verify a BCS16-compiled Spartan proof. Returns false for malformed keys,
/// proofs, transcript-derived singularities, or failed terminal openings.
bool verify(const VerifierKey &key, std::span<const Fq> public_inputs,
            const Proof &proof, const IPCS &pcs,
            Transcript &transcript);

/// Canonical length-prefixed field encoding absorbed by the BCS16 transcript.
std::vector<std::uint8_t>
encode_public_inputs(std::span<const Fq> public_inputs);

/// Absorb the setup digest and canonical public-input encoding under the
/// exact labels used by Spartan's BCS16 compilation.
void bind_public_statement(const Digest &setup_digest,
                           std::span<const Fq> public_inputs,
                           PublicCoin &public_coin);

/// Exact BCS16 transcript observations shared by resident and artifact-backed
/// Spartan provers.
void bind_witness_commitment(const PcsCommitment &commitment,
                             PublicCoin &public_coin);
void bind_constraint_terminal(const Fq2 &az, const Fq2 &bz,
                              const Fq2 &cz, PublicCoin &public_coin);
void bind_wiring_terminal(const Fq2 &matrix_evaluation,
                          const Fq2 &assignment_evaluation,
                          PublicCoin &public_coin);

/// Recover the private-half MLE claim opened by the witness PCS from the
/// WiringCheck terminal assignment claim.
Fq2 derive_witness_opening_evaluation(
    std::span<const Fq> public_inputs, const R1csMetadata &metadata,
    std::span<const Fq2> wiring_point,
    const Fq2 &assignment_evaluation);

/// Evaluate `(1, public_inputs, 0, ...)` over one power-of-two assignment
/// half. The live-prefix traversal costs O(public_inputs.size() + log H).
Fq2 evaluate_public_input_mle(std::span<const Fq> public_inputs,
                              std::size_t half_size,
                              std::span<const Fq2> point);

/// Canonical proof bytes. Round counts are setup-derived and therefore are
/// not redundantly transmitted. The opaque, variable-length witness opening
/// is explicitly length-framed for bounded outer decoders.
void append_encoded_proof(const Proof &proof,
                          std::vector<std::uint8_t> &output);

std::vector<std::uint8_t> encode_proof(const Proof &proof);

std::size_t proof_size_bytes(const Proof &proof);

} // namespace laminate::spartan

#endif // LAMINATE_SPARTAN_SPARTAN_HPP
