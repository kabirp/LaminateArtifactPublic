#ifndef LAMINATE_SPARTAN_SUMCHECK_HPP
#define LAMINATE_SPARTAN_SUMCHECK_HPP

/// @file sumcheck.hpp
/// @brief The two ordinary plaintext sumchecks in Spartan's PIOP.

#include "laminate/field/fq.hpp"
#include "laminate/field/fq2.hpp"
#include "laminate/storage/native_field_artifact.hpp"
#include "laminate/transcript/public_coin.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <vector>

namespace laminate::spartan {

/// Number of leading rounds recomputed from the source evaluations before the
/// prover materializes extension-field folding tables. Two rounds bound the
/// dense tables to one quarter of the original domain, trading bounded source
/// rescanning for a smaller extension-field checkpoint.
inline constexpr std::size_t kDefaultSourceSumcheckRounds = 2;

/// Design point for the artifact-backed ConstraintCheck prover. Four source
/// rescans reduce the first extension-field checkpoint to one sixteenth of
/// the original domain without making the prefix table appreciable.
inline constexpr std::size_t kDefaultArtifactConstraintSourceRounds = 4;

struct ConstraintSumcheckRound {
    /// S(1), except when tau_i=1, in which case this is S(0).
    Fq2 endpoint{};
    Fq2 at_two{};

    bool operator==(const ConstraintSumcheckRound &) const = default;
};

struct WiringSumcheckRound {
    Fq2 at_one{};
    Fq2 at_two{};

    bool operator==(const WiringSumcheckRound &) const = default;
};

struct ConstraintSumcheckProof {
    /// Gruen-stripped degree-two messages. The omitted endpoint is recovered
    /// from `(1-tau_i)S(0) + tau_i S(1) = claim`.
    std::vector<ConstraintSumcheckRound> rounds;
};

struct WiringSumcheckProof {
    /// Degree-two evaluations at X=1 and X=2. X=0 is omitted.
    std::vector<WiringSumcheckRound> rounds;
};

struct ConstraintSumcheckOutput {
    ConstraintSumcheckProof proof;
    std::vector<Fq2> point;
    Fq2 final_claim{};
    Fq2 az_evaluation{};
    Fq2 bz_evaluation{};
    Fq2 cz_evaluation{};
};

struct ConstraintSumcheckArtifactArrays {
    std::string az;
    std::string bz;
    std::string cz;

    bool operator==(const ConstraintSumcheckArtifactArrays &) const = default;
};

/// Explicit storage and memory authority for one artifact-backed
/// ConstraintCheck proof. `scratch_directory` must be an existing, empty,
/// caller-owned real directory disjoint from the immutable source artifact.
/// `max_working_field_bytes` covers dynamic working Fq/Fq2 payloads, excluding
/// caller inputs, returned proof/point storage, reader objects, byte-encoding
/// buffers, and allocator metadata.
struct ConstraintSumcheckArtifactOptions {
    Digest expected_source_identity{};
    std::filesystem::path scratch_directory;
    /// Complete physical bytes allowed for the immutable source artifact and
    /// every simultaneously live scratch checkpoint.
    std::uint64_t max_live_storage_bytes = 0;
    std::uint64_t max_total_scratch_bytes = 0;
    std::uint64_t min_free_bytes = 0;
    std::uint64_t max_working_field_bytes = 0;
    std::size_t block_elements = 0;
    std::size_t source_rounds =
        kDefaultArtifactConstraintSourceRounds;
    /// Logical power-of-two row domain. Zero infers the domain from the
    /// source-array length. When nonzero, each selected source array is the
    /// nonempty active prefix of this domain; omitted rows are synthesized
    /// as zero.
    std::size_t logical_domain_size = 0;
};

struct ConstraintSumcheckArtifactReport {
    std::uint64_t source_artifact_physical_bytes = 0;
    std::uint64_t source_validation_bytes = 0;
    std::uint64_t selected_source_payload_bytes = 0;
    std::uint64_t scratch_artifact_validation_bytes = 0;
    std::uint64_t sequential_read_payload_bytes = 0;
    std::uint64_t indexed_read_payload_bytes = 0;
    std::uint64_t sequential_write_payload_bytes = 0;
    std::uint64_t indexed_write_payload_bytes = 0;
    /// Data-carrying logical transfers, independent of iostream buffering and
    /// OS syscall counts.
    std::uint64_t sequential_read_operations = 0;
    std::uint64_t indexed_read_operations = 0;
    std::uint64_t sequential_write_operations = 0;
    std::uint64_t indexed_write_operations = 0;
    std::uint64_t scratch_peak_physical_bytes = 0;
    std::uint64_t scratch_written_physical_bytes = 0;
    std::uint64_t scratch_deleted_physical_bytes = 0;
    std::uint64_t scratch_retained_physical_bytes = 0;
    std::uint64_t peak_live_storage_bytes = 0;
    std::uint64_t peak_working_field_bytes = 0;
    std::size_t effective_block_elements = 0;
    std::size_t source_rescan_rounds = 0;
    std::size_t fold_passes = 0;

    bool operator==(const ConstraintSumcheckArtifactReport &) const = default;
};

/// Exact maximum physical scratch simultaneously retained by the artifact
/// ConstraintCheck schedule for this logical domain.
std::uint64_t constraint_sumcheck_artifact_scratch_peak_physical_bytes(
    std::size_t logical_domain_size, std::size_t source_rounds);

struct ConstraintSumcheckArtifactOutput {
    ConstraintSumcheckOutput sumcheck;
    ConstraintSumcheckArtifactReport report;
};

struct ConstraintSumcheckArtifactPlan {
    std::uint64_t scratch_peak_physical_bytes = 0;
    std::uint64_t scratch_written_physical_bytes = 0;
    std::uint64_t minimum_working_field_bytes = 0;
    std::size_t effective_block_elements = 0;
    std::uint64_t peak_working_field_bytes = 0;

    bool operator==(
        const ConstraintSumcheckArtifactPlan &) const = default;
};

ConstraintSumcheckArtifactPlan plan_constraint_sumcheck_artifact(
    std::size_t logical_domain_size, std::size_t source_rounds,
    std::uint64_t max_working_field_bytes,
    std::size_t requested_block_elements);

struct WiringSumcheckOutput {
    WiringSumcheckProof proof;
    std::vector<Fq2> point;
    Fq2 final_claim{};
    Fq2 matrix_evaluation{};
    Fq2 assignment_evaluation{};
};

struct SumcheckVerification {
    bool accepts = false;
    std::vector<Fq2> point;
    Fq2 final_claim{};
};

/// Prove sum_x eq(tau,x) * (Az(x)Bz(x)-Cz(x)) = 0.
///
/// Preconditions: `az`, `bz`, and `cz` have the same power-of-two length and
/// `tau.size() == log2(az.size())`.
/// Postcondition: each round contains S(1),S(2) for Gruen's stripped degree-
/// two polynomial, except that tau_i=1 uses S(0),S(2); the terminal evaluations
/// satisfy the full equality-weighted claim at the sampled verifier point.
/// @param tau Verifier row point whose equality polynomial weights the claim.
/// The three source vectors are accepted by value so target callers can move
/// them into the prover. They are released as soon as the smaller folded state
/// has been constructed.
/// @param az Evaluations of the R1CS A matrix applied to the assignment.
/// @param bz Evaluations of the R1CS B matrix applied to the assignment.
/// @param cz Evaluations of the R1CS C matrix applied to the assignment.
/// @param public_coin Hash-agnostic channel that supplies round challenges.
/// @param source_rounds Leading rounds to recompute without dense Fq2 tables.
/// Values from zero through `kDefaultSourceSumcheckRounds` are supported; the
/// count is clamped to the number of variables on smaller domains.
ConstraintSumcheckOutput prove_constraint_sumcheck(
    std::span<const Fq2> tau, std::vector<Fq> az,
    std::vector<Fq> bz, std::vector<Fq> cz,
    PublicCoin &public_coin,
    std::size_t source_rounds = kDefaultSourceSumcheckRounds);

/// Prove ConstraintCheck from three immutable Fq arrays in one validated
/// native-field artifact while keeping only bounded blocks and reduced Fq2
/// checkpoints in memory. Equal-length arrays may store either the complete
/// power-of-two row domain or, when `logical_domain_size` is explicit, its
/// nonempty active prefix. Rows after that prefix are logically zero and are
/// never read from disk. Checkpoints remain dense over the logical domain.
/// The function reopens the source against `expected_source_identity`, so its
/// full validation scan is reported separately from canonical prover reads.
///
/// All validation and resource preflight occurs before the first transcript
/// observation. Once a round has been observed, however, an I/O failure leaves
/// `public_coin` advanced even though scratch is cleaned. Such a failure is
/// not retryable with that coin object; reconstruct the transcript from its
/// preceding protocol checkpoint before retrying.
ConstraintSumcheckArtifactOutput prove_constraint_sumcheck_artifact(
    const storage::NativeFieldArtifact &source,
    const ConstraintSumcheckArtifactArrays &arrays,
    std::span<const Fq2> tau, PublicCoin &public_coin,
    ConstraintSumcheckArtifactOptions options);

/// Prove `sum_y M(r_x,y) * z(y) = claimed_value`.
///
/// Preconditions: `matrix` and `assignment` have the same power-of-two
/// length. Postcondition: every round transmits only R(1),R(2), and the output
/// exposes `M(r_y)`, `z(r_y)`, and their product claim.
/// The source tables are accepted by value so target callers can transfer
/// ownership. They are released once the reduced folding state exists.
/// @param matrix Evaluations of the row-bound batched matrix M(r_x, y).
/// @param assignment Padded Spartan assignment z(y).
/// @param claimed_value Claimed inner product sum_y M(r_x,y)z(y).
/// @param public_coin Hash-agnostic channel that supplies round challenges.
/// @param source_rounds Leading rounds to recompute without dense Fq2 tables.
/// Values from zero through `kDefaultSourceSumcheckRounds` are supported; the
/// count is clamped to the number of variables on smaller domains.
WiringSumcheckOutput prove_wiring_sumcheck(
    std::vector<Fq2> matrix, std::vector<Fq> assignment,
    const Fq2 &claimed_value, PublicCoin &public_coin,
    std::size_t source_rounds = kDefaultSourceSumcheckRounds);

/// Verify Gruen ConstraintCheck messages against `claimed_sum` and `tau`.
/// Returns `accepts=false` on a malformed round count. Acceptance means the
/// sumcheck transcript is well formed; the caller must compare `final_claim`
/// with the terminal Az/Bz/Cz oracle expression.
/// @param proof Two-value round messages supplied by the prover.
/// @param claimed_sum Initial equality-weighted constraint claim.
/// @param tau Verifier row point used to recover each omitted endpoint.
/// @param public_coin Hash-agnostic channel that supplies round challenges.
SumcheckVerification verify_constraint_sumcheck(
    const ConstraintSumcheckProof &proof, const Fq2 &claimed_sum,
    std::span<const Fq2> tau, PublicCoin &public_coin);

/// Verify WiringCheck messages. The caller must compare `final_claim` with
/// the terminal matrix/assignment product.
/// @param proof Two-value round messages supplied by the prover.
/// @param claimed_sum Initial matrix-assignment inner-product claim.
/// @param public_coin Hash-agnostic channel that supplies round challenges.
SumcheckVerification verify_wiring_sumcheck(
    const WiringSumcheckProof &proof, const Fq2 &claimed_sum,
    PublicCoin &public_coin);

} // namespace laminate::spartan

#endif // LAMINATE_SPARTAN_SUMCHECK_HPP
