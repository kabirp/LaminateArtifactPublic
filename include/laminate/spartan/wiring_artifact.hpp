#ifndef LAMINATE_SPARTAN_WIRING_ARTIFACT_HPP
#define LAMINATE_SPARTAN_WIRING_ARTIFACT_HPP

/// @file wiring_artifact.hpp
/// @brief Bounded-memory WiringCheck over compact matrix and assignment files.

#include "laminate/spartan/sumcheck.hpp"
#include "laminate/storage/native_field_artifact.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace laminate::spartan {

/// Design point for the artifact-backed WiringCheck prover. Four source
/// rescans reduce each first extension-field checkpoint to one sixteenth of
/// the logical assignment domain.
inline constexpr std::size_t kDefaultArtifactWiringSourceRounds = 4;

/// Names of the compact source arrays. The logical matrix is
///
///   [matrix_public | zeroes to H | matrix_witness | zeroes to 2H],
///
/// while the logical assignment is
///
///   [1 | assignment_public | zeroes to H | assignment_witness].
///
/// `assignment_witness` has exactly H base-field values, including its
/// structural padding. Matrix zero tails and the public constant one are
/// virtual and consume no source storage.
struct WiringSumcheckArtifactArrays {
    std::string matrix_public;
    std::string matrix_witness;
    std::string assignment_public;
    std::string assignment_witness;

    bool operator==(
        const WiringSumcheckArtifactArrays &) const = default;
};

/// One stored run in an otherwise virtual-zero witness half. Logical offsets
/// address the H-element witness polynomial; stored offsets address the
/// compact assignment artifact array.
struct WiringAssignmentStorageSegment {
    std::uint64_t logical_begin = 0;
    std::uint64_t stored_begin = 0;
    std::uint64_t element_count = 0;

    bool operator==(const WiringAssignmentStorageSegment &) const = default;
};

/// Optional compact layout for `assignment_witness`. A zero `half_size`
/// selects a dense layout, in which the array itself has H values.
/// Otherwise the array stores exactly the ordered segments below and missing
/// logical positions are canonical zeroes.
struct WiringAssignmentStorageLayout {
    std::uint64_t half_size = 0;
    std::vector<WiringAssignmentStorageSegment> segments;

    bool operator==(const WiringAssignmentStorageLayout &) const = default;
};

/// Explicit storage and memory authority for one artifact-backed
/// WiringCheck. Both source artifacts and the scratch directory must be
/// caller-owned, real, and pairwise disjoint. Scratch must start empty.
/// `max_working_field_bytes` covers dynamic Fq/Fq2 buffers, the small
/// fixed-prefix table, and the returned proof/point field payload; reader
/// objects, encoders, and allocator metadata are excluded.
struct WiringSumcheckArtifactOptions {
    Digest expected_matrix_identity{};
    Digest expected_assignment_identity{};
    std::filesystem::path scratch_directory;
    /// Complete physical bytes allowed for both immutable source artifacts
    /// plus every simultaneously live scratch checkpoint.
    std::uint64_t max_live_storage_bytes = 0;
    std::uint64_t max_total_scratch_bytes = 0;
    std::uint64_t min_free_bytes = 0;
    std::uint64_t max_working_field_bytes = 0;
    std::size_t block_elements = 0;
    std::size_t source_rounds =
        kDefaultArtifactWiringSourceRounds;
};

/// Exact logical I/O and live-scratch ledger for one WiringCheck proof.
/// Validation reads are reported separately from protocol-selected source
/// reads. Read operations are data-carrying array reads, not OS syscalls.
struct WiringSumcheckArtifactReport {
    std::uint64_t matrix_artifact_physical_bytes = 0;
    std::uint64_t assignment_artifact_physical_bytes = 0;
    std::uint64_t source_validation_bytes = 0;
    std::uint64_t selected_matrix_payload_bytes = 0;
    std::uint64_t selected_assignment_payload_bytes = 0;
    std::uint64_t selected_source_payload_bytes = 0;
    std::uint64_t source_read_payload_bytes = 0;
    std::uint64_t source_read_operations = 0;
    /// Full artifact bytes read while validating publication and again while
    /// binding pre-deletion cleanup to the exact published tree.
    std::uint64_t scratch_artifact_validation_bytes = 0;
    std::uint64_t scratch_read_payload_bytes = 0;
    std::uint64_t scratch_read_operations = 0;
    std::uint64_t scratch_write_payload_bytes = 0;
    std::uint64_t scratch_write_operations = 0;
    std::uint64_t scratch_peak_physical_bytes = 0;
    std::uint64_t scratch_written_physical_bytes = 0;
    std::uint64_t scratch_deleted_physical_bytes = 0;
    std::uint64_t scratch_retained_physical_bytes = 0;
    std::uint64_t peak_live_storage_bytes = 0;
    std::uint64_t peak_working_field_bytes = 0;
    std::size_t effective_block_elements = 0;
    std::size_t source_rescan_rounds = 0;
    std::size_t fold_passes = 0;

    bool operator==(
        const WiringSumcheckArtifactReport &) const = default;
};

struct WiringSumcheckArtifactOutput {
    WiringSumcheckOutput sumcheck;
    WiringSumcheckArtifactReport report;
};

struct WiringSumcheckArtifactPlan {
    std::uint64_t scratch_peak_physical_bytes = 0;
    std::uint64_t scratch_written_physical_bytes = 0;
    std::uint64_t minimum_working_field_bytes = 0;
    std::size_t effective_block_elements = 0;
    std::uint64_t peak_working_field_bytes = 0;

    bool operator==(
        const WiringSumcheckArtifactPlan &) const = default;
};

WiringSumcheckArtifactPlan plan_wiring_sumcheck_artifact(
    std::size_t half_size, std::size_t source_rounds,
    std::uint64_t max_working_field_bytes,
    std::size_t requested_block_elements);

/// Exact maximum physical scratch simultaneously retained by the artifact
/// WiringCheck schedule for an assignment whose two halves each have H
/// values.
std::uint64_t wiring_sumcheck_artifact_scratch_peak_physical_bytes(
    std::size_t half_size, std::size_t source_rounds);

/// Prove `sum_y M(y) z(y) = claimed_value` from compact immutable sources.
/// The witness-half length determines H and must be a power of two. The
/// public-input and active-witness-matrix arrays are nonempty, the public
/// matrix has exactly `public_inputs+1` values, the active witness matrix has
/// at most H values, and this dense overload requires the stored witness
/// assignment itself to have H values.
///
/// The first `source_rounds` messages rescan only the stored source arrays.
/// A dense pair of reduced Fq2 checkpoints is then published. Every later
/// round finalizes and validates its successor before deleting its
/// predecessor. All source and resource validation precedes the first
/// transcript observation. An I/O failure after that point performs checked
/// cleanup of only the scratch directories registered by this call, but leaves
/// `public_coin` advanced, so the caller must restart from its prior transcript
/// checkpoint. Changed or path-substituted scratch is retained and reported
/// rather than removed.
WiringSumcheckArtifactOutput prove_wiring_sumcheck_artifact(
    const storage::NativeFieldArtifact &matrix_source,
    const storage::NativeFieldArtifact &assignment_source,
    const WiringSumcheckArtifactArrays &arrays,
    const Fq2 &claimed_value, PublicCoin &public_coin,
    WiringSumcheckArtifactOptions options);

/// Compact-witness overload. The transcript is byte-identical to the dense
/// prover over the logical assignment obtained by inserting zeroes outside
/// `assignment_layout.segments`.
WiringSumcheckArtifactOutput prove_wiring_sumcheck_artifact(
    const storage::NativeFieldArtifact &matrix_source,
    const storage::NativeFieldArtifact &assignment_source,
    const WiringSumcheckArtifactArrays &arrays,
    const WiringAssignmentStorageLayout &assignment_layout,
    const Fq2 &claimed_value, PublicCoin &public_coin,
    WiringSumcheckArtifactOptions options);

} // namespace laminate::spartan

#endif // LAMINATE_SPARTAN_WIRING_ARTIFACT_HPP
