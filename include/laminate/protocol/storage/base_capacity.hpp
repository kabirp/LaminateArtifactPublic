#ifndef LAMINATE_PROTOCOL_STORAGE_BASE_CAPACITY_HPP
#define LAMINATE_PROTOCOL_STORAGE_BASE_CAPACITY_HPP

/// @file base_capacity.hpp
/// @brief Phase-local disk and RAM admission for a file-backed Base server.

#include "laminate/protocol/storage/checkpoint_replay.hpp"

#include <array>
#include <cstddef>
#include <cstdint>

namespace laminate::protocol {

/// Caller-supplied disk and RAM ceilings. Zero defaults fail closed so the
/// reusable protocol layer cannot silently inherit one benchmark machine's
/// deployment policy.
struct BaseServerCapacityCaps {
    std::uint64_t max_live_local_disk_bytes = 0;
    std::uint64_t max_resident_ram_bytes = 0;

    bool operator==(const BaseServerCapacityCaps &) const = default;
};

/// Resource declarations are physical disk bytes and simultaneous resident
/// bytes. A serialized artifact and its loaded representation belong on the
/// two independent axes of the same pair when both remain live.
///
/// Every component is exclusive of every other component. In particular,
/// `compact_replay_trace` contains only canonical stored public-or-encrypted
/// values and their artifact metadata. Public stored values have records and
/// bytes but no ciphertext-object charge. Structural padding denotes the
/// public plaintext zero polynomial and has no value, record, or byte charge.
///
/// The checkpoint planner's peaks already contain `budgets.reserved_*`.
/// Those reserves are not another component here. The integrated binder
/// verifies that they cover the detailed non-artifact resources, copies the
/// planner peaks into `payload_replay_phase_floor`, and the composer takes a
/// component-wise maximum of that floor and its detailed phase sum. Thus the
/// planner cannot hide an omitted resource, and its reserve is never added a
/// second time. Request/output resources belong to forward evaluation;
/// accumulated proof bytes belong to reverse replay, so the binder requires
/// the planner reserve to cover their component-wise maximum rather than a
/// fictitious simultaneous sum.
struct BaseServerCapacityComponents {
    /// Capacity deliberately withheld for the OS, filesystem allocation,
    /// allocator slack, page cache policy, and recovery/quarantine. This is
    /// charged in every phase rather than subtracted after admission.
    ServerResourcePair operational_reserve;

    /// Serialized and loaded FHE/proving material retained for the session.
    ServerResourcePair preprocessed_keys;
    /// Prepared plaintexts and other immutable evaluation caches.
    ServerResourcePair prepared_plaintext_cache;
    /// Any retained Base GateMLE preprocessing (zero for structured access).
    ServerResourcePair gate_mle_preprocessing;

    /// Peak live compact checkpoint/replay artifacts, including their own
    /// indexes and metadata but excluding the workspaces below. For the
    /// integrated checkpoint path, local-disk bytes are derived from the
    /// selected plan (including a replayed transient source that survives into
    /// a reduction), so callers leave that axis zero. Resident bytes remain a
    /// caller measurement, raised by the binder to a conservative in-memory
    /// record-index/digest bound: every selected checkpoint plus the largest
    /// exact transient state across a relation edge or natural-plus-reduced
    /// proof-ingress publication.
    ServerResourcePair compact_replay_trace;
    /// Complete decoded request retained only through evaluation.
    ServerResourcePair encrypted_input_request;
    /// Evaluation response retained only until it is moved to the client.
    /// The server must not keep this response while accepting the claim or
    /// proving. An exceptional duplicate belongs in a persistent reserve.
    ServerResourcePair encrypted_output_response;
    ServerResourcePair payload_replay_workspace;
    /// Absolute whole-phase floor derived from the admitted checkpoint plan.
    /// Integrated callers leave this pair zero. The binder copies the selected
    /// planner peaks here only after checking that `budgets.reserved_*` cover
    /// every non-artifact resource that can coexist with forward or reverse
    /// replay. Composition then takes the larger of this absolute floor and
    /// the detailed payload-phase sum; it never adds the planner reserve to
    /// those detailed components a second time.
    ServerResourcePair payload_replay_phase_floor;

    ServerResourcePair affine_reduction_workspace;
    /// Peak combined final-output and temporary-run bytes while building one
    /// multiplication source. Temporary runs are gone before reduction.
    ServerResourcePair multiplication_build_scratch;
    /// Finalized multiplication source retained during its reduction.
    ServerResourcePair multiplication_artifact;
    ServerResourcePair multiplication_builder_workspace;
    ServerResourcePair multiplication_reduction_workspace;

    /// The largest encrypted Base proof prefix retained during GKR.
    ServerResourcePair accumulated_proof;
    /// Online workspace for the optional outsourced GateMLE opening. Direct
    /// and dummy-direct profiles leave this zero.
    ServerResourcePair gate_mle_opening_workspace;
    /// Canonical proof bytes coexisting with the proof object at publication.
    ServerResourcePair proof_encoding;
    /// Outer message/frame copy coexisting with the canonical proof bytes.
    ServerResourcePair transport_framing;

    bool operator==(
        const BaseServerCapacityComponents &) const = default;
};

enum class BaseServerCapacityPhase : std::uint8_t {
    PreprocessedReady = 0,
    PayloadCheckpointReplay = 1,
    AffineReduction = 2,
    MultiplicationScratchBuild = 3,
    MultiplicationReduction = 4,
    GateMleOpening = 5,
    ProofPublication = 6,
};

inline constexpr std::size_t kBaseServerCapacityPhaseCount = 7;

/// Bytes that coexist at one lifecycle boundary. `combined_bytes` is
/// diagnostic only; the deployment limits disk and RAM independently.
struct BaseServerCapacityPhasePeak {
    BaseServerCapacityPhase phase =
        BaseServerCapacityPhase::PreprocessedReady;
    std::uint64_t live_local_disk_bytes = 0;
    std::uint64_t resident_ram_bytes = 0;
    std::uint64_t combined_bytes = 0;

    bool operator==(
        const BaseServerCapacityPhasePeak &) const = default;
};

struct BaseServerCapacityAdmission {
    BaseServerCapacityCaps caps;
    std::array<BaseServerCapacityPhasePeak,
               kBaseServerCapacityPhaseCount>
        phases{};
    std::uint64_t max_live_local_disk_bytes = 0;
    std::uint64_t max_resident_ram_bytes = 0;
    std::uint64_t max_phase_combined_bytes = 0;

    const BaseServerCapacityPhasePeak &
    phase(BaseServerCapacityPhase requested) const;

    const BaseServerCapacityPhasePeak &peak_live_local_disk_phase() const;

    bool operator==(
        const BaseServerCapacityAdmission &) const = default;
};

/// Validate a complete Base lifecycle before any artifact is written.
///
/// This function is pure arithmetic: it receives no path or mutable server
/// object. It throws before returning when any phase exceeds an independent
/// capacity or when byte arithmetic overflows. The caller must run it before
/// opening replay or multiplication-scratch writers.
BaseServerCapacityAdmission admit_base_server_capacity(
    const BaseServerCapacityCaps &caps,
    const BaseServerCapacityComponents &components);

/// Free bytes required before setup writes either role's preprocessing.
/// The admitted server peak is the conservative allocation model; the
/// configured cap is only a policy ceiling. Client preprocessing remains
/// live beside that server peak, while the second branch covers the initial
/// preprocessing write.
std::uint64_t required_base_setup_available_disk(
    const BaseServerCapacityAdmission &admission,
    std::uint64_t client_preprocessing_bytes,
    std::uint64_t all_preprocessing_bytes,
    std::uint64_t free_space_reserve_bytes);

/// Free bytes required when the server starts after preprocessing already
/// exists. Available filesystem space already excludes every persisted role
/// artifact, so subtract the modeled server-preprocessing component before
/// adding the required post-peak reserve.
std::uint64_t required_base_server_available_disk(
    const BaseServerCapacityAdmission &admission,
    std::uint64_t server_preprocessing_bytes,
    std::uint64_t free_space_reserve_bytes);

} // namespace laminate::protocol

#endif // LAMINATE_PROTOCOL_STORAGE_BASE_CAPACITY_HPP
