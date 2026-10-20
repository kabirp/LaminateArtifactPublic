#ifndef LAMINATE_SETUP_GATE_MLE_HPP
#define LAMINATE_SETUP_GATE_MLE_HPP

/// @file setup/gate_mle.hpp
/// @brief Deterministic structured GateMLE setup and server restoration.

#include "laminate/setup/public.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

namespace laminate {

/// Public verifier metadata paired with the server-only opening state built
/// from one canonical circuit. Production setup persists the latter for
/// server startup; bounded reference callers can reconstruct it on demand.
struct OutsourcedGateMleSetupArtifacts {
    PublicSetup public_setup;
    std::shared_ptr<const gates::GateTableProverKey> prover_key;
};

/// Conservative resource bounds for retained keys and the largest opening.
/// Wide codewords and reverse traces are stored on disk; Laned retains its
/// resident RS tables. RAM formulas include explicit process slack.
struct GateMleProverResourceBounds {
    std::uint64_t retained_prover_key_bytes = 0;
    std::uint64_t opening_workspace_bytes = 0;
    /// Conservative encoded proof cap, allowing two output points per affine
    /// layer. Current GKR uses one; public-table queries batch by commitment.
    std::uint64_t proof_bytes_upper_bound = 0;
    std::uint64_t retained_prover_key_disk_bytes = 0;
    std::uint64_t opening_workspace_disk_bytes = 0;

    bool operator==(const GateMleProverResourceBounds &) const = default;
};

/// Structural setup plan. It contains no commitment roots or verifier key.
/// Computing it scans the canonical circuit without building field columns,
/// codewords, Merkle trees, or filesystem artifacts.
struct GateMlePreprocessingPlan {
    gates::GateTableLayout layout;
    std::vector<gates::SparseTableShape> tables;
    basefold::Parameters basefold_parameters{};
    basefold::foldable::Parameters foldable_parameters{};
    /// Zero for Laned or an empty Wide public index.
    std::size_t wide_public_message_size = 0;
    std::size_t wide_public_width = 0;
    GateMleProverResourceBounds resources;
    std::size_t basefold_soundness_bits = 0;
    /// Peak public-index disk usage while building the commitment.
    std::uint64_t commitment_peak_disk_bytes = 0;
};

GateMlePreprocessingPlan plan_gate_mle_preprocessing(
    const payload::LayeredCircuit &circuit,
    gates::GateTableSet table_set,
    const gates::GateTableBuildOptions &options = {});

/// Offline structural admission for public affine preparation in Base/Folded
/// GKR. Conservatively reserves one reverse pass and an extra retained basis
/// family, equality tables, and per-node map metadata. Current GKR has one claim.
std::uint64_t affine_gate_preparation_workspace_bytes(
    const payload::LayeredCircuit &circuit);

GateMleProverResourceBounds gate_mle_prover_resource_bounds(
    const gates::GateTableVerifierKey &verifier_key);

/// Proven BaseFold RBR bits: the minimum bit bound over all table openings.
/// Zero means that this key has no supported positive soundness bound.
std::size_t gate_mle_basefold_soundness_bits(
    const gates::GateTableVerifierKey &verifier_key);

OutsourcedGateMleSetupArtifacts preprocess_outsourced_gate_mle_setup(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    gates::GateTableSet table_set,
    const gates::GateTableBuildOptions &options = {});

/// Open the persisted server-only state when a prover_key_directory is set;
/// otherwise deterministically rebuild it for reference callers. Require its
/// verifier projection to match authenticated public setup exactly.
/// Direct profiles return an empty pointer, so process drivers retain a
/// deliberate fallback without branching at every call site.
std::shared_ptr<const gates::GateTableProverKey>
restore_gate_mle_prover_key(const payload::LayeredCircuit &circuit,
                            const PublicSetup &public_setup,
                            const gates::GateTableBuildOptions &runtime_options = {});

} // namespace laminate

#endif // LAMINATE_SETUP_GATE_MLE_HPP
