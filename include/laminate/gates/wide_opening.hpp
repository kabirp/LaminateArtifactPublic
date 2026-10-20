#ifndef LAMINATE_GATES_WIDE_OPENING_HPP
#define LAMINATE_GATES_WIDE_OPENING_HPP

#include "laminate/basefold/foldable.hpp"
#include "laminate/gates/action_sumcheck.hpp"
#include "laminate/gates/masked_action.hpp"
#include "laminate/gates/table_types.hpp"
#include "laminate/gates/wide_program.hpp"

namespace laminate::gates {

struct GateTableProverKey;
struct RecordedGateQuery;

/// One evaluation of a preprocessed affine operator or constant, whether
/// represented by composed boundary rows or local primitive rows.
/// Uniform/rotation and plaintext-mask contributions are independently bound.
struct WideLocalOpeningProof {
    Fpk first_component = Fpk::zero();
    Fpk second_component = Fpk::zero();
    std::optional<WideActionSumcheckProof> action;
    std::optional<MaskedActionProof> masked;
    std::vector<sparse::SparseProductProof> products;
};

struct WideTraceOpeningProof {
    bool has_adjoint = false;
    /// Output-boundary terms, in recorded-query order, followed by the
    /// internal residual boundary. The latter exists only for nonempty DAGs.
    std::vector<Fpk> boundary_values;
    Fpk residual_evaluation = Fpk::zero();
    QuadraticProductProof product;
    /// Local internal-matrix values at the product-sumcheck terminal.
    std::vector<Fpk> terminal_values;
    /// Boundary evaluations followed by internal terminal evaluations.
    std::vector<WideLocalOpeningProof> local_openings;
};

struct WidePublicTableOpeningProof {
    std::size_t table_selector = 0;
    basefold::ColumnTargets column_targets;
};

/// Equal-sized traces share an unpadded scalar message. Groups have at most
/// four members and at most 2^32 entries; larger individual traces stay alone.
/// Zero trace sizes denote affine programs without internal nodes.
struct WideAdjointGroupLayout {
    std::vector<std::size_t> trace_indices;
    std::size_t block_size = 0;
    std::size_t message_size = 0;
    bool operator==(const WideAdjointGroupLayout &) const = default;
};
std::vector<WideAdjointGroupLayout> wide_adjoint_group_layout(
    std::span<const std::size_t> trace_sizes);

struct WideAdjointGroupProof {
    basefold::Digest root{};
    basefold::foldable::Proof opening;
};

/// Number of distinct row operands needed to open one sparse-table request
/// against the public index's canonical honest-column layout.
std::size_t wide_public_operands_per_request(
    const SparseTableCommitment &, const basefold::foldable::Metadata &);

struct WideGateOpeningProof {
    /// One certificate per distinct (layer, output point). Composed boundary
    /// programs need only local openings; retained DAGs also need an adjoint
    /// trace. Requests with the same output point share this certificate.
    std::vector<WideTraceOpeningProof> traces;
    /// The verifier derives group membership and offsets from ordered queries.
    std::vector<WideAdjointGroupProof> adjoint_groups;
    /// Per-table targets discharge the sparse-product terminal claims.
    std::vector<WidePublicTableOpeningProof> tables;
    /// For each derived row operand, evaluations against every honest public
    /// column. Local targets are checked against the corresponding entries;
    /// this entire matrix is fixed before the shared column-batching challenge.
    basefold::ColumnTargets public_column_targets;
    /// All pending public requests share one honest-column PCS batch.
    /// Empty exactly when there are no public requests.
    basefold::foldable::Proof public_opening;
};

WideGateOpeningProof prove_wide_gate_opening(
    const payload::LayeredCircuit &circuit, const GateTableProverKey &key,
    std::span<const RecordedGateQuery> queries,
    std::span<const Fpk> claimed_values, PublicCoin &coin);

bool verify_wide_gate_opening(
    const GateTableVerifierKey &key, std::span<const RecordedGateQuery> queries,
    std::span<const Fpk> claimed_values, const WideGateOpeningProof &proof,
    PublicCoin &coin);

} // namespace laminate::gates

#endif
