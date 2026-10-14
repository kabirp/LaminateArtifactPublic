#ifndef LAMINATE_GATES_OUTSOURCED_HPP
#define LAMINATE_GATES_OUTSOURCED_HPP

/// @file outsourced.hpp
/// @brief Transcript-bound structured GateMLE reductions and openings.

#include "laminate/gates/action_sumcheck.hpp"
#include "laminate/basefold/proof_io.hpp"
#include "laminate/gates/canonical_tables.hpp"
#include "laminate/gates/gate_mle.hpp"
#include "laminate/gates/wide_opening.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace laminate::gates {

enum class RecordedGateQueryKind : std::uint8_t {
    WideAffine,
    LanedAffineWire,
    AffineConstant,
};

struct RecordedGateQuery {
    std::size_t layer_index = 0;
    RecordedGateQueryKind kind = RecordedGateQueryKind::WideAffine;
    std::size_t first_point_size = 0;
    std::vector<Fpk> local_point_msb;
};

struct SparseTableOpeningProof {
    std::size_t table_selector = 0;
    /// One row per sparse product reduction targeting this polynomial.
    basefold::ColumnTargets column_targets;
    basefold::Proof opening;
};

struct OutsourcedGateMleProof {
    /// Values consumed online by the GKR verifier, in transcript order.
    std::vector<Fpk> claimed_values;
    /// Base/Folded authenticate composed sparse boundary operators or, when
    /// composition is unavailable, a reverse trace of the local affine DAG.
    /// Laned uses the compact wire-polynomial fields below.
    std::optional<WideGateOpeningProof> wide;
    /// Laned compact-polynomial values in online-claim order. Constants may
    /// expand into uniform and slot-dependent components.
    std::vector<Fpk> sparse_values;
    /// Reserved proof collection, empty in the current Wide and Laned paths.
    std::vector<WideActionSumcheckProof> action_sumchecks;
    std::vector<sparse::SparseProductProof> sparse_products;
    /// One BaseFold batch for every compact polynomial used by this proof,
    /// ordered by table selector.
    std::vector<SparseTableOpeningProof> table_openings;
};

std::vector<std::uint8_t>
encode_canonical(const GateTableVerifierKey &key);
std::vector<std::uint8_t>
encode_canonical(const OutsourcedGateMleProof &proof);

void observe_gate_table_key(const GateTableVerifierKey &key,
                            Transcript &transcript);

/// Evaluation-side channel. Calls are explicit protocol claims, not the many
/// direct gate evaluations used internally to construct encrypted rounds.
/// The enclosing protocol must validate and absorb the matching verifier key
/// into `transcript` before constructing this channel.
class GateClaimProver {
  public:
    GateClaimProver(const payload::LayeredCircuit &circuit,
                    const GateTableLayout &layout,
                    Transcript &transcript);

    Fpk evaluate(const GateMleQuery &query);
    Fpk evaluate_affine_constant(std::size_t layer_index,
                                 std::span<const Fpk> output_point);

    std::size_t claim_count() const { return queries_.size(); }

    /// Authenticate the ordered GKR claims after every claim is bound. Wide
    /// batches public tables and any adjoint groups; Laned opens each compact
    /// polynomial in a separate BaseFold batch.
    OutsourcedGateMleProof finish(const GateTableProverKey &key);

  private:
    Fpk record(RecordedGateQuery query, const Fpk &value);

    const payload::LayeredCircuit &circuit_;
    const GateTableLayout &layout_;
    DirectGateMle direct_;
    Transcript &transcript_;
    std::vector<RecordedGateQuery> queries_;
    std::vector<Fpk> claimed_values_;
};

/// Client-side channel. It returns untrusted online claims immediately, then
/// `finish()` authenticates the whole ordered batch before verification may
/// accept. The enclosing protocol must first validate and absorb `key` into
/// `transcript`; the raw channel deliberately does not repeat that binding.
class GateClaimVerifier {
  public:
    GateClaimVerifier(const GateTableVerifierKey &key,
                      const OutsourcedGateMleProof &proof,
                      Transcript &transcript);

    Fpk evaluate(const GateMleQuery &query);
    Fpk evaluate_affine_constant(std::size_t layer_index,
                                 std::span<const Fpk> output_point);

    /// Verify action and sparse product reductions, BaseFold batches, and all
    /// analytic equality terminals. Returns false on any shape mismatch.
    bool finish();

    std::size_t consumed_claims() const { return cursor_; }

  private:
    Fpk consume(RecordedGateQuery query);

    const GateTableVerifierKey &key_;
    const OutsourcedGateMleProof &proof_;
    Transcript &transcript_;
    std::size_t cursor_ = 0;
    std::vector<RecordedGateQuery> queries_;
};

} // namespace laminate::gates

#endif // LAMINATE_GATES_OUTSOURCED_HPP
