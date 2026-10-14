#ifndef LAMINATE_GATES_ACTION_SUMCHECK_HPP
#define LAMINATE_GATES_ACTION_SUMCHECK_HPP

/// @file action_sumcheck.hpp
/// @brief Sparse sumcheck for the Wide affine BGV action.
///
/// A Wide affine coefficient is represented by a compact sparse polynomial
///
///   W(output wire, source wire, BGV offset).
///
/// Fixing the two wire points leaves the full slot-expanded coefficient
///
///   sum_a W(r_out, r_src, a) * GridAction(s_out, s_src, a),
///
/// where `a` ranges over the Boolean BGV-offset cube.  This module reduces
/// that sum to one compact-weight evaluation with exactly `log N`
/// degree-two rounds.  The returned offset point is MSB-first so it can be
/// appended directly to the fixed wire points for a sparse-table opening.

#include "laminate/gates/sparse_product.hpp"
#include "laminate/transcript/public_coin.hpp"

#include <cstddef>
#include <optional>
#include <span>
#include <vector>

namespace laminate::gates {

struct WideActionSumcheckRound {
    Fpk at_one = Fpk::zero();
    Fpk at_two = Fpk::zero();

    bool operator==(const WideActionSumcheckRound &) const = default;
};

struct WideActionSumcheckProof {
    /// Exactly one round for every output/source slot coordinate.
    std::vector<WideActionSumcheckRound> rounds;
    /// W(output_wire, source_wire, sampled_offset).
    Fpk terminal_compact_weight = Fpk::zero();

    bool operator==(const WideActionSumcheckProof &) const = default;
};

struct WideActionSumcheckReduction {
    std::vector<Fpk> offset_point_msb;
    Fpk compact_weight = Fpk::zero();

    bool operator==(
        const WideActionSumcheckReduction &) const = default;
};

struct WideActionSumcheckProverOutput {
    WideActionSumcheckProof proof;
    WideActionSumcheckReduction reduction;

    bool operator==(
        const WideActionSumcheckProverOutput &) const = default;
};

/// Direct/reference evaluation of the full slot-expanded Wide coefficient.
/// Sparse addresses are MSB-first `[output-wire | source-wire | offset]`;
/// the four point spans keep wire and slot coordinates explicitly split.
Fpk evaluate_wide_affine_coefficient(
    std::span<const sparse::SparseEntry> entries,
    std::span<const Fpk> output_wire_point,
    std::span<const Fpk> output_slot_point,
    std::span<const Fpk> source_wire_point,
    std::span<const Fpk> source_slot_point);

/// Prove a claimed full Wide coefficient value.  All input validation and
/// the initial claimed-value check happen before the public coin is observed.
WideActionSumcheckProverOutput prove_wide_action_sumcheck(
    std::span<const sparse::SparseEntry> entries,
    std::span<const Fpk> output_wire_point,
    std::span<const Fpk> output_slot_point,
    std::span<const Fpk> source_wire_point,
    std::span<const Fpk> source_slot_point, const Fpk &claimed_value,
    PublicCoin &public_coin);

/// Verify the action reduction.  Acceptance authenticates the degree-two
/// reduction and its analytic BGV-action terminal only.  The caller must
/// separately authenticate `compact_weight` against the sparse compact table
/// at `[output_wire_point | source_wire_point | offset_point_msb]`.
std::optional<WideActionSumcheckReduction> verify_wide_action_sumcheck(
    std::span<const Fpk> output_wire_point,
    std::span<const Fpk> output_slot_point,
    std::span<const Fpk> source_wire_point,
    std::span<const Fpk> source_slot_point, const Fpk &claimed_value,
    const WideActionSumcheckProof &proof, PublicCoin &public_coin);

} // namespace laminate::gates

#endif // LAMINATE_GATES_ACTION_SUMCHECK_HPP
