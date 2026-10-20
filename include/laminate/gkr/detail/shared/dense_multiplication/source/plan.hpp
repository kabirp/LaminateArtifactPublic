#ifndef LAMINATE_GKR_DETAIL_SHARED_DENSE_MULTIPLICATION_SOURCE_PLAN_HPP
#define LAMINATE_GKR_DETAIL_SHARED_DENSE_MULTIPLICATION_SOURCE_PLAN_HPP

/// @file plan.hpp
/// @brief Preprocessed operand aliasing and physical pair order.

#include "laminate/gkr/detail/shared/dense_multiplication/source/descriptor.hpp"

#include <algorithm>
#include <bit>
#include <cstddef>
#include <numeric>
#include <optional>
#include <stdexcept>
#include <vector>

namespace laminate::gkr::detail {

/// The source artifact stores each distinct packed operand once. A logical
/// multiplication pair is therefore two public operand ids, not two repeated
/// ciphertext records. The plan also fixes the bit-reversed physical pair
/// order consumed by every file-backed sumcheck scan.

/// One distinct packed operand is determined entirely by the compact source
/// ordinals occupying its chunk positions. `nullopt` is structural padding.
struct DenseMultiplicationOperandSignature {
    std::vector<std::optional<std::size_t>> stored_ordinals;

    bool operator==(
        const DenseMultiplicationOperandSignature &) const = default;
};

/// Setup-derived public alias map for a packed multiplication source. The two
/// logical maps have `live_pair_count` entries. `storage_order` lists distinct
/// operand ids in their first-use order while logical pairs are traversed in
/// bit-reversed physical order.
struct DenseMultiplicationAliasPlan {
    std::size_t pair_count = 0;
    std::size_t live_pair_count = 0;
    std::vector<DenseMultiplicationOperandSignature> operands;
    std::vector<std::size_t> left_operand;
    std::vector<std::size_t> right_operand;
    std::vector<std::size_t> physical_pair_order;
    std::vector<std::size_t> storage_order;
    std::vector<std::size_t> storage_ordinal_by_operand;
    std::vector<std::size_t> operand_occurrences;

    bool has_aliases() const {
        return operands.size() < 2U * live_pair_count;
    }
};

/// Setup/admission plan for one file-backed multiplication reduction.
///
/// This is immutable public metadata, not an opened source or an on-disk
/// artifact. The request contributes only its authenticated trace id;
/// support, storage, aliasing, layouts, levels, and setup identities are
/// derived once during server preprocessing.
struct DenseMultiplicationSourcePlan {
    /// Trace geometry with the request-varying trace id cleared.
    payload::EncryptedTraceDescriptor trace_template;
    /// Artifact descriptor with request-varying trace and artifact ids clear.
    FileDenseMultiplicationSourceDescriptor descriptor_template;
    /// Canonical live-wire support for the source layer.
    payload::LayerWireSupport source_support;
    /// Canonical compact-storage layout for the source layer.
    payload::LayerStorageLayout source_storage;
    /// Public mapping from logical pairs to distinct stored operands.
    DenseMultiplicationAliasPlan aliases;
    /// Minimum bytes required even before the first ciphertext record.
    std::uint64_t minimum_artifact_framing_bytes = 0;
};

/// Construct one source plan from whole-circuit admission results.
/// `source_support` and `source_storage` are the already-derived entries for
/// `reduction_layer + 1`; this function never rediscovers them or redigests the
/// complete circuit. The returned plan is mandatory for build, open, and every
/// reader subsequently created from the opened source.
DenseMultiplicationSourcePlan make_dense_multiplication_source_plan(
    const payload::LayeredCircuit &circuit,
    payload::EncryptedTraceDescriptor trace_template,
    const Digest &layered_circuit_id, const Digest &backend_context_id,
    std::size_t reduction_layer,
    const payload::LayerWireSupport &source_support,
    const payload::LayerStorageLayout &source_storage,
    const Digest &setup_id,
    std::size_t source_proof_ingress_rns_limbs);

/// Instantiate an artifact descriptor by binding the request's trace id to a
/// setup-derived source plan. This does not open or build the artifact and
/// does not rescan the circuit.
FileDenseMultiplicationSourceDescriptor
bind_dense_multiplication_source_descriptor(
    const DenseMultiplicationSourcePlan &plan,
    const payload::EncryptedTraceDescriptor &trace,
    const Digest &layered_circuit_id, const Digest &backend_context_id);

/// Derive a standalone alias plan for reference implementations and cost
/// analysis. Production file-backed proving uses the cached-metadata overload
/// below through `DenseMultiplicationSourcePlan`.
DenseMultiplicationAliasPlan make_dense_multiplication_alias_plan(
    const payload::LayeredCircuit &circuit, std::size_t reduction_layer);

/// Build the plan from the source layer's setup-cached canonical metadata.
/// Production callers derive support and storage once for the whole circuit,
/// then pass the two entries for `reduction_layer + 1` here.
DenseMultiplicationAliasPlan make_dense_multiplication_alias_plan(
    const payload::LayeredCircuit &circuit, std::size_t reduction_layer,
    const payload::LayerWireSupport &source_support,
    const payload::LayerStorageLayout &source_storage);

/// Reverse exactly `bit_count` low bits. Both the input and output are in
/// `[0, 2^bit_count)`. This is public because the file-backed round evaluator
/// must map physical group numbers back to canonical suffix indices.
std::size_t bit_reverse_index(std::size_t value, std::size_t bit_count);

inline std::vector<std::size_t> live_packed_indices_in_physical_order(
    std::size_t live_pair_count, std::size_t pair_count) {
    if (pair_count == 0U ||
        (pair_count & (pair_count - 1U)) != 0U ||
        live_pair_count > pair_count) {
        throw std::invalid_argument(
            "packed multiplication live-order shape is invalid");
    }
    const std::size_t bits = std::bit_width(pair_count) - 1U;
    std::vector<std::size_t> result(live_pair_count);
    std::iota(result.begin(), result.end(), std::size_t{0});
    std::sort(result.begin(), result.end(),
              [&](std::size_t left, std::size_t right) {
                  return bit_reverse_index(left, bits) <
                         bit_reverse_index(right, bits);
              });
    return result;
}

namespace file_dense_multiplication_source_detail {

inline std::size_t advance_bit_reversed_index(
    std::size_t current, std::size_t bit_count,
    std::uint64_t *bit_flips = nullptr) {
    if (bit_count == 0) {
        return 0;
    }
    std::size_t bit = std::size_t{1} << (bit_count - 1U);
    while ((current & bit) != 0) {
        current ^= bit;
        if (bit_flips != nullptr) {
            checked_accumulate(*bit_flips, 1,
                               "bit-reversed iterator flip count");
        }
        bit >>= 1U;
    }
    current ^= bit;
    if (bit_flips != nullptr) {
        checked_accumulate(*bit_flips, 1,
                           "bit-reversed iterator flip count");
    }
    return current;
}

} // namespace file_dense_multiplication_source_detail

} // namespace laminate::gkr::detail

#endif // LAMINATE_GKR_DETAIL_SHARED_DENSE_MULTIPLICATION_SOURCE_PLAN_HPP
