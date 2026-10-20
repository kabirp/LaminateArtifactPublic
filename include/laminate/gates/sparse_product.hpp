#ifndef LAMINATE_GATES_SPARSE_PRODUCT_HPP
#define LAMINATE_GATES_SPARSE_PRODUCT_HPP

/// @file sparse_product.hpp
/// @brief Low-degree product-tree reduction for one sparse multilinear MLE.
///
/// A sparse polynomial with entries `(address, value)` evaluates at `q` as
///
///   sum_j value_j * product_i selector(q_i, address_j[i]).
///
/// Proving that expression with one sumcheck would give degree proportional
/// to the address width.  This module instead places the value and every bit
/// selector at the leaves of a binary product tree.  A degree-one sumcheck
/// reduces the root sum, and one Gruen-stripped degree-two sumcheck proves
/// each multiplication layer.  The result is a single evaluation of the
/// joint `(factor, entry)` leaf table, ready to be authenticated by the gate
/// BaseFold commitment.

#include "laminate/field/fp.hpp"
#include "laminate/field/fpk.hpp"
#include "laminate/transcript/public_coin.hpp"

#include <array>
#include <cstddef>
#include <optional>
#include <span>
#include <vector>

namespace laminate::gates::sparse {

/// One nonzero in a canonical sparse table.  Addresses use the ordinary
/// integer encoding of an MSB-first Boolean vector.
struct SparseEntry {
    std::size_t address = 0;
    Fp value = Fp::zero();

    bool operator==(const SparseEntry &) const = default;
};

/// One product-tree multiplication layer, ordered from root to leaves.
struct ProductLayerProof {
    /// Each round sends one endpoint and the stripped degree-two polynomial
    /// at X=2.  The endpoint is S(1), except when the current equality-point
    /// coordinate is one, in which case it is S(0).  This is the same
    /// division-free singular branch used by Spartan's Gruen sumcheck.
    std::vector<std::array<Fpk, 2>> rounds;
    Fpk left_claim = Fpk::zero();
    Fpk right_claim = Fpk::zero();

    bool operator==(const ProductLayerProof &) const = default;
};

struct SparseProductProof {
    /// Degree-one root sumcheck messages.  The sole transmitted value is
    /// R(1); R(0) is recovered from the current sum.
    std::vector<Fpk> root_rounds;
    std::vector<ProductLayerProof> layers;

    bool operator==(const SparseProductProof &) const = default;
};

/// Terminal claim about the padded joint leaf table.  Both points are in
/// BaseFold-compatible LSB-first order even though sparse addresses and the
/// original query point are MSB-first.
struct SparseProductReduction {
    std::vector<Fpk> entry_point_lsb;
    std::vector<Fpk> factor_point_lsb;
    Fpk leaf_claim = Fpk::zero();

    bool operator==(const SparseProductReduction &) const = default;
};

struct SparseProductProverOutput {
    SparseProductProof proof;
    SparseProductReduction reduction;
};

/// Affine expression for the terminal joint-leaf claim.  `column_weights`
/// names the logical committed columns in the order
///
///   value, address-bit-0 (MSB), ..., address-bit-(d-1) (LSB).
///
/// At the product reduction's entry point,
///
///   leaf_claim = constant + sum_c column_weights[c] * column_c(point).
struct SparseLeafLinearization {
    std::vector<Fpk> column_weights;
    Fpk constant = Fpk::zero();
};

/// Direct/reference evaluation of a canonical sparse table.
Fpk evaluate_sparse_entries(std::span<const SparseEntry> entries,
                            std::size_t address_variables,
                            std::span<const Fpk> query_point_msb);

/// Prove the claimed sparse-table evaluation.  `message_size` is the padded
/// power-of-two number of entry slots; unused slots have zero value and zero
/// address bits.  Throws on malformed inputs or an incorrect claim.
SparseProductProverOutput prove_sparse_evaluation(
    std::span<const SparseEntry> entries, std::size_t message_size,
    std::size_t address_variables,
    std::span<const Fpk> query_point_msb, const Fpk &claimed,
    PublicCoin &public_coin);

/// Verify only the low-degree reduction.  The caller must separately
/// authenticate the returned leaf claim against committed value/address-bit
/// columns, normally using `linearize_sparse_leaf` and gate BaseFold.
std::optional<SparseProductReduction> verify_sparse_evaluation(
    std::size_t message_size, std::size_t address_variables,
    std::span<const Fpk> query_point_msb, const Fpk &claimed,
    const SparseProductProof &proof, PublicCoin &public_coin);

/// Derive the known constant and logical committed-column weights needed to
/// authenticate a product-tree terminal claim.
SparseLeafLinearization linearize_sparse_leaf(
    std::size_t address_variables,
    std::span<const Fpk> query_point_msb,
    std::span<const Fpk> factor_point_lsb);

} // namespace laminate::gates::sparse

#endif // LAMINATE_GATES_SPARSE_PRODUCT_HPP
