#ifndef LAMINATE_GATES_QUADRATIC_PRODUCT_HPP
#define LAMINATE_GATES_QUADRATIC_PRODUCT_HPP

/// Degree-two sumcheck for an inner product of two multilinear tables.
/// Terminal values are claims: the composing protocol must authenticate both.
/// Points use the BaseFold least-significant-coordinate-first convention.

#include "laminate/basefold/sumcheck.hpp"
#include "laminate/basefold/foldable.hpp"

#include <optional>
#include <span>
#include <vector>

namespace laminate::gates {

struct QuadraticProductProof {
    std::vector<std::array<Fpk, 3>> rounds;
    Fpk left = Fpk::zero();
    Fpk right = Fpk::zero();

    bool operator==(const QuadraticProductProof &) const = default;
};

struct QuadraticProductReduction {
    std::vector<Fpk> point_lsb;
    Fpk left = Fpk::zero();
    Fpk right = Fpk::zero();
};

struct QuadraticProductOutput {
    QuadraticProductProof proof;
    QuadraticProductReduction reduction;
};

/// Bounded reference helper. The production reverse trace uses the external
/// array overload so a full slot-expanded trace need not be resident.
QuadraticProductOutput prove_quadratic_product(
    std::vector<Fpk> left, std::vector<Fpk> right, const Fpk &claim,
    PublicCoin &coin);

/// Bounded-memory production path. The caller supplies a private, empty
/// scratch directory and a disk/working-block budget. Input sources are
/// borrowed; temporary fold arrays are removed on success or exception.
QuadraticProductOutput prove_quadratic_product(
    basefold::foldable::ValueSource left,
    basefold::foldable::ValueSource right, const Fpk &claim,
    PublicCoin &coin, const std::filesystem::path &scratch,
    const basefold::foldable::Options &options = {});

std::optional<QuadraticProductReduction> verify_quadratic_product(
    std::size_t variables, const Fpk &claim,
    const QuadraticProductProof &proof, PublicCoin &coin);

} // namespace laminate::gates

#endif
