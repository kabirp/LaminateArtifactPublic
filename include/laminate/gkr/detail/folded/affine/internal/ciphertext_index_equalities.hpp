#ifndef LAMINATE_GKR_DETAIL_FOLDED_AFFINE_CIPHERTEXT_INDEX_EQUALITIES_HPP
#define LAMINATE_GKR_DETAIL_FOLDED_AFFINE_CIPHERTEXT_INDEX_EQUALITIES_HPP

/// @file ciphertext_index_equalities.hpp
/// @brief Incremental public equality weights for Folded ciphertext indices.

#include "laminate/field/fpk.hpp"
#include "laminate/poly/multilinear.hpp"

#include <cstddef>
#include <span>
#include <stdexcept>
#include <vector>

namespace laminate::gkr::folded_detail {

/// Evaluate `eq(point, index)` when `point` fixes only a prefix of the
/// ciphertext-index variables. The unfixed suffix remains Boolean.
inline Fpk ciphertext_index_equality_prefix(
    std::span<const Fpk> point, std::size_t index,
    std::size_t variables) {
    if (point.size() > variables) {
        throw std::invalid_argument(
            "LaminateFolded ciphertext-index equality prefix is too long");
    }
    Fpk result = Fpk::one();
    for (std::size_t variable = 0; variable < point.size(); ++variable) {
        const std::size_t shift = variables - 1U - variable;
        result *= ((index >> shift) & std::size_t{1}) != 0
                      ? point[variable]
                      : Fpk::one() - point[variable];
    }
    return result;
}

/// Host-work ledger for one rolling table of ciphertext-index equalities.
struct CiphertextIndexEqualityStatistics {
    std::size_t evaluation_products = 0;
    std::size_t fixed_lookups = 0;
    std::size_t bind_products = 0;

    bool operator==(const CiphertextIndexEqualityStatistics &) const = default;
};

/// Incremental values of `eq(prefix, i)` over the ciphertext-index domain.
///
/// A Folded ciphertext-index round needs the same public equality prefix
/// at X=1 and X=2. Binding this table once per challenge makes each lookup
/// O(1) and all updates O(Sv), instead of recomputing v factors per source in
/// each of v rounds. This is host-field bookkeeping; it invokes no FHE
/// backend operation and does not change the from-scratch encrypted round.
class PreparedCiphertextIndexEqualities {
  public:
    static PreparedCiphertextIndexEqualities create(std::size_t variables) {
        return PreparedCiphertextIndexEqualities(
            variables, poly::hypercube_size(variables));
    }

    Fpk evaluate(std::size_t ciphertext_index,
                 const Fpk &round_value) {
        validate_index(ciphertext_index);
        if (bound_variables_ >= variables_) {
            throw std::logic_error(
                "LaminateFolded ciphertext-index equality has no free variable");
        }
        ++statistics_.evaluation_products;
        const std::size_t shift = variables_ - 1U - bound_variables_;
        const Fpk branch =
            ((ciphertext_index >> shift) & std::size_t{1}) != 0
                               ? round_value
                               : Fpk::one() - round_value;
        return prefixes_[ciphertext_index] * branch;
    }

    Fpk fixed(std::size_t ciphertext_index) {
        validate_index(ciphertext_index);
        if (bound_variables_ != variables_) {
            throw std::logic_error(
                "LaminateFolded ciphertext-index equality is not fully bound");
        }
        ++statistics_.fixed_lookups;
        return prefixes_[ciphertext_index];
    }

    void bind(const Fpk &challenge) {
        if (bound_variables_ >= variables_) {
            throw std::logic_error(
                "LaminateFolded ciphertext-index equality is already terminal");
        }
        const std::size_t shift = variables_ - 1U - bound_variables_;
        for (std::size_t index = 0; index < prefixes_.size(); ++index) {
            prefixes_[index] *= ((index >> shift) & std::size_t{1}) != 0
                                    ? challenge
                                    : Fpk::one() - challenge;
            ++statistics_.bind_products;
        }
        ++bound_variables_;
    }

    std::size_t variables() const { return variables_; }
    std::size_t bound_variables() const { return bound_variables_; }
    std::size_t domain_size() const { return prefixes_.size(); }

    const CiphertextIndexEqualityStatistics &statistics() const {
        return statistics_;
    }

  private:
    PreparedCiphertextIndexEqualities(std::size_t variables,
                                      std::size_t domain_size)
        : variables_(variables), prefixes_(domain_size, Fpk::one()) {}

    void validate_index(std::size_t index) const {
        if (index >= prefixes_.size()) {
            throw std::invalid_argument(
                "LaminateFolded ciphertext index is out of range");
        }
    }

    std::size_t variables_ = 0;
    std::size_t bound_variables_ = 0;
    std::vector<Fpk> prefixes_;
    CiphertextIndexEqualityStatistics statistics_;
};

} // namespace laminate::gkr::folded_detail

#endif // LAMINATE_GKR_DETAIL_FOLDED_AFFINE_CIPHERTEXT_INDEX_EQUALITIES_HPP
