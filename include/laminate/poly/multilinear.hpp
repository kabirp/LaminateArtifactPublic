#ifndef LAMINATE_POLY_MULTILINEAR_HPP
#define LAMINATE_POLY_MULTILINEAR_HPP

/// @file multilinear.hpp
/// @brief Small plaintext multilinear tables used by the GKR oracle.
///
/// Evaluations are stored in Boolean-hypercube order with x_0 as the most
/// significant bit. Consequently, binding x_0 pairs the front and back halves
/// of the table. Payload tables may start in Fp, while proof challenges live
/// in Fpk; the first bind promotes values to Fpk without changing this order.

#include "laminate/concepts.hpp"
#include "laminate/field/fp.hpp"
#include "laminate/field/fpk.hpp"

#include <algorithm>
#include <cstddef>
#include <limits>
#include <stdexcept>
#include <type_traits>
#include <utility>
#include <vector>

namespace laminate::poly {

inline std::size_t hypercube_size(std::size_t num_vars) {
    if (num_vars >=
        static_cast<std::size_t>(std::numeric_limits<std::size_t>::digits)) {
        throw std::invalid_argument(
            "hypercube_size: number of variables overflows size_t");
    }
    return std::size_t{1} << num_vars;
}

namespace detail {

template <typename Value, typename Challenge> struct FieldPromotion;

template <Field Value> struct FieldPromotion<Value, Value> {
    using type = Value;
    static Value lift(const Value &value) { return value; }
};

template <> struct FieldPromotion<Fp, Fpk> {
    using type = Fpk;
    static Fpk lift(const Fp &value) { return Fpk::from_base(value); }
};

template <typename Value, typename Challenge>
concept PromotableFields = requires(const Value &value) {
    typename FieldPromotion<Value, Challenge>::type;
    {
        FieldPromotion<Value, Challenge>::lift(value)
    } -> std::same_as<typename FieldPromotion<Value, Challenge>::type>;
};

template <typename Value, typename Challenge>
using promoted_field_t = typename FieldPromotion<Value, Challenge>::type;

} // namespace detail

template <Field Value> class Multilinear {
  public:
    Multilinear(std::size_t num_vars, std::vector<Value> evaluations)
        : num_vars_(num_vars), evaluations_(std::move(evaluations)) {
        if (evaluations_.size() != hypercube_size(num_vars_)) {
            throw std::invalid_argument(
                "Multilinear: evaluations size must equal 2^num_vars");
        }
    }

    std::size_t num_vars() const { return num_vars_; }
    const std::vector<Value> &evaluations() const { return evaluations_; }

    const Value &on_hypercube(std::size_t index) const {
        if (index >= evaluations_.size()) {
            throw std::out_of_range(
                "Multilinear::on_hypercube: index is out of range");
        }
        return evaluations_[index];
    }

    template <Field Challenge>
        requires detail::PromotableFields<Value, Challenge>
    auto fix_first_variable(const Challenge &challenge) const
        -> Multilinear<detail::promoted_field_t<Value, Challenge>> {
        if (num_vars_ == 0) {
            throw std::logic_error(
                "Multilinear::fix_first_variable: no variables remain");
        }

        using Promotion = detail::FieldPromotion<Value, Challenge>;
        using Result = typename Promotion::type;
        const std::size_t half = evaluations_.size() / 2;
        std::vector<Result> result;
        result.reserve(half);
        for (std::size_t index = 0; index < half; ++index) {
            const Result low = Promotion::lift(evaluations_[index]);
            const Result high = Promotion::lift(evaluations_[half + index]);
            result.push_back(low + challenge * (high - low));
        }
        return Multilinear<Result>(num_vars_ - 1, std::move(result));
    }

    template <Field Challenge>
        requires detail::PromotableFields<Value, Challenge>
    auto fix_first_variables(const std::vector<Challenge> &challenges) const
        -> Multilinear<detail::promoted_field_t<Value, Challenge>> {
        if (challenges.size() > num_vars_) {
            throw std::invalid_argument(
                "Multilinear::fix_first_variables: prefix is too long");
        }

        using Promotion = detail::FieldPromotion<Value, Challenge>;
        using Result = typename Promotion::type;
        if (challenges.empty()) {
            std::vector<Result> lifted;
            lifted.reserve(evaluations_.size());
            for (const Value &value : evaluations_) {
                lifted.push_back(Promotion::lift(value));
            }
            return Multilinear<Result>(num_vars_, std::move(lifted));
        }

        Multilinear<Result> current =
            fix_first_variable(challenges.front());
        for (std::size_t index = 1; index < challenges.size(); ++index) {
            current = current.fix_first_variable(challenges[index]);
        }
        return current;
    }

    template <Field Challenge>
        requires detail::PromotableFields<Value, Challenge>
    auto evaluate(const std::vector<Challenge> &point) const
        -> detail::promoted_field_t<Value, Challenge> {
        if (point.size() != num_vars_) {
            throw std::invalid_argument(
                "Multilinear::evaluate: point size must equal num_vars");
        }
        if (point.empty()) {
            return detail::FieldPromotion<Value, Challenge>::lift(
                evaluations_.front());
        }
        return fix_first_variables(point).evaluations().front();
    }

  private:
    std::size_t num_vars_;
    std::vector<Value> evaluations_;
};

template <Field Value> struct SparseEntry {
    std::size_t index = 0;
    Value value = Value::zero();

    bool operator==(const SparseEntry &) const = default;
};

/// Sparse Boolean-hypercube evaluation table. Entries are sorted once at the
/// boundary, and duplicate indices or explicit zero entries are rejected so
/// the representation stays canonical.
template <Field Value> class SparseMultilinear {
  public:
    SparseMultilinear(std::size_t num_vars,
                      std::vector<SparseEntry<Value>> entries)
        : num_vars_(num_vars), entries_(std::move(entries)) {
        const std::size_t size = hypercube_size(num_vars_);
        std::sort(entries_.begin(), entries_.end(),
                  [](const auto &left, const auto &right) {
                      return left.index < right.index;
                  });
        for (std::size_t index = 0; index < entries_.size(); ++index) {
            if (entries_[index].index >= size) {
                throw std::invalid_argument(
                    "SparseMultilinear: entry index is out of range");
            }
            if (entries_[index].value.is_zero()) {
                throw std::invalid_argument(
                    "SparseMultilinear: explicit zero entries are forbidden");
            }
            if (index != 0 &&
                entries_[index - 1].index == entries_[index].index) {
                throw std::invalid_argument(
                    "SparseMultilinear: duplicate entry index");
            }
        }
    }

    std::size_t num_vars() const { return num_vars_; }
    const std::vector<SparseEntry<Value>> &entries() const { return entries_; }

    Value on_hypercube(std::size_t index) const {
        if (index >= hypercube_size(num_vars_)) {
            throw std::out_of_range(
                "SparseMultilinear::on_hypercube: index is out of range");
        }
        const auto position = std::lower_bound(
            entries_.begin(), entries_.end(), index,
            [](const SparseEntry<Value> &entry, std::size_t wanted) {
                return entry.index < wanted;
            });
        return position != entries_.end() && position->index == index
                   ? position->value
                   : Value::zero();
    }

    Multilinear<Value> dense() const {
        std::vector<Value> evaluations(hypercube_size(num_vars_),
                                       Value::zero());
        for (const auto &entry : entries_) {
            evaluations[entry.index] = entry.value;
        }
        return Multilinear<Value>(num_vars_, std::move(evaluations));
    }

    template <Field Challenge>
        requires detail::PromotableFields<Value, Challenge>
    auto evaluate(const std::vector<Challenge> &point) const
        -> detail::promoted_field_t<Value, Challenge> {
        if (point.size() != num_vars_) {
            throw std::invalid_argument(
                "SparseMultilinear::evaluate: point size must equal num_vars");
        }
        using Promotion = detail::FieldPromotion<Value, Challenge>;
        using Result = typename Promotion::type;
        Result result = Result::zero();
        for (const auto &entry : entries_) {
            Result weight = Result::one();
            for (std::size_t variable = 0; variable < num_vars_; ++variable) {
                const bool bit =
                    ((entry.index >> (num_vars_ - 1 - variable)) & 1U) != 0;
                weight *= bit ? point[variable]
                              : Challenge::one() - point[variable];
            }
            result += Promotion::lift(entry.value) * weight;
        }
        return result;
    }

  private:
    std::size_t num_vars_;
    std::vector<SparseEntry<Value>> entries_;
};

} // namespace laminate::poly

#endif // LAMINATE_POLY_MULTILINEAR_HPP
