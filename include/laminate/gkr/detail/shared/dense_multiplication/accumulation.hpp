#ifndef LAMINATE_GKR_DETAIL_SHARED_DENSE_MULTIPLICATION_ACCUMULATION_HPP
#define LAMINATE_GKR_DETAIL_SHARED_DENSE_MULTIPLICATION_ACCUMULATION_HPP

/// @file accumulation.hpp
/// @brief Shared encrypted accumulation algebra for dense multiplication.

#include "laminate/fhe/extension.hpp"

#include <stdexcept>
#include <utility>

namespace laminate::gkr::detail {
namespace dense_multiplication_accumulation_detail {

/// Accumulate base-field source values against extension-field scalars without
/// promoting structural public zero into an encrypted value.
template <fhe::FheBackend Backend> class WeightedBaseAccumulator {
  public:
    void add(const typename Backend::EvalContext &eval,
             const fhe::FheValue<Backend> &source,
             const Fpk &weight) {
        if (source.is_public_zero() || weight.is_zero()) {
            return;
        }
        value_.accumulate_scaled_base(eval, source, weight);
    }

    void add(const typename Backend::EvalContext &eval,
             const typename Backend::Ciphertext &source,
             const Fpk &weight) {
        value_.accumulate_scaled_base(eval, source, weight);
    }

    /// Retain the fact that this term has only base-field support. This is
    /// observable to symbolic noise backends even though it is algebraically
    /// equivalent to `add` for concrete backends.
    void add_public_support(
        const typename Backend::EvalContext &eval,
        const fhe::FheValue<Backend> &source, const Fpk &weight) {
        if (source.is_public_zero() || weight.is_zero()) {
            return;
        }
        value_.accumulate_scaled_base_with_public_support(
            eval, source, weight);
    }

    fhe::ExtensionValue<Backend> finish(
        const typename Backend::EvalContext &eval) && {
        return std::move(value_).finish(eval);
    }

  private:
    fhe::MixedExtensionAccumulator<Backend> value_;
};

/// Select the low, high, or X=2 extrapolated branch of one multilinear
/// base-field source pair. The caller supplies its protocol-specific diagnostic.
template <fhe::FheBackend Backend>
fhe::FheValue<Backend> select_base_pair_branch(
    const typename Backend::EvalContext &eval,
    const fhe::FheValue<Backend> &low,
    const fhe::FheValue<Backend> &high, const Fpk &round_value,
    const char *invalid_round_value_message) {
    if (round_value == Fpk::zero()) {
        return low;
    }
    if (round_value == Fpk::one()) {
        return high;
    }
    if (round_value == Fpk::from_base(Fp(2))) {
        const auto doubled = fhe::value_add<Backend>(eval, high, high);
        return fhe::value_sub<Backend>(eval, doubled, low);
    }
    throw std::invalid_argument(invalid_round_value_message);
}

enum class BaseProductSupport {
    GeneralExtension,
    PublicBase,
};

/// Multiply one dense pair without relinearization, scale it by the public
/// suffix weight, and add it to the sparse extension accumulator. Returns
/// whether a nonzero product was accumulated so callers can maintain exact
/// operation ledgers without duplicating the arithmetic.
template <fhe::FheBackend Backend>
bool accumulate_base_product(
    const typename Backend::EvalContext &eval,
    fhe::MixedExtensionAccumulator<Backend> &accumulator,
    const fhe::FheValue<Backend> &left,
    const fhe::FheValue<Backend> &right, const Fpk &suffix_weight,
    BaseProductSupport support = BaseProductSupport::GeneralExtension) {
    if (left.is_public_zero() || right.is_public_zero() ||
        suffix_weight.is_zero()) {
        return false;
    }
    fhe::FheValue<Backend> product;
    if (left.is_encrypted() && right.is_encrypted()) {
        product = fhe::FheValue<Backend>::from_ciphertext(
            Backend::mul_no_relin(eval, left.ciphertext(),
                                  right.ciphertext()));
    } else {
        product = fhe::value_mul<Backend>(eval, left, right);
    }
    if (product.is_public_zero()) {
        return false;
    }
    if (support == BaseProductSupport::PublicBase) {
        accumulator.accumulate_scaled_base_with_public_support(
            eval, product, suffix_weight);
    } else {
        accumulator.accumulate_scaled_base(eval, product, suffix_weight);
    }
    return true;
}

/// Multiply two extension-valued dense operands without relinearization,
/// scale by the public suffix weight, and add the result to the output.
/// Returns whether a nonzero product was accumulated.
template <fhe::FheBackend Backend>
bool accumulate_extension_product(
    const typename Backend::EvalContext &eval,
    fhe::ExtensionValue<Backend> &accumulator,
    const fhe::ExtensionValue<Backend> &left,
    const fhe::ExtensionValue<Backend> &right,
    const Fpk &suffix_weight) {
    if (left.is_public_zero() || right.is_public_zero() ||
        suffix_weight.is_zero()) {
        return false;
    }
    auto product = fhe::mixed_extension_mul_no_relin<Backend>(
        eval, left, right);
    auto term = fhe::scale_extension_value<Backend>(
        eval, product, suffix_weight);
    fhe::extension_add_assign<Backend>(eval, accumulator,
                                       std::move(term));
    return true;
}

template <fhe::FheBackend Backend>
fhe::ExtensionValue<Backend> finish_product_sum(
    const typename Backend::EvalContext &eval,
    fhe::MixedExtensionAccumulator<Backend> accumulator) {
    auto result = std::move(accumulator).finish(eval);
    fhe::relinearize_extension_value<Backend>(eval, result);
    return result;
}

template <fhe::FheBackend Backend>
fhe::ExtensionValue<Backend> finish_product_sum(
    const typename Backend::EvalContext &eval,
    fhe::ExtensionValue<Backend> accumulator) {
    fhe::relinearize_extension_value<Backend>(eval, accumulator);
    return accumulator;
}

} // namespace dense_multiplication_accumulation_detail
} // namespace laminate::gkr::detail

#endif // LAMINATE_GKR_DETAIL_SHARED_DENSE_MULTIPLICATION_ACCUMULATION_HPP
