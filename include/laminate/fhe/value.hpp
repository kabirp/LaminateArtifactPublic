#ifndef LAMINATE_FHE_VALUE_HPP
#define LAMINATE_FHE_VALUE_HPP

/// @file value.hpp
/// @brief Canonical public-plaintext or encrypted payload values.

#include "laminate/fhe/backend.hpp"

#include <algorithm>
#include <cstddef>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <variant>

namespace laminate::fhe {

/// A publicly known SIMD plaintext in its smallest canonical host form.
///
/// Uniform values use one scalar. Only genuinely slot-varying values retain a
/// full vector. This distinction lets evaluators select scalar plaintext APIs
/// without scanning or allocating an N-entry vector in their inner loops.
class PublicPlaintext {
  public:
    static PublicPlaintext from_scalar(Fp value) {
        return PublicPlaintext(value);
    }

    static PublicPlaintext from_slots(SlotVector values) {
        if (values.empty()) {
            throw std::invalid_argument(
                "PublicPlaintext::from_slots: values must not be empty");
        }
        if (std::all_of(values.begin() + 1, values.end(),
                        [&](const Fp &value) {
                            return value == values.front();
                        })) {
            return from_scalar(values.front());
        }
        return PublicPlaintext(std::move(values));
    }

    bool is_scalar() const { return std::holds_alternative<Fp>(value_); }
    bool is_slots() const { return std::holds_alternative<SlotVector>(value_); }

    bool is_zero() const {
        return is_scalar() && std::get<Fp>(value_).is_zero();
    }

    bool is_one() const {
        return is_scalar() && std::get<Fp>(value_) == Fp::one();
    }

    const Fp &scalar() const {
        if (!is_scalar()) {
            throw std::logic_error(
                "PublicPlaintext::scalar: value is slot-varying");
        }
        return std::get<Fp>(value_);
    }

    const SlotVector &slots() const {
        if (!is_slots()) {
            throw std::logic_error(
                "PublicPlaintext::slots: value is uniform");
        }
        return std::get<SlotVector>(value_);
    }

    /// Validate a slot-varying value against an FHE context. Uniform values
    /// are independent of the physical SIMD width.
    void validate_slot_count(std::size_t expected,
                             std::string_view operation) const {
        if (is_slots() && slots().size() != expected) {
            throw std::invalid_argument(std::string(operation) +
                                        ": public plaintext has the wrong "
                                        "slot count");
        }
    }

    SlotVector materialize(std::size_t slot_count) const {
        validate_slot_count(slot_count, "PublicPlaintext::materialize");
        if (is_scalar()) {
            return SlotVector(slot_count, scalar());
        }
        return slots();
    }

    bool operator==(const PublicPlaintext &) const = default;

  private:
    explicit PublicPlaintext(Fp value) : value_(value) {}
    explicit PublicPlaintext(SlotVector values)
        : value_(std::move(values)) {}

    std::variant<Fp, SlotVector> value_;
};

/// One semantic base-field SIMD value used by payload evaluation and GKR.
///
/// Public values are plaintext data derived from the public circuit. Private
/// values are backed by a backend ciphertext even when their hidden plaintext
/// is zero. Cryptographic privacy depends on the chosen backend; MockBackend
/// retains plaintext slots. This type never uses a ciphertext as an anchor
/// for a public value.
template <FheBackend Backend> class FheValue {
  public:
    using Ciphertext = typename Backend::Ciphertext;

    FheValue() : value_(PublicPlaintext::from_scalar(Fp::zero())) {}

    static FheValue public_zero() {
        return public_scalar(Fp::zero());
    }

    static FheValue public_scalar(Fp value) {
        return FheValue(PublicPlaintext::from_scalar(value));
    }

    static FheValue public_slots(SlotVector values) {
        return FheValue(PublicPlaintext::from_slots(std::move(values)));
    }

    static FheValue public_plaintext(PublicPlaintext value) {
        return FheValue(std::move(value));
    }

    static FheValue from_ciphertext(Ciphertext ciphertext) {
        return FheValue(std::move(ciphertext));
    }

    bool is_public() const {
        return std::holds_alternative<PublicPlaintext>(value_);
    }

    bool is_encrypted() const {
        return std::holds_alternative<Ciphertext>(value_);
    }

    bool is_public_zero() const {
        return is_public() && plaintext().is_zero();
    }

    const PublicPlaintext &plaintext() const {
        if (!is_public()) {
            throw std::logic_error(
                "FheValue::plaintext: value is encrypted");
        }
        return std::get<PublicPlaintext>(value_);
    }

    const Ciphertext &ciphertext() const {
        if (!is_encrypted()) {
            throw std::logic_error(
                "FheValue::ciphertext: value is public");
        }
        return std::get<Ciphertext>(value_);
    }

    Ciphertext &ciphertext() {
        if (!is_encrypted()) {
            throw std::logic_error(
                "FheValue::ciphertext: value is public");
        }
        return std::get<Ciphertext>(value_);
    }

    Ciphertext take_ciphertext() && {
        if (!is_encrypted()) {
            throw std::logic_error(
                "FheValue::take_ciphertext: value is public");
        }
        return std::move(std::get<Ciphertext>(value_));
    }

  private:
    explicit FheValue(PublicPlaintext value) : value_(std::move(value)) {}
    explicit FheValue(Ciphertext ciphertext) : value_(std::move(ciphertext)) {}

    std::variant<PublicPlaintext, Ciphertext> value_;
};

namespace value_detail {

inline PublicPlaintext negate_public(const PublicPlaintext &value) {
    if (value.is_scalar()) {
        return PublicPlaintext::from_scalar(Fp::zero() - value.scalar());
    }
    SlotVector result = value.slots();
    for (Fp &slot : result) {
        slot = Fp::zero() - slot;
    }
    return PublicPlaintext::from_slots(std::move(result));
}

template <typename Operation>
PublicPlaintext binary_public(const PublicPlaintext &left,
                              const PublicPlaintext &right,
                              std::size_t slot_count,
                              Operation operation) {
    left.validate_slot_count(slot_count, "FheValue public arithmetic");
    right.validate_slot_count(slot_count, "FheValue public arithmetic");
    if (left.is_scalar() && right.is_scalar()) {
        return PublicPlaintext::from_scalar(
            operation(left.scalar(), right.scalar()));
    }

    SlotVector result(slot_count);
    for (std::size_t slot = 0; slot < slot_count; ++slot) {
        const Fp &left_value =
            left.is_scalar() ? left.scalar() : left.slots()[slot];
        const Fp &right_value =
            right.is_scalar() ? right.scalar() : right.slots()[slot];
        result[slot] = operation(left_value, right_value);
    }
    return PublicPlaintext::from_slots(std::move(result));
}

template <FheBackend Backend>
void validate_public(const typename Backend::EvalContext &eval,
                     const FheValue<Backend> &value,
                     const char *operation) {
    if (value.is_public()) {
        value.plaintext().validate_slot_count(Backend::slot_count(eval),
                                              operation);
    }
}

template <FheBackend Backend>
typename Backend::Ciphertext add_plaintext(
    const typename Backend::EvalContext &eval,
    const typename Backend::Ciphertext &ciphertext,
    const PublicPlaintext &plaintext) {
    if (plaintext.is_scalar()) {
        return Backend::add_plain_scalar(eval, ciphertext,
                                         plaintext.scalar());
    }
    return Backend::add_plain(eval, ciphertext, plaintext.slots());
}

template <FheBackend Backend>
typename Backend::Ciphertext multiply_plaintext(
    const typename Backend::EvalContext &eval,
    const typename Backend::Ciphertext &ciphertext,
    const PublicPlaintext &plaintext) {
    if (plaintext.is_scalar()) {
        return Backend::mul_plain_scalar(eval, ciphertext,
                                         plaintext.scalar());
    }
    return Backend::mul_plain(eval, ciphertext, plaintext.slots());
}

/// Recognize an exact ciphertext copy without asking the raw backend to
/// compute a transparent zero. Backends opt in only when they have a cheap,
/// sound identity test; the portable fallback recognizes same-object
/// subtraction in `value_sub` itself.
template <FheBackend Backend>
bool same_ciphertext(const typename Backend::EvalContext &eval,
                     const typename Backend::Ciphertext &left,
                     const typename Backend::Ciphertext &right) {
    if constexpr (requires {
                      {
                          Backend::same_ciphertext(eval, left, right)
                      } -> std::convertible_to<bool>;
                  }) {
        return Backend::same_ciphertext(eval, left, right);
    }
    return false;
}

} // namespace value_detail

template <FheBackend Backend>
FheValue<Backend>
value_negate(const typename Backend::EvalContext &eval,
             const FheValue<Backend> &value) {
    value_detail::validate_public<Backend>(eval, value, "value_negate");
    if (value.is_public()) {
        return FheValue<Backend>::public_plaintext(
            value_detail::negate_public(value.plaintext()));
    }
    return FheValue<Backend>::from_ciphertext(
        Backend::negate(eval, value.ciphertext()));
}

template <FheBackend Backend>
FheValue<Backend>
value_add(const typename Backend::EvalContext &eval,
          const FheValue<Backend> &left, const FheValue<Backend> &right) {
    value_detail::validate_public<Backend>(eval, left, "value_add");
    value_detail::validate_public<Backend>(eval, right, "value_add");
    if (left.is_public() && right.is_public()) {
        return FheValue<Backend>::public_plaintext(
            value_detail::binary_public(
                left.plaintext(), right.plaintext(),
                Backend::slot_count(eval),
                [](const Fp &a, const Fp &b) { return a + b; }));
    }
    if (left.is_public_zero()) {
        return right;
    }
    if (right.is_public_zero()) {
        return left;
    }
    if (left.is_public()) {
        return FheValue<Backend>::from_ciphertext(
            value_detail::add_plaintext<Backend>(
                eval, right.ciphertext(), left.plaintext()));
    }
    if (right.is_public()) {
        return FheValue<Backend>::from_ciphertext(
            value_detail::add_plaintext<Backend>(
                eval, left.ciphertext(), right.plaintext()));
    }
    typename Backend::Ciphertext result = left.ciphertext();
    if (auto public_result = add_assign_or_public<Backend>(
            eval, result, right.ciphertext())) {
        return FheValue<Backend>::public_slots(
            std::move(*public_result));
    }
    return FheValue<Backend>::from_ciphertext(std::move(result));
}

/// Add a value into an exclusively owned accumulator. In particular, adding
/// public zero is a true no-op: it performs neither backend arithmetic nor a
/// ciphertext copy.
template <FheBackend Backend>
void value_add_assign(const typename Backend::EvalContext &eval,
                      FheValue<Backend> &accumulator,
                      const FheValue<Backend> &term) {
    value_detail::validate_public<Backend>(eval, accumulator,
                                           "value_add_assign");
    value_detail::validate_public<Backend>(eval, term, "value_add_assign");
    if (term.is_public_zero()) {
        return;
    }
    if (accumulator.is_public() && term.is_public()) {
        accumulator = FheValue<Backend>::public_plaintext(
            value_detail::binary_public(
                accumulator.plaintext(), term.plaintext(),
                Backend::slot_count(eval),
                [](const Fp &a, const Fp &b) { return a + b; }));
        return;
    }
    if (accumulator.is_public_zero()) {
        accumulator = term;
        return;
    }
    if (accumulator.is_public()) {
        accumulator = FheValue<Backend>::from_ciphertext(
            value_detail::add_plaintext<Backend>(
                eval, term.ciphertext(), accumulator.plaintext()));
        return;
    }
    if (term.is_public()) {
        accumulator.ciphertext() =
            value_detail::add_plaintext<Backend>(
                eval, accumulator.ciphertext(), term.plaintext());
        return;
    }
    if (auto public_result = add_assign_or_public<Backend>(
            eval, accumulator.ciphertext(), term.ciphertext())) {
        accumulator = FheValue<Backend>::public_slots(
            std::move(*public_result));
    }
}

/// Add a temporary value into an exclusively owned accumulator. When the
/// accumulator is public zero, ownership of the first live term transfers
/// directly; a large ciphertext is not copied merely to initialize a sum.
template <FheBackend Backend>
void value_add_assign(const typename Backend::EvalContext &eval,
                      FheValue<Backend> &accumulator,
                      FheValue<Backend> &&term) {
    if (&accumulator == &term || !accumulator.is_public_zero()) {
        value_add_assign<Backend>(
            eval, accumulator,
            static_cast<const FheValue<Backend> &>(term));
        return;
    }

    value_detail::validate_public<Backend>(eval, accumulator,
                                           "value_add_assign");
    value_detail::validate_public<Backend>(eval, term,
                                           "value_add_assign");
    accumulator = std::move(term);
}

template <FheBackend Backend>
FheValue<Backend>
value_sub(const typename Backend::EvalContext &eval,
          const FheValue<Backend> &left, const FheValue<Backend> &right) {
    value_detail::validate_public<Backend>(eval, left, "value_sub");
    value_detail::validate_public<Backend>(eval, right, "value_sub");
    if (left.is_public() && right.is_public()) {
        return FheValue<Backend>::public_plaintext(
            value_detail::binary_public(
                left.plaintext(), right.plaintext(),
                Backend::slot_count(eval),
                [](const Fp &a, const Fp &b) { return a - b; }));
    }
    // The caller has supplied the same semantic object twice, so equality is
    // public structural information. Do not ask a concrete backend to create
    // a ciphertext representation of the known-zero difference.
    if (&left == &right) {
        return FheValue<Backend>::public_zero();
    }
    if (left.is_encrypted() && right.is_encrypted() &&
        value_detail::same_ciphertext<Backend>(
            eval, left.ciphertext(), right.ciphertext())) {
        return FheValue<Backend>::public_zero();
    }
    if (right.is_public_zero()) {
        return left;
    }
    if (left.is_public()) {
        auto result = Backend::negate(eval, right.ciphertext());
        if (!left.is_public_zero()) {
            result = value_detail::add_plaintext<Backend>(
                eval, result, left.plaintext());
        }
        return FheValue<Backend>::from_ciphertext(std::move(result));
    }
    if (right.is_public()) {
        return FheValue<Backend>::from_ciphertext(
            value_detail::add_plaintext<Backend>(
                eval, left.ciphertext(),
                value_detail::negate_public(right.plaintext())));
    }
    typename Backend::Ciphertext result = left.ciphertext();
    if (auto public_result = sub_assign_or_public<Backend>(
            eval, result, right.ciphertext())) {
        return FheValue<Backend>::public_slots(
            std::move(*public_result));
    }
    return FheValue<Backend>::from_ciphertext(std::move(result));
}

template <FheBackend Backend>
FheValue<Backend>
value_mul(const typename Backend::EvalContext &eval,
          const FheValue<Backend> &left, const FheValue<Backend> &right) {
    value_detail::validate_public<Backend>(eval, left, "value_mul");
    value_detail::validate_public<Backend>(eval, right, "value_mul");
    if (left.is_public() && right.is_public()) {
        return FheValue<Backend>::public_plaintext(
            value_detail::binary_public(
                left.plaintext(), right.plaintext(),
                Backend::slot_count(eval),
                [](const Fp &a, const Fp &b) { return a * b; }));
    }
    if (left.is_public_zero() || right.is_public_zero()) {
        return FheValue<Backend>::public_scalar(Fp::zero());
    }
    if (left.is_public()) {
        if (left.plaintext().is_one()) {
            return right;
        }
        return FheValue<Backend>::from_ciphertext(
            value_detail::multiply_plaintext<Backend>(
                eval, right.ciphertext(), left.plaintext()));
    }
    if (right.is_public()) {
        if (right.plaintext().is_one()) {
            return left;
        }
        return FheValue<Backend>::from_ciphertext(
            value_detail::multiply_plaintext<Backend>(
                eval, left.ciphertext(), right.plaintext()));
    }
    return FheValue<Backend>::from_ciphertext(
        Backend::mul(eval, left.ciphertext(), right.ciphertext()));
}

/// Multiply two semantic values without relinearizing a ciphertext/ciphertext
/// product. Public operands still use ordinary plaintext arithmetic, so this
/// is a no-op with respect to ciphertext size unless both operands are
/// encrypted.
template <FheBackend Backend>
FheValue<Backend>
value_mul_no_relin(const typename Backend::EvalContext &eval,
                   const FheValue<Backend> &left,
                   const FheValue<Backend> &right) {
    value_detail::validate_public<Backend>(eval, left,
                                           "value_mul_no_relin");
    value_detail::validate_public<Backend>(eval, right,
                                           "value_mul_no_relin");
    if (left.is_public() || right.is_public()) {
        return value_mul<Backend>(eval, left, right);
    }
    return FheValue<Backend>::from_ciphertext(
        Backend::mul_no_relin(eval, left.ciphertext(),
                              right.ciphertext()));
}

/// Relinearize an encrypted value. Public values require no work.
template <FheBackend Backend>
void value_relinearize(const typename Backend::EvalContext &eval,
                       FheValue<Backend> &value) {
    value_detail::validate_public<Backend>(eval, value,
                                           "value_relinearize");
    if (!value.is_encrypted()) {
        return;
    }
    Backend::relinearize(eval, value.ciphertext());
}

template <FheBackend Backend>
FheValue<Backend>
value_rotate(const typename Backend::EvalContext &eval,
             const FheValue<Backend> &value, std::size_t steps) {
    value_detail::validate_public<Backend>(eval, value, "value_rotate");
    const std::size_t slot_count = Backend::slot_count(eval);
    if (steps % slot_count == 0 ||
        (value.is_public() && value.plaintext().is_scalar())) {
        return value;
    }
    if (value.is_public()) {
        return FheValue<Backend>::public_slots(
            grid_rotate(value.plaintext().slots(), steps));
    }
    return FheValue<Backend>::from_ciphertext(
        Backend::rotate(eval, value.ciphertext(), steps));
}

template <FheBackend Backend>
FheValue<Backend>
value_fold(const typename Backend::EvalContext &eval,
           const FheValue<Backend> &value) {
    value_detail::validate_public<Backend>(eval, value, "value_fold");
    if (value.is_encrypted()) {
        if constexpr (requires(
                          typename Backend::Ciphertext &accumulator,
                          const typename Backend::Ciphertext &term) {
                          {
                              Backend::add_assign_or_public(
                                  eval, accumulator, term)
                          } -> std::same_as<std::optional<SlotVector>>;
                      }) {
            FheValue<Backend> result = value;
            for (std::size_t shift = 1;
                 shift < Backend::slot_count(eval); shift *= 2) {
                const FheValue<Backend> rotated = value_rotate<Backend>(
                    eval, result, shift);
                value_add_assign<Backend>(eval, result, rotated);
            }
            return result;
        }
        return FheValue<Backend>::from_ciphertext(
            Backend::fold(eval, value.ciphertext()));
    }

    Fp sum = Fp::zero();
    if (value.plaintext().is_scalar()) {
        sum = value.plaintext().scalar() *
              Fp(static_cast<std::uint64_t>(Backend::slot_count(eval)));
    } else {
        for (const Fp &slot : value.plaintext().slots()) {
            sum += slot;
        }
    }
    return FheValue<Backend>::public_scalar(sum);
}

template <FheBackend Backend>
void value_mod_switch_to_next(const typename Backend::EvalContext &eval,
                              FheValue<Backend> &value) {
    value_detail::validate_public<Backend>(eval, value,
                                           "value_mod_switch_to_next");
    if (value.is_encrypted()) {
        Backend::mod_switch_to_next(eval, value.ciphertext());
    }
}

template <FheBackend Backend>
void value_compact_for_transport(
    const typename Backend::EvalContext &eval, FheValue<Backend> &value,
    std::size_t reserved_mult_depth = 0) {
    value_detail::validate_public<Backend>(
        eval, value, "value_compact_for_transport");
    if (value.is_encrypted()) {
        compact_for_transport<Backend>(eval, value.ciphertext(),
                                       reserved_mult_depth);
    }
}

/// Recover SIMD slots without forcing a public value through encryption.
template <FheBackend Backend>
SlotVector materialize_or_decrypt(
    const typename Backend::ClientContext &client,
    const FheValue<Backend> &value) {
    if (value.is_public()) {
        return value.plaintext().materialize(Backend::slot_count(client));
    }
    return Backend::decrypt(client, value.ciphertext());
}

} // namespace laminate::fhe

#endif // LAMINATE_FHE_VALUE_HPP
