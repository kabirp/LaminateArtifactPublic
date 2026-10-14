#ifndef LAMINATE_CONCEPTS_HPP
#define LAMINATE_CONCEPTS_HPP

/// @file concepts.hpp
/// @brief Small algebraic concepts used by protocol templates.

#include <concepts>

namespace laminate {

template <typename T>
concept RingElement = std::copyable<T> && requires(T a, const T b) {
    { T::zero() } -> std::same_as<T>;
    { T::one() } -> std::same_as<T>;
    { a + b } -> std::same_as<T>;
    { a - b } -> std::same_as<T>;
    { a * b } -> std::same_as<T>;
    { a += b } -> std::same_as<T &>;
    { a -= b } -> std::same_as<T &>;
    { a *= b } -> std::same_as<T &>;
    { a == b } -> std::convertible_to<bool>;
};

template <typename T>
concept Field = RingElement<T> && requires(const T a) {
    { a.inverse() } -> std::same_as<T>;
    { a.is_zero() } -> std::convertible_to<bool>;
};

} // namespace laminate

#endif // LAMINATE_CONCEPTS_HPP
