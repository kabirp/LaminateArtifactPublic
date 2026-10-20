#ifndef LAMINATE_BASEFOLD_FOLDABLE_QUERY_POLICY_HPP
#define LAMINATE_BASEFOLD_FOLDABLE_QUERY_POLICY_HPP

#include <cstddef>

namespace laminate::basefold::foldable {

/// Certified minimum for a power-of-two message size through 2^40; zero
/// for unsupported sizes. Conditional local RBR error is at most 2^-112.
/// The shared hierarchy failure remains a separate term below 2^-123.
std::size_t minimum_queries(std::size_t message_size) noexcept;

/// Accept an explicit count at least the certified minimum and at most
/// 65536. Zero is not an automatic-policy sentinel.
bool admitted_query_count(std::size_t message_size,
                          std::size_t queries) noexcept;

} // namespace laminate::basefold::foldable
#endif
