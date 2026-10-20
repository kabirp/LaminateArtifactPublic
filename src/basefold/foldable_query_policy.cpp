#include "laminate/basefold/foldable_query_policy.hpp"
#include "laminate/basefold/foldable.hpp"
#include "laminate/params.hpp"

#include <array>
#include <bit>
#include <cstdint>
#include <limits>

namespace laminate::basefold::foldable {
namespace {
// Generated and checked using exact integer powers by
// tests/basefold/check_foldable_query_certificate.py. See the weighted
// K=65536 argument in docs/WIDE_GATE_SOUNDNESS.md.
constexpr std::array<std::size_t, 41> kMinimumQueries = {
    226, 226, 226, 226, 226, 226, 226, 226, 226, 226,
    226, 226, 226, 226, 228, 229, 231, 233, 235, 237,
    239, 242, 244, 246, 248, 251, 253, 256, 258, 261,
    264, 266, 269, 272, 275, 278, 281, 284, 288, 291,
    295
};
static_assert(kLogRate == 3 && kRsBaseVariables == 13 && kMaxVariables == 40);
static_assert(kHierarchyVersion == 1 && kLocalRbrSecurityBits == 112);
static_assert(kHierarchyFailureSecurityBits == 123);
static_assert(kBaseFieldOrder == 65537 && kExtensionDegree == 8);
static_assert(std::numeric_limits<std::size_t>::digits > kMaxVariables);
} // namespace

std::size_t minimum_queries(std::size_t message_size) noexcept {
    if (!std::has_single_bit(message_size) ||
        message_size > (std::size_t{1} << kMaxVariables)) {
        return 0;
    }
    return kMinimumQueries[std::countr_zero(message_size)];
}

bool admitted_query_count(std::size_t message_size,
                          std::size_t queries) noexcept {
    const auto minimum = minimum_queries(message_size);
    return minimum != 0 && queries >= minimum && queries <= 65536;
}

} // namespace laminate::basefold::foldable
