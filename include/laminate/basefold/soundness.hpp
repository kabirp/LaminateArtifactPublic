#ifndef LAMINATE_BASEFOLD_SOUNDNESS_HPP
#define LAMINATE_BASEFOLD_SOUNDNESS_HPP

#include <algorithm>
#include <bit>
#include <cstddef>

namespace laminate::basefold {

/// Integer lower bounds on -log2(error) for conditional IOP transitions.
/// Merkle binding, Fiat--Shamir, and the enclosing protocol are separate.
struct RbrSoundnessBound {
    std::size_t folding_bits = 0;
    std::size_t query_bits = 0;
    std::size_t batching_bits = 0;
    std::size_t rbr_bits = 0;
};

constexpr std::size_t ceil_log2_count(std::size_t count) {
    return count <= 1 ? 0 : std::bit_width(count - 1);
}

/// Conservative integer bound from the paper's unique-decoding analysis;
/// docs/BASEFOLD_SOUNDNESS.md maps the analysis to the implementation policy.
/// Query paths are sampled as one challenge block after fixing the oracles.
///
/// initial_batch_degree is the total degree of the initial batching block's
/// bad-event polynomial, assuming authenticated honest column commitments.
/// Use ceil(log2(width))+1 for gate equality/operand batching, and zero for a
/// fixed virtual oracle. Require |F| >=2^field_bits (119 for Fq2, 128 for Fpk).
/// The RBR error is a maximum over transitions, not a union over folds or
/// opening count. Unsupported rates/shapes return no positive guarantee.
constexpr RbrSoundnessBound conservative_rbr_soundness_bound(
    std::size_t message_log, std::size_t initial_batch_degree,
    std::size_t log_rate, std::size_t query_count, std::size_t field_bits) {
    if (log_rate != 3 || message_log > 34 || query_count == 0 ||
        field_bits <= 9) {
        return {};
    }
    const std::size_t degree_bits = ceil_log2_count(initial_batch_degree);
    const std::size_t batching_bits = field_bits > degree_bits
        ? field_bits - degree_bits : 0;
    const std::size_t folding_bits = field_bits - 9; // 511 < 2^9
    const std::size_t remainder = query_count % 4;
    const std::size_t query_bits = (query_count / 4) * 3 +
        (remainder > 1 ? remainder - 1 : 0);
    return {folding_bits, query_bits, batching_bits,
            std::min({folding_bits, query_bits, batching_bits})};
}

} // namespace laminate::basefold

#endif
