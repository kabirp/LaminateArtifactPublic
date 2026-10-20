#include "laminate/gates/quadratic_product.hpp"

#include "laminate/basefold/common.hpp"
#include "laminate/field/serialization.hpp"

#include <stdexcept>
#include <algorithm>
#include <limits>
#include <string>

namespace laminate::gates {
namespace {

void observe_begin(std::size_t variables, const Fpk &claim,
                   PublicCoin &coin) {
    coin.observe("wide-gates/quadratic-product/v1", variables);
    const std::array<Fpk, 1> values{claim};
    coin.observe("wide-gates/quadratic-product/claim",
                 basefold::serialize_values(values));
}

void observe_terminal(const QuadraticProductProof &proof, PublicCoin &coin) {
    const std::array<Fpk, 2> values{proof.left, proof.right};
    coin.observe("wide-gates/quadratic-product/terminal",
                 basefold::serialize_values(values));
}

} // namespace

QuadraticProductOutput prove_quadratic_product(
    std::vector<Fpk> left, std::vector<Fpk> right, const Fpk &claim,
    PublicCoin &coin) {
    if (left.empty() || left.size() != right.size() ||
        (left.size() & (left.size() - 1)) != 0) {
        throw std::invalid_argument("quadratic product: invalid table sizes");
    }
    Fpk actual = Fpk::zero();
    for (std::size_t i = 0; i < left.size(); ++i) {
        actual += left[i] * right[i];
    }
    if (actual != claim) {
        throw std::invalid_argument("quadratic product: incorrect claim");
    }
    const std::size_t variables = basefold::log2_exact(left.size());
    observe_begin(variables, claim, coin);
    basefold::SumcheckProver prover(left, right);
    basefold::SumcheckProof sumcheck;
    for (std::size_t round = 0; round < variables; ++round) {
        prover.prove_round(sumcheck, coin);
    }
    QuadraticProductProof proof{
        std::move(sumcheck.rounds),
        basefold::evaluate_multilinear(left, prover.point()),
        basefold::evaluate_multilinear(right, prover.point())};
    observe_terminal(proof, coin);
    QuadraticProductReduction reduction{
        prover.point(), proof.left, proof.right};
    return {std::move(proof), std::move(reduction)};
}

QuadraticProductOutput prove_quadratic_product(
    basefold::foldable::ValueSource left,
    basefold::foldable::ValueSource right, const Fpk &claim,
    PublicCoin &coin, const std::filesystem::path &scratch,
    const basefold::foldable::Options &options) {
    using basefold::foldable::ScalarArray;
    using basefold::foldable::source;
    if (left.size == 0 || left.size != right.size ||
        (left.size & (left.size - 1)) != 0 || !left.read || !right.read ||
        options.block_elements < 2 || (options.block_elements & 1) != 0 ||
        !std::filesystem::is_directory(scratch) ||
        !std::filesystem::is_empty(scratch)) {
        throw std::invalid_argument("external quadratic product: invalid inputs");
    }
    // Input and output fold arrays coexist for one streaming pass. Six field
    // elements per original position conservatively cover that peak, even
    // without relying on the caller's borrowed-source storage.
    constexpr std::uint64_t bytes_per_entry = 6 * kSerializedFpkBytes;
    if (left.size > std::numeric_limits<std::uint64_t>::max() /
                        bytes_per_entry) {
        throw std::overflow_error("external quadratic product: disk bound");
    }
    const auto reserved = left.size * bytes_per_entry;
    const auto available = std::filesystem::space(scratch).available;
    if (reserved > options.max_disk_bytes ||
        options.min_free_bytes > available ||
        reserved > available - options.min_free_bytes) {
        throw std::runtime_error("external quadratic product: insufficient disk budget");
    }
    const auto variables = basefold::log2_exact(left.size);
    const auto block = std::min(options.block_elements, left.size);
    std::vector<Fpk> left_buffer(block), right_buffer(block);
    Fpk actual = Fpk::zero();
    for (std::size_t offset = 0; offset < left.size; offset += block) {
        const auto count = std::min(block, left.size - offset);
        const auto a = std::span(left_buffer).first(count);
        const auto b = std::span(right_buffer).first(count);
        left.read(offset, a);
        right.read(offset, b);
        for (std::size_t j = 0; j < count; ++j) {
            actual += a[j] * b[j];
        }
    }
    if (actual != claim) {
        throw std::invalid_argument("external quadratic product: incorrect claim");
    }
    observe_begin(variables, claim, coin);
    QuadraticProductProof proof;
    std::vector<Fpk> point;
    std::vector<Fpk> folded_left(block / 2), folded_right(block / 2);
    for (std::size_t round = 0; round < variables; ++round) {
        std::array<Fpk, 3> message{};
        for (std::size_t offset = 0; offset < left.size; offset += block) {
            const auto count = std::min(block, left.size - offset);
            const auto a = std::span(left_buffer).first(count);
            const auto b = std::span(right_buffer).first(count);
            left.read(offset, a);
            right.read(offset, b);
            for (std::size_t j = 0; j < count; j += 2) {
                message[0] += a[j] * b[j];
                message[1] += a[j + 1] * b[j + 1];
                message[2] += (a[j + 1] + a[j + 1] - a[j]) *
                              (b[j + 1] + b[j + 1] - b[j]);
            }
        }
        proof.rounds.push_back(message);
        // Match the resident helper's canonical BaseFold sumcheck message.
        coin.observe("basefold/round", basefold::serialize_values(message));
        const auto challenge = coin.challenge_fpk();
        point.push_back(challenge);
        auto next_left = ScalarArray::create(
            scratch / ("left-" + std::to_string(round)), left.size / 2);
        auto next_right = ScalarArray::create(
            scratch / ("right-" + std::to_string(round)), right.size / 2);
        for (std::size_t offset = 0; offset < left.size; offset += block) {
            const auto count = std::min(block, left.size - offset);
            const auto a = std::span(left_buffer).first(count);
            const auto b = std::span(right_buffer).first(count);
            left.read(offset, a);
            right.read(offset, b);
            for (std::size_t j = 0; j < count / 2; ++j) {
                folded_left[j] = a[2 * j] + challenge * (a[2 * j + 1] - a[2 * j]);
                folded_right[j] = b[2 * j] + challenge * (b[2 * j + 1] - b[2 * j]);
            }
            next_left.write_block(offset / 2,
                                  std::span(folded_left).first(count / 2));
            next_right.write_block(offset / 2,
                                   std::span(folded_right).first(count / 2));
        }
        left = source(next_left);
        right = source(next_right);
    }
    left.read(0, std::span(&proof.left, 1));
    right.read(0, std::span(&proof.right, 1));
    observe_terminal(proof, coin);
    QuadraticProductReduction reduction{
        std::move(point), proof.left, proof.right};
    return {std::move(proof), std::move(reduction)};
}

std::optional<QuadraticProductReduction> verify_quadratic_product(
    std::size_t variables, const Fpk &claim,
    const QuadraticProductProof &proof, PublicCoin &coin) {
    if (proof.rounds.size() != variables) {
        return std::nullopt;
    }
    observe_begin(variables, claim, coin);
    basefold::SumcheckVerifier verifier(claim);
    for (const auto &round : proof.rounds) {
        if (!verifier.verify_round(round, coin)) {
            return std::nullopt;
        }
    }
    const std::array<Fpk, 1> weight{Fpk::one()};
    const std::array<Fpk, 1> operand{proof.right};
    if (!verifier.verify_terminal(proof.left, weight, operand)) {
        return std::nullopt;
    }
    observe_terminal(proof, coin);
    return QuadraticProductReduction{
        verifier.point(), proof.left, proof.right};
}

} // namespace laminate::gates
