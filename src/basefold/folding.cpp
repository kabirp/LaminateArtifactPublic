#include "laminate/basefold/folding.hpp"

#include "laminate/basefold/common.hpp"

#include <stdexcept>
#include <string_view>
#include <utility>

namespace laminate::basefold {
namespace {

constexpr std::string_view kFoldedOracleLabel = "basefold/oracle";
constexpr std::string_view kFinalCodewordLabel = "basefold/final";

std::vector<std::vector<std::uint8_t>>
make_fpk_leaves(std::span<const Fpk> values) {
    std::vector<std::vector<std::uint8_t>> leaves(values.size());
    for (std::size_t index = 0; index < values.size(); ++index) {
        leaves[index] = serialize_values(values.subspan(index, 1));
    }
    return leaves;
}

Fp initial_generator(std::span<const Fpk> codeword) {
    if (codeword.empty()) {
        throw std::invalid_argument(
            "basefold::FoldingProver: codeword must not be empty");
    }
    return Fp::two_adic_generator(log2_exact(codeword.size()));
}

} // namespace

Fpk fold_codeword_pair(const Fpk &lo, const Fpk &hi,
                       const Fpk &challenge,
                       const Fp &inverse_generator_power,
                       const Fp &inverse_two) {
    return (lo + hi + challenge * ((lo - hi) * inverse_generator_power)) *
           inverse_two;
}

std::vector<Fpk> fold_codeword(std::span<const Fpk> codeword,
                               const Fpk &challenge,
                               const Fp &generator) {
    if (codeword.size() < 2 || (codeword.size() & 1U) != 0) {
        throw std::invalid_argument(
            "basefold::fold_codeword: codeword length must be even");
    }
    const std::size_t half = codeword.size() / 2;
    const Fp inverse_generator = generator.inverse();
    const Fp inverse_two = Fp(2).inverse();
    Fp inverse_generator_power = Fp::one();
    std::vector<Fpk> result(half);
    for (std::size_t index = 0; index < half; ++index) {
        result[index] = fold_codeword_pair(
            codeword[index], codeword[index + half], challenge,
            inverse_generator_power, inverse_two);
        inverse_generator_power *= inverse_generator;
    }
    return result;
}

void observe_folded_root(const Digest &root, PublicCoin &public_coin) {
    public_coin.observe(kFoldedOracleLabel, root);
}

void observe_final_codeword(std::span<const Fpk> codeword,
                            PublicCoin &public_coin) {
    public_coin.observe(kFinalCodewordLabel, serialize_values(codeword));
}

FoldingProver::FoldingProver(std::vector<Fpk> combined_codeword)
    : layers_{std::move(combined_codeword)},
      generator_(initial_generator(layers_.front())) {}

void FoldingProver::fold_round(const Fpk &challenge, bool commit_result,
                               FoldingProof &proof,
                               PublicCoin &public_coin) {
    std::vector<Fpk> folded =
        fold_codeword(layers_.back(), challenge, generator_);
    generator_ *= generator_;
    if (commit_result) {
        trees_.emplace_back(make_fpk_leaves(folded));
        proof.roots.push_back(trees_.back().root());
        observe_folded_root(proof.roots.back(), public_coin);
    }
    layers_.push_back(std::move(folded));
}

void FoldingProver::finish(FoldingProof &proof,
                           PublicCoin &public_coin) const {
    proof.final_codeword = layers_.back();
    observe_final_codeword(proof.final_codeword, public_coin);
}

bool terminal_codeword_is_constant(const FoldingProof &proof) {
    if (proof.final_codeword.empty()) {
        return false;
    }
    for (const Fpk &value : proof.final_codeword) {
        if (!(value == proof.final_codeword.front())) {
            return false;
        }
    }
    return true;
}

} // namespace laminate::basefold
