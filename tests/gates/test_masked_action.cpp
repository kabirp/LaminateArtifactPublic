#include "test_helpers.hpp"

#include "laminate/basefold/common.hpp"
#include "laminate/gates/masked_action.hpp"
#include "laminate/transcript/transcript.hpp"

#include <bit>
#include <filesystem>
#include <unistd.h>

using namespace laminate;

namespace {
Fpk extension(std::size_t seed) {
    Fpk::Coefficients c{};
    for (std::size_t i = 0; i < c.size(); ++i) c[i] = Fp(seed + 13 * i);
    return Fpk(c);
}
std::vector<Fpk> reverse(std::span<const Fpk> p) {
    return {p.rbegin(), p.rend()};
}
struct Scratch {
    std::filesystem::path path;
    Scratch() {
        auto pattern = (std::filesystem::temp_directory_path() /
                        "laminate-masked-test-XXXXXX").string();
        if (!::mkdtemp(pattern.data())) throw std::runtime_error("mkdtemp");
        path = pattern;
    }
    ~Scratch() { std::error_code e; std::filesystem::remove_all(path, e); }
};
} // namespace

int main() {
    test::Runner runner("test_masked_action");
    runner.run("masked local edges reduce to independently checked terminals", [] {
        for (std::size_t actual_masks : {std::size_t{1}, std::size_t{3}, std::size_t{4}}) {
            const std::size_t masks = std::bit_ceil(actual_masks);
            std::vector<std::vector<Fp>> p(actual_masks, std::vector<Fp>(8));
            std::vector<Fpk> w(masks);
            for (std::size_t a = 0; a < masks; ++a) {
                w[a] = extension(9 + a);
                if (a < actual_masks)
                    for (std::size_t s = 0; s < 8; ++s) p[a][s] = Fp(1 + 11 * a + s * s);
            }
            const std::vector<Fpk> r{extension(3), extension(7), extension(11)};
            const std::vector<Fpk> t{extension(17), extension(23), extension(29)};
            const auto er = basefold::equality_evaluations(reverse(r));
            const auto et = basefold::equality_evaluations(reverse(t));
            Fpk claim = Fpk::zero();
            for (std::size_t a = 0; a < actual_masks; ++a)
                for (std::size_t s = 0; s < 8; ++s)
                    claim += w[a] * p[a][s] * er[s] * et[s];
            Transcript prover("masked-test"), verifier("masked-test");
            const auto output = gates::prove_masked_action(w, p, r, t, claim, prover);
            auto explicitly_padded = p;
            explicitly_padded.resize(masks, std::vector<Fp>(8));
            Transcript padded_prover("masked-test");
            CHECK(gates::prove_masked_action(w, explicitly_padded, r, t, claim, padded_prover).proof == output.proof);
            const auto checked = gates::verify_masked_action(
                basefold::log2_exact(masks), r, t, claim, output.proof, verifier);
            CHECK(checked.has_value());
            CHECK(prover.challenge_fpk() == verifier.challenge_fpk());
            CHECK(checked->mask_weight == basefold::evaluate_multilinear(
                w, reverse(checked->mask_point_msb)));
            const auto ea = basefold::equality_evaluations(reverse(checked->mask_point_msb));
            const auto es = basefold::equality_evaluations(reverse(checked->slot_point_msb));
            Fpk expected = Fpk::zero();
            for (std::size_t a = 0; a < actual_masks; ++a)
                for (std::size_t s = 0; s < 8; ++s)
                    expected += ea[a] * es[s] * p[a][s];
            CHECK(checked->plaintext == expected);
            auto forged = output.proof;
            forged.slots.right += Fpk::one();
            Transcript bad("masked-test");
            CHECK(!gates::verify_masked_action(basefold::log2_exact(masks),
                                               r, t, claim, forged, bad));
            forged = output.proof;
            forged.masks.left += Fpk::one();
            Transcript bad_mask("masked-test");
            CHECK(!gates::verify_masked_action(basefold::log2_exact(masks),
                                               r, t, claim, forged, bad_mask));
        }
    });
    runner.run("diagonal equality is the Boolean product MLE", [] {
        const std::vector<Fpk> r{extension(3), Fpk::one()};
        const std::vector<Fpk> t{extension(5), Fpk::zero()};
        const std::vector<Fpk> s{extension(7), extension(11)};
        CHECK(gates::evaluate_diagonal_equality(r, t, s).is_zero());
        auto rr = r;
        rr.back() = extension(13);
        const auto a = basefold::equality_evaluations(reverse(rr));
        const auto b = basefold::equality_evaluations(reverse(t));
        std::vector<Fpk> product(4);
        for (std::size_t i = 0; i < 4; ++i) product[i] = a[i] * b[i];
        CHECK(gates::evaluate_diagonal_equality(rr, t, s) ==
              basefold::evaluate_multilinear(product, reverse(s)));
    });
    runner.run("external quadratic product matches resident transcript and retires files", [] {
        for (std::size_t size : {std::size_t{1}, std::size_t{32}}) {
            std::vector<Fpk> a(size), b(size);
            Fpk claim = Fpk::zero();
            for (std::size_t i = 0; i < size; ++i) {
                a[i] = extension(i + 3); b[i] = extension(3 * i + 7);
                claim += a[i] * b[i];
            }
            Transcript resident("product-test"), external("product-test");
            auto reference = gates::prove_quadratic_product(a, b, claim, resident);
            Scratch scratch;
            basefold::foldable::Options options;
            options.block_elements = 6; // Non-power-of-two block boundary.
            const auto proof = gates::prove_quadratic_product(
                basefold::foldable::source(a), basefold::foldable::source(b),
                claim, external, scratch.path, options);
            CHECK(proof.proof == reference.proof);
            CHECK(resident.challenge_fpk() == external.challenge_fpk());
            CHECK(std::filesystem::is_empty(scratch.path));
        }
    });
    return runner.summary();
}
