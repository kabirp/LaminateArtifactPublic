/// @file test_packed_dense_multiplication_verifier.cpp
/// @brief Parity tests for the shared Folded/Laned dense verifier.

#include "test_helpers.hpp"

#include "laminate/fhe/mock_backend.hpp"
#include "laminate/gkr/folded.hpp"
#include "laminate/gkr/laned.hpp"
#include "laminate/gkr/detail/folded/multiplication/verifier.hpp"
#include "laminate/gkr/detail/laned/multiplication/verifier.hpp"
#include "laminate/poly/multilinear.hpp"

#include <array>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <stdexcept>
#include <string_view>
#include <vector>

using namespace laminate;
using namespace laminate::fhe;
using namespace laminate::gkr;

namespace {

struct FixedReader {
    std::vector<std::array<Fpk, 2>> decoded;
    std::size_t next = 0;

    template <typename Message>
    std::vector<Fpk> read(const Message &, std::size_t expected) {
        if (expected != 2U || next >= decoded.size()) {
            throw std::logic_error("fixed packed reader shape mismatch");
        }
        const auto values = decoded[next++];
        return {values[0], values[1]};
    }
};

template <ProtocolVariant Variant> struct FixedGeometry {
    std::size_t rounds = 0;
    bool accepts = true;

    std::size_t round_count() const { return rounds; }
    std::size_t ciphertext_index_round_count() const { return rounds; }
    std::size_t slot_index_round_count() const { return 0; }

    template <typename Message>
    bool admits(
        const SingleClaim &claim,
        const gkr::detail::PackedMultiplicationReduction<
            Message, Variant> &proof) const {
        return accepts && claim.point.size() == rounds &&
               proof.rounds.size() == rounds;
    }
};

using FoldedCommittedProof =
    FoldedMultiplicationLayerReduction<CommittedPackedMessage>;
using LanedCommittedProof =
    LanedMultiplicationLayerReduction<CommittedPackedMessage>;

static_assert(gkr::detail::PackedDenseMultiplicationVerificationGeometry<
              folded_detail::FoldedMultiplicationVerificationGeometry,
              FoldedCommittedProof>);
static_assert(gkr::detail::PackedDenseMultiplicationVerificationGeometry<
              laned_detail::LanedMultiplicationVerificationGeometry,
              LanedCommittedProof>);

Fpk value(std::uint64_t input) {
    return Fpk::from_base(Fp(input));
}

CommittedPackedMessage public_message(std::uint64_t input) {
    return CommittedPackedMessage::public_message(
        PublicPlaintext::from_scalar(Fp(input)));
}

template <ProtocolVariant Variant>
gkr::detail::PackedMultiplicationReduction<
    CommittedPackedMessage, Variant>
one_round_proof() {
    gkr::detail::PackedMultiplicationReduction<
        CommittedPackedMessage, Variant>
        proof;
    proof.rounds.push_back(
        gkr::detail::PackedRound<CommittedPackedMessage, Variant>{
            public_message(71)});
    proof.packed_source_values = public_message(73);
    return proof;
}

template <ProtocolVariant Variant>
SingleClaim verify_constant_round(std::string_view transcript_domain) {
    const Fpk left = value(7);
    const Fpk right = value(17);
    const Fpk product = left * right;
    const SingleClaim claim{{value(3)}, product};
    const auto proof = one_round_proof<Variant>();
    FixedReader reader{{
        std::array<Fpk, 2>{product, product},
        std::array<Fpk, 2>{left, right},
    }};
    Transcript transcript(transcript_domain);
    gkr::detail::PackedDenseMultiplicationVerifier<
        Variant, MockBackend, FixedReader, CommittedPackedMessage,
        FixedGeometry<Variant>>
        verifier(reader, 4, claim, proof, transcript,
                 FixedGeometry<Variant>{1, true});
    const std::optional<SingleClaim> actual = verifier.run();
    CHECK(actual.has_value());
    CHECK(reader.next == 2U);

    Transcript reference(transcript_domain);
    gkr::detail::observe_packed_reduction_begin<Variant>(
        4, payload::LayerKind::Multiplication, 1, reference);
    gkr::detail::observe_packed_round_message<Variant, MockBackend>(
        4, 0, proof.rounds.front(), reference);
    const Fpk shared_point = reference.challenge_fpk();
    gkr::detail::observe_packed_terminal_message<Variant, MockBackend>(
        4, proof.packed_source_values, reference);
    const Fpk selector = reference.challenge_fpk();
    const SingleClaim expected{
        {selector, shared_point},
        (Fpk::one() - selector) * left + selector * right};
    CHECK(*actual == expected);
    const poly::Multilinear<Fpk> source(2, {left, left, right, right});
    CHECK(actual->value == source.evaluate(actual->point));
    CHECK(transcript.challenge_fpk() == reference.challenge_fpk());
    return *actual;
}

} // namespace

int main() {
    test::Runner runner("test_packed_dense_multiplication_verifier");

    runner.run("Folded uses the shared replay and terminal claim path", [] {
        const SingleClaim result =
            verify_constant_round<ProtocolVariant::LaminateFolded>(
                "test/packed-dense/folded/v1");
        CHECK(result.point.size() == 2U);
    });

    runner.run("Laned uses the shared replay and terminal claim path", [] {
        const SingleClaim result =
            verify_constant_round<ProtocolVariant::LaminateLaned>(
                "test/packed-dense/laned/v1");
        CHECK(result.point.size() == 2U);
    });

    runner.run("selector endpoints and non-Boolean points evaluate the source MLE", [] {
        const poly::Multilinear<Fp> source(
            3, {Fp(3), Fp(7), Fp(11), Fp(13),
                Fp(19), Fp(23), Fp(29), Fp(31)});
        const std::vector<Fpk> shared{value(5), value(9)};
        const Fpk left = source.evaluate(
            std::vector<Fpk>{Fpk::zero(), shared[0], shared[1]});
        const Fpk right = source.evaluate(
            std::vector<Fpk>{Fpk::one(), shared[0], shared[1]});
        CHECK(left != right);
        CHECK(!left.is_zero());
        Fpk::Coefficients extension_coefficients{};
        extension_coefficients[0] = Fp(5);
        extension_coefficients[1] = Fp(3);
        for (const Fpk &alpha : {Fpk::zero(), Fpk::one(), value(11),
                                Fpk(extension_coefficients)}) {
            const SingleClaim claim =
                gkr::detail::make_dense_multiplication_source_claim(
                    shared, left, right, alpha);
            CHECK(claim.point == std::vector<Fpk>({alpha, shared[0], shared[1]}));
            CHECK(claim.value == source.evaluate(claim.point));
            if (alpha.is_zero()) {
                CHECK(claim.value == left);
            } else {
                CHECK(claim.value != left + alpha * right);
            }
            if (alpha == Fpk::one()) {
                CHECK(claim.value == right);
            }
        }
        const SingleClaim no_suffix =
            gkr::detail::make_dense_multiplication_source_claim(
                {}, value(7), value(17), value(3));
        CHECK(no_suffix.point == std::vector<Fpk>({value(3)}));
        CHECK(no_suffix.value ==
              poly::Multilinear<Fp>(1, {Fp(7), Fp(17)}).evaluate(no_suffix.point));
    });

    runner.run("admission rejection leaves transcript and reader untouched",
               [] {
                   constexpr ProtocolVariant kVariant =
                       ProtocolVariant::LaminateFolded;
                   const auto proof = one_round_proof<kVariant>();
                   const SingleClaim claim{{value(3)}, value(17)};
                   FixedReader reader{{
                       std::array<Fpk, 2>{value(17), value(17)},
                       std::array<Fpk, 2>{Fpk::one(), value(17)},
                   }};
                   Transcript rejected("test/packed-dense/reject/v1");
                   Transcript pristine("test/packed-dense/reject/v1");
                   gkr::detail::PackedDenseMultiplicationVerifier<
                       kVariant, MockBackend, FixedReader,
                       CommittedPackedMessage, FixedGeometry<kVariant>>
                       verifier(reader, 4, claim, proof, rejected,
                                FixedGeometry<kVariant>{1, false});
                   CHECK(!verifier.run().has_value());
                   CHECK(reader.next == 0U);
                   CHECK(rejected.challenge_fpk() ==
                         pristine.challenge_fpk());
               });

    runner.run("terminal mismatch rejects before selector sampling", [] {
        constexpr ProtocolVariant kVariant =
            ProtocolVariant::LaminateLaned;
        const Fpk terminal = value(17);
        const SingleClaim claim{{value(3)}, terminal};
        const auto proof = one_round_proof<kVariant>();
        FixedReader reader{{
            std::array<Fpk, 2>{terminal, terminal},
            std::array<Fpk, 2>{Fpk::one(), terminal + Fpk::one()},
        }};
        Transcript transcript("test/packed-dense/terminal-reject/v1");
        gkr::detail::PackedDenseMultiplicationVerifier<
            kVariant, MockBackend, FixedReader, CommittedPackedMessage,
            FixedGeometry<kVariant>>
            verifier(reader, 4, claim, proof, transcript,
                     FixedGeometry<kVariant>{1, true});
        CHECK(!verifier.run().has_value());
        CHECK(reader.next == 2U);
        Transcript reference("test/packed-dense/terminal-reject/v1");
        gkr::detail::observe_packed_reduction_begin<kVariant>(
            4, payload::LayerKind::Multiplication, 1, reference);
        gkr::detail::observe_packed_round_message<kVariant, MockBackend>(
            4, 0, proof.rounds.front(), reference);
        (void)reference.challenge_fpk();
        gkr::detail::observe_packed_terminal_message<kVariant, MockBackend>(
            4, proof.packed_source_values, reference);
        CHECK(transcript.challenge_fpk() == reference.challenge_fpk());
    });

    return runner.summary();
}
