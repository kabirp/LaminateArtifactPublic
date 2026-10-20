/// @file test_packed_proof_schema.cpp
/// @brief Compatibility tests for the shared Folded/Laned proof schema.

#include "test_helpers.hpp"

#include "laminate/fhe/mock_backend.hpp"
#include "laminate/gkr/folded.hpp"
#include "laminate/gkr/detail/shared/packed/transcript.hpp"
#include "laminate/gkr/laned.hpp"
#include "laminate/gkr/detail/shared/encoding/canonical.hpp"
#include "laminate/protocol/metrics/proof_size.hpp"

#include <concepts>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

using namespace laminate;
using namespace laminate::fhe;
using namespace laminate::gkr;

namespace {

static_assert(std::same_as<
              FoldedLayerReductionSumcheckRound<int>,
              gkr::detail::PackedRound<
                  int, ProtocolVariant::LaminateFolded>>);
static_assert(std::same_as<
              LanedLayerReductionSumcheckRound<int>,
              gkr::detail::PackedRound<
                  int, ProtocolVariant::LaminateLaned>>);
static_assert(!std::same_as<FoldedLayerReductionSumcheckRound<int>, LanedLayerReductionSumcheckRound<int>>);
static_assert(std::is_aggregate_v<FoldedGkrProof<int>>);
static_assert(std::is_aggregate_v<LanedGkrProof<int>>);

CommittedPackedMessage committed_message(std::uint8_t seed) {
    PackedMessageCommitment commitment;
    for (std::size_t index = 0; index < commitment.digest.size(); ++index) {
        commitment.digest[index] =
            static_cast<std::uint8_t>(seed + 7U * index);
    }
    return CommittedPackedMessage::encrypted_message(commitment);
}

CommittedPackedMessage public_message(std::uint64_t value) {
    return CommittedPackedMessage::public_message(
        PublicPlaintext::from_scalar(Fp(value)));
}

void observe_reference_begin(std::string_view label, std::size_t layer,
                             payload::LayerKind kind, std::size_t rounds,
                             Transcript &transcript) {
    std::vector<std::uint8_t> encoded;
    gkr::detail::canonical_encoding::append_size(encoded, layer);
    encoded.push_back(static_cast<std::uint8_t>(kind));
    gkr::detail::canonical_encoding::append_size(encoded, rounds);
    transcript.observe(label, encoded);
}

void observe_reference_round(std::string_view label, std::size_t layer,
                             std::size_t round_index,
                             const CommittedPackedMessage &message,
                             Transcript &transcript) {
    std::vector<std::uint8_t> encoded;
    gkr::detail::canonical_encoding::append_size(encoded, layer);
    gkr::detail::canonical_encoding::append_size(encoded, round_index);
    append_committed_packed_message(encoded, message);
    transcript.observe(label, encoded);
}

void observe_reference_terminal(std::string_view label, std::size_t layer,
                                const CommittedPackedMessage &message,
                                Transcript &transcript) {
    std::vector<std::uint8_t> encoded;
    gkr::detail::canonical_encoding::append_size(encoded, layer);
    append_committed_packed_message(encoded, message);
    transcript.observe(label, encoded);
}

template <typename Message>
void append_reference_message(std::vector<std::uint8_t> &output,
                              const Message &message,
                              std::string_view description) {
    const std::vector<std::uint8_t> encoded =
        encode_canonical_fhe_value<MockBackend>(message, description);
    gkr::detail::canonical_encoding::append_size(output, encoded.size());
    output.insert(output.end(), encoded.begin(), encoded.end());
}

template <typename Proof>
void append_reference_header(std::vector<std::uint8_t> &output,
                             const Proof &proof) {
    const std::vector<std::uint8_t> header =
        gkr::encode_canonical(proof.header);
    gkr::detail::canonical_encoding::append_size(output, header.size());
    output.insert(output.end(), header.begin(), header.end());
}

} // namespace

int main() {
    test::Runner runner("test_packed_proof_schema");

    runner.run("variant traits preserve versions labels and public fields",
               [] {
                   CHECK(kEncryptedFoldedProofVersion == 9);
                   CHECK(kEncryptedLanedProofVersion == 8);
                   CHECK(gkr::detail::PackedProofTraits<
                             ProtocolVariant::LaminateFolded>::begin_label ==
                         "laminate/folded/reduction/v1");
                   CHECK(gkr::detail::PackedProofTraits<
                             ProtocolVariant::LaminateFolded>::round_label ==
                         "laminate/folded/round/v3");
                   CHECK(
                       gkr::detail::PackedProofTraits<
                           ProtocolVariant::LaminateFolded>::terminal_label ==
                       "laminate/folded/terminal/v2");
                   CHECK(gkr::detail::PackedProofTraits<
                             ProtocolVariant::LaminateLaned>::begin_label ==
                         "laminate/laned/reduction/v1");
                   CHECK(gkr::detail::PackedProofTraits<
                             ProtocolVariant::LaminateLaned>::round_label ==
                         "laminate/laned/round/v3");
                   CHECK(gkr::detail::PackedProofTraits<
                             ProtocolVariant::LaminateLaned>::terminal_label ==
                         "laminate/laned/terminal/v2");

                   FoldedAffineLayerReduction<int> folded;
                   folded.packed_terminal_value = 17;
                   CHECK(folded.packed_terminal_value == 17);
                   LanedAffineLayerReduction<int> laned;
                   laned.packed_terminal_value = 23;
                   CHECK(laned.packed_terminal_value == 23);
               });

    runner.run("folded transcript remains byte-for-byte compatible", [] {
        const CommittedPackedMessage round_message = committed_message(11);
        const CommittedPackedMessage terminal_message = public_message(29);
        Transcript shared("test/packed-proof-schema/folded/v1");
        Transcript reference("test/packed-proof-schema/folded/v1");

        gkr::detail::observe_packed_reduction_begin<
            ProtocolVariant::LaminateFolded>(
            3, payload::LayerKind::Multiplication, 7, shared);
        gkr::detail::observe_packed_round<ProtocolVariant::LaminateFolded>(
            3, 2,
            CommittedFoldedLayerReductionSumcheckRound{round_message},
            shared);
        gkr::detail::observe_packed_terminal<ProtocolVariant::LaminateFolded>(
            3, terminal_message, shared);

        observe_reference_begin("laminate/folded/reduction/v1", 3,
                                payload::LayerKind::Multiplication, 7,
                                reference);
        observe_reference_round("laminate/folded/round/v3", 3, 2,
                                round_message, reference);
        observe_reference_terminal("laminate/folded/terminal/v2", 3,
                                   terminal_message, reference);
        CHECK(shared.challenge_fpk() == reference.challenge_fpk());
    });

    runner.run("laned transcript remains byte-for-byte compatible", [] {
        const CommittedPackedMessage round_message = committed_message(37);
        const CommittedPackedMessage terminal_message = public_message(41);
        Transcript shared("test/packed-proof-schema/laned/v1");
        Transcript reference("test/packed-proof-schema/laned/v1");

        gkr::detail::observe_packed_reduction_begin<
            ProtocolVariant::LaminateLaned>(
            5, payload::LayerKind::Affine, 9, shared);
        gkr::detail::observe_packed_round<ProtocolVariant::LaminateLaned>(
            5, 4, CommittedLanedLayerReductionSumcheckRound{round_message}, shared);
        gkr::detail::observe_packed_terminal<ProtocolVariant::LaminateLaned>(
            5, terminal_message, shared);

        observe_reference_begin("laminate/laned/reduction/v1", 5,
                                payload::LayerKind::Affine, 9, reference);
        observe_reference_round("laminate/laned/round/v3", 5, 4,
                                round_message, reference);
        observe_reference_terminal("laminate/laned/terminal/v2", 5,
                                   terminal_message, reference);
        CHECK(shared.challenge_fpk() == reference.challenge_fpk());
    });

    runner.run("canonical packed proof bytes keep their variant encodings",
               [] {
                   EncryptedFoldedProof<MockBackend> folded;
                   EncryptedFoldedAffineLayerReduction<MockBackend>
                       folded_affine;
                   folded_affine.rounds.push_back(
                       EncryptedFoldedLayerReductionSumcheckRound<MockBackend>{
                           FheValue<MockBackend>::public_scalar(Fp(43))});
                   folded_affine.packed_terminal_value =
                       FheValue<MockBackend>::public_scalar(Fp(47));
                   folded.reductions.emplace_back(
                       std::move(folded_affine));

                   std::vector<std::uint8_t> folded_reference{
                       'L', 'M', 'F', 'P', 9};
                   append_reference_header(folded_reference, folded);
                   gkr::detail::canonical_encoding::append_size(
                       folded_reference, 1);
                   folded_reference.push_back(0);
                   gkr::detail::canonical_encoding::append_size(
                       folded_reference, 1);
                   const auto &folded_reduction =
                       std::get<EncryptedFoldedAffineLayerReduction<MockBackend>>(
                           folded.reductions.front());
                   append_reference_message(
                       folded_reference,
                       folded_reduction.rounds.front().packed_evaluations,
                       "LaminateFolded packed proof message");
                   append_reference_message(
                       folded_reference,
                       folded_reduction.packed_terminal_value,
                       "LaminateFolded packed proof message");
                   folded_reference.push_back(0);
                   CHECK(protocol::encode_canonical<MockBackend>(folded) ==
                         folded_reference);

                   EncryptedLanedProof<MockBackend> laned;
                   EncryptedLanedAffineLayerReduction<MockBackend> laned_affine;
                   laned_affine.rounds.push_back(
                       EncryptedLanedLayerReductionSumcheckRound<MockBackend>{
                           FheValue<MockBackend>::public_scalar(Fp(53))});
                   laned_affine.packed_terminal_value =
                       FheValue<MockBackend>::public_scalar(Fp(59));
                   laned.reductions.emplace_back(std::move(laned_affine));

                   std::vector<std::uint8_t> laned_reference{
                       'L', 'M', 'L', 'P', 8};
                   append_reference_header(laned_reference, laned);
                   gkr::detail::canonical_encoding::append_size(
                       laned_reference, 1);
                   laned_reference.push_back(0);
                   gkr::detail::canonical_encoding::append_size(
                       laned_reference, 1);
                   const auto &laned_reduction =
                       std::get<EncryptedLanedAffineLayerReduction<MockBackend>>(
                           laned.reductions.front());
                   append_reference_message(
                       laned_reference,
                       laned_reduction.rounds.front().packed_evaluations,
                       "LaminateLaned packed proof message");
                   append_reference_message(
                       laned_reference,
                       laned_reduction.packed_terminal_value,
                       "LaminateLaned packed proof message");
                   laned_reference.push_back(0);
                   CHECK(protocol::encode_canonical<MockBackend>(laned) ==
                         laned_reference);
               });

    return runner.summary();
}
