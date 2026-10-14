#ifndef LAMINATE_TRANSCRIPT_TRANSCRIPT_HPP
#define LAMINATE_TRANSCRIPT_TRANSCRIPT_HPP

/// @file transcript.hpp
/// @brief Labeled Fiat-Shamir transcript for encrypted GKR messages.
///
/// Observations are length-prefixed and buffered. Sampling folds pending data
/// into a rolling SHA-256 state, then samples field challenges by rejection
/// from a counter-mode stream, avoiding modular-reduction bias. Encrypted GKR
/// messages are observed as canonical ciphertext bytes, never secret plaintexts.
/// The domain label, observation order, and challenge call sequence are part
/// of the protocol: prover and verifier must use the same sequence.

#include "laminate/field/fpk.hpp"
#include "laminate/field/fq2.hpp"
#include "laminate/transcript/hash.hpp"
#include "laminate/transcript/public_coin.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

namespace laminate {

/// SHA-256 Fiat--Shamir implementation used by every BCS16 compilation and
/// every Laminate GKR transcript.
class Transcript final : public PublicCoin {
  public:
    explicit Transcript(std::string_view domain_label);

    void observe(std::string_view label,
                 std::span<const std::uint8_t> bytes) override;
    void observe(std::string_view label, std::uint64_t value) override;

    Fpk challenge_fpk() override;
    Fq challenge_fq() override;
    Fq2 challenge_fq2() override;
    std::vector<Fq2> challenge_fq2_vector(std::size_t count) override;
    std::vector<Fpk> challenge_vector(std::size_t count) override;
    std::vector<bool> challenge_bits(std::size_t count) override;

  private:
    static constexpr std::size_t kWordsPerDigest = Digest{}.size() / 8;

    void absorb_pending();
    void reset_words() { word_index_ = kWordsPerDigest; }
    std::uint64_t next_word();
    std::uint64_t sample_uniform(std::uint64_t modulus);

    Digest state_{};
    std::vector<std::uint8_t> pending_;
    std::uint64_t counter_ = 0;
    Digest block_{};
    std::size_t word_index_ = kWordsPerDigest;
};

} // namespace laminate

#endif // LAMINATE_TRANSCRIPT_TRANSCRIPT_HPP
