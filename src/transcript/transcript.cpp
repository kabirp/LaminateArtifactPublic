#include "laminate/transcript/transcript.hpp"

#include "laminate/params.hpp"
#include "laminate/verification_profile.hpp"

#include <cstddef>
#include <cstdint>
#include <stdexcept>

namespace laminate {
namespace {

void append_little_endian_u64(std::vector<std::uint8_t> &output,
                              std::uint64_t value) {
    for (std::size_t byte = 0; byte < 8; ++byte) {
        output.push_back(static_cast<std::uint8_t>(
            (value >> (8U * byte)) & 0xffU));
    }
}

std::uint64_t read_little_endian_u64(const Digest &digest,
                                     std::size_t offset) {
    std::uint64_t value = 0;
    for (int byte = 7; byte >= 0; --byte) {
        value = (value << 8U) |
                digest[offset + static_cast<std::size_t>(byte)];
    }
    return value;
}

} // namespace

Transcript::Transcript(std::string_view domain_label) {
    const verification_profile::ScopedTranscriptRecovery recovery;
    const auto *begin = reinterpret_cast<const std::uint8_t *>(
        domain_label.data());
    state_ = sha256(
        std::span<const std::uint8_t>(begin, domain_label.size()));
}

void Transcript::observe(std::string_view label,
                         std::span<const std::uint8_t> bytes) {
    const verification_profile::ScopedTranscriptRecovery recovery;
    append_little_endian_u64(pending_, label.size());
    pending_.insert(pending_.end(), label.begin(), label.end());
    append_little_endian_u64(pending_, bytes.size());
    pending_.insert(pending_.end(), bytes.begin(), bytes.end());
}

void Transcript::observe(std::string_view label, std::uint64_t value) {
    const verification_profile::ScopedTranscriptRecovery recovery;
    std::vector<std::uint8_t> bytes;
    bytes.reserve(8);
    append_little_endian_u64(bytes, value);
    observe(label, bytes);
}

void Transcript::absorb_pending() {
    if (pending_.empty()) {
        return;
    }

    std::vector<std::uint8_t> input(state_.begin(), state_.end());
    input.insert(input.end(), pending_.begin(), pending_.end());
    state_ = sha256(input);
    pending_.clear();
    counter_ = 0;
}

std::uint64_t Transcript::next_word() {
    if (word_index_ == kWordsPerDigest) {
        std::vector<std::uint8_t> input(state_.begin(), state_.end());
        append_little_endian_u64(input, counter_++);
        block_ = sha256(input);
        word_index_ = 0;
    }
    return read_little_endian_u64(block_, 8 * word_index_++);
}

std::uint64_t Transcript::sample_uniform(std::uint64_t modulus) {
    if (modulus == 0 || modulus > kOuterFieldOrder) {
        throw std::invalid_argument("transcript sampling modulus is invalid");
    }
    // Rejection from all 2^64 SHA bits avoids bias for every field modulus.
    constexpr std::uint64_t kMaximum = ~std::uint64_t{0};
    const std::uint64_t remainder =
        (kMaximum % modulus + 1U) % modulus;
    const std::uint64_t largest_accepted = kMaximum - remainder;
    std::uint64_t word = next_word();
    while (word > largest_accepted) {
        word = next_word();
    }
    return word % modulus;
}

Fpk Transcript::challenge_fpk() {
    const verification_profile::ScopedTranscriptRecovery recovery;
    absorb_pending();
    reset_words();

    Fpk::Coefficients coefficients{};
    for (Fp &coefficient : coefficients) {
        coefficient = Fp(sample_uniform(kBaseFieldOrder));
    }
    return Fpk(coefficients);
}

Fq Transcript::challenge_fq() {
    const verification_profile::ScopedTranscriptRecovery recovery;
    absorb_pending();
    reset_words();
    return Fq(sample_uniform(kOuterFieldOrder));
}

Fq2 Transcript::challenge_fq2() {
    const verification_profile::ScopedTranscriptRecovery recovery;
    absorb_pending();
    reset_words();
    return Fq2({Fq(sample_uniform(kOuterFieldOrder)),
                Fq(sample_uniform(kOuterFieldOrder))});
}

std::vector<Fq2> Transcript::challenge_fq2_vector(std::size_t count) {
    const verification_profile::ScopedTranscriptRecovery recovery;
    std::vector<Fq2> challenges;
    challenges.reserve(count);
    for (std::size_t index = 0; index < count; ++index) {
        challenges.push_back(challenge_fq2());
    }
    return challenges;
}

std::vector<Fpk> Transcript::challenge_vector(std::size_t count) {
    const verification_profile::ScopedTranscriptRecovery recovery;
    std::vector<Fpk> challenges;
    challenges.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        challenges.push_back(challenge_fpk());
    }
    return challenges;
}

std::vector<bool> Transcript::challenge_bits(std::size_t count) {
    const verification_profile::ScopedTranscriptRecovery recovery;
    absorb_pending();
    reset_words();

    std::vector<bool> bits;
    bits.reserve(count);
    std::uint64_t word = 0;
    for (std::size_t i = 0; i < count; ++i) {
        if (i % 64 == 0) {
            word = next_word();
        }
        bits.push_back(((word >> (i % 64)) & 1U) != 0);
    }
    return bits;
}

} // namespace laminate
