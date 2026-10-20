/// @file hash.cpp
/// @brief SHA-256 with accelerated system providers and portable fallback.
///
/// Known-answer tests cover both one-shot and incremental interfaces in
/// tests/transcript/test_transcript.cpp for the provider selected by a build.

#include "laminate/transcript/hash.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <stdexcept>
#include <utility>

#if defined(__APPLE__)
#include <CommonCrypto/CommonDigest.h>
#elif defined(LAMINATE_SHA256_OPENSSL)
#include <openssl/evp.h>
#include <openssl/sha.h>
#endif

namespace laminate {
#if !defined(__APPLE__) && !defined(LAMINATE_SHA256_OPENSSL)
namespace {

constexpr std::uint32_t kRoundConstants[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b,
    0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
    0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
    0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152,
    0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
    0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
    0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
    0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
    0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

std::uint32_t rotate_right(std::uint32_t value, std::uint32_t count) {
    return (value >> count) | (value << (32U - count));
}

void compress(const std::uint8_t *chunk,
              std::array<std::uint32_t, 8> &state) {
    std::uint32_t words[64]{};
    for (std::size_t i = 0; i < 16; ++i) {
        words[i] =
            (static_cast<std::uint32_t>(chunk[4 * i]) << 24U) |
            (static_cast<std::uint32_t>(chunk[4 * i + 1]) << 16U) |
            (static_cast<std::uint32_t>(chunk[4 * i + 2]) << 8U) |
            static_cast<std::uint32_t>(chunk[4 * i + 3]);
    }
    for (std::size_t i = 16; i < 64; ++i) {
        const std::uint32_t sigma_zero =
            rotate_right(words[i - 15], 7) ^
            rotate_right(words[i - 15], 18) ^ (words[i - 15] >> 3U);
        const std::uint32_t sigma_one =
            rotate_right(words[i - 2], 17) ^
            rotate_right(words[i - 2], 19) ^ (words[i - 2] >> 10U);
        words[i] = words[i - 16] + sigma_zero + words[i - 7] + sigma_one;
    }

    std::uint32_t a = state[0];
    std::uint32_t b = state[1];
    std::uint32_t c = state[2];
    std::uint32_t d = state[3];
    std::uint32_t e = state[4];
    std::uint32_t f = state[5];
    std::uint32_t g = state[6];
    std::uint32_t h = state[7];

    for (std::size_t i = 0; i < 64; ++i) {
        const std::uint32_t sigma_one =
            rotate_right(e, 6) ^ rotate_right(e, 11) ^
            rotate_right(e, 25);
        const std::uint32_t choose = (e & f) ^ (~e & g);
        const std::uint32_t temporary_one =
            h + sigma_one + choose + kRoundConstants[i] + words[i];
        const std::uint32_t sigma_zero =
            rotate_right(a, 2) ^ rotate_right(a, 13) ^
            rotate_right(a, 22);
        const std::uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
        const std::uint32_t temporary_two = sigma_zero + majority;

        h = g;
        g = f;
        f = e;
        e = d + temporary_one;
        d = c;
        c = b;
        b = a;
        a = temporary_one + temporary_two;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

} // namespace
#endif

struct Sha256Hasher::State {
#if defined(__APPLE__)
    CC_SHA256_CTX context{};
#elif defined(LAMINATE_SHA256_OPENSSL)
    EVP_MD_CTX *context = nullptr;
#else
    std::array<std::uint32_t, 8> words{};
    std::array<std::uint8_t, 64> block{};
    std::size_t buffered_bytes = 0;
#endif
    std::uint64_t total_bytes = 0;
    bool finished = false;

    ~State() {
#if defined(LAMINATE_SHA256_OPENSSL)
        EVP_MD_CTX_free(context);
#endif
    }
};

Sha256Hasher::Sha256Hasher() : state_(std::make_unique<State>()) {
#if defined(__APPLE__)
    if (CC_SHA256_Init(&state_->context) != 1) {
        throw std::runtime_error("Sha256Hasher: CommonCrypto init failed");
    }
#elif defined(LAMINATE_SHA256_OPENSSL)
    state_->context = EVP_MD_CTX_new();
    if (state_->context == nullptr ||
        EVP_DigestInit_ex(state_->context, EVP_sha256(), nullptr) != 1) {
        throw std::runtime_error("Sha256Hasher: OpenSSL init failed");
    }
#else
    state_->words = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
#endif
}

Sha256Hasher::~Sha256Hasher() = default;
Sha256Hasher::Sha256Hasher(Sha256Hasher &&) noexcept = default;
Sha256Hasher &Sha256Hasher::operator=(Sha256Hasher &&) noexcept = default;

void Sha256Hasher::update(std::span<const std::uint8_t> input) {
    if (!state_) {
        throw std::logic_error("Sha256Hasher: use after move");
    }
    if (state_->finished) {
        throw std::logic_error("Sha256Hasher: update after finish");
    }
    constexpr std::uint64_t kMaximumMessageBytes =
        std::numeric_limits<std::uint64_t>::max() / 8U;
    if (input.size() > kMaximumMessageBytes - state_->total_bytes) {
        throw std::overflow_error("Sha256Hasher: message is too long");
    }
    state_->total_bytes += static_cast<std::uint64_t>(input.size());

#if defined(__APPLE__)
    constexpr std::size_t kMaximumUpdateBytes =
        std::numeric_limits<CC_LONG>::max();
    while (!input.empty()) {
        const std::size_t chunk_bytes =
            std::min(input.size(), kMaximumUpdateBytes);
        if (CC_SHA256_Update(&state_->context, input.data(),
                             static_cast<CC_LONG>(chunk_bytes)) != 1) {
            throw std::runtime_error(
                "Sha256Hasher: CommonCrypto update failed");
        }
        input = input.subspan(chunk_bytes);
    }
#elif defined(LAMINATE_SHA256_OPENSSL)
    if (!input.empty() &&
        EVP_DigestUpdate(state_->context, input.data(), input.size()) != 1) {
        throw std::runtime_error("Sha256Hasher: OpenSSL update failed");
    }
#else
    if (state_->buffered_bytes != 0) {
        const std::size_t copied =
            std::min(state_->block.size() - state_->buffered_bytes,
                     input.size());
        std::copy_n(input.begin(), copied,
                    state_->block.begin() + static_cast<std::ptrdiff_t>(
                                                state_->buffered_bytes));
        state_->buffered_bytes += copied;
        input = input.subspan(copied);
        if (state_->buffered_bytes != state_->block.size()) {
            return;
        }
        compress(state_->block.data(), state_->words);
        state_->buffered_bytes = 0;
    }

    while (input.size() >= state_->block.size()) {
        compress(input.data(), state_->words);
        input = input.subspan(state_->block.size());
    }
    std::copy(input.begin(), input.end(), state_->block.begin());
    state_->buffered_bytes = input.size();
#endif
}

Digest Sha256Hasher::finish() {
    if (!state_) {
        throw std::logic_error("Sha256Hasher: use after move");
    }
    if (state_->finished) {
        throw std::logic_error("Sha256Hasher: finish called twice");
    }
    Digest digest{};
#if defined(__APPLE__)
    if (CC_SHA256_Final(digest.data(), &state_->context) != 1) {
        throw std::runtime_error(
            "Sha256Hasher: CommonCrypto finish failed");
    }
#elif defined(LAMINATE_SHA256_OPENSSL)
    unsigned int digest_bytes = 0;
    if (EVP_DigestFinal_ex(state_->context, digest.data(), &digest_bytes) !=
            1 ||
        digest_bytes != digest.size()) {
        throw std::runtime_error("Sha256Hasher: OpenSSL finish failed");
    }
#else
    const std::uint64_t input_bits = state_->total_bytes * 8U;
    state_->block[state_->buffered_bytes++] = 0x80;
    if (state_->buffered_bytes > 56) {
        std::fill(state_->block.begin() + static_cast<std::ptrdiff_t>(
                                              state_->buffered_bytes),
                  state_->block.end(), 0);
        compress(state_->block.data(), state_->words);
        state_->buffered_bytes = 0;
    }
    std::fill(state_->block.begin() + static_cast<std::ptrdiff_t>(
                                          state_->buffered_bytes),
              state_->block.begin() + 56, 0);
    for (std::size_t byte = 0; byte < sizeof(input_bits); ++byte) {
        state_->block[63 - byte] =
            static_cast<std::uint8_t>(input_bits >> (8U * byte));
    }
    compress(state_->block.data(), state_->words);
    for (std::size_t i = 0; i < 8; ++i) {
        digest[4 * i] =
            static_cast<std::uint8_t>((state_->words[i] >> 24U) & 0xffU);
        digest[4 * i + 1] =
            static_cast<std::uint8_t>((state_->words[i] >> 16U) & 0xffU);
        digest[4 * i + 2] =
            static_cast<std::uint8_t>((state_->words[i] >> 8U) & 0xffU);
        digest[4 * i + 3] =
            static_cast<std::uint8_t>(state_->words[i] & 0xffU);
    }
#endif
    state_->finished = true;
    return digest;
}

Digest sha256(std::span<const std::uint8_t> input) {
#if defined(__APPLE__)
    CC_SHA256_CTX context{};
    if (CC_SHA256_Init(&context) != 1) {
        throw std::runtime_error("sha256: CommonCrypto init failed");
    }
    constexpr std::size_t kMaximumUpdateBytes =
        std::numeric_limits<CC_LONG>::max();
    while (!input.empty()) {
        const std::size_t chunk_bytes =
            std::min(input.size(), kMaximumUpdateBytes);
        if (CC_SHA256_Update(&context, input.data(),
                             static_cast<CC_LONG>(chunk_bytes)) != 1) {
            throw std::runtime_error(
                "sha256: CommonCrypto update failed");
        }
        input = input.subspan(chunk_bytes);
    }
    Digest digest{};
    if (CC_SHA256_Final(digest.data(), &context) != 1) {
        throw std::runtime_error("sha256: CommonCrypto finish failed");
    }
    return digest;
#elif defined(LAMINATE_SHA256_OPENSSL)
    Digest digest{};
    constexpr std::uint8_t kEmptyInput = 0;
    const std::uint8_t *data =
        input.empty() ? &kEmptyInput : input.data();
    if (::SHA256(data, input.size(), digest.data()) == nullptr) {
        throw std::runtime_error("sha256: OpenSSL digest failed");
    }
    return digest;
#else
    Sha256Hasher hasher;
    hasher.update(input);
    return hasher.finish();
#endif
}

} // namespace laminate
