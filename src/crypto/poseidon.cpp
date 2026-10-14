/// @file poseidon.cpp
/// @brief Width-16 Poseidon over Laminate's native 60-bit field.

#include "laminate/crypto/poseidon.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <stdexcept>
#include <vector>

namespace laminate {
namespace {

using State = PoseidonState;

/// Poseidon's standard 80-bit Grain-LFSR parameter generator. The generated
/// constants are deterministic from (prime field, alpha=5, q bits, width,
/// full rounds, partial rounds); no external hash primitive is involved.
class GrainLfsr {
  public:
    GrainLfsr() {
        append(1, 2); // prime field
        append(0, 4); // x^alpha S-box
        append(60, 12);
        append(kPoseidonWidth, 12);
        append(kPoseidonFullRounds, 10);
        append(kPoseidonPartialRounds, 10);
        while (filled_ < state_.size()) {
            state_[filled_++] = true;
        }
        for (std::size_t bit = 0; bit < 160; ++bit) {
            (void)step();
        }
    }

    std::uint64_t bits(std::size_t count) {
        if (count > 64) {
            throw std::invalid_argument("Poseidon Grain bit request too large");
        }
        std::uint64_t result = 0;
        for (std::size_t bit = 0; bit < count; ++bit) {
            result = (result << 1U) |
                     static_cast<std::uint64_t>(self_shrinking_bit());
        }
        return result;
    }

    Fq field_element_rejection_sampled() {
        while (true) {
            const std::uint64_t candidate = bits(60);
            if (candidate < kOuterFieldOrder) {
                return Fq(candidate);
            }
        }
    }

  private:
    void append(std::uint64_t value, std::size_t bits) {
        if (bits > 64 || filled_ + bits > state_.size()) {
            throw std::logic_error("Poseidon Grain initialization overflow");
        }
        for (std::size_t bit = 0; bit < bits; ++bit) {
            const std::size_t shift = bits - 1 - bit;
            state_[filled_++] = ((value >> shift) & 1U) != 0;
        }
    }

    bool step() {
        const bool feedback = state_[62] ^ state_[51] ^ state_[38] ^
                              state_[23] ^ state_[13] ^ state_[0];
        for (std::size_t bit = 1; bit < state_.size(); ++bit) {
            state_[bit - 1] = state_[bit];
        }
        state_.back() = feedback;
        return feedback;
    }

    bool self_shrinking_bit() {
        while (true) {
            const bool selector = step();
            const bool value = step();
            if (selector) {
                return value;
            }
        }
    }

    std::array<bool, 80> state_{};
    std::size_t filled_ = 0;
};

struct PoseidonParameters {
    std::array<State,
               kPoseidonFullRounds + kPoseidonPartialRounds>
        round_constants{};
    std::array<State, kPoseidonWidth> mds{};
};

const PoseidonParameters &parameters() {
    static const PoseidonParameters result = [] {
        PoseidonParameters generated;
        GrainLfsr grain;
        for (State &round : generated.round_constants) {
            for (Fq &constant : round) {
                constant = grain.field_element_rejection_sampled();
            }
        }

        // The Poseidon reference generator draws 2t field values from the
        // same Grain stream (reducing rather than rejection-sampling), then
        // constructs the Cauchy MDS M[i,j] = 1/(x_i+y_j). Retry the complete
        // sample if the values are not distinct or a denominator is zero.
        std::array<Fq, 2 * kPoseidonWidth> samples{};
        bool valid = false;
        while (!valid) {
            valid = true;
            for (Fq &sample : samples) {
                sample = Fq(grain.bits(60));
            }
            for (std::size_t left = 0; left < samples.size(); ++left) {
                for (std::size_t right = left + 1; right < samples.size();
                     ++right) {
                    if (samples[left] == samples[right]) {
                        valid = false;
                    }
                }
            }
            for (std::size_t row = 0; row < kPoseidonWidth; ++row) {
                for (std::size_t column = 0; column < kPoseidonWidth;
                     ++column) {
                    if ((samples[row] +
                         samples[kPoseidonWidth + column])
                            .is_zero()) {
                        valid = false;
                    }
                }
            }
        }
        for (std::size_t row = 0; row < kPoseidonWidth; ++row) {
            for (std::size_t column = 0; column < kPoseidonWidth; ++column) {
                generated.mds[row][column] =
                    (samples[row] + samples[kPoseidonWidth + column])
                        .inverse();
            }
        }
        return generated;
    }();
    return result;
}

Fq sbox(const Fq &value) {
    const Fq squared = value * value;
    const Fq fourth = squared * squared;
    return fourth * value;
}

void mix(State &state, const std::array<State, kPoseidonWidth> &mds) {
    State mixed{};
    for (std::size_t row = 0; row < kPoseidonWidth; ++row) {
        for (std::size_t column = 0; column < kPoseidonWidth; ++column) {
            mixed[row] += mds[row][column] * state[column];
        }
    }
    state = mixed;
}

PoseidonDigest digest_from_state(const State &state) {
    PoseidonDigest digest{};
    for (std::size_t element = 0; element < kPoseidonDigestElements;
         ++element) {
        const std::uint64_t word = state[element].value();
        for (std::size_t byte = 0; byte < 8; ++byte) {
            digest[8 * element + byte] = static_cast<std::uint8_t>(
                (word >> (8U * byte)) & 0xffU);
        }
    }
    return digest;
}

template <typename Next>
PoseidonDigest sponge_hash(std::uint64_t element_count,
                           PoseidonDomain domain,
                           std::uint64_t logical_length, Next &&next) {
    State state{};
    state[kPoseidonRate] = Fq(static_cast<std::uint64_t>(domain));
    state[kPoseidonRate + 1] = Fq(logical_length);
    state[kPoseidonRate + 2] = Fq(element_count);
    state[kPoseidonRate + 3] =
        Fq(kPoseidonEncodingVersionDelimiter);

    std::uint64_t consumed = 0;
    bool padded = false;
    while (!padded) {
        for (std::size_t rate_index = 0; rate_index < kPoseidonRate;
             ++rate_index) {
            Fq value = Fq::zero();
            if (consumed < element_count) {
                value = next(consumed++);
            } else if (!padded) {
                value = Fq(kPoseidonRatePaddingDelimiter);
                padded = true;
            }
            state[rate_index] += value;
        }
        poseidon_permute(state);
    }
    return digest_from_state(state);
}

std::uint64_t checked_ceil_div(std::uint64_t numerator,
                               std::uint64_t denominator) {
    return numerator / denominator + (numerator % denominator != 0 ? 1 : 0);
}

} // namespace

void poseidon_permute(std::array<Fq, kPoseidonWidth> &state) {
    const PoseidonParameters &poseidon = parameters();
    for (std::size_t round = 0;
         round < kPoseidonFullRounds + kPoseidonPartialRounds; ++round) {
        for (std::size_t index = 0; index < kPoseidonWidth; ++index) {
            state[index] += poseidon.round_constants[round][index];
        }
        const bool full = poseidon_round_is_full(round);
        if (full) {
            for (Fq &value : state) {
                value = sbox(value);
            }
        } else {
            state[0] = sbox(state[0]);
        }
        mix(state, poseidon.mds);
    }
}

const PoseidonRoundConstants &poseidon_round_constants() {
    return parameters().round_constants;
}

const PoseidonMdsMatrix &poseidon_mds_matrix() {
    return parameters().mds;
}

bool poseidon_round_is_full(std::size_t round) {
    if (round >= kPoseidonFullRounds + kPoseidonPartialRounds) {
        throw std::out_of_range("Poseidon round index is out of range");
    }
    constexpr std::size_t kHalfFullRounds = kPoseidonFullRounds / 2;
    return round < kHalfFullRounds ||
           round >= kHalfFullRounds + kPoseidonPartialRounds;
}

bool poseidon_round_is_r1cs_checkpoint(std::size_t round) {
    if (poseidon_round_is_full(round)) {
        return true;
    }
    constexpr std::size_t kHalfFullRounds = kPoseidonFullRounds / 2;
    const std::size_t partial_index = round - kHalfFullRounds;
    return (partial_index + 1U) % 5U == 0;
}

PoseidonDigest poseidon_hash(std::span<const std::uint8_t> input,
                             PoseidonDomain domain) {
    constexpr std::uint64_t kBytesPerElement = 7;
    const std::uint64_t elements = checked_ceil_div(
        static_cast<std::uint64_t>(input.size()), kBytesPerElement);
    return sponge_hash(
        elements, domain, static_cast<std::uint64_t>(input.size()),
        [&](std::uint64_t element) {
            const std::size_t begin =
                static_cast<std::size_t>(element * kBytesPerElement);
            const std::size_t end =
                std::min(input.size(),
                         begin + static_cast<std::size_t>(kBytesPerElement));
            std::uint64_t word = 0;
            for (std::size_t index = end; index > begin; --index) {
                word = (word << 8U) | input[index - 1];
            }
            return Fq(word);
        });
}

PoseidonDigest poseidon_hash_fields(std::span<const Fq> input,
                                    PoseidonDomain domain,
                                    std::uint64_t logical_length) {
    return sponge_hash(
        static_cast<std::uint64_t>(input.size()), domain, logical_length,
        [&](std::uint64_t index) {
            return input[static_cast<std::size_t>(index)];
        });
}

std::array<Fq, kPoseidonDigestElements>
poseidon_digest_field_elements(const PoseidonDigest &digest) {
    std::array<Fq, kPoseidonDigestElements> result{};
    for (std::size_t element = 0; element < result.size(); ++element) {
        std::uint64_t word = 0;
        for (std::size_t byte = 0; byte < 8; ++byte) {
            word |= static_cast<std::uint64_t>(
                        digest[8 * element + byte])
                    << (8U * byte);
        }
        if (word >= kOuterFieldOrder) {
            throw std::invalid_argument(
                "Poseidon digest contains a noncanonical field element");
        }
        result[element] = Fq(word);
    }
    return result;
}

std::uint64_t poseidon_r1cs_constraints_for_field_elements(
    std::uint64_t field_elements) {
    if (field_elements == std::numeric_limits<std::uint64_t>::max()) {
        throw std::overflow_error("Poseidon field-element ledger overflow");
    }
    const std::uint64_t permutations = checked_ceil_div(
        field_elements + 1, static_cast<std::uint64_t>(kPoseidonRate));
    const std::uint64_t sboxes_per_permutation =
        kPoseidonFullRounds * kPoseidonWidth + kPoseidonPartialRounds;
    if (permutations > std::numeric_limits<std::uint64_t>::max() /
                           (3 * sboxes_per_permutation)) {
        throw std::overflow_error("Poseidon constraint ledger overflow");
    }
    return permutations * 3 * sboxes_per_permutation;
}

std::uint64_t poseidon_r1cs_checkpoint_constraints_for_field_elements(
    std::uint64_t field_elements) {
    if (field_elements == std::numeric_limits<std::uint64_t>::max()) {
        throw std::overflow_error("Poseidon field-element ledger overflow");
    }
    const std::uint64_t permutations = checked_ceil_div(
        field_elements + 1, static_cast<std::uint64_t>(kPoseidonRate));
    std::uint64_t checkpoint_rounds = 0;
    for (std::size_t round = 0;
         round < kPoseidonFullRounds + kPoseidonPartialRounds; ++round) {
        checkpoint_rounds += poseidon_round_is_r1cs_checkpoint(round) ? 1 : 0;
    }
    const std::uint64_t per_permutation =
        checkpoint_rounds * kPoseidonWidth;
    if (permutations > std::numeric_limits<std::uint64_t>::max() /
                           per_permutation) {
        throw std::overflow_error("Poseidon checkpoint ledger overflow");
    }
    return permutations * per_permutation;
}

std::uint64_t poseidon_r1cs_constraints_for_bytes(
    std::uint64_t byte_count) {
    const std::uint64_t elements = checked_ceil_div(byte_count, 7);
    return poseidon_r1cs_constraints_for_field_elements(elements);
}

} // namespace laminate
