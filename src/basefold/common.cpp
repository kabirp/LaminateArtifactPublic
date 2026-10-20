#include "laminate/basefold/common.hpp"

#include "laminate/field/serialization.hpp"

#include <limits>
#include <stdexcept>

namespace laminate::basefold {

std::size_t log2_exact(std::size_t n) {
    if (n == 0 || (n & (n - 1)) != 0) {
        throw std::invalid_argument(
            "basefold::log2_exact: argument is not a power of two");
    }
    std::size_t result = 0;
    while (n > 1) {
        n >>= 1U;
        ++result;
    }
    return result;
}

std::size_t codeword_length(std::size_t message_length,
                            std::size_t log_rate) {
    (void)log2_exact(message_length);
    if (log_rate >= std::numeric_limits<std::size_t>::digits ||
        message_length >
            (std::numeric_limits<std::size_t>::max() >> log_rate)) {
        throw std::overflow_error(
            "basefold::codeword_length: inverse-rate expansion overflows");
    }
    return message_length << log_rate;
}

std::vector<std::uint8_t> serialize_values(std::span<const Fp> values) {
    std::vector<std::uint8_t> encoded;
    encoded.reserve(values.size() * kSerializedFpBytes);
    for (const Fp &value : values) {
        const SerializedFp bytes = serialize(value);
        encoded.insert(encoded.end(), bytes.begin(), bytes.end());
    }
    return encoded;
}

std::vector<std::uint8_t> serialize_values(std::span<const Fpk> values) {
    std::vector<std::uint8_t> encoded;
    encoded.reserve(values.size() * kSerializedFpkBytes);
    for (const Fpk &value : values) {
        const SerializedFpk bytes = serialize(value);
        encoded.insert(encoded.end(), bytes.begin(), bytes.end());
    }
    return encoded;
}

Fp field_power(Fp base, std::size_t exponent) {
    Fp result = Fp::one();
    while (exponent > 0) {
        if ((exponent & 1U) != 0) {
            result *= base;
        }
        base *= base;
        exponent >>= 1U;
    }
    return result;
}

Fpk equality_evaluation(std::size_t Boolean_index,
                        std::span<const Fpk> point) {
    Fpk result = Fpk::one();
    for (std::size_t variable = 0; variable < point.size(); ++variable) {
        const bool bit = ((Boolean_index >> variable) & 1U) != 0;
        result *= bit ? point[variable] : Fpk::one() - point[variable];
    }
    return result;
}

std::vector<Fpk> equality_evaluations(std::span<const Fpk> point) {
    if (point.size() >= std::numeric_limits<std::size_t>::digits) {
        throw std::invalid_argument(
            "basefold::equality_evaluations: point dimension overflows size_t");
    }
    std::vector<Fpk> result{Fpk::one()};
    for (const Fpk &coordinate : point) {
        const std::size_t previous_size = result.size();
        result.resize(2U * previous_size);
        for (std::size_t index = 0; index < previous_size; ++index) {
            const Fpk high = result[index] * coordinate;
            result[index + previous_size] = high;
            result[index] -= high;
        }
    }
    return result;
}

Fpk evaluate_multilinear(std::span<const Fpk> evaluations,
                         std::span<const Fpk> point) {
    if (evaluations.empty() || log2_exact(evaluations.size()) != point.size()) {
        throw std::invalid_argument(
            "basefold::evaluate_multilinear: table and point disagree");
    }
    std::vector<Fpk> folded(evaluations.begin(), evaluations.end());
    for (const Fpk &coordinate : point) {
        const std::size_t next_size = folded.size() / 2;
        for (std::size_t index = 0; index < next_size; ++index) {
            const Fpk &lo = folded[2 * index];
            const Fpk &hi = folded[2 * index + 1];
            folded[index] = lo + coordinate * (hi - lo);
        }
        folded.resize(next_size);
    }
    return folded.front();
}

} // namespace laminate::basefold
