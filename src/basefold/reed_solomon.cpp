#include "laminate/basefold/reed_solomon.hpp"

#include "laminate/basefold/common.hpp"

#include <algorithm>
#include <stdexcept>
#include <utility>

namespace laminate::basefold {
namespace {

template <typename Value>
void bit_reverse_permutation(std::vector<Value> &values) {
    const std::size_t n = values.size();
    for (std::size_t index = 0, reversed = 0; index < n; ++index) {
        if (index < reversed) {
            std::swap(values[index], values[reversed]);
        }
        std::size_t bit = n >> 1U;
        while ((reversed & bit) != 0) {
            reversed ^= bit;
            bit >>= 1U;
        }
        reversed ^= bit;
    }
}

template <typename Value>
void ntt(std::vector<Value> &values, const Fp &generator) {
    if (values.size() <= 1) {
        return;
    }
    const std::size_t log_n = log2_exact(values.size());
    bit_reverse_permutation(values);

    for (std::size_t stage = 1; stage <= log_n; ++stage) {
        const std::size_t butterfly_size = std::size_t{1} << stage;
        Fp stage_generator = generator;
        for (std::size_t order = butterfly_size; order < values.size();
             order <<= 1U) {
            stage_generator *= stage_generator;
        }
        for (std::size_t start = 0; start < values.size();
             start += butterfly_size) {
            Fp twiddle = Fp::one();
            for (std::size_t offset = 0; offset < butterfly_size / 2;
                 ++offset) {
                const Value lo = values[start + offset];
                const Value hi =
                    values[start + offset + butterfly_size / 2] * twiddle;
                values[start + offset] = lo + hi;
                values[start + offset + butterfly_size / 2] = lo - hi;
                twiddle *= stage_generator;
            }
        }
    }
}

template <typename Value>
std::vector<Value> mobius_transform(std::span<const Value> values,
                                    bool inverse) {
    (void)log2_exact(values.size());
    std::vector<Value> result(values.begin(), values.end());
    for (std::size_t bit = 1; bit < result.size(); bit <<= 1U) {
        for (std::size_t index = 0; index < result.size(); ++index) {
            if ((index & bit) != 0) {
                if (inverse) {
                    result[index] += result[index ^ bit];
                } else {
                    result[index] -= result[index ^ bit];
                }
            }
        }
    }
    return result;
}

template <typename Value>
std::vector<Value> encode(std::span<const Value> coefficients,
                          std::size_t log_rate) {
    const std::size_t encoded_size =
        codeword_length(coefficients.size(), log_rate);
    std::vector<Value> result(coefficients.begin(), coefficients.end());
    result.resize(encoded_size, Value::zero());
    ntt(result, Fp::two_adic_generator(log2_exact(encoded_size)));
    return result;
}

} // namespace

void ntt_in_place(std::vector<Fp> &values, const Fp &generator) {
    ntt(values, generator);
}

void ntt_in_place(std::vector<Fpk> &values, const Fp &generator) {
    ntt(values, generator);
}

std::vector<Fp> evaluations_to_coefficients(std::span<const Fp> values) {
    return mobius_transform(values, false);
}

std::vector<Fpk> evaluations_to_coefficients(std::span<const Fpk> values) {
    return mobius_transform(values, false);
}

std::vector<Fp> coefficients_to_evaluations(std::span<const Fp> values) {
    return mobius_transform(values, true);
}

std::vector<Fp> reed_solomon_encode(std::span<const Fp> coefficients,
                                    std::size_t log_rate) {
    return encode(coefficients, log_rate);
}

std::vector<Fpk> reed_solomon_encode(std::span<const Fpk> coefficients,
                                     std::size_t log_rate) {
    return encode(coefficients, log_rate);
}

} // namespace laminate::basefold
