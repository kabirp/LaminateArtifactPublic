/// @file claims.cpp
/// @brief GKR claim batching and direct terminal evaluation.

#include "laminate/gkr/claims.hpp"

#include "laminate/field/serialization.hpp"
#include "laminate/poly/eq.hpp"

#include <bit>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string_view>
#include <utility>
#include <vector>

namespace laminate::gkr {
namespace {

constexpr std::string_view kClaimPairLabel =
    "laminate/gkr/two-claim-batch/v1";
constexpr std::string_view kSingleClaimLabel =
    "laminate/gkr/single-claim/v1";

bool is_power_of_two(std::size_t value) {
    return value != 0 && (value & (value - 1)) == 0;
}

std::size_t log2_exact(std::size_t value, const char *operation) {
    if (!is_power_of_two(value)) {
        throw std::invalid_argument(std::string(operation) +
                                    ": dimension is not a power of two");
    }
    return std::bit_width(value) - 1U;
}

void append_u64(std::vector<std::uint8_t> &output, std::size_t value) {
    if (value > std::numeric_limits<std::uint64_t>::max()) {
        throw std::overflow_error("batch_claims: size does not fit u64");
    }
    const auto encoded = static_cast<std::uint64_t>(value);
    for (std::size_t byte = 0; byte < 8; ++byte) {
        output.push_back(static_cast<std::uint8_t>(
            (encoded >> (8U * byte)) & std::uint64_t{0xff}));
    }
}

void append_fpk(std::vector<std::uint8_t> &output, const Fpk &value) {
    const SerializedFpk encoded = serialize(value);
    output.insert(output.end(), encoded.begin(), encoded.end());
}

void append_claim(std::vector<std::uint8_t> &output,
                  const SingleClaim &claim) {
    append_u64(output, claim.point.size());
    for (const Fpk &coordinate : claim.point) {
        append_fpk(output, coordinate);
    }
    append_fpk(output, claim.value);
}

void validate_layer(std::span<const fhe::SlotVector> layer,
                    std::size_t point_size) {
    const std::size_t wire_variables =
        log2_exact(layer.size(), "evaluate_layer_mle");
    const std::size_t width = layer.front().size();
    const std::size_t slot_variables =
        log2_exact(width, "evaluate_layer_mle");
    if (wire_variables > std::numeric_limits<std::size_t>::max() -
                             slot_variables ||
        point_size != wire_variables + slot_variables) {
        throw std::invalid_argument(
            "evaluate_layer_mle: point has the wrong dimension");
    }
    for (const fhe::SlotVector &wire : layer) {
        if (wire.size() != width) {
            throw std::invalid_argument(
                "evaluate_layer_mle: layer wires have inconsistent widths");
        }
    }
}

} // namespace

void observe_claim(const SingleClaim &claim, Transcript &transcript) {
    std::vector<std::uint8_t> encoded;
    append_claim(encoded, claim);
    transcript.observe(kSingleClaimLabel, encoded);
}

BatchedClaim batch_claims(const SingleClaim &first, const SingleClaim &second,
                          Transcript &transcript) {
    if (first.point.size() != second.point.size()) {
        throw std::invalid_argument(
            "batch_claims: component point dimensions differ");
    }
    std::vector<std::uint8_t> encoded;
    append_u64(encoded, 2);
    append_claim(encoded, first);
    append_claim(encoded, second);
    transcript.observe(kClaimPairLabel, encoded);
    const Fpk challenge = transcript.challenge_fpk();
    return BatchedClaim{first, second, challenge,
                        first.value + challenge * second.value};
}

Fpk evaluate_layer_mle(std::span<const fhe::SlotVector> layer,
                       std::span<const Fpk> point) {
    validate_layer(layer, point.size());
    const std::size_t wire_variables =
        log2_exact(layer.size(), "evaluate_layer_mle");
    const std::vector<Fpk> wire_point(point.begin(),
                                      point.begin() + static_cast<std::ptrdiff_t>(
                                                          wire_variables));
    const std::vector<Fpk> slot_point(
        point.begin() + static_cast<std::ptrdiff_t>(wire_variables),
        point.end());
    const std::vector<Fpk> wire_weights = poly::eq_evaluations(wire_point);
    const std::vector<Fpk> slot_weights = poly::eq_evaluations(slot_point);

    // The layer table is a tensor indexed by (wire, slot):
    //
    //   V~(r_w,r_s) = sum_w eq(r_w,w)
    //                       * [sum_s eq(r_s,s) V[w,s]].
    //
    // Accumulating the inner slot sum uses extension-by-base products. Only
    // one full extension multiplication remains per wire.
    Fpk result = Fpk::zero();
    for (std::size_t wire = 0; wire < layer.size(); ++wire) {
        Fpk slot_evaluation = Fpk::zero();
        for (std::size_t slot = 0; slot < layer[wire].size(); ++slot) {
            slot_evaluation +=
                slot_weights[slot] * layer[wire][slot];
        }
        result += wire_weights[wire] * slot_evaluation;
    }
    return result;
}

Fpk evaluate_prefix_input_mle(std::span<const Fp> logical_input,
                              std::span<const Fpk> point) {
    const std::size_t input_variables =
        log2_exact(logical_input.size(), "evaluate_prefix_input_mle");
    if (point.size() < input_variables) {
        throw std::invalid_argument(
            "evaluate_prefix_input_mle: point is too short");
    }

    const std::size_t padding_variables = point.size() - input_variables;
    Fpk zero_prefix_weight = Fpk::one();
    for (std::size_t variable = 0; variable < padding_variables;
         ++variable) {
        zero_prefix_weight *= Fpk::one() - point[variable];
    }
    const std::vector<Fpk> input_point(
        point.end() - static_cast<std::ptrdiff_t>(input_variables),
        point.end());
    const std::vector<Fpk> lagrange_basis =
        poly::eq_evaluations(input_point);

    // The logical values occupy addresses (0,...,0,i) in the full table, so
    //
    //   V~(r_prefix,r_i)
    //     = [prod_j (1-r_prefix[j])] * sum_i eq(r_i,i) x[i].
    //
    // This is one inner product of F_{p^k} Lagrange weights with base-field
    // input values. No explicit zero padding is allocated or scanned.
    Fpk result = Fpk::zero();
    for (std::size_t index = 0; index < logical_input.size(); ++index) {
        result += lagrange_basis[index] * logical_input[index];
    }
    return zero_prefix_weight * result;
}

SingleClaim make_layer_claim(std::span<const fhe::SlotVector> layer,
                             std::vector<Fpk> point) {
    const Fpk value = evaluate_layer_mle(layer, point);
    return SingleClaim{std::move(point), value};
}

bool verify_terminal_claim(std::span<const fhe::SlotVector> input_layer,
                           const SingleClaim &claim) {
    try {
        return evaluate_layer_mle(input_layer, claim.point) == claim.value;
    } catch (const std::invalid_argument &) {
        return false;
    }
}

bool verify_terminal_claim(std::span<const fhe::SlotVector> input_layer,
                           const BatchedClaim &claim) {
    if (claim.first.point.size() != claim.second.point.size() ||
        claim.value !=
            claim.first.value + claim.challenge * claim.second.value) {
        return false;
    }
    try {
        const Fpk expected =
            evaluate_layer_mle(input_layer, claim.first.point) +
            claim.challenge *
                evaluate_layer_mle(input_layer, claim.second.point);
        return claim.value == expected;
    } catch (const std::invalid_argument &) {
        return false;
    }
}

bool verify_terminal_claim(std::span<const fhe::SlotVector> input_layer,
                           const LayerClaim &claim) {
    return std::visit(
        [&](const auto &typed_claim) {
            return verify_terminal_claim(input_layer, typed_claim);
        },
        claim);
}

bool verify_prefix_input_claim(std::span<const Fp> logical_input,
                               const SingleClaim &claim) {
    try {
        return evaluate_prefix_input_mle(logical_input, claim.point) ==
               claim.value;
    } catch (const std::invalid_argument &) {
        return false;
    }
}

bool verify_prefix_input_claim(std::span<const Fp> logical_input,
                               const BatchedClaim &claim) {
    if (claim.first.point.size() != claim.second.point.size() ||
        claim.value !=
            claim.first.value + claim.challenge * claim.second.value) {
        return false;
    }
    try {
        const Fpk expected =
            evaluate_prefix_input_mle(logical_input, claim.first.point) +
            claim.challenge *
                evaluate_prefix_input_mle(logical_input,
                                          claim.second.point);
        return claim.value == expected;
    } catch (const std::invalid_argument &) {
        return false;
    }
}

bool verify_prefix_input_claim(std::span<const Fp> logical_input,
                               const LayerClaim &claim) {
    return std::visit(
        [&](const auto &typed_claim) {
            return verify_prefix_input_claim(logical_input, typed_claim);
        },
        claim);
}

} // namespace laminate::gkr
