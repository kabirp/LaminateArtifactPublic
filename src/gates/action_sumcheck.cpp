/// @file action_sumcheck.cpp
/// @brief Sparse degree-two reduction of the Wide BGV action.

#include "laminate/gates/action_sumcheck.hpp"

#include "laminate/basefold/common.hpp"
#include "laminate/poly/eq.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <map>
#include <span>
#include <stdexcept>
#include <string_view>
#include <utility>
#include <vector>

namespace laminate::gates {
namespace {

constexpr std::string_view kStatementLabel =
    "Laminate/gates/wide-action/v1/statement";
constexpr std::string_view kRoundIndexLabel =
    "Laminate/gates/wide-action/v1/round-index";
constexpr std::string_view kRoundValuesLabel =
    "Laminate/gates/wide-action/v1/round-values";
constexpr std::string_view kTerminalWeightLabel =
    "Laminate/gates/wide-action/v1/terminal-compact-weight";

struct ActionShape {
    std::size_t output_wire_variables = 0;
    std::size_t source_wire_variables = 0;
    std::size_t offset_variables = 0;
    std::size_t address_variables = 0;
    std::size_t address_count = 0;
};

struct BoundOffsetWeight {
    std::size_t offset = 0;
    Fpk compact_weight = Fpk::zero();
    Fpk prefix_weight = Fpk::one();
};

struct RoundEvaluations {
    Fpk at_zero = Fpk::zero();
    Fpk at_one = Fpk::zero();
    Fpk at_two = Fpk::zero();
};

struct CachedRoundOffset {
    std::array<Fpk, 3> compact_weights{};
    std::array<Fpk, 3> action_values{};
};

std::size_t checked_add(std::size_t left, std::size_t right,
                        const char *operation) {
    if (right > std::numeric_limits<std::size_t>::max() - left) {
        throw std::overflow_error(operation);
    }
    return left + right;
}

ActionShape validate_shape(
    std::span<const Fpk> output_wire_point,
    std::span<const Fpk> output_slot_point,
    std::span<const Fpk> source_wire_point,
    std::span<const Fpk> source_slot_point) {
    if (output_slot_point.empty() ||
        output_slot_point.size() != source_slot_point.size()) {
        throw std::invalid_argument(
            "Wide action sumcheck has inconsistent slot points");
    }
    const std::size_t wire_variables = checked_add(
        output_wire_point.size(), source_wire_point.size(),
        "Wide action wire dimension overflows");
    const std::size_t address_variables = checked_add(
        wire_variables, output_slot_point.size(),
        "Wide action address dimension overflows");
    if (address_variables >=
        std::numeric_limits<std::size_t>::digits) {
        throw std::invalid_argument(
            "Wide action address dimension exceeds size_t");
    }
    return ActionShape{
        output_wire_point.size(), source_wire_point.size(),
        output_slot_point.size(), address_variables,
        std::size_t{1} << address_variables};
}

void validate_entries(std::span<const sparse::SparseEntry> entries,
                      const ActionShape &shape) {
    for (std::size_t index = 0; index < entries.size(); ++index) {
        const sparse::SparseEntry &entry = entries[index];
        if (entry.address >= shape.address_count) {
            throw std::invalid_argument(
                "Wide action sparse address exceeds its domain");
        }
        if (entry.value.is_zero()) {
            throw std::invalid_argument(
                "Wide action sparse entries must be nonzero");
        }
        if (index != 0 &&
            entries[index - 1U].address >= entry.address) {
            throw std::invalid_argument(
                "Wide action sparse entries are not canonical");
        }
    }
}

bool bit_msb(std::size_t address, std::size_t variable,
             std::size_t variables) {
    return ((address >> (variables - 1U - variable)) & 1U) != 0;
}

Fpk selector(const Fpk &coordinate, bool bit) {
    return bit ? coordinate : Fpk::one() - coordinate;
}

std::size_t low_mask(std::size_t bits) {
    return bits == 0 ? 0 : (std::size_t{1} << bits) - 1U;
}

std::vector<Fpk> Boolean_point(std::size_t address,
                               std::size_t variables) {
    std::vector<Fpk> result;
    result.reserve(variables);
    for (std::size_t variable = 0; variable < variables; ++variable) {
        result.push_back(bit_msb(address, variable, variables)
                             ? Fpk::one()
                             : Fpk::zero());
    }
    return result;
}

std::vector<Fpk> round_offset_point(
    std::span<const Fpk> prefix, const Fpk &round_value,
    std::size_t suffix, std::size_t suffix_variables) {
    std::vector<Fpk> result;
    result.reserve(prefix.size() + 1U + suffix_variables);
    result.insert(result.end(), prefix.begin(), prefix.end());
    result.push_back(round_value);
    for (std::size_t variable = 0; variable < suffix_variables;
         ++variable) {
        result.push_back(bit_msb(suffix, variable, suffix_variables)
                             ? Fpk::one()
                             : Fpk::zero());
    }
    return result;
}

Fpk fixed_wire_weight(
    std::size_t address, const ActionShape &shape,
    std::span<const Fpk> output_wire_point,
    std::span<const Fpk> source_wire_point) {
    Fpk result = Fpk::one();
    for (std::size_t variable = 0;
         variable < shape.output_wire_variables; ++variable) {
        result *= selector(
            output_wire_point[variable],
            bit_msb(address, variable, shape.address_variables));
    }
    for (std::size_t variable = 0;
         variable < shape.source_wire_variables; ++variable) {
        result *= selector(
            source_wire_point[variable],
            bit_msb(address, shape.output_wire_variables + variable,
                    shape.address_variables));
    }
    return result;
}

std::vector<BoundOffsetWeight> bind_wire_points(
    std::span<const sparse::SparseEntry> entries,
    const ActionShape &shape,
    std::span<const Fpk> output_wire_point,
    std::span<const Fpk> source_wire_point) {
    const std::size_t offset_mask = low_mask(shape.offset_variables);
    std::map<std::size_t, Fpk> by_offset;
    for (const sparse::SparseEntry &entry : entries) {
        by_offset[entry.address & offset_mask] +=
            Fpk::from_base(entry.value) *
            fixed_wire_weight(entry.address, shape, output_wire_point,
                              source_wire_point);
    }

    std::vector<BoundOffsetWeight> result;
    result.reserve(by_offset.size());
    for (const auto &[offset, weight] : by_offset) {
        if (!weight.is_zero()) {
            result.push_back(BoundOffsetWeight{offset, weight,
                                               Fpk::one()});
        }
    }
    return result;
}

Fpk evaluate_bound_coefficient(
    std::span<const BoundOffsetWeight> offsets,
    const std::vector<Fpk> &output_slot_point,
    const std::vector<Fpk> &source_slot_point,
    std::size_t offset_variables) {
    Fpk result = Fpk::zero();
    for (const BoundOffsetWeight &offset : offsets) {
        result += offset.compact_weight *
                  poly::grid_action_eval(
                      output_slot_point, source_slot_point,
                      Boolean_point(offset.offset, offset_variables));
    }
    return result;
}

RoundEvaluations evaluate_round(
    std::span<const BoundOffsetWeight> offsets,
    std::span<const Fpk> prefix, std::size_t variable,
    const std::vector<Fpk> &output_slot_point,
    const std::vector<Fpk> &source_slot_point,
    std::size_t offset_variables) {
    if (variable != prefix.size() || variable >= offset_variables) {
        throw std::logic_error(
            "Wide action round prefix is inconsistent");
    }
    const std::size_t suffix_variables =
        offset_variables - variable - 1U;
    const std::size_t suffix_mask = low_mask(suffix_variables);
    const std::array<Fpk, 3> round_values{
        Fpk::zero(), Fpk::one(), Fpk::from_base(Fp(2))};

    // Several sparse wire entries may carry the same BGV offset, and several
    // bound offsets may collapse to the same remaining suffix.  Aggregate
    // their compact weights first, then evaluate the analytic action exactly
    // once per `(round endpoint, suffix)` cache entry.
    std::map<std::size_t, CachedRoundOffset> cache;
    for (const BoundOffsetWeight &offset : offsets) {
        const std::size_t suffix = offset.offset & suffix_mask;
        const bool current_bit =
            bit_msb(offset.offset, variable, offset_variables);
        CachedRoundOffset &cached = cache[suffix];
        for (std::size_t endpoint = 0; endpoint < round_values.size();
             ++endpoint) {
            cached.compact_weights[endpoint] +=
                offset.compact_weight * offset.prefix_weight *
                selector(round_values[endpoint], current_bit);
        }
    }

    RoundEvaluations result;
    for (auto &[suffix, cached] : cache) {
        for (std::size_t endpoint = 0; endpoint < round_values.size();
             ++endpoint) {
            cached.action_values[endpoint] = poly::grid_action_eval(
                output_slot_point, source_slot_point,
                round_offset_point(prefix, round_values[endpoint], suffix,
                                   suffix_variables));
        }
        result.at_zero +=
            cached.compact_weights[0] * cached.action_values[0];
        result.at_one +=
            cached.compact_weights[1] * cached.action_values[1];
        result.at_two +=
            cached.compact_weights[2] * cached.action_values[2];
    }
    return result;
}

Fpk interpolate_quadratic(const RoundEvaluations &round,
                          const Fpk &point) {
    const Fpk one = Fpk::one();
    const Fpk two = Fpk::from_base(Fp(2));
    const Fpk half = Fpk::from_base(Fp(2).inverse());
    return round.at_zero * (point - one) * (point - two) * half -
           round.at_one * point * (point - two) +
           round.at_two * point * (point - one) * half;
}

void append_u64(std::vector<std::uint8_t> &output,
                std::size_t value) {
    if constexpr (sizeof(std::size_t) > sizeof(std::uint64_t)) {
        if (value > std::numeric_limits<std::uint64_t>::max()) {
            throw std::overflow_error(
                "Wide action transcript length exceeds u64");
        }
    }
    const std::uint64_t encoded = static_cast<std::uint64_t>(value);
    for (std::size_t byte = 0; byte < sizeof(encoded); ++byte) {
        output.push_back(static_cast<std::uint8_t>(
            (encoded >> (8U * byte)) & std::uint64_t{0xff}));
    }
}

void append_fields(std::vector<std::uint8_t> &output,
                   std::span<const Fpk> values) {
    const std::vector<std::uint8_t> encoded =
        basefold::serialize_values(values);
    output.insert(output.end(), encoded.begin(), encoded.end());
}

void observe_statement(
    std::span<const Fpk> output_wire_point,
    std::span<const Fpk> output_slot_point,
    std::span<const Fpk> source_wire_point,
    std::span<const Fpk> source_slot_point, const Fpk &claimed_value,
    PublicCoin &public_coin) {
    std::vector<std::uint8_t> encoded;
    append_u64(encoded, output_wire_point.size());
    append_u64(encoded, output_slot_point.size());
    append_u64(encoded, source_wire_point.size());
    append_u64(encoded, source_slot_point.size());
    append_fields(encoded, output_wire_point);
    append_fields(encoded, output_slot_point);
    append_fields(encoded, source_wire_point);
    append_fields(encoded, source_slot_point);
    const std::array<Fpk, 1> claim{claimed_value};
    append_fields(encoded, claim);
    public_coin.observe(kStatementLabel, encoded);
}

void observe_round(std::size_t index,
                   const WideActionSumcheckRound &round,
                   PublicCoin &public_coin) {
    public_coin.observe(kRoundIndexLabel,
                        static_cast<std::uint64_t>(index));
    const std::array<Fpk, 2> values{round.at_one, round.at_two};
    public_coin.observe(kRoundValuesLabel,
                        basefold::serialize_values(values));
}

void observe_terminal_weight(const Fpk &value,
                             PublicCoin &public_coin) {
    const std::array<Fpk, 1> values{value};
    public_coin.observe(kTerminalWeightLabel,
                        basefold::serialize_values(values));
}

Fpk terminal_compact_weight(
    std::span<const BoundOffsetWeight> offsets) {
    Fpk result = Fpk::zero();
    for (const BoundOffsetWeight &offset : offsets) {
        result += offset.compact_weight * offset.prefix_weight;
    }
    return result;
}

void bind_offset_prefix(std::span<BoundOffsetWeight> offsets,
                        std::size_t variable,
                        std::size_t offset_variables,
                        const Fpk &challenge) {
    for (BoundOffsetWeight &offset : offsets) {
        offset.prefix_weight *= selector(
            challenge,
            bit_msb(offset.offset, variable, offset_variables));
    }
}

} // namespace

Fpk evaluate_wide_affine_coefficient(
    std::span<const sparse::SparseEntry> entries,
    std::span<const Fpk> output_wire_point,
    std::span<const Fpk> output_slot_point,
    std::span<const Fpk> source_wire_point,
    std::span<const Fpk> source_slot_point) {
    const ActionShape shape = validate_shape(
        output_wire_point, output_slot_point, source_wire_point,
        source_slot_point);
    validate_entries(entries, shape);
    const std::vector<BoundOffsetWeight> offsets = bind_wire_points(
        entries, shape, output_wire_point, source_wire_point);
    return evaluate_bound_coefficient(
        offsets,
        std::vector<Fpk>(output_slot_point.begin(),
                         output_slot_point.end()),
        std::vector<Fpk>(source_slot_point.begin(),
                         source_slot_point.end()),
        shape.offset_variables);
}

WideActionSumcheckProverOutput prove_wide_action_sumcheck(
    std::span<const sparse::SparseEntry> entries,
    std::span<const Fpk> output_wire_point,
    std::span<const Fpk> output_slot_point,
    std::span<const Fpk> source_wire_point,
    std::span<const Fpk> source_slot_point, const Fpk &claimed_value,
    PublicCoin &public_coin) {
    const ActionShape shape = validate_shape(
        output_wire_point, output_slot_point, source_wire_point,
        source_slot_point);
    validate_entries(entries, shape);
    std::vector<BoundOffsetWeight> offsets = bind_wire_points(
        entries, shape, output_wire_point, source_wire_point);
    const std::vector<Fpk> output_slots(output_slot_point.begin(),
                                         output_slot_point.end());
    const std::vector<Fpk> source_slots(source_slot_point.begin(),
                                         source_slot_point.end());

    // Reject a false input claim before the first transcript observation.
    if (evaluate_bound_coefficient(offsets, output_slots, source_slots,
                                   shape.offset_variables) !=
        claimed_value) {
        throw std::invalid_argument(
            "Wide action claimed coefficient is incorrect");
    }
    observe_statement(output_wire_point, output_slot_point,
                      source_wire_point, source_slot_point,
                      claimed_value, public_coin);

    WideActionSumcheckProverOutput output;
    output.proof.rounds.reserve(shape.offset_variables);
    output.reduction.offset_point_msb.reserve(shape.offset_variables);
    Fpk running_claim = claimed_value;
    for (std::size_t variable = 0;
         variable < shape.offset_variables; ++variable) {
        const RoundEvaluations evaluations = evaluate_round(
            offsets, output.reduction.offset_point_msb, variable,
            output_slots, source_slots, shape.offset_variables);
        if (evaluations.at_zero + evaluations.at_one !=
            running_claim) {
            throw std::logic_error(
                "Wide action sumcheck running identity failed");
        }
        const WideActionSumcheckRound round{
            evaluations.at_one, evaluations.at_two};
        output.proof.rounds.push_back(round);
        observe_round(variable, round, public_coin);
        const Fpk challenge = public_coin.challenge_fpk();
        running_claim = interpolate_quadratic(evaluations, challenge);
        bind_offset_prefix(offsets, variable, shape.offset_variables,
                           challenge);
        output.reduction.offset_point_msb.push_back(challenge);
    }

    output.reduction.compact_weight = terminal_compact_weight(offsets);
    const Fpk action_terminal = poly::grid_action_eval(
        output_slots, source_slots,
        output.reduction.offset_point_msb);
    if (running_claim !=
        output.reduction.compact_weight * action_terminal) {
        throw std::logic_error(
            "Wide action sumcheck terminal identity failed");
    }
    output.proof.terminal_compact_weight =
        output.reduction.compact_weight;
    observe_terminal_weight(output.proof.terminal_compact_weight,
                            public_coin);
    return output;
}

std::optional<WideActionSumcheckReduction> verify_wide_action_sumcheck(
    std::span<const Fpk> output_wire_point,
    std::span<const Fpk> output_slot_point,
    std::span<const Fpk> source_wire_point,
    std::span<const Fpk> source_slot_point, const Fpk &claimed_value,
    const WideActionSumcheckProof &proof, PublicCoin &public_coin) {
    try {
        const ActionShape shape = validate_shape(
            output_wire_point, output_slot_point, source_wire_point,
            source_slot_point);
        if (proof.rounds.size() != shape.offset_variables) {
            return std::nullopt;
        }

        observe_statement(output_wire_point, output_slot_point,
                          source_wire_point, source_slot_point,
                          claimed_value, public_coin);
        WideActionSumcheckReduction result;
        result.offset_point_msb.reserve(shape.offset_variables);
        Fpk running_claim = claimed_value;
        for (std::size_t variable = 0;
             variable < shape.offset_variables; ++variable) {
            const WideActionSumcheckRound &round =
                proof.rounds[variable];
            const RoundEvaluations evaluations{
                running_claim - round.at_one, round.at_one,
                round.at_two};
            observe_round(variable, round, public_coin);
            const Fpk challenge = public_coin.challenge_fpk();
            result.offset_point_msb.push_back(challenge);
            running_claim =
                interpolate_quadratic(evaluations, challenge);
        }

        result.compact_weight = proof.terminal_compact_weight;
        observe_terminal_weight(result.compact_weight, public_coin);
        const std::vector<Fpk> output_slots(output_slot_point.begin(),
                                             output_slot_point.end());
        const std::vector<Fpk> source_slots(source_slot_point.begin(),
                                             source_slot_point.end());
        const Fpk action_terminal = poly::grid_action_eval(
            output_slots, source_slots, result.offset_point_msb);
        if (running_claim != result.compact_weight * action_terminal) {
            return std::nullopt;
        }
        return result;
    } catch (const std::invalid_argument &) {
        return std::nullopt;
    } catch (const std::overflow_error &) {
        return std::nullopt;
    }
}

} // namespace laminate::gates
