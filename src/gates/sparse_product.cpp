#include "laminate/gates/sparse_product.hpp"

#include "laminate/basefold/common.hpp"

#include <algorithm>
#include <bit>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string_view>
#include <utility>

namespace laminate::gates::sparse {
namespace {

constexpr std::string_view kStatementLabel =
    "Laminate/gates/sparse/v1/statement";
constexpr std::string_view kRootRoundLabel =
    "Laminate/gates/sparse/v1/root-round";
constexpr std::string_view kLayerRoundLabel =
    "Laminate/gates/sparse/v1/layer-round";
constexpr std::string_view kLayerClaimsLabel =
    "Laminate/gates/sparse/v1/layer-claims";

bool is_power_of_two(std::size_t value) {
    return value != 0 && (value & (value - 1U)) == 0;
}

bool factor_count_fits(std::size_t factor_count) {
    return factor_count != 0 &&
           factor_count <=
               (std::numeric_limits<std::size_t>::max() >> 1U) + 1U;
}

void append_u64(std::vector<std::uint8_t> &output, std::size_t value) {
    const std::uint64_t encoded = static_cast<std::uint64_t>(value);
    for (std::size_t byte = 0; byte < sizeof(encoded); ++byte) {
        output.push_back(static_cast<std::uint8_t>(
            (encoded >> (8U * byte)) & std::uint64_t{0xff}));
    }
}

void observe_statement(std::size_t message_size,
                       std::size_t address_variables,
                       std::span<const Fpk> query_point_msb,
                       const Fpk &claimed, PublicCoin &public_coin) {
    std::vector<std::uint8_t> bytes;
    append_u64(bytes, message_size);
    append_u64(bytes, address_variables);
    std::vector<Fpk> fields(query_point_msb.begin(),
                            query_point_msb.end());
    fields.push_back(claimed);
    const std::vector<std::uint8_t> encoded =
        basefold::serialize_values(fields);
    bytes.insert(bytes.end(), encoded.begin(), encoded.end());
    public_coin.observe(kStatementLabel, bytes);
}

void observe_root_round(const Fpk &at_one, PublicCoin &public_coin) {
    const std::array<Fpk, 1> values{at_one};
    public_coin.observe(kRootRoundLabel,
                        basefold::serialize_values(values));
}

void observe_layer_round(const std::array<Fpk, 2> &round,
                         PublicCoin &public_coin) {
    public_coin.observe(kLayerRoundLabel,
                        basefold::serialize_values(round));
}

void observe_layer_claims(const Fpk &left, const Fpk &right,
                          PublicCoin &public_coin) {
    const std::array<Fpk, 2> values{left, right};
    public_coin.observe(kLayerClaimsLabel,
                        basefold::serialize_values(values));
}

bool bit_msb(std::size_t address, std::size_t variable,
             std::size_t variables) {
    return ((address >> (variables - 1U - variable)) & 1U) != 0;
}

bool address_fits(std::size_t address, std::size_t variables) {
    constexpr std::size_t digits =
        std::numeric_limits<std::size_t>::digits;
    return variables >= digits || address < (std::size_t{1} << variables);
}

void validate_statement_shape(std::size_t message_size,
                              std::size_t address_variables,
                              std::span<const Fpk> query_point_msb) {
    constexpr std::size_t digits =
        std::numeric_limits<std::size_t>::digits;
    if (!is_power_of_two(message_size) ||
        address_variables > digits ||
        query_point_msb.size() != address_variables ||
        !factor_count_fits(address_variables + 1U)) {
        throw std::invalid_argument(
            "sparse product has an invalid statement shape");
    }
}

void validate_entries(std::span<const SparseEntry> entries,
                      std::size_t message_size,
                      std::size_t address_variables) {
    if (entries.size() > message_size) {
        throw std::invalid_argument(
            "sparse product has more entries than message slots");
    }
    for (const SparseEntry &entry : entries) {
        if (!address_fits(entry.address, address_variables)) {
            throw std::invalid_argument(
                "sparse product entry address exceeds its domain");
        }
    }
}

Fpk equality_weight_lsb(std::size_t index,
                        std::span<const Fpk> point_lsb) {
    Fpk result = Fpk::one();
    for (std::size_t variable = 0; variable < point_lsb.size(); ++variable) {
        result *= ((index >> variable) & 1U) != 0
                      ? point_lsb[variable]
                      : Fpk::one() - point_lsb[variable];
    }
    return result;
}

std::vector<Fpk> equality_table_lsb(std::span<const Fpk> point_lsb) {
    std::vector<Fpk> table{Fpk::one()};
    for (auto coordinate = point_lsb.rbegin();
         coordinate != point_lsb.rend(); ++coordinate) {
        std::vector<Fpk> expanded(table.size() * 2U, Fpk::zero());
        for (std::size_t index = 0; index < table.size(); ++index) {
            const Fpk high = *coordinate * table[index];
            expanded[2U * index] = table[index] - high;
            expanded[2U * index + 1U] = high;
        }
        table = std::move(expanded);
    }
    return table;
}

void remove_lsb_variable_in_place(std::vector<Fpk> &table) {
    if (table.size() < 2U || (table.size() & 1U) != 0) {
        throw std::invalid_argument(
            "sparse product cannot remove a variable from this table");
    }
    const std::size_t half = table.size() / 2U;
    for (std::size_t index = 0; index < half; ++index) {
        table[index] = table[2U * index] + table[2U * index + 1U];
    }
    table.resize(half);
}

void fold_adjacent_in_place(std::vector<Fpk> &table,
                            const Fpk &challenge) {
    if (table.size() < 2U || (table.size() & 1U) != 0) {
        throw std::invalid_argument(
            "sparse product cannot fold an odd table");
    }
    const std::size_t half = table.size() / 2U;
    for (std::size_t index = 0; index < half; ++index) {
        const Fpk lo = table[2U * index];
        const Fpk hi = table[2U * index + 1U];
        table[index] = lo + challenge * (hi - lo);
    }
    table.resize(half);
}

void fold_node_major_entries_in_place(std::vector<Fpk> &table,
                                      std::size_t node_count,
                                      std::size_t entry_count,
                                      const Fpk &challenge) {
    if (entry_count < 2U || (entry_count & 1U) != 0 ||
        node_count > std::numeric_limits<std::size_t>::max() / entry_count ||
        table.size() != node_count * entry_count) {
        throw std::invalid_argument(
            "sparse product cannot fold this node-major table");
    }
    const std::size_t next_entries = entry_count / 2U;
    for (std::size_t node = 0; node < node_count; ++node) {
        for (std::size_t entry = 0; entry < next_entries; ++entry) {
            const Fpk lo = table[node * entry_count + 2U * entry];
            const Fpk hi =
                table[node * entry_count + 2U * entry + 1U];
            table[node * next_entries + entry] =
                lo + challenge * (hi - lo);
        }
    }
    table.resize(node_count * next_entries);
}

Fpk interpolate_linear(const Fpk &at_zero, const Fpk &at_one,
                       const Fpk &point) {
    return at_zero + point * (at_one - at_zero);
}

Fpk interpolate_quadratic(const Fpk &at_zero, const Fpk &at_one,
                          const Fpk &at_two, const Fpk &point) {
    const Fpk one = Fpk::one();
    const Fpk two = one + one;
    const Fpk inverse_two = Fpk::from_base(Fp(2).inverse());
    const Fpk l0 = (point - one) * (point - two) * inverse_two;
    const Fpk l1 = point * (point - two);
    const Fpk l2 = point * (point - one) * inverse_two;
    return at_zero * l0 - at_one * l1 + at_two * l2;
}

class RelationFactorOracle {
  public:
    RelationFactorOracle(std::span<const SparseEntry> entries,
                         std::size_t message_size,
                         std::size_t address_variables,
                         std::span<const Fpk> query_point_msb)
        : entries_(entries), message_size_(message_size),
          address_variables_(address_variables),
          query_point_msb_(query_point_msb) {
        zero_selectors_.reserve(query_point_msb.size());
        for (const Fpk &coordinate : query_point_msb) {
            zero_selectors_.push_back(Fpk::one() - coordinate);
        }
    }

    std::size_t factor_count() const { return 1U + address_variables_; }
    std::size_t entry_count() const { return message_size_; }

    Fpk at(std::size_t factor, std::size_t entry) const {
        const bool padding = entry >= entries_.size();
        if (factor == 0) {
            return padding ? Fpk::zero()
                           : Fpk::from_base(entries_[entry].value);
        }
        const std::size_t bit = factor - 1U;
        const bool one = !padding &&
                         bit_msb(entries_[entry].address, bit,
                                 address_variables_);
        return one ? query_point_msb_[bit] : zero_selectors_[bit];
    }

  private:
    std::span<const SparseEntry> entries_;
    std::size_t message_size_ = 0;
    std::size_t address_variables_ = 0;
    std::span<const Fpk> query_point_msb_;
    std::vector<Fpk> zero_selectors_;
};

struct EvaluationLayer {
    std::size_t node_count = 0;
    std::size_t entry_count = 0;
    std::vector<Fpk> values;

    const Fpk &at(std::size_t node, std::size_t entry) const {
        return values[node * entry_count + entry];
    }
};

Fpk padded_factor_value(const RelationFactorOracle &factors,
                        std::size_t factor, std::size_t entry) {
    return factor < factors.factor_count() ? factors.at(factor, entry)
                                           : Fpk::one();
}

Fpk factor_group_product(const RelationFactorOracle &factors,
                         std::size_t first_factor,
                         std::size_t group_size, std::size_t entry) {
    Fpk product = padded_factor_value(factors, first_factor, entry);
    for (std::size_t offset = 1; offset < group_size; ++offset) {
        product *= padded_factor_value(
            factors, first_factor + offset, entry);
    }
    return product;
}

EvaluationLayer materialize_factor_groups(
    const RelationFactorOracle &factors,
    std::size_t padded_factor_count, std::size_t group_size) {
    if (!is_power_of_two(group_size) ||
        group_size > padded_factor_count ||
        (padded_factor_count % group_size) != 0) {
        throw std::invalid_argument(
            "sparse product checkpoint group is invalid");
    }
    EvaluationLayer layer;
    layer.node_count = padded_factor_count / group_size;
    layer.entry_count = factors.entry_count();
    if (layer.node_count >
        std::numeric_limits<std::size_t>::max() / layer.entry_count) {
        throw std::overflow_error(
            "sparse product checkpoint table overflows size_t");
    }
    layer.values.reserve(layer.node_count * layer.entry_count);
    for (std::size_t node = 0; node < layer.node_count; ++node) {
        for (std::size_t entry = 0; entry < layer.entry_count; ++entry) {
            layer.values.push_back(factor_group_product(
                factors, node * group_size, group_size, entry));
        }
    }
    return layer;
}

std::vector<EvaluationLayer> build_checkpoint_layers(
    const RelationFactorOracle &factors,
    std::size_t padded_factor_count,
    std::size_t checkpoint_group_size) {
    std::vector<EvaluationLayer> layers;
    layers.reserve(basefold::log2_exact(
                       padded_factor_count / checkpoint_group_size) +
                   1U);
    layers.push_back(materialize_factor_groups(
        factors, padded_factor_count, checkpoint_group_size));
    while (layers.back().node_count > 1U) {
        const EvaluationLayer &children = layers.back();
        EvaluationLayer parents;
        parents.node_count = children.node_count / 2U;
        parents.entry_count = children.entry_count;
        if (parents.node_count >
            std::numeric_limits<std::size_t>::max() /
                parents.entry_count) {
            throw std::overflow_error(
                "sparse product checkpoint tree overflows size_t");
        }
        parents.values.reserve(parents.node_count * parents.entry_count);
        for (std::size_t node = 0; node < parents.node_count; ++node) {
            for (std::size_t entry = 0; entry < parents.entry_count;
                 ++entry) {
                parents.values.push_back(
                    children.at(2U * node, entry) *
                    children.at(2U * node + 1U, entry));
            }
        }
        layers.push_back(std::move(parents));
    }
    return layers;
}

struct RootOutput {
    std::vector<Fpk> rounds;
    std::vector<Fpk> point_lsb;
    Fpk terminal_claim = Fpk::zero();
};

RootOutput prove_root_sumcheck(std::vector<Fpk> table,
                               const Fpk &claimed,
                               PublicCoin &public_coin) {
    Fpk actual = Fpk::zero();
    for (const Fpk &value : table) {
        actual += value;
    }
    if (!(actual == claimed)) {
        throw std::invalid_argument(
            "sparse product root does not match the claimed evaluation");
    }

    RootOutput output;
    const std::size_t round_count = basefold::log2_exact(table.size());
    output.rounds.reserve(round_count);
    output.point_lsb.reserve(round_count);
    for (std::size_t round = 0; round < round_count; ++round) {
        Fpk at_one = Fpk::zero();
        for (std::size_t index = 1; index < table.size(); index += 2U) {
            at_one += table[index];
        }
        observe_root_round(at_one, public_coin);
        output.rounds.push_back(at_one);
        const Fpk challenge = public_coin.challenge_fpk();
        output.point_lsb.push_back(challenge);
        fold_adjacent_in_place(table, challenge);
    }
    output.terminal_claim = table.front();
    return output;
}

void accumulate_layer_pair(const Fpk &left_zero,
                           const Fpk &left_one,
                           const Fpk &right_zero,
                           const Fpk &right_one,
                           const Fpk &equality_weight,
                           bool transmit_at_zero, Fpk &endpoint,
                           Fpk &at_two) {
    const Fpk left_two = left_one + left_one - left_zero;
    const Fpk right_two = right_one + right_one - right_zero;
    endpoint += equality_weight *
                (transmit_at_zero ? left_zero * right_zero
                                  : left_one * right_one);
    at_two += equality_weight * left_two * right_two;
}

struct LayerOutput {
    std::vector<std::array<Fpk, 2>> rounds;
    std::vector<Fpk> point_lsb;
    Fpk left_claim = Fpk::zero();
    Fpk right_claim = Fpk::zero();
};

template <typename ChildValue>
LayerOutput prove_layer_sumcheck_streamed(
    std::size_t entry_count, std::size_t parent_count,
    std::span<const Fpk> entry_eq_point_lsb,
    std::span<const Fpk> gate_eq_point_lsb,
    ChildValue child_value, PublicCoin &public_coin) {
    if (!is_power_of_two(entry_count) ||
        !is_power_of_two(parent_count) ||
        entry_eq_point_lsb.size() !=
            basefold::log2_exact(entry_count) ||
        gate_eq_point_lsb.size() !=
            basefold::log2_exact(parent_count) ||
        parent_count >
            std::numeric_limits<std::size_t>::max() / entry_count) {
        throw std::invalid_argument(
            "sparse product layer has an invalid shape");
    }

    std::vector<Fpk> gate_equality =
        equality_table_lsb(gate_eq_point_lsb);
    LayerOutput output;
    output.rounds.reserve(entry_eq_point_lsb.size() +
                          gate_eq_point_lsb.size());
    output.point_lsb.reserve(entry_eq_point_lsb.size() +
                             gate_eq_point_lsb.size());
    std::vector<Fpk> left;
    std::vector<Fpk> right;

    if (entry_count == 1U) {
        left.reserve(parent_count);
        right.reserve(parent_count);
        for (std::size_t parent = 0; parent < parent_count; ++parent) {
            left.push_back(child_value(2U * parent, 0));
            right.push_back(child_value(2U * parent + 1U, 0));
        }
    } else {
        const std::span<const Fpk> entry_suffix =
            entry_eq_point_lsb.subspan(1);
        std::vector<Fpk> entry_equality =
            equality_table_lsb(entry_suffix);
        const std::size_t first_entries = entry_count / 2U;
        const bool transmit_at_zero =
            entry_eq_point_lsb.front() == Fpk::one();
        Fpk endpoint = Fpk::zero();
        Fpk at_two = Fpk::zero();
        for (std::size_t parent = 0; parent < parent_count; ++parent) {
            for (std::size_t entry = 0; entry < first_entries; ++entry) {
                const std::size_t lo = 2U * entry;
                const std::size_t hi = lo + 1U;
                const Fpk equality_weight =
                    entry_equality[entry] * gate_equality[parent];
                accumulate_layer_pair(
                    child_value(2U * parent, lo),
                    child_value(2U * parent, hi),
                    child_value(2U * parent + 1U, lo),
                    child_value(2U * parent + 1U, hi),
                    equality_weight, transmit_at_zero, endpoint, at_two);
            }
        }
        const std::array<Fpk, 2> first_round{endpoint, at_two};
        observe_layer_round(first_round, public_coin);
        output.rounds.push_back(first_round);
        const Fpk first_challenge = public_coin.challenge_fpk();
        output.point_lsb.push_back(first_challenge);

        const std::size_t first_size = parent_count * first_entries;
        left.reserve(first_size);
        right.reserve(first_size);
        for (std::size_t parent = 0; parent < parent_count; ++parent) {
            for (std::size_t entry = 0; entry < first_entries; ++entry) {
                const std::size_t lo = 2U * entry;
                const std::size_t hi = lo + 1U;
                const Fpk left_zero = child_value(2U * parent, lo);
                const Fpk left_one = child_value(2U * parent, hi);
                const Fpk right_zero =
                    child_value(2U * parent + 1U, lo);
                const Fpk right_one =
                    child_value(2U * parent + 1U, hi);
                left.push_back(left_zero +
                               first_challenge *
                                   (left_one - left_zero));
                right.push_back(right_zero +
                                first_challenge *
                                    (right_one - right_zero));
            }
        }

        std::size_t current_entries = first_entries;
        while (current_entries > 1U) {
            remove_lsb_variable_in_place(entry_equality);
            const std::size_t pairs_per_parent =
                current_entries / 2U;
            const std::size_t variable = output.point_lsb.size();
            const bool transmit_at_zero =
                entry_eq_point_lsb[variable] == Fpk::one();
            endpoint = Fpk::zero();
            at_two = Fpk::zero();
            for (std::size_t parent = 0; parent < parent_count; ++parent) {
                for (std::size_t pair = 0; pair < pairs_per_parent;
                     ++pair) {
                    const std::size_t lo =
                        parent * current_entries + 2U * pair;
                    const std::size_t hi = lo + 1U;
                    const Fpk equality_weight =
                        entry_equality[pair] * gate_equality[parent];
                    accumulate_layer_pair(left[lo], left[hi], right[lo],
                                          right[hi], equality_weight,
                                          transmit_at_zero, endpoint,
                                          at_two);
                }
            }
            const std::array<Fpk, 2> round{endpoint, at_two};
            observe_layer_round(round, public_coin);
            output.rounds.push_back(round);
            const Fpk challenge = public_coin.challenge_fpk();
            output.point_lsb.push_back(challenge);
            fold_node_major_entries_in_place(
                left, parent_count, current_entries, challenge);
            fold_node_major_entries_in_place(
                right, parent_count, current_entries, challenge);
            current_entries = pairs_per_parent;
        }
    }

    std::size_t current_parents = parent_count;
    while (current_parents > 1U) {
        remove_lsb_variable_in_place(gate_equality);
        const std::size_t pairs = current_parents / 2U;
        const std::size_t gate_variable =
            output.point_lsb.size() - entry_eq_point_lsb.size();
        const bool transmit_at_zero =
            gate_eq_point_lsb[gate_variable] == Fpk::one();
        Fpk endpoint = Fpk::zero();
        Fpk at_two = Fpk::zero();
        for (std::size_t pair = 0; pair < pairs; ++pair) {
            accumulate_layer_pair(
                left[2U * pair], left[2U * pair + 1U],
                right[2U * pair], right[2U * pair + 1U],
                gate_equality[pair], transmit_at_zero, endpoint, at_two);
        }
        const std::array<Fpk, 2> round{endpoint, at_two};
        observe_layer_round(round, public_coin);
        output.rounds.push_back(round);
        const Fpk challenge = public_coin.challenge_fpk();
        output.point_lsb.push_back(challenge);
        fold_node_major_entries_in_place(
            left, 1U, current_parents, challenge);
        fold_node_major_entries_in_place(
            right, 1U, current_parents, challenge);
        current_parents = pairs;
    }

    output.left_claim = left.front();
    output.right_claim = right.front();
    return output;
}

struct SumcheckVerification {
    bool ok = false;
    std::vector<Fpk> point_lsb;
    Fpk final_claim = Fpk::zero();
};

SumcheckVerification verify_root_sumcheck(
    std::span<const Fpk> rounds, const Fpk &claimed,
    PublicCoin &public_coin) {
    SumcheckVerification result;
    result.point_lsb.reserve(rounds.size());
    Fpk running = claimed;
    for (const Fpk &at_one : rounds) {
        const Fpk at_zero = running - at_one;
        observe_root_round(at_one, public_coin);
        const Fpk challenge = public_coin.challenge_fpk();
        result.point_lsb.push_back(challenge);
        running = interpolate_linear(at_zero, at_one, challenge);
    }
    result.ok = true;
    result.final_claim = running;
    return result;
}

SumcheckVerification verify_layer_sumcheck(
    std::span<const std::array<Fpk, 2>> rounds,
    const Fpk &claimed,
    std::span<const Fpk> equality_point_lsb,
    PublicCoin &public_coin) {
    SumcheckVerification result;
    if (rounds.size() != equality_point_lsb.size()) {
        return result;
    }
    result.point_lsb.reserve(rounds.size());
    Fpk running = claimed;
    for (std::size_t index = 0; index < rounds.size(); ++index) {
        const Fpk &tau = equality_point_lsb[index];
        const bool singular = tau == Fpk::one();
        // The Gruen identity is
        //   running = (1-tau)S(0) + tau*S(1).
        // Normally the proof sends S(1) and the verifier recovers S(0).
        // At tau=1, S(1)=running, so sending S(0) instead avoids division by
        // zero without changing the proof shape or transcript length.
        const Fpk at_zero =
            singular
                ? rounds[index][0]
                : (running - tau * rounds[index][0]) *
                      (Fpk::one() - tau).inverse();
        const Fpk at_one = singular ? running : rounds[index][0];
        const Fpk &at_two = rounds[index][1];
        observe_layer_round(rounds[index], public_coin);
        const Fpk challenge = public_coin.challenge_fpk();
        result.point_lsb.push_back(challenge);
        running = interpolate_quadratic(
            at_zero, at_one, at_two, challenge);
    }
    result.ok = true;
    // Each Gruen round strips the current equality factor before
    // interpolation, so the terminal claim is the child product itself.
    result.final_claim = running;
    return result;
}

} // namespace

Fpk evaluate_sparse_entries(std::span<const SparseEntry> entries,
                            std::size_t address_variables,
                            std::span<const Fpk> query_point_msb) {
    validate_statement_shape(1U, address_variables, query_point_msb);
    validate_entries(entries, std::max<std::size_t>(entries.size(), 1U),
                     address_variables);
    // Cache equality factors in small chunks to bound allocation independently
    // of the complete address space.
    constexpr std::size_t maximum_chunk_bits = 8;
    const std::size_t chunk_bits = std::min(
        maximum_chunk_bits,
        std::max<std::size_t>(1, std::bit_width(entries.size())));
    struct Chunk {
        std::size_t shift;
        std::size_t mask;
        std::vector<Fpk> weights;
    };
    std::vector<Chunk> chunks;
    for (std::size_t begin = 0; begin < address_variables;
         begin += chunk_bits) {
        const std::size_t bits =
            std::min(chunk_bits, address_variables - begin);
        std::vector<Fpk> weights(std::size_t{1} << bits, Fpk::zero());
        weights[0] = Fpk::one();
        std::size_t width = 1;
        for (std::size_t bit = 0; bit < bits; ++bit) {
            const Fpk &coordinate = query_point_msb[begin + bit];
            for (std::size_t index = width; index-- > 0;) {
                const Fpk low = weights[index];
                const Fpk high = low * coordinate;
                weights[2 * index] = low - high;
                weights[2 * index + 1] = high;
            }
            width *= 2;
        }
        chunks.push_back({address_variables - begin - bits,
                          weights.size() - 1, std::move(weights)});
    }
    Fpk result = Fpk::zero();
    for (const SparseEntry &entry : entries) {
        Fpk weight = Fpk::one();
        for (const auto &chunk : chunks) {
            weight *= chunk.weights[(entry.address >> chunk.shift) & chunk.mask];
        }
        result += weight * entry.value;
    }
    return result;
}

SparseProductProverOutput prove_sparse_evaluation(
    std::span<const SparseEntry> entries, std::size_t message_size,
    std::size_t address_variables,
    std::span<const Fpk> query_point_msb, const Fpk &claimed,
    PublicCoin &public_coin) {
    validate_statement_shape(message_size, address_variables,
                             query_point_msb);
    validate_entries(entries, message_size, address_variables);
    observe_statement(message_size, address_variables, query_point_msb,
                      claimed, public_coin);

    const RelationFactorOracle factors(
        entries, message_size, address_variables, query_point_msb);
    const std::size_t padded_factor_count =
        std::bit_ceil(factors.factor_count());
    const std::size_t layer_count =
        basefold::log2_exact(padded_factor_count);
    constexpr std::size_t checkpoint_limit = 8U;
    constexpr std::size_t minimum_materialized_group = 4U;
    const std::size_t checkpoint_group =
        std::min(checkpoint_limit, padded_factor_count);
    std::vector<EvaluationLayer> checkpoints = build_checkpoint_layers(
        factors, padded_factor_count, checkpoint_group);

    SparseProductProverOutput output;
    RootOutput root = prove_root_sumcheck(
        std::move(checkpoints.back().values), claimed, public_coin);
    output.proof.root_rounds = std::move(root.rounds);
    std::vector<Fpk> entry_point = std::move(root.point_lsb);
    std::vector<Fpk> gate_point;
    Fpk current_claim = root.terminal_claim;
    const std::size_t entry_variables = entry_point.size();

    output.proof.layers.reserve(layer_count);
    for (std::size_t layer_index = 0; layer_index < layer_count;
         ++layer_index) {
        const std::size_t parent_count =
            std::size_t{1} << layer_index;
        const std::size_t child_group =
            padded_factor_count / (2U * parent_count);
        LayerOutput layer;
        if (child_group >= checkpoint_group) {
            const std::size_t checkpoint_index =
                basefold::log2_exact(child_group / checkpoint_group);
            EvaluationLayer &children = checkpoints[checkpoint_index];
            layer = prove_layer_sumcheck_streamed(
                factors.entry_count(), parent_count, entry_point,
                gate_point,
                [&](std::size_t child, std::size_t entry) {
                    return children.at(child, entry);
                },
                public_coin);
            std::vector<Fpk>().swap(children.values);
        } else if (child_group >= minimum_materialized_group) {
            EvaluationLayer children = materialize_factor_groups(
                factors, padded_factor_count, child_group);
            layer = prove_layer_sumcheck_streamed(
                factors.entry_count(), parent_count, entry_point,
                gate_point,
                [&](std::size_t child, std::size_t entry) {
                    return children.at(child, entry);
                },
                public_coin);
        } else {
            layer = prove_layer_sumcheck_streamed(
                factors.entry_count(), parent_count, entry_point,
                gate_point,
                [&](std::size_t child, std::size_t entry) {
                    return factor_group_product(
                        factors, child * child_group, child_group,
                        entry);
                },
                public_coin);
        }

        ProductLayerProof layer_proof;
        layer_proof.rounds = std::move(layer.rounds);
        layer_proof.left_claim = layer.left_claim;
        layer_proof.right_claim = layer.right_claim;
        observe_layer_claims(layer.left_claim, layer.right_claim,
                             public_coin);
        const Fpk child_challenge = public_coin.challenge_fpk();
        current_claim =
            layer.left_claim +
            child_challenge * (layer.right_claim - layer.left_claim);

        entry_point.assign(
            layer.point_lsb.begin(),
            layer.point_lsb.begin() +
                static_cast<std::ptrdiff_t>(entry_variables));
        gate_point.assign(
            layer.point_lsb.begin() +
                static_cast<std::ptrdiff_t>(entry_variables),
            layer.point_lsb.end());
        gate_point.insert(gate_point.begin(), child_challenge);
        output.proof.layers.push_back(std::move(layer_proof));
    }

    output.reduction = SparseProductReduction{
        std::move(entry_point), std::move(gate_point), current_claim};
    return output;
}

std::optional<SparseProductReduction> verify_sparse_evaluation(
    std::size_t message_size, std::size_t address_variables,
    std::span<const Fpk> query_point_msb, const Fpk &claimed,
    const SparseProductProof &proof, PublicCoin &public_coin) {
    try {
        validate_statement_shape(message_size, address_variables,
                                 query_point_msb);
        const std::size_t entry_variables =
            basefold::log2_exact(message_size);
        const std::size_t padded_factor_count =
            std::bit_ceil(address_variables + 1U);
        const std::size_t layer_count =
            basefold::log2_exact(padded_factor_count);
        if (proof.root_rounds.size() != entry_variables ||
            proof.layers.size() != layer_count) {
            return std::nullopt;
        }
        for (std::size_t layer = 0; layer < layer_count; ++layer) {
            if (proof.layers[layer].rounds.size() !=
                entry_variables + layer) {
                return std::nullopt;
            }
        }

        observe_statement(message_size, address_variables,
                          query_point_msb, claimed, public_coin);
        const SumcheckVerification root = verify_root_sumcheck(
            proof.root_rounds, claimed, public_coin);
        if (!root.ok) {
            return std::nullopt;
        }
        std::vector<Fpk> entry_point = root.point_lsb;
        std::vector<Fpk> gate_point;
        Fpk current_claim = root.final_claim;

        for (const ProductLayerProof &layer : proof.layers) {
            std::vector<Fpk> equality_point = entry_point;
            equality_point.insert(equality_point.end(),
                                  gate_point.begin(), gate_point.end());
            const SumcheckVerification wiring =
                verify_layer_sumcheck(layer.rounds, current_claim,
                                      equality_point, public_coin);
            if (!wiring.ok ||
                !(wiring.final_claim ==
                  layer.left_claim * layer.right_claim)) {
                return std::nullopt;
            }

            observe_layer_claims(layer.left_claim, layer.right_claim,
                                 public_coin);
            const Fpk child_challenge = public_coin.challenge_fpk();
            current_claim =
                layer.left_claim +
                child_challenge *
                    (layer.right_claim - layer.left_claim);
            entry_point.assign(
                wiring.point_lsb.begin(),
                wiring.point_lsb.begin() +
                    static_cast<std::ptrdiff_t>(entry_variables));
            gate_point.assign(
                wiring.point_lsb.begin() +
                    static_cast<std::ptrdiff_t>(entry_variables),
                wiring.point_lsb.end());
            gate_point.insert(gate_point.begin(), child_challenge);
        }
        return SparseProductReduction{
            std::move(entry_point), std::move(gate_point), current_claim};
    } catch (const std::invalid_argument &) {
        return std::nullopt;
    } catch (const std::overflow_error &) {
        return std::nullopt;
    }
}

SparseLeafLinearization linearize_sparse_leaf(
    std::size_t address_variables,
    std::span<const Fpk> query_point_msb,
    std::span<const Fpk> factor_point_lsb) {
    validate_statement_shape(1U, address_variables, query_point_msb);
    const std::size_t used_factors = address_variables + 1U;
    const std::size_t padded_factors = std::bit_ceil(used_factors);
    if (factor_point_lsb.size() !=
        basefold::log2_exact(padded_factors)) {
        throw std::invalid_argument(
            "sparse product factor point has the wrong dimension");
    }

    SparseLeafLinearization result;
    result.column_weights.assign(used_factors, Fpk::zero());
    result.column_weights[0] =
        equality_weight_lsb(0, factor_point_lsb);
    for (std::size_t bit = 0; bit < address_variables; ++bit) {
        const Fpk factor_weight =
            equality_weight_lsb(1U + bit, factor_point_lsb);
        result.column_weights[1U + bit] =
            factor_weight *
            (query_point_msb[bit] + query_point_msb[bit] -
             Fpk::one());
        result.constant +=
            factor_weight * (Fpk::one() - query_point_msb[bit]);
    }
    for (std::size_t factor = used_factors;
         factor < padded_factors; ++factor) {
        result.constant +=
            equality_weight_lsb(factor, factor_point_lsb);
    }
    return result;
}

} // namespace laminate::gates::sparse
