#include "laminate/payload/fixtures/workloads.hpp"

#include "laminate/params.hpp"

#include <algorithm>
#include <array>
#include <functional>
#include <limits>
#include <stdexcept>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace laminate::payload {
namespace {

class StableRandom {
  public:
    explicit StableRandom(std::uint64_t seed) : state_(seed) {}

    std::uint64_t next() {
        state_ += 0x9e3779b97f4a7c15ULL;
        std::uint64_t value = state_;
        value = (value ^ (value >> 30U)) * 0xbf58476d1ce4e5b9ULL;
        value = (value ^ (value >> 27U)) * 0x94d049bb133111ebULL;
        return value ^ (value >> 31U);
    }

    Fp field() { return Fp(next() % kBaseFieldOrder); }

    std::size_t bounded(std::size_t bound) {
        if (bound == 0) {
            throw std::invalid_argument(
                "StableRandom::bounded requires a nonzero bound");
        }
        const std::uint64_t threshold =
            (std::uint64_t{0} - static_cast<std::uint64_t>(bound)) %
            static_cast<std::uint64_t>(bound);
        std::uint64_t value = 0;
        do {
            value = next();
        } while (value < threshold);
        return static_cast<std::size_t>(
            value % static_cast<std::uint64_t>(bound));
    }

  private:
    std::uint64_t state_;
};

template <typename T>
void stable_shuffle(std::vector<T> &values, StableRandom &random) {
    for (std::size_t remaining = values.size(); remaining > 1;
         --remaining) {
        std::swap(values[remaining - 1],
                  values[random.bounded(remaining)]);
    }
}

struct BudgetGeometry {
    std::size_t multiplication_gates = 0;
    std::size_t addition_gates = 0;
    std::size_t scalar_gates = 0;
    std::size_t rotation_gates = 0;
    std::size_t plaintext_multiplications = 0;
    std::vector<std::size_t> multiplication_widths;
};

BudgetGeometry budget_geometry(const WorkloadSpec &spec) {
    if (!spec.operation_count || *spec.operation_count == 0 ||
        *spec.operation_count >
            (std::numeric_limits<std::size_t>::max() - 10U) / 17U ||
        spec.multiplication_widths.size() != spec.multiplicative_depth) {
        throw std::invalid_argument(
            "make_workload: budgeted workload requires an operation count "
            "and one CT-CT width per multiplication level");
    }
    const std::size_t operations = *spec.operation_count;
    BudgetGeometry result;
    if (spec.kind == WorkloadKind::BalancedLaned) {
        result.multiplication_gates = operations / 2U;
        result.addition_gates = (9U * operations + 10U) / 20U;
        result.scalar_gates = operations - result.multiplication_gates -
                              result.addition_gates;
    } else {
        result.multiplication_gates = (17U * operations + 10U) / 20U;
        result.addition_gates = (operations + 5U) / 10U;
        const std::size_t wide_gates = operations -
            result.multiplication_gates - result.addition_gates;
        result.plaintext_multiplications = wide_gates / 2U;
        result.rotation_gates = wide_gates -
                                result.plaintext_multiplications;
        if (spec.shape.kind != PayloadKind::Wide ||
            spec.multiplicative_depth < 2) {
            throw std::invalid_argument(
                "make_workload: multiplication pyramid requires Wide shape "
                "and at least two multiplication levels");
        }
    }
    result.multiplication_widths = spec.multiplication_widths;
    std::size_t sum = 0;
    for (const std::size_t width : result.multiplication_widths) {
        if (width == 0 || width > result.multiplication_gates - sum) {
            throw std::invalid_argument(
                "make_workload: invalid budgeted multiplication width");
        }
        sum += width;
    }
    if (sum != result.multiplication_gates ||
        spec.width != result.multiplication_widths.front() ||
        result.multiplication_widths.back() - 1U > result.addition_gates) {
        throw std::invalid_argument(
            "make_workload: multiplication widths disagree with gate budget");
    }
    return result;
}

struct WirePair {
    WireId left;
    WireId right;
    bool operator==(const WirePair &) const = default;
};

struct WirePairHash {
    std::size_t operator()(const WirePair &pair) const {
        const std::size_t a = std::hash<WireId>{}(pair.left);
        const std::size_t b = std::hash<WireId>{}(pair.right);
        return a ^ (b + 0x9e3779b9U + (a << 6U) + (a >> 2U));
    }
};

WirePair ordered_pair(WireId left, WireId right) {
    return {std::min(left, right), std::max(left, right)};
}

/// Retain every source and construct distinct sparse linear forms. Large
/// input expansions use canonical four-element subsets, with shared two-term
/// sums; different parenthesizations cannot alias the same affine expression.
/// Later balanced levels need only distinct sums of two nonlinear atoms.
std::vector<WireId> affine_sources(PayloadBuilder &builder,
                                   const std::vector<WireId> &state,
                                   std::size_t additions,
                                   StableRandom &random) {
    std::vector<WireId> sources = state;
    sources.reserve(state.size() + additions);
    const std::size_t count = state.size();
    const std::size_t pair_count = count * (count - 1U) / 2U;
    if (additions <= pair_count) {
        std::unordered_set<WirePair, WirePairHash> seen;
        seen.reserve(additions);
        while (seen.size() < additions) {
            const WirePair pair = ordered_pair(random.bounded(count),
                                                random.bounded(count));
            if (pair.left == pair.right || !seen.insert(pair).second) {
                continue;
            }
            sources.push_back(builder.add(state[pair.left],
                                           state[pair.right]));
        }
        return sources;
    }
    if (count < 4 || count > 64) {
        throw std::invalid_argument(
            "make_workload: affine seed expansion requires 4..64 inputs");
    }
    const std::size_t quartet_count =
        count * (count - 1U) * (count - 2U) * (count - 3U) / 24U;
    if (additions - pair_count > quartet_count) {
        throw std::invalid_argument(
            "make_workload: affine seed budget exceeds distinct sparse forms");
    }
    std::vector<WireId> pairs(count * count, kNoWire);
    for (std::size_t left = 0; left < count; ++left) {
        for (std::size_t right = left + 1U; right < count; ++right) {
            const WireId sum = builder.add(state[left], state[right]);
            pairs[left * count + right] = sum;
            sources.push_back(sum);
        }
    }
    std::unordered_set<std::uint64_t> seen_quartets;
    seen_quartets.reserve(additions - pair_count);
    while (sources.size() < state.size() + additions) {
        std::array<std::size_t, 4> indices{
            random.bounded(count), random.bounded(count),
            random.bounded(count), random.bounded(count)};
        std::sort(indices.begin(), indices.end());
        if (std::adjacent_find(indices.begin(), indices.end()) !=
            indices.end()) {
            continue;
        }
        std::uint64_t support = 0;
        for (const std::size_t index : indices) {
            support |= std::uint64_t{1} << index;
        }
        if (!seen_quartets.insert(support).second) {
            continue;
        }
        sources.push_back(builder.add(
            pairs[indices[0] * count + indices[1]],
            pairs[indices[2] * count + indices[3]]));
    }
    return sources;
}

struct ProductIdentity {
    std::uint64_t first = 0;
    std::uint64_t second = 0;
    bool operator==(const ProductIdentity &) const = default;
};

struct ProductIdentityHash {
    std::size_t operator()(const ProductIdentity &identity) const {
        return static_cast<std::size_t>(
            identity.first ^ (identity.second + 0x9e3779b97f4a7c15ULL +
                              (identity.first << 6U) +
                              (identity.first >> 2U)));
    }
};

/// Additive fingerprints of a product's multiset of affine factors reject
/// associative aliases as well as immediate commutative duplicates. A hash
/// collision can only reject an additional candidate, never admit an alias.
class ProductIdentities {
  public:
    ProductIdentity product(WirePair pair) const {
        const ProductIdentity left = factor(pair.left);
        const ProductIdentity right = factor(pair.right);
        return {left.first + right.first, left.second + right.second};
    }

    bool contains(const ProductIdentity &identity) const {
        return seen_.contains(identity);
    }

    void insert(WireId wire, ProductIdentity identity) {
        wires_.emplace(wire, identity);
        seen_.insert(identity);
    }

  private:
    ProductIdentity factor(WireId wire) const {
        const auto found = wires_.find(wire);
        if (found != wires_.end()) {
            return found->second;
        }
        StableRandom random(static_cast<std::uint64_t>(wire) ^
                            0x8f3f73b5cf1c9adeULL);
        return {random.next(), random.next()};
    }

    std::unordered_map<WireId, ProductIdentity> wires_;
    std::unordered_set<ProductIdentity, ProductIdentityHash> seen_;
};

/// Consume every source at least once, then sample additional distinct
/// unordered products. Fingerprints also reject products that become equal
/// after flattening earlier multiplication gates. Affine sums remain factors.
std::vector<WireId> distinct_products(PayloadBuilder &builder,
                                      std::vector<WireId> sources,
                                      std::size_t width,
                                      StableRandom &random,
                                      ProductIdentities &identities) {
    if (sources.size() > 2U * width || sources.empty() ||
        (sources.size() <= width &&
         sources.size() * (sources.size() + 1U) / 2U < width)) {
        throw std::invalid_argument(
            "make_workload: product width cannot consume distinct sources");
    }
    std::unordered_set<ProductIdentity, ProductIdentityHash> seen;
    seen.reserve(width);
    std::vector<WirePair> pairs;
    pairs.reserve(width);
    // Plan before emitting gates: reshuffling preserves every mandatory source
    // when a proposed pair aliases another factored product.
    for (std::size_t attempt = 0;; ++attempt) {
        if (attempt == 1'024) {
            throw std::invalid_argument(
                "make_workload: cannot pair sources without product aliases");
        }
        stable_shuffle(sources, random);
        pairs.clear();
        seen.clear();
        bool distinct = true;
        for (std::size_t index = 0; index < sources.size(); index += 2U) {
            const WirePair pair = ordered_pair(
                sources[index], index + 1U < sources.size()
                                    ? sources[index + 1U]
                                    : sources[random.bounded(sources.size())]);
            const ProductIdentity identity = identities.product(pair);
            if (identities.contains(identity) ||
                !seen.insert(identity).second) {
                distinct = false;
                break;
            }
            pairs.push_back(pair);
        }
        if (distinct) {
            break;
        }
    }
    std::size_t failed_candidates = 0;
    while (pairs.size() < width) {
        const WirePair pair = ordered_pair(
            sources[random.bounded(sources.size())],
            sources[random.bounded(sources.size())]);
        const ProductIdentity identity = identities.product(pair);
        if (!identities.contains(identity) && seen.insert(identity).second) {
            pairs.push_back(pair);
            failed_candidates = 0;
        } else if (++failed_candidates == 100'000) {
            throw std::invalid_argument(
                "make_workload: too few distinct factored products");
        }
    }
    std::vector<WireId> products;
    products.reserve(width);
    for (const WirePair pair : pairs) {
        const WireId product = builder.mul(pair.left, pair.right);
        identities.insert(product, identities.product(pair));
        products.push_back(product);
    }
    stable_shuffle(products, random);
    return products;
}

std::vector<fhe::SlotVector> make_inputs(std::size_t input_count,
                                         const PayloadShape &shape,
                                         StableRandom &random) {
    std::vector<fhe::SlotVector> inputs(
        input_count, fhe::SlotVector(shape.value_width(), Fp::zero()));
    for (fhe::SlotVector &input : inputs) {
        for (Fp &value : input) {
            value = random.field();
        }
    }
    return inputs;
}

std::vector<WireId> reduce_to_outputs(PayloadBuilder &builder,
                                     std::vector<WireId> state) {
    const std::size_t output_count = std::min(
        state.size(), kBenchmarkDiamondOutputCiphertexts);
    std::vector<std::vector<WireId>> groups(output_count);
    for (std::size_t index = 0; index < state.size(); ++index) {
        groups[index % output_count].push_back(state[index]);
    }

    std::vector<WireId> outputs;
    outputs.reserve(output_count);
    for (std::vector<WireId> &group : groups) {
        while (group.size() > 1) {
            std::vector<WireId> next;
            next.reserve((group.size() + 1) / 2);
            for (std::size_t index = 0; index < group.size(); index += 2) {
                next.push_back(index + 1 < group.size()
                                   ? builder.add(group[index],
                                                 group[index + 1])
                                   : group[index]);
            }
            group = std::move(next);
        }
        outputs.push_back(group.front());
    }
    return outputs;
}

PayloadCircuit make_diamond(const WorkloadSpec &spec, StableRandom &random) {
    const std::size_t input_count = spec.input_count.value_or(
        std::min(spec.width, kBenchmarkDiamondInputCiphertexts));
    PayloadBuilder builder(spec.shape, input_count);
    const std::size_t bias = builder.add_scalar_plaintext(random.field());
    std::vector<WireId> state;
    state.reserve(spec.width);
    for (std::size_t index = 0; index < spec.width; ++index) {
        state.push_back(index % input_count);
    }
    const std::size_t ctct_depth =
        spec.multiplicative_depth -
        static_cast<std::size_t>(
            spec.terminal_nonuniform_plaintext_multiplication);
    for (std::size_t depth = 0; depth < ctct_depth; ++depth) {
        std::vector<WireId> next;
        next.reserve(state.size());
        for (std::size_t index = 0; index < state.size(); ++index) {
            const WireId left = state[index];
            const WireId right = state[(index + 1) % state.size()];
            const WireId shifted = builder.add_plain(right, bias);
            next.push_back(builder.mul(left, shifted));
        }
        state = std::move(next);
    }
    if (spec.terminal_nonuniform_plaintext_multiplication) {
        fhe::SlotVector mask(spec.shape.value_width());
        for (std::size_t coordinate = 0; coordinate < mask.size();
             ++coordinate) {
            mask[coordinate] = Fp(2 + coordinate % 251);
        }
        const std::size_t mask_id = builder.add_plaintext(std::move(mask));
        for (WireId &wire : state) {
            wire = builder.mul_plain(wire, mask_id);
        }
    }
    builder.set_outputs(reduce_to_outputs(builder, std::move(state)));
    return builder.finish();
}

PayloadCircuit make_balanced(const WorkloadSpec &spec,
                             StableRandom &random) {
    const BudgetGeometry geometry = budget_geometry(spec);
    ProductIdentities identities;
    const std::size_t input_count = spec.input_count.value_or(
        std::min(spec.width, kBenchmarkDiamondInputCiphertexts));
    PayloadBuilder builder(spec.shape, input_count);
    // A bounded shared table avoids materializing tens of thousands of full
    // slot vectors when the same scalar is used by different live expressions.
    constexpr std::array<std::uint64_t, 8> biases{2, 3, 5, 7, 11, 13, 17, 19};
    std::array<std::size_t, biases.size()> plaintexts{};
    for (std::size_t index = 0; index < biases.size(); ++index) {
        plaintexts[index] = builder.add_scalar_plaintext(Fp(biases[index]));
    }
    std::vector<WireId> state(input_count);
    for (std::size_t index = 0; index < input_count; ++index) {
        state[index] = index;
    }
    const std::size_t mixed_additions = geometry.addition_gates -
        (geometry.multiplication_widths.back() - 1U);
    for (std::size_t level = 0; level < spec.multiplicative_depth; ++level) {
        const std::size_t additions =
            mixed_additions / spec.multiplicative_depth +
            static_cast<std::size_t>(
                level < mixed_additions % spec.multiplicative_depth);
        const std::size_t scalar_gates =
            geometry.scalar_gates / spec.multiplicative_depth +
            static_cast<std::size_t>(
                level < geometry.scalar_gates % spec.multiplicative_depth);
        std::vector<WireId> sources =
            affine_sources(builder, state, additions, random);
        if (scalar_gates > sources.size()) {
            throw std::invalid_argument(
                "make_workload: scalar budget exceeds distinct affine sources");
        }
        std::vector<WireId> shifted_sources = sources;
        stable_shuffle(shifted_sources, random);
        for (std::size_t gate = 0; gate < scalar_gates; ++gate) {
            sources.push_back(builder.add_plain(
                shifted_sources[gate],
                plaintexts[random.bounded(plaintexts.size())]));
        }
        state = distinct_products(builder, std::move(sources),
                                  geometry.multiplication_widths[level],
                                  random, identities);
    }
    builder.set_outputs(reduce_to_outputs(builder, std::move(state)));
    PayloadCircuit result = builder.finish();
    if (result.gates.size() != *spec.operation_count) {
        throw std::logic_error("balanced gate count disagrees with its budget");
    }
    return result;
}

PayloadCircuit make_mulheavy_pyramid(const WorkloadSpec &spec,
                                     StableRandom &random) {
    const BudgetGeometry geometry = budget_geometry(spec);
    ProductIdentities identities;
    const std::size_t input_count = spec.input_count.value_or(
        std::min(spec.width, kBenchmarkDiamondInputCiphertexts));
    PayloadBuilder builder(spec.shape, input_count);
    std::vector<WireId> inputs(input_count);
    for (std::size_t index = 0; index < input_count; ++index) {
        inputs[index] = index;
    }
    const std::size_t input_additions = geometry.addition_gates -
        (geometry.multiplication_widths.back() - 1U);
    std::vector<WireId> affine =
        affine_sources(builder, inputs, input_additions, random);
    if (geometry.rotation_gates > affine.size() ||
        geometry.plaintext_multiplications > affine.size()) {
        throw std::invalid_argument(
            "make_workload: Wide gate budget exceeds distinct affine sources");
    }
    std::vector<WireId> sources = affine;
    stable_shuffle(affine, random);
    for (std::size_t gate = 0; gate < geometry.rotation_gates; ++gate) {
        sources.push_back(builder.rotate(
            affine[gate], 1U + random.bounded(spec.shape.slot_count - 1U)));
    }

    // Apply distinct nonzero, nonuniform masks to the affine input branches.
    // These branches join the second generator stage. A pair of masked
    // branches has CT-CT depth one, so compilation can place that product
    // earlier. The masks themselves remain affine.
    constexpr std::size_t mask_count = 8;
    std::array<std::size_t, mask_count> masks{};
    if (geometry.plaintext_multiplications != 0) {
        for (std::size_t index = 0; index < masks.size(); ++index) {
            fhe::SlotVector mask(spec.shape.value_width());
            for (Fp &value : mask) {
                value = Fp(2U + random.bounded(kBaseFieldOrder - 2U));
            }
            mask[0] = Fp(2U + index);
            mask[1] = Fp(17U + index);
            masks[index] = builder.add_plaintext(std::move(mask));
        }
    }
    stable_shuffle(affine, random);
    std::vector<WireId> masked_sources;
    masked_sources.reserve(geometry.plaintext_multiplications);
    for (std::size_t gate = 0; gate < geometry.plaintext_multiplications;
         ++gate) {
        masked_sources.push_back(builder.mul_plain(
            affine[gate], masks[random.bounded(masks.size())]));
    }
    std::vector<WireId> state = distinct_products(
        builder, std::move(sources), geometry.multiplication_widths.front(),
        random, identities);
    for (std::size_t level = 1; level < spec.multiplicative_depth; ++level) {
        if (level == 1) {
            state.insert(state.end(), masked_sources.begin(),
                         masked_sources.end());
        }
        state = distinct_products(builder, std::move(state),
                                  geometry.multiplication_widths[level],
                                  random, identities);
    }
    builder.set_outputs(reduce_to_outputs(builder, std::move(state)));
    PayloadCircuit result = builder.finish();
    if (result.gates.size() != *spec.operation_count) {
        throw std::logic_error(
            "multiplication-pyramid gate count disagrees with its budget");
    }
    return result;
}

PayloadCircuit make_deep_snake(const WorkloadSpec &spec,
                               StableRandom &random) {
    PayloadBuilder builder(spec.shape, 2);
    const std::size_t bias = builder.add_scalar_plaintext(random.field());
    WireId state = 0;
    for (std::size_t depth = 0; depth < spec.multiplicative_depth; ++depth) {
        const WireId side = builder.add(state, 1);
        const WireId shifted = builder.add_plain(side, bias);
        state = builder.mul(state, shifted);
    }
    builder.set_outputs({state});
    return builder.finish();
}

PayloadCircuit make_fanout_heavy(const WorkloadSpec &spec,
                                 StableRandom &random) {
    PayloadBuilder builder(spec.shape, 2);
    const std::size_t bias = builder.add_scalar_plaintext(random.field());
    WireId root = 0;
    for (std::size_t depth = 0; depth < spec.multiplicative_depth; ++depth) {
        std::vector<WireId> branches;
        branches.reserve(spec.width);
        for (std::size_t branch = 0; branch < spec.width; ++branch) {
            WireId side = builder.add(root, 1);
            side = builder.add_plain(side, bias);
            branches.push_back(builder.mul(root, side));
        }
        root = branches.front();
        for (std::size_t branch = 1; branch < branches.size(); ++branch) {
            root = builder.add(root, branches[branch]);
        }
    }
    builder.set_outputs({root});
    return builder.finish();
}

PayloadCircuit make_rotation_heavy(const WorkloadSpec &spec,
                                   StableRandom &random) {
    if (spec.shape.kind != PayloadKind::Wide) {
        throw std::invalid_argument(
            "make_workload: RotationHeavy requires a wide payload");
    }
    PayloadBuilder builder(spec.shape, 1);
    fhe::SlotVector bias(spec.shape.slot_count);
    for (Fp &value : bias) {
        value = random.field();
    }
    const std::size_t bias_id = builder.add_plaintext(std::move(bias));
    WireId state = 0;
    for (std::size_t depth = 0; depth < spec.multiplicative_depth; ++depth) {
        WireId combined = kNoWire;
        for (std::size_t rotation = 0; rotation < spec.width; ++rotation) {
            const std::size_t step =
                1 + (random.next() % (spec.shape.slot_count - 1));
            const WireId rotated = builder.rotate(state, step);
            combined = combined == kNoWire
                           ? rotated
                           : builder.add(combined, rotated);
        }
        combined = builder.add_plain(combined, bias_id);
        state = builder.mul(state, combined);
    }
    builder.set_outputs({state});
    return builder.finish();
}

} // namespace

std::string_view workload_name(WorkloadKind kind) {
    switch (kind) {
    case WorkloadKind::Diamond:
        return "diamond";
    case WorkloadKind::MulHeavyPyramid:
        return "mulHeavyPyramid";
    case WorkloadKind::BalancedLaned:
        return "balancedLaned";
    case WorkloadKind::DeepSnake:
        return "deep-snake";
    case WorkloadKind::FanoutHeavy:
        return "fanout-heavy";
    case WorkloadKind::RotationHeavy:
        return "rotation-heavy";
    }
    throw std::invalid_argument("workload_name: unknown workload kind");
}

namespace {

void validate_workload_spec(const WorkloadSpec &spec) {
    spec.shape.validate();
    if (spec.width == 0 || spec.multiplicative_depth == 0 ||
        spec.multiplicative_depth >
            kMaximumPayloadMultiplicativeDepth) {
        throw std::invalid_argument(
            "make_workload: width must be nonzero and depth must be in "
            "1..8");
    }
    const bool budgeted = spec.kind == WorkloadKind::BalancedLaned ||
                          spec.kind == WorkloadKind::MulHeavyPyramid;
    if ((spec.kind == WorkloadKind::Diamond || budgeted) &&
        spec.input_count &&
        (*spec.input_count == 0 || *spec.input_count > spec.width)) {
        throw std::invalid_argument(
            "make_workload: input count must be in 1..width");
    }
    if (budgeted && spec.input_count && *spec.input_count > 64) {
        throw std::invalid_argument(
            "make_workload: budgeted benchmark supports at most 64 inputs");
    }
    if (spec.kind != WorkloadKind::Diamond && !budgeted && spec.input_count) {
        throw std::invalid_argument(
            "make_workload: input count is unsupported for this workload");
    }
    if (budgeted) {
        if (spec.terminal_nonuniform_plaintext_multiplication) {
            throw std::invalid_argument(
                "make_workload: budgeted workloads do not support terminal "
                "plaintext multiplication");
        }
        (void)budget_geometry(spec);
    } else if (spec.operation_count || !spec.multiplication_widths.empty()) {
        throw std::invalid_argument(
            "make_workload: operation budgets are only valid for BalancedLaned "
            "and MulHeavyPyramid");
    }
    if (spec.terminal_nonuniform_plaintext_multiplication &&
        spec.shape.kind == PayloadKind::Laned) {
        throw std::invalid_argument(
            "make_workload: nonuniform plaintext multiplication requires a "
            "Wide payload");
    }
}

PayloadCircuit make_payload_circuit_with_random(
    const WorkloadSpec &spec, StableRandom &random) {
    PayloadCircuit circuit;
    switch (spec.kind) {
    case WorkloadKind::Diamond:
        circuit = make_diamond(spec, random);
        break;
    case WorkloadKind::MulHeavyPyramid:
        circuit = make_mulheavy_pyramid(spec, random);
        break;
    case WorkloadKind::BalancedLaned:
        circuit = make_balanced(spec, random);
        break;
    case WorkloadKind::DeepSnake:
        circuit = make_deep_snake(spec, random);
        break;
    case WorkloadKind::FanoutHeavy:
        circuit = make_fanout_heavy(spec, random);
        break;
    case WorkloadKind::RotationHeavy:
        circuit = make_rotation_heavy(spec, random);
        break;
    }
    return circuit;
}

} // namespace

PayloadCircuit make_payload_circuit(const WorkloadSpec &spec) {
    validate_workload_spec(spec);
    StableRandom random(spec.seed);
    return make_payload_circuit_with_random(spec, random);
}

std::vector<fhe::SlotVector> make_workload_inputs(
    const WorkloadSpec &spec) {
    validate_workload_spec(spec);
    if (spec.kind == WorkloadKind::MulHeavyPyramid ||
        spec.kind == WorkloadKind::BalancedLaned) {
        StableRandom input_random(
            spec.seed ^ 0xd1b54a32d192ed03ULL);
        const std::size_t input_count = spec.input_count.value_or(
            std::min(spec.width, kBenchmarkDiamondInputCiphertexts));
        return make_inputs(input_count, spec.shape, input_random);
    }
    StableRandom random(spec.seed);
    std::size_t input_count = 0;
    switch (spec.kind) {
    case WorkloadKind::Diamond:
        // Diamond consumes one field element for its scalar bias before it
        // samples the plaintext inputs.
        (void)random.next();
        input_count = spec.input_count.value_or(
            std::min(spec.width, kBenchmarkDiamondInputCiphertexts));
        break;
    case WorkloadKind::MulHeavyPyramid:
    case WorkloadKind::BalancedLaned:
        throw std::logic_error(
            "make_workload_inputs: unreachable multiplication pyramid");
    case WorkloadKind::DeepSnake:
    case WorkloadKind::FanoutHeavy:
        (void)random.next();
        input_count = 2;
        break;
    case WorkloadKind::RotationHeavy:
        // RotationHeavy first samples its nonuniform bias and then one step
        // for each rotation gate.
        for (std::size_t slot = 0; slot < spec.shape.slot_count; ++slot) {
            (void)random.next();
        }
        for (std::size_t depth = 0; depth < spec.multiplicative_depth;
             ++depth) {
            for (std::size_t rotation = 0; rotation < spec.width;
                 ++rotation) {
                (void)random.next();
            }
        }
        input_count = 1;
        break;
    }
    return make_inputs(input_count, spec.shape, random);
}

Workload make_workload(const WorkloadSpec &spec) {
    validate_workload_spec(spec);
    if (spec.kind == WorkloadKind::MulHeavyPyramid ||
        spec.kind == WorkloadKind::BalancedLaned) {
        StableRandom circuit_random(spec.seed);
        PayloadCircuit circuit =
            make_payload_circuit_with_random(spec, circuit_random);
        StableRandom input_random(
            spec.seed ^ 0xd1b54a32d192ed03ULL);
        std::vector<fhe::SlotVector> inputs = make_inputs(
            circuit.input_count, spec.shape, input_random);
        return Workload{spec, std::move(circuit), std::move(inputs)};
    }
    StableRandom random(spec.seed);
    PayloadCircuit circuit = make_payload_circuit_with_random(spec, random);
    std::vector<fhe::SlotVector> inputs =
        make_inputs(circuit.input_count, spec.shape, random);
    return Workload{spec, std::move(circuit), std::move(inputs)};
}

} // namespace laminate::payload
