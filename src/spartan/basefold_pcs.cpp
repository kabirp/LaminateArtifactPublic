/// @file basefold_pcs.cpp
/// @brief Fq/Fq2 BaseFold PCS and its canonical BCS16 proof encoding.

#include "laminate/spartan/basefold_pcs.hpp"

#include "laminate/basefold/merkle.hpp"
#include "laminate/field/serialization.hpp"
#include "laminate/params.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <filesystem>
#include <functional>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

#ifndef _WIN32
#include <sys/stat.h>
#endif

namespace laminate::spartan {
namespace {

using basefold::MerkleTree;
using Digest = basefold::Digest;

constexpr std::uint64_t kOpeningEncodingVersion = 4;
constexpr std::size_t kMerkleLeafLogSize = 6;
constexpr std::size_t kMerkleLeafMaxElements =
    std::size_t{1} << kMerkleLeafLogSize;
constexpr std::string_view kRoundLabel =
    "laminate/basefold/round/v2";
constexpr std::string_view kFoldedOracleLabel =
    "laminate/basefold/oracle/v1";
constexpr std::string_view kFinalCodewordLabel =
    "laminate/basefold/final/v1";
constexpr std::string_view kExternalStateIdentityDomain =
    "LaminateImpl/SpartanBaseFoldExternalState/v1";
constexpr std::string_view kFoldScratchIdentityDomain =
    "LaminateImpl/SpartanBaseFoldFoldScratch/v1";
constexpr std::string_view kFoldChunkIdentityDomain =
    "LaminateImpl/SpartanBaseFoldFoldChunk/v1";
constexpr std::size_t kDigestWriteElements = 1024;

bool is_power_of_two(std::size_t value) {
    return value != 0 && (value & (value - 1)) == 0;
}

std::size_t log2_exact(std::size_t value) {
    if (!is_power_of_two(value)) {
        throw std::invalid_argument(
            "BaseFold PCS dimension is not a power of two");
    }
    std::size_t result = 0;
    while ((std::size_t{1} << result) < value) {
        ++result;
    }
    return result;
}

std::size_t checked_codeword_size(std::size_t message_size,
                                  std::size_t log_rate) {
    const std::size_t log_message = log2_exact(message_size);
    if (log_rate > kOuterFieldTwoAdicity ||
        log_message > kOuterFieldTwoAdicity - log_rate ||
        log_message + log_rate >=
            std::numeric_limits<std::size_t>::digits) {
        throw std::invalid_argument(
            "BaseFold PCS domain exceeds Fq two-adicity");
    }
    return std::size_t{1} << (log_message + log_rate);
}

std::size_t merkle_leaf_size(std::size_t codeword_size) {
    (void)log2_exact(codeword_size);
    return std::min(codeword_size, kMerkleLeafMaxElements);
}

std::size_t merkle_leaf_count(std::size_t codeword_size) {
    return codeword_size / merkle_leaf_size(codeword_size);
}

std::vector<std::uint8_t> encode(const Fq2 &value) {
    const SerializedFq2 bytes = serialize(value);
    return {bytes.begin(), bytes.end()};
}

template <typename Value>
std::vector<std::uint8_t> encode_values(std::span<const Value> values) {
    std::vector<std::uint8_t> output;
    if constexpr (std::is_same_v<Value, Fq>) {
        output.reserve(values.size() * kSerializedFqBytes);
    } else {
        output.reserve(values.size() * kSerializedFq2Bytes);
    }
    for (const Value &value : values) {
        const std::vector<std::uint8_t> encoded = encode(value);
        output.insert(output.end(), encoded.begin(), encoded.end());
    }
    return output;
}

void observe_round(const std::array<Fq2, 2> &round,
                   PublicCoin &public_coin) {
    const std::vector<std::uint8_t> bytes = encode_values<Fq2>(round);
    public_coin.observe(kRoundLabel, bytes);
}

void observe_root(const Digest &root, PublicCoin &public_coin) {
    public_coin.observe(kFoldedOracleLabel, root);
}

void observe_final(std::span<const Fq2> codeword,
                   PublicCoin &public_coin) {
    public_coin.observe(kFinalCodewordLabel, encode_values<Fq2>(codeword));
}

template <typename Value>
void evaluations_to_coefficients_in_place(
    std::vector<Value> &coefficients) {
    (void)log2_exact(coefficients.size());
    for (std::size_t bit = 1; bit < coefficients.size(); bit <<= 1U) {
        for (std::size_t index = 0; index < coefficients.size(); ++index) {
            if ((index & bit) != 0) {
                coefficients[index] -= coefficients[index ^ bit];
            }
        }
    }
}

void ntt_in_place(std::vector<Fq> &values, const Fq &omega) {
    const std::size_t size = values.size();
    if (size <= 1) {
        return;
    }
    const std::size_t log_size = log2_exact(size);
    for (std::size_t index = 1, reverse = 0; index < size; ++index) {
        std::size_t bit = size >> 1U;
        while ((reverse & bit) != 0) {
            reverse ^= bit;
            bit >>= 1U;
        }
        reverse ^= bit;
        if (index < reverse) {
            std::swap(values[index], values[reverse]);
        }
    }
    for (std::size_t stage = 1; stage <= log_size; ++stage) {
        const std::size_t length = std::size_t{1} << stage;
        Fq stage_root = omega;
        for (std::size_t exponent = length; exponent < size;
             exponent <<= 1U) {
            stage_root *= stage_root;
        }
        const std::size_t half_length = length / 2;
        for (std::size_t begin = 0; begin < size; begin += length) {
            Fq twiddle = Fq::one();
            for (std::size_t offset = 0; offset < half_length; ++offset) {
                const Fq lo = values[begin + offset];
                const Fq hi =
                    values[begin + offset + half_length] * twiddle;
                values[begin + offset] = lo + hi;
                values[begin + offset + half_length] = lo - hi;
                twiddle *= stage_root;
            }
        }
    }
}

std::vector<Fq> reed_solomon_encode(std::span<const Fq> evaluations,
                                    std::size_t log_rate) {
    const std::size_t codeword_size =
        checked_codeword_size(evaluations.size(), log_rate);
    std::vector<Fq> codeword;
    codeword.reserve(codeword_size);
    codeword.assign(evaluations.begin(), evaluations.end());
    evaluations_to_coefficients_in_place(codeword);
    codeword.resize(codeword_size, Fq::zero());
    ntt_in_place(codeword,
                 Fq::two_adic_generator(log2_exact(codeword_size)));
    return codeword;
}

std::vector<Fq2> equality_table_lsb(std::size_t size,
                                    std::span<const Fq2> point) {
    if (point.size() != log2_exact(size)) {
        throw std::invalid_argument(
            "BaseFold opening point has the wrong dimension");
    }
    std::vector<Fq2> result(size, Fq2::zero());
    result[0] = Fq2::one();
    std::size_t active = 1;
    for (const Fq2 &coordinate : point) {
        for (std::size_t index = 0; index < active; ++index) {
            const Fq2 previous = result[index];
            const Fq2 high = previous * coordinate;
            result[index] = previous - high;
            result[index + active] = high;
        }
        active *= 2;
    }
    return result;
}

void fold_adjacent_into(std::span<const Fq2> table,
                        std::span<Fq2> output,
                        const Fq2 &challenge) {
    if (table.size() < 2 || (table.size() & 1U) != 0 ||
        output.size() != table.size() / 2) {
        throw std::invalid_argument(
            "BaseFold sumcheck table cannot be folded");
    }
    for (std::size_t index = 0; index < output.size(); ++index) {
        // Copy before writing: output may occupy an earlier part of table.
        const Fq2 lo = table[2 * index];
        const Fq2 hi = table[2 * index + 1];
        output[index] = lo + challenge * (hi - lo);
    }
}

std::array<Fq2, 2> sumcheck_round(std::span<const Fq2> message,
                                 std::span<const Fq2> operand) {
    if (message.size() != operand.size() || message.size() < 2 ||
        (message.size() & 1U) != 0) {
        throw std::invalid_argument("malformed BaseFold sumcheck state");
    }
    std::array<Fq2, 2> result{};
    for (std::size_t index = 0; index < message.size() / 2; ++index) {
        const Fq2 &a0 = message[2 * index];
        const Fq2 &a1 = message[2 * index + 1];
        const Fq2 &b0 = operand[2 * index];
        const Fq2 &b1 = operand[2 * index + 1];
        result[0] += a1 * b1;
        result[1] += (a1 + a1 - a0) * (b1 + b1 - b0);
    }
    return result;
}

Fq2 interpolate_quadratic(const Fq2 &at_zero,
                          const std::array<Fq2, 2> &message,
                          const Fq2 &point) {
    const Fq2 one = Fq2::one();
    const Fq2 two = one + one;
    const Fq2 inverse_two = Fq2::from_base(Fq(2).inverse());
    const Fq2 l0 = (point - one) * (point - two) * inverse_two;
    const Fq2 l1 = point * (point - two);
    const Fq2 l2 = point * (point - one) * inverse_two;
    return at_zero * l0 - message[0] * l1 + message[1] * l2;
}

Fq2 fold_pair(const Fq2 &lo, const Fq2 &hi,
              const Fq2 &challenge,
              const Fq &inverse_generator_power) {
    static const Fq inverse_two = Fq(2).inverse();
    return (lo + hi +
            challenge * ((lo - hi) * inverse_generator_power)) *
           inverse_two;
}

std::vector<Fq2> fold_codeword(std::span<const Fq2> codeword,
                               const Fq2 &challenge,
                               const Fq &generator) {
    if (codeword.size() < 2 || (codeword.size() & 1U) != 0) {
        throw std::invalid_argument("BaseFold codeword cannot be folded");
    }
    const Fq inverse_generator = generator.inverse();
    std::vector<Fq2> result(codeword.size() / 2);
    Fq inverse_power = Fq::one();
    for (std::size_t index = 0; index < result.size(); ++index) {
        result[index] = fold_pair(
            codeword[index], codeword[index + result.size()], challenge,
            inverse_power);
        inverse_power *= inverse_generator;
    }
    return result;
}

MerkleTree make_interleaved_tree(
    const std::vector<std::vector<Fq>> &codewords) {
    if (codewords.empty()) {
        throw std::invalid_argument(
            "BaseFold commitment requires at least one column");
    }
    const std::size_t size = codewords.front().size();
    for (const std::vector<Fq> &codeword : codewords) {
        if (codeword.size() != size) {
            throw std::invalid_argument(
                "BaseFold codeword columns have different sizes");
        }
    }
    const std::size_t leaf_size = merkle_leaf_size(size);
    const std::size_t leaf_count = merkle_leaf_count(size);
    std::vector<Fq> interleaved_leaf(leaf_size * codewords.size());
    return MerkleTree(leaf_count, [&](std::size_t leaf_index) {
        const std::size_t begin = leaf_index * leaf_size;
        if (codewords.size() == 1) {
            return MerkleTree::hash_fq_leaf(
                std::span<const Fq>(codewords.front())
                    .subspan(begin, leaf_size));
        }
        for (std::size_t offset = 0; offset < leaf_size; ++offset) {
            for (std::size_t column = 0; column < codewords.size();
                 ++column) {
                interleaved_leaf[offset * codewords.size() + column] =
                    codewords[column][begin + offset];
            }
        }
        return MerkleTree::hash_fq_leaf(interleaved_leaf);
    });
}

MerkleTree make_fq2_tree(std::span<const Fq2> values) {
    const std::size_t leaf_size = merkle_leaf_size(values.size());
    const std::size_t leaf_count = merkle_leaf_count(values.size());
    return MerkleTree(leaf_count, [&](std::size_t leaf_index) {
        const std::size_t begin = leaf_index * leaf_size;
        return MerkleTree::hash_fq2_leaf(
            values.subspan(begin, leaf_size));
    });
}

Digest hash_fq_leaf(std::span<const Fq> values) {
    return MerkleTree::hash_fq_leaf(values);
}

Digest hash_fq2_leaf(std::span<const Fq2> values) {
    return MerkleTree::hash_fq2_leaf(values);
}

template <typename Value>
struct MerkleMultiOpening {
    /// Sorted unique leaf positions. They are derived from `queries` and are
    /// not repeated in the encoding.
    std::vector<std::size_t> leaf_indices;
    std::size_t values_per_leaf = 0;
    /// Consecutive canonical leaves. Keeping one allocation per oracle layer
    /// makes decoding and verifier hashing cache-friendly at target query
    /// counts.
    std::vector<Value> values;
    /// Canonical union frontier in MerkleTree's level/left-to-right order.
    std::vector<Digest> frontier;
};

struct BaseFoldProof {
    /// Each sumcheck round transmits R(1),R(2); R(0)=claim-R(1).
    std::vector<std::array<Fq2, 2>> rounds;
    std::vector<Digest> roots;
    std::vector<Fq2> final_codeword;
    std::vector<std::size_t> queries;
    MerkleMultiOpening<Fq> base;
    std::vector<MerkleMultiOpening<Fq2>> folds;
};

std::vector<std::size_t> queried_leaf_indices(
    std::span<const std::size_t> positions, std::size_t layer_size) {
    if (layer_size < 2U || !is_power_of_two(layer_size)) {
        throw std::invalid_argument(
            "BaseFold queried layer has invalid size");
    }
    const std::size_t half = layer_size / 2U;
    const std::size_t leaf_size = merkle_leaf_size(layer_size);
    std::vector<std::size_t> result;
    result.reserve(2U * positions.size());
    for (const std::size_t position : positions) {
        if (position >= half) {
            throw std::invalid_argument(
                "BaseFold query position is out of range");
        }
        result.push_back(position / leaf_size);
        result.push_back((position + half) / leaf_size);
    }
    std::sort(result.begin(), result.end());
    result.erase(std::unique(result.begin(), result.end()), result.end());
    return result;
}

struct MaximumMultiProofShape {
    std::size_t leaves = 0;
    std::size_t frontier = 0;
    std::size_t parent_hashes = 0;
};

MaximumMultiProofShape maximum_multi_shape(std::size_t layer_size,
                                            std::size_t query_count) {
    const std::size_t leaf_count = merkle_leaf_count(layer_size);
    if (leaf_count == 1U) {
        return MaximumMultiProofShape{
            .leaves = 1U, .frontier = 0U, .parent_hashes = 0U};
    }
    // Every query asks for matching leaves in the low and high halves.
    // Within either half, spreading m leaves over distinct subtrees
    // maximizes both the union frontier and occupied parent nodes at every
    // level. If a level has a occupied nodes and its parent has b, it adds
    // 2b-a missing siblings and b parent hashes.
    const std::size_t half_leaves = leaf_count / 2U;
    const std::size_t selected = std::min(query_count, half_leaves);
    // The largest leaf disclosure uses every available query, whereas the
    // largest frontier can occur with fewer distinct leaves after query
    // collisions. Bound the two components independently so the framing cap
    // remains valid for every Fiat--Shamir outcome.
    const std::size_t frontier_selected =
        std::min(selected, half_leaves / 2U);
    std::size_t frontier_per_half = 0;
    std::size_t parents_per_half = 0;
    std::size_t frontier_occupied = frontier_selected;
    for (std::size_t nodes = half_leaves; nodes > 1U;) {
        nodes /= 2U;
        const std::size_t frontier_parents =
            std::min(frontier_selected, nodes);
        frontier_per_half +=
            2U * frontier_parents - frontier_occupied;
        frontier_occupied = frontier_parents;
        parents_per_half += std::min(selected, nodes);
    }
    return MaximumMultiProofShape{
        .leaves = 2U * selected,
        .frontier = 2U * frontier_per_half,
        // Two authenticated half roots are joined by one final hash.
        .parent_hashes = 2U * parents_per_half + 1U,
    };
}

template <typename Value>
std::span<const Value> opened_leaf(
    const MerkleMultiOpening<Value> &opening, std::size_t leaf_index) {
    const auto position = std::lower_bound(opening.leaf_indices.begin(),
                                           opening.leaf_indices.end(),
                                           leaf_index);
    if (position == opening.leaf_indices.end() ||
        *position != leaf_index) {
        throw std::out_of_range("BaseFold multiproof omits a queried leaf");
    }
    const std::size_t offset = static_cast<std::size_t>(
                                   position - opening.leaf_indices.begin()) *
                               opening.values_per_leaf;
    return std::span<const Value>(opening.values)
        .subspan(offset, opening.values_per_leaf);
}

template <typename Value, typename HashLeaf>
bool verify_multi_opening(const Digest &root, std::size_t leaf_count,
                          const MerkleMultiOpening<Value> &opening,
                          HashLeaf hash_leaf) {
    if (opening.values_per_leaf == 0 ||
        opening.leaf_indices.size() >
            std::numeric_limits<std::size_t>::max() /
                opening.values_per_leaf ||
        opening.values.size() !=
            opening.leaf_indices.size() * opening.values_per_leaf) {
        return false;
    }
    std::vector<Digest> hashes;
    hashes.reserve(opening.leaf_indices.size());
    for (std::size_t leaf = 0; leaf < opening.leaf_indices.size(); ++leaf) {
        hashes.push_back(hash_leaf(
            std::span<const Value>(opening.values)
                .subspan(leaf * opening.values_per_leaf,
                         opening.values_per_leaf)));
    }
    return MerkleTree::verify_many_hashes(
        root, leaf_count, opening.leaf_indices, hashes, opening.frontier);
}

class BaseFoldProverState final : public IPCS::ProverState {
  public:
    BaseFoldProverState(std::vector<std::vector<Fq>> message_columns,
                        std::vector<std::vector<Fq>> encoded_columns,
                        MerkleTree commitment_tree,
                        PcsCommitment public_commitment)
        : columns(std::move(message_columns)),
          codewords(std::move(encoded_columns)),
          tree(std::move(commitment_tree)),
          commitment(std::move(public_commitment)) {}

    std::vector<std::vector<Fq>> columns;
    std::vector<std::vector<Fq>> codewords;
    MerkleTree tree;
    PcsCommitment commitment;
};

class BaseFoldExternalProverState final : public IPCS::ProverState {
  public:
    BaseFoldExternalProverState(
        std::shared_ptr<const storage::NativeFieldArtifact> artifact_value,
        PcsCommitment public_commitment)
        : artifact(std::move(artifact_value)),
          commitment(std::move(public_commitment)) {}

    std::shared_ptr<const storage::NativeFieldArtifact> artifact;
    PcsCommitment commitment;
};

void append_u64(std::vector<std::uint8_t> &output, std::uint64_t value);
void append_fq2(std::vector<std::uint8_t> &output, const Fq2 &value);

std::uint64_t checked_u64(std::size_t value, const char *label) {
    if constexpr (sizeof(std::size_t) > sizeof(std::uint64_t)) {
        if (value > std::numeric_limits<std::uint64_t>::max()) {
            throw std::overflow_error(std::string(label) + " exceeds u64");
        }
    }
    return static_cast<std::uint64_t>(value);
}

std::uint64_t checked_add_u64(std::uint64_t left, std::uint64_t right,
                              const char *label) {
    if (right > std::numeric_limits<std::uint64_t>::max() - left) {
        throw std::overflow_error(std::string(label) + " overflows");
    }
    return left + right;
}

std::uint64_t checked_multiply_u64(std::uint64_t left,
                                   std::uint64_t right,
                                   const char *label) {
    if (left != 0 &&
        right > std::numeric_limits<std::uint64_t>::max() / left) {
        throw std::overflow_error(std::string(label) + " overflows");
    }
    return left * right;
}

void append_bytes(std::vector<std::uint8_t> &output,
                  std::span<const std::uint8_t> bytes) {
    output.insert(output.end(), bytes.begin(), bytes.end());
}

std::string message_array_name(std::size_t column) {
    return "message-column-" + std::to_string(column);
}

std::string codeword_array_name(std::size_t column) {
    return "codeword-column-" + std::to_string(column);
}

constexpr std::string_view kFoldValuesArray = "fold-values";

constexpr std::string_view kBaseTreePostorderArray =
    "base-tree-postorder";
constexpr std::string_view kFoldTreePostorderArray =
    "fold-tree-postorder";

std::string_view tree_postorder_array_name(bool base) {
    return base ? kBaseTreePostorderArray : kFoldTreePostorderArray;
}

std::size_t merkle_node_count(std::size_t leaf_count) {
    if (!is_power_of_two(leaf_count)) {
        throw std::invalid_argument(
            "external Merkle leaf count is not a power of two");
    }
    // Written this way, the largest representable power-of-two leaf count
    // still yields the representable full-tree size without an intermediate
    // multiplication overflow.
    return 2U * (leaf_count - 1U) + 1U;
}

std::size_t postorder_node_position(std::size_t tree_height,
                                    std::size_t node_level,
                                    std::size_t node_index) {
    if (node_level > tree_height ||
        node_index >= (std::size_t{1} << (tree_height - node_level))) {
        throw std::out_of_range("external Merkle node is out of range");
    }
    std::size_t offset = 0;
    std::size_t current_height = tree_height;
    for (std::size_t bit_count = tree_height - node_level;
         bit_count != 0; --bit_count, --current_height) {
        const std::size_t bit = bit_count - 1U;
        if (((node_index >> bit) & 1U) != 0) {
            offset += (std::size_t{1} << current_height) - 1U;
        }
    }
    const std::size_t subtree_root =
        merkle_node_count(std::size_t{1} << node_level) - 1U;
    return offset + subtree_root;
}

laminate::Digest fold_scratch_identity(
    const laminate::Digest &source_identity, const PcsCommitment &commitment,
    std::size_t round_index, const Fq2 &challenge) {
    std::vector<std::uint8_t> encoding(kFoldScratchIdentityDomain.begin(),
                                       kFoldScratchIdentityDomain.end());
    append_bytes(encoding, source_identity);
    append_bytes(encoding, encode_pcs_commitment(commitment));
    append_u64(encoding, checked_u64(round_index, "FRI round index"));
    append_fq2(encoding, challenge);
    return sha256(encoding);
}

laminate::Digest fold_chunk_identity(
    const laminate::Digest &layer_identity, std::size_t chunk_index,
    std::size_t first_element, std::size_t element_count) {
    std::vector<std::uint8_t> encoding(kFoldChunkIdentityDomain.begin(),
                                       kFoldChunkIdentityDomain.end());
    append_bytes(encoding, layer_identity);
    append_u64(encoding, checked_u64(chunk_index, "fold chunk index"));
    append_u64(encoding, checked_u64(first_element, "fold chunk start"));
    append_u64(encoding, checked_u64(element_count, "fold chunk length"));
    return sha256(encoding);
}

class MerkleFrontier {
  public:
    void push(const Digest &leaf) {
        push_postorder(leaf, [](const Digest &) {});
    }

    template <typename Emit>
    void push_postorder(const Digest &leaf, Emit emit) {
        Digest node = leaf;
        emit(node);
        std::size_t level = 0;
        while (level < occupied_.size() && occupied_[level]) {
            node = MerkleTree::hash_children(nodes_[level], node);
            emit(node);
            occupied_[level] = false;
            ++level;
        }
        if (level == occupied_.size()) {
            occupied_.push_back(false);
            nodes_.push_back({});
        }
        nodes_[level] = node;
        occupied_[level] = true;
        ++count_;
    }

    Digest finish(std::size_t expected_count) const {
        if (!is_power_of_two(expected_count) || count_ != expected_count) {
            throw std::logic_error("malformed external Merkle frontier");
        }
        const std::size_t level = log2_exact(expected_count);
        if (level >= occupied_.size() || !occupied_[level] ||
            std::count(occupied_.begin(), occupied_.end(), true) != 1) {
            throw std::logic_error("incomplete external Merkle frontier");
        }
        return nodes_[level];
    }

  private:
    std::vector<Digest> nodes_;
    std::vector<bool> occupied_;
    std::size_t count_ = 0;
};

Digest stored_tree_root(const storage::NativeFieldArtifact &artifact,
                        bool base, std::size_t leaf_count) {
    storage::NativeFieldArrayReader reader =
        artifact.open_array(tree_postorder_array_name(base));
    reader.seek(merkle_node_count(leaf_count) - 1U);
    std::array<Digest, 1> root{};
    if (reader.read(root) != 1) {
        throw std::invalid_argument("malformed external Merkle root array");
    }
    return root.front();
}

void validate_external_state_layout(
    const storage::NativeFieldArtifact &artifact,
    const PcsCommitment &commitment) {
    if (commitment.scheme != BaseFoldPcs::kSchemeIdentifier ||
        commitment.width == 0 || commitment.evaluation_count == 0 ||
        commitment.width > std::numeric_limits<std::size_t>::max() ||
        commitment.evaluation_count >
            std::numeric_limits<std::size_t>::max()) {
        throw std::invalid_argument("invalid external BaseFold commitment");
    }
    const std::size_t width = static_cast<std::size_t>(commitment.width);
    const std::size_t message_size =
        static_cast<std::size_t>(commitment.evaluation_count);
    const std::size_t codeword_size =
        checked_codeword_size(message_size, commitment.log_rate);
    const std::size_t leaf_count = merkle_leaf_count(codeword_size);
    if (width > (std::numeric_limits<std::size_t>::max() - 1U) / 2U ||
        artifact.arrays().size() != 2U * width + 1U ||
        artifact.identity() != basefold_external_state_identity(commitment)) {
        throw std::invalid_argument("external BaseFold artifact shape mismatch");
    }
    std::size_t array_index = 0;
    const auto check = [&](std::string_view expected_name,
                           storage::NativeFieldElementKind kind,
                           std::size_t count) {
        const storage::NativeFieldArrayDescriptor &array =
            artifact.arrays().at(array_index++);
        if (array.name != expected_name || array.kind != kind ||
            array.element_count != count ||
            array.encoded_element_bytes !=
                storage::encoded_element_bytes(kind)) {
            throw std::invalid_argument(
                "external BaseFold artifact layout mismatch");
        }
    };
    for (std::size_t column = 0; column < width; ++column) {
        check(message_array_name(column),
              storage::NativeFieldElementKind::Fq, message_size);
    }
    for (std::size_t column = 0; column < width; ++column) {
        check(codeword_array_name(column),
              storage::NativeFieldElementKind::Fq, codeword_size);
    }
    check(kBaseTreePostorderArray,
          storage::NativeFieldElementKind::BaseFoldDigest,
          merkle_node_count(leaf_count));
    if (stored_tree_root(artifact, true, leaf_count) != commitment.root) {
        throw std::invalid_argument(
            "external BaseFold artifact has the wrong Merkle root");
    }
}

void append_u64(std::vector<std::uint8_t> &output, std::uint64_t value) {
    for (std::size_t byte = 0; byte < 8; ++byte) {
        output.push_back(static_cast<std::uint8_t>(value >> (8U * byte)));
    }
}

void append_fq(std::vector<std::uint8_t> &output, const Fq &value) {
    const SerializedFq bytes = serialize(value);
    output.insert(output.end(), bytes.begin(), bytes.end());
}

void append_fq2(std::vector<std::uint8_t> &output, const Fq2 &value) {
    const SerializedFq2 bytes = serialize(value);
    output.insert(output.end(), bytes.begin(), bytes.end());
}

void append_digest(std::vector<std::uint8_t> &output,
                   const Digest &digest) {
    output.insert(output.end(), digest.begin(), digest.end());
}

template <typename Value>
void append_multi_opening(std::vector<std::uint8_t> &output,
                          const MerkleMultiOpening<Value> &opening) {
    if (opening.values_per_leaf == 0 ||
        opening.leaf_indices.size() >
            std::numeric_limits<std::size_t>::max() /
                opening.values_per_leaf ||
        opening.values.size() !=
            opening.leaf_indices.size() * opening.values_per_leaf) {
        throw std::logic_error("BaseFold multiproof leaf shape mismatch");
    }
    append_u64(output, opening.leaf_indices.size());
    for (const Value &value : opening.values) {
        if constexpr (std::is_same_v<Value, Fq>) {
            append_fq(output, value);
        } else {
            append_fq2(output, value);
        }
    }
    append_u64(output, opening.frontier.size());
    for (const Digest &digest : opening.frontier) {
        append_digest(output, digest);
    }
}

std::vector<std::uint8_t> encode_proof(const BaseFoldProof &proof) {
    std::vector<std::uint8_t> output;
    append_u64(output, kOpeningEncodingVersion);
    append_u64(output, proof.rounds.size());
    for (const auto &round : proof.rounds) {
        for (const Fq2 &value : round) {
            append_fq2(output, value);
        }
    }
    append_u64(output, proof.roots.size());
    for (const Digest &root : proof.roots) {
        append_digest(output, root);
    }
    append_u64(output, proof.final_codeword.size());
    for (const Fq2 &value : proof.final_codeword) {
        append_fq2(output, value);
    }
    append_u64(output, proof.queries.size());
    for (const std::size_t query : proof.queries) {
        append_u64(output, query);
    }
    append_multi_opening(output, proof.base);
    append_u64(output, proof.folds.size());
    for (const MerkleMultiOpening<Fq2> &fold : proof.folds) {
        append_multi_opening(output, fold);
    }
    return output;
}

class Reader {
  public:
    explicit Reader(std::span<const std::uint8_t> bytes) : bytes_(bytes) {}

    std::uint64_t u64() {
        require(8);
        std::uint64_t value = 0;
        for (std::size_t byte = 8; byte > 0; --byte) {
            value = (value << 8U) | bytes_[position_ + byte - 1];
        }
        position_ += 8;
        return value;
    }

    void count(std::size_t expected) {
        if (u64() != expected) {
            throw std::invalid_argument("noncanonical BaseFold proof shape");
        }
    }

    Fq fq() {
        require(kSerializedFqBytes);
        const Fq result = deserialize_fq(
            bytes_.subspan(position_, kSerializedFqBytes));
        position_ += kSerializedFqBytes;
        return result;
    }

    Fq2 fq2() {
        require(kSerializedFq2Bytes);
        const Fq2 result = deserialize_fq2(
            bytes_.subspan(position_, kSerializedFq2Bytes));
        position_ += kSerializedFq2Bytes;
        return result;
    }

    Digest digest() {
        require(Digest{}.size());
        Digest result{};
        std::copy_n(bytes_.begin() +
                        static_cast<std::ptrdiff_t>(position_),
                    result.size(), result.begin());
        position_ += result.size();
        return result;
    }

    bool at_end() const { return position_ == bytes_.size(); }

  private:
    void require(std::size_t count) const {
        if (count > bytes_.size() - position_) {
            throw std::invalid_argument("truncated BaseFold opening proof");
        }
    }

    std::span<const std::uint8_t> bytes_;
    std::size_t position_ = 0;
};

std::optional<BaseFoldProof> decode_proof(
    std::span<const std::uint8_t> bytes, std::size_t message_log,
    std::size_t width, std::size_t log_rate,
    std::size_t query_count) {
    try {
        Reader reader(bytes);
        if (reader.u64() != kOpeningEncodingVersion) {
            return std::nullopt;
        }
        const std::size_t codeword_log = message_log + log_rate;
        const std::size_t codeword_size = std::size_t{1} << codeword_log;
        const std::size_t base_leaf_size = merkle_leaf_size(codeword_size);
        const std::size_t base_leaf_count = merkle_leaf_count(codeword_size);
        if (width > std::numeric_limits<std::size_t>::max() /
                        base_leaf_size) {
            return std::nullopt;
        }
        BaseFoldProof proof;
        reader.count(message_log);
        proof.rounds.resize(message_log);
        for (auto &round : proof.rounds) {
            for (Fq2 &value : round) {
                value = reader.fq2();
            }
        }
        const std::size_t root_count =
            message_log == 0 ? 0 : message_log - 1;
        reader.count(root_count);
        proof.roots.resize(root_count);
        for (Digest &root : proof.roots) {
            root = reader.digest();
        }
        const std::size_t final_size = std::size_t{1} << log_rate;
        reader.count(final_size);
        proof.final_codeword.resize(final_size);
        for (Fq2 &value : proof.final_codeword) {
            value = reader.fq2();
        }
        reader.count(query_count);
        proof.queries.resize(query_count);
        const std::size_t half_base = codeword_size / 2U;
        for (std::size_t &query : proof.queries) {
            const std::uint64_t index = reader.u64();
            if (index > std::numeric_limits<std::size_t>::max() ||
                index >= half_base) {
                return std::nullopt;
            }
            query = static_cast<std::size_t>(index);
        }

        const auto read_frontier = [&](std::size_t leaf_count,
                                       std::span<const std::size_t> indices) {
            const std::size_t expected =
                MerkleTree::multiproof_frontier_positions(
                    leaf_count, indices)
                    .size();
            reader.count(expected);
            std::vector<Digest> result(expected);
            for (Digest &digest : result) {
                digest = reader.digest();
            }
            return result;
        };
        proof.base.leaf_indices =
            queried_leaf_indices(proof.queries, codeword_size);
        reader.count(proof.base.leaf_indices.size());
        proof.base.values_per_leaf = width * base_leaf_size;
        if (proof.base.leaf_indices.size() >
            std::numeric_limits<std::size_t>::max() /
                proof.base.values_per_leaf) {
            return std::nullopt;
        }
        proof.base.values.resize(proof.base.leaf_indices.size() *
                                 proof.base.values_per_leaf);
        for (Fq &value : proof.base.values) {
            value = reader.fq();
        }
        proof.base.frontier = read_frontier(
            base_leaf_count, proof.base.leaf_indices);

        reader.count(root_count);
        proof.folds.resize(root_count);
        std::vector<std::size_t> positions = proof.queries;
        for (std::size_t round = 0; round < root_count; ++round) {
            const std::size_t layer_size =
                codeword_size >> (round + 1U);
            const std::size_t half = layer_size / 2U;
            for (std::size_t &position : positions) {
                position %= half;
            }
            const std::size_t leaf_size = merkle_leaf_size(layer_size);
            const std::size_t leaf_count = merkle_leaf_count(layer_size);
            MerkleMultiOpening<Fq2> &fold = proof.folds[round];
            fold.leaf_indices = queried_leaf_indices(positions, layer_size);
            reader.count(fold.leaf_indices.size());
            fold.values_per_leaf = leaf_size;
            if (fold.leaf_indices.size() >
                std::numeric_limits<std::size_t>::max() / leaf_size) {
                return std::nullopt;
            }
            fold.values.resize(fold.leaf_indices.size() * leaf_size);
            for (Fq2 &value : fold.values) {
                value = reader.fq2();
            }
            fold.frontier = read_frontier(leaf_count, fold.leaf_indices);
        }
        if (!reader.at_end()) {
            return std::nullopt;
        }
        return proof;
    } catch (const std::invalid_argument &) {
        return std::nullopt;
    } catch (const std::out_of_range &) {
        return std::nullopt;
    }
}

std::vector<std::size_t> derive_queries(PublicCoin &public_coin,
                                        std::size_t count,
                                        std::size_t half_codeword) {
    const std::size_t bits = log2_exact(half_codeword);
    if (bits != 0 && count >
                         std::numeric_limits<std::size_t>::max() / bits) {
        throw std::overflow_error("BaseFold query challenge count overflows");
    }
    const std::vector<bool> raw = public_coin.challenge_bits(count * bits);
    std::vector<std::size_t> result(count, 0);
    for (std::size_t query = 0; query < count; ++query) {
        for (std::size_t bit = 0; bit < bits; ++bit) {
            if (raw[query * bits + bit]) {
                result[query] |= std::size_t{1} << bit;
            }
        }
    }
    return result;
}

template <typename Value>
Value read_one(storage::NativeFieldArrayReader &reader) {
    std::array<Value, 1> value{};
    if (reader.read(value) != 1) {
        throw std::runtime_error("truncated external BaseFold array");
    }
    return value.front();
}

std::vector<storage::NativeFieldArrayReader> open_column_readers(
    const storage::NativeFieldArtifact &artifact, std::size_t width,
    bool codewords) {
    std::vector<storage::NativeFieldArrayReader> readers;
    readers.reserve(width);
    for (std::size_t column = 0; column < width; ++column) {
        readers.push_back(artifact.open_array(
            codewords ? codeword_array_name(column)
                      : message_array_name(column)));
    }
    return readers;
}

Fq2 read_weighted_fq(
    std::vector<storage::NativeFieldArrayReader> &readers,
    std::span<const Fq2> weights) {
    if (readers.size() != weights.size()) {
        throw std::logic_error("external BaseFold reader width mismatch");
    }
    Fq2 value = Fq2::zero();
    for (std::size_t column = 0; column < readers.size(); ++column) {
        value += weights[column] * read_one<Fq>(readers[column]);
    }
    return value;
}

Fq2 equality_coordinate(const Fq2 &target, const Fq2 &value) {
    return Fq2::one() - target - value +
           (target + target) * value;
}

Fq2 equality_on_boolean_suffix(std::span<const Fq2> point_lsb,
                               std::size_t suffix) {
    Fq2 value = Fq2::one();
    for (std::size_t variable = 0; variable < point_lsb.size(); ++variable) {
        value *= ((suffix >> variable) & 1U) != 0
                     ? point_lsb[variable]
                     : Fq2::one() - point_lsb[variable];
    }
    return value;
}

Fq2 multilinear_basis(std::span<const Fq2> point,
                      std::size_t assignment) {
    Fq2 value = Fq2::one();
    for (std::size_t variable = 0; variable < point.size(); ++variable) {
        value *= ((assignment >> variable) & 1U) != 0
                     ? point[variable]
                     : Fq2::one() - point[variable];
    }
    return value;
}

std::uint64_t add_sequential_column_pass(
    BaseFoldExternalOpeningReport &report, std::size_t width,
    std::size_t element_count) {
    const std::uint64_t bytes = checked_multiply_u64(
        checked_multiply_u64(checked_u64(width, "column width"),
                             checked_u64(element_count, "column length"),
                             "column pass elements"),
        kSerializedFqBytes, "column pass bytes");
    report.sequential_read_payload_bytes = checked_add_u64(
        report.sequential_read_payload_bytes, bytes,
        "sequential read payloads");
    return bytes;
}

struct FromScratchRound {
    std::array<Fq2, 2> values{};
    Fq2 terminal_message_zero = Fq2::zero();
    Fq2 terminal_message_one = Fq2::zero();
    Fq2 terminal_operand_zero = Fq2::zero();
    Fq2 terminal_operand_one = Fq2::zero();
};

FromScratchRound compute_sumcheck_round_from_source(
    const BaseFoldExternalProverState &state,
    std::span<const Fq2> column_weights,
    std::span<const Fq2> point_lsb,
    std::span<const Fq2> bound_challenges,
    BaseFoldExternalOpeningReport &report) {
    const std::size_t message_size =
        static_cast<std::size_t>(state.commitment.evaluation_count);
    const std::size_t round_index = bound_challenges.size();
    if (round_index >= point_lsb.size() ||
        point_lsb.size() != log2_exact(message_size)) {
        throw std::logic_error("invalid from-scratch sumcheck round");
    }
    const std::size_t half_group = std::size_t{1} << round_index;
    const std::size_t group_size = half_group << 1U;
    const std::size_t group_count = message_size / group_size;
    std::vector<storage::NativeFieldArrayReader> readers =
        open_column_readers(*state.artifact, column_weights.size(), false);
    Fq2 bound_operand = Fq2::one();
    for (std::size_t variable = 0; variable < round_index; ++variable) {
        bound_operand *= equality_coordinate(
            point_lsb[variable], bound_challenges[variable]);
    }
    const Fq2 operand_zero =
        bound_operand * (Fq2::one() - point_lsb[round_index]);
    const Fq2 operand_one =
        bound_operand * point_lsb[round_index];

    FromScratchRound result;
    for (std::size_t group = 0; group < group_count; ++group) {
        std::array<Fq2, 2> message{};
        for (std::size_t branch = 0; branch < 2; ++branch) {
            for (std::size_t assignment = 0; assignment < half_group;
                 ++assignment) {
                message[branch] +=
                    multilinear_basis(bound_challenges, assignment) *
                    read_weighted_fq(readers, column_weights);
            }
        }
        const Fq2 suffix = equality_on_boolean_suffix(
            point_lsb.subspan(round_index + 1U), group);
        const Fq2 b0 = operand_zero * suffix;
        const Fq2 b1 = operand_one * suffix;
        result.values[0] += message[1] * b1;
        result.values[1] +=
            (message[1] + message[1] - message[0]) *
            (b1 + b1 - b0);
        if (group_count == 1) {
            result.terminal_message_zero = message[0];
            result.terminal_message_one = message[1];
            result.terminal_operand_zero = b0;
            result.terminal_operand_one = b1;
        }
    }
    report.sumcheck_sequential_read_payload_bytes = checked_add_u64(
        report.sumcheck_sequential_read_payload_bytes,
        add_sequential_column_pass(report, column_weights.size(),
                                   message_size),
        "BaseFold sumcheck source reads");
    return result;
}

struct RestrictedTables {
    std::vector<Fq2> message;
    std::vector<Fq2> operand;
};

RestrictedTables materialize_restricted_tables(
    const BaseFoldExternalProverState &state,
    std::span<const Fq2> column_weights,
    std::span<const Fq2> point_lsb,
    std::span<const Fq2> bound_challenges,
    BaseFoldExternalOpeningReport &report) {
    const std::size_t message_size =
        static_cast<std::size_t>(state.commitment.evaluation_count);
    const std::size_t block_size =
        std::size_t{1} << bound_challenges.size();
    const std::size_t active_size = message_size / block_size;
    RestrictedTables tables{
        std::vector<Fq2>(active_size, Fq2::zero()),
        std::vector<Fq2>(active_size, Fq2::zero()),
    };
    std::vector<storage::NativeFieldArrayReader> readers =
        open_column_readers(*state.artifact, column_weights.size(), false);
    Fq2 operand_prefix = Fq2::one();
    for (std::size_t variable = 0; variable < bound_challenges.size();
         ++variable) {
        operand_prefix *= equality_coordinate(
            point_lsb[variable], bound_challenges[variable]);
    }
    for (std::size_t suffix = 0; suffix < active_size; ++suffix) {
        Fq2 message = Fq2::zero();
        for (std::size_t assignment = 0; assignment < block_size;
             ++assignment) {
            message += multilinear_basis(bound_challenges, assignment) *
                       read_weighted_fq(readers, column_weights);
        }
        tables.message[suffix] = message;
        tables.operand[suffix] =
            operand_prefix * equality_on_boolean_suffix(
                                 point_lsb.subspan(bound_challenges.size()),
                                 suffix);
    }
    report.sumcheck_sequential_read_payload_bytes = checked_add_u64(
        report.sumcheck_sequential_read_payload_bytes,
        add_sequential_column_pass(report, column_weights.size(),
                                   message_size),
        "BaseFold sumcheck source reads");
    return tables;
}

void enforce_field_peak(BaseFoldExternalOpeningReport &report,
                        const BaseFoldExternalOpeningOptions &options,
                        std::uint64_t bytes) {
    report.peak_working_field_bytes =
        std::max(report.peak_working_field_bytes, bytes);
    if (bytes > options.max_working_field_bytes) {
        throw std::runtime_error(
            "BaseFold external opening field-memory limit exceeded");
    }
}

using FoldValueConsumer = std::function<void(const Fq2 &)>;

std::vector<Digest> external_merkle_frontier(
    const storage::NativeFieldArtifact &artifact,
    bool base_tree, std::size_t leaf_count,
    std::span<const std::size_t> requested,
    BaseFoldExternalOpeningReport &report) {
    const std::size_t depth = log2_exact(leaf_count);
    const std::vector<basefold::MerkleNodePosition> frontier =
        MerkleTree::multiproof_frontier_positions(leaf_count, requested);
    std::vector<std::pair<std::size_t, std::size_t>> positions;
    positions.reserve(frontier.size());
    for (std::size_t index = 0; index < frontier.size(); ++index) {
        const auto &node = frontier[index];
        positions.emplace_back(
            postorder_node_position(depth, node.level, node.index), index);
    }
    std::sort(positions.begin(), positions.end());
    storage::NativeFieldArrayReader reader = artifact.open_array(
        tree_postorder_array_name(base_tree));
    std::vector<Digest> result(frontier.size());
    std::vector<Digest> adjacent;
    std::size_t cursor = 0;
    while (cursor < positions.size()) {
        std::size_t end = cursor + 1U;
        while (end < positions.size() &&
               positions[end].first == positions[end - 1U].first + 1U) {
            ++end;
        }
        adjacent.resize(end - cursor);
        reader.seek(positions[cursor].first);
        if (reader.read(adjacent) != adjacent.size()) {
            throw std::runtime_error(
                "truncated external Merkle multiproof frontier");
        }
        for (std::size_t offset = 0; offset < adjacent.size(); ++offset) {
            result[positions[cursor + offset].second] = adjacent[offset];
        }
        const std::uint64_t bytes = checked_multiply_u64(
            checked_u64(adjacent.size(), "Merkle frontier run"),
            Digest{}.size(), "Merkle frontier run bytes");
        report.indexed_read_payload_bytes = checked_add_u64(
            report.indexed_read_payload_bytes, bytes,
            "indexed read payloads");
        report.base_query_indexed_read_payload_bytes = checked_add_u64(
            report.base_query_indexed_read_payload_bytes, bytes,
            "base query indexed reads");
        cursor = end;
    }
    return result;
}

bool external_path_prefix(const std::filesystem::path &prefix,
                          const std::filesystem::path &path) {
    auto prefix_part = prefix.begin();
    auto path_part = path.begin();
    while (prefix_part != prefix.end() && path_part != path.end() &&
           *prefix_part == *path_part) {
        ++prefix_part;
        ++path_part;
    }
    return prefix_part == prefix.end();
}

struct FoldScratchProjection {
    std::uint64_t peak_bytes = 0;
    std::uint64_t one_pass_written_bytes = 0;
    std::uint64_t one_pass_payload_bytes = 0;
    std::uint64_t one_pass_chunk_artifacts = 0;
};

FoldScratchProjection project_chunked_fold_scratch(
    std::size_t codeword_size, std::size_t message_log,
    std::size_t maximum_chunk_elements);

struct OpeningWorkingProjection {
    std::uint64_t minimum_bytes = 0;
    std::uint64_t required_bytes = 0;
    std::size_t materialized_sumcheck_entries = 0;
};

OpeningWorkingProjection project_opening_working_fields(
    const PcsCommitment &commitment,
    const BaseFoldPcsParameters &parameters,
    std::uint64_t max_working_field_bytes) {
    if (max_working_field_bytes == 0) {
        throw std::invalid_argument(
            "BaseFold opening planning needs a nonzero field-memory cap");
    }
    if (commitment.evaluation_count == 0 ||
        commitment.evaluation_count >
            std::numeric_limits<std::size_t>::max()) {
        throw std::invalid_argument(
            "BaseFold opening planning has an invalid message size");
    }
    const std::size_t message_size =
        static_cast<std::size_t>(commitment.evaluation_count);
    const std::size_t message_log = log2_exact(message_size);
    const std::size_t codeword_size = checked_codeword_size(
        message_size, parameters.log_rate);
    const std::uint64_t persistent_field_bytes = checked_multiply_u64(
        checked_multiply_u64(checked_u64(message_log, "message log"), 2U,
                             "point and challenge fields"),
        sizeof(Fq2), "point and challenge bytes");

    const auto schedule_peak = [&](bool permit_table) {
        OpeningWorkingProjection projection;
        projection.required_bytes = persistent_field_bytes;
        std::size_t table_capacity_entries = 0;
        if (message_log == 0) {
            projection.required_bytes = std::max(
                projection.required_bytes,
                checked_add_u64(
                    persistent_field_bytes,
                    checked_multiply_u64(
                        checked_u64(codeword_size,
                                    "singleton codeword size"),
                        sizeof(Fq2), "singleton final codeword bytes"),
                    "singleton working fields"));
        } else {
            for (std::size_t round = 0; round < message_log; ++round) {
                if (permit_table && table_capacity_entries == 0 &&
                    round + 1U < message_log) {
                    const std::size_t next_size =
                        message_size >> (round + 1U);
                    const std::uint64_t table_bytes = checked_multiply_u64(
                        checked_multiply_u64(
                            checked_u64(next_size,
                                        "sumcheck table size"),
                            2U, "sumcheck table entries"),
                        sizeof(Fq2), "sumcheck table bytes");
                    if (checked_add_u64(
                            persistent_field_bytes, table_bytes,
                            "sumcheck working fields") <=
                        max_working_field_bytes) {
                        table_capacity_entries = 2U * next_size;
                        projection.materialized_sumcheck_entries =
                            next_size;
                    }
                }
                const std::uint64_t live_table_bytes =
                    checked_multiply_u64(
                        checked_u64(table_capacity_entries,
                                    "live sumcheck table entries"),
                        sizeof(Fq2), "live sumcheck table bytes");
                const std::size_t output_size =
                    codeword_size >> (round + 1U);
                const std::uint64_t output_buffer_bytes =
                    round + 1U < message_log
                        ? checked_multiply_u64(
                              checked_u64(merkle_leaf_size(output_size),
                                          "FRI leaf size"),
                              sizeof(Fq2), "FRI leaf buffer")
                        : checked_multiply_u64(
                              checked_u64(output_size,
                                          "final FRI size"),
                              sizeof(Fq2), "final FRI field bytes");
                projection.required_bytes = std::max(
                    projection.required_bytes,
                    checked_add_u64(
                        checked_add_u64(
                            persistent_field_bytes, live_table_bytes,
                            "live BaseFold fields"),
                        output_buffer_bytes, "FRI working fields"));
            }
        }

        projection.required_bytes = std::max(
            projection.required_bytes,
            checked_multiply_u64(
                checked_multiply_u64(
                    checked_u64(merkle_leaf_size(codeword_size),
                                "base leaf size"),
                    checked_add_u64(commitment.width, 1U,
                                    "base leaf staging width"),
                    "base query staging fields"),
                sizeof(Fq), "base query leaf buffer"));
        for (std::size_t round = 0; round + 1U < message_log; ++round) {
            const std::size_t layer_size =
                codeword_size >> (round + 1U);
            projection.required_bytes = std::max(
                projection.required_bytes,
                checked_multiply_u64(
                    checked_u64(merkle_leaf_size(layer_size),
                                "fold leaf size"),
                    sizeof(Fq2), "fold query leaf buffer"));
        }
        return projection;
    };

    OpeningWorkingProjection result = schedule_peak(true);
    result.minimum_bytes = schedule_peak(false).required_bytes;
    if (max_working_field_bytes < result.minimum_bytes ||
        result.required_bytes > max_working_field_bytes) {
        throw std::runtime_error(
            "BaseFold external opening field-memory limit is below the "
            "deterministic minimum");
    }
    return result;
}

BaseFoldExternalOpeningPreflight preflight_external_opening_impl(
    const std::shared_ptr<const IPCS::ProverState> &prover_state,
    const PcsCommitment &expected_commitment,
    const BaseFoldPcsParameters &parameters,
    const BaseFoldExternalOpeningOptions &options,
    std::shared_ptr<const IPCS::ProverState> *validated_state = nullptr) {
    const auto state = std::dynamic_pointer_cast<
        const BaseFoldExternalProverState>(prover_state);
    if (!state || !state->artifact ||
        state->commitment != expected_commitment ||
        expected_commitment.scheme != BaseFoldPcs::kSchemeIdentifier ||
        expected_commitment.log_rate != parameters.log_rate ||
        expected_commitment.query_count != parameters.query_count ||
        expected_commitment.width == 0 ||
        expected_commitment.width >
            std::numeric_limits<std::size_t>::max() ||
        expected_commitment.evaluation_count == 0 ||
        expected_commitment.evaluation_count >
            std::numeric_limits<std::size_t>::max()) {
        throw std::invalid_argument(
            "BaseFold external state is not bound to the expected "
            "commitment");
    }
    if (options.max_live_storage_bytes == 0 ||
        options.max_total_scratch_bytes == 0 ||
        options.min_free_bytes == 0 ||
        options.max_working_field_bytes == 0) {
        throw std::invalid_argument(
            "BaseFold external opening needs explicit nonzero limits");
    }
    if (!is_power_of_two(options.fold_chunk_elements)) {
        throw std::invalid_argument(
            "BaseFold fold chunk size must be a power of two");
    }

    // Reopen at the admission boundary. This repeats the artifact's complete
    // manifest/integrity scan so a retained handle cannot defer corruption
    // detection until after a composing protocol has sampled challenges.
    auto validated = std::make_shared<const storage::NativeFieldArtifact>(
        storage::NativeFieldArtifact::open(
            state->artifact->directory(),
            basefold_external_state_identity(expected_commitment)));
    validate_external_state_layout(*validated, expected_commitment);

    const std::filesystem::path scratch =
        std::filesystem::absolute(options.scratch_directory)
            .lexically_normal();
    const std::filesystem::file_status scratch_status =
        std::filesystem::symlink_status(scratch);
    if (!std::filesystem::is_directory(scratch_status) ||
        std::filesystem::is_symlink(scratch_status) ||
        !std::filesystem::is_empty(scratch)) {
        throw std::invalid_argument(
            "BaseFold external opening needs an empty real scratch "
            "directory");
    }
    const std::filesystem::path state_directory =
        std::filesystem::canonical(validated->directory());
    const std::filesystem::path scratch_directory =
        std::filesystem::canonical(scratch);
    if (external_path_prefix(state_directory, scratch_directory) ||
        external_path_prefix(scratch_directory, state_directory)) {
        throw std::invalid_argument(
            "BaseFold external state and opening scratch must be "
            "disjoint");
    }

    const std::size_t message_size = static_cast<std::size_t>(
        expected_commitment.evaluation_count);
    const std::size_t message_log = log2_exact(message_size);
    const std::size_t codeword_size =
        checked_codeword_size(message_size, parameters.log_rate);
    BaseFoldExternalOpeningPreflight result;
    result.state_artifact_directory = state_directory;
    result.state_artifact_physical_bytes = validated->physical_bytes();

    if (message_log >= 2) {
        const std::size_t first_fold_size = codeword_size / 2U;
        const std::size_t selected_chunk =
            std::min(first_fold_size, options.fold_chunk_elements);
        if (selected_chunk % merkle_leaf_size(first_fold_size) != 0) {
            throw std::invalid_argument(
                "BaseFold fold chunks must align to Merkle leaves");
        }
    }
    const FoldScratchProjection scratch_projection =
        project_chunked_fold_scratch(
            codeword_size, message_log, options.fold_chunk_elements);
    result.required_scratch_physical_bytes = scratch_projection.peak_bytes;
    result.required_scratch_written_physical_bytes = checked_multiply_u64(
        scratch_projection.one_pass_written_bytes, 2U,
        "BaseFold two-pass scratch writes");
    result.required_sequential_write_payload_bytes = checked_multiply_u64(
        scratch_projection.one_pass_payload_bytes, 2U,
        "BaseFold two-pass payload writes");
    result.required_chunk_artifacts_written = checked_multiply_u64(
        scratch_projection.one_pass_chunk_artifacts, 2U,
        "BaseFold two-pass chunk artifacts");
    result.required_scratch_files_written = checked_multiply_u64(
        result.required_chunk_artifacts_written, 2U,
        "BaseFold two-pass scratch files");
    if (result.required_scratch_physical_bytes >
        options.max_total_scratch_bytes) {
        throw std::runtime_error(
            "BaseFold external opening scratch quota is below the exact "
            "requirement");
    }
    result.required_live_storage_bytes = checked_add_u64(
        result.state_artifact_physical_bytes,
        result.required_scratch_physical_bytes,
        "BaseFold opening live storage");
    if (result.required_live_storage_bytes >
        options.max_live_storage_bytes) {
        throw std::runtime_error(
            "BaseFold external opening live-storage quota is below the "
            "exact requirement");
    }
    const std::uint64_t required_free = checked_add_u64(
        result.required_scratch_physical_bytes, options.min_free_bytes,
        "BaseFold opening free-space requirement");
    if (std::filesystem::space(scratch).available < required_free) {
        throw std::runtime_error(
            "BaseFold external opening has insufficient preflight free "
            "space");
    }

    const OpeningWorkingProjection working =
        project_opening_working_fields(
            expected_commitment, parameters,
            options.max_working_field_bytes);
    result.required_working_field_bytes = working.required_bytes;
    result.materialized_sumcheck_entries =
        working.materialized_sumcheck_entries;
    if (validated_state != nullptr) {
        *validated_state =
            std::make_shared<const BaseFoldExternalProverState>(
                std::move(validated), expected_commitment);
    }
    return result;
}

void fill_base_query_openings(
    const BaseFoldExternalProverState &state,
    std::span<const std::size_t> query_indices, BaseFoldProof &proof,
    const BaseFoldExternalOpeningOptions &options,
    BaseFoldExternalOpeningReport &report) {
    const std::size_t width = static_cast<std::size_t>(state.commitment.width);
    const std::size_t codeword_size = checked_codeword_size(
        static_cast<std::size_t>(state.commitment.evaluation_count),
        state.commitment.log_rate);
    const std::size_t leaf_size = merkle_leaf_size(codeword_size);
    const std::size_t leaf_count = merkle_leaf_count(codeword_size);
    proof.base.leaf_indices =
        queried_leaf_indices(query_indices, codeword_size);
    proof.base.frontier = external_merkle_frontier(
        *state.artifact, true, leaf_count, proof.base.leaf_indices, report);
    enforce_field_peak(
        report, options,
        checked_multiply_u64(
            checked_multiply_u64(checked_u64(leaf_size, "base leaf size"),
                                 checked_add_u64(
                                     checked_u64(width, "base width"), 1U,
                                     "base leaf staging width"),
                                 "base query staging fields"),
            sizeof(Fq), "base query leaf buffer"));
    proof.base.values_per_leaf = leaf_size * width;
    proof.base.values.resize(proof.base.leaf_indices.size() *
                             proof.base.values_per_leaf);
    std::vector<storage::NativeFieldArrayReader> codeword_readers =
        open_column_readers(*state.artifact, width, true);
    std::vector<Fq> column_values(leaf_size);
    for (std::size_t opened_leaf_index = 0;
         opened_leaf_index < proof.base.leaf_indices.size();
         ++opened_leaf_index) {
        const std::size_t leaf_index =
            proof.base.leaf_indices[opened_leaf_index];
        const std::size_t output_offset =
            opened_leaf_index * proof.base.values_per_leaf;
        for (std::size_t column = 0; column < width; ++column) {
            storage::NativeFieldArrayReader &reader =
                codeword_readers[column];
            reader.seek(leaf_index * leaf_size);
            if (reader.read(column_values) != leaf_size) {
                throw std::runtime_error("truncated base query leaf");
            }
            for (std::size_t offset = 0; offset < leaf_size; ++offset) {
                proof.base.values[output_offset + offset * width + column] =
                    column_values[offset];
            }
        }
        report.indexed_read_payload_bytes = checked_add_u64(
            report.indexed_read_payload_bytes,
            checked_multiply_u64(
                checked_multiply_u64(checked_u64(width, "base width"),
                                     checked_u64(leaf_size, "base leaf size"),
                                     "base query values"),
                kSerializedFqBytes, "base query bytes"),
            "indexed read payloads");
        report.base_query_indexed_read_payload_bytes = checked_add_u64(
            report.base_query_indexed_read_payload_bytes,
            checked_multiply_u64(
                checked_multiply_u64(checked_u64(width, "base width"),
                                     checked_u64(leaf_size, "base leaf size"),
                                     "base query values"),
                kSerializedFqBytes, "base query bytes"),
            "base query indexed reads");
    }
}

std::uint64_t fold_chunk_physical_bytes(std::size_t element_count) {
    const std::array<storage::NativeFieldArrayLayout, 1> layout{{
        {std::string(kFoldValuesArray),
         storage::NativeFieldElementKind::Fq2,
         checked_u64(element_count, "fold chunk length")},
    }};
    return storage::native_field_artifact_physical_bytes(layout);
}

std::size_t fold_chunk_size(std::size_t layer_size,
                            std::size_t maximum) {
    if (!is_power_of_two(maximum)) {
        throw std::invalid_argument(
            "BaseFold fold chunk size must be a power of two");
    }
    return std::min(layer_size, maximum);
}

std::vector<std::size_t> fold_chunk_lengths(std::size_t layer_size,
                                            std::size_t maximum) {
    const std::size_t chunk_size = fold_chunk_size(layer_size, maximum);
    std::vector<std::size_t> result;
    result.reserve(layer_size / chunk_size);
    for (std::size_t first = 0; first < layer_size;
         first += chunk_size) {
        result.push_back(std::min(chunk_size, layer_size - first));
    }
    return result;
}

FoldScratchProjection project_chunked_fold_scratch(
    std::size_t codeword_size, std::size_t message_log,
    std::size_t maximum_chunk_elements) {
    FoldScratchProjection result;
    if (message_log < 2) {
        return result;
    }

    const std::size_t root_count = message_log - 1U;
    std::vector<std::uint64_t> current;
    const auto layer_bytes = [&](std::size_t layer_size) {
        std::vector<std::uint64_t> bytes;
        for (const std::size_t count :
             fold_chunk_lengths(layer_size, maximum_chunk_elements)) {
            bytes.push_back(fold_chunk_physical_bytes(count));
            result.one_pass_chunk_artifacts = checked_add_u64(
                result.one_pass_chunk_artifacts, 1U,
                "BaseFold one-pass chunk artifacts");
            result.one_pass_written_bytes = checked_add_u64(
                result.one_pass_written_bytes, bytes.back(),
                "BaseFold one-pass chunk writes");
        }
        result.one_pass_payload_bytes = checked_add_u64(
            result.one_pass_payload_bytes,
            checked_multiply_u64(checked_u64(layer_size, "fold layer size"),
                                 kSerializedFq2Bytes,
                                 "fold layer payload bytes"),
            "BaseFold one-pass payload writes");
        return bytes;
    };

    std::uint64_t live = 0;
    current = layer_bytes(codeword_size / 2U);
    for (const std::uint64_t bytes : current) {
        live = checked_add_u64(live, bytes, "BaseFold scratch live bytes");
        result.peak_bytes = std::max(result.peak_bytes, live);
    }

    std::size_t source_size = codeword_size / 2U;
    for (std::size_t round = 1; round < root_count; ++round) {
        const std::size_t output_size = source_size / 2U;
        std::vector<std::uint64_t> next = layer_bytes(output_size);
        if (current.size() != 1U &&
            current.size() != 2U * next.size()) {
            throw std::logic_error("invalid BaseFold chunk projection");
        }
        for (std::size_t chunk = 0; chunk < next.size(); ++chunk) {
            live = checked_add_u64(live, next[chunk],
                                   "BaseFold scratch live bytes");
            result.peak_bytes = std::max(result.peak_bytes, live);
            if (current.size() == 1U) {
                if (next.size() != 1U || live < current.front()) {
                    throw std::logic_error(
                        "invalid BaseFold singleton chunk projection");
                }
                live -= current.front();
            } else {
                const std::uint64_t consumed = checked_add_u64(
                    current[chunk], current[chunk + next.size()],
                    "BaseFold consumed chunk bytes");
                if (live < consumed) {
                    throw std::logic_error(
                        "invalid BaseFold scratch projection balance");
                }
                live -= consumed;
            }
        }
        current = std::move(next);
        source_size = output_size;
    }
    return result;
}

struct ScratchFileSnapshot {
    std::filesystem::path name;
    std::uint64_t bytes = 0;
    std::uintmax_t device = 0;
    std::uintmax_t inode = 0;

    bool operator==(const ScratchFileSnapshot &) const = default;
};

ScratchFileSnapshot snapshot_scratch_file(
    const std::filesystem::path &path) {
    const std::filesystem::file_status status =
        std::filesystem::symlink_status(path);
    if (!std::filesystem::is_regular_file(status) ||
        std::filesystem::is_symlink(status)) {
        throw std::runtime_error(
            "BaseFold scratch chunk contains a non-regular entry");
    }
#ifndef _WIN32
    struct stat metadata {};
    if (::lstat(path.c_str(), &metadata) != 0 ||
        !S_ISREG(metadata.st_mode) || metadata.st_size < 0) {
        throw std::runtime_error(
            "failed to inspect a BaseFold scratch file");
    }
    return ScratchFileSnapshot{
        path.filename(), static_cast<std::uint64_t>(metadata.st_size),
        static_cast<std::uintmax_t>(metadata.st_dev),
        static_cast<std::uintmax_t>(metadata.st_ino)};
#else
    return ScratchFileSnapshot{
        path.filename(),
        checked_u64(std::filesystem::file_size(path),
                    "BaseFold scratch file bytes"),
        0,
        0};
#endif
}

std::vector<ScratchFileSnapshot> snapshot_scratch_chunk(
    const std::filesystem::path &directory) {
    std::vector<ScratchFileSnapshot> result;
    for (const std::filesystem::directory_entry &entry :
         std::filesystem::directory_iterator(directory)) {
        result.push_back(snapshot_scratch_file(entry.path()));
    }
    std::sort(result.begin(), result.end(),
              [](const ScratchFileSnapshot &left,
                 const ScratchFileSnapshot &right) {
                  return left.name.generic_string() <
                         right.name.generic_string();
              });
    if (result.size() != 2U) {
        throw std::runtime_error(
            "BaseFold scratch chunk has the wrong file count");
    }
    return result;
}

struct ScratchDirectorySnapshot {
    std::filesystem::path canonical_path;
    std::uintmax_t device = 0;
    std::uintmax_t inode = 0;
};

ScratchDirectorySnapshot snapshot_scratch_directory(
    const std::filesystem::path &path) {
    const std::filesystem::file_status status =
        std::filesystem::symlink_status(path);
    if (!std::filesystem::is_directory(status) ||
        std::filesystem::is_symlink(status)) {
        throw std::runtime_error(
            "BaseFold pending scratch path is not a real directory");
    }
    const std::filesystem::path canonical =
        std::filesystem::canonical(path);
#ifndef _WIN32
    struct stat metadata {};
    if (::lstat(canonical.c_str(), &metadata) != 0 ||
        !S_ISDIR(metadata.st_mode)) {
        throw std::runtime_error(
            "failed to inspect a BaseFold scratch directory");
    }
    return ScratchDirectorySnapshot{
        canonical, static_cast<std::uintmax_t>(metadata.st_dev),
        static_cast<std::uintmax_t>(metadata.st_ino)};
#else
    return ScratchDirectorySnapshot{canonical, 0, 0};
#endif
}

bool same_scratch_directory(const ScratchDirectorySnapshot &expected) {
    try {
        const ScratchDirectorySnapshot current =
            snapshot_scratch_directory(expected.canonical_path);
        return current.canonical_path == expected.canonical_path &&
#ifndef _WIN32
               current.device == expected.device &&
               current.inode == expected.inode;
#else
               true;
#endif
    } catch (const std::exception &) {
        return false;
    }
}

bool pending_scratch_filename(const std::filesystem::path &name) {
    const std::string selected = name.generic_string();
    return selected == "array-0000000000000000.partial" ||
           selected == "array-0000000000000000.bin" ||
           selected == "manifest.partial" ||
           selected == "manifest.bin";
}

/// Owns the exact, initially empty directory created for one unpublished
/// scratch chunk. Publication transfers ownership to ScratchRootCleanup.
/// Before that transfer, an exceptional exit removes only the writer's four
/// possible regular-file names and then the same created directory. An
/// unexpected entry or path substitution is retained for diagnosis.
class PendingScratchChunk {
  public:
    PendingScratchChunk(const std::filesystem::path &directory,
                        const std::filesystem::path &root)
        : directory_(snapshot_scratch_directory(directory)) {
        const std::filesystem::path canonical_root =
            std::filesystem::canonical(root);
        if (!external_path_prefix(canonical_root,
                                  directory_.canonical_path) ||
            canonical_root == directory_.canonical_path ||
            !std::filesystem::is_empty(directory_.canonical_path)) {
            throw std::runtime_error(
                "BaseFold pending scratch chunk escaped its empty root");
        }
    }

    PendingScratchChunk(const PendingScratchChunk &) = delete;
    PendingScratchChunk &operator=(const PendingScratchChunk &) = delete;

    ~PendingScratchChunk() {
        if (armed_) {
            cleanup_noexcept();
        }
    }

    void bind_published_files() {
        if (!armed_ || !same_scratch_directory(directory_)) {
            throw std::runtime_error(
                "BaseFold pending scratch chunk path was substituted");
        }
        bound_files_ = snapshot_scratch_chunk(
            directory_.canonical_path);
    }

    void disarm() noexcept { armed_ = false; }

  private:
    void cleanup_noexcept() noexcept {
        try {
            if (!same_scratch_directory(directory_)) {
                return;
            }
            std::vector<ScratchFileSnapshot> files;
            for (const std::filesystem::directory_entry &entry :
                 std::filesystem::directory_iterator(
                     directory_.canonical_path)) {
                if (!pending_scratch_filename(entry.path().filename())) {
                    return;
                }
                files.push_back(snapshot_scratch_file(entry.path()));
            }
            std::sort(files.begin(), files.end(),
                      [](const ScratchFileSnapshot &left,
                         const ScratchFileSnapshot &right) {
                          return left.name.generic_string() <
                                 right.name.generic_string();
                      });
            if (bound_files_.has_value() && files != *bound_files_) {
                return;
            }
            for (const ScratchFileSnapshot &file : files) {
                if (!same_scratch_directory(directory_) ||
                    snapshot_scratch_file(
                        directory_.canonical_path / file.name) != file) {
                    return;
                }
                std::error_code error;
                if (!std::filesystem::remove(
                        directory_.canonical_path / file.name, error) ||
                    error) {
                    return;
                }
            }
            if (!same_scratch_directory(directory_) ||
                !std::filesystem::is_empty(directory_.canonical_path)) {
                return;
            }
            std::error_code error;
            (void)std::filesystem::remove(directory_.canonical_path, error);
        } catch (const std::exception &) {
            // Cleanup is deliberately fail-closed: never recurse through or
            // remove an entry that cannot be rebound to this exact chunk.
        }
    }

    ScratchDirectorySnapshot directory_;
    std::optional<std::vector<ScratchFileSnapshot>> bound_files_;
    bool armed_ = true;
};

struct PublishedScratchChunk {
    std::filesystem::path directory;
    laminate::Digest identity{};
    std::size_t element_count = 0;
    std::uint64_t physical_bytes = 0;
    std::vector<storage::NativeFieldArrayDescriptor> arrays;
    std::vector<ScratchFileSnapshot> files;
};

class ScratchRootCleanup {
  public:
    explicit ScratchRootCleanup(std::filesystem::path root)
        : root_(std::move(root)) {}

    ~ScratchRootCleanup() {
        if (!armed_) {
            return;
        }
        for (auto chunk = chunks_.rbegin(); chunk != chunks_.rend(); ++chunk) {
            try {
                delete_chunk(chunk->second);
            } catch (const std::exception &) {
                // A substituted or corrupt path is deliberately retained for
                // diagnosis. Failure cleanup never recursively removes an
                // unvalidated tree.
            }
        }
        for (auto path = owned_layers_.rbegin();
             path != owned_layers_.rend(); ++path) {
            std::error_code ignored;
            (void)std::filesystem::remove(*path, ignored);
        }
    }

    void own(const std::filesystem::path &path) {
        const std::filesystem::path canonical =
            std::filesystem::canonical(path);
        if (!external_path_prefix(root_, canonical) || canonical == root_) {
            throw std::runtime_error(
                "BaseFold scratch layer escaped its caller-owned root");
        }
        owned_layers_.push_back(canonical);
    }

    void published(
        const storage::NativeFieldArtifact &artifact,
        const laminate::Digest &identity, std::size_t element_count,
        std::uint64_t physical_bytes) {
        const std::filesystem::path canonical =
            std::filesystem::canonical(artifact.directory());
        if (!external_path_prefix(root_, canonical) || canonical == root_ ||
            artifact.identity() != identity ||
            artifact.physical_bytes() != physical_bytes) {
            throw std::runtime_error(
                "BaseFold scratch publication escaped its bound root");
        }
        PublishedScratchChunk record{
            canonical, identity, element_count, physical_bytes,
            artifact.arrays(), snapshot_scratch_chunk(canonical)};
        const auto [entry, inserted] = chunks_.emplace(
            canonical.generic_string(), std::move(record));
        (void)entry;
        if (!inserted) {
            throw std::logic_error(
                "duplicate BaseFold scratch chunk publication");
        }
    }

    void remove_published(const std::filesystem::path &directory) {
        const std::filesystem::path canonical =
            std::filesystem::canonical(directory);
        const auto found = chunks_.find(canonical.generic_string());
        if (found == chunks_.end()) {
            throw std::logic_error(
                "untracked BaseFold scratch chunk deletion");
        }
        delete_chunk(found->second);
        chunks_.erase(found);
    }

    void finish() {
        if (!chunks_.empty() || !std::filesystem::is_empty(root_)) {
            throw std::runtime_error(
                "BaseFold opening did not reclaim its scratch root");
        }
        armed_ = false;
    }

  private:
    static void delete_chunk(const PublishedScratchChunk &record) {
        const std::filesystem::file_status status =
            std::filesystem::symlink_status(record.directory);
        if (!std::filesystem::is_directory(status) ||
            std::filesystem::is_symlink(status) ||
            std::filesystem::canonical(record.directory) !=
                record.directory ||
            snapshot_scratch_chunk(record.directory) != record.files) {
            throw std::runtime_error(
                "BaseFold scratch chunk path was substituted");
        }
        const storage::NativeFieldArtifact reopened =
            storage::NativeFieldArtifact::open(record.directory,
                                               record.identity);
        if (reopened.physical_bytes() != record.physical_bytes ||
            reopened.arrays() != record.arrays ||
            reopened.arrays().size() != 1U ||
            reopened.arrays().front().name != kFoldValuesArray ||
            reopened.arrays().front().kind !=
                storage::NativeFieldElementKind::Fq2 ||
            reopened.arrays().front().element_count !=
                record.element_count) {
            throw std::runtime_error(
                "BaseFold scratch chunk changed before deletion");
        }
        for (const ScratchFileSnapshot &file : record.files) {
            std::error_code error;
            if (!std::filesystem::remove(record.directory / file.name,
                                         error) ||
                error) {
                throw std::runtime_error(
                    "failed to remove a bound BaseFold scratch file");
            }
        }
        std::error_code error;
        if (!std::filesystem::remove(record.directory, error) || error) {
            throw std::runtime_error(
                "failed to remove a bound BaseFold scratch directory");
        }
    }

    std::filesystem::path root_;
    std::vector<std::filesystem::path> owned_layers_;
    std::map<std::string, PublishedScratchChunk> chunks_;
    bool armed_ = true;
};

class FoldScratchLedger {
  public:
    FoldScratchLedger(const BaseFoldExternalOpeningOptions &options,
                      std::uint64_t state_bytes,
                      BaseFoldExternalOpeningReport &report)
        : options_(options), state_bytes_(state_bytes), report_(report) {}

    void admit(std::uint64_t bytes) const {
        const std::uint64_t prospective = checked_add_u64(
            live_bytes_, bytes, "BaseFold scratch publication");
        if (prospective > options_.max_total_scratch_bytes ||
            checked_add_u64(state_bytes_, prospective,
                            "BaseFold live opening storage") >
                options_.max_live_storage_bytes) {
            throw std::runtime_error(
                "BaseFold chunk publication exceeds admitted storage");
        }
    }

    void published(std::uint64_t bytes, bool pass_two) {
        live_bytes_ = checked_add_u64(live_bytes_, bytes,
                                      "BaseFold live scratch bytes");
        report_.scratch_physical_bytes = live_bytes_;
        report_.scratch_peak_physical_bytes = std::max(
            report_.scratch_peak_physical_bytes, live_bytes_);
        report_.scratch_written_physical_bytes = checked_add_u64(
            report_.scratch_written_physical_bytes, bytes,
            "BaseFold scratch writes");
        std::uint64_t &pass_bytes =
            pass_two ? report_.pass_two_scratch_written_physical_bytes
                     : report_.pass_one_scratch_written_physical_bytes;
        pass_bytes = checked_add_u64(pass_bytes, bytes,
                                     "BaseFold pass scratch writes");
        report_.scratch_chunk_artifacts_written = checked_add_u64(
            report_.scratch_chunk_artifacts_written, 1U,
            "BaseFold scratch chunk artifacts");
        std::uint64_t &pass_artifacts =
            pass_two ? report_.pass_two_chunk_artifacts_written
                     : report_.pass_one_chunk_artifacts_written;
        pass_artifacts = checked_add_u64(
            pass_artifacts, 1U, "BaseFold pass chunk artifacts");
        report_.scratch_files_written = checked_add_u64(
            report_.scratch_files_written, 2U,
            "BaseFold scratch files written");
    }

    void deleted(std::uint64_t bytes) {
        if (bytes > live_bytes_) {
            throw std::logic_error("BaseFold scratch ledger underflow");
        }
        live_bytes_ -= bytes;
        report_.scratch_physical_bytes = live_bytes_;
        report_.scratch_deleted_physical_bytes = checked_add_u64(
            report_.scratch_deleted_physical_bytes, bytes,
            "BaseFold scratch deletions");
        report_.scratch_chunk_artifacts_deleted = checked_add_u64(
            report_.scratch_chunk_artifacts_deleted, 1U,
            "BaseFold scratch chunk deletions");
        report_.scratch_files_deleted = checked_add_u64(
            report_.scratch_files_deleted, 2U,
            "BaseFold scratch file deletions");
        report_.artifact_validation_bytes = checked_add_u64(
            report_.artifact_validation_bytes, bytes,
            "BaseFold deletion validation bytes");
        report_.scratch_deletion_validation_bytes = checked_add_u64(
            report_.scratch_deletion_validation_bytes, bytes,
            "BaseFold deletion validation bytes");
    }

    std::uint64_t live_bytes() const { return live_bytes_; }

  private:
    const BaseFoldExternalOpeningOptions &options_;
    std::uint64_t state_bytes_ = 0;
    BaseFoldExternalOpeningReport &report_;
    std::uint64_t live_bytes_ = 0;
};

class KnownQueryMerkleFrontier {
  public:
    KnownQueryMerkleFrontier(std::size_t leaf_count,
                             std::set<std::size_t> requested)
        : leaf_count_(leaf_count), requested_(std::move(requested)) {
        (void)log2_exact(leaf_count);
        for (const std::size_t leaf : requested_) {
            if (leaf >= leaf_count_) {
                throw std::logic_error(
                    "BaseFold replay query leaf is out of range");
            }
        }
    }

    void push(std::span<const Fq2> values) {
        if (count_ >= leaf_count_) {
            throw std::logic_error("too many BaseFold replay leaves");
        }
        if (requested_.contains(count_)) {
            leaves_.emplace(count_,
                            std::vector<Fq2>(values.begin(), values.end()));
        }
        Node node{hash_fq2_leaf(values), count_, 1U,
                  requested_.contains(count_)};
        std::size_t level = 0;
        while (level < occupied_.size() && occupied_[level]) {
            const Node left = nodes_[level];
            if (left.requested != node.requested) {
                const Node &sibling = left.requested ? node : left;
                frontier_.emplace(
                    basefold::MerkleNodePosition{
                        .level = level,
                        .index = sibling.first >> level,
                    },
                    sibling.digest);
            }
            node = Node{MerkleTree::hash_children(left.digest, node.digest),
                        left.first, left.count + node.count,
                        left.requested || node.requested};
            occupied_[level] = false;
            ++level;
        }
        if (level == occupied_.size()) {
            occupied_.push_back(false);
            nodes_.push_back({});
        }
        nodes_[level] = node;
        occupied_[level] = true;
        ++count_;
    }

    Digest finish() const {
        if (count_ != leaf_count_) {
            throw std::logic_error("incomplete BaseFold replay frontier");
        }
        const std::size_t level = log2_exact(leaf_count_);
        if (level >= occupied_.size() || !occupied_[level] ||
            std::count(occupied_.begin(), occupied_.end(), true) != 1) {
            throw std::logic_error("malformed BaseFold replay frontier");
        }
        if (requested_.empty()) {
            return nodes_[level].digest;
        }
        const std::vector<basefold::MerkleNodePosition> expected =
            MerkleTree::multiproof_frontier_positions(
                leaf_count_, std::vector<std::size_t>(requested_.begin(),
                                                      requested_.end()));
        if (frontier_.size() != expected.size() ||
            !std::all_of(expected.begin(), expected.end(),
                         [&](const auto &position) {
                             return frontier_.contains(position);
                         })) {
            throw std::logic_error(
                "incomplete BaseFold replay multiproof frontier");
        }
        return nodes_[level].digest;
    }

    const std::vector<Fq2> &leaf(std::size_t index) const {
        return leaves_.at(index);
    }

    std::vector<Digest> frontier() const {
        if (requested_.empty()) {
            throw std::logic_error(
                "BaseFold replay has no requested multiproof leaves");
        }
        const std::vector<std::size_t> requested(requested_.begin(),
                                                 requested_.end());
        const std::vector<basefold::MerkleNodePosition> positions =
            MerkleTree::multiproof_frontier_positions(leaf_count_, requested);
        std::vector<Digest> result;
        result.reserve(positions.size());
        for (const auto &position : positions) {
            result.push_back(frontier_.at(position));
        }
        return result;
    }

  private:
    struct Node {
        Digest digest{};
        std::size_t first = 0;
        std::size_t count = 0;
        bool requested = false;
    };

    std::size_t leaf_count_ = 0;
    std::set<std::size_t> requested_;
    std::map<std::size_t, std::vector<Fq2>> leaves_;
    std::map<basefold::MerkleNodePosition, Digest> frontier_;
    std::vector<Node> nodes_;
    std::vector<bool> occupied_;
    std::size_t count_ = 0;
};

struct ChunkedFoldChunk {
    std::shared_ptr<const storage::NativeFieldArtifact> artifact;
    std::filesystem::path directory;
    laminate::Digest identity{};
    std::size_t first = 0;
    std::size_t count = 0;
    std::uint64_t physical_bytes = 0;
};

struct ChunkedFoldLayer {
    std::vector<ChunkedFoldChunk> chunks;
    std::filesystem::path directory;
    laminate::Digest identity{};
    Digest root{};
    std::size_t size = 0;
    std::size_t leaf_size = 0;
    std::set<std::size_t> requested_leaves;
    std::shared_ptr<KnownQueryMerkleFrontier> query_frontier;
};

using RangedFoldEnumerator = std::function<void(
    std::size_t, std::size_t, const FoldValueConsumer &)>;
using ChunkPublished =
    std::function<void(std::size_t, std::size_t)>;

void validate_fold_chunk_layout(
    const storage::NativeFieldArtifact &artifact,
    const laminate::Digest &identity, std::size_t count) {
    if (artifact.identity() != identity || artifact.arrays().size() != 1U) {
        throw std::invalid_argument("malformed BaseFold fold chunk");
    }
    const storage::NativeFieldArrayDescriptor &values =
        artifact.arrays().front();
    if (values.name != kFoldValuesArray ||
        values.kind != storage::NativeFieldElementKind::Fq2 ||
        values.element_count != count) {
        throw std::invalid_argument("malformed BaseFold fold chunk values");
    }
}

ChunkedFoldLayer write_chunked_fold_layer(
    const std::filesystem::path &directory,
    const laminate::Digest &identity, std::size_t layer_size,
    std::size_t maximum_chunk_elements,
    const RangedFoldEnumerator &enumerate,
    std::set<std::size_t> requested_leaves,
    const BaseFoldExternalOpeningOptions &options,
    std::uint64_t persistent_field_bytes, bool pass_two,
    FoldScratchLedger &ledger, ScratchRootCleanup &cleanup,
    BaseFoldExternalOpeningReport &report,
    const ChunkPublished &published = {}) {
    if (!std::filesystem::create_directory(directory)) {
        throw std::runtime_error(
            "failed to create BaseFold chunked layer directory");
    }
    cleanup.own(directory);
    const std::size_t leaf_size = merkle_leaf_size(layer_size);
    const std::size_t leaf_count = merkle_leaf_count(layer_size);
    const std::size_t chunk_size =
        fold_chunk_size(layer_size, maximum_chunk_elements);
    if (chunk_size % leaf_size != 0) {
        throw std::invalid_argument(
            "BaseFold fold chunks must align to Merkle leaves");
    }
    enforce_field_peak(
        report, options,
        checked_add_u64(
            persistent_field_bytes,
            checked_multiply_u64(checked_u64(leaf_size, "FRI leaf size"),
                                 sizeof(Fq2), "FRI leaf buffer"),
            "FRI working fields"));

    auto frontier = std::make_shared<KnownQueryMerkleFrontier>(
        leaf_count, requested_leaves);
    ChunkedFoldLayer result;
    result.directory = directory;
    result.identity = identity;
    result.size = layer_size;
    result.leaf_size = leaf_size;
    result.requested_leaves = std::move(requested_leaves);
    std::size_t chunk_index = 0;
    for (std::size_t first = 0; first < layer_size;
         first += chunk_size, ++chunk_index) {
        const std::size_t count = std::min(chunk_size, layer_size - first);
        const std::uint64_t physical = fold_chunk_physical_bytes(count);
        ledger.admit(physical);
        const std::filesystem::path chunk_directory =
            directory / ("chunk-" + std::to_string(chunk_index));
        if (!std::filesystem::create_directory(chunk_directory)) {
            throw std::runtime_error(
                "failed to create BaseFold fold chunk directory");
        }
        PendingScratchChunk pending_chunk(chunk_directory,
                                          options.scratch_directory);
        const laminate::Digest chunk_identity = fold_chunk_identity(
            identity, chunk_index, first, count);
        storage::NativeFieldArtifactWriter writer(
            chunk_directory,
            {.max_total_bytes = physical,
             .min_free_bytes = options.min_free_bytes},
            chunk_identity);
        writer.begin_array(std::string(kFoldValuesArray),
                           storage::NativeFieldElementKind::Fq2,
                           checked_u64(count, "fold chunk length"));
        std::vector<Fq2> leaf;
        leaf.reserve(leaf_size);
        std::size_t enumerated = 0;
        enumerate(first, count, [&](const Fq2 &value) {
            leaf.push_back(value);
            ++enumerated;
            if (leaf.size() == leaf_size) {
                writer.append(leaf);
                frontier->push(leaf);
                leaf.clear();
            }
        });
        if (!leaf.empty() || enumerated != count) {
            throw std::logic_error(
                "BaseFold chunk enumerator returned wrong size");
        }
        writer.finish_array();
        const storage::NativeFieldArtifactWriteResult written =
            writer.finish();
        if (written.physical_bytes != physical) {
            throw std::logic_error(
                "BaseFold fold chunk physical size changed after preflight");
        }
        auto artifact = std::make_shared<storage::NativeFieldArtifact>(
            storage::NativeFieldArtifact::open(written.directory,
                                               chunk_identity));
        validate_fold_chunk_layout(*artifact, chunk_identity, count);
        pending_chunk.bind_published_files();
        report.artifact_validation_bytes = checked_add_u64(
            report.artifact_validation_bytes, physical,
            "BaseFold chunk validation bytes");
        const std::uint64_t payload = checked_multiply_u64(
            checked_u64(count, "fold chunk length"), kSerializedFq2Bytes,
            "fold chunk payload bytes");
        report.sequential_write_payload_bytes = checked_add_u64(
            report.sequential_write_payload_bytes, payload,
            "BaseFold sequential write payloads");
        std::uint64_t &pass_payload =
            pass_two ? report.pass_two_sequential_write_payload_bytes
                     : report.pass_one_sequential_write_payload_bytes;
        pass_payload = checked_add_u64(pass_payload, payload,
                                       "BaseFold pass payload writes");
        cleanup.published(*artifact, chunk_identity, count, physical);
        pending_chunk.disarm();
        ledger.published(physical, pass_two);
        result.chunks.push_back(ChunkedFoldChunk{
            std::move(artifact), chunk_directory, chunk_identity, first,
            count, physical});
        if (published) {
            published(first, count);
        }
    }
    result.root = frontier->finish();
    result.query_frontier = std::move(frontier);
    return result;
}

const ChunkedFoldChunk &fold_chunk_containing(
    const ChunkedFoldLayer &layer, std::size_t first,
    std::size_t count) {
    for (const ChunkedFoldChunk &chunk : layer.chunks) {
        if (chunk.artifact && first >= chunk.first &&
            first + count <= chunk.first + chunk.count) {
            return chunk;
        }
    }
    throw std::logic_error("missing BaseFold predecessor fold chunk");
}

std::vector<std::size_t> fold_dependency_chunks(
    const ChunkedFoldLayer &layer, std::size_t first,
    std::size_t count) {
    const std::size_t half = layer.size / 2U;
    std::vector<std::size_t> result;
    for (const std::size_t source_first : {first, first + half}) {
        bool found = false;
        for (std::size_t index = 0; index < layer.chunks.size(); ++index) {
            const ChunkedFoldChunk &chunk = layer.chunks[index];
            if (chunk.artifact && source_first >= chunk.first &&
                source_first + count <= chunk.first + chunk.count) {
                if (result.empty() || result.back() != index) {
                    result.push_back(index);
                }
                found = true;
                break;
            }
        }
        if (!found) {
            throw std::logic_error(
                "missing BaseFold predecessor dependency chunk");
        }
    }
    return result;
}

void remove_fold_chunk(ChunkedFoldChunk &chunk,
                       FoldScratchLedger &ledger,
                       ScratchRootCleanup &cleanup) {
    if (!chunk.artifact) {
        throw std::logic_error("BaseFold fold chunk already removed");
    }
    chunk.artifact.reset();
    cleanup.remove_published(chunk.directory);
    ledger.deleted(chunk.physical_bytes);
}

void remove_consumed_fold_chunks(ChunkedFoldLayer &layer,
                                 std::size_t first, std::size_t count,
                                 FoldScratchLedger &ledger,
                                 ScratchRootCleanup &cleanup) {
    const std::vector<std::size_t> dependencies =
        fold_dependency_chunks(layer, first, count);
    for (const std::size_t index : dependencies) {
        remove_fold_chunk(layer.chunks[index], ledger, cleanup);
    }
}

void finish_removed_fold_layer(ChunkedFoldLayer &layer) {
    if (std::any_of(layer.chunks.begin(), layer.chunks.end(),
                    [](const ChunkedFoldChunk &chunk) {
                        return static_cast<bool>(chunk.artifact);
                    })) {
        throw std::logic_error("BaseFold predecessor layer is still live");
    }
    std::error_code error;
    if (!std::filesystem::remove(layer.directory, error) || error) {
        throw std::runtime_error(
            "failed to remove empty BaseFold fold layer directory");
    }
}

RangedFoldEnumerator make_base_ranged_fold_enumerator(
    const BaseFoldExternalProverState &state,
    std::span<const Fq2> column_weights, const Fq2 &challenge,
    const Fq &generator, bool pass_two,
    BaseFoldExternalOpeningReport &report) {
    const BaseFoldExternalProverState *state_pointer = &state;
    const std::span<const Fq2> weights = column_weights;
    return [state_pointer, weights, challenge, generator, pass_two,
            &report](std::size_t first, std::size_t count,
                     const FoldValueConsumer &consume) {
        const std::size_t codeword_size = checked_codeword_size(
            static_cast<std::size_t>(
                state_pointer->commitment.evaluation_count),
            state_pointer->commitment.log_rate);
        const std::size_t half = codeword_size / 2U;
        if (first > half || count > half - first) {
            throw std::logic_error("BaseFold base fold range is invalid");
        }
        std::vector<storage::NativeFieldArrayReader> lo =
            open_column_readers(*state_pointer->artifact, weights.size(), true);
        std::vector<storage::NativeFieldArrayReader> hi =
            open_column_readers(*state_pointer->artifact, weights.size(), true);
        for (auto &reader : lo) {
            reader.seek(first);
        }
        for (auto &reader : hi) {
            reader.seek(half + first);
        }
        const Fq inverse_generator = generator.inverse();
        Fq inverse_power = inverse_generator.pow(
            checked_u64(first, "BaseFold fold range start"));
        for (std::size_t offset = 0; offset < count; ++offset) {
            consume(fold_pair(read_weighted_fq(lo, weights),
                              read_weighted_fq(hi, weights), challenge,
                              inverse_power));
            inverse_power *= inverse_generator;
        }
        const std::uint64_t bytes = add_sequential_column_pass(
            report, weights.size(), 2U * count);
        std::uint64_t &pass_bytes =
            pass_two ? report.pass_two_fold_sequential_read_payload_bytes
                     : report.pass_one_fold_sequential_read_payload_bytes;
        pass_bytes = checked_add_u64(pass_bytes, bytes,
                                     "BaseFold pass fold reads");
    };
}

RangedFoldEnumerator make_chunked_ranged_fold_enumerator(
    const ChunkedFoldLayer &source, const Fq2 &challenge,
    const Fq &generator, bool pass_two,
    BaseFoldExternalOpeningReport &report) {
    const ChunkedFoldLayer *source_pointer = &source;
    return [source_pointer, challenge, generator, pass_two,
            &report](std::size_t first, std::size_t count,
                     const FoldValueConsumer &consume) {
        const std::size_t half = source_pointer->size / 2U;
        if (first > half || count > half - first) {
            throw std::logic_error("BaseFold fold range is invalid");
        }
        const ChunkedFoldChunk &lo_chunk =
            fold_chunk_containing(*source_pointer, first, count);
        const ChunkedFoldChunk &hi_chunk =
            fold_chunk_containing(*source_pointer, half + first, count);
        storage::NativeFieldArrayReader lo =
            lo_chunk.artifact->open_array(kFoldValuesArray);
        storage::NativeFieldArrayReader hi =
            hi_chunk.artifact->open_array(kFoldValuesArray);
        lo.seek(first - lo_chunk.first);
        hi.seek(half + first - hi_chunk.first);
        const Fq inverse_generator = generator.inverse();
        Fq inverse_power = inverse_generator.pow(
            checked_u64(first, "BaseFold fold range start"));
        for (std::size_t offset = 0; offset < count; ++offset) {
            consume(fold_pair(read_one<Fq2>(lo), read_one<Fq2>(hi),
                              challenge, inverse_power));
            inverse_power *= inverse_generator;
        }
        const std::uint64_t bytes = checked_multiply_u64(
            checked_u64(2U * count, "FRI source range"),
            kSerializedFq2Bytes, "FRI source range bytes");
        report.sequential_read_payload_bytes = checked_add_u64(
            report.sequential_read_payload_bytes, bytes,
            "sequential read payloads");
        std::uint64_t &pass_bytes =
            pass_two ? report.pass_two_fold_sequential_read_payload_bytes
                     : report.pass_one_fold_sequential_read_payload_bytes;
        pass_bytes = checked_add_u64(pass_bytes, bytes,
                                     "BaseFold pass fold reads");
    };
}

std::vector<Fq2> collect_final_chunked_fold(
    ChunkedFoldLayer &source, std::size_t output_size,
    std::size_t maximum_chunk_elements, const Fq2 &challenge,
    const Fq &generator, const BaseFoldExternalOpeningOptions &options,
    std::uint64_t persistent_field_bytes, FoldScratchLedger &ledger,
    ScratchRootCleanup &cleanup, bool pass_two,
    BaseFoldExternalOpeningReport &report) {
    enforce_field_peak(
        report, options,
        checked_add_u64(
            persistent_field_bytes,
            checked_multiply_u64(checked_u64(output_size, "final FRI size"),
                                 sizeof(Fq2), "final FRI field bytes"),
            "final FRI working fields"));
    std::vector<Fq2> result;
    result.reserve(output_size);
    const std::size_t chunk_size =
        fold_chunk_size(output_size, maximum_chunk_elements);
    const RangedFoldEnumerator enumerate =
        make_chunked_ranged_fold_enumerator(source, challenge, generator,
                                            pass_two, report);
    for (std::size_t first = 0; first < output_size; first += chunk_size) {
        const std::size_t count = std::min(chunk_size, output_size - first);
        enumerate(first, count,
                  [&](const Fq2 &value) { result.push_back(value); });
        remove_consumed_fold_chunks(source, first, count, ledger, cleanup);
    }
    finish_removed_fold_layer(source);
    if (result.size() != output_size) {
        throw std::logic_error("BaseFold final replay returned wrong size");
    }
    return result;
}

std::set<std::size_t> fold_requested_leaves(
    std::span<const std::size_t> positions, std::size_t layer_size) {
    const std::vector<std::size_t> indices =
        queried_leaf_indices(positions, layer_size);
    return {indices.begin(), indices.end()};
}

void fill_replayed_fold_query_openings(
    const ChunkedFoldLayer &layer, std::size_t fold_index,
    std::span<const std::size_t> positions, BaseFoldProof &proof) {
    if (!layer.query_frontier) {
        throw std::logic_error("missing BaseFold replay query collector");
    }
    MerkleMultiOpening<Fq2> &fold = proof.folds.at(fold_index);
    fold.leaf_indices = queried_leaf_indices(positions, layer.size);
    fold.values_per_leaf = layer.leaf_size;
    fold.values.reserve(fold.leaf_indices.size() * fold.values_per_leaf);
    for (const std::size_t leaf : fold.leaf_indices) {
        const std::vector<Fq2> &values = layer.query_frontier->leaf(leaf);
        fold.values.insert(fold.values.end(), values.begin(), values.end());
    }
    fold.frontier = layer.query_frontier->frontier();
}

bool constant_codeword(std::span<const Fq2> codeword) {
    if (codeword.empty()) {
        return false;
    }
    return std::all_of(codeword.begin(), codeword.end(),
                       [&](const Fq2 &value) {
                           return value == codeword.front();
                       });
}

} // namespace

laminate::Digest
basefold_external_state_identity(const PcsCommitment &commitment) {
    std::vector<std::uint8_t> encoding(kExternalStateIdentityDomain.begin(),
                                       kExternalStateIdentityDomain.end());
    append_bytes(encoding, encode_pcs_commitment(commitment));
    return sha256(encoding);
}

BaseFoldPcs::BaseFoldPcs(BaseFoldPcsParameters parameters)
    : parameters_(parameters) {
    if (parameters_.query_count == 0 ||
        parameters_.query_count >
            std::numeric_limits<std::uint32_t>::max() ||
        parameters_.log_rate > kOuterFieldTwoAdicity ||
        parameters_.log_rate >
            std::numeric_limits<std::uint32_t>::max()) {
        throw std::invalid_argument("invalid BaseFold PCS parameters");
    }
}

std::size_t basefold_opening_proof_max_size_bytes(
    std::size_t message_log, std::size_t width,
    BaseFoldPcsParameters parameters) {
    if (width == 0 || parameters.query_count == 0 ||
        message_log >= std::numeric_limits<std::size_t>::digits ||
        parameters.log_rate >=
            std::numeric_limits<std::size_t>::digits ||
        message_log > kOuterFieldTwoAdicity ||
        parameters.log_rate >
            kOuterFieldTwoAdicity - message_log) {
        throw std::invalid_argument(
            "invalid BaseFold opening-size parameters");
    }
    const auto add = [](std::size_t left, std::size_t right) {
        if (right > std::numeric_limits<std::size_t>::max() - left) {
            throw std::overflow_error("BaseFold opening size overflows");
        }
        return left + right;
    };
    const auto multiply = [](std::size_t left, std::size_t right) {
        if (left != 0 &&
            right > std::numeric_limits<std::size_t>::max() / left) {
            throw std::overflow_error("BaseFold opening size overflows");
        }
        return left * right;
    };
    const auto vector_bytes = [&](std::size_t count,
                                  std::size_t element_bytes) {
        return add(8U, multiply(count, element_bytes));
    };
    const auto multi_opening_bytes = [&](const MaximumMultiProofShape &shape,
                                         std::size_t leaf_values,
                                         std::size_t value_bytes) {
        std::size_t result = 8U; // unique leaf count
        result = add(result,
                     multiply(shape.leaves,
                              multiply(leaf_values, value_bytes)));
        result = add(result, 8U); // frontier count
        return add(result,
                   multiply(shape.frontier, Digest{}.size()));
    };

    const std::size_t codeword_size =
        std::size_t{1} << (message_log + parameters.log_rate);
    const std::size_t base_leaf_size = merkle_leaf_size(codeword_size);
    const std::size_t root_count =
        message_log == 0 ? 0 : message_log - 1U;
    const std::size_t final_size =
        std::size_t{1} << parameters.log_rate;

    std::size_t size = 8U; // encoding version
    size = add(size, 8U);  // round count
    size = add(size, multiply(message_log, 2U * kSerializedFq2Bytes));
    size = add(size, vector_bytes(root_count, Digest{}.size()));
    size = add(size, vector_bytes(final_size, kSerializedFq2Bytes));
    size = add(size, 8U); // query count
    size = add(size, multiply(parameters.query_count, 8U));
    const std::size_t base_values = multiply(width, base_leaf_size);
    size = add(size, multi_opening_bytes(
                         maximum_multi_shape(codeword_size,
                                             parameters.query_count),
                         base_values,
                         kSerializedFqBytes));
    size = add(size, 8U); // fold-opening count
    for (std::size_t round = 0; round < root_count; ++round) {
        const std::size_t layer_size =
            codeword_size >> (round + 1U);
        const std::size_t leaf_size = merkle_leaf_size(layer_size);
        size = add(size, multi_opening_bytes(
                             maximum_multi_shape(layer_size,
                                                 parameters.query_count),
                             leaf_size,
                             kSerializedFq2Bytes));
    }
    return size;
}

std::size_t basefold_opening_max_merkle_hashes(
    std::size_t message_log, BaseFoldPcsParameters parameters) {
    if (parameters.query_count == 0 ||
        message_log >= std::numeric_limits<std::size_t>::digits ||
        parameters.log_rate >=
            std::numeric_limits<std::size_t>::digits ||
        message_log > kOuterFieldTwoAdicity ||
        parameters.log_rate >
            kOuterFieldTwoAdicity - message_log) {
        throw std::invalid_argument(
            "invalid BaseFold Merkle-work parameters");
    }
    const auto add = [](std::size_t left, std::size_t right) {
        if (right > std::numeric_limits<std::size_t>::max() - left) {
            throw std::overflow_error("BaseFold Merkle work overflows");
        }
        return left + right;
    };
    const auto layer_hashes = [&](std::size_t layer_size) {
        const MaximumMultiProofShape shape =
            maximum_multi_shape(layer_size, parameters.query_count);
        return add(shape.leaves, shape.parent_hashes);
    };

    const std::size_t codeword_size =
        std::size_t{1} << (message_log + parameters.log_rate);
    std::size_t result = layer_hashes(codeword_size);
    const std::size_t root_count =
        message_log == 0 ? 0 : message_log - 1U;
    for (std::size_t round = 0; round < root_count; ++round) {
        result = add(result,
                     layer_hashes(codeword_size >> (round + 1U)));
    }
    return result;
}

IPCS::CommitOutput
BaseFoldPcs::commit(std::span<const Fq> evaluations) const {
    std::vector<std::vector<Fq>> columns;
    columns.emplace_back(evaluations.begin(), evaluations.end());
    return commit_owned_columns(std::move(columns));
}

IPCS::CommitOutput BaseFoldPcs::commit_columns(
    const std::vector<std::vector<Fq>> &input_columns) const {
    return commit_owned_columns(input_columns);
}

IPCS::CommitOutput BaseFoldPcs::commit_owned_columns(
    std::vector<std::vector<Fq>> columns) const {
    if (columns.empty() || columns.size() >
                                     std::numeric_limits<std::uint64_t>::max()) {
        throw std::invalid_argument(
            "BaseFold commitment needs a nonempty column batch");
    }
    const std::size_t message_size = columns.front().size();
    const std::size_t codeword_size =
        checked_codeword_size(message_size, parameters_.log_rate);
    if (message_size > std::numeric_limits<std::uint64_t>::max()) {
        throw std::overflow_error("BaseFold message length exceeds u64");
    }
    std::vector<std::vector<Fq>> codewords;
    codewords.reserve(columns.size());
    for (const std::vector<Fq> &column : columns) {
        if (column.size() != message_size) {
            throw std::invalid_argument(
                "BaseFold columns have different message lengths");
        }
        codewords.push_back(
            reed_solomon_encode(column, parameters_.log_rate));
        if (codewords.back().size() != codeword_size) {
            throw std::logic_error("BaseFold encoder returned wrong length");
        }
    }
    MerkleTree tree = make_interleaved_tree(codewords);
    PcsCommitment commitment{
        .scheme = kSchemeIdentifier,
        .root = tree.root(),
        .evaluation_count = static_cast<std::uint64_t>(message_size),
        .width = static_cast<std::uint64_t>(columns.size()),
        .log_rate = static_cast<std::uint32_t>(parameters_.log_rate),
        .query_count = static_cast<std::uint32_t>(parameters_.query_count),
    };
    auto state = std::make_shared<BaseFoldProverState>(
        std::move(columns), std::move(codewords), std::move(tree),
        commitment);
    return CommitOutput{commitment, std::move(state)};
}

BaseFoldExternalization BaseFoldPcs::externalize_prover_state(
    const std::shared_ptr<const ProverState> &prover_state,
    BaseFoldExternalStateOptions options) const {
    const auto state =
        std::dynamic_pointer_cast<const BaseFoldProverState>(prover_state);
    if (!state || state->commitment.scheme != kSchemeIdentifier ||
        state->commitment.log_rate != parameters_.log_rate ||
        state->commitment.query_count != parameters_.query_count ||
        state->columns.empty() ||
        state->columns.size() != state->codewords.size() ||
        state->commitment.width != state->columns.size()) {
        throw std::invalid_argument(
            "only a matching resident BaseFold state can be externalized");
    }
    const std::size_t message_size = state->columns.front().size();
    const std::size_t codeword_size =
        checked_codeword_size(message_size, parameters_.log_rate);
    for (std::size_t column = 0; column < state->columns.size(); ++column) {
        if (state->columns[column].size() != message_size ||
            state->codewords[column].size() != codeword_size) {
            throw std::invalid_argument("malformed resident BaseFold state");
        }
    }

    const laminate::Digest identity =
        basefold_external_state_identity(state->commitment);
    storage::NativeFieldArtifactWriter writer(
        options.directory, options.limits, identity);
    for (std::size_t column = 0; column < state->columns.size(); ++column) {
        writer.begin_array(message_array_name(column),
                           storage::NativeFieldElementKind::Fq,
                           checked_u64(message_size, "message size"));
        writer.append(state->columns[column]);
        writer.finish_array();
    }
    for (std::size_t column = 0; column < state->codewords.size(); ++column) {
        writer.begin_array(codeword_array_name(column),
                           storage::NativeFieldElementKind::Fq,
                           checked_u64(codeword_size, "codeword size"));
        writer.append(state->codewords[column]);
        writer.finish_array();
    }

    const std::size_t leaf_count = merkle_leaf_count(codeword_size);
    const auto &tree_levels = state->tree.levels();
    if (tree_levels.size() != log2_exact(leaf_count) + 1U ||
        tree_levels.front().size() != leaf_count ||
        tree_levels.back().size() != 1 ||
        tree_levels.back().front() != state->commitment.root) {
        throw std::logic_error(
            "resident BaseFold tree has an inconsistent shape");
    }
    const std::size_t tree_digest_count = merkle_node_count(leaf_count);
    writer.begin_array(std::string(kBaseTreePostorderArray),
                       storage::NativeFieldElementKind::BaseFoldDigest,
                       checked_u64(tree_digest_count,
                                   "base tree digest count"));
    MerkleFrontier frontier;
    std::vector<Digest> nodes;
    nodes.reserve(kDigestWriteElements);
    std::size_t written_tree_nodes = 0;
    for (const Digest &leaf : tree_levels.front()) {
        frontier.push_postorder(leaf, [&](const Digest &digest) {
            nodes.push_back(digest);
            if (nodes.size() == kDigestWriteElements) {
                writer.append(nodes);
                nodes.clear();
            }
            ++written_tree_nodes;
        });
    }
    if (!nodes.empty()) {
        writer.append(nodes);
    }
    writer.finish_array();
    if (written_tree_nodes != tree_digest_count ||
        frontier.finish(leaf_count) != state->commitment.root) {
        throw std::logic_error("resident BaseFold tree is inconsistent");
    }
    const storage::NativeFieldArtifactWriteResult written = writer.finish();
    auto artifact = std::make_shared<storage::NativeFieldArtifact>(
        writer.trusted_finished_artifact());

    const std::uint64_t width = checked_u64(
        state->columns.size(), "external BaseFold width");
    BaseFoldExternalStateReport report;
    report.physical_bytes = written.physical_bytes;
    report.message_payload_bytes = checked_multiply_u64(
        checked_multiply_u64(width, checked_u64(message_size, "message size"),
                             "message elements"),
        kSerializedFqBytes, "message payload bytes");
    report.codeword_payload_bytes = checked_multiply_u64(
        checked_multiply_u64(width,
                             checked_u64(codeword_size, "codeword size"),
                             "codeword elements"),
        kSerializedFqBytes, "codeword payload bytes");
    report.merkle_tree_payload_bytes = checked_multiply_u64(
        checked_u64(tree_digest_count, "base tree digest count"),
        Digest{}.size(), "base tree payload bytes");
    auto external_state = adopt_external_prover_state(
        std::move(artifact), state->commitment);
    return BaseFoldExternalization{
        state->commitment,
        std::move(external_state),
        identity,
        report,
    };
}

std::shared_ptr<const IPCS::ProverState>
BaseFoldPcs::open_external_prover_state(
    const std::filesystem::path &directory,
    const PcsCommitment &commitment) const {
    if (commitment.log_rate != parameters_.log_rate ||
        commitment.query_count != parameters_.query_count) {
        throw std::invalid_argument(
            "external BaseFold commitment uses different parameters");
    }
    auto artifact = std::make_shared<storage::NativeFieldArtifact>(
        storage::NativeFieldArtifact::open(
            directory, basefold_external_state_identity(commitment)));
    return adopt_external_prover_state(std::move(artifact), commitment);
}

std::shared_ptr<const IPCS::ProverState>
BaseFoldPcs::adopt_external_prover_state(
    std::shared_ptr<const storage::NativeFieldArtifact> artifact,
    const PcsCommitment &commitment) const {
    if (!artifact || commitment.log_rate != parameters_.log_rate ||
        commitment.query_count != parameters_.query_count) {
        throw std::invalid_argument(
            "external BaseFold state uses different parameters");
    }
    validate_external_state_layout(*artifact, commitment);
    return std::make_shared<BaseFoldExternalProverState>(
        std::move(artifact), commitment);
}

void BaseFoldPcs::validate_resident_prover_state(
    const std::shared_ptr<const ProverState> &prover_state,
    const PcsCommitment &expected_commitment) const {
    const auto state =
        std::dynamic_pointer_cast<const BaseFoldProverState>(prover_state);
    if (!state || state->commitment != expected_commitment ||
        expected_commitment.scheme != kSchemeIdentifier ||
        expected_commitment.log_rate != parameters_.log_rate ||
        expected_commitment.query_count != parameters_.query_count ||
        expected_commitment.width == 0 ||
        expected_commitment.width >
            std::numeric_limits<std::size_t>::max() ||
        expected_commitment.evaluation_count == 0 ||
        expected_commitment.evaluation_count >
            std::numeric_limits<std::size_t>::max()) {
        throw std::invalid_argument(
            "BaseFold resident state is not bound to the expected "
            "commitment");
    }
    const std::size_t width =
        static_cast<std::size_t>(expected_commitment.width);
    const std::size_t message_size =
        static_cast<std::size_t>(expected_commitment.evaluation_count);
    const std::size_t codeword_size =
        checked_codeword_size(message_size, parameters_.log_rate);
    if (state->columns.size() != width ||
        state->codewords.size() != width ||
        state->tree.root() != expected_commitment.root) {
        throw std::invalid_argument(
            "BaseFold resident state has malformed geometry or root");
    }
    for (std::size_t column = 0; column < width; ++column) {
        if (state->columns[column].size() != message_size ||
            state->codewords[column].size() != codeword_size) {
            throw std::invalid_argument(
                "BaseFold resident state has malformed columns");
        }
    }
}

BaseFoldExternalOpeningPreflight
BaseFoldPcs::preflight_external_opening(
    const std::shared_ptr<const ProverState> &prover_state,
    const PcsCommitment &expected_commitment,
    const BaseFoldExternalOpeningOptions &options) const {
    return preflight_external_opening_impl(
        prover_state, expected_commitment, parameters_, options);
}

BaseFoldExternalOpeningStoragePlan
BaseFoldPcs::plan_external_opening_storage(
    const PcsCommitment &commitment,
    std::size_t fold_chunk_elements,
    std::uint64_t max_working_field_bytes) const {
    if (commitment.scheme != kSchemeIdentifier ||
        commitment.log_rate != parameters_.log_rate ||
        commitment.query_count != parameters_.query_count ||
        commitment.width == 0 ||
        commitment.width > std::numeric_limits<std::size_t>::max() ||
        commitment.evaluation_count == 0 ||
        commitment.evaluation_count >
            std::numeric_limits<std::size_t>::max() ||
        !is_power_of_two(fold_chunk_elements)) {
        throw std::invalid_argument(
            "BaseFold opening storage plan has invalid geometry");
    }
    const std::size_t width =
        static_cast<std::size_t>(commitment.width);
    const std::size_t message_size =
        static_cast<std::size_t>(commitment.evaluation_count);
    const std::size_t message_log = log2_exact(message_size);
    const std::size_t codeword_size =
        checked_codeword_size(message_size, parameters_.log_rate);
    const std::size_t leaf_count = merkle_leaf_count(codeword_size);
    std::vector<storage::NativeFieldArrayLayout> state_layout;
    state_layout.reserve(2U * width + 1U);
    for (std::size_t column = 0; column < width; ++column) {
        state_layout.push_back({
            message_array_name(column),
            storage::NativeFieldElementKind::Fq,
            checked_u64(message_size, "message size"),
        });
    }
    for (std::size_t column = 0; column < width; ++column) {
        state_layout.push_back({
            codeword_array_name(column),
            storage::NativeFieldElementKind::Fq,
            checked_u64(codeword_size, "codeword size"),
        });
    }
    state_layout.push_back({
        std::string(kBaseTreePostorderArray),
        storage::NativeFieldElementKind::BaseFoldDigest,
        checked_u64(merkle_node_count(leaf_count),
                    "base tree digest count"),
    });
    if (message_log >= 2) {
        const std::size_t first_fold_size = codeword_size / 2U;
        const std::size_t selected_chunk =
            std::min(first_fold_size, fold_chunk_elements);
        if (selected_chunk % merkle_leaf_size(first_fold_size) != 0) {
            throw std::invalid_argument(
                "BaseFold fold chunks must align to Merkle leaves");
        }
    }
    const FoldScratchProjection scratch = project_chunked_fold_scratch(
        codeword_size, message_log, fold_chunk_elements);
    const OpeningWorkingProjection working =
        project_opening_working_fields(
            commitment, parameters_, max_working_field_bytes);
    return {
        .state_artifact_physical_bytes =
            storage::native_field_artifact_physical_bytes(state_layout),
        .scratch_peak_physical_bytes = scratch.peak_bytes,
        .minimum_working_field_bytes = working.minimum_bytes,
        .required_working_field_bytes = working.required_bytes,
        .materialized_sumcheck_entries =
            working.materialized_sumcheck_entries,
    };
}

BaseFoldExternalOpeningAdmission BaseFoldPcs::admit_external_opening(
    const std::shared_ptr<const ProverState> &prover_state,
    const PcsCommitment &expected_commitment,
    BaseFoldExternalOpeningOptions options) const {
    BaseFoldExternalOpeningAdmission result;
    result.commitment_ = expected_commitment;
    result.options_ = std::move(options);
    result.preflight_ = preflight_external_opening_impl(
        prover_state, expected_commitment, parameters_, result.options_,
        &result.validated_prover_state_);
    return result;
}

BaseFoldExternalOpening BaseFoldPcs::open_external(
    const std::shared_ptr<const ProverState> &prover_state,
    std::span<const Fq2> point, const Fq2 &claimed_value,
    BaseFoldExternalOpeningOptions options,
    PublicCoin &public_coin) const {
    const std::array<Fq2, 1> weight{Fq2::one()};
    return open_linear_combination_external(
        prover_state, weight, point, claimed_value, std::move(options),
        public_coin);
}

BaseFoldExternalOpening BaseFoldPcs::open_external_admitted(
    BaseFoldExternalOpeningAdmission admission,
    std::span<const Fq2> point, const Fq2 &claimed_value,
    PublicCoin &public_coin) const {
    const std::array<Fq2, 1> weight{Fq2::one()};
    return open_linear_combination_external_admitted(
        std::move(admission), weight, point, claimed_value, public_coin);
}

BaseFoldExternalOpening BaseFoldPcs::open_linear_combination_external(
    const std::shared_ptr<const ProverState> &prover_state,
    std::span<const Fq2> column_weights,
    std::span<const Fq2> point, const Fq2 &claimed_value,
    BaseFoldExternalOpeningOptions options,
    PublicCoin &public_coin) const {
    const auto state = std::dynamic_pointer_cast<
        const BaseFoldExternalProverState>(prover_state);
    if (!state || !state->artifact) {
        throw std::invalid_argument(
            "BaseFold external opening state is malformed");
    }
    return open_linear_combination_external_admitted(
        admit_external_opening(prover_state, state->commitment,
                               std::move(options)),
        column_weights, point, claimed_value, public_coin);
}

BaseFoldExternalOpening
BaseFoldPcs::open_linear_combination_external_admitted(
    BaseFoldExternalOpeningAdmission admission,
    std::span<const Fq2> column_weights,
    std::span<const Fq2> point, const Fq2 &claimed_value,
    PublicCoin &public_coin) const {
    const auto state = std::dynamic_pointer_cast<
        const BaseFoldExternalProverState>(
            admission.validated_prover_state_);
    BaseFoldExternalOpeningOptions options =
        std::move(admission.options_);
    const BaseFoldExternalOpeningPreflight admission_plan =
        std::move(admission.preflight_);
    if (!state || !state->artifact ||
        state->commitment != admission.commitment_ ||
        state->commitment.scheme != kSchemeIdentifier ||
        state->commitment.log_rate != parameters_.log_rate ||
        state->commitment.query_count != parameters_.query_count ||
        state->commitment.width != column_weights.size() ||
        state->commitment.evaluation_count == 0 ||
        state->commitment.evaluation_count >
            std::numeric_limits<std::size_t>::max() ||
        point.size() != log2_exact(static_cast<std::size_t>(
                            state->commitment.evaluation_count))) {
        throw std::invalid_argument(
            "BaseFold external opening state, point, or weights disagree");
    }

    const std::size_t message_size =
        static_cast<std::size_t>(state->commitment.evaluation_count);
    const std::size_t message_log = log2_exact(message_size);
    const std::size_t codeword_size =
        checked_codeword_size(message_size, parameters_.log_rate);
    const std::size_t root_count =
        message_log == 0 ? 0 : message_log - 1U;
    BaseFoldExternalOpeningReport report;
    report.artifact_validation_bytes =
        admission_plan.state_artifact_physical_bytes;
    report.state_artifact_validation_bytes =
        admission_plan.state_artifact_physical_bytes;
    report.artifact_validation_passes = 1;
    report.indexed_read_payload_bytes = Digest{}.size();
    const std::uint64_t persistent_field_bytes = checked_multiply_u64(
        checked_multiply_u64(checked_u64(message_log, "message log"), 2U,
                             "point and challenge fields"),
        sizeof(Fq2), "point and challenge bytes");
    enforce_field_peak(report, options, persistent_field_bytes);
    const std::filesystem::path scratch_directory =
        std::filesystem::canonical(options.scratch_directory);
    ScratchRootCleanup scratch_cleanup(scratch_directory);
    FoldScratchLedger scratch_ledger(
        options, admission_plan.state_artifact_physical_bytes, report);
    std::vector<Fq2> point_lsb(point.rbegin(), point.rend());
    std::vector<Fq2> challenges(message_log, Fq2::zero());
    std::size_t challenge_count = 0;

    BaseFoldProof proof;
    proof.rounds.reserve(message_log);
    proof.roots.reserve(root_count);
    RestrictedTables tables;
    std::size_t table_capacity_entries = 0;
    Fq2 terminal_message = Fq2::zero();
    Fq2 terminal_operand = Fq2::one();
    Fq2 running_claim = claimed_value;
    Fq generator =
        Fq::two_adic_generator(log2_exact(codeword_size));
    std::optional<ChunkedFoldLayer> previous_layer;
    laminate::Digest source_identity = state->artifact->identity();
    std::size_t source_size = codeword_size;

    if (message_log == 0) {
        std::vector<storage::NativeFieldArrayReader> message_readers =
            open_column_readers(*state->artifact, column_weights.size(),
                                false);
        terminal_message =
            read_weighted_fq(message_readers, column_weights);
        report.sumcheck_sequential_read_payload_bytes = checked_add_u64(
            report.sumcheck_sequential_read_payload_bytes,
            add_sequential_column_pass(report, column_weights.size(), 1),
            "BaseFold singleton message reads");

        enforce_field_peak(
            report, options,
            checked_add_u64(
                persistent_field_bytes,
                checked_multiply_u64(checked_u64(codeword_size,
                                                 "singleton codeword size"),
                                     sizeof(Fq2),
                                     "singleton final codeword bytes"),
                "singleton working fields"));
        proof.final_codeword.assign(codeword_size, Fq2::zero());
        std::vector<storage::NativeFieldArrayReader> codeword_readers =
            open_column_readers(*state->artifact, column_weights.size(), true);
        for (Fq2 &value : proof.final_codeword) {
            value = read_weighted_fq(codeword_readers, column_weights);
        }
        report.pass_one_fold_sequential_read_payload_bytes = checked_add_u64(
            report.pass_one_fold_sequential_read_payload_bytes,
            add_sequential_column_pass(report, column_weights.size(),
                                       codeword_size),
            "BaseFold singleton codeword reads");
    } else {
        for (std::size_t round_index = 0; round_index < message_log;
             ++round_index) {
            std::array<Fq2, 2> round{};
            FromScratchRound from_scratch;
            if (tables.message.empty()) {
                from_scratch = compute_sumcheck_round_from_source(
                    *state, column_weights, point_lsb,
                    std::span<const Fq2>(challenges).first(challenge_count),
                    report);
                round = from_scratch.values;
                ++report.from_scratch_sumcheck_rounds;
            } else {
                round = sumcheck_round(tables.message, tables.operand);
            }
            proof.rounds.push_back(round);
            observe_round(round, public_coin);
            const Fq2 challenge = public_coin.challenge_fq2();
            challenges[challenge_count++] = challenge;
            const Fq2 at_zero = running_claim - round[0];
            running_claim =
                interpolate_quadratic(at_zero, round, challenge);

            if (!tables.message.empty()) {
                const std::size_t next_size = tables.message.size() / 2U;
                fold_adjacent_into(tables.message,
                                   std::span<Fq2>(tables.message)
                                       .first(next_size),
                                   challenge);
                fold_adjacent_into(tables.operand,
                                   std::span<Fq2>(tables.operand)
                                       .first(next_size),
                                   challenge);
                tables.message.resize(next_size);
                tables.operand.resize(next_size);
                if (next_size == 1) {
                    terminal_message = tables.message.front();
                    terminal_operand = tables.operand.front();
                }
            } else if (round_index + 1U == message_log) {
                terminal_message =
                    from_scratch.terminal_message_zero +
                    challenge * (from_scratch.terminal_message_one -
                                 from_scratch.terminal_message_zero);
                terminal_operand =
                    from_scratch.terminal_operand_zero +
                    challenge * (from_scratch.terminal_operand_one -
                                 from_scratch.terminal_operand_zero);
            } else {
                const std::size_t next_size =
                    message_size >> challenge_count;
                const std::uint64_t table_bytes = checked_multiply_u64(
                    checked_multiply_u64(checked_u64(next_size,
                                                     "sumcheck table size"),
                                         2U, "sumcheck table entries"),
                    sizeof(Fq2), "sumcheck table bytes");
                if (checked_add_u64(persistent_field_bytes, table_bytes,
                                    "sumcheck working fields") <=
                    options.max_working_field_bytes) {
                    tables = materialize_restricted_tables(
                        *state, column_weights, point_lsb,
                        std::span<const Fq2>(challenges)
                            .first(challenge_count),
                        report);
                    table_capacity_entries = 2U * next_size;
                    report.materialized_sumcheck_entries = next_size;
                    enforce_field_peak(
                        report, options,
                        checked_add_u64(persistent_field_bytes, table_bytes,
                                        "sumcheck working fields"));
                }
            }

            const std::size_t output_size = source_size / 2U;
            const std::uint64_t live_table_bytes = checked_multiply_u64(
                checked_u64(table_capacity_entries,
                            "live sumcheck table entries"),
                sizeof(Fq2), "live sumcheck table bytes");
            const std::uint64_t live_field_bytes = checked_add_u64(
                persistent_field_bytes, live_table_bytes,
                "live BaseFold fields");
            if (round_index + 1U < message_log) {
                const laminate::Digest identity = fold_scratch_identity(
                    source_identity, state->commitment, round_index,
                    challenge);
                RangedFoldEnumerator enumerate;
                ChunkPublished consumed;
                if (round_index == 0) {
                    enumerate = make_base_ranged_fold_enumerator(
                        *state, column_weights, challenge, generator,
                        false, report);
                } else {
                    if (!previous_layer) {
                        throw std::logic_error(
                            "missing previous FRI fold layer");
                    }
                    enumerate = make_chunked_ranged_fold_enumerator(
                        *previous_layer, challenge, generator, false,
                        report);
                    consumed = [&](std::size_t first, std::size_t count) {
                        remove_consumed_fold_chunks(
                            *previous_layer, first, count, scratch_ledger,
                            scratch_cleanup);
                    };
                }
                ChunkedFoldLayer layer = write_chunked_fold_layer(
                    scratch_directory /
                        ("pass-one-layer-" +
                         std::to_string(round_index)),
                    identity, output_size, options.fold_chunk_elements,
                    enumerate, {}, options, live_field_bytes, false,
                    scratch_ledger, scratch_cleanup, report, consumed);
                if (previous_layer) {
                    finish_removed_fold_layer(*previous_layer);
                    previous_layer.reset();
                }
                proof.roots.push_back(layer.root);
                observe_root(layer.root, public_coin);
                source_identity = identity;
                previous_layer.emplace(std::move(layer));
            } else {
                if (round_index == 0) {
                    const RangedFoldEnumerator enumerate =
                        make_base_ranged_fold_enumerator(
                            *state, column_weights, challenge, generator,
                            false, report);
                    enforce_field_peak(
                        report, options,
                        checked_add_u64(
                            live_field_bytes,
                            checked_multiply_u64(
                                checked_u64(output_size, "final FRI size"),
                                sizeof(Fq2), "final FRI field bytes"),
                            "final FRI working fields"));
                    proof.final_codeword.reserve(output_size);
                    enumerate(0, output_size, [&](const Fq2 &value) {
                        proof.final_codeword.push_back(value);
                    });
                } else {
                    if (!previous_layer) {
                        throw std::logic_error(
                            "missing final FRI predecessor layer");
                    }
                    proof.final_codeword = collect_final_chunked_fold(
                        *previous_layer, output_size,
                        options.fold_chunk_elements, challenge, generator,
                        options, live_field_bytes, scratch_ledger,
                        scratch_cleanup, false, report);
                    previous_layer.reset();
                }
            }
            source_size = output_size;
            generator *= generator;
        }
    }

    if (running_claim != terminal_message * terminal_operand ||
        !constant_codeword(proof.final_codeword) ||
        proof.final_codeword.front() != terminal_message) {
        throw std::logic_error("BaseFold external terminal mismatch");
    }
    observe_final(proof.final_codeword, public_coin);
    const std::size_t half_base = codeword_size / 2U;
    const std::vector<std::size_t> query_indices = derive_queries(
        public_coin, parameters_.query_count, half_base);
    proof.queries = query_indices;
    proof.folds.resize(root_count);

    // Sumcheck tables and the evaluation point have no query-phase use.
    // Challenges remain as immutable replay input; no transcript method is
    // called while consuming them.
    std::vector<Fq2>{}.swap(tables.message);
    std::vector<Fq2>{}.swap(tables.operand);
    std::vector<Fq2>{}.swap(point_lsb);
    fill_base_query_openings(*state, query_indices, proof, options, report);

    // Replay every recorded FRI challenge from the immutable base codeword.
    // This phase deliberately performs no PublicCoin operation. Merkle roots
    // are recomputed in full, checked against pass one, and authentication
    // data is retained only for the already known query leaves.
    std::vector<std::size_t> positions = query_indices;
    previous_layer.reset();
    source_identity = state->artifact->identity();
    source_size = codeword_size;
    generator = Fq::two_adic_generator(log2_exact(codeword_size));
    for (std::size_t round_index = 0; round_index < message_log;
         ++round_index) {
        const std::size_t output_size = source_size / 2U;
        const Fq2 &challenge = challenges[round_index];
        if (round_index + 1U < message_log) {
            const std::size_t half = output_size / 2U;
            for (std::size_t &position : positions) {
                position %= half;
            }
            const laminate::Digest identity = fold_scratch_identity(
                source_identity, state->commitment, round_index,
                challenge);
            RangedFoldEnumerator enumerate;
            ChunkPublished consumed;
            if (round_index == 0) {
                enumerate = make_base_ranged_fold_enumerator(
                    *state, column_weights, challenge, generator, true,
                    report);
            } else {
                if (!previous_layer) {
                    throw std::logic_error(
                        "missing BaseFold replay predecessor layer");
                }
                enumerate = make_chunked_ranged_fold_enumerator(
                    *previous_layer, challenge, generator, true, report);
                consumed = [&](std::size_t first, std::size_t count) {
                    remove_consumed_fold_chunks(
                        *previous_layer, first, count, scratch_ledger,
                        scratch_cleanup);
                };
            }
            ChunkedFoldLayer layer = write_chunked_fold_layer(
                scratch_directory /
                    ("pass-two-layer-" + std::to_string(round_index)),
                identity, output_size, options.fold_chunk_elements,
                enumerate, fold_requested_leaves(positions, output_size),
                options, persistent_field_bytes, true, scratch_ledger,
                scratch_cleanup, report, consumed);
            if (previous_layer) {
                finish_removed_fold_layer(*previous_layer);
                previous_layer.reset();
            }
            if (layer.root != proof.roots[round_index]) {
                throw std::runtime_error(
                    "BaseFold replay root disagrees with pass one");
            }
            fill_replayed_fold_query_openings(
                layer, round_index, positions, proof);
            source_identity = identity;
            previous_layer.emplace(std::move(layer));
        } else {
            std::vector<Fq2> replayed_final;
            if (round_index == 0) {
                const RangedFoldEnumerator enumerate =
                    make_base_ranged_fold_enumerator(
                        *state, column_weights, challenge, generator,
                        true, report);
                replayed_final.reserve(output_size);
                enumerate(0, output_size, [&](const Fq2 &value) {
                    replayed_final.push_back(value);
                });
            } else {
                if (!previous_layer) {
                    throw std::logic_error(
                        "missing final BaseFold replay predecessor");
                }
                replayed_final = collect_final_chunked_fold(
                    *previous_layer, output_size,
                    options.fold_chunk_elements, challenge, generator,
                    options, persistent_field_bytes, scratch_ledger,
                    scratch_cleanup, true, report);
                previous_layer.reset();
            }
            if (replayed_final != proof.final_codeword) {
                throw std::runtime_error(
                    "BaseFold final replay disagrees with pass one");
            }
        }
        source_size = output_size;
        generator *= generator;
    }
    std::vector<Fq2>{}.swap(challenges);
    if (scratch_ledger.live_bytes() != 0 ||
        report.scratch_physical_bytes != 0 ||
        report.scratch_written_physical_bytes !=
            admission_plan.required_scratch_written_physical_bytes ||
        report.scratch_deleted_physical_bytes !=
            report.scratch_written_physical_bytes ||
        report.scratch_peak_physical_bytes !=
            admission_plan.required_scratch_physical_bytes ||
        report.sequential_write_payload_bytes !=
            admission_plan.required_sequential_write_payload_bytes ||
        report.scratch_chunk_artifacts_written !=
            admission_plan.required_chunk_artifacts_written ||
        report.scratch_chunk_artifacts_deleted !=
            report.scratch_chunk_artifacts_written ||
        report.scratch_files_written !=
            admission_plan.required_scratch_files_written ||
        report.scratch_files_deleted != report.scratch_files_written ||
        report.scratch_deletion_validation_bytes !=
            report.scratch_written_physical_bytes ||
        report.artifact_validation_bytes !=
            checked_add_u64(
                admission_plan.state_artifact_physical_bytes,
                checked_multiply_u64(
                    report.scratch_written_physical_bytes, 2U,
                    "BaseFold scratch publication and deletion scans"),
                "BaseFold complete artifact validation bytes") ||
        report.sequential_read_payload_bytes !=
            checked_add_u64(
                checked_add_u64(
                    report.sumcheck_sequential_read_payload_bytes,
                    report.pass_one_fold_sequential_read_payload_bytes,
                    "BaseFold sumcheck and pass-one reads"),
                report.pass_two_fold_sequential_read_payload_bytes,
                "BaseFold complete sequential reads")) {
        throw std::logic_error(
            "BaseFold two-pass scratch accounting disagrees with preflight");
    }
    report.peak_live_storage_bytes = checked_add_u64(
        admission_plan.state_artifact_physical_bytes,
        report.scratch_peak_physical_bytes,
        "BaseFold peak live opening storage");
    if (report.peak_live_storage_bytes !=
        admission_plan.required_live_storage_bytes) {
        throw std::logic_error(
            "BaseFold live-storage report disagrees with preflight");
    }
    scratch_cleanup.finish();
    BaseFoldExternalOpening result;
    result.proof.bytes = encode_proof(proof);
    result.report = report;
    result.report.proof_bytes = checked_u64(result.proof.bytes.size(),
                                            "BaseFold proof bytes");
    return result;
}

PcsOpeningProof BaseFoldPcs::open(
    const std::shared_ptr<const ProverState> &prover_state,
    std::span<const Fq2> point, const Fq2 &claimed_value,
    PublicCoin &public_coin) const {
    const std::array<Fq2, 1> weight{Fq2::one()};
    return open_linear_combination(prover_state, weight, point,
                                   claimed_value, public_coin);
}

PcsOpeningProof BaseFoldPcs::open_linear_combination(
    const std::shared_ptr<const ProverState> &prover_state,
    std::span<const Fq2> column_weights,
    std::span<const Fq2> point, const Fq2 &claimed_value,
    PublicCoin &public_coin) const {
    const auto state =
        std::dynamic_pointer_cast<const BaseFoldProverState>(prover_state);
    if (!state || state->commitment.scheme != kSchemeIdentifier ||
        state->commitment.log_rate != parameters_.log_rate ||
        state->commitment.query_count != parameters_.query_count ||
        state->columns.empty() || state->codewords.size() !=
                                      state->columns.size() ||
        state->commitment.width != state->columns.size() ||
        column_weights.size() != state->columns.size() ||
        point.size() != log2_exact(state->columns.front().size())) {
        throw std::invalid_argument(
            "BaseFold opening state, point, or claim is inconsistent");
    }

    const std::size_t message_size = state->columns.front().size();
    const std::size_t message_log = log2_exact(message_size);
    std::vector<Fq2> point_lsb(point.rbegin(), point.rend());
    std::vector<Fq2> message(message_size, Fq2::zero());
    for (std::size_t column = 0; column < state->columns.size(); ++column) {
        if (state->columns[column].size() != message_size) {
            throw std::invalid_argument(
                "BaseFold opening state has malformed columns");
        }
        for (std::size_t index = 0; index < message_size; ++index) {
            message[index] += column_weights[column] *
                              state->columns[column][index];
        }
    }
    // The sumcheck below reduces the claimed opening to a checked terminal
    // product; no separate evaluation of the full message is needed.
    std::vector<Fq2> operand =
        equality_table_lsb(message.size(), point_lsb);
    std::vector<std::vector<Fq2>> layers(1);
    layers.front().assign(state->codewords.front().size(), Fq2::zero());
    for (std::size_t column = 0; column < state->codewords.size(); ++column) {
        if (state->codewords[column].size() != layers.front().size()) {
            throw std::invalid_argument(
                "BaseFold opening state has malformed codewords");
        }
        for (std::size_t index = 0; index < layers.front().size(); ++index) {
            layers.front()[index] +=
                column_weights[column] * state->codewords[column][index];
        }
    }
    std::vector<MerkleTree> trees;
    trees.reserve(message_log == 0 ? 0 : message_log - 1);

    BaseFoldProof proof;
    proof.rounds.reserve(message_log);
    proof.roots.reserve(message_log == 0 ? 0 : message_log - 1);
    Fq generator =
        Fq::two_adic_generator(log2_exact(layers.front().size()));
    Fq2 running_claim = claimed_value;
    std::size_t active_message_size = message.size();
    for (std::size_t round_index = 0; round_index < message_log;
         ++round_index) {
        const std::span<const Fq2> active_message(
            message.data(), active_message_size);
        const std::span<const Fq2> active_operand =
            round_index == 0
                ? std::span<const Fq2>(operand)
                : std::span<const Fq2>(message.data() + active_message_size,
                                       active_message_size);
        const std::array<Fq2, 2> round =
            sumcheck_round(active_message, active_operand);
        proof.rounds.push_back(round);
        observe_round(round, public_coin);
        const Fq2 challenge = public_coin.challenge_fq2();
        // R(0)+R(1)=claim, so the prover and verifier need not transmit R(0).
        const Fq2 at_zero = running_claim - round[0];
        running_claim = interpolate_quadratic(at_zero, round, challenge);
        const std::size_t next_size = active_message_size / 2;
        fold_adjacent_into(
            active_message,
            std::span<Fq2>(message.data(), next_size), challenge);
        fold_adjacent_into(
            active_operand,
            std::span<Fq2>(message.data() + next_size, next_size),
            challenge);
        active_message_size = next_size;
        if (round_index == 0) {
            // Both fold tables now share the original message allocation.
            // Releasing operand avoids retaining another full-domain buffer.
            std::vector<Fq2>{}.swap(operand);
        }
        layers.push_back(
            fold_codeword(layers.back(), challenge, generator));
        if (round_index == 0) {
            // Base queries use the committed Fq codeword. Only folded Fq2
            // layers are needed below, so discard the weighted base layer.
            std::vector<Fq2>{}.swap(layers.front());
        }
        generator *= generator;
        if (round_index + 1 < message_log) {
            trees.push_back(make_fq2_tree(layers.back()));
            proof.roots.push_back(trees.back().root());
            observe_root(proof.roots.back(), public_coin);
        }
    }
    const Fq2 terminal_operand =
        message_log == 0 ? operand.front() : message[1];
    if (active_message_size != 1 ||
        running_claim != message.front() * terminal_operand) {
        throw std::logic_error("BaseFold terminal sumcheck mismatch");
    }
    proof.final_codeword = layers.back();
    if (!constant_codeword(proof.final_codeword) ||
        proof.final_codeword.front() != message.front()) {
        throw std::logic_error("BaseFold terminal codeword mismatch");
    }
    observe_final(proof.final_codeword, public_coin);

    const std::size_t half_base = state->codewords.front().size() / 2;
    const std::vector<std::size_t> query_indices = derive_queries(
        public_coin, parameters_.query_count, half_base);
    proof.queries = query_indices;
    const std::size_t base_leaf_size =
        merkle_leaf_size(state->codewords.front().size());
    proof.base.leaf_indices = queried_leaf_indices(
        query_indices, state->codewords.front().size());
    proof.base.values_per_leaf =
        base_leaf_size * state->codewords.size();
    proof.base.values.resize(proof.base.leaf_indices.size() *
                             proof.base.values_per_leaf);
    for (std::size_t opened_leaf_index = 0;
         opened_leaf_index < proof.base.leaf_indices.size();
         ++opened_leaf_index) {
        const std::size_t leaf_index =
            proof.base.leaf_indices[opened_leaf_index];
        const std::size_t begin = leaf_index * base_leaf_size;
        const std::size_t output_offset =
            opened_leaf_index * proof.base.values_per_leaf;
        for (std::size_t offset = 0; offset < base_leaf_size; ++offset) {
            for (std::size_t column = 0;
                 column < state->codewords.size(); ++column) {
                proof.base.values[output_offset +
                                  offset * state->codewords.size() + column] =
                    state->codewords[column][begin + offset];
            }
        }
    }
    proof.base.frontier = state->tree.open_many(proof.base.leaf_indices);

    proof.folds.resize(message_log == 0 ? 0 : message_log - 1U);
    std::vector<std::size_t> positions = query_indices;
    for (std::size_t round_index = 0; round_index < proof.folds.size();
         ++round_index) {
        const std::vector<Fq2> &layer = layers[round_index + 1U];
        const std::size_t half = layer.size() / 2U;
        for (std::size_t &position : positions) {
            position %= half;
        }
        const std::size_t leaf_size = merkle_leaf_size(layer.size());
        MerkleMultiOpening<Fq2> &opening = proof.folds[round_index];
        opening.leaf_indices = queried_leaf_indices(positions, layer.size());
        opening.values_per_leaf = leaf_size;
        opening.values.reserve(opening.leaf_indices.size() * leaf_size);
        for (const std::size_t leaf_index : opening.leaf_indices) {
            const std::size_t begin = leaf_index * leaf_size;
            opening.values.insert(
                opening.values.end(),
                layer.begin() + static_cast<std::ptrdiff_t>(begin),
                layer.begin() +
                    static_cast<std::ptrdiff_t>(begin + leaf_size));
        }
        opening.frontier =
            trees[round_index].open_many(opening.leaf_indices);
    }
    return PcsOpeningProof{encode_proof(proof)};
}

bool BaseFoldPcs::verify(const PcsCommitment &commitment,
                         std::span<const Fq2> point,
                         const Fq2 &claimed_value,
                         const PcsOpeningProof &opening,
                         PublicCoin &public_coin) const {
    if (commitment.width != 1) {
        return false;
    }
    const std::array<Fq2, 1> weight{Fq2::one()};
    return verify_linear_combination(commitment, weight, point,
                                     claimed_value, opening, public_coin);
}

bool BaseFoldPcs::verify_linear_combination(
    const PcsCommitment &commitment,
    std::span<const Fq2> column_weights,
    std::span<const Fq2> point, const Fq2 &claimed_value,
    const PcsOpeningProof &opening, PublicCoin &public_coin) const {
    try {
        if (commitment.scheme != kSchemeIdentifier ||
            commitment.log_rate != parameters_.log_rate ||
            commitment.query_count != parameters_.query_count ||
            commitment.evaluation_count == 0 || commitment.width == 0 ||
            commitment.evaluation_count >
                std::numeric_limits<std::size_t>::max() ||
            commitment.width > std::numeric_limits<std::size_t>::max() ||
            column_weights.size() != commitment.width) {
            return false;
        }
        const std::size_t message_size =
            static_cast<std::size_t>(commitment.evaluation_count);
        const std::size_t width =
            static_cast<std::size_t>(commitment.width);
        const std::size_t message_log = log2_exact(message_size);
        const std::size_t codeword_size =
            checked_codeword_size(message_size, parameters_.log_rate);
        if (point.size() != message_log) {
            return false;
        }
        const std::optional<BaseFoldProof> decoded = decode_proof(
            opening.bytes, message_log, width, parameters_.log_rate,
            parameters_.query_count);
        if (!decoded.has_value()) {
            return false;
        }
        const BaseFoldProof &proof = *decoded;

        Fq2 running_claim = claimed_value;
        std::vector<Fq2> challenges;
        challenges.reserve(message_log);
        for (std::size_t round = 0; round < message_log; ++round) {
            observe_round(proof.rounds[round], public_coin);
            const Fq2 challenge = public_coin.challenge_fq2();
            challenges.push_back(challenge);
            const Fq2 at_zero =
                running_claim - proof.rounds[round][0];
            running_claim = interpolate_quadratic(
                at_zero, proof.rounds[round], challenge);
            if (round + 1 < message_log) {
                observe_root(proof.roots[round], public_coin);
            }
        }
        std::vector<Fq2> point_lsb(point.rbegin(), point.rend());
        Fq2 operand_evaluation = Fq2::one();
        for (std::size_t variable = 0; variable < message_log; ++variable) {
            operand_evaluation *=
                Fq2::one() - point_lsb[variable] - challenges[variable] +
                (point_lsb[variable] + point_lsb[variable]) *
                    challenges[variable];
        }
        if (!constant_codeword(proof.final_codeword) ||
            running_claim !=
                proof.final_codeword.front() * operand_evaluation) {
            return false;
        }
        observe_final(proof.final_codeword, public_coin);

        const std::size_t half_base = codeword_size / 2;
        const std::vector<std::size_t> expected_queries = derive_queries(
            public_coin, parameters_.query_count, half_base);
        if (proof.queries != expected_queries) {
            return false;
        }
        const std::size_t codeword_log = log2_exact(codeword_size);
        const Fq omega = Fq::two_adic_generator(codeword_log);
        const Fq inverse_omega = omega.inverse();
        const std::size_t base_leaf_size = merkle_leaf_size(codeword_size);
        const std::size_t base_leaf_count = merkle_leaf_count(codeword_size);
        if (!verify_multi_opening(
                commitment.root, base_leaf_count, proof.base,
                [](std::span<const Fq> leaf) {
                    return hash_fq_leaf(leaf);
                })) {
            return false;
        }
        for (std::size_t round = 0; round < proof.folds.size(); ++round) {
            const std::size_t layer_size = codeword_size >> (round + 1U);
            if (!verify_multi_opening(
                    proof.roots[round], merkle_leaf_count(layer_size),
                    proof.folds[round], [](std::span<const Fq2> leaf) {
                        return hash_fq2_leaf(leaf);
                    })) {
                return false;
            }
        }

        // Compute the initial inverse-generator power once per distinct
        // query. Later rounds obtain their power by squaring and, when the
        // folded index crosses the next half, one sign change. This replaces
        // an inverse plus exponentiation in every query of every layer.
        std::vector<std::pair<std::size_t, Fq>> inverse_powers;
        inverse_powers.reserve(expected_queries.size());
        std::vector<std::size_t> unique_queries = expected_queries;
        std::sort(unique_queries.begin(), unique_queries.end());
        unique_queries.erase(
            std::unique(unique_queries.begin(), unique_queries.end()),
            unique_queries.end());
        for (const std::size_t query : unique_queries) {
            inverse_powers.emplace_back(query, inverse_omega.pow(query));
        }
        for (std::size_t query_index = 0;
             query_index < proof.queries.size(); ++query_index) {
            const std::size_t query = proof.queries[query_index];
            const std::size_t lo_leaf_index =
                query / base_leaf_size;
            const std::size_t hi_position = query + half_base;
            const std::size_t hi_leaf_index =
                hi_position / base_leaf_size;
            const std::span<const Fq> base_lo =
                opened_leaf(proof.base, lo_leaf_index);
            const std::span<const Fq> base_hi =
                opened_leaf(proof.base, hi_leaf_index);
            Fq2 lo = Fq2::zero();
            Fq2 hi = Fq2::zero();
            const std::size_t lo_offset =
                (query % base_leaf_size) * width;
            const std::size_t hi_offset =
                (hi_position % base_leaf_size) * width;
            for (std::size_t column = 0; column < width; ++column) {
                lo += column_weights[column] *
                      base_lo[lo_offset + column];
                hi += column_weights[column] *
                      base_hi[hi_offset + column];
            }
            std::size_t index = query;
            std::size_t layer_half = half_base;
            const auto initial_power = std::lower_bound(
                inverse_powers.begin(), inverse_powers.end(), query,
                [](const auto &entry, std::size_t value) {
                    return entry.first < value;
                });
            if (initial_power == inverse_powers.end() ||
                initial_power->first != query) {
                return false;
            }
            Fq inverse_generator_power = initial_power->second;
            if (message_log == 0 &&
                (lo != proof.final_codeword[index] ||
                 hi != proof.final_codeword[index + half_base])) {
                return false;
            }
            for (std::size_t round = 0; round < message_log; ++round) {
                const Fq2 folded = fold_pair(
                    lo, hi, challenges[round],
                    inverse_generator_power);
                const std::size_t next_half = layer_half / 2;
                const std::size_t next_index =
                    index % (next_half == 0 ? 1 : next_half);
                if (round + 1 < message_log) {
                    const MerkleMultiOpening<Fq2> &next =
                        proof.folds[round];
                    const std::size_t next_layer_size = layer_half;
                    const std::size_t leaf_size =
                        merkle_leaf_size(next_layer_size);
                    const std::size_t hi_next_position =
                        next_index + next_half;
                    const std::span<const Fq2> next_lo =
                        opened_leaf(next, next_index / leaf_size);
                    const std::span<const Fq2> next_hi = opened_leaf(
                        next, hi_next_position / leaf_size);
                    const Fq2 lo_next =
                        next_lo[next_index % leaf_size];
                    const Fq2 hi_next =
                        next_hi[hi_next_position % leaf_size];
                    const Fq2 &expected =
                        index < next_half ? lo_next : hi_next;
                    if (folded != expected) {
                        return false;
                    }
                    lo = lo_next;
                    hi = hi_next;
                } else if (index >= proof.final_codeword.size() ||
                           folded != proof.final_codeword[index]) {
                    return false;
                }
                if (round + 1U < message_log) {
                    inverse_generator_power *= inverse_generator_power;
                    if (index >= next_half) {
                        inverse_generator_power =
                            Fq::zero() - inverse_generator_power;
                    }
                }
                layer_half = next_half;
                index = next_index;
            }
        }
        return true;
    } catch (const std::invalid_argument &) {
        return false;
    } catch (const std::out_of_range &) {
        return false;
    } catch (const std::domain_error &) {
        return false;
    } catch (const std::overflow_error &) {
        return false;
    }
}

} // namespace laminate::spartan
